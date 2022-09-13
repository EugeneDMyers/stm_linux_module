
 /* dual_monitor_mode.c: Interface to Intel's SMM Transfer Monitor (STM)
 *
 * This program contains functions that opt-in to STM and create STM policies
 * to protect Linux's critical resources.
 *
 * Tejaswini Vibhute - <tejaswiniav@gmail.com> - Portland State University
 *
 * Copyright (C) 2018 Portland State University
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; If not, see <http://www.gnu.org/licenses/>.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include "dual_monitor_mode.h"

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/kvm_host.h>
#include <linux/nmi.h>
#include <linux/reboot.h>
#include <linux/syscore_ops.h>
#include <linux/cpu.h>
#include <linux/suspend.h>
#include <linux/version.h>

#include <asm/apic.h>
#include <asm/processor.h>
#include <asm/msr.h>
#include <asm/vmx.h>
#include <asm/kvm_host.h>
#include <asm/uaccess.h>
#include <asm/virtext.h>
#include "vmx.h"

#include "vmx_ops.h"

MODULE_LICENSE("GPL");
MODULE_SOFTDEP("pre: kvm-intel");

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
extern struct kvm_x86_ops *kvm_x86_ops;
#endif

static DEFINE_PER_CPU(struct vmcs *, temp_vmcs);
//static DEFINE_SPINLOCK(cntr_lock);
static atomic_t stmbsp_done;

static u32 vmcs_revision_id;
static atomic_t bspready;

/* VMX_BASIC_MSR addition for Linux  */

#define VMX_BASIC_DUAL_MONITOR (1ULL << 49)
#define MSR_VMX_BASIC_VMCS_REVISION_MASK             0x7FFFFFFFull

/* MSR_IA32_SMM_MONITOR_CTL addition for Linux */

#define IA32_SMM_MONITOR_CTL_VALID      0x0001

/*
 * is_stm can take the following status codes. Each code represents the state of
 * STM on the current system
 * 0x00 : STM initialization not yet started
 * 0x01 : STM successfully launched on all the logical CPUs
 * 0x02 : STM launch failed
 * 0x03 : STM not supported
 * 0x04 : STM suspended
 * 0x05 : STM suspended by PM_HIBERNATION_PREPARE
 */

#define STM_UINIT        0x00
#define STM_LAUNCHED     0x01
#define STM_FAILED       0x02
#define STM_NOT_SUP      0x03
#define STM_SHUTDOWN     0x04
#define STM_SHUTDOWN_PM  0x05

static atomic_t is_stm;
static atomic_t number_ap;

noinline void dmm_fault()
{
	unsigned long cr4 = __read_cr4();
        int cpu = smp_processor_id();

	printk("%d STM-LINUX: DMM fault cr4: %lx\n", cpu, cr4);
	if((cr4 & X86_CR4_VMXE) == X86_CR4_VMXE)
		printk("%d STM-LINUX VMXE bit set\n", cpu);
	else
		printk("%d STM-LINUX VMXE bit not set\n", cpu);
}

noinline void vmclear_error(struct vmcs *vmcs, u64 phys_addr)
{
	int cpu = smp_processor_id();
        printk("%d STM-LINUX: vmclear failed: %p/%llx\n", cpu, vmcs, phys_addr);
}

/* from XEN */

#undef rdmsr_safe
/* rdmsr with exception handling */
#define rdmsr_safe(msr,val) ({\
    int _rc; \
    uint32_t lo, hi; \
    __asm__ __volatile__( \
        "1: rdmsr\n2:\n" \
        ".section .fixup,\"ax\"\n" \
        "3: xorl %0,%0\n; xorl %1,%1\n" \
        "   movl %5,%2\n; jmp 2b\n" \
        ".previous\n" \
        _ASM_EXTABLE(1b, 3b) \
        : "=a" (lo), "=d" (hi), "=&r" (_rc) \
        : "c" (msr), "2" (0), "i" (-EFAULT)); \
    val = lo | ((uint64_t)hi << 32); \
    _rc; })

/* from kvm */
struct vmcs *alloc_vmcs_cpu(int cpu, gfp_t flags)
{
        int node = cpu_to_node(cpu);
        struct page *pages;
        struct vmcs *vmcs;

        pages = __alloc_pages_node(node, flags, get_order(4096));
        if (!pages)
                return NULL;
        vmcs = page_address(pages);
        memset(vmcs, 0, 4096);

       vmcs->hdr.revision_id = vmcs_revision_id;

       return vmcs;
}

struct vmcs * vmx_temp_vmcs(void)
{
     int cpu = smp_processor_id();
     return alloc_vmcs_cpu(cpu, GFP_KERNEL );
}

/*
 * Set the temporary VMCS for the current CPU
 */
static void set_temp_vmcs(void)
{
    u64 msr_content = 0;
    int cpu = raw_smp_processor_id();
    u64 phys_addr = __pa(per_cpu(temp_vmcs, cpu));

	vmcs_clear(per_cpu(temp_vmcs, cpu));
    ///current->arch.hvm_vmx.vmcs_pa = per_cpu(temp_vmcs, cpu);
    //vmx_vmcs_reload(current);

    //BUG - need to deal with extra VMCS when the STM is done with it
    vmptrld(phys_addr);

    rdmsr_safe(MSR_IA32_VMX_EXIT_CTLS, msr_content);
    vmwrite(VM_EXIT_CONTROLS, msr_content);
    return;
}

/*
 * Add or Delete a VMCS entry to/from the VMCS Database in STM.
 * @param add_remove determines whether to add an entry or remove the previously
 * stored entry.
 * While adding an entry specify the Domain protection policy in the appropriate
 * fields.
 */
int manage_vmcs_database(uint64_t vmcs_ptr, uint32_t add_remove)
{
    STM_VMCS_DATABASE_REQUEST *vmcsdb_request = NULL;
    void *request_list;
    uint32_t eax_reg = 0;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;
   int cpu = smp_processor_id();

    printk("%d STM-LINUX: Invoking Operation on VMCS Database\n", cpu);
    if ( atomic_read(&is_stm) != 0x01)  //is_stm != 0x01
    {
        printk("%d STM-LINUX: STM not enabled\n", cpu);
        return -1;
    }

    if ( (request_list = alloc_pages(GFP_KERNEL, 0)) == NULL )
    {
        printk("%d STM-LINUX: Failed to allocate resource page.\n", cpu);
        return -1;
    }

    vmcsdb_request = (STM_VMCS_DATABASE_REQUEST*)request_list;
    vmcsdb_request->VmcsPhysPointer = vmcs_ptr;
    vmcsdb_request->DomainType = DOMAIN_UNPROTECTED;
    vmcsdb_request->XStatePolicy = XSTATE_READONLY;
    vmcsdb_request->DegradationPolicy = DOMAIN_UNPROTECTED;
    vmcsdb_request->AddOrRemove = add_remove;
    vmcsdb_request->Reserved1 = 0x0;

    ebx_reg = (uint64_t)__pa((unsigned long)request_list);
    ecx_reg = ((uint64_t)__pa((unsigned long)request_list)) >> 32;

    asm volatile(
            ".byte 0x0f,0x01,0xc1\n"
            :"=a"(eax_reg)
            :"a"(STM_API_MANAGE_VMCS_DATABASE), "b"(ebx_reg), "c"(ecx_reg)
            );

    if ( eax_reg != STM_SUCCESS )
    {
        printk("%d STM-LINUX: STM_API_MANAGE_VMCS_DATABASE failed with error: 0x%lx\n",\
                cpu, (unsigned long)eax_reg);

        clear_page(request_list);
        free_pages((unsigned long)request_list, 0);
        return -1;
    }
    clear_page(request_list);
    free_pages((unsigned long)request_list, 0);
    return 0;
}

/*
 * protect_resources creates resource protection policy profile and invokes the
 * PROTECT_RESOURCE VMCALL to apply these policy profiles over SMI handler.
 * While creating the policy profile the adopter should check for STM
 * capabilities reported after successful return from INITIALIZE_PROTECTION
 * VMCALL. The capabilities value will indicate whether the underlying STM
 * supports bit granular or whole MSR resource protection methodology. (Byte
 * granular or entire page level protection for MMIO and Memory regions.)
 * Intel's STM implementation currently only supports whole MSR or page level
 * resource protection.
 * Our sample policy profile implementation below is in synchronous with this
 * idea.
 */
int protect_resources(void)
{
    struct page *resource_list;
    uint8_t *linuxresources;
    uint32_t eax_reg = STM_API_PROTECT_RESOURCE;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;
    int page_index = 0;
    int cpu = smp_processor_id();
    STM_RSC_MSR_DESC MsrDesc = {};
    STM_RSC_IO_DESC IoDesc = {};
    STM_RSC_END EndDesc = {};

    printk("%d STM-LINUX: Protecting Linux Resources\n", cpu);
    if ( (resource_list = alloc_pages(GFP_KERNEL, 0)) == NULL )
    {
        printk("%d STM-LINUX: Failed to allocate resource page.\n", cpu);
        return -1;
    }

    linuxresources = page_address(resource_list);

    memset(linuxresources, 0, 4096);

    MsrDesc.Hdr.RscType = MACHINE_SPECIFIC_REG;
    MsrDesc.Hdr.Length = sizeof(STM_RSC_MSR_DESC);
    MsrDesc.Hdr.ReturnStatus = 0;
    MsrDesc.Hdr.Reserved = 0;
    MsrDesc.Hdr.IgnoreResource = 0;
    MsrDesc.MsrIndex = 0x9b;
    MsrDesc.KernelModeProcessing = 1;
    MsrDesc.Reserved = 0;
    MsrDesc.WriteMask = (uint64_t) - 1;
    MsrDesc.ReadMask = 0;

    memcpy(linuxresources, &MsrDesc, sizeof(MsrDesc));
    linuxresources += MsrDesc.Hdr.Length;

    MsrDesc.Hdr.RscType = MACHINE_SPECIFIC_REG;
    MsrDesc.Hdr.Length = sizeof(STM_RSC_MSR_DESC);
    MsrDesc.Hdr.ReturnStatus = 0;
    MsrDesc.Hdr.Reserved = 0;
    MsrDesc.Hdr.IgnoreResource = 0;
    MsrDesc.MsrIndex = MSR_IA32_MISC_ENABLE; /* 0x1A0 */
    MsrDesc.KernelModeProcessing = 0;
    MsrDesc.Reserved = 0;
    MsrDesc.WriteMask = (uint64_t) - 1;
    MsrDesc.ReadMask = 0;

    memcpy(linuxresources, &MsrDesc, sizeof(MsrDesc));
    linuxresources += MsrDesc.Hdr.Length;

    MsrDesc.Hdr.RscType = MACHINE_SPECIFIC_REG;
    MsrDesc.Hdr.Length = sizeof(STM_RSC_MSR_DESC);
    MsrDesc.Hdr.ReturnStatus = 0;
    MsrDesc.Hdr.Reserved = 0;
    MsrDesc.Hdr.IgnoreResource = 0;
    MsrDesc.MsrIndex =MSR_IA32_SYSENTER_EIP; /* 0x176 */
    MsrDesc.KernelModeProcessing = 0;
    MsrDesc.Reserved = 0;
    MsrDesc.WriteMask = (uint64_t) - 1;
    MsrDesc.ReadMask  = (uint64_t) - 1;

    memcpy(linuxresources, &MsrDesc, sizeof(MsrDesc));
    linuxresources += MsrDesc.Hdr.Length;

    MsrDesc.Hdr.RscType = MACHINE_SPECIFIC_REG;
    MsrDesc.Hdr.Length = sizeof(STM_RSC_MSR_DESC);
    MsrDesc.Hdr.ReturnStatus = 0;
    MsrDesc.Hdr.Reserved = 0;
    MsrDesc.Hdr.IgnoreResource = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
    MsrDesc.MsrIndex = MSR_IA32_FEATURE_CONTROL;
#else
    MsrDesc.MsrIndex = MSR_IA32_FEAT_CTL;
#endif
    MsrDesc.KernelModeProcessing = 0;
    MsrDesc.Reserved = 0;
    MsrDesc.ReadMask = (uint64_t) - 1;
    MsrDesc.WriteMask = (uint64_t) - 1;

    memcpy(linuxresources, &MsrDesc, sizeof(MsrDesc));
    linuxresources += MsrDesc.Hdr.Length;

    IoDesc.Hdr.RscType = IO_RANGE;
    IoDesc.Hdr.Length = sizeof(STM_RSC_IO_DESC);
    IoDesc.Hdr.ReturnStatus = 0;
    IoDesc.Hdr.Reserved = 0;
    IoDesc.Hdr.IgnoreResource = 0;
    IoDesc.Base = 0x60; // 0x60 to 0x64
    IoDesc.Length = 5;
    IoDesc.Reserved = 0;

    memcpy(linuxresources, &IoDesc, sizeof(IoDesc));
    linuxresources += IoDesc.Hdr.Length;

    // Termination
    EndDesc.Hdr.RscType = END_OF_RESOURCES;
    EndDesc.Hdr.Length = sizeof(STM_RSC_END);
    EndDesc.Hdr.ReturnStatus = 0;
    EndDesc.Hdr.Reserved = 0;
    EndDesc.Hdr.IgnoreResource = 0;
    EndDesc.ResourceListContinuation = 0;

    memcpy(linuxresources, &EndDesc, sizeof(EndDesc));

    printk("\n%d STM-LINUX: Going to request protection for: %llx", cpu, (uint64_t)resource_list);
    dump_stm_resource(page_address(resource_list));
    ebx_reg = (uint64_t)virt_to_phys(page_address(resource_list)) + \
                    page_index*PAGE_SIZE;
    ecx_reg = ((uint64_t)virt_to_phys(page_address(resource_list)) + \
                    page_index*PAGE_SIZE) >> 32;

    asm volatile(
            ".byte 0x0f,0x01,0xc1\n"
            :"=a"(eax_reg)
            :"a"(eax_reg), "b"(ebx_reg), "c"(ecx_reg)
            :"memory"
            );

    if ( eax_reg != STM_SUCCESS )
    {
        printk("%d STM-LINUX: STM_API_PROTECT_RESOURCE failed with error: 0x%lx\n", \
                cpu, (unsigned long)eax_reg);
        printk("%d STM-LINUX: STM_API_PROTECT_RESOURCE return status in Hdr: %d\n", \
                cpu, EndDesc.Hdr.ReturnStatus);
        __free_pages(resource_list, 0);
        return -1;
    }
    clear_page(page_address(resource_list));
    __free_pages(resource_list, 0);
    return 0;
}

/*
 * Obtain the BIOS resource protection list
 */
int get_bios_resource(void)
{
    struct page *resource_list;
    STM_RSC *resource;
    uint32_t eax_reg = 0;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;
    uint32_t edx_reg = 0;
    int page_index;
    int cpu = smp_processor_id();

    printk("%d STM-LINUX: Obtaining BIOS resource list.\n", cpu);

    if ( (resource_list = alloc_pages( \
                    GFP_KERNEL, get_order(MAX_RESOURCE_SIZE))) == NULL )
    {
        printk("%d STM-LINUX: Failed to allocate resource page.\n", cpu);
        return -1;
    }

    for ( page_index = 0; page_index < MAX_RESOURCE_PAGES; page_index++ )
    {
        eax_reg = STM_API_GET_BIOS_RESOURCES;

        ebx_reg = (uint64_t)virt_to_phys(page_address(resource_list)) + \
                page_index*4096;
        ecx_reg = ((uint64_t)virt_to_phys(page_address(resource_list)) + \
                    page_index*4096) >> 32;
        edx_reg = page_index;

        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(eax_reg), "b"(ebx_reg), "c"(ecx_reg), "d"(edx_reg)
                :"memory"
                );

        if ( eax_reg != STM_SUCCESS )
        {
            printk("%d STM-LINUX: STM_API_GET_BIOS_RESOURCES failed with error: \
                    0x%lx\n", cpu, (unsigned long)eax_reg);
            free_pages((unsigned long) resource_list, get_order(MAX_RESOURCE_SIZE));
            return -1;
        }
        resource = (STM_RSC*)((uint64_t)page_address(resource_list) + page_index*4096);
        dump_stm_resource(resource);
        if ( edx_reg == 0 )
        {
            printk("%d STM-LINUX: Reached end of BIOS Resource list\n", cpu);
            break;
        }
    }
    __free_pages(resource_list, get_order(MAX_RESOURCE_SIZE));
    return 0;
}

/*
 * Opt-in to STM by invoking the INTIALIZE_PROTECTION VMCALL and STM_START
 * VMCALL. Also, obtain the BIOS resource protection list from STM and define
 * resource protection policies over MLE resources.
 */
static void launch_stm(void *unused)
{
    u64 msr_content = 0;
    uint32_t eax_reg = 0;
    uint32_t ebx_reg = 0;
    uint32_t ecx_reg = 0;
    uint32_t edx_reg = 0;
    unsigned long eflags;
    unsigned int cpu;
    int ret;

    cpu = smp_processor_id();

        if(cpu != 0)
		while(atomic_read(&bspready) == 0) {};

    printk("%d STM-LINUX - starting launch_stm\n", cpu);

    /* Consult MSR IA32_VMX_BASIC to find out if STM is supported.
     * If STM is supported then bit 49 of this MSR will be set and
     * MSR IA32_SMM_MONITOR_CTL exists on such a processor.
     * Trying to access MSR IA32_SMM_MONITOR_CTL on a processor that does not
     * support STM will result in a #GP Fault.
     */
    rdmsr_safe(MSR_IA32_VMX_BASIC, msr_content);
    if ( (msr_content & VMX_BASIC_DUAL_MONITOR) == 0 )
    {
        printk("%d STM-LINUX: STM is not supported on the processor\n", cpu);
        //is_stm = 0x03;
	smp_mb__before_atomic();
	atomic_set(&is_stm, 0x03);
	smp_mb__after_atomic();
        //return;
	goto done;
    }

    vmcs_revision_id = msr_content & MSR_VMX_BASIC_VMCS_REVISION_MASK; 

    /* check to see if vmx is enabled */
    if ( !cpu_vmx_enabled() )
    {
        printk("%d STM-LINUX: VMX is not enabled\n", cpu);
        //is_stm = 0x03;
	smp_mb__before_atomic();
	atomic_set(&is_stm, 0x03);
	smp_mb__after_atomic();
        //return;
        goto done;
    }

    msr_content = 0;
    /* Proceed only if BIOS has opt-in to STM. */
    rdmsr_safe(MSR_IA32_SMM_MONITOR_CTL, msr_content);
    if ( (msr_content & IA32_SMM_MONITOR_CTL_VALID) == 0 )
    {
        printk("%d STM-LINUX: No STM opt-in from BIOS\n", cpu);
        //is_stm = 0x03;
	smp_mb__before_atomic();
	atomic_set(&is_stm, 0x03);
	smp_mb__after_atomic();
        //return;
        goto done;
    }
    /* Allocate a temporary VMCS per CPU */
    printk("%d STM-LINUX: Opt-in to STM commences\n", cpu);
    per_cpu(temp_vmcs, cpu) = vmx_temp_vmcs();
    if ( !per_cpu(temp_vmcs, cpu) )
    {
        printk("%d STM-LINUX: Failed to create VMCS\n", cpu);
        //is_stm = 0x02;
	smp_mb__before_atomic();
	atomic_set(&is_stm, 0x02);
	smp_mb__after_atomic();
        //return;
	goto done;
    }

    set_temp_vmcs();

    if (cpu == 0 )
    {
        printk("%d STM-LINUX: Initializing STM Resources\n", cpu);
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
		"    pushf;     "
		"    pop %2;    " 
                :"=a"(eax_reg), "=b"(ebx_reg), "=c"(eflags), "=d"(edx_reg)
                :"a"(STM_API_INITIALIZE_PROTECTION), "b"(ebx_reg), "c"(ecx_reg), "d"(edx_reg)
                :"cc");

	if (eflags & X86_EFLAGS_CF)
		printk("%d STM-LINUX: vmfailinvalid error\n", cpu);

	if (eflags & X86_EFLAGS_ZF)
		printk("%d STM-LINUX - vmfailvalid error\n", cpu); 

        if ( eax_reg != STM_SUCCESS )
        {
            printk("%d STM-LINUX: STM_API_INITIALIZE_PROTECTION failed with error: \
                    0x%lx\n", cpu, (unsigned long)eax_reg);
            //is_stm = 0x02;
	    smp_mb__after_atomic();
	    atomic_set(&is_stm, 0x02);
	    smp_mb__after_atomic();
            //return;
	    goto done;
        }

        printk("%d STM-LINUX: STM_API_INITIALIZE_PROTECTION succeeded\n", cpu);

        /* Get Bios Resources */
        ret = get_bios_resource();

	if (ret !=0)
	{
	    printk("%d STM-LINUX: Exiting STM opt-in\n", cpu);
	    //is_stm = 0x02;
	    smp_mb__before_atomic();
	    atomic_set(&is_stm, 0x02);
	    smp_mb__after_atomic();
	    //return;
	    goto done;
	}

        /* Protect Linux Resources */
        ret = protect_resources();
        if ( ret != 0 )
        {
            printk("%d STM-LINUX: Exiting STM opt-in\n", cpu);
            //is_stm = 0x02;
	    smp_mb__before_atomic();
	    atomic_set(&is_stm, 0x02);
	    smp_mb__after_atomic();
            //return;
	    goto done;
        }

	// have to start the others first
	smp_mb__before_atomic();
	atomic_set(&bspready, 1); 
	smp_mb__after_atomic();

        /* Start STM */
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_START));
        if ( eax_reg == STM_SUCCESS )
            printk("%d STM-LINUX: STM_API_START (BSP) succeeded\n", cpu);
        else
        {
            printk("%d STM-LINUX: STM_API_START (BSP) failed with error: 0x%lx\n", \
                    cpu, (unsigned long)eax_reg);
            //is_stm = 0x02;
	    smp_mb__before_atomic();
	    atomic_set(&is_stm, 0x02);
	    smp_mb__after_atomic();
            //return;
	    goto done;
        }
    }
    else
    {
//	while(atomic_read(&bspready) == 0) {};
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_START));

        if ( eax_reg == STM_SUCCESS )
            printk("%d STM-LINUX: STM_API_START (AP) succeeded\n", cpu);
        else
        {
            printk("%d STM-LINUX: STM_API_START (AP) failed with error: 0x%lx\n", \
                    cpu, (unsigned long)eax_reg);
            //return;
	    goto done;
        }
    }
done:
    if(cpu == 0)
    {
	printk("%d STM-LINUX - waiting for APs to finish\n", cpu);
        while ((atomic_read(&number_ap) < ((int)num_online_cpus() - 1)))
        {
            //    yield();
            //spin_unlock(&cntr_lock);
            //spin_lock(&cntr_lock);
        }
        printk("%d STM-LINUX - APs finished,  BSP getting out\n", cpu);
	smp_mb__before_atomic();
        atomic_set(&stmbsp_done, 1);
	smp_mb__after_atomic();
    }
    else
    {
	smp_mb__before_atomic();
    	atomic_inc(&number_ap);
	smp_mb__after_atomic();
	printk("%d STM-LINUX - (done-AP) waiting for BSP to finish\n", cpu);
	while (atomic_read(&stmbsp_done) != 1) {} // hold till all done
    }
    //local_irq_enable();
    return;
}

/*
 * Shutdown STM
 */
void teardown_stm(void *unused)
{
    uint32_t eax_reg = 0;
    uint32_t cpu;

    cpu = smp_processor_id();

    printk("%d STM-LINUX: teardown_stm started\n", cpu);

    /* Teardown STM only if it has been previously enabled */
    if ( atomic_read(&is_stm) != 0x01 )
    {
        printk("%d STM-LINUX: teardown_stm - STM not enabled (%d)\n", cpu, atomic_read(&is_stm));
        goto done;
    }

    if (cpu == 0 )
    {
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_STOP));

        if ( eax_reg == STM_SUCCESS )
            printk("%d STM-LINUX: teardown_stm STM_API_STOP succeeded\n", cpu);
        else
        {
            printk("%d STM-LINUX: teardown_stm STM_API_STOP failed with error: 0x%lx\n", \
                    cpu, (unsigned long)eax_reg);
            goto done;
        }
    }
    else
    {
        /* Teardown STM */
        asm volatile(
                ".byte 0x0f,0x01,0xc1\n"
                :"=a"(eax_reg)
                :"a"(STM_API_STOP));

        if ( eax_reg == STM_SUCCESS )
            printk("%d STM-LINUX: STM_API_STOP succeeded\n", cpu);
        else
        {
            printk("%d STM-LINUX: STM_API_STOP failed with error: 0x%lx\n", \
                    cpu, (unsigned long)eax_reg);
	    goto done;
        }
    }
done:
    if(cpu == 0)
    {
        printk("%d STM-LINUX - (teardown) waiting for APs to finish\n", cpu);
        while ( atomic_read(&number_ap) < ((int)num_online_cpus() - 1) )
        {
        }
        printk("%d STM-LINUX - (teardown) APs finished,  BSP getting out\n", cpu);
	smp_mb__before_atomic();
        atomic_set(&stmbsp_done, 1);
	smp_mb__after_atomic();
    }
    else
    {
	smp_mb__before_atomic();
        atomic_inc(&number_ap);
	smp_mb__after_atomic();
        while (atomic_read(&stmbsp_done) != 1) {} // hold till all done
    }

    //local_irq_enable();
    return;
}

/*
 * This function dumps STM resource node header.
 */
void dump_stm_resource_header(STM_RSC *Resource)
{
   uint32_t cpu;
   cpu = smp_processor_id();

    printk("%d STM-LINUX: RscType       : %08x\n", cpu, Resource->Header.RscType);
    printk("%d STM-LINUX: RscLength     : %04x\n", cpu, Resource->Header.Length);
    printk("%d STM-LINUX: ReturnStatus  : %04x\n", cpu, Resource->Header.ReturnStatus);
    printk("%d STM-LINUX: IgnoreResource: %04x\n", cpu, Resource->Header.IgnoreResource);
}

/*
 * This function dumps STM resource node.
 */
void dump_stm_resource_node(STM_RSC *Resource)
{
    uint8_t pci_index;
    uint32_t cpu;

    cpu = smp_processor_id();

    switch (Resource->Header.RscType)
    {
        case END_OF_RESOURCES:
            printk("%d STM-LINUX: END_OF_RESOURCES:\n", cpu);
            dump_stm_resource_header(Resource);
            printk("%d STM-LINUX: ResourceListContinuation : %016llx\n", \
                cpu, Resource->End.ResourceListContinuation);
            break;
        case MEM_RANGE:
            printk("%d STM-LINUX: MEM_RANGE:\n", cpu);
            dump_stm_resource_header(Resource);
            printk("%d STM-LINUX: Base          : %016llx\n", cpu, Resource->Mem.Base);
            printk("%d STM-LINUX: Length        : %016llx\n", cpu, Resource->Mem.Length);
            printk("%d STM-LINUX: RWXAttributes : %08x\n", \
                cpu, (uint8_t)Resource->Mem.RWXAttributes);
            break;
        case IO_RANGE:
            printk("%d STM-LINUX: IO_RANGE:\n", cpu);
            dump_stm_resource_header(Resource);
            printk("%d STM-LINUX: Base          : %04x\n", cpu, (int)Resource->Io.Base);
            printk("%d STM-LINUX: Length        : %04x\n", cpu, (int)Resource->Io.Length);
            break;
        case MMIO_RANGE:
            printk("%d STM-LINUX: MMIO_RANGE:\n", cpu);
            dump_stm_resource_header(Resource);
            printk("%d STM-LINUX: Base          : %016llx\n", cpu, Resource->Mmio.Base);
            printk("%d STM-LINUX: Length        : %016llx\n", cpu, Resource->Mmio.Length);
            printk("%d STM-LINUX: RWXAttributes : %08x\n", \
                cpu, (uint8_t)Resource->Mmio.RWXAttributes);
            break;
        case MACHINE_SPECIFIC_REG:
            printk("%d STM-LINUX: MSR_RANGE:\n", cpu);
            dump_stm_resource_header(Resource);
            printk("%d STM-LINUX: MsrIndex      : %08x\n", \
                cpu, (uint8_t)Resource->Msr.MsrIndex);
            printk("%d STM-LINUX: KernelModeProc: %08x\n", \
                cpu,(uint8_t)Resource->Msr.KernelModeProcessing);
            printk("%d STM-LINUX: ReadMask      : %016llx\n", cpu, Resource->Msr.ReadMask);
            printk("%d STM-LINUX: WriteMask     : %016llx\n", \
                cpu, Resource->Msr.WriteMask);
            break;
        case PCI_CFG_RANGE:
            printk("%d STM-LINUX: PCI_CFG_RANGE:\n", cpu);
            dump_stm_resource_header(Resource);
            printk("%d STM-LINUX: RWAttributes  : %04x\n", \
                cpu, (int)Resource->PciCfg.RWAttributes);
            printk("%d STM-LINUX: Base          : %04x\n", \
                cpu, (int)Resource->PciCfg.Base);
            printk("%d STM-LINUX: Length        : %04x\n", \
                cpu, (int)Resource->PciCfg.Length);
            printk("%d STM-LINUX: OriginatingBus: %02x\n", \
                cpu, (int)Resource->PciCfg.OriginatingBusNumber);
            printk("%d STM-LINUX: LastNodeIndex : %02x\n", \
                cpu, (int)Resource->PciCfg.LastNodeIndex);

            for (pci_index = 0; pci_index < Resource->PciCfg.LastNodeIndex + 1;\
                   pci_index++)
            {
                printk("%d STM-LINUX: Type          : %02x\n", \
                    cpu, (int)Resource->PciCfg.PciDevicePath[pci_index].Type);
                printk("%d STM-LINUX: Subtype       : %02x\n", \
                    cpu, (int)Resource->PciCfg.PciDevicePath[pci_index].Subtype);
                printk("%d STM-LINUX: Length        : %04x\n", \
                    cpu, (int)Resource->PciCfg.PciDevicePath[pci_index].Length);
                printk("%d STM-LINUX: PciDevice     : %02x\n", \
                    cpu, (int)Resource->PciCfg.PciDevicePath[pci_index].PciDevice);
                printk("%d STM-LINUX: PciFunction   : %02x\n", \
                    cpu, (int)Resource->PciCfg.PciDevicePath[pci_index].PciFunction);
            }
            break;
        case TRAPPED_IO_RANGE:
            printk("%d STM-LINUX: TRAPPED_IO_RANGE:\n", cpu);
            dump_stm_resource_header(Resource);
            printk("%d STM-LINUX: Base          : %04x\n", \
                cpu, (int)Resource->TrappedIo.Base);
            printk("%d STM-LINUX: Length        : %04x\n", \
                cpu, (int)Resource->TrappedIo.Length);
            printk("%d STM-LINUX: In            : %04x\n", \
                cpu, (int)Resource->TrappedIo.In);
            printk("%d STM-LINUX: Out           : %04x\n", \
                cpu, (int)Resource->TrappedIo.Out);
            printk("%d STM-LINUX: Api           : %04x\n", \
                cpu, (int)Resource->TrappedIo.Api);
            break;
        case ALL_RESOURCES:
            printk("%d STM-LINUX: ALL_RESOURCES:\n", cpu);
            dump_stm_resource_header(Resource);
            break;
        case REGISTER_VIOLATION:
            printk("%d STM-LINUX: REGISTER_VIOLATION:\n", cpu);
            dump_stm_resource_header(Resource);
            printk("%d STM-LINUX: RegisterType  : %08x\n", \
                cpu, (uint8_t)Resource->RegisterViolation.RegisterType);
            printk("%d STM-LINUX: ReadMask      : %016llx\n", \
                cpu, Resource->RegisterViolation.ReadMask);
            printk("%d STM-LINUX: WriteMask     : %016llx\n", \
                cpu, Resource->RegisterViolation.WriteMask);
            break;
        default:
            dump_stm_resource_header(Resource);
            break;
    }
}

/*
 * This function dumps STM resource list.
 */
void dump_stm_resource(STM_RSC *Resource)
{
    while (Resource->Header.RscType != END_OF_RESOURCES)
    {
        dump_stm_resource_node(Resource);
        Resource = (STM_RSC *)((uint64_t)Resource + Resource->Header.Length);
    }
    /* Dump End Node */
    dump_stm_resource_node(Resource);

    if (Resource->End.ResourceListContinuation != 0)
        dump_stm_resource( \
                (STM_RSC *)(uint64_t)Resource->End.ResourceListContinuation);
}

static int  stm_shutdown(struct notifier_block *notifier, unsigned long val, void *v)
{
	int cpu = smp_processor_id();

	printk("%d STM-LINUX: stm_shutdown entered\n", cpu);
	
	if(atomic_read(&is_stm) != 0x01)
		return 0;

	smp_mb__before_atomic();
        atomic_set(&stmbsp_done, 0);
        atomic_set(&number_ap, 0);
	smp_mb__after_atomic();

        printk("%d STM-LINUX Shutting down STM (%d)\n", cpu, atomic_read(&is_stm));

        smp_call_function(teardown_stm, NULL, 0);
        teardown_stm(NULL);

        while(atomic_read(&stmbsp_done) == 0)
        {};

        smp_mb__before_atomic();
        atomic_set(&is_stm, STM_SHUTDOWN);  // STM is shutdoqn 
        smp_mb__after_atomic();

        printk("%d STM-LINUX STM shutdown complete\n", cpu);
	return 0;
}

static int stm_start(void);

static int stm_reboot(struct notifier_block *notifier, unsigned long val, void *v)
{
	stm_start();
	local_irq_enable();

	return NOTIFY_OK;
}

static int stm_pm_notifier(struct notifier_block *nb, unsigned long mode, void *_unused)
{
	switch(mode)
	{
		case PM_HIBERNATION_PREPARE:
/*debug*/		printk("STM-LINUX: stm_pm_notifier: PM_HIBERNATION_PREPARE\n");
			stm_shutdown( nb, mode, _unused);
			smp_mb__before_atomic();
			atomic_set(&is_stm, STM_SHUTDOWN_PM);
			smp_mb__after_atomic();
			break;

		case PM_POST_HIBERNATION:
			printk("STM-LINUX: stm_pm_notifier: PM_POST_HIBERNATION\n");
			stm_reboot( nb, mode, _unused);
			break;

		case PM_SUSPEND_PREPARE:
			printk("STM-LINUX: stm_pm_notifier: PM_SUSPEND_PREPARE\n");
			stm_shutdown( nb, mode, _unused);
                        smp_mb__before_atomic();
                        atomic_set(&is_stm, STM_SHUTDOWN_PM);
                        smp_mb__after_atomic();
			break;

		case PM_POST_SUSPEND:
			printk("STM-LINUX: stm_pm_notifier: PM_POST_SUSPEND\n");
			stm_reboot(nb, mode, _unused);
			break;

		case PM_RESTORE_PREPARE:
			printk("STM-LINUX: stm_pm_notifier: PM_RESTORE_PREPARE - no action\n");
			break;

		case PM_POST_RESTORE:
			printk("STM-LINUX: stm_pm_notifier: PM_POST_RESTORE - no action\n");
			break;

		default:
			printk("STM-LINUX: stm_pm_notifier mode; %ld\n", mode);
			break;
	}
	return 0;
}

static struct notifier_block stm_reboot_notifier =
{
	.notifier_call = stm_shutdown,
	.priority = 1,     // priority must be higher than kvm_reboot
};

static struct notifier_block stm_notifier_block =
{
	.notifier_call = stm_pm_notifier,
	.priority = 1,
};

static int stm_start(void)
{
	int cpu = smp_processor_id();	
	int result = 0;
	printk("%d STM-LINUX: starting launch_stm on all processors\n", cpu);

        smp_mb__before_atomic();
        atomic_set(&bspready, 0);
        smp_mb__after_atomic();
        smp_call_function(launch_stm, NULL, 0);

        printk("%d STM-LINUX: starting launch_stm on this processor\n", cpu);
        launch_stm(NULL);

        printk("%d STM-LINUX: Waiting for APs and BSP to finis\n", cpu);
        while(atomic_read(&stmbsp_done) == 0)
        {};

	if((atomic_read(&is_stm) == 0x2) ||
           (atomic_read(&is_stm) == 0x3))
        {
                printk("%d STM-LINUX: STM launch failed\n", cpu);
                //local_irq_enable();
                return -1;
        }
        smp_mb__before_atomic();
        atomic_set(&is_stm, 0x01);  // STM is up
        smp_mb__after_atomic();
        printk("%d STM-LINUX: STM apparently launched (%d)\n", cpu, atomic_read(&is_stm));

	return result;
}

static int boot_stm(void)
{
        int cpu = smp_processor_id();
	struct file *nmi_watchdog_f;
	int nmi_watchdog_cfg_i;

	loff_t position;
	char nmi_watchdog_cfg[25];
	char nmi_watchdog_result[25];

        struct file *threshold_watchdog_f;
	
	smp_mb__before_atomic();
	atomic_set(&stmbsp_done, 0);
	atomic_set(&is_stm, 0);
	atomic_set(&number_ap, 0);
	smp_mb__after_atomic();

	// turn off the watchdog for STM startup
	nmi_watchdog_f = filp_open("/proc/sys/kernel/nmi_watchdog", O_RDWR, 0);
	printk("%d STM-LINUX - watchdog proc file opened\n", cpu);
	
	if (IS_ERR(nmi_watchdog_f))
	{
		printk("%d STM-LINUX: error %ld opening nmi watchdog\n", cpu, PTR_ERR(nmi_watchdog_f)); 
	}
	else
	{
		int err = 0;
		int count;
		printk("%d STM-LINUX - reading nmi watchdog config\n", cpu);
		position = 0;
		count = kernel_read(nmi_watchdog_f, (char *)&nmi_watchdog_cfg,
					sizeof(nmi_watchdog_cfg), &position);

		sscanf(nmi_watchdog_cfg, "%d", &nmi_watchdog_cfg_i);
		
		printk("%d STM-LINUX nmi_watchdog_cfg %d count:%d\n", cpu, nmi_watchdog_cfg_i, count);
		
		if(strncmp(nmi_watchdog_cfg, "0", 1) !=0)
		{
			printk("%d STM-LINUX turning off nmi watchdog\n", cpu);
			position = 0;
			err = kernel_write(nmi_watchdog_f, "0", 1, &position);
		}
		position = 0;

		kernel_read(nmi_watchdog_f, (char *)&nmi_watchdog_result, sizeof(nmi_watchdog_result), &position);
		sscanf(nmi_watchdog_result, "%d", &nmi_watchdog_cfg_i);
                printk("%d STM-LINUX nmi_watchdog_cfg - after %d err=%d\n", cpu, nmi_watchdog_cfg_i, err);
	}

	threshold_watchdog_f = filp_open("/proc/sys/kernel/watchdog_thresh", O_RDWR, 0);

	if (IS_ERR(nmi_watchdog_f))
        {
                printk("%d STM-LINUX: error %ld opening threshold watchdog\n", cpu, PTR_ERR(nmi_watchdog_f));
        }
        else
        {
                int err = 0;
                int count;
                printk("%d STM-LINUX - reading threshold watchdog config\n", cpu);
                position = 0;
                count = kernel_read(threshold_watchdog_f, (char *)&nmi_watchdog_cfg,
					sizeof(nmi_watchdog_cfg), &position);

                sscanf(nmi_watchdog_cfg, "%d", &nmi_watchdog_cfg_i);

                printk("%d STM-LINUX threshold_watchdog_cfg %d count:%d\n", cpu, nmi_watchdog_cfg_i, count);

                {
                        printk("%d STM-LINUX increasing threshold watchdog\n", cpu);
                        position = 0;
                        err = kernel_write(nmi_watchdog_f, "60", 3, &position);
                }
                position = 0;

		kernel_read(threshold_watchdog_f, (char *)&nmi_watchdog_result,
					sizeof(nmi_watchdog_result), &position);

                sscanf(nmi_watchdog_result, "%d", &nmi_watchdog_cfg_i);
                printk("%d STM-LINUX threshold_watchdog_cfg - after %d err=%d\n", cpu, nmi_watchdog_cfg_i, err);
        }

	stm_start();
		
	if(strncmp(nmi_watchdog_cfg, "0", 1) !=0)
	{
		printk("%d STM-LINUX - restarting nmi_watchdog\n", cpu);
		kernel_write(nmi_watchdog_f, (char *)&nmi_watchdog_cfg, strlen(nmi_watchdog_cfg), &position);
	}
	return 0;
}

static int stm_suspend(void)
{
	struct notifier_block *notifier = NULL;
	unsigned long val = 0;
	void *v = NULL;
	printk("STM-LINUX: stm_suspend\n");
	
        stm_shutdown(notifier, val, v);
        return 0;
}

static void stm_resume(void)
{
	// this is necessary because in the case of hibernate
	// the cpus get shutdown before the STM can be suspended
	// in that case - the STM gets shutdown at PM_HIBERNATE_PREPARE 

	printk("STM-LINUX: stm_resume\n");

	if(atomic_read(&is_stm) != STM_SHUTDOWN)
		return;
 
        stm_start();
}

static struct syscore_ops stm_syscore_ops =
{
        .suspend = stm_suspend,
        .resume = stm_resume,
};

static int __init start_stm(void)
{
	int retval;
	int status;
        struct file *kvm_f;
        int cpu = smp_processor_id();

//	cpu_hotplug_disable();

	printk("%d STM-LINUX: make sure KVM is loaded\n", cpu);
        status = request_module("kvm-intel");
        printk("%d STM-LINUX: request_module status: %d\n", cpu, status);

        // get KVM to get the processor into VT-X mode
        printk("%d STM-LINUX - faking KVM\n", cpu);
        kvm_f = filp_open("/dev/kvm", O_WRONLY, 0);

        status = kvm_f->f_op->unlocked_ioctl(kvm_f, KVM_CREATE_VM, 0);

	printk("STM-LINUX: VM created - status: %d\n", status);

        // keep KVM from getting out of VT-X mode
        // if tries a GP fault will happen
        status = kvm_f->f_op->unlocked_ioctl(kvm_f, KVM_BUMP_USAGE_COUNT, 0);
        printk("%d STM-LINUX = kvm faked - status %d\n", cpu, status);

	retval = boot_stm();

	register_reboot_notifier(&stm_reboot_notifier);

	register_syscore_ops(&stm_syscore_ops);

	register_pm_notifier(&stm_notifier_block);

	local_irq_enable();
	return retval;
}

static void __exit stop_stm(void)
{
	struct notifier_block *notifier = NULL;
	unsigned long val = 0;
	void *v = NULL;;

	stm_shutdown(notifier, val, v);
        unregister_reboot_notifier(&stm_reboot_notifier);
	unregister_pm_notifier(&stm_notifier_block);
//	cpu_hotplug_enable();
}

module_init(start_stm);
module_exit(stop_stm);
