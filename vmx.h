/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef STM_VMX_H
#define STM_VMX_H

#define CPUID_VMX_BIT				5

#define CPUID_VMX				(1 << 5)

//#include "evmcs.h"

static inline int vmxon(uint64_t phys)
{
	uint8_t ret;

	__asm__ __volatile__ ("vmxon %[pa]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [pa]"m"(phys)
		: "cc", "memory");

	return ret;
}

static inline void vmxoff(void)
{
	__asm__ __volatile__("vmxoff");
}

static inline int vmclear(uint64_t vmcs_pa)
{
	uint8_t ret;

	__asm__ __volatile__ ("vmclear %[pa]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [pa]"m"(vmcs_pa)
		: "cc", "memory");

	return ret;
}

static inline int vmptrld(uint64_t vmcs_pa)
{
	uint8_t ret;

	__asm__ __volatile__ ("vmptrld %[pa]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [pa]"m"(vmcs_pa)
		: "cc", "memory");

	return ret;
}

static inline int vmptrst(uint64_t *value)
{
	uint64_t tmp;
	uint8_t ret;

	__asm__ __volatile__("vmptrst %[value]; setna %[ret]"
		: [value]"=m"(tmp), [ret]"=rm"(ret)
		: : "cc", "memory");

	*value = tmp;
	return ret;
}

/*
 * A wrapper around vmptrst that ignores errors and returns zero if the
 * vmptrst instruction fails.
 */
static inline uint64_t vmptrstz(void)
{
	uint64_t value = 0;
	vmptrst(&value);
	return value;
}

/*
 * No guest state (e.g. GPRs) is established by this vmlaunch.
 */
static inline int vmlaunch(void)
{
	int ret;

	__asm__ __volatile__("push %%rbp;"
			     "push %%rcx;"
			     "push %%rdx;"
			     "push %%rsi;"
			     "push %%rdi;"
			     "push $0;"
			     "vmwrite %%rsp, %[host_rsp];"
			     "lea 1f(%%rip), %%rax;"
			     "vmwrite %%rax, %[host_rip];"
			     "vmlaunch;"
			     "incq (%%rsp);"
			     "1: pop %%rax;"
			     "pop %%rdi;"
			     "pop %%rsi;"
			     "pop %%rdx;"
			     "pop %%rcx;"
			     "pop %%rbp;"
			     : [ret]"=&a"(ret)
			     : [host_rsp]"r"((uint64_t)HOST_RSP),
			       [host_rip]"r"((uint64_t)HOST_RIP)
			     : "memory", "cc", "rbx", "r8", "r9", "r10",
			       "r11", "r12", "r13", "r14", "r15");
	return ret;
}

/*
 * No guest state (e.g. GPRs) is established by this vmresume.
 */
static inline int vmresume(void)
{
	int ret;

	__asm__ __volatile__("push %%rbp;"
			     "push %%rcx;"
			     "push %%rdx;"
			     "push %%rsi;"
			     "push %%rdi;"
			     "push $0;"
			     "vmwrite %%rsp, %[host_rsp];"
			     "lea 1f(%%rip), %%rax;"
			     "vmwrite %%rax, %[host_rip];"
			     "vmresume;"
			     "incq (%%rsp);"
			     "1: pop %%rax;"
			     "pop %%rdi;"
			     "pop %%rsi;"
			     "pop %%rdx;"
			     "pop %%rcx;"
			     "pop %%rbp;"
			     : [ret]"=&a"(ret)
			     : [host_rsp]"r"((uint64_t)HOST_RSP),
			       [host_rip]"r"((uint64_t)HOST_RIP)
			     : "memory", "cc", "rbx", "r8", "r9", "r10",
			       "r11", "r12", "r13", "r14", "r15");
	return ret;
}

static inline void vmcall(void)
{
	/* Currently, L1 destroys our GPRs during vmexits.  */
	__asm__ __volatile__("push %%rbp; vmcall; pop %%rbp" : : :
			     "rax", "rbx", "rcx", "rdx",
			     "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
			     "r13", "r14", "r15");
}

static inline int vmread(uint64_t encoding, uint64_t *value)
{
	uint64_t tmp;
	uint8_t ret;

	__asm__ __volatile__("vmread %[encoding], %[value]; setna %[ret]"
		: [value]"=rm"(tmp), [ret]"=rm"(ret)
		: [encoding]"r"(encoding)
		: "cc", "memory");

	*value = tmp;
	return ret;
}

/*
 * A wrapper around vmread that ignores errors and returns zero if the
 * vmread instruction fails.
 */
static inline uint64_t vmreadz(uint64_t encoding)
{
	uint64_t value = 0;
	vmread(encoding, &value);
	return value;
}

static inline int vmwrite(uint64_t encoding, uint64_t value)
{
	uint8_t ret;

	__asm__ __volatile__ ("vmwrite %[value], %[encoding]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [value]"rm"(value), [encoding]"r"(encoding)
		: "cc", "memory");

	return ret;
}

union vmx_basic {
	u64 val;
	struct {
		u32 revision;
		u32	size:13,
			reserved1:3,
			width:1,
			dual:1,
			type:4,
			insouts:1,
			ctrl:1,
			vm_entry_exception_ctrl:1,
			reserved2:7;
	};
};

union vmx_ctrl_msr {
	u64 val;
	struct {
		u32 set, clr;
	};
};


#endif /* SELFTEST_KVM_VMX_H */
