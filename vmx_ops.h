#ifndef VMX_OPS
#define VMX_OPS

#include "vmcs.h"

void vmclear_error(struct vmcs *vmcs, u64 phys_addr);
void dmm_fault(void);

#define vmx_asm1(insn, op1, error_args...)                              \
do {                                                                    \
        asm_volatile_goto("1: " __stringify(insn) " %0\n\t"             \
                          ".byte 0x2e\n\t" /* branch not taken hint */  \
                          "jna %l[error]\n\t"                           \
                          _ASM_EXTABLE(1b, %l[fault])                   \
                          : : op1 : "cc" : error, fault);               \
        return;                                                         \
error: 									\
        /*instrumentation_begin();*/                                    \
        insn##_error(error_args);                                       \
        /*instrumentation_end();*/                                      \
        return;                                                         \
fault:                                                                  \
	dmm_fault();							\
	return;								\
} while (0)

static inline void vmcs_clear(struct vmcs *vmcs)
{
        u64 phys_addr = __pa(vmcs);

        vmx_asm1(vmclear, "m"(phys_addr), vmcs, phys_addr);
}


#endif
