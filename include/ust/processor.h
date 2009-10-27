#ifndef UST_PROCESSOR_H
#define UST_PROCESSOR_H

#include <stddef.h>

#ifdef X86_32

struct registers {
	long eax;
	long ebx;
	long ecx;
	long edx;
	long ebp;
	long esp;
	long esi;
	long edi;
	int  xds;
	int  xes;
	int  xfs;
	int  xgs;
	long eip;
	int  xcs;
	long eflags;
	int  xss;
};

static inline save_registers(struct registers *regs)
{
}

#define RELATIVE_ADDRESS(__rel_label__) __rel_label__

#define _ASM_PTR ".long "

#else

struct registers {
	unsigned long rax;
	unsigned long rbx;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rbp;
	unsigned long rsp;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
	int cs;
	int ss;
};

#define save_registers(regsptr) \
	asm ("movq %%rax,%c[rax_off](%[regs])\n\t" \
	     "movq %%rbx,%c[rbx_off](%[regs])\n\t" \
	     "movq %%rcx,%c[rcx_off](%[regs])\n\t" \
	     "movq %%rdx,%c[rdx_off](%[regs])\n\t" \
	     "movq %%rbp,%c[rbp_off](%[regs])\n\t" \
	     "movq %%rsp,%c[rsp_off](%[regs])\n\t" \
	     "movq %%rsi,%c[rsi_off](%[regs])\n\t" \
	     "movq %%rdi,%c[rdi_off](%[regs])\n\t" \
	     "movq %%r8,%c[r8_off](%[regs])\n\t" \
	     "movq %%r9,%c[r9_off](%[regs])\n\t" \
	     "movq %%r10,%c[r10_off](%[regs])\n\t" \
	     "movq %%r11,%c[r11_off](%[regs])\n\t" \
	     "movq %%r12,%c[r12_off](%[regs])\n\t" \
	     "movq %%r13,%c[r13_off](%[regs])\n\t" \
	     "movq %%r14,%c[r14_off](%[regs])\n\t" \
	     "movq %%r15,%c[r15_off](%[regs])\n\t" \
	     "movw %%cs,%c[cs_off](%[regs])\n\t" \
	     "movw %%ss,%c[ss_off](%[regs])\n\t" \
	: \
	: [regs] "r" (regsptr), \
	  [rax_off] "i" (offsetof(struct registers, rax)), \
	  [rbx_off] "i" (offsetof(struct registers, rbx)), \
	  [rcx_off] "i" (offsetof(struct registers, rcx)), \
	  [rdx_off] "i" (offsetof(struct registers, rdx)), \
	  [rbp_off] "i" (offsetof(struct registers, rbp)), \
	  [rsp_off] "i" (offsetof(struct registers, rsp)), \
	  [rsi_off] "i" (offsetof(struct registers, rsi)), \
	  [rdi_off] "i" (offsetof(struct registers, rdi)), \
	  [r8_off] "i" (offsetof(struct registers, r8)), \
	  [r9_off] "i" (offsetof(struct registers, r9)), \
	  [r10_off] "i" (offsetof(struct registers, r10)), \
	  [r11_off] "i" (offsetof(struct registers, r11)), \
	  [r12_off] "i" (offsetof(struct registers, r12)), \
	  [r13_off] "i" (offsetof(struct registers, r13)), \
	  [r14_off] "i" (offsetof(struct registers, r14)), \
	  [r15_off] "i" (offsetof(struct registers, r15)), \
	  [cs_off] "i" (offsetof(struct registers, cs)), \
	  [ss_off] "i" (offsetof(struct registers, ss)) \
	);

/* Macro to insert the address of a relative jump in an assembly stub,
 * in a relocatable way. On x86-64, this uses a special (%rip) notation. */
#define RELATIVE_ADDRESS(__rel_label__) __rel_label__(%%rip)

#define _ASM_PTR ".quad "

#endif

#endif /* UST_PROCESSOR_H */
