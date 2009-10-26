#ifndef UST_REGISTERS_H
#define UST_REGISTERS_H

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
	unsigned long rip;
	int cs;
	int ss;
};

static inline save_registers(struct registers *regs)
{
	asm ("movq %%rax,%c[rax_off](%[regs])\n\t"
/*	     "movq %%rax,%[rax_el]\n\t"
	     "movq %%rbx,%[rbx_el]\n\t"
	     "movq %%rcx,%[rcx_el]\n\t"
	     "movq %%rdx,%[rdx_el]\n\t"
	     "movq %%rbp,%[rbp_el]\n\t"
	     "movq %%rsp,%[rsp_el]\n\t"
	     "movq %%rsi,%[rsi_el]\n\t"
	     "movq %%rdi,%[rdi_el]\n\t"
	     "movq %%r8, %[r8_el]\n\t"
	     "movq %%r9, %[r9_el]\n\t"
	     "movq %%r10,%[r10_el]\n\t"
	     "movq %%r11,%[r11_el]\n\t"
	     "movq %%r12,%[r12_el]\n\t"
	     "movq %%r13,%[r13_el]\n\t"
	     "movq %%r14,%[r14_el]\n\t"
	     "movq %%r15,%[r15_el]\n\t"
	     "movw %%cs,%[cs_el]\n\t"
	     "movw %%ss,%[ss_el]\n\t"
	     "call getip\n\t"
	     "getip:\n\t"
	     "popq %[rip_el]\n\t" */
	: /* do output regs */
	: [rax_off] "i" (offsetof(struct registers, rax)),
	  [regs] "r" (regs)
/*	: [rax_el] "m" (regs->rax),
	  [rbx_el] "m" (regs->rbx),
	  [rcx_el] "m" (regs->rcx),
	  [rdx_el] "m" (regs->rdx),
	  [rbp_el] "m" (regs->rbp),
	  [rsp_el] "m" (regs->rsp),
	  [rsi_el] "m" (regs->rsi),
	  [rdi_el] "m" (regs->rdi),
	  [r8_el] "m" (regs->r8),
	  [r9_el] "m" (regs->r9),
	  [r10_el] "m" (regs->r10),
	  [r11_el] "m" (regs->r11),
	  [r12_el] "m" (regs->r12),
	  [r13_el] "m" (regs->r13),
	  [r14_el] "m" (regs->r14),
	  [r15_el] "m" (regs->r15),
	  [cs_el] "m" (regs->cs),
	  [ss_el] "m" (regs->ss),
	  [rip_el] "m" (regs->rip)*/
	);
}

#endif

#endif /* UST_REGISTERS_H */
