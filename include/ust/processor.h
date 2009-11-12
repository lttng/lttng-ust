#ifndef UST_PROCESSOR_H
#define UST_PROCESSOR_H

#include <stddef.h>
#include <string.h>

extern __thread long ust_reg_stack[500];
extern volatile __thread long *ust_reg_stack_ptr;


#ifdef x86_32
#error "32-bit support broken"

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
	int padding; /* 4 bytes */
	short ss;
	short cs;
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rsi;
	unsigned long rbp;
	unsigned long rdx;
	unsigned long rcx;
	unsigned long rdi;
	unsigned long rbx;
	unsigned long rax;
	unsigned long rflags;
	unsigned long rsp;
};

#define save_registers(regsptr) \
	asm volatile ( \
	     /* save original rsp */ \
	     "pushq %%rsp\n\t" \
	     /* push original rflags */ \
	     "pushfq\n\t" \
	      /* rax will hold the ptr to the private stack bottom */ \
	     "pushq %%rax\n\t" \
	     /* rbx will be used to temporarily hold the stack bottom addr */ \
	     "pushq %%rbx\n\t" \
	     /* rdi is the input to __tls_get_addr, and also a temp var */ \
	     "pushq %%rdi\n\t" \
	     /* Start TLS access of private reg stack pointer */ \
	     ".byte 0x66\n\t" \
	     "leaq ust_reg_stack_ptr@tlsgd(%%rip), %%rdi\n\t" \
	     ".word 0x6666\n\t" \
	     "rex64\n\t" \
	     "call __tls_get_addr@plt\n\t" \
	     /* --- End TLS access */ \
	     /* check if ust_reg_stack_ptr has been initialized */ \
	     "movq (%%rax),%%rbx\n\t" \
	     "testq %%rbx,%%rbx\n\t" \
	     "jne 1f\n\t" \
	     "movq %%rax,%%rbx\n\t" \
	     /* Start TLS access of private reg stack */ \
	     ".byte 0x66\n\t" \
	     "leaq ust_reg_stack@tlsgd(%%rip), %%rdi\n\t" \
	     ".word 0x6666\n\t" \
	     "rex64\n\t" \
	     "call __tls_get_addr@plt\n\t" \
	     /* --- End TLS access */ \
	     "addq $500,%%rax\n\t" \
	     "movq %%rax,(%%rbx)\n\t" \
	     "movq %%rbx,%%rax\n\t" \
	     /* now the pointer to the private stack is in rax.
	        must add stack size so the ptr points to the stack bottom. */ \
	"1:\n\t" \
	     /* Manually push rsp to private stack */ \
	     "addq $-8,(%%rax)\n\t" \
	     "movq 32(%%rsp), %%rdi\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%rdi, (%%rbx)\n\t" \
	     /* Manually push eflags to private stack */ \
	     "addq $-8,(%%rax)\n\t" \
	     "movq 24(%%rsp), %%rdi\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%rdi, (%%rbx)\n\t" \
	     /* Manually push rax to private stack */ \
	     "addq $-8,(%%rax)\n\t" \
	     "movq 16(%%rsp), %%rdi\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%rdi, (%%rbx)\n\t" \
	     /* Manually push rbx to private stack */ \
	     "addq $-8,(%%rax)\n\t" \
	     "movq 8(%%rsp), %%rdi\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%rdi, (%%rbx)\n\t" \
	     /* Manually push rdi to private stack */ \
	     "addq $-8,(%%rax)\n\t" \
	     "movq 0(%%rsp), %%rdi\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%rdi, (%%rbx)\n\t" \
	     /* now push regs to tls */ \
	     /* -- rsp already pushed -- */ \
	     /* -- rax already pushed -- */ \
	     /* -- rbx already pushed -- */ \
	     /* -- rdi already pushed -- */ \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%rcx,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%rdx,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%rbp,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%rsi,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%r8,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%r9,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%r10,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%r11,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%r12,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%r13,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%r14,(%%rbx)\n\t" \
	     "addq $-8,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movq %%r15,(%%rbx)\n\t" \
	     /* push cs */ \
	     "addq $-2,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movw %%cs, (%%rbx)\n\t" \
	     /* push ss */ \
	     "addq $-2,(%%rax)\n\t" \
	     "movq (%%rax), %%rbx\n\t" \
	     "movw %%ss, (%%rbx)\n\t" \
	     /* add padding for struct registers */ \
	     "addq $-4,(%%rax)\n\t" \
	     /* restore original values of regs that were used internally */ \
	     "popq %%rdi\n\t" \
	     "popq %%rbx\n\t" \
	     "popq %%rax\n\t" \
	     /* cancel push of rsp */ \
	     "addq $8,%%rsp\n\t" \
	     /* cancel push of rflags */ \
	     "addq $8,%%rsp\n\t" \
	     ::); \
	memcpy(regsptr, (void *)ust_reg_stack_ptr, sizeof(struct registers)); \
	ust_reg_stack_ptr = (void *)(((long)ust_reg_stack_ptr) + sizeof(struct registers));

/* Macro to insert the address of a relative jump in an assembly stub,
 * in a relocatable way. On x86-64, this uses a special (%rip) notation. */
#define RELATIVE_ADDRESS(__rel_label__) __rel_label__(%%rip)

#define _ASM_PTR ".quad "

#endif

#endif /* UST_PROCESSOR_H */
