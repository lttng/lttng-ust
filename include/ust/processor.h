/* Copyright (C) 2009  Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#ifndef UST_PROCESSOR_H
#define UST_PROCESSOR_H

#include <stddef.h>
#include <string.h>

extern __thread long ust_reg_stack[500];
extern volatile __thread long *ust_reg_stack_ptr;

#ifdef __i386

struct registers {
	short ss;
	short cs;
	long esi;
	long ebp;
	long edx;
	long edi;
	long ecx;
	long ebx;
	long eax;
	long eflags;
	long esp;
};

static inline int fls(int x)
{
        int r;
        asm("bsrl %1,%0\n\t"
            "cmovzl %2,%0"
            : "=&r" (r) : "rm" (x), "rm" (-1));
        return r + 1;
}

#ifdef CONFIG_UST_GDB_INTEGRATION

/* save_registers - saves most of the processor's registers so
 * they are available to the probe. gdb uses this to give the
 * value of local variables.
 *
 * Saving all registers without losing any of their values is
 * tricky.
 *
 * We cannot pass to the asm stub the address of a registers structure
 * on the stack, because it will use a register and override its value.
 *
 * We don't want to use a stub to push the regs on the stack and then
 * another stub to copy them to a structure because changing %sp in asm
 * and then returning to C (even briefly) can have unexpected results.
 * Also, gcc might modify %sp between the stubs in reaction to the
 * register needs of the second stub that needs to know where to copy
 * the register values.
 *
 * So the chosen approach is to use another stack, declared in thread-
 * local storage, to push the registers. They are subsequently copied
 * to the stack, by C code.
 */

#define save_registers(regsptr) \
	asm volatile ( \
	     /* save original esp */ \
	     "pushl %%esp\n\t" \
	     /* push original eflags */ \
	     "pushfl\n\t" \
	      /* eax will hold the ptr to the private stack bottom */ \
	     "pushl %%eax\n\t" \
	     /* ebx is used for TLS access */ \
	     "pushl %%ebx\n\t" \
	     /* ecx will be used to temporarily hold the stack bottom addr */\
	     "pushl %%ecx\n\t"						     \
	     /* rdi is the input to __tls_get_addr, and also a temp var */   \
	     "pushl %%edi\n\t"						     \
	     /* For TLS access, we have to do function calls. However,	     \
	      * we must not lose the original value of:			     \
	      *   esp, eflags, eax, ebx, ecx, edx, esi, edi, ebp, cs, ss     \
	      *								     \
	      * Some registers' original values have already been saved:     \
	      *   esp, eflags, eax, ebx, ecx, edi			     \
	      *								     \
	      * In addition, the i386 ABI says the following registers belong\
	      * to the caller function:					     \
	      *   esp, ebp, esi, edi, ebx				     \
	      *								     \
	      * The following registers should not be changed by the callee: \
	      *   cs, ss						     \
	      *								     \
	      * Therefore, the following registers must be explicitly 	     \
	      * preserved:						     \
	      *   edx							     \
	      */ \
	     "pushl %%edx\n\t" \
	     /* Get GOT address */ \
	     "call __i686.get_pc_thunk.bx\n\t" \
	     "addl $_GLOBAL_OFFSET_TABLE_, %%ebx\n\t" \
	     /* Start TLS access of private reg stack pointer */ \
	     "leal ust_reg_stack_ptr@tlsgd(,%%ebx,1),%%eax\n\t" \
	     "call ___tls_get_addr@plt\n\t" \
	     /* --- End TLS access */ \
	     /* check if ust_reg_stack_ptr has been initialized */ \
	     "movl (%%eax),%%ecx\n\t" \
	     "testl %%ecx,%%ecx\n\t" \
	     "jne 1f\n\t" \
	     "movl %%eax,%%ecx\n\t" \
	     /* Save ecx because we are using it. */ \
	     "pushl %%ecx\n\t" \
	     /* Start TLS access of private reg stack */ \
	     "leal ust_reg_stack@tlsgd(,%%ebx,1),%%eax\n\t" \
	     "call ___tls_get_addr@plt\n\t" \
	     /* --- End TLS access */ \
	     "popl %%ecx\n\t" \
	     "addl $500,%%eax\n\t" \
	     "movl %%eax,(%%ecx)\n\t" \
	     "movl %%ecx,%%eax\n\t" \
	     /* now the pointer to the private stack is in eax. \
	        must add stack size so the ptr points to the stack bottom. */ \
	"1:\n\t" \
	     /* edx was pushed for function calls */ \
	     "popl %%edx\n\t" \
	     /* Manually push esp to private stack */ \
	     "addl $-4,(%%eax)\n\t" \
	     "movl 20(%%esp), %%edi\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movl %%edi, (%%ebx)\n\t" \
	     /* Manually push eflags to private stack */ \
	     "addl $-4,(%%eax)\n\t" \
	     "movl 16(%%esp), %%edi\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movl %%edi, (%%ebx)\n\t" \
	     /* Manually push eax to private stack */ \
	     "addl $-4,(%%eax)\n\t" \
	     "movl 12(%%esp), %%edi\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movl %%edi, (%%ebx)\n\t" \
	     /* Manually push ebx to private stack */ \
	     "addl $-4,(%%eax)\n\t" \
	     "movl 8(%%esp), %%edi\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movl %%edi, (%%ebx)\n\t" \
	     /* Manually push ecx to private stack */ \
	     "addl $-4,(%%eax)\n\t" \
	     "movl 4(%%esp), %%edi\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movl %%edi, (%%ebx)\n\t" \
	     /* Manually push edi to private stack */ \
	     "addl $-4,(%%eax)\n\t" \
	     "movl 0(%%esp), %%edi\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movl %%edi, (%%ebx)\n\t" \
	     /* now push regs to tls */ \
	     /* -- esp already pushed -- */ \
	     /* -- eax already pushed -- */ \
	     /* -- ebx already pushed -- */ \
	     /* -- ecx already pushed -- */ \
	     /* -- edi already pushed -- */ \
	     "addl $-4,(%%eax)\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movl %%edx,(%%ebx)\n\t" \
	     "addl $-4,(%%eax)\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movl %%ebp,(%%ebx)\n\t" \
	     "addl $-4,(%%eax)\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movl %%esi,(%%ebx)\n\t" \
	     /* push cs */ \
	     "addl $-2,(%%eax)\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movw %%cs, (%%ebx)\n\t" \
	     /* push ss */ \
	     "addl $-2,(%%eax)\n\t" \
	     "movl (%%eax), %%ebx\n\t" \
	     "movw %%ss, (%%ebx)\n\t" \
	     /* restore original values of regs that were used internally */ \
	     "popl %%edi\n\t" \
	     "popl %%ecx\n\t" \
	     "popl %%ebx\n\t" \
	     "popl %%eax\n\t" \
	     /* cancel push of rsp */ \
	     "addl $4,%%esp\n\t" \
	     /* cancel push of eflags */ \
	     "addl $4,%%esp\n\t" \
	     ::: "memory"); \
	memcpy(regsptr, (void *)ust_reg_stack_ptr, sizeof(struct registers)); \
	ust_reg_stack_ptr = (void *)(((long)ust_reg_stack_ptr) + sizeof(struct registers));

#else /* CONFIG_UST_GDB_INTEGRATION */

#define save_registers(a)

#endif /* CONFIG_UST_GDB_INTEGRATION */

#define RELATIVE_ADDRESS(__rel_label__) __rel_label__

#define ARCH_COPY_ADDR(dst) "lea 2b," dst "\n\t"

#define _ASM_PTR ".long "

#endif /* below is code for x86-64 */

#ifdef __x86_64

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

static inline int fls(int x)
{
        int r;
        asm("bsrl %1,%0\n\t"
            "cmovzl %2,%0"
            : "=&r" (r) : "rm" (x), "rm" (-1));
        return r + 1;
}

#ifdef CONFIG_UST_GDB_INTEGRATION

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
	     /* For TLS access, we have to do function calls. However,	     \
	      * we must not lose the original value of:			     \
	      *   rsp, rflags, rax, rbx, rcx, rdx, rsi, rdi, rbp, r8, r9     \
	      *   r10, r11, r12, r13, r14, r15, cs, ss			     \
	      *								     \
	      * Some registers' original values have already been saved:     \
	      *   rsp, rflags, rax, rbx, rdi				     \
	      *								     \
	      * In addition, the x86-64 ABI says the following registers     \
	      * belong to the caller function:				     \
	      *   rbp, rbx, r12, r13, r14, r15				     \
	      *								     \
	      * The following registers should not be changed by the callee: \
	      *   cs, ss						     \
	      *								     \
	      * Therefore, the following registers must be explicitly 	     \
	      * preserved:						     \
	      *   rcx, rdx, rsi, r8, r9, r10, r11			     \
	      */ \
	     "pushq %%rcx\n\t" \
	     "pushq %%rdx\n\t" \
	     "pushq %%rsi\n\t" \
	     "pushq %%r8\n\t" \
	     "pushq %%r9\n\t" \
	     "pushq %%r10\n\t" \
	     "pushq %%r11\n\t" \
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
	     /* Pop regs that were pushed for function calls */ \
	     "popq %%r11\n\t" \
	     "popq %%r10\n\t" \
	     "popq %%r9\n\t" \
	     "popq %%r8\n\t" \
	     "popq %%rsi\n\t" \
	     "popq %%rdx\n\t" \
	     "popq %%rcx\n\t" \
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

#else /* CONFIG_UST_GDB_INTEGRATION */

#define save_registers(a)

#endif /* CONFIG_UST_GDB_INTEGRATION */

/* Macro to insert the address of a relative jump in an assembly stub,
 * in a relocatable way. On x86-64, this uses a special (%rip) notation. */
#define RELATIVE_ADDRESS(__rel_label__) __rel_label__(%%rip)

#define ARCH_COPY_ADDR(dst) "lea 2b(%%rip)," dst "\n\t"

#define _ASM_PTR ".quad "

#endif /* x86_64 */

#ifdef __PPC__

struct registers {
};

static __inline__ int fls(unsigned int x)
{
        int lz;

        asm ("cntlzw %0,%1" : "=r" (lz) : "r" (x));
        return 32 - lz;
}

#define ARCH_COPY_ADDR(dst) \
		     "lis " dst ",2b@h\n\t" /* load high bytes */ \
		     "ori " dst "," dst ",2b@l\n\t" /* load low bytes */

#define _ASM_PTR ".long "
#define save_registers(a)

#endif /* __PPC__ */

#endif /* UST_PROCESSOR_H */
