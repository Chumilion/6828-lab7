/* See COPYRIGHT for copyright information. */

#include <inc/mmu.h>
#include <inc/memlayout.h>
#include <inc/trap.h>

#include <kern/picirq.h>


###################################################################
# exceptions/interrupts
###################################################################

/* TRAPHANDLER defines a globally-visible function for handling a trap.
 * It pushes a trap number onto the stack, then jumps to _alltraps.
 * Use TRAPHANDLER for traps where the CPU automatically pushes an error code.
 *
 * You shouldn't call a TRAPHANDLER function from C, but you may
 * need to _declare_ one in C (for instance, to get a function pointer
 * during IDT setup).  You can declare the function with
 *   void NAME();
 * where NAME is the argument passed to TRAPHANDLER.
 */
#define TRAPHANDLER(name, num)						\
	.globl name;		/* define global symbol for 'name' */	\
	.type name, @function;	/* symbol type is function */		\
	.align 2;		/* align function definition */		\
	name:			/* function starts here */		\
	pushl $(num);							\
	jmp _alltraps

/* Use TRAPHANDLER_NOEC for traps where the CPU doesn't push an error code.
 * It pushes a 0 in place of the error code, so the trap frame has the same
 * format in either case.
 */
#define TRAPHANDLER_NOEC(name, num)					\
	.globl name;							\
	.type name, @function;						\
	.align 2;							\
	name:								\
	pushl $0;							\
	pushl $(num);							\
	jmp _alltraps

.text

/*
 * Lab 3: Your code here for generating entry points for the different traps.
 */
TRAPHANDLER_NOEC(F_DIVIDE, T_DIVIDE);
TRAPHANDLER_NOEC(F_DEBUG, T_DEBUG);
TRAPHANDLER_NOEC(F_NMI, T_NMI);
TRAPHANDLER_NOEC(F_BRKPT, T_BRKPT);
TRAPHANDLER_NOEC(F_OFLOW, T_OFLOW);
TRAPHANDLER_NOEC(F_BOUND, T_BOUND);
TRAPHANDLER_NOEC(F_ILLOP, T_ILLOP);
TRAPHANDLER_NOEC(F_DEVICE, T_DEVICE);
TRAPHANDLER(F_DBLFLT, T_DBLFLT);
TRAPHANDLER(F_TSS, T_TSS);
TRAPHANDLER(F_SEGNP, T_SEGNP);
TRAPHANDLER(F_STACK, T_STACK);
TRAPHANDLER(F_GPFLT, T_GPFLT);
TRAPHANDLER(F_PGFLT, T_PGFLT);
TRAPHANDLER_NOEC(F_FPERR, T_FPERR);
TRAPHANDLER_NOEC(F_SYSCALL, T_SYSCALL);
TRAPHANDLER_NOEC(F_IRQ0, IRQ_OFFSET + 0);
TRAPHANDLER_NOEC(F_IRQ1, IRQ_OFFSET + 1);
TRAPHANDLER_NOEC(F_IRQ2, IRQ_OFFSET + 2);
TRAPHANDLER_NOEC(F_IRQ3, IRQ_OFFSET + 3);
TRAPHANDLER_NOEC(F_IRQ4, IRQ_OFFSET + 4);
TRAPHANDLER_NOEC(F_IRQ5, IRQ_OFFSET + 5);
TRAPHANDLER_NOEC(F_IRQ6, IRQ_OFFSET + 6);
TRAPHANDLER_NOEC(F_IRQ7, IRQ_OFFSET + 7);
TRAPHANDLER_NOEC(F_IRQ8, IRQ_OFFSET + 8);
TRAPHANDLER_NOEC(F_IRQ9, IRQ_OFFSET + 9);
TRAPHANDLER_NOEC(F_IRQ10, IRQ_OFFSET + 10);
TRAPHANDLER_NOEC(F_IRQ11, IRQ_OFFSET + 11);
TRAPHANDLER_NOEC(F_IRQ12, IRQ_OFFSET + 12);
TRAPHANDLER_NOEC(F_IRQ13, IRQ_OFFSET + 13);
TRAPHANDLER_NOEC(F_IRQ14, IRQ_OFFSET + 14);
TRAPHANDLER_NOEC(F_IRQ15, IRQ_OFFSET + 15);

/*
 * Lab 3: Your code here for _alltraps
 */
_alltraps:
	//tf_trapno already pushed on stack
	pushl %ds;
	pushl %es;
	pushal;
	//end of Trapframe struct

	movl $GD_KD, %eax
	movw %ax, %ds
	movw %ax, %es

	pushl %esp
	call trap
