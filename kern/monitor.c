// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>
#include <kern/pmap.h>
#include <kern/env.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "showmappings", "Display the physical address mappings", mon_showmappings },
	{ "chgperms", "Change the permissions of a page", mon_chgperms },
	{ "memdump", "Dump the contents of virtual or physical memory", mon_memdump },
	{ "next", "Single-step through instructions after an interruption", mon_next },
	{ "continue", "Continue a program after an interruption", mon_continue }
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t ebp = read_ebp();
	cprintf("Stack backtrace:\n");
	mon_backtrace_r(ebp);
	return 0;
}

void
mon_backtrace_r(uint32_t ebp)
{
        if(ebp == 0x0)
		return;
	uint32_t* stack_ptr = (uint32_t*) ebp;
	uint32_t new_ebp = *stack_ptr;
	cprintf("  ebp %08x", ebp);
	cprintf("  eip %08x", *(++stack_ptr));
	uintptr_t eip = (uintptr_t) *stack_ptr;
	cprintf("  args");
	for(uint8_t i = 0; i < 5; i++)
	{
		cprintf(" %08x", *(++stack_ptr));
	}
	cprintf("\n");
	struct Eipdebuginfo info_val;
	debuginfo_eip(eip, &info_val);
	cprintf("        %s:%d: %.*s+%d", info_val.eip_file,
				         info_val.eip_line,
					 info_val.eip_fn_namelen,
					 info_val.eip_fn_name,
					 eip - info_val.eip_fn_addr);
	cprintf("\n");
	mon_backtrace_r(new_ebp);
	return;
}

int
mon_showmappings(int argc, char** argv, struct Trapframe *tf)
{
	uint32_t start_va;
	uint32_t end_va;
	pte_t* ptentry;
	uint32_t jump;
	jump = 1;
	if(argc == 1)
	{
		cprintf("Please provide a virtual address or a range of virtual addresses!\n");
		return 0;
	}
	start_va = (uint32_t) strtol(argv[1], NULL, 0);
	if(argc == 2)
		end_va = start_va;
	else
	{
		end_va = (uint32_t) strtol(argv[2], NULL, 0);
		if(end_va < start_va)
		{
			cprintf("Second should be bigger than the first!\n");
			return 0;
		}
		if(argc > 3)
		{
			jump = (uint32_t) strtol(argv[3], NULL, 0);
		}
	}
	for(uint32_t i = start_va; i <= end_va; i+=jump)
	{
		ptentry = pgdir_walk(kern_pgdir, (void*) start_va, 0);
		cprintf("0x%08x: ", i);
		if(ptentry == NULL)
		{
			cprintf("Hasn't been mapped!\n");
			continue;
		}
		cprintf("0x%08x\n", PGNUM(*ptentry) << PTXSHIFT | PGOFF(i));
		cprintf("    Read/Write: %s\n", *ptentry & PTE_W ? "true": "false");
		cprintf("    User: %s\n", *ptentry & PTE_U ? "true": "false");
	}
	
	return 0;
}
int
mon_chgperms(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t address;
	pte_t* ptentry;
	uint32_t perms;
	if(argc < 3)
	{
		cprintf("Please provide a subcommand and an address!\n");
		return 0;
	}
	address = (uint32_t) strtol(argv[1], NULL, 0);
	ptentry = pgdir_walk(kern_pgdir, (void*) address, 0);
	if(ptentry == NULL)
	{
		cprintf("That address hasn't been mapped!\n");
		return 0;
	}
	perms = PGOFF(*ptentry);
	for(int i = 1; i < argc; i++)
	{
		if(strcmp(argv[i], "clear") == 0)
			perms = 0;
		if(strcmp(argv[i], "rwon") == 0)
			perms |= PTE_W;
		if(strcmp(argv[i], "rwoff") == 0)
			perms &= ~PTE_W;
		if(strcmp(argv[i], "useron") == 0)
			perms |= PTE_U;
		if(strcmp(argv[i], "useroff") == 0)
			perms &= ~PTE_U;
		if(strcmp(argv[i], "preson") == 0)
			perms |= PTE_P;
		if(strcmp(argv[i], "presoff") == 0)
			perms &= ~PTE_P;
	}
	*ptentry = (PGNUM(*ptentry) << PTXSHIFT) | perms;
	return 0;
}

int
mon_memdump(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t start_a;
	uint32_t end_a;
	uint32_t perms;
	pte_t* ptentry;
	if(argc < 2)
	{
		cprintf("Please provide an address, or a range!\n");
		return 0;
	}
	if(strcmp(argv[1], "p") == 0)
	{
		argc--;
		argv++;
	}
	if(argc < 2)
	{
		cprintf("Please provide an address, or a range!\n");
		return 0;
	}
	start_a = (uint32_t) strtol(argv[1], NULL, 0);
	if(argc == 2)
		end_a = start_a;
	else
		end_a = (uint32_t) strtol(argv[2], NULL, 0);
	if(strcmp(argv[0], "p") == 0)
	{
		for(uint32_t i = start_a; i <= end_a; i++)
		{	
			if(i > 0x100000000 - KERNBASE)
			{
				cprintf("Out of range!\n");
				continue;
			}
			cprintf("0x%08x\n", *((uint32_t*)KADDR(i)));
		}
	}
	else
	{
		for(uint32_t i = start_a; i <= end_a; i++)
		{
			ptentry = pgdir_walk(kern_pgdir, (void*) i, 0);
			if(ptentry == NULL)
			{
				cprintf("Not mapped yet!\n");
				continue;
			}
			cprintf("0x%08x\n", *((uint32_t*)i));
		}
	}
	return 0;
	
}

//extern struct Env* curenv;
//static uint32_t monitor_eip;

int
mon_continue(int argc, char **argv, struct Trapframe *tf)
{
	uint32_t flags;
	if(curenv->env_status != ENV_RUNNING)
	{
		cprintf("Need a running program!\n");
		return 0;
	}
	flags = (tf->tf_eflags) & ~(1 << 8);
	tf->tf_eflags = flags;
	curenv->env_tf = *tf;
	env_run(curenv);
	return 0;
}
int
mon_next(int argc, char **argv, struct Trapframe *tf)
{
	cprintf("eip: %08x\n", tf->tf_eip);
	uint32_t flags;
	if(curenv->env_status != ENV_RUNNING)
	{
		cprintf("Need a running program!\n");
		return 0;
	}
	//asm volatile("movl (%esp), %eax"); 
	//asm volatile("\t movl %%eax, %0" : "=g"(monitor_eip));
	curenv->env_tf = *tf;
	flags = (tf->tf_eflags) | (1 << 8);
	tf->tf_eflags = flags;
	curenv->env_tf = *tf;
	env_run(curenv);
	return 0;
}

int
next_end(struct Trapframe *tf)
{
	uint32_t eip;
	eip = tf->tf_eip;
	struct Eipdebuginfo info_val;
	debuginfo_eip(eip, &info_val);
	cprintf("%s:%d: %.*s+%d", info_val.eip_file,
		                  info_val.eip_line,
				  info_val.eip_fn_namelen,
				  info_val.eip_fn_name,
				  eip - info_val.eip_fn_addr);
	cprintf("\n");
	monitor(tf);
	//asm volatile("\t movl %0, %%eax" : :"g"(monitor_eip));
	//asm volatile("pushl 0; movl %eax, (%esp)");
	return 0;
}
/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
