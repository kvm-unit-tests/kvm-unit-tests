/*
 * Copyright 2010 Siemens AG
 * Author: Jan Kiszka
 *
 * Released under GPLv2.
 */

#include "libcflat.h"
#include "x86/desc.h"
#include "x86/processor.h"
#include "vmalloc.h"

#define TSS_RETURN		(FIRST_SPARE_SEL)

void fault_entry(void);
void icebp_entry(void);

static __attribute__((used, regparm(1))) void
fault_handler(unsigned long error_code)
{
	print_current_tss_info();
	printf("error code %lx\n", error_code);

	tss[0].eip += 2;

	gdt[TSS_MAIN / 8].type &= ~DESC_BUSY;

	set_gdt_task_gate(TSS_RETURN, tss_intr.prev);
}

asm (
	"fault_entry:\n"
	"	mov (%esp),%eax\n"
	"	call fault_handler\n"
	"	jmp $" xstr(TSS_RETURN) ", $0\n"
);

/*
 * Handler invoked via a #DB task gate.  When the CPU switches to this task
 * via the IDT task gate, the outgoing task's CS:EIP is saved to the main
 * TSS, so reading tss[0].eip yields the saved EIP at the point of #DB.
 */
static volatile u32 icebp_eip;

static __attribute__((used)) void
icebp_handler(void)
{
	print_current_tss_info();
        icebp_eip = tss[0].eip;

	/* catch invalid AMD behavior */
	if (*(unsigned char *)icebp_eip == 0xf1)
		tss[0].eip++;
}

asm (
	"icebp_entry:\n"
	"	call icebp_handler\n"
	"	iret\n"
);

int main(int ac, char **av)
{
	const long invalid_segment = 0x1234;

	setup_tss32();
	set_intr_task_gate(GP_VECTOR, fault_entry);

	asm (
		"mov %0,%%es\n"
		: : "r" (invalid_segment) : "edi"
	);

	report(1, "jump to task gate");

	/*
	 * ICEBP causes a trap-like #DB, so the saved EIP must point past the
	 * 0xF1 byte regardless of how #DB is delivered.  On SVM, when #DB is
	 * delivered via a task gate the hardware-saved EIP points at the
	 * ICEBP instruction; the hypervisor has to fix this up by advancing
	 * RIP before the task switch.
	 */
	extern unsigned char after_icebp;

	set_intr_task_gate(DB_VECTOR, icebp_entry);
	icebp_eip = 0;
	asm volatile(".byte 0xf1; after_icebp:");
	report(icebp_eip == (u32)&after_icebp,
	       "ICEBP via #DB task gate: saved EIP %#x, expected %#x",
	       icebp_eip, (u32)&after_icebp);

	return 0;
}
