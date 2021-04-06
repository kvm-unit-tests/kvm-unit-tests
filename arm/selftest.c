/*
 * Test the framework itself. These tests confirm that setup works.
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <util.h>
#include <devicetree.h>
#include <vmalloc.h>
#include <asm/setup.h>
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/psci.h>
#include <asm/smp.h>
#include <asm/mmu.h>
#include <asm/barrier.h>

static cpumask_t ready, valid;

static void __user_psci_system_off(void)
{
	psci_system_off();
	halt();
	__builtin_unreachable();
}

static void check_setup(int argc, char **argv)
{
	int nr_tests = 0, len, i;
	long val;

	for (i = 0; i < argc; ++i) {

		len = parse_keyval(argv[i], &val);
		if (len == -1)
			continue;

		argv[i][len] = '\0';
		report_prefix_push(argv[i]);

		if (strcmp(argv[i], "mem") == 0) {

			phys_addr_t memsize = PHYS_END - PHYS_OFFSET;
			phys_addr_t expected = ((phys_addr_t)val)*1024*1024;

			report(memsize == expected,
			       "memory size matches expectation");
			report_info("found %" PRIu64 " MB", memsize/1024/1024);
			++nr_tests;

		} else if (strcmp(argv[i], "smp") == 0) {

			report(nr_cpus == (int)val,
			       "number of CPUs matches expectation");
			report_info("found %d CPUs", nr_cpus);
			++nr_tests;
		}

		report_prefix_pop();
	}

	if (nr_tests < 2)
		report_abort("missing input");
}

unsigned long check_pabt_invalid_paddr;
static bool check_pabt_init(void)
{
	phys_addr_t highest_end = 0;
	unsigned long vaddr;
	struct mem_region *r;

	/*
	 * We need a physical address that isn't backed by anything. Without
	 * fully parsing the device tree there's no way to be certain of any
	 * address, but an unknown address immediately following the highest
	 * memory region has a reasonable chance. This is because we can
	 * assume that that memory region could have been larger, if the user
	 * had configured more RAM, and therefore no MMIO region should be
	 * there.
	 */
	for (r = mem_regions; r->end; ++r) {
		if (r->flags & MR_F_IO)
			continue;
		if (r->end > highest_end)
			highest_end = PAGE_ALIGN(r->end);
	}

	if (mem_region_get_flags(highest_end) != MR_F_UNKNOWN)
		return false;

	vaddr = (unsigned long)vmap(highest_end, PAGE_SIZE);
	mmu_clear_user(current_thread_info()->pgtable, vaddr);
	check_pabt_invalid_paddr = vaddr;

	return true;
}

static struct pt_regs expected_regs;
static bool und_works;
static bool svc_works;
static bool pabt_works;
#if defined(__arm__)
/*
 * Capture the current register state and execute an instruction
 * that causes an exception. The test handler will check that its
 * capture of the current register state matches the capture done
 * here.
 */
#define test_exception(pre_insns, excptn_insn, post_insns, clobbers...)	\
	asm volatile(							\
		pre_insns "\n"						\
		"mov	r0, %0\n"					\
		"stmia	r0, { r0-lr }\n"				\
		"mrs	r1, cpsr\n"					\
		"str	r1, [r0, #" xstr(S_PSR) "]\n"			\
		"mov	r1, #-1\n"					\
		"str	r1, [r0, #" xstr(S_OLD_R0) "]\n"		\
		"add	r1, pc, #8\n"					\
		"str	r1, [r0, #" xstr(S_R1) "]\n"			\
		"str	r1, [r0, #" xstr(S_PC) "]\n"			\
		excptn_insn "\n"					\
		post_insns "\n"						\
	:: "r" (&expected_regs) : "r0", "r1", ##clobbers)

static bool check_regs(struct pt_regs *regs)
{
	unsigned i;

	/* exception handlers should always run in svc mode */
	if (current_mode() != SVC_MODE)
		return false;

	for (i = 0; i < ARRAY_SIZE(regs->uregs); ++i) {
		if (regs->uregs[i] != expected_regs.uregs[i])
			return false;
	}

	return true;
}

static void und_handler(struct pt_regs *regs)
{
	und_works = check_regs(regs);
}

static bool check_und(void)
{
	install_exception_handler(EXCPTN_UND, und_handler);

	/* issue an instruction to a coprocessor we don't have */
	test_exception("", "mcr p2, 0, r0, c0, c0", "", "r0");

	install_exception_handler(EXCPTN_UND, NULL);

	return und_works;
}

static void svc_handler(struct pt_regs *regs)
{
	u32 svc = *(u32 *)(regs->ARM_pc - 4) & 0xffffff;

	if (processor_mode(regs) == SVC_MODE) {
		/*
		 * When issuing an svc from supervisor mode lr_svc will
		 * get corrupted. So before issuing the svc, callers must
		 * always push it on the stack. We pushed it to offset 4.
		 */
		regs->ARM_lr = *(unsigned long *)(regs->ARM_sp + 4);
	}

	svc_works = check_regs(regs) && svc == 123;
}

static bool check_svc(void)
{
	install_exception_handler(EXCPTN_SVC, svc_handler);

	if (current_mode() == SVC_MODE) {
		/*
		 * An svc from supervisor mode will corrupt lr_svc and
		 * spsr_svc. We need to save/restore them separately.
		 */
		test_exception(
			"mrs	r0, spsr\n"
			"push	{ r0,lr }\n",
			"svc	#123\n",
			"pop	{ r0,lr }\n"
			"msr	spsr_cxsf, r0\n",
			"r0", "lr"
		);
	} else {
		test_exception("", "svc #123", "");
	}

	install_exception_handler(EXCPTN_SVC, NULL);

	return svc_works;
}

static void pabt_handler(struct pt_regs *regs)
{
	expected_regs.ARM_lr = expected_regs.ARM_pc;
	expected_regs.ARM_pc = expected_regs.ARM_r9;

	pabt_works = check_regs(regs);

	regs->ARM_pc = regs->ARM_lr;
}

static bool check_pabt(void)
{
	install_exception_handler(EXCPTN_PABT, pabt_handler);

	test_exception("ldr	r9, =check_pabt_invalid_paddr\n"
		       "ldr	r9, [r9]\n",
		       "blx	r9\n",
		       "", "r9", "lr");

	install_exception_handler(EXCPTN_PABT, NULL);

	return pabt_works;
}

static void user_psci_system_off(struct pt_regs *regs)
{
	__user_psci_system_off();
}
#elif defined(__aarch64__)

/*
 * Capture the current register state and execute an instruction
 * that causes an exception. The test handler will check that its
 * capture of the current register state matches the capture done
 * here.
 */
#define test_exception(pre_insns, excptn_insn, post_insns, clobbers...)	\
	asm volatile(							\
		pre_insns "\n"						\
		"mov	x1, %0\n"					\
		"ldr	x0, [x1, #" xstr(S_PSTATE) "]\n"		\
		"mrs	x1, nzcv\n"					\
		"orr	w0, w0, w1\n"					\
		"mov	x1, %0\n"					\
		"str	w0, [x1, #" xstr(S_PSTATE) "]\n"		\
		"mov	x0, sp\n"					\
		"str	x0, [x1, #" xstr(S_SP) "]\n"			\
		"adr	x0, 1f\n"					\
		"str	x0, [x1, #" xstr(S_PC) "]\n"			\
		"stp	 x2,  x3, [x1,  #16]\n"				\
		"stp	 x4,  x5, [x1,  #32]\n"				\
		"stp	 x6,  x7, [x1,  #48]\n"				\
		"stp	 x8,  x9, [x1,  #64]\n"				\
		"stp	x10, x11, [x1,  #80]\n"				\
		"stp	x12, x13, [x1,  #96]\n"				\
		"stp	x14, x15, [x1, #112]\n"				\
		"stp	x16, x17, [x1, #128]\n"				\
		"stp	x18, x19, [x1, #144]\n"				\
		"stp	x20, x21, [x1, #160]\n"				\
		"stp	x22, x23, [x1, #176]\n"				\
		"stp	x24, x25, [x1, #192]\n"				\
		"stp	x26, x27, [x1, #208]\n"				\
		"stp	x28, x29, [x1, #224]\n"				\
		"str	x30, [x1, #" xstr(S_LR) "]\n"			\
		"stp	 x0,  x1, [x1]\n"				\
	"1:"	excptn_insn "\n"					\
		post_insns "\n"						\
	:: "r" (&expected_regs) : "x0", "x1", ##clobbers)

static bool check_regs(struct pt_regs *regs)
{
	unsigned i;

	/* exception handlers should always run in EL1 */
	if (current_level() != CurrentEL_EL1)
		return false;

	for (i = 0; i < ARRAY_SIZE(regs->regs); ++i) {
		if (regs->regs[i] != expected_regs.regs[i])
			return false;
	}

	regs->pstate &= 0xf0000000 /* NZCV */ | 0x3c0 /* DAIF */
			| PSR_MODE_MASK;

	return regs->sp == expected_regs.sp
		&& regs->pc == expected_regs.pc
		&& regs->pstate == expected_regs.pstate;
}

static enum vector check_vector_prep(void)
{
	unsigned long daif;

	if (is_user())
		return EL0_SYNC_64;

	asm volatile("mrs %0, daif" : "=r" (daif) ::);
	expected_regs.pstate = daif | PSR_MODE_EL1h;
	return EL1H_SYNC;
}

static void unknown_handler(struct pt_regs *regs, unsigned int esr __unused)
{
	und_works = check_regs(regs);
	regs->pc += 4;
}

static bool check_und(void)
{
	enum vector v = check_vector_prep();

	install_exception_handler(v, ESR_EL1_EC_UNKNOWN, unknown_handler);

	/* try to read an el2 sysreg from el0/1 */
	test_exception("", "mrs x0, sctlr_el2", "", "x0");

	install_exception_handler(v, ESR_EL1_EC_UNKNOWN, NULL);

	return und_works;
}

static void svc_handler(struct pt_regs *regs, unsigned int esr)
{
	u16 svc = esr & 0xffff;

	expected_regs.pc += 4;
	svc_works = check_regs(regs) && svc == 123;
}

static bool check_svc(void)
{
	enum vector v = check_vector_prep();

	install_exception_handler(v, ESR_EL1_EC_SVC64, svc_handler);

	test_exception("", "svc #123", "");

	install_exception_handler(v, ESR_EL1_EC_SVC64, NULL);

	return svc_works;
}

static void pabt_handler(struct pt_regs *regs, unsigned int esr)
{
	bool is_extabt = (esr & ESR_EL1_FSC_MASK) == ESR_EL1_FSC_EXTABT;

	expected_regs.regs[30] = expected_regs.pc + 4;
	expected_regs.pc = expected_regs.regs[9];

	pabt_works = check_regs(regs) && is_extabt;

	regs->pc = regs->regs[30];
}

static bool check_pabt(void)
{
	enum vector v = check_vector_prep();

	install_exception_handler(v, ESR_EL1_EC_IABT_EL1, pabt_handler);

	test_exception("adrp	x9, check_pabt_invalid_paddr\n"
		       "add	x9, x9, :lo12:check_pabt_invalid_paddr\n"
		       "ldr	x9, [x9]\n",
		       "blr	x9\n",
		       "", "x9", "x30");

	install_exception_handler(v, ESR_EL1_EC_IABT_EL1, NULL);

	return pabt_works;
}

static void user_psci_system_off(struct pt_regs *regs, unsigned int esr)
{
	__user_psci_system_off();
}
#endif

static void check_vectors(void *arg __unused)
{
	report(check_und(), "und");
	report(check_svc(), "svc");
	if (is_user()) {
#ifdef __arm__
		install_exception_handler(EXCPTN_UND, user_psci_system_off);
#else
		install_exception_handler(EL0_SYNC_64, ESR_EL1_EC_UNKNOWN,
					  user_psci_system_off);
#endif
	} else {
		if (!check_pabt_init())
			report_skip("Couldn't guess an invalid physical address");
		else
			report(check_pabt(), "pabt");
	}
	exit(report_summary());
}

static void psci_print(void)
{
	int ver = psci_invoke(PSCI_0_2_FN_PSCI_VERSION, 0, 0, 0);
	report_info("PSCI version: %d.%d", PSCI_VERSION_MAJOR(ver),
					  PSCI_VERSION_MINOR(ver));
	report_info("PSCI method: %s", psci_invoke == psci_invoke_hvc ?
				       "hvc" : "smc");
}

static void cpu_report(void *data __unused)
{
	uint64_t mpidr = get_mpidr();
	int cpu = smp_processor_id();

	if (mpidr_to_cpu(mpidr) == cpu)
		cpumask_set_cpu(smp_processor_id(), &valid);
	smp_wmb();		/* Paired with rmb in main(). */
	cpumask_set_cpu(smp_processor_id(), &ready);
	report_info("CPU%3d: MPIDR=%010" PRIx64, cpu, mpidr);
}

int main(int argc, char **argv)
{
	report_prefix_push("selftest");

	if (argc < 2)
		report_abort("no test specified");

	report_prefix_push(argv[1]);

	if (strcmp(argv[1], "setup") == 0) {

		check_setup(argc-2, &argv[2]);

	} else if (strcmp(argv[1], "vectors-kernel") == 0) {

		check_vectors(NULL);

	} else if (strcmp(argv[1], "vectors-user") == 0) {

		start_usr(check_vectors, NULL,
				(unsigned long)thread_stack_alloc());

	} else if (strcmp(argv[1], "smp") == 0) {

		psci_print();
		on_cpus(cpu_report, NULL);
		while (!cpumask_full(&ready))
			cpu_relax();
		smp_rmb();		/* Paired with wmb in cpu_report(). */
		report(cpumask_full(&valid), "MPIDR test on all CPUs");
		report_info("%d CPUs reported back", nr_cpus);

	} else {
		printf("Unknown subtest\n");
		abort();
	}

	return report_summary();
}
