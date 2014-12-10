/*
 * Test the framework itself. These tests confirm that setup works.
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <alloc.h>
#include <asm/setup.h>
#ifdef __arm__
#include <asm/ptrace.h>
#include <asm/asm-offsets.h>
#include <asm/processor.h>
#include <asm/page.h>
#endif

static void assert_args(int num_args, int needed_args)
{
	if (num_args < needed_args) {
		printf("selftest: not enough arguments\n");
		abort();
	}
}

static char *split_var(char *s, long *val)
{
	char *p;

	p = strchr(s, '=');
	if (!p)
		return NULL;

	*val = atol(p+1);
	*p = '\0';

	return s;
}

static void check_setup(int argc, char **argv)
{
	int nr_tests = 0, i;
	char *var;
	long val;

	for (i = 0; i < argc; ++i) {

		var = split_var(argv[i], &val);
		if (!var)
			continue;

		report_prefix_push(var);

		if (strcmp(var, "mem") == 0) {

			phys_addr_t memsize = PHYS_END - PHYS_OFFSET;
			phys_addr_t expected = ((phys_addr_t)val)*1024*1024;

			report("size = %d MB", memsize == expected,
							memsize/1024/1024);
			++nr_tests;

		} else if (strcmp(var, "smp") == 0) {

			report("nr_cpus = %d", nr_cpus == (int)val, nr_cpus);
			++nr_tests;
		}

		report_prefix_pop();
	}

	assert_args(nr_tests, 2);
}

#ifdef __arm__
static struct pt_regs expected_regs;
/*
 * Capture the current register state and execute an instruction
 * that causes an exception. The test handler will check that its
 * capture of the current register state matches the capture done
 * here.
 *
 * NOTE: update clobber list if passed insns needs more than r0,r1
 */
#define test_exception(pre_insns, excptn_insn, post_insns)	\
	asm volatile(						\
		pre_insns "\n"					\
		"mov	r0, %0\n"				\
		"stmia	r0, { r0-lr }\n"			\
		"mrs	r1, cpsr\n"				\
		"str	r1, [r0, #" xstr(S_PSR) "]\n"		\
		"mov	r1, #-1\n"				\
		"str	r1, [r0, #" xstr(S_OLD_R0) "]\n"	\
		"add	r1, pc, #8\n"				\
		"str	r1, [r0, #" xstr(S_R1) "]\n"		\
		"str	r1, [r0, #" xstr(S_PC) "]\n"		\
		excptn_insn "\n"				\
		post_insns "\n"					\
	:: "r" (&expected_regs) : "r0", "r1")

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

static bool und_works;
static void und_handler(struct pt_regs *regs)
{
	und_works = check_regs(regs);
}

static bool check_und(void)
{
	install_exception_handler(EXCPTN_UND, und_handler);

	/* issue an instruction to a coprocessor we don't have */
	test_exception("", "mcr p2, 0, r0, c0, c0", "");

	install_exception_handler(EXCPTN_UND, NULL);

	return und_works;
}

static bool svc_works;
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
			"msr	spsr_cxsf, r0\n"
		);
	} else {
		test_exception("", "svc #123", "");
	}

	install_exception_handler(EXCPTN_SVC, NULL);

	return svc_works;
}

static void check_vectors(void *arg __unused)
{
	report("und", check_und());
	report("svc", check_svc());
	exit(report_summary());
}
#endif

int main(int argc, char **argv)
{
	report_prefix_push("selftest");
	assert_args(argc, 1);
	report_prefix_push(argv[0]);

	if (strcmp(argv[0], "setup") == 0) {

		check_setup(argc-1, &argv[1]);

#ifdef __arm__
	} else if (strcmp(argv[0], "vectors-kernel") == 0) {

		check_vectors(NULL);

	} else if (strcmp(argv[0], "vectors-user") == 0) {

		void *sp = memalign(PAGE_SIZE, PAGE_SIZE);
		memset(sp, 0, PAGE_SIZE);
		start_usr(check_vectors, NULL, (unsigned long)sp + PAGE_SIZE);
#endif
	}

	return report_summary();
}
