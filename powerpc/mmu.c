// SPDX-License-Identifier: GPL-2.0-only
/*
 * MMU Tests
 *
 * Copyright 2024 Nicholas Piggin, IBM Corp.
 */
#include <libcflat.h>
#include <asm/atomic.h>
#include <asm/barrier.h>
#include <asm/processor.h>
#include <asm/mmu.h>
#include <asm/smp.h>
#include <asm/setup.h>
#include <asm/ppc_asm.h>
#include <vmalloc.h>
#include <devicetree.h>

static volatile bool tlbie_test_running = true;
static volatile bool tlbie_test_failed = false;
static int tlbie_fn_started;

static void *memory;

static void trap_handler(struct pt_regs *regs, void *opaque)
{
	tlbie_test_failed = true;
	regs_advance_insn(regs);
}

static void tlbie_fn(int cpu_id)
{
	volatile char *m = memory;

	setup_mmu(0, NULL);

	atomic_fetch_inc(&tlbie_fn_started);
	while (tlbie_test_running) {
		unsigned long tmp;

		/*
		 * This is intended to execuse a QEMU TCG bug by forming a
		 * large TB which can prevent async work from running while the
		 * TB executes, so it could miss a broadcast TLB invalidation
		 * and pick up a stale translation.
		 */
		asm volatile (".rept 256 ; lbz %0,0(%1) ; tdnei %0,0 ; .endr" : "=&r"(tmp) : "r"(m));
	}
}

#define ITERS 100000

static void test_tlbie(int argc, char **argv)
{
	void *m[2];
	phys_addr_t p[2];
	pteval_t pteval[2];
	pteval_t *ptep;
	int i;

	if (argc > 2)
		report_abort("Unsupported argument: '%s'", argv[2]);

	if (nr_cpus_present < 2) {
		report_skip("Requires SMP (2 or more CPUs)");
		return;
	}

	handle_exception(0x700, &trap_handler, NULL);

	m[0] = alloc_page();
	p[0] = virt_to_phys(m[0]);
	memset(m[0], 0, PAGE_SIZE);
	m[1] = alloc_page();
	p[1] = virt_to_phys(m[1]);
	memset(m[1], 0, PAGE_SIZE);

	memory = alloc_vpages(1);
	ptep = install_page(NULL, p[0], memory);
	pteval[0] = *ptep;
	assert(ptep == install_page(NULL, p[1], memory));
	pteval[1] = *ptep;
	assert(ptep == install_page(NULL, p[0], memory));
	assert(pteval[0] == *ptep);
	flush_tlb_page((unsigned long)memory);

	if (!start_all_cpus(tlbie_fn))
		report_abort("Failed to start secondary cpus");

	while (tlbie_fn_started < nr_cpus_present - 1) {
		cpu_relax();
	}

	for (i = 0; i < ITERS; i++) {
		*ptep = pteval[1];
		flush_tlb_page((unsigned long)memory);
		*(long *)m[0] = -1;
		barrier();
		*(long *)m[0] = 0;
		barrier();
		*ptep = pteval[0];
		flush_tlb_page((unsigned long)memory);
		*(long *)m[1] = -1;
		barrier();
		*(long *)m[1] = 0;
		barrier();
		if (tlbie_test_failed)
			break;
	}

	tlbie_test_running = false;

	stop_all_cpus();

	handle_exception(0x700, NULL, NULL);

	/* TCG has a known race invalidating other CPUs */
	report_kfail(host_is_tcg, !tlbie_test_failed, "tlbie");
}

#define THIS_ITERS 100000

static void test_tlbie_this_cpu(int argc, char **argv)
{
	void *m[2];
	phys_addr_t p[2];
	pteval_t pteval[2];
	pteval_t *ptep;
	int i;
	bool success;

	if (argc > 2)
		report_abort("Unsupported argument: '%s'", argv[2]);

	m[0] = alloc_page();
	p[0] = virt_to_phys(m[0]);
	memset(m[0], 0, PAGE_SIZE);
	m[1] = alloc_page();
	p[1] = virt_to_phys(m[1]);
	memset(m[1], 0, PAGE_SIZE);

	memory = alloc_vpages(1);
	ptep = install_page(NULL, p[0], memory);
	pteval[0] = *ptep;
	assert(ptep == install_page(NULL, p[1], memory));
	pteval[1] = *ptep;
	assert(ptep == install_page(NULL, p[0], memory));
	assert(pteval[0] == *ptep);
	flush_tlb_page((unsigned long)memory);

	*(long *)m[0] = 0;
	*(long *)m[1] = -1;

	success = true;
	for (i = 0; i < THIS_ITERS; i++) {
		if (*(long *)memory != 0) {
			success = false;
			break;
		}
		*ptep = pteval[1];
		flush_tlb_page_local((unsigned long)memory);
		if (*(long *)memory != -1) {
			success = false;
			break;
		}
		*ptep = pteval[0];
		flush_tlb_page_local((unsigned long)memory);
	}
	report(success, "tlbiel");

	success = true;
	flush_tlb_page((unsigned long)memory);
	for (i = 0; i < THIS_ITERS; i++) {
		if (*(long *)memory != 0) {
			success = false;
			break;
		}
		*ptep = pteval[1];
		flush_tlb_page((unsigned long)memory);
		if (*(long *)memory != -1) {
			success = false;
			break;
		}
		*ptep = pteval[0];
		flush_tlb_page((unsigned long)memory);
	}
	report(success, "tlbie");
}


struct {
	const char *name;
	void (*func)(int argc, char **argv);
} hctests[] = {
	{ "tlbi-this-cpu", test_tlbie_this_cpu },
	{ "tlbi-other-cpu", test_tlbie },
	{ NULL, NULL }
};

int main(int argc, char **argv)
{
	bool all;
	int i;

	if (!vm_available()) {
		report_skip("MMU is only supported for radix");
		return 0;
	}

	setup_vm();

	all = argc == 1 || !strcmp(argv[1], "all");

	report_prefix_push("mmu");

	for (i = 0; hctests[i].name != NULL; i++) {
		if (all || strcmp(argv[1], hctests[i].name) == 0) {
			report_prefix_push(hctests[i].name);
			hctests[i].func(argc, argv);
			report_prefix_pop();
		}
	}

	report_prefix_pop();
	return report_summary();
}
