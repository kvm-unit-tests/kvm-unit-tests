/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Floating interrupt tests.
 *
 * Copyright 2021 Red Hat Inc
 *
 * Authors:
 *    David Hildenbrand <david@redhat.com>
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/page.h>
#include <asm-generic/barrier.h>

#include <sclp.h>
#include <smp.h>
#include <alloc_page.h>

static void wait_for_sclp_int(void)
{
	/* Enable SCLP interrupts on this CPU only. */
	ctl_set_bit(0, CTL0_SERVICE_SIGNAL);

	/* Enable external interrupts and go to the wait state. */
	wait_for_interrupt(PSW_MASK_EXT);
}

/*
 * Some KVM versions might mix CPUs when looking for a floating IRQ target,
 * accidentially detecting a stopped CPU as waiting and resulting in the actually
 * waiting CPU not getting woken up for the interrupt.
 */
static void test_wait_state_delivery(void)
{
	SCCBHeader *h;
	int ret;

	report_prefix_push("wait state delivery");

	if (smp_query_num_cpus() < 3) {
		report_skip("need at least 3 CPUs for this test");
		goto out;
	}

	/* Stop CPU #2. It must succeed because we have at least 3 CPUs */
	ret = smp_cpu_stop(2);
	assert(!ret);

	/*
	 * We're going to perform an SCLP service call but expect the
	 * interrupt on CPU #1 while it is in the wait state.
	 */
	sclp_mark_busy();

	/* Start CPU #1 and let it wait for the interrupt. */
	ret = smp_cpu_setup(1, PSW_WITH_CUR_MASK(wait_for_sclp_int));
	/* This must not fail because we have at least 3 CPUs */
	assert(!ret);

	/*
	 * We'd have to jump trough some hoops to sense e.g., via SIGP
	 * CONDITIONAL EMERGENCY SIGNAL if CPU #1 is already in the
	 * wait state.
	 *
	 * Although not completely reliable, use SIGP SENSE RUNNING STATUS
	 * until not reported as running -- after all, our SCLP processing
	 * will take some time as well and smp_cpu_setup() returns when we're
	 * either already in wait_for_sclp_int() or just about to execute it.
	 */
	while(smp_sense_running_status(1));

	h = alloc_pages_flags(0, AREA_DMA31);
	h->length = 4096;
	ret = servc(SCLP_CMDW_READ_CPU_INFO, __pa(h));
	if (ret) {
		sclp_clear_busy();
		report_fail("SCLP_CMDW_READ_CPU_INFO failed");
		goto out_destroy;
	}

	/*
	 * Wait until the interrupt gets delivered on CPU #1, marking the
	 * SCLP requests as done.
	 */
	sclp_wait_busy();

	report(true, "sclp interrupt delivered");

out_destroy:
	free_page(h);
	smp_cpu_destroy(1);
out:
	report_prefix_pop();
}

int main(void)
{
	report_prefix_push("firq");

	test_wait_state_delivery();

	report_prefix_pop();
	return report_summary();
}
