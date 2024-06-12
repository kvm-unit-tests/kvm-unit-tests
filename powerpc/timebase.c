// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test Timebase
 *
 * Copyright 2024 Nicholas Piggin, IBM Corp.
 *
 * This contains tests of timebase facility, TB, DEC, etc.
 */
#include <libcflat.h>
#include <util.h>
#include <migrate.h>
#include <alloc.h>
#include <asm/handlers.h>
#include <devicetree.h>
#include <asm/hcall.h>
#include <asm/processor.h>
#include <asm/time.h>
#include <asm/barrier.h>

static int dec_bits = 0;

static void cpu_dec_bits(int fdtnode, u64 regval __unused, void *arg __unused)
{
	const struct fdt_property *prop;
	int plen;

	prop = fdt_get_property(dt_fdt(), fdtnode, "ibm,dec-bits", &plen);
	if (!prop) {
		dec_bits = 32;
		return;
	}

	/* Sanity check for the property layout (first two bytes are header) */
	assert(plen == 4);

	/* Check all CPU nodes have the same value of dec-bits */
	if (dec_bits)
		assert(dec_bits == fdt32_to_cpu(*(uint32_t *)prop->data));
	else
		dec_bits = fdt32_to_cpu(*(uint32_t *)prop->data);
}

/* Check amount of CPUs nodes that have the TM flag */
static int find_dec_bits(void)
{
	int ret;

	ret = dt_for_each_cpu_node(cpu_dec_bits, NULL);
	if (ret < 0)
		return ret;

	return dec_bits;
}


static bool do_migrate = false;
static volatile bool got_interrupt;
static volatile struct pt_regs recorded_regs;

static uint64_t dec_max;
static uint64_t dec_min;

static void test_tb(int argc, char **argv)
{
	uint64_t tb;
	int i;

	tb = get_tb();
	report(get_tb() >= tb, "timebase is not going backwards");
	if (do_migrate) {
		tb = get_tb();
		migrate();
		report(get_tb() >= tb,
		       "timebase is not going backwards over migration");
	}

	for (i = 0; i < 100; i++) {
		if (get_tb() > tb)
			break;
	}
	report(get_tb() > tb, "timebase is incrementing");
}

static void dec_stop_handler(struct pt_regs *regs, void *data)
{
	mtspr(SPR_DEC, dec_max);
}

static void dec_handler(struct pt_regs *regs, void *data)
{
	got_interrupt = true;
	memcpy((void *)&recorded_regs, regs, sizeof(struct pt_regs));
	regs->msr &= ~MSR_EE;
}

static void test_dec(int argc, char **argv)
{
	uint64_t tb1, tb2, dec;
	int i;

	handle_exception(0x900, &dec_handler, NULL);

	for (i = 0; i < 100; i++) {
		tb1 = get_tb();
		mtspr(SPR_DEC, dec_max);
		dec = mfspr(SPR_DEC);
		tb2 = get_tb();
		if (tb2 - tb1 < dec_max - dec)
			break;
	}
	/* POWER CPUs can have a slight (few ticks) variation here */
	report_kfail(!host_is_tcg, tb2 - tb1 >= dec_max - dec,
		     "decrementer remains within TB after mtDEC");

	tb1 = get_tb();
	mtspr(SPR_DEC, dec_max);
	mdelay(1000);
	dec = mfspr(SPR_DEC);
	tb2 = get_tb();
	report(tb2 - tb1 >= dec_max - dec,
	       "decrementer remains within TB after 1s");

	mtspr(SPR_DEC, dec_max);
	local_irq_enable();
	local_irq_disable();
	if (mfspr(SPR_DEC) <= dec_max) {
		report(!got_interrupt,
		       "no interrupt on decrementer positive");
	}
	got_interrupt = false;

	mtspr(SPR_DEC, 1);
	mdelay(100); /* Give the timer a chance to run */
	if (do_migrate)
		migrate();
	local_irq_enable();
	local_irq_disable();
	report(got_interrupt, "interrupt on decrementer underflow");
	got_interrupt = false;

	if (do_migrate)
		migrate();
	local_irq_enable();
	local_irq_disable();
	report(got_interrupt, "interrupt on decrementer still underflown");
	got_interrupt = false;

	mtspr(SPR_DEC, 0);
	mdelay(100); /* Give the timer a chance to run */
	if (do_migrate)
		migrate();
	local_irq_enable();
	local_irq_disable();
	report(got_interrupt, "DEC deal with set to 0");
	got_interrupt = false;

	/* Test for level-triggered decrementer */
	mtspr(SPR_DEC, -1ULL);
	if (do_migrate)
		migrate();
	local_irq_enable();
	local_irq_disable();
	report(got_interrupt, "interrupt on decrementer write MSB");
	got_interrupt = false;

	mtspr(SPR_DEC, dec_max);
	local_irq_enable();
	if (do_migrate)
		migrate();
	mtspr(SPR_DEC, -1);
	local_irq_disable();
	report(got_interrupt, "interrupt on decrementer write MSB with irqs on");
	got_interrupt = false;

	mtspr(SPR_DEC, dec_min + 1);
	mdelay(100);
	local_irq_enable();
	local_irq_disable();
	/* TCG does not model this correctly */
	report_kfail(host_is_tcg, !got_interrupt,
		     "no interrupt after wrap to positive");
	got_interrupt = false;

	handle_exception(0x900, NULL, NULL);
}

static void test_hdec(int argc, char **argv)
{
	uint64_t tb1, tb2, hdec;

	if (!machine_is_powernv()) {
		report_skip("test reqiures powernv machine");
		return;
	}

	handle_exception(0x900, &dec_stop_handler, NULL);
	handle_exception(0x980, &dec_handler, NULL);

	mtspr(SPR_HDEC, dec_max);
	mtspr(SPR_LPCR, mfspr(SPR_LPCR) | LPCR_HDICE);

	tb1 = get_tb();
	mtspr(SPR_HDEC, dec_max);
	hdec = mfspr(SPR_HDEC);
	tb2 = get_tb();
	report(tb2 - tb1 >= dec_max - hdec, "hdecrementer remains within TB");

	tb1 = get_tb();
	mtspr(SPR_HDEC, dec_max);
	mdelay(1000);
	hdec = mfspr(SPR_HDEC);
	tb2 = get_tb();
	report(tb2 - tb1 >= dec_max - hdec, "hdecrementer remains within TB after 1s");

	mtspr(SPR_HDEC, dec_max);
	local_irq_enable();
	local_irq_disable();
	if (mfspr(SPR_HDEC) <= dec_max) {
		report(!got_interrupt, "no interrupt on decrementer positive");
	}
	got_interrupt = false;

	mtspr(SPR_HDEC, 1);
	mdelay(100); /* Give the timer a chance to run */
	if (do_migrate)
		migrate();
	/* HDEC is edge triggered so ensure it still fires */
	mtspr(SPR_HDEC, dec_max);
	local_irq_enable();
	local_irq_disable();
	report(got_interrupt, "interrupt on hdecrementer underflow");
	got_interrupt = false;

	if (do_migrate)
		migrate();
	local_irq_enable();
	local_irq_disable();
	report(!got_interrupt, "no interrupt on hdecrementer still underflown");
	got_interrupt = false;

	mtspr(SPR_HDEC, -1ULL);
	if (do_migrate)
		migrate();
	local_irq_enable();
	local_irq_disable();
	report(got_interrupt, "no interrupt on hdecrementer underflown write MSB");
	got_interrupt = false;

	mtspr(SPR_HDEC, 0);
	mdelay(100); /* Give the timer a chance to run */
	if (do_migrate)
		migrate();
	/* HDEC is edge triggered so ensure it still fires */
	mtspr(SPR_HDEC, dec_max);
	local_irq_enable();
	local_irq_disable();
	report(got_interrupt, "HDEC deal with set to 0");
	got_interrupt = false;

	mtspr(SPR_HDEC, dec_max);
	local_irq_enable();
	if (do_migrate)
		migrate();
	mtspr(SPR_HDEC, -1ULL);
	local_irq_disable();
	report(got_interrupt, "interrupt on hdecrementer write MSB with irqs on");
	got_interrupt = false;

	mtspr(SPR_HDEC, dec_max);
	got_interrupt = false;
	mtspr(SPR_HDEC, dec_min + 1);
	if (do_migrate)
		migrate();
	mdelay(100);
	local_irq_enable();
	local_irq_disable();
	report(got_interrupt, "got interrupt after wrap to positive");
	got_interrupt = false;

	mtspr(SPR_HDEC, -1ULL);
	local_irq_enable();
	local_irq_disable();
	got_interrupt = false;
	mtspr(SPR_HDEC, dec_min + 1000000);
	if (do_migrate)
		migrate();
	mdelay(100);
	mtspr(SPR_HDEC, -1ULL);
	local_irq_enable();
	local_irq_disable();
	report(got_interrupt, "edge re-armed after wrap to positive");
	got_interrupt = false;

	mtspr(SPR_LPCR, mfspr(SPR_LPCR) & ~LPCR_HDICE);

	handle_exception(0x900, NULL, NULL);
	handle_exception(0x980, NULL, NULL);
}

struct {
	const char *name;
	void (*func)(int argc, char **argv);
} hctests[] = {
	{ "tb", test_tb },
	{ "dec", test_dec },
	{ "hdec", test_hdec },
	{ NULL, NULL }
};

int main(int argc, char **argv)
{
	bool all;
	int i;

	all = argc == 1 || !strcmp(argv[1], "all");

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-w")) {
			do_migrate = true;
			if (!all && argc == 2)
				all = true;
		}
	}

	find_dec_bits();
	dec_max = (1ULL << (dec_bits - 1)) - 1;
	dec_min = (1ULL << (dec_bits - 1));

	if (machine_is_powernv() && dec_bits > 32) {
		mtspr(SPR_LPCR, mfspr(SPR_LPCR) | LPCR_LD);
	}

	report_prefix_push("timebase");

	for (i = 0; hctests[i].name != NULL; i++) {
		if (all || strcmp(argv[1], hctests[i].name) == 0) {
			report_prefix_push(hctests[i].name);
			hctests[i].func(argc, argv);
			report_prefix_pop();
		}
	}

	report_prefix_pop();

	if (machine_is_powernv() && dec_bits > 32) {
		mtspr(SPR_LPCR, mfspr(SPR_LPCR) & ~LPCR_LD);
	}

	return report_summary();
}
