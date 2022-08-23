/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * External interrupt loop test
 *
 * Copyright IBM Corp. 2022
 *
 * Authors:
 *  Nico Boehr <nrb@linux.ibm.com>
 */
#include <libcflat.h>
#include <asm/interrupt.h>
#include <asm/barrier.h>
#include <asm/time.h>
#include <hardware.h>
#include <bitops.h>

static void ext_int_cleanup(struct stack_frame_int *stack)
{
	/*
	 * Since we form a loop of ext interrupts, this code should never be
	 * executed. In case it is executed, something went wrong and we want to
	 * print a failure.
	 *
	 * Because the CPU timer subclass mask is still enabled, the CPU timer
	 * interrupt will fire every time we enable external interrupts,
	 * preventing us from printing the failure on the console. To avoid
	 * this, clear the CPU timer subclass mask here.
	 */
	stack->crs[0] &= ~BIT(CTL0_CPU_TIMER);
}

int main(void)
{
	report_prefix_push("panic-loop-extint");

	if (!host_is_qemu() || host_is_tcg()) {
		report_skip("QEMU-KVM-only test");
		goto out;
	}

	expect_ext_int();
	lowcore.ext_new_psw.mask |= PSW_MASK_EXT;

	psw_mask_set_bits(PSW_MASK_EXT);

	register_ext_cleanup_func(ext_int_cleanup);

	cpu_timer_set_ms(10);
	ctl_set_bit(0, CTL0_CPU_TIMER);
	mdelay(2000);

	register_ext_cleanup_func(NULL);

	report_fail("survived extint loop");

out:
	report_prefix_pop();
	return report_summary();
}
