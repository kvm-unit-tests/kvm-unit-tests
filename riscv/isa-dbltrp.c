// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2025, Rivos Inc., Clément Léger <cleger@rivosinc.com>
 */
#include <alloc.h>
#include <alloc_page.h>
#include <libcflat.h>
#include <stdlib.h>

#include <asm/csr.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/sbi.h>

#include <sbi-tests.h>

static bool double_trap;
static bool clear_sdt;

#define GEN_TRAP()								\
do {										\
	void *ptr = NULL;							\
	unsigned long value = 0;						\
	asm volatile(								\
	"	.option push\n"							\
	"	.option arch,-c\n"						\
	"	sw %0, 0(%1)\n"							\
	"	.option pop\n"							\
	: : "r" (value), "r" (ptr) : "memory");					\
} while (0)

static void pagefault_trap_handler(struct pt_regs *regs)
{
	if (READ_ONCE(clear_sdt))
		local_dlbtrp_disable();

	if (READ_ONCE(double_trap)) {
		WRITE_ONCE(double_trap, false);
		GEN_TRAP();
	}

	/* Skip trapping instruction */
	regs->epc += 4;

	local_dlbtrp_enable();
}

static bool sse_dbltrp_called;

static void sse_dbltrp_handler(void *data, struct pt_regs *regs, unsigned int hartid)
{
	struct sbiret ret;
	unsigned long flags;
	unsigned long expected_flags = SBI_SSE_ATTR_INTERRUPTED_FLAGS_SSTATUS_SPP |
				       SBI_SSE_ATTR_INTERRUPTED_FLAGS_SSTATUS_SDT;

	ret = sbi_sse_read_attrs(SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP, SBI_SSE_ATTR_INTERRUPTED_FLAGS, 1,
				 &flags);
	sbiret_report_error(&ret, SBI_SUCCESS, "Get double trap event flags");
	report(flags == expected_flags, "SSE flags == 0x%lx", expected_flags);

	WRITE_ONCE(sse_dbltrp_called, true);

	/* Skip trapping instruction */
	regs->epc += 4;
}

static int sse_double_trap(void)
{
	struct sbiret ret;
	int err = 0;

	struct sbi_sse_handler_arg handler_arg = {
		.handler = sse_dbltrp_handler,
		.stack = alloc_page() + PAGE_SIZE,
	};

	report_prefix_push("sse");

	ret = sbi_sse_hart_unmask();
	if (!sbiret_report_error(&ret, SBI_SUCCESS, "SSE hart unmask ok")) {
		report_skip("Failed to unmask SSE events, skipping test");
		goto out_free_page;
	}

	ret = sbi_sse_register(SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP, &handler_arg);
	if (ret.error == SBI_ERR_NOT_SUPPORTED) {
		report_skip("SSE double trap event is not supported");
		goto out_mask_sse;
	}
	sbiret_report_error(&ret, SBI_SUCCESS, "SSE double trap register");

	ret = sbi_sse_enable(SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP);
	if (!sbiret_report_error(&ret, SBI_SUCCESS, "SSE double trap enable"))
		goto out_unregister;

	/*
	 * Generate a double crash so that an SSE event should be generated. The SPEC (ISA nor SBI)
	 * does not explicitly tell that if supported it should generate an SSE event but that's
	 * a reasonable assumption to do so if both FWFT and SSE are supported.
	 */
	WRITE_ONCE(clear_sdt, false);
	WRITE_ONCE(double_trap, true);
	GEN_TRAP();

	report(READ_ONCE(sse_dbltrp_called), "SSE double trap event generated");

	ret = sbi_sse_disable(SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP);
	sbiret_report_error(&ret, SBI_SUCCESS, "SSE double trap disable");

out_unregister:
	ret = sbi_sse_unregister(SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP);
	if (!sbiret_report_error(&ret, SBI_SUCCESS, "SSE double trap unregister"))
		err = ret.error;

out_mask_sse:
	sbi_sse_hart_mask();

out_free_page:
	free_page(handler_arg.stack - PAGE_SIZE);
	report_prefix_pop();

	return err;
}

static void check_double_trap(void)
{
	struct sbiret ret;

	/* Disable double trap */
	ret = sbi_fwft_set(SBI_FWFT_DOUBLE_TRAP, 0, 0);
	sbiret_report_error(&ret, SBI_SUCCESS, "Set double trap enable feature value == 0");
	ret = sbi_fwft_get(SBI_FWFT_DOUBLE_TRAP);
	sbiret_report(&ret, SBI_SUCCESS, 0, "Get double trap enable feature value == 0");

	install_exception_handler(EXC_STORE_PAGE_FAULT, pagefault_trap_handler);

	WRITE_ONCE(clear_sdt, true);
	WRITE_ONCE(double_trap, true);
	GEN_TRAP();
	report_pass("Double trap disabled, trap first time ok");

	/* Enable double trap */
	ret = sbi_fwft_set(SBI_FWFT_DOUBLE_TRAP, 1, 0);
	sbiret_report_error(&ret, SBI_SUCCESS, "Set double trap enable feature value == 1");
	ret = sbi_fwft_get(SBI_FWFT_DOUBLE_TRAP);
	if (!sbiret_report(&ret, SBI_SUCCESS, 1, "Get double trap enable feature value == 1"))
		return;

	/* First time, clear the double trap flag (SDT) so that it doesn't generate a double trap */
	WRITE_ONCE(clear_sdt, true);
	WRITE_ONCE(double_trap, true);

	GEN_TRAP();
	report_pass("Trapped twice allowed ok");

	if (sbi_probe(SBI_EXT_SSE)) {
		if (sse_double_trap()) {
			report_skip("Could not correctly unregister SSE event, skipping last test");
			return;
		}
	} else {
		report_skip("SSE double trap event will not be tested, extension is not available");
	}

	if (!env_or_skip("DOUBLE_TRAP_TEST_CRASH"))
		return;

	/*
	 * Third time, keep the double trap flag (SDT) and generate another trap, this should
	 * generate a double trap. Since there is no SSE handler registered, it should crash to
	 * M-mode.
	 */
	WRITE_ONCE(clear_sdt, false);
	WRITE_ONCE(double_trap, true);
	report_info("Should generate a double trap and crash!");
	GEN_TRAP();
	report_fail("Should have crashed!");
}

int main(int argc, char **argv)
{
	struct sbiret ret;

	report_prefix_push("dbltrp");

	if (!sbi_probe(SBI_EXT_FWFT)) {
		report_skip("FWFT extension is not available, can not enable double traps");
		goto out;
	}

	ret = sbi_fwft_get(SBI_FWFT_DOUBLE_TRAP);
	if (ret.error == SBI_ERR_NOT_SUPPORTED) {
		report_skip("SBI_FWFT_DOUBLE_TRAP is not supported!");
		goto out;
	}

	if (sbiret_report_error(&ret, SBI_SUCCESS, "SBI_FWFT_DOUBLE_TRAP get value"))
		check_double_trap();

out:
	report_prefix_pop();

	return report_summary();
}
