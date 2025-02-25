// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2024, Rivos Inc., Clément Léger <cleger@rivosinc.com>
 */
#include <libcflat.h>
#include <stdlib.h>

#include <asm/csr.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/sbi.h>

#include "sbi-tests.h"

void check_fwft(void);


static struct sbiret fwft_set_raw(unsigned long feature, unsigned long value, unsigned long flags)
{
	return sbi_ecall(SBI_EXT_FWFT, SBI_EXT_FWFT_SET, feature, value, flags, 0, 0, 0);
}

static struct sbiret fwft_set(uint32_t feature, unsigned long value, unsigned long flags)
{
	return fwft_set_raw(feature, value, flags);
}

static struct sbiret fwft_get_raw(unsigned long feature)
{
	return sbi_ecall(SBI_EXT_FWFT, SBI_EXT_FWFT_GET, feature, 0, 0, 0, 0, 0);
}

static struct sbiret fwft_get(uint32_t feature)
{
	return fwft_get_raw(feature);
}

static void fwft_check_reserved(unsigned long id)
{
	struct sbiret ret;

	ret = fwft_get(id);
	sbiret_report_error(&ret, SBI_ERR_DENIED, "get reserved feature 0x%lx", id);

	ret = fwft_set(id, 1, 0);
	sbiret_report_error(&ret, SBI_ERR_DENIED, "set reserved feature 0x%lx", id);
}

static void fwft_check_base(void)
{
	report_prefix_push("base");

	fwft_check_reserved(SBI_FWFT_LOCAL_RESERVED_START);
	fwft_check_reserved(SBI_FWFT_LOCAL_RESERVED_END);
	fwft_check_reserved(SBI_FWFT_GLOBAL_RESERVED_START);
	fwft_check_reserved(SBI_FWFT_GLOBAL_RESERVED_END);

	report_prefix_pop();
}

static bool misaligned_handled;

static void misaligned_handler(struct pt_regs *regs)
{
	misaligned_handled = true;
	regs->epc += 4;
}

static struct sbiret fwft_misaligned_exc_set(unsigned long value, unsigned long flags)
{
	return fwft_set(SBI_FWFT_MISALIGNED_EXC_DELEG, value, flags);
}

static struct sbiret fwft_misaligned_exc_get(void)
{
	return fwft_get(SBI_FWFT_MISALIGNED_EXC_DELEG);
}

static void fwft_check_misaligned_exc_deleg(void)
{
	struct sbiret ret;

	report_prefix_push("misaligned_exc_deleg");

	ret = fwft_misaligned_exc_get();
	if (ret.error == SBI_ERR_NOT_SUPPORTED) {
		report_skip("SBI_FWFT_MISALIGNED_EXC_DELEG is not supported");
		return;
	}

	if (!sbiret_report_error(&ret, SBI_SUCCESS, "Get misaligned deleg feature"))
		return;

	ret = fwft_misaligned_exc_set(2, 0);
	sbiret_report_error(&ret, SBI_ERR_INVALID_PARAM,
			    "Set misaligned deleg feature invalid value 2");
	ret = fwft_misaligned_exc_set(0xFFFFFFFF, 0);
	sbiret_report_error(&ret, SBI_ERR_INVALID_PARAM,
			    "Set misaligned deleg feature invalid value 0xFFFFFFFF");

#if __riscv_xlen > 32
	ret = fwft_misaligned_exc_set(BIT(32), 0);
	sbiret_report_error(&ret, SBI_ERR_INVALID_PARAM,
			    "Set misaligned deleg with invalid value > 32bits");

	ret = fwft_misaligned_exc_set(0, BIT(32));
	sbiret_report_error(&ret, SBI_ERR_INVALID_PARAM,
			    "Set misaligned deleg with invalid flag > 32bits");
#endif

	/* Set to 0 and check after with get */
	ret = fwft_misaligned_exc_set(0, 0);
	sbiret_report_error(&ret, SBI_SUCCESS, "Set misaligned deleg feature value 0");
	ret = fwft_misaligned_exc_get();
	sbiret_report(&ret, SBI_SUCCESS, 0, "Get misaligned deleg feature expected value 0");

	/* Set to 1 and check after with get */
	ret = fwft_misaligned_exc_set(1, 0);
	sbiret_report_error(&ret, SBI_SUCCESS, "Set misaligned deleg feature value 1");
	ret = fwft_misaligned_exc_get();
	sbiret_report(&ret, SBI_SUCCESS, 1, "Get misaligned deleg feature expected value 1");

	install_exception_handler(EXC_LOAD_MISALIGNED, misaligned_handler);

	asm volatile (
		".option push\n"
		/*
		 * Disable compression so the lw takes exactly 4 bytes and thus
		 * can be skipped reliably from the exception handler.
		 */
		".option arch,-c\n"
		"lw %[val], 1(%[val_addr])\n"
		".option pop\n"
		: [val] "+r" (ret.value)
		: [val_addr] "r" (&ret.value)
		: "memory");

	/*
	 * Even though the SBI delegated the misaligned exception to S-mode, it might not trap on
	 * misaligned load/store access, report that during tests.
	 */
	if (!misaligned_handled)
		report_skip("Misaligned load exception does not trap in S-mode");
	else
		report_pass("Misaligned load exception trap in S-mode");

	install_exception_handler(EXC_LOAD_MISALIGNED, NULL);

	/* Lock the feature */
	ret = fwft_misaligned_exc_set(0, SBI_FWFT_SET_FLAG_LOCK);
	sbiret_report_error(&ret, SBI_SUCCESS, "Set misaligned deleg feature value 0 and lock");
	ret = fwft_misaligned_exc_set(1, 0);
	sbiret_report_error(&ret, SBI_ERR_DENIED_LOCKED,
			    "Set locked misaligned deleg feature to new value");
	ret = fwft_misaligned_exc_get();
	sbiret_report(&ret, SBI_SUCCESS, 0, "Get misaligned deleg locked value 0");

	report_prefix_pop();
}

void check_fwft(void)
{
	report_prefix_push("fwft");

	if (!sbi_probe(SBI_EXT_FWFT)) {
		report_skip("FWFT extension not available");
		report_prefix_pop();
		return;
	}

	fwft_check_base();
	fwft_check_misaligned_exc_deleg();

	report_prefix_pop();
}
