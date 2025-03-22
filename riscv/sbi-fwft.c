// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI verification
 *
 * Copyright (C) 2024, Rivos Inc., Clément Léger <cleger@rivosinc.com>
 */
#include <libcflat.h>
#include <alloc.h>
#include <stdlib.h>

#include <asm/csr.h>
#include <asm/io.h>
#include <asm/mmu.h>
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

static struct sbiret fwft_set_and_check_raw(const char *str, unsigned long feature,
					    unsigned long value, unsigned long flags)
{
	struct sbiret ret;

	ret = fwft_set_raw(feature, value, flags);
	if (!sbiret_report_error(&ret, SBI_SUCCESS, "set to %ld%s", value, str))
		return ret;

	ret = fwft_get_raw(feature);
	sbiret_report(&ret, SBI_SUCCESS, value, "get %ld after set%s", value, str);

	return ret;
}

static void fwft_check_reserved(unsigned long id)
{
	struct sbiret ret;

	ret = fwft_get(id);
	sbiret_report_error(&ret, SBI_ERR_DENIED, "get reserved feature 0x%lx", id);

	ret = fwft_set(id, 1, 0);
	sbiret_report_error(&ret, SBI_ERR_DENIED, "set reserved feature 0x%lx", id);
}

/* Must be called before any fwft_set() call is made for @feature */
static void fwft_check_reset(uint32_t feature, unsigned long reset)
{
	struct sbiret ret = fwft_get(feature);

	sbiret_report(&ret, SBI_SUCCESS, reset, "resets to %lu", reset);
}

/* Must be called after locking the feature using SBI_FWFT_SET_FLAG_LOCK */
static void fwft_feature_lock_test_values(uint32_t feature, size_t nr_values,
					  unsigned long test_values[],
					  unsigned long locked_value)
{
	struct sbiret ret;

	report_prefix_push("locked");

	bool kfail = __sbi_get_imp_id() == SBI_IMPL_OPENSBI &&
		     __sbi_get_imp_version() < sbi_impl_opensbi_mk_version(1, 7);

	for (int i = 0; i < nr_values; ++i) {
		ret = fwft_set(feature, test_values[i], 0);
		sbiret_kfail_error(kfail, &ret, SBI_ERR_DENIED_LOCKED,
				   "Set to %lu without lock flag", test_values[i]);

		ret = fwft_set(feature, test_values[i], SBI_FWFT_SET_FLAG_LOCK);
		sbiret_kfail_error(kfail, &ret, SBI_ERR_DENIED_LOCKED,
				   "Set to %lu with lock flag", test_values[i]);
	}

	ret = fwft_get(feature);
	sbiret_report(&ret, SBI_SUCCESS, locked_value, "Get value %lu", locked_value);

	report_prefix_pop();
}

static void fwft_feature_lock_test(uint32_t feature, unsigned long locked_value)
{
	unsigned long values[] = {0, 1};

	fwft_feature_lock_test_values(feature, 2, values, locked_value);
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
	unsigned long expected;

	report_prefix_push("misaligned_exc_deleg");

	ret = fwft_misaligned_exc_get();
	if (ret.error != SBI_SUCCESS) {
		if (env_enabled("SBI_HAVE_FWFT_MISALIGNED_EXC_DELEG")) {
			sbiret_report_error(&ret, SBI_SUCCESS, "supported");
			return;
		}
		report_skip("not supported by platform");
		return;
	}

	if (!sbiret_report_error(&ret, SBI_SUCCESS, "Get misaligned deleg feature"))
		return;

	if (env_or_skip("MISALIGNED_EXC_DELEG_RESET")) {
		expected = strtoul(getenv("MISALIGNED_EXC_DELEG_RESET"), NULL, 0);
		fwft_check_reset(SBI_FWFT_MISALIGNED_EXC_DELEG, expected);
	}

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
	fwft_set_and_check_raw("", SBI_FWFT_MISALIGNED_EXC_DELEG, 0, 0);

	/* Set to 1 and check after with get */
	fwft_set_and_check_raw("", SBI_FWFT_MISALIGNED_EXC_DELEG, 1, 0);

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

	fwft_feature_lock_test(SBI_FWFT_MISALIGNED_EXC_DELEG, 0);

	report_prefix_pop();
}

static bool adue_triggered_read, adue_triggered_write;

static void adue_set_ad(unsigned long addr, pteval_t prot)
{
	pte_t *ptep = get_pte(current_pgtable(), addr);
	*ptep = __pte(pte_val(*ptep) | prot);
	local_flush_tlb_page(addr);
}

static void adue_read_handler(struct pt_regs *regs)
{
	adue_triggered_read = true;
	adue_set_ad(regs->badaddr, _PAGE_ACCESSED);
}

static void adue_write_handler(struct pt_regs *regs)
{
	adue_triggered_write = true;
	adue_set_ad(regs->badaddr, _PAGE_ACCESSED | _PAGE_DIRTY);
}

static bool adue_check_pte(pteval_t pte, bool write)
{
	return (pte & (_PAGE_ACCESSED | _PAGE_DIRTY)) == (_PAGE_ACCESSED | (write ? _PAGE_DIRTY : 0));
}

static void adue_check(bool hw_updating_enabled, bool write)
{
	unsigned long *ptr = malloc(sizeof(unsigned long));
	pte_t *ptep = get_pte(current_pgtable(), (uintptr_t)ptr);
	bool *triggered;
	const char *op;

	WRITE_ONCE(adue_triggered_read, false);
	WRITE_ONCE(adue_triggered_write, false);

	*ptep = __pte(pte_val(*ptep) & ~(_PAGE_ACCESSED | _PAGE_DIRTY));
	local_flush_tlb_page((uintptr_t)ptr);

	if (write) {
		op = "write";
		triggered = &adue_triggered_write;
		writel(0xdeadbeef, ptr);
	} else {
		op = "read";
		triggered = &adue_triggered_read;
		readl(ptr);
	}

	report(hw_updating_enabled != *triggered &&
	       adue_check_pte(pte_val(*ptep), write), "hw updating %s %s",
	       hw_updating_enabled ? "enabled" : "disabled", op);

	free(ptr);
}

static bool adue_toggle_and_check_raw(const char *str, unsigned long feature, unsigned long value,
				      unsigned long flags)
{
	struct sbiret ret = fwft_set_and_check_raw(str, feature, value, flags);

	if (!ret.error) {
		adue_check(value, false);
		adue_check(value, true);
		return true;
	}

	return false;
}

static bool adue_toggle_and_check(const char *str, unsigned long value, unsigned long flags)
{
	return adue_toggle_and_check_raw(str, SBI_FWFT_PTE_AD_HW_UPDATING, value, flags);
}

static void fwft_check_pte_ad_hw_updating(void)
{
	struct sbiret ret;
	bool enabled;

	report_prefix_push("pte_ad_hw_updating");

	ret = fwft_get(SBI_FWFT_PTE_AD_HW_UPDATING);
	if (ret.error != SBI_SUCCESS) {
		if (env_enabled("SBI_HAVE_FWFT_PTE_AD_HW_UPDATING")) {
			sbiret_report_error(&ret, SBI_SUCCESS, "supported");
			return;
		}
		report_skip("not supported by platform");
		return;
	} else if (!sbiret_report_error(&ret, SBI_SUCCESS, "get")) {
		/* Not much we can do without a working get... */
		return;
	}

	report(ret.value == 0 || ret.value == 1, "first get value is 0/1");

	enabled = ret.value;

	bool kfail = __sbi_get_imp_id() == SBI_IMPL_OPENSBI &&
		     __sbi_get_imp_version() < sbi_impl_opensbi_mk_version(1, 7);
	report_kfail(kfail, !enabled, "resets to 0");

	install_exception_handler(EXC_LOAD_PAGE_FAULT, adue_read_handler);
	install_exception_handler(EXC_STORE_PAGE_FAULT, adue_write_handler);

	adue_check(enabled, false);
	adue_check(enabled, true);

	if (!adue_toggle_and_check("", !enabled, 0))
		goto adue_inval_tests;
	else
		enabled = !enabled;

	if (!adue_toggle_and_check(" again", !enabled, 0))
		goto adue_inval_tests;
	else
		enabled = !enabled;

#if __riscv_xlen > 32
	if (!adue_toggle_and_check_raw(" with high feature bits set",
				       BIT(32) | SBI_FWFT_PTE_AD_HW_UPDATING, !enabled, 0))
		goto adue_inval_tests;
	else
		enabled = !enabled;
#endif

adue_inval_tests:
	ret = fwft_set(SBI_FWFT_PTE_AD_HW_UPDATING, 2, 0);
	sbiret_report_error(&ret, SBI_ERR_INVALID_PARAM, "set to 2");

	ret = fwft_set(SBI_FWFT_PTE_AD_HW_UPDATING, !enabled, 2);
	sbiret_report_error(&ret, SBI_ERR_INVALID_PARAM, "set to %d with flags=2", !enabled);

	if (!adue_toggle_and_check(" with lock", !enabled, 1))
		goto adue_done;
	else
		enabled = !enabled;

	fwft_feature_lock_test(SBI_FWFT_PTE_AD_HW_UPDATING, enabled);

adue_done:
	install_exception_handler(EXC_LOAD_PAGE_FAULT, NULL);
	install_exception_handler(EXC_STORE_PAGE_FAULT, NULL);

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

	sbi_bad_fid(SBI_EXT_FWFT);

	fwft_check_base();
	fwft_check_misaligned_exc_deleg();
	fwft_check_pte_ad_hw_updating();

	report_prefix_pop();
}
