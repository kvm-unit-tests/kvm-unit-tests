// SPDX-License-Identifier: GPL-2.0-only
/*
 * SBI DBTR testsuite
 *
 * Copyright (C) 2025, Rivos Inc., Jesse Taube <jesse@rivosinc.com>
 */

#include <libcflat.h>
#include <bitops.h>

#include <asm/io.h>
#include <asm/processor.h>

#include "sbi-tests.h"

#define RV_MAX_TRIGGERS			32

#define SBI_DBTR_TRIG_STATE_MAPPED		BIT(0)
#define SBI_DBTR_TRIG_STATE_U			BIT(1)
#define SBI_DBTR_TRIG_STATE_S			BIT(2)
#define SBI_DBTR_TRIG_STATE_VU			BIT(3)
#define SBI_DBTR_TRIG_STATE_VS			BIT(4)
#define SBI_DBTR_TRIG_STATE_HAVE_HW_TRIG	BIT(5)
#define SBI_DBTR_TRIG_STATE_RESERVED		GENMASK(7, 6)

#define SBI_DBTR_TRIG_STATE_HW_TRIG_IDX_SHIFT		8
#define SBI_DBTR_TRIG_STATE_HW_TRIG_IDX(trig_state)	(trig_state >> SBI_DBTR_TRIG_STATE_HW_TRIG_IDX_SHIFT)

#define SBI_DBTR_TDATA1_TYPE_SHIFT		(__riscv_xlen - 4)
#define SBI_DBTR_TDATA1_DMODE			BIT_UL(__riscv_xlen - 5)

#define SBI_DBTR_TDATA1_MCONTROL6_LOAD		BIT(0)
#define SBI_DBTR_TDATA1_MCONTROL6_STORE		BIT(1)
#define SBI_DBTR_TDATA1_MCONTROL6_EXECUTE	BIT(2)
#define SBI_DBTR_TDATA1_MCONTROL6_U		BIT(3)
#define SBI_DBTR_TDATA1_MCONTROL6_S		BIT(4)
#define SBI_DBTR_TDATA1_MCONTROL6_M		BIT(6)
#define SBI_DBTR_TDATA1_MCONTROL6_SIZE_SHIFT	16
#define SBI_DBTR_TDATA1_MCONTROL6_SIZE_MASK	0x7
#define SBI_DBTR_TDATA1_MCONTROL6_SELECT	BIT(21)
#define SBI_DBTR_TDATA1_MCONTROL6_VU		BIT(23)
#define SBI_DBTR_TDATA1_MCONTROL6_VS		BIT(24)

#define SBI_DBTR_TDATA1_MCONTROL_LOAD		BIT(0)
#define SBI_DBTR_TDATA1_MCONTROL_STORE		BIT(1)
#define SBI_DBTR_TDATA1_MCONTROL_EXECUTE	BIT(2)
#define SBI_DBTR_TDATA1_MCONTROL_U		BIT(3)
#define SBI_DBTR_TDATA1_MCONTROL_S		BIT(4)
#define SBI_DBTR_TDATA1_MCONTROL_M		BIT(6)
#define SBI_DBTR_TDATA1_MCONTROL_SIZELO_SHIFT	16
#define SBI_DBTR_TDATA1_MCONTROL_SIZELO_MASK	0x3
#define SBI_DBTR_TDATA1_MCONTROL_SELECT		BIT(19)
#define SBI_DBTR_TDATA1_MCONTROL_SIZEHI_SHIFT	21
#define SBI_DBTR_TDATA1_MCONTROL_SIZEHI_MASK	0x3

enum McontrolType {
	SBI_DBTR_TDATA1_TYPE_NONE =		(0UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_LEGACY =		(1UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_MCONTROL =		(2UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_ICOUNT =		(3UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_ITRIGGER =		(4UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_ETRIGGER =		(5UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_MCONTROL6 =	(6UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_TMEXTTRIGGER =	(7UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_RESERVED0 =	(8UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_RESERVED1 =	(9UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_RESERVED2 =	(10UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_RESERVED3 =	(11UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_CUSTOM0 =		(12UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_CUSTOM1 =		(13UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_CUSTOM2 =		(14UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
	SBI_DBTR_TDATA1_TYPE_DISABLED =		(15UL << SBI_DBTR_TDATA1_TYPE_SHIFT),
};

enum Tdata1Size {
	SIZE_ANY = 0,
	SIZE_8BIT,
	SIZE_16BIT,
	SIZE_32BIT,
	SIZE_48BIT,
	SIZE_64BIT,
};

enum Tdata1Value {
	VALUE_NONE =	0,
	VALUE_LOAD =	BIT(0),
	VALUE_STORE =	BIT(1),
	VALUE_EXECUTE =	BIT(2),
};

enum Tdata1Mode {
	MODE_NONE =	0,
	MODE_M =	BIT(0),
	MODE_U =	BIT(1),
	MODE_S =	BIT(2),
	MODE_VU =	BIT(3),
	MODE_VS =	BIT(4),
};

enum sbi_ext_dbtr_fid {
	SBI_EXT_DBTR_NUM_TRIGGERS = 0,
	SBI_EXT_DBTR_SETUP_SHMEM,
	SBI_EXT_DBTR_TRIGGER_READ,
	SBI_EXT_DBTR_TRIGGER_INSTALL,
	SBI_EXT_DBTR_TRIGGER_UPDATE,
	SBI_EXT_DBTR_TRIGGER_UNINSTALL,
	SBI_EXT_DBTR_TRIGGER_ENABLE,
	SBI_EXT_DBTR_TRIGGER_DISABLE,
};

struct sbi_dbtr_data_msg {
	unsigned long tstate;
	unsigned long tdata1;
	unsigned long tdata2;
	unsigned long tdata3;
};

struct sbi_dbtr_id_msg {
	unsigned long idx;
};

/* SBI shared mem messages layout */
struct sbi_dbtr_shmem_entry {
	union {
		struct sbi_dbtr_data_msg data;
		struct sbi_dbtr_id_msg id;
	};
};

static bool dbtr_handled;

/* Expected to be leaf function as not to disrupt frame-pointer */
static __attribute__((naked)) void exec_call(void)
{
	/* skip over nop when triggered instead of ret. */
	asm volatile (".option push\n"
		      ".option arch, -c\n"
		      "nop\n"
		      "ret\n"
		      ".option pop\n");
}

static void dbtr_exception_handler(struct pt_regs *regs)
{
	dbtr_handled = true;

	/* Reading *epc may cause a fault, skip over nop */
	if ((void *)regs->epc == exec_call) {
		regs->epc += 4;
		return;
	}

	/* WARNING: Skips over the trapped intruction */
	regs->epc += RV_INSN_LEN(readw((void *)regs->epc));
}

static bool do_store(void *tdata2)
{
	bool ret;

	writel(0, tdata2);

	ret = dbtr_handled;
	dbtr_handled = false;

	return ret;
}

static bool do_load(void *tdata2)
{
	bool ret;

	readl(tdata2);

	ret = dbtr_handled;
	dbtr_handled = false;

	return ret;
}

static bool do_exec(void)
{
	bool ret;

	exec_call();

	ret = dbtr_handled;
	dbtr_handled = false;

	return ret;
}

static unsigned long mcontrol_size(enum Tdata1Size mode)
{
	unsigned long ret = 0;

	ret |= ((mode >> 2) & SBI_DBTR_TDATA1_MCONTROL_SIZEHI_MASK)
		<< SBI_DBTR_TDATA1_MCONTROL_SIZEHI_SHIFT;
	ret |= (mode & SBI_DBTR_TDATA1_MCONTROL_SIZELO_MASK)
		<< SBI_DBTR_TDATA1_MCONTROL_SIZELO_SHIFT;

	return ret;
}

static unsigned long mcontrol6_size(enum Tdata1Size mode)
{
	return (mode & SBI_DBTR_TDATA1_MCONTROL6_SIZE_MASK)
		<< SBI_DBTR_TDATA1_MCONTROL6_SIZE_SHIFT;
}

static unsigned long gen_tdata1_mcontrol(enum Tdata1Mode mode, enum Tdata1Value value)
{
	unsigned long tdata1 = SBI_DBTR_TDATA1_TYPE_MCONTROL;

	if (value & VALUE_LOAD)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL_LOAD;

	if (value & VALUE_STORE)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL_STORE;

	if (value & VALUE_EXECUTE)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL_EXECUTE;

	if (mode & MODE_M)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL_M;

	if (mode & MODE_U)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL_U;

	if (mode & MODE_S)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL_S;

	return tdata1;
}

static unsigned long gen_tdata1_mcontrol6(enum Tdata1Mode mode, enum Tdata1Value value)
{
	unsigned long tdata1 = SBI_DBTR_TDATA1_TYPE_MCONTROL6;

	if (value & VALUE_LOAD)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL6_LOAD;

	if (value & VALUE_STORE)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL6_STORE;

	if (value & VALUE_EXECUTE)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL6_EXECUTE;

	if (mode & MODE_M)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL6_M;

	if (mode & MODE_U)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL6_U;

	if (mode & MODE_S)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL6_S;

	if (mode & MODE_VU)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL6_VU;

	if (mode & MODE_VS)
		tdata1 |= SBI_DBTR_TDATA1_MCONTROL6_VS;

	return tdata1;
}

static unsigned long gen_tdata1(enum McontrolType type, enum Tdata1Value value, enum Tdata1Mode mode)
{
	switch (type) {
	case SBI_DBTR_TDATA1_TYPE_MCONTROL:
		return gen_tdata1_mcontrol(mode, value) | mcontrol_size(SIZE_32BIT);
	case SBI_DBTR_TDATA1_TYPE_MCONTROL6:
		return gen_tdata1_mcontrol6(mode, value) | mcontrol6_size(SIZE_32BIT);
	default:
		assert_msg(false, "Invalid mcontrol type: %lu", (unsigned long)type);
	}
}

static struct sbiret sbi_debug_num_triggers(unsigned long trig_tdata1)
{
	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_NUM_TRIGGERS, trig_tdata1, 0, 0, 0, 0, 0);
}

static struct sbiret sbi_debug_set_shmem_raw(unsigned long shmem_phys_lo,
					     unsigned long shmem_phys_hi,
					     unsigned long flags)
{
	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_SETUP_SHMEM, shmem_phys_lo,
			 shmem_phys_hi, flags, 0, 0, 0);
}

static struct sbiret sbi_debug_set_shmem(void *shmem)
{
	unsigned long base_addr_lo, base_addr_hi;

	split_phys_addr(virt_to_phys(shmem), &base_addr_hi, &base_addr_lo);
	return sbi_debug_set_shmem_raw(base_addr_lo, base_addr_hi, 0);
}

static struct sbiret sbi_debug_read_triggers(unsigned long trig_idx_base,
					     unsigned long trig_count)
{
	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_READ, trig_idx_base,
			 trig_count, 0, 0, 0, 0);
}

static struct sbiret sbi_debug_install_triggers(unsigned long trig_count)
{
	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_INSTALL, trig_count, 0, 0, 0, 0, 0);
}

static struct sbiret sbi_debug_update_triggers(unsigned long trig_count)
{
	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_UPDATE, trig_count, 0, 0, 0, 0, 0);
}

static struct sbiret sbi_debug_uninstall_triggers(unsigned long trig_idx_base,
						  unsigned long trig_idx_mask)
{
	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_UNINSTALL, trig_idx_base,
			 trig_idx_mask, 0, 0, 0, 0);
}

static struct sbiret sbi_debug_enable_triggers(unsigned long trig_idx_base,
					       unsigned long trig_idx_mask)
{
	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_ENABLE, trig_idx_base,
			 trig_idx_mask, 0, 0, 0, 0);
}

static struct sbiret sbi_debug_disable_triggers(unsigned long trig_idx_base,
						unsigned long trig_idx_mask)
{
	return sbi_ecall(SBI_EXT_DBTR, SBI_EXT_DBTR_TRIGGER_DISABLE, trig_idx_base,
			 trig_idx_mask, 0, 0, 0, 0);
}

static bool dbtr_install_trigger(struct sbi_dbtr_shmem_entry *shmem, void *trigger,
				 unsigned long control)
{
	struct sbiret sbi_ret;
	bool ret;

	shmem->data.tdata1 = control;
	shmem->data.tdata2 = (unsigned long)trigger;

	sbi_ret = sbi_debug_install_triggers(1);
	ret = sbiret_report_error(&sbi_ret, SBI_SUCCESS, "sbi_debug_install_triggers");
	if (ret)
		install_exception_handler(EXC_BREAKPOINT, dbtr_exception_handler);

	return ret;
}

static bool dbtr_uninstall_trigger(void)
{
	struct sbiret ret;

	install_exception_handler(EXC_BREAKPOINT, NULL);

	ret = sbi_debug_uninstall_triggers(0, 1);
	return sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_uninstall_triggers");
}

static unsigned long dbtr_test_num_triggers(void)
{
	struct sbiret ret;
	unsigned long tdata1 = 0;
	/* sbi_debug_num_triggers will return trig_max in sbiret.value when trig_tdata1 == 0 */

	report_prefix_push("available triggers");

	/* should be at least one trigger. */
	ret = sbi_debug_num_triggers(tdata1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_num_triggers");

	if (ret.value == 0) {
		report_fail("Returned 0 triggers available");
	} else {
		report_pass("Returned triggers available");
		report_info("Returned %lu triggers available", ret.value);
	}

	report_prefix_pop();
	return ret.value;
}

static enum McontrolType dbtr_test_type(unsigned long *num_trig)
{
	struct sbiret ret;
	unsigned long tdata1 = SBI_DBTR_TDATA1_TYPE_MCONTROL6;

	report_prefix_push("test type");
	report_prefix_push("sbi_debug_num_triggers");

	ret = sbi_debug_num_triggers(tdata1);
	sbiret_report_error(&ret, SBI_SUCCESS, "mcontrol6");
	*num_trig = ret.value;
	if (ret.value > 0) {
		report_pass("Returned mcontrol6 triggers available");
		report_info("Returned %lu mcontrol6 triggers available",
			    ret.value);
		report_prefix_popn(2);
		return tdata1;
	}

	tdata1 = SBI_DBTR_TDATA1_TYPE_MCONTROL;

	ret = sbi_debug_num_triggers(tdata1);
	sbiret_report_error(&ret, SBI_SUCCESS, "mcontrol");
	*num_trig = ret.value;
	if (ret.value > 0) {
		report_pass("Returned mcontrol triggers available");
		report_info("Returned %lu mcontrol triggers available",
			    ret.value);
		report_prefix_popn(2);
		return tdata1;
	}

	report_fail("Returned 0 mcontrol(6) triggers available");
	report_prefix_popn(2);

	return SBI_DBTR_TDATA1_TYPE_NONE;
}

static struct sbiret dbtr_test_store_install_uninstall(struct sbi_dbtr_shmem_entry *shmem,
						      enum McontrolType type)
{
	static unsigned long test;
	struct sbiret ret;

	report_prefix_push("store trigger");

	shmem->data.tdata1 = gen_tdata1(type, VALUE_STORE, MODE_S);
	shmem->data.tdata2 = (unsigned long)&test;

	ret = sbi_debug_install_triggers(1);
	if (!sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_install_triggers")) {
		report_prefix_pop();
		return ret;
	}

	install_exception_handler(EXC_BREAKPOINT, dbtr_exception_handler);

	report(do_store(&test), "triggered");

	if (do_load(&test))
		report_fail("triggered by load");

	ret = sbi_debug_uninstall_triggers(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_uninstall_triggers");

	if (do_store(&test))
		report_fail("triggered after uninstall");

	install_exception_handler(EXC_BREAKPOINT, NULL);
	report_prefix_pop();

	return ret;
}

static void dbtr_test_update(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type)
{
	static unsigned long test;
	struct sbiret ret;
	bool kfail;

	report_prefix_push("update trigger");

	if (!dbtr_install_trigger(shmem, NULL, gen_tdata1(type, VALUE_NONE, MODE_NONE))) {
		report_prefix_pop();
		return;
	}

	shmem->id.idx = 0;
	shmem->data.tdata1 = gen_tdata1(type, VALUE_STORE, MODE_S);
	shmem->data.tdata2 = (unsigned long)&test;

	ret = sbi_debug_update_triggers(1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_update_triggers");

	/*
	 * Known broken update_triggers.
	 * https://lore.kernel.org/opensbi/aDdp1UeUh7GugeHp@ghost/T/#t
	 */
	kfail = __sbi_get_imp_id() == SBI_IMPL_OPENSBI &&
		__sbi_get_imp_version() < sbi_impl_opensbi_mk_version(1, 7);
	report_kfail(kfail, do_store(&test), "triggered");

	dbtr_uninstall_trigger();
	report_prefix_pop();
}

static void dbtr_test_load(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type)
{
	static unsigned long test;

	report_prefix_push("load trigger");
	if (!dbtr_install_trigger(shmem, &test, gen_tdata1(type, VALUE_LOAD, MODE_S))) {
		report_prefix_pop();
		return;
	}

	report(do_load(&test), "triggered");

	if (do_store(&test))
		report_fail("triggered by store");

	dbtr_uninstall_trigger();
	report_prefix_pop();
}

static void dbtr_test_disable_enable(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type)
{
	static unsigned long test;
	struct sbiret ret;

	report_prefix_push("disable trigger");
	if (!dbtr_install_trigger(shmem, &test, gen_tdata1(type, VALUE_STORE, MODE_S))) {
		report_prefix_pop();
		return;
	}

	ret = sbi_debug_disable_triggers(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_disable_triggers");

	if (!report(!do_store(&test), "should not trigger")) {
		dbtr_uninstall_trigger();
		report_prefix_pop();
		report_skip("enable trigger: no disable");

		return;
	}

	report_prefix_pop();
	report_prefix_push("enable trigger");

	ret = sbi_debug_enable_triggers(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_enable_triggers");

	report(do_store(&test), "triggered");

	dbtr_uninstall_trigger();
	report_prefix_pop();
}

static void dbtr_test_exec(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type)
{
	static unsigned long test;

	report_prefix_push("exec trigger");
	/* check if loads and stores trigger exec */
	if (!dbtr_install_trigger(shmem, &test, gen_tdata1(type, VALUE_EXECUTE, MODE_S))) {
		report_prefix_pop();
		return;
	}

	if (do_load(&test))
		report_fail("triggered by load");

	if (do_store(&test))
		report_fail("triggered by store");

	dbtr_uninstall_trigger();

	/* Check if exec works */
	if (!dbtr_install_trigger(shmem, exec_call, gen_tdata1(type, VALUE_EXECUTE, MODE_S))) {
		report_prefix_pop();
		return;
	}
	report(do_exec(), "triggered");

	dbtr_uninstall_trigger();
	report_prefix_pop();
}

static void dbtr_test_read(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type)
{
	const unsigned long tstatus_expected = SBI_DBTR_TRIG_STATE_S | SBI_DBTR_TRIG_STATE_MAPPED;
	const unsigned long tdata1 = gen_tdata1(type, VALUE_STORE, MODE_S);
	static unsigned long test;
	struct sbiret ret;

	report_prefix_push("read trigger");
	if (!dbtr_install_trigger(shmem, &test, tdata1)) {
		report_prefix_pop();
		return;
	}

	ret = sbi_debug_read_triggers(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_read_triggers");

	if (!report(shmem->data.tdata1 == tdata1, "tdata1 expected: 0x%016lx", tdata1))
		report_info("tdata1 found: 0x%016lx", shmem->data.tdata1);
	if (!report(shmem->data.tdata2 == ((unsigned long)&test), "tdata2 expected: 0x%016lx",
		    (unsigned long)&test))
		report_info("tdata2 found: 0x%016lx", shmem->data.tdata2);
	if (!report(shmem->data.tstate == tstatus_expected, "tstate expected: 0x%016lx", tstatus_expected))
		report_info("tstate found: 0x%016lx", shmem->data.tstate);

	dbtr_uninstall_trigger();
	report_prefix_pop();
}

static void check_exec(unsigned long base)
{
	struct sbiret ret;

	report(do_exec(), "exec triggered");

	ret = sbi_debug_uninstall_triggers(base, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_uninstall_triggers");
}

static void dbtr_test_multiple(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type,
			       unsigned long num_trigs)
{
	static unsigned long test[2];
	struct sbiret ret;
	bool have_three = num_trigs > 2;

	if (num_trigs < 2) {
		report_skip("test multiple");
		return;
	}

	report_prefix_push("test multiple");

	if (!dbtr_install_trigger(shmem, &test[0], gen_tdata1(type, VALUE_STORE, MODE_S))) {
		report_prefix_pop();
		return;
	}
	if (!dbtr_install_trigger(shmem, &test[1], gen_tdata1(type, VALUE_LOAD, MODE_S)))
		goto error;
	if (have_three &&
	    !dbtr_install_trigger(shmem, exec_call, gen_tdata1(type, VALUE_EXECUTE, MODE_S))) {
		ret = sbi_debug_uninstall_triggers(1, 1);
		sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_uninstall_triggers");
		goto error;
	}

	report(do_store(&test[0]), "store triggered");

	if (do_load(&test[0]))
		report_fail("store triggered by load");

	report(do_load(&test[1]), "load triggered");

	if (do_store(&test[1]))
		report_fail("load triggered by store");

	if (have_three)
		check_exec(2);

	ret = sbi_debug_uninstall_triggers(1, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_uninstall_triggers");

	if (do_load(&test[1]))
		report_fail("load triggered after uninstall");

	report(do_store(&test[0]), "store triggered");

	if (!have_three &&
	    dbtr_install_trigger(shmem, exec_call, gen_tdata1(type, VALUE_EXECUTE, MODE_S)))
		check_exec(1);

error:
	ret = sbi_debug_uninstall_triggers(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_uninstall_triggers");

	install_exception_handler(EXC_BREAKPOINT, NULL);
	report_prefix_pop();
}

static void dbtr_test_multiple_types(struct sbi_dbtr_shmem_entry *shmem, unsigned long type)
{
	static unsigned long test;

	report_prefix_push("test multiple types");

	/* check if loads and stores trigger exec */
	if (!dbtr_install_trigger(shmem, &test,
			     gen_tdata1(type, VALUE_EXECUTE | VALUE_LOAD | VALUE_STORE, MODE_S))) {
		report_prefix_pop();
		return;
	}

	report(do_load(&test), "load triggered");

	report(do_store(&test), "store triggered");

	dbtr_uninstall_trigger();

	/* Check if exec works */
	if (!dbtr_install_trigger(shmem, exec_call,
			     gen_tdata1(type, VALUE_EXECUTE | VALUE_LOAD | VALUE_STORE, MODE_S))) {
		report_prefix_pop();
		return;
	}

	report(do_exec(), "exec triggered");

	dbtr_uninstall_trigger();
	report_prefix_pop();
}

static void dbtr_test_disable_uninstall(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type)
{
	static unsigned long test;
	struct sbiret ret;

	report_prefix_push("disable uninstall");
	if (!dbtr_install_trigger(shmem, &test, gen_tdata1(type, VALUE_STORE, MODE_S))) {
		report_prefix_pop();
		return;
	}

	ret = sbi_debug_disable_triggers(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_disable_triggers");

	dbtr_uninstall_trigger();

	if (!dbtr_install_trigger(shmem, &test, gen_tdata1(type, VALUE_STORE, MODE_S))) {
		report_prefix_pop();
		return;
	}

	report(do_store(&test), "triggered");

	dbtr_uninstall_trigger();
	report_prefix_pop();
}

static void dbtr_test_uninstall_enable(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type)
{
	static unsigned long test;
	struct sbiret ret;

	report_prefix_push("uninstall enable");
	if (!dbtr_install_trigger(shmem, &test, gen_tdata1(type, VALUE_STORE, MODE_S))) {
		report_prefix_pop();
		return;
	}
	dbtr_uninstall_trigger();

	ret = sbi_debug_enable_triggers(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_enable_triggers");

	install_exception_handler(EXC_BREAKPOINT, dbtr_exception_handler);

	report(!do_store(&test), "should not trigger");

	install_exception_handler(EXC_BREAKPOINT, NULL);
	report_prefix_pop();
}

static void dbtr_test_uninstall_update(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type)
{
	static unsigned long test;
	struct sbiret ret;
	bool kfail;

	report_prefix_push("uninstall update");
	if (!dbtr_install_trigger(shmem, NULL, gen_tdata1(type, VALUE_NONE, MODE_NONE))) {
		report_prefix_pop();
		return;
	}

	dbtr_uninstall_trigger();

	shmem->id.idx = 0;
	shmem->data.tdata1 = gen_tdata1(type, VALUE_STORE, MODE_S);
	shmem->data.tdata2 = (unsigned long)&test;

	/*
	 * Known broken update_triggers.
	 * https://lore.kernel.org/opensbi/aDdp1UeUh7GugeHp@ghost/T/#t
	 */
	kfail = __sbi_get_imp_id() == SBI_IMPL_OPENSBI &&
		__sbi_get_imp_version() < sbi_impl_opensbi_mk_version(1, 7);
	ret = sbi_debug_update_triggers(1);
	sbiret_kfail_error(kfail, &ret, SBI_ERR_FAILURE, "sbi_debug_update_triggers");

	install_exception_handler(EXC_BREAKPOINT, dbtr_exception_handler);

	report(!do_store(&test), "should not trigger");

	install_exception_handler(EXC_BREAKPOINT, NULL);
	report_prefix_pop();
}

static void dbtr_test_disable_read(struct sbi_dbtr_shmem_entry *shmem, enum McontrolType type)
{
	const unsigned long tstatus_expected = SBI_DBTR_TRIG_STATE_S | SBI_DBTR_TRIG_STATE_MAPPED;
	const unsigned long tdata1 = gen_tdata1(type, VALUE_STORE, MODE_NONE);
	static unsigned long test;
	struct sbiret ret;

	report_prefix_push("disable read");
	if (!dbtr_install_trigger(shmem, &test, gen_tdata1(type, VALUE_STORE, MODE_S))) {
		report_prefix_pop();
		return;
	}

	ret = sbi_debug_disable_triggers(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_disable_triggers");

	ret = sbi_debug_read_triggers(0, 1);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_read_triggers");

	if (!report(shmem->data.tdata1 == tdata1, "tdata1 expected: 0x%016lx", tdata1))
		report_info("tdata1 found: 0x%016lx", shmem->data.tdata1);
	if (!report(shmem->data.tdata2 == ((unsigned long)&test), "tdata2 expected: 0x%016lx",
		    (unsigned long)&test))
		report_info("tdata2 found: 0x%016lx", shmem->data.tdata2);
	if (!report(shmem->data.tstate == tstatus_expected, "tstate expected: 0x%016lx", tstatus_expected))
		report_info("tstate found: 0x%016lx", shmem->data.tstate);

	dbtr_uninstall_trigger();
	report_prefix_pop();
}

void check_dbtr(void)
{
	static struct sbi_dbtr_shmem_entry shmem[RV_MAX_TRIGGERS] = {};
	unsigned long num_trigs;
	enum McontrolType trig_type;
	struct sbiret ret;

	report_prefix_push("dbtr");

	if (!sbi_probe(SBI_EXT_DBTR)) {
		report_skip("extension not available");
		goto exit_test;
	}

	num_trigs = dbtr_test_num_triggers();
	if (!num_trigs)
		goto exit_test;

	trig_type = dbtr_test_type(&num_trigs);
	if (trig_type == SBI_DBTR_TDATA1_TYPE_NONE)
		goto exit_test;

	ret = sbi_debug_set_shmem(shmem);
	sbiret_report_error(&ret, SBI_SUCCESS, "sbi_debug_set_shmem");

	ret = dbtr_test_store_install_uninstall(&shmem[0], trig_type);
	/* install or uninstall failed */
	if (ret.error != SBI_SUCCESS)
		goto exit_test;

	dbtr_test_load(&shmem[0], trig_type);
	dbtr_test_exec(&shmem[0], trig_type);
	dbtr_test_read(&shmem[0], trig_type);
	dbtr_test_disable_enable(&shmem[0], trig_type);
	dbtr_test_update(&shmem[0], trig_type);
	dbtr_test_multiple_types(&shmem[0], trig_type);
	dbtr_test_multiple(shmem, trig_type, num_trigs);
	dbtr_test_disable_uninstall(&shmem[0], trig_type);
	dbtr_test_uninstall_enable(&shmem[0], trig_type);
	dbtr_test_uninstall_update(&shmem[0], trig_type);
	dbtr_test_disable_read(&shmem[0], trig_type);

exit_test:
	report_prefix_pop();
}
