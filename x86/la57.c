#include "libcflat.h"
#include "apic.h"
#include "processor.h"
#include "msr.h"
#include "x86/vm.h"
#include "asm/setup.h"

#ifdef __x86_64__
enum TEST_REGISTER {
	TEST_REGISTER_GDTR_BASE,
	TEST_REGISTER_IDTR_BASE,
	TEST_REGISTER_TR_BASE,
	TEST_REGISTER_LDT_BASE,
	TEST_REGISTER_MSR /* upper 32 bits = msr address */
};

static u64 get_test_register_value(u64 test_register)
{
	struct descriptor_table_ptr dt_ptr;
	u32 msr = test_register >> 32;

	/*
	 * Note: value for LDT and TSS base might not reflect the actual base
	 * that the CPU currently uses, because the (hidden) base value can't be
	 * directly read.
	 */
	switch ((u32)test_register) {
	case TEST_REGISTER_GDTR_BASE:
		sgdt(&dt_ptr);
		return  dt_ptr.base;
	case TEST_REGISTER_IDTR_BASE:
		sidt(&dt_ptr);
		return dt_ptr.base;
	case TEST_REGISTER_TR_BASE:
		return get_gdt_entry_base(get_tss_descr());
	case TEST_REGISTER_LDT_BASE:
		return get_gdt_entry_base(get_ldt_descr());
	case TEST_REGISTER_MSR:
		return rdmsr(msr);
	default:
		assert(0);
		return 0;
	}
}

enum SET_REGISTER_MODE {
	SET_REGISTER_MODE_UNSAFE,
	SET_REGISTER_MODE_SAFE,
	SET_REGISTER_MODE_FEP,
};

static bool set_test_register_value(u64 test_register, int test_mode, u64 value)
{
	struct descriptor_table_ptr dt_ptr;
	u32 msr = test_register >> 32;
	u16 sel;

	switch ((u32)test_register) {
	case TEST_REGISTER_GDTR_BASE:
		sgdt(&dt_ptr);
		dt_ptr.base = value;

		switch (test_mode) {
		case SET_REGISTER_MODE_UNSAFE:
			lgdt(&dt_ptr);
			return true;
		case SET_REGISTER_MODE_SAFE:
			return lgdt_safe(&dt_ptr) == 0;
		case SET_REGISTER_MODE_FEP:
			return lgdt_fep_safe(&dt_ptr) == 0;
		}
	case TEST_REGISTER_IDTR_BASE:
		sidt(&dt_ptr);
		dt_ptr.base = value;

		switch (test_mode) {
		case SET_REGISTER_MODE_UNSAFE:
			lidt(&dt_ptr);
			return true;
		case SET_REGISTER_MODE_SAFE:
			return lidt_safe(&dt_ptr) == 0;
		case SET_REGISTER_MODE_FEP:
			return lidt_fep_safe(&dt_ptr) == 0;
		}
	case TEST_REGISTER_TR_BASE:
		sel = str();
		set_gdt_entry_base(sel, value);
		clear_tss_busy(sel);

		switch (test_mode) {
		case SET_REGISTER_MODE_UNSAFE:
			ltr(sel);
			return true;
		case SET_REGISTER_MODE_SAFE:
			return ltr_safe(sel) == 0;
		case SET_REGISTER_MODE_FEP:
			return ltr_fep_safe(sel) == 0;
		}

	case TEST_REGISTER_LDT_BASE:
		sel = sldt();
		set_gdt_entry_base(sel, value);

		switch (test_mode) {
		case SET_REGISTER_MODE_UNSAFE:
			lldt(sel);
			return true;
		case SET_REGISTER_MODE_SAFE:
			return lldt_safe(sel) == 0;
		case SET_REGISTER_MODE_FEP:
			return lldt_fep_safe(sel) == 0;
		}
	case TEST_REGISTER_MSR:
		switch (test_mode) {
		case SET_REGISTER_MODE_UNSAFE:
			wrmsr(msr, value);
			return true;
		case SET_REGISTER_MODE_SAFE:
			return wrmsr_safe(msr, value) == 0;
		case SET_REGISTER_MODE_FEP:
			return wrmsr_fep_safe(msr, value) == 0;
		}
	default:
		assert(false);
		return 0;
	}
}

static void test_register_write(const char *register_name, u64 test_register,
				bool force_emulation, u64 test_value,
				bool expect_success)
{
	int test_mode = (force_emulation ? SET_REGISTER_MODE_FEP : SET_REGISTER_MODE_SAFE);
	u64 old_value, expected_value;
	bool success;

	old_value = get_test_register_value(test_register);
	expected_value = expect_success ? test_value : old_value;

	/*
	 * TODO: A successful write to the MSR_GS_BASE corrupts it, and that
	 * breaks the wrmsr_safe macro (it uses GS for per-CPU data).
	 */
	if ((test_register >> 32) == MSR_GS_BASE && expect_success)
		test_mode = SET_REGISTER_MODE_UNSAFE;

	/* Write the test value*/
	success = set_test_register_value(test_register, test_mode, test_value);
	report(success == expect_success,
	       "Write to %s with value %lx did %s%s as expected",
	       register_name, test_value,
	       success == expect_success ? "" : "NOT ",
	       (expect_success ? "succeed" : "fail"));

	/*
	 * Check that the value was really written.  Don't test TR and LDTR,
	 * because it's not possible to read them directly.
	 */
	if (success == expect_success &&
	    test_register != TEST_REGISTER_TR_BASE &&
	    test_register != TEST_REGISTER_LDT_BASE) {
		u64 new_value = get_test_register_value(test_register);

		report(new_value == expected_value,
		       "%s set to %lx as expected (actual value %lx)",
		       register_name, expected_value, new_value);
	}


	/*
	 * Restore the old value directly without safety wrapper, to avoid test
	 * crashes related to temporary clobbered GDT/IDT/etc bases.
	 */
	set_test_register_value(test_register, SET_REGISTER_MODE_UNSAFE, old_value);
}

static void test_register(const char *register_name, u64 test_register,
			  bool force_emulation)
{
	/* Canonical 48 bit value should always succeed */
	test_register_write(register_name, test_register, force_emulation,
			    CANONICAL_48_VAL, true);

	/* 57-canonical value will work on CPUs that *support* LA57 */
	test_register_write(register_name, test_register, force_emulation,
			    CANONICAL_57_VAL, this_cpu_has(X86_FEATURE_LA57));

	/* Non 57 canonical value should never work */
	test_register_write(register_name, test_register, force_emulation,
			    NONCANONICAL, false);
}


#define TEST_REGISTER(name, force_emulation) \
		      test_register(#name, TEST_REGISTER_ ##name, force_emulation)

#define __TEST_MSR(msr_name, address, force_emulation) \
		   test_register(msr_name, ((u64)TEST_REGISTER_MSR |  \
		   ((u64)(address) << 32)), force_emulation)

#define TEST_MSR(msr_name, force_emulation) \
	__TEST_MSR(#msr_name, msr_name, force_emulation)

static void __test_invpcid(u64 test_value, bool expect_success)
{
	struct invpcid_desc desc;

	memset(&desc, 0, sizeof(desc));
	bool success;

	desc.addr = test_value;
	desc.pcid = 10; /* Arbitrary number*/

	success = invpcid_safe(0, &desc) == 0;

	report(success == expect_success,
	       "Tested invpcid type 0 with 0x%lx value - %s",
	       test_value, success ? "success" : "failure");
}

static void test_invpcid(void)
{
	/*
	 * Note that this test tests the kvm's behavior only when ept=0.
	 * Otherwise invpcid is not intercepted.
	 *
	 * Also KVM's x86 emulator doesn't support invpcid, thus testing invpcid
	 * with FEP is pointless.
	 */
	assert(write_cr4_safe(read_cr4() | X86_CR4_PCIDE) == 0);

	__test_invpcid(CANONICAL_48_VAL, true);
	__test_invpcid(CANONICAL_57_VAL, this_cpu_has(X86_FEATURE_LA57));
	__test_invpcid(NONCANONICAL, false);
}

static void __test_canonical_checks(bool force_emulation)
{
	printf("\nRunning canonical test %s forced emulation:\n",
	       force_emulation ? "with" : "without");

	/* Direct DT addresses */
	TEST_REGISTER(GDTR_BASE, force_emulation);
	TEST_REGISTER(IDTR_BASE, force_emulation);

	/* Indirect DT addresses */
	TEST_REGISTER(TR_BASE, force_emulation);
	TEST_REGISTER(LDT_BASE, force_emulation);

	/* x86_64 extended segment bases */
	TEST_MSR(MSR_FS_BASE, force_emulation);
	TEST_MSR(MSR_GS_BASE, force_emulation);
	TEST_MSR(MSR_KERNEL_GS_BASE, force_emulation);

	/*
	 * SYSENTER ESP/EIP MSRs have canonical checks only on Intel, because
	 * only on Intel these instructions were extended to 64 bit.
	 *
	 * KVM emulation however ignores canonical checks for these MSRs, even
	 * on Intel, to support cross-vendor migration.  This includes nested
	 * virtualization.
	 *
	 * Thus, the checks only work when run on bare metal, without forced
	 * emulation.  Unfortunately, there is no foolproof way to detect bare
	 * metal from within this test.  E.g. checking HYPERVISOR in CPUID is
	 * useless because that only detects if _this_ code is running in a VM,
	 * it doesn't detect if the "host" is itself a VM.
	 *
	 * TODO: Enable testing of SYSENTER MSRs on bare metal.
	 */
	if (false && is_intel() && !force_emulation) {
		TEST_MSR(MSR_IA32_SYSENTER_ESP, force_emulation);
		TEST_MSR(MSR_IA32_SYSENTER_EIP, force_emulation);
	} else {
		report_skip("skipping MSR_IA32_SYSENTER_ESP/MSR_IA32_SYSENTER_EIP %s",
			    (is_intel() ? "due to known errata in KVM" : "due to AMD host"));
	}

	/*  SYSCALL target MSRs */
	TEST_MSR(MSR_CSTAR, force_emulation);
	TEST_MSR(MSR_LSTAR, force_emulation);

	/* PEBS DS area */
	if (this_cpu_has(X86_FEATURE_DS))
		TEST_MSR(MSR_IA32_DS_AREA, force_emulation);
	else
		report_skip("Skipping MSR_IA32_DS_AREA - PEBS not supported");

	/* PT filter ranges */
	if (this_cpu_has(X86_FEATURE_INTEL_PT)) {
		int n_ranges = cpuid_indexed(0x14, 0x1).a & 0x7;
		int i;

		for (i = 0 ; i < n_ranges ; i++) {
			wrmsr(MSR_IA32_RTIT_CTL, (1ull << (RTIT_CTL_ADDR0_OFFSET+i*4)));
			__TEST_MSR("MSR_IA32_RTIT_ADDR_A",
				   MSR_IA32_RTIT_ADDR0_A + i*2, force_emulation);
			__TEST_MSR("MSR_IA32_RTIT_ADDR_B",
				   MSR_IA32_RTIT_ADDR0_B + i*2, force_emulation);
		}
	} else {
		report_skip("Skipping MSR_IA32_RTIT_ADDR* - Intel PT is not supported");
	}

	/* Test that INVPCID type 0 #GPs correctly */
	if (this_cpu_has(X86_FEATURE_INVPCID))
		test_invpcid();
	else
		report_skip("Skipping INVPCID - not supported");
}

static void test_canonical_checks(void)
{
	__test_canonical_checks(false);

	if (is_fep_available())
		__test_canonical_checks(true);
	else
		report_skip("Force emulation prefix not enabled");
}
#endif

int main(int ac, char **av)
{
	int vector = write_cr4_safe(read_cr4() | X86_CR4_LA57);
	bool is_64bit = rdmsr(MSR_EFER) & EFER_LMA;
	int expected = !is_64bit && this_cpu_has(X86_FEATURE_LA57) ? 0 : GP_VECTOR;

	report(vector == expected, "%s when CR4.LA57 %ssupported (in %u-bit mode)",
	       expected ? "#GP" : "No fault",
	       this_cpu_has(X86_FEATURE_LA57) ? "un" : "", is_64bit ? 64 : 32);

#ifdef __x86_64__
	/* set dummy LDTR pointer */
	set_gdt_entry(FIRST_SPARE_SEL, 0xffaabb, 0xffff, 0x82, 0);
	lldt(FIRST_SPARE_SEL);

	test_canonical_checks();

	if (is_64bit && this_cpu_has(X86_FEATURE_LA57)) {
		printf("Switching to 5 level paging mode and rerunning canonical tests.\n");
		setup_5level_page_table();
	}
#endif

	return report_summary();
}
