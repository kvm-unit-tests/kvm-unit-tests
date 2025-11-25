/*
 * Intel LAM unit test
 *
 * Copyright (C) 2023 Intel
 *
 * Author: Robert Hoo <robert.hu@linux.intel.com>
 *         Binbin Wu <binbin.wu@linux.intel.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or
 * later.
 */

#include "libcflat.h"
#include "processor.h"
#include "desc.h"
#include <util.h>
#include "vmalloc.h"
#include "alloc_page.h"
#include "vm.h"
#include "asm/io.h"
#include "ioram.h"

static void test_cr4_lam_set_clear(void)
{
	int vector;
	bool has_lam = this_cpu_has(X86_FEATURE_LAM);

	vector = write_cr4_safe(read_cr4() | X86_CR4_LAM_SUP);
	report(has_lam ? !vector : vector == GP_VECTOR,
	       "Expected CR4.LAM_SUP=1 to %s", has_lam ? "succeed" : "#GP");

	vector = write_cr4_safe(read_cr4() & ~X86_CR4_LAM_SUP);
	report(!vector, "Expected CR4.LAM_SUP=0 to succeed");
}

/* Refer to emulator.c */
static void do_mov(void *mem)
{
	unsigned long t1, t2;

	t1 = 0x123456789abcdefull & -1ul;
	asm volatile("mov %[t1], (%[mem])\n\t"
		     "mov (%[mem]), %[t2]"
		     : [t2]"=r"(t2)
		     : [t1]"r"(t1), [mem]"r"(mem)
		     : "memory");
	report(t1 == t2, "Mov result check");
}

static bool get_lam_mask(u64 address, u64* lam_mask)
{
	/*
	 * Use LAM57_MASK as mask to construct non-canonical address if LAM is
	 * not supported or enabled.
	 */
	*lam_mask = LAM57_MASK;

	/*
	 * Bit 63 determines if the address should be treated as a user address
	 * or a supervisor address.
	 */
	if (address & BIT_ULL(63)) {
		if (!(is_lam_sup_enabled()))
			return false;

		if (!is_la57_enabled())
			*lam_mask = LAM48_MASK;
		return true;
	}

	if(is_lam_u48_enabled()) {
		*lam_mask = LAM48_MASK;
		return true;
	}

	if(is_lam_u57_enabled())
		return true;

	return false;
}


static void test_ptr(u64* ptr, bool is_mmio)
{
	u64 lam_mask;
	bool lam_active, fault;

	lam_active = get_lam_mask((u64)ptr, &lam_mask);

	fault = test_for_exception(GP_VECTOR, do_mov, ptr);
	report(!fault, "Expected access to untagged address for %s to succeed",
	       is_mmio ? "MMIO" : "memory");

	ptr = (u64 *)get_non_canonical((u64)ptr, lam_mask);
	fault = test_for_exception(GP_VECTOR, do_mov, ptr);
	report(fault != lam_active, "Expected access to tagged address for %s %s LAM to %s",
	       is_mmio ? "MMIO" : "memory", lam_active ? "with" : "without",
	       lam_active ? "succeed" : "#GP");

	/*
	 * This test case is only triggered when LAM_U57 is active and 4-level
	 * paging is used. For the case, bit[56:47] aren't all 0 triggers #GP.
	 */
	if (lam_active && (lam_mask == LAM57_MASK) && !is_la57_enabled()) {
		ptr = (u64 *)get_non_canonical((u64)ptr, LAM48_MASK);
		fault = test_for_exception(GP_VECTOR, do_mov, ptr);
		report(fault, "Expected access to non-LAM-canonical address for %s to #GP",
		       is_mmio ? "MMIO" : "memory");
	}
}

/* invlpg with tagged address is same as NOP, no #GP expected. */
static void test_invlpg(void *va, bool fep)
{
	u64 lam_mask;
	u64 *ptr;

	/*
	 * The return value is not checked, invlpg should never faults no matter
	 * LAM is supported or not.
	 */
	get_lam_mask((u64)va, &lam_mask);
	ptr = (u64 *)get_non_canonical((u64)va, lam_mask);
	if (fep)
		asm volatile(KVM_FEP "invlpg (%0)" ::"r" (ptr) : "memory");
	else
		invlpg(ptr);

	report_pass("Expected %sINVLPG with tagged addr to succeed", fep ? "fep: " : "");
}

/* LAM doesn't apply to the linear address in the descriptor of invpcid */
static void test_invpcid(void *data)
{
	/*
	 * Reuse the memory address for the descriptor since stack memory
	 * address in KUT doesn't follow the kernel address space partitions.
	 */
	struct invpcid_desc *desc_ptr = data;
	int vector;
	u64 lam_mask;
	bool lam_active;

	if (!this_cpu_has(X86_FEATURE_INVPCID)) {
		report_skip("INVPCID not supported");
		return;
	}

	lam_active = get_lam_mask((u64)data, &lam_mask);

	memset(desc_ptr, 0, sizeof(struct invpcid_desc));
	desc_ptr->addr = (u64)data;

	vector = invpcid_safe(0, desc_ptr);
	report(!vector,
	       "Expected INVPCID with untagged pointer + untagged addr to succeed, got vector %u",
	       vector);

	desc_ptr->addr = get_non_canonical(desc_ptr->addr, lam_mask);
	vector = invpcid_safe(0, desc_ptr);
	report(vector == GP_VECTOR,
	       "Expected INVPCID with untagged pointer + tagged addr to #GP, got vector %u",
	       vector);

	desc_ptr = (void *)get_non_canonical((u64)desc_ptr, lam_mask);
	vector = invpcid_safe(0, desc_ptr);
	report(vector == GP_VECTOR,
	       "Expected INVPCID with tagged pointer + tagged addr to #GP, got vector %u",
	       vector);

	desc_ptr = data;
	desc_ptr->addr = (u64)data;
	desc_ptr = (void *)get_non_canonical((u64)desc_ptr, lam_mask);
	vector = invpcid_safe(0, desc_ptr);
	report(lam_active ? !vector : vector == GP_VECTOR,
	       "Expected INVPCID with tagged pointer + untagged addr to %s, got vector %u",
	       lam_active ? "succeed" : "#GP", vector);
}

static void __test_lam_sup(void *vaddr, void *vaddr_mmio)
{
	/* Test for normal memory. */
	test_ptr(vaddr, false);
	/* Test for MMIO to trigger instruction emulation. */
	test_ptr(vaddr_mmio, true);
	test_invpcid(vaddr);
	test_invlpg(vaddr, false);
	if (is_fep_available)
		test_invlpg(vaddr, true);
}

static void test_lam_sup(void)
{
	void *vaddr, *vaddr_mmio;
	phys_addr_t paddr;
	unsigned long cr4 = read_cr4();
	int vector;

	/*
	 * KUT initializes vfree_top to -PAGE_SIZE for X86_64, and each virtual
	 * address allocation decreases the size from vfree_top. It's
	 * guaranteed that the return value of alloc_vpage() is considered as
	 * kernel mode address and canonical since only a small amount of
	 * virtual address range is allocated in this test.
	 */
	vaddr = alloc_vpage();
	vaddr_mmio = alloc_vpage();
	paddr = virt_to_phys(alloc_page());
	install_page(current_page_table(), paddr, vaddr);
	install_page(current_page_table(), IORAM_BASE_PHYS, vaddr_mmio);

	test_cr4_lam_set_clear();

	/* Test without LAM Supervisor enabled. */
	__test_lam_sup(vaddr, vaddr_mmio);

	/* Test with LAM Supervisor enabled, if supported. */
	if (this_cpu_has(X86_FEATURE_LAM)) {
		vector = write_cr4_safe(cr4 | X86_CR4_LAM_SUP);
		report(!vector && is_lam_sup_enabled(),
		       "Expected CR4.LAM_SUP=1 to succeed");
		__test_lam_sup(vaddr, vaddr_mmio);
	}
}

static void test_lam_user(void)
{
	void* vaddr;
	int vector;
	unsigned long cr3 = read_cr3() & ~(X86_CR3_LAM_U48 | X86_CR3_LAM_U57);
	bool has_lam = this_cpu_has(X86_FEATURE_LAM);

	/*
	 * The physical address of AREA_NORMAL is within 36 bits, so that using
	 * identical mapping, the linear address will be considered as user mode
	 * address from the view of LAM, and the metadata bits are not used as
	 * address for both LAM48 and LAM57.
	 */
	vaddr = alloc_pages_flags(0, AREA_NORMAL);
	static_assert((AREA_NORMAL_PFN & GENMASK(63, 47)) == 0UL);

	/*
	 * Note, LAM doesn't have a global control bit to turn on/off LAM
	 * completely, but purely depends on hardware's CPUID to determine it
	 * can be enabled or not. That means, when EPT is on, even when KVM
	 * doesn't expose LAM to guest, the guest can still set LAM control bits
	 * in CR3 w/o causing problem. This is an unfortunate virtualization
	 * hole. KVM doesn't choose to intercept CR3 in this case for
	 * performance.
	 * Only enable LAM CR3 bits when LAM feature is exposed.
	 */
	if (has_lam) {
		vector = write_cr3_safe(cr3 | X86_CR3_LAM_U48);
		report(!vector && is_lam_u48_enabled(), "Expected CR3.LAM_U48=1 to succeed");
	}
	/*
	 * Physical memory & MMIO have already been identical mapped in
	 * setup_mmu().
	 */
	test_ptr(vaddr, false);
	test_ptr(phys_to_virt(IORAM_BASE_PHYS), true);

	if (has_lam) {
		vector = write_cr3_safe(cr3 | X86_CR3_LAM_U57);
		report(!vector && is_lam_u57_enabled(), "Expected CR3.LAM_U57=1 to succeed");

		/* If !has_lam, it has been tested above, no need to test again. */
		test_ptr(vaddr, false);
		test_ptr(phys_to_virt(IORAM_BASE_PHYS), true);
	}
}

int main(int ac, char **av)
{
	setup_vm();

	if (!this_cpu_has(X86_FEATURE_LAM))
		report_info("This CPU doesn't support LAM\n");
	else
		report_info("This CPU supports LAM\n");

	test_lam_sup();
	test_lam_user();

	return report_summary();
}
