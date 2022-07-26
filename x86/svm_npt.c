#include "svm.h"
#include "vm.h"
#include "alloc_page.h"
#include "vmalloc.h"

static void *scratch_page;

static void null_test(struct svm_test *test)
{
}

static void npt_np_prepare(struct svm_test *test)
{
	u64 *pte;

	scratch_page = alloc_page();
	pte = npt_get_pte((u64) scratch_page);

	*pte &= ~1ULL;
}

static void npt_np_test(struct svm_test *test)
{
	(void)*(volatile u64 *)scratch_page;
}

static bool npt_np_check(struct svm_test *test)
{
	u64 *pte = npt_get_pte((u64) scratch_page);

	*pte |= 1ULL;

	return (vmcb->control.exit_code == SVM_EXIT_NPF)
	    && (vmcb->control.exit_info_1 == 0x100000004ULL);
}

static void npt_nx_prepare(struct svm_test *test)
{
	u64 *pte;

	test->scratch = rdmsr(MSR_EFER);
	wrmsr(MSR_EFER, test->scratch | EFER_NX);

	/* Clear the guest's EFER.NX, it should not affect NPT behavior. */
	vmcb->save.efer &= ~EFER_NX;

	pte = npt_get_pte((u64) null_test);

	*pte |= PT64_NX_MASK;
}

static bool npt_nx_check(struct svm_test *test)
{
	u64 *pte = npt_get_pte((u64) null_test);

	wrmsr(MSR_EFER, test->scratch);

	*pte &= ~PT64_NX_MASK;

	return (vmcb->control.exit_code == SVM_EXIT_NPF)
	    && (vmcb->control.exit_info_1 == 0x100000015ULL);
}

static void npt_us_prepare(struct svm_test *test)
{
	u64 *pte;

	scratch_page = alloc_page();
	pte = npt_get_pte((u64) scratch_page);

	*pte &= ~(1ULL << 2);
}

static void npt_us_test(struct svm_test *test)
{
	(void)*(volatile u64 *)scratch_page;
}

static bool npt_us_check(struct svm_test *test)
{
	u64 *pte = npt_get_pte((u64) scratch_page);

	*pte |= (1ULL << 2);

	return (vmcb->control.exit_code == SVM_EXIT_NPF)
	    && (vmcb->control.exit_info_1 == 0x100000005ULL);
}

static void npt_rw_prepare(struct svm_test *test)
{

	u64 *pte;

	pte = npt_get_pte(0x80000);

	*pte &= ~(1ULL << 1);
}

static void npt_rw_test(struct svm_test *test)
{
	u64 *data = (void *)(0x80000);

	*data = 0;
}

static bool npt_rw_check(struct svm_test *test)
{
	u64 *pte = npt_get_pte(0x80000);

	*pte |= (1ULL << 1);

	return (vmcb->control.exit_code == SVM_EXIT_NPF)
	    && (vmcb->control.exit_info_1 == 0x100000007ULL);
}

static void npt_rw_pfwalk_prepare(struct svm_test *test)
{

	u64 *pte;

	pte = npt_get_pte(read_cr3());

	*pte &= ~(1ULL << 1);
}

static bool npt_rw_pfwalk_check(struct svm_test *test)
{
	u64 *pte = npt_get_pte(read_cr3());

	*pte |= (1ULL << 1);

	return (vmcb->control.exit_code == SVM_EXIT_NPF)
	    && (vmcb->control.exit_info_1 == 0x200000007ULL)
	    && (vmcb->control.exit_info_2 == read_cr3());
}

static void npt_l1mmio_prepare(struct svm_test *test)
{
}

u32 nested_apic_version1;
u32 nested_apic_version2;

static void npt_l1mmio_test(struct svm_test *test)
{
	volatile u32 *data = (volatile void *)(0xfee00030UL);

	nested_apic_version1 = *data;
	nested_apic_version2 = *data;
}

static bool npt_l1mmio_check(struct svm_test *test)
{
	volatile u32 *data = (volatile void *)(0xfee00030);
	u32 lvr = *data;

	return nested_apic_version1 == lvr && nested_apic_version2 == lvr;
}

static void npt_rw_l1mmio_prepare(struct svm_test *test)
{

	u64 *pte;

	pte = npt_get_pte(0xfee00080);

	*pte &= ~(1ULL << 1);
}

static void npt_rw_l1mmio_test(struct svm_test *test)
{
	volatile u32 *data = (volatile void *)(0xfee00080);

	*data = *data;
}

static bool npt_rw_l1mmio_check(struct svm_test *test)
{
	u64 *pte = npt_get_pte(0xfee00080);

	*pte |= (1ULL << 1);

	return (vmcb->control.exit_code == SVM_EXIT_NPF)
	    && (vmcb->control.exit_info_1 == 0x100000007ULL);
}

static void basic_guest_main(struct svm_test *test)
{
}

static void __svm_npt_rsvd_bits_test(u64 * pxe, u64 rsvd_bits, u64 efer,
				     ulong cr4, u64 guest_efer, ulong guest_cr4)
{
	u64 pxe_orig = *pxe;
	int exit_reason;
	u64 pfec;

	wrmsr(MSR_EFER, efer);
	write_cr4(cr4);

	vmcb->save.efer = guest_efer;
	vmcb->save.cr4 = guest_cr4;

	*pxe |= rsvd_bits;

	exit_reason = svm_vmrun();

	report(exit_reason == SVM_EXIT_NPF,
	       "Wanted #NPF on rsvd bits = 0x%lx, got exit = 0x%x", rsvd_bits,
	       exit_reason);

	if (pxe == npt_get_pdpe((u64) basic_guest_main) || pxe == npt_get_pml4e()) {
		/*
		 * The guest's page tables will blow up on a bad PDPE/PML4E,
		 * before starting the final walk of the guest page.
		 */
		pfec = 0x20000000full;
	} else {
		/* RSVD #NPF on final walk of guest page. */
		pfec = 0x10000000dULL;

		/* PFEC.FETCH=1 if NX=1 *or* SMEP=1. */
		if ((cr4 & X86_CR4_SMEP) || (efer & EFER_NX))
			pfec |= 0x10;

	}

	report(vmcb->control.exit_info_1 == pfec,
	       "Wanted PFEC = 0x%lx, got PFEC = %lx, PxE = 0x%lx.  "
	       "host.NX = %u, host.SMEP = %u, guest.NX = %u, guest.SMEP = %u",
	       pfec, vmcb->control.exit_info_1, *pxe,
	       !!(efer & EFER_NX), !!(cr4 & X86_CR4_SMEP),
	       !!(guest_efer & EFER_NX), !!(guest_cr4 & X86_CR4_SMEP));

	*pxe = pxe_orig;
}

static void _svm_npt_rsvd_bits_test(u64 * pxe, u64 pxe_rsvd_bits, u64 efer,
				    ulong cr4, u64 guest_efer, ulong guest_cr4)
{
	u64 rsvd_bits;
	int i;

	/*
	 * RDTSC or RDRAND can sometimes fail to generate a valid reserved bits
	 */
	if (!pxe_rsvd_bits) {
		report_skip
		    ("svm_npt_rsvd_bits_test: Reserved bits are not valid");
		return;
	}

	/*
	 * Test all combinations of guest/host EFER.NX and CR4.SMEP.  If host
	 * EFER.NX=0, use NX as the reserved bit, otherwise use the passed in
	 * @pxe_rsvd_bits.
	 */
	for (i = 0; i < 16; i++) {
		if (i & 1) {
			rsvd_bits = pxe_rsvd_bits;
			efer |= EFER_NX;
		} else {
			rsvd_bits = PT64_NX_MASK;
			efer &= ~EFER_NX;
		}
		if (i & 2)
			cr4 |= X86_CR4_SMEP;
		else
			cr4 &= ~X86_CR4_SMEP;
		if (i & 4)
			guest_efer |= EFER_NX;
		else
			guest_efer &= ~EFER_NX;
		if (i & 8)
			guest_cr4 |= X86_CR4_SMEP;
		else
			guest_cr4 &= ~X86_CR4_SMEP;

		__svm_npt_rsvd_bits_test(pxe, rsvd_bits, efer, cr4,
					 guest_efer, guest_cr4);
	}
}

static u64 get_random_bits(u64 hi, u64 low)
{
	unsigned retry = 5;
	u64 rsvd_bits = 0;

	if (this_cpu_has(X86_FEATURE_RDRAND)) {
		do {
			rsvd_bits = (rdrand() << low) & GENMASK_ULL(hi, low);
			retry--;
		} while (!rsvd_bits && retry);
	}

	if (!rsvd_bits) {
		retry = 5;
		do {
			rsvd_bits = (rdtsc() << low) & GENMASK_ULL(hi, low);
			retry--;
		} while (!rsvd_bits && retry);
	}

	return rsvd_bits;
}

static void svm_npt_rsvd_bits_test(void)
{
	u64 saved_efer, host_efer, sg_efer, guest_efer;
	ulong saved_cr4, host_cr4, sg_cr4, guest_cr4;

	if (!npt_supported()) {
		report_skip("NPT not supported");
		return;
	}

	saved_efer = host_efer = rdmsr(MSR_EFER);
	saved_cr4 = host_cr4 = read_cr4();
	sg_efer = guest_efer = vmcb->save.efer;
	sg_cr4 = guest_cr4 = vmcb->save.cr4;

	test_set_guest(basic_guest_main);

	/*
	 * 4k PTEs don't have reserved bits if MAXPHYADDR >= 52, just skip the
	 * sub-test.  The NX test is still valid, but the extra bit of coverage
	 * isn't worth the extra complexity.
	 */
	if (cpuid_maxphyaddr() >= 52)
		goto skip_pte_test;

	_svm_npt_rsvd_bits_test(npt_get_pte((u64) basic_guest_main),
				get_random_bits(51, cpuid_maxphyaddr()),
				host_efer, host_cr4, guest_efer, guest_cr4);

skip_pte_test:
	_svm_npt_rsvd_bits_test(npt_get_pde((u64) basic_guest_main),
				get_random_bits(20, 13) | PT_PAGE_SIZE_MASK,
				host_efer, host_cr4, guest_efer, guest_cr4);

	_svm_npt_rsvd_bits_test(npt_get_pdpe((u64) basic_guest_main),
				PT_PAGE_SIZE_MASK |
				(this_cpu_has(X86_FEATURE_GBPAGES) ?
				 get_random_bits(29, 13) : 0), host_efer,
				host_cr4, guest_efer, guest_cr4);

	_svm_npt_rsvd_bits_test(npt_get_pml4e(), BIT_ULL(8),
				host_efer, host_cr4, guest_efer, guest_cr4);

	wrmsr(MSR_EFER, saved_efer);
	write_cr4(saved_cr4);
	vmcb->save.efer = sg_efer;
	vmcb->save.cr4 = sg_cr4;
}

#define NPT_V1_TEST(name, prepare, guest_code, check)				\
	{ #name, npt_supported, prepare, default_prepare_gif_clear, guest_code,	\
	  default_finished, check }

#define NPT_V2_TEST(name) { #name, .v2 = name }

static struct svm_test npt_tests[] = {
	NPT_V1_TEST(npt_nx, npt_nx_prepare, null_test, npt_nx_check),
	NPT_V1_TEST(npt_np, npt_np_prepare, npt_np_test, npt_np_check),
	NPT_V1_TEST(npt_us, npt_us_prepare, npt_us_test, npt_us_check),
	NPT_V1_TEST(npt_rw, npt_rw_prepare, npt_rw_test, npt_rw_check),
	NPT_V1_TEST(npt_rw_pfwalk, npt_rw_pfwalk_prepare, null_test, npt_rw_pfwalk_check),
	NPT_V1_TEST(npt_l1mmio, npt_l1mmio_prepare, npt_l1mmio_test, npt_l1mmio_check),
	NPT_V1_TEST(npt_rw_l1mmio, npt_rw_l1mmio_prepare, npt_rw_l1mmio_test, npt_rw_l1mmio_check),
	NPT_V2_TEST(svm_npt_rsvd_bits_test),
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};

int main(int ac, char **av)
{
	pteval_t opt_mask = 0;

	__setup_vm(&opt_mask);
	return run_svm_tests(ac, av, npt_tests);
}
