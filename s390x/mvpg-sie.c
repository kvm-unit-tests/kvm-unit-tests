#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm-generic/barrier.h>
#include <asm/pgtable.h>
#include <mmu.h>
#include <asm/page.h>
#include <asm/facility.h>
#include <asm/mem.h>
#include <alloc_page.h>
#include <vm.h>
#include <sclp.h>
#include <sie.h>

static u8 *guest;
static u8 *guest_instr;
static struct vm vm;

static uint8_t *src;
static uint8_t *dst;
static uint8_t *cmp;

extern const char _binary_s390x_snippets_c_mvpg_snippet_gbin_start[];
extern const char _binary_s390x_snippets_c_mvpg_snippet_gbin_end[];
int binary_size;

static void sie(struct vm *vm)
{
	/* Reset icptcode so we don't trip over it below */
	vm->sblk->icptcode = 0;

	while (vm->sblk->icptcode == 0) {
		sie64a(vm->sblk, &vm->save_area);
		assert(vm->sblk->icptcode != ICPT_VALIDITY);
	}
	vm->save_area.guest.grs[14] = vm->sblk->gg14;
	vm->save_area.guest.grs[15] = vm->sblk->gg15;
}

static void test_mvpg_pei(void)
{
	uint64_t **pei_dst = (uint64_t **)((uintptr_t) vm.sblk + 0xc0);
	uint64_t **pei_src = (uint64_t **)((uintptr_t) vm.sblk + 0xc8);

	report_prefix_push("pei");

	report_prefix_push("src");
	memset(dst, 0, PAGE_SIZE);
	protect_page(src, PAGE_ENTRY_I);
	sie(&vm);
	report(vm.sblk->icptcode == ICPT_PARTEXEC, "Partial execution");
	report((uintptr_t)**pei_src == (uintptr_t)src + PAGE_ENTRY_I, "PEI_SRC correct");
	report((uintptr_t)**pei_dst == (uintptr_t)dst, "PEI_DST correct");
	unprotect_page(src, PAGE_ENTRY_I);
	report(!memcmp(cmp, dst, PAGE_SIZE), "Destination intact");
	/*
	 * We need to execute the diag44 which is used as a blocker
	 * behind the mvpg. It makes sure we fail the tests above if
	 * the mvpg wouldn't have intercepted.
	 */
	sie(&vm);
	/* Make sure we intercepted for the diag44 and nothing else */
	assert(vm.sblk->icptcode == ICPT_INST &&
	       vm.sblk->ipa == 0x8300 && vm.sblk->ipb == 0x440000);
	report_prefix_pop();

	/* Clear PEI data for next check */
	report_prefix_push("dst");
	memset((uint64_t *)((uintptr_t) vm.sblk + 0xc0), 0, 16);
	memset(dst, 0, PAGE_SIZE);
	protect_page(dst, PAGE_ENTRY_I);
	sie(&vm);
	report(vm.sblk->icptcode == ICPT_PARTEXEC, "Partial execution");
	report((uintptr_t)**pei_src == (uintptr_t)src, "PEI_SRC correct");
	report((uintptr_t)**pei_dst == (uintptr_t)dst + PAGE_ENTRY_I, "PEI_DST correct");
	/* Needed for the memcmp and general cleanup */
	unprotect_page(dst, PAGE_ENTRY_I);
	report(!memcmp(cmp, dst, PAGE_SIZE), "Destination intact");
	report_prefix_pop();

	report_prefix_pop();
}

static void test_mvpg(void)
{
	int binary_size = ((uintptr_t)_binary_s390x_snippets_c_mvpg_snippet_gbin_end -
			   (uintptr_t)_binary_s390x_snippets_c_mvpg_snippet_gbin_start);

	memcpy(guest, _binary_s390x_snippets_c_mvpg_snippet_gbin_start, binary_size);
	memset(src, 0x42, PAGE_SIZE);
	memset(dst, 0x43, PAGE_SIZE);
	sie(&vm);
	report(!memcmp(src, dst, PAGE_SIZE) && *dst == 0x42, "Page moved");
}

static void setup_guest(void)
{
	setup_vm();

	/* Allocate 1MB as guest memory */
	guest = alloc_pages(8);
	/* The first two pages are the lowcore */
	guest_instr = guest + PAGE_SIZE * 2;

	vm.sblk = alloc_page();

	vm.sblk->cpuflags = CPUSTAT_ZARCH | CPUSTAT_RUNNING;
	vm.sblk->prefix = 0;
	/*
	 * Pageable guest with the same ASCE as the test programm, but
	 * the guest memory 0x0 is offset to start at the allocated
	 * guest pages and end after 1MB.
	 *
	 * It's not pretty but faster and easier than managing guest ASCEs.
	 */
	vm.sblk->mso = (u64)guest;
	vm.sblk->msl = (u64)guest;
	vm.sblk->ihcpu = 0xffff;

	vm.sblk->crycbd = (uint64_t)alloc_page();

	vm.sblk->gpsw.addr = PAGE_SIZE * 4;
	vm.sblk->gpsw.mask = 0x0000000180000000ULL;
	vm.sblk->ictl = ICTL_OPEREXC | ICTL_PINT;
	/* Enable MVPG interpretation as we want to test KVM and not ourselves */
	vm.sblk->eca = ECA_MVPGI;

	src = guest + PAGE_SIZE * 6;
	dst = guest + PAGE_SIZE * 5;
	cmp = alloc_page();
	memset(cmp, 0, PAGE_SIZE);
}

int main(void)
{
	report_prefix_push("mvpg-sie");
	if (!sclp_facilities.has_sief2) {
		report_skip("SIEF2 facility unavailable");
		goto done;
	}

	setup_guest();
	test_mvpg();
	test_mvpg_pei();

done:
	report_prefix_pop();
	return report_summary();

}
