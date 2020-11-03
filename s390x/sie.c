#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/arch_def.h>
#include <asm/interrupt.h>
#include <asm/page.h>
#include <alloc_page.h>
#include <vmalloc.h>
#include <asm/facility.h>
#include <mmu.h>
#include <sclp.h>
#include <sie.h>

static u8 *guest;
static u8 *guest_instr;
static struct vm vm;

static void handle_validity(struct vm *vm)
{
	report(0, "VALIDITY: %x", vm->sblk->ipb >> 16);
}

static void sie(struct vm *vm)
{
	while (vm->sblk->icptcode == 0) {
		sie64a(vm->sblk, &vm->save_area);
		if (vm->sblk->icptcode == ICPT_VALIDITY)
			handle_validity(vm);
	}
	vm->save_area.guest.grs[14] = vm->sblk->gg14;
	vm->save_area.guest.grs[15] = vm->sblk->gg15;
}

static void sblk_cleanup(struct vm *vm)
{
	vm->sblk->icptcode = 0;
}

static void test_diag(u32 instr)
{
	vm.sblk->gpsw.addr = PAGE_SIZE * 2;
	vm.sblk->gpsw.mask = 0x0000000180000000ULL;

	memset(guest_instr, 0, PAGE_SIZE);
	memcpy(guest_instr, &instr, 4);
	sie(&vm);
	report(vm.sblk->icptcode == ICPT_INST &&
	       vm.sblk->ipa == instr >> 16 && vm.sblk->ipb == instr << 16,
	       "Intercept data");
	sblk_cleanup(&vm);
}

static struct {
	const char *name;
	u32 instr;
} tests[] = {
	{ "10", 0x83020010 },
	{ "44", 0x83020044 },
	{ "9c", 0x8302009c },
	{ NULL, 0 }
};

static void test_diags(void)
{
	int i;

	for (i = 0; tests[i].name; i++) {
		report_prefix_push(tests[i].name);
		test_diag(tests[i].instr);
		report_prefix_pop();
	}
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
}

int main(void)
{
	report_prefix_push("sie");
	if (!sclp_facilities.has_sief2) {
		report_skip("SIEF2 facility unavailable");
		goto done;
	}

	setup_guest();
	test_diags();
done:
	report_prefix_pop();
	return report_summary();
}
