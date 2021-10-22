// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright IBM Corp. 2021
 *
 * Specification exception interception test.
 * Checks that specification exception interceptions occur as expected when
 * specification exception interpretation is off/on.
 */
#include <libcflat.h>
#include <sclp.h>
#include <asm/page.h>
#include <asm/arch_def.h>
#include <alloc_page.h>
#include <vm.h>
#include <sie.h>
#include <snippet.h>

static struct vm vm;
extern const char SNIPPET_NAME_START(c, spec_ex)[];
extern const char SNIPPET_NAME_END(c, spec_ex)[];

static void setup_guest(void)
{
	char *guest;
	int binary_size = SNIPPET_LEN(c, spec_ex);

	setup_vm();
	guest = alloc_pages(8);
	memcpy(guest, SNIPPET_NAME_START(c, spec_ex), binary_size);
	sie_guest_create(&vm, (uint64_t) guest, HPAGE_SIZE);
}

static void reset_guest(void)
{
	vm.sblk->gpsw = snippet_psw;
	vm.sblk->icptcode = 0;
}

static void test_spec_ex_sie(void)
{
	setup_guest();

	report_prefix_push("SIE spec ex interpretation");
	report_prefix_push("off");
	reset_guest();
	sie(&vm);
	/* interpretation off -> initial exception must cause interception */
	report(vm.sblk->icptcode == ICPT_PROGI
	       && vm.sblk->iprcc == PGM_INT_CODE_SPECIFICATION
	       && vm.sblk->gpsw.addr != 0xdeadbeee,
	       "Received specification exception intercept for initial exception");
	report_prefix_pop();

	report_prefix_push("on");
	vm.sblk->ecb |= ECB_SPECI;
	reset_guest();
	sie(&vm);
	/* interpretation on -> configuration dependent if initial exception causes
	 * interception, but invalid new program PSW must
	 */
	report(vm.sblk->icptcode == ICPT_PROGI
	       && vm.sblk->iprcc == PGM_INT_CODE_SPECIFICATION,
	       "Received specification exception intercept");
	if (vm.sblk->gpsw.addr == 0xdeadbeee)
		report_info("Interpreted initial exception, intercepted invalid program new PSW exception");
	else
		report_info("Did not interpret initial exception");
	report_prefix_pop();
	report_prefix_pop();
}

int main(int argc, char **argv)
{
	if (!sclp_facilities.has_sief2) {
		report_skip("SIEF2 facility unavailable");
		goto out;
	}

	test_spec_ex_sie();
out:
	return report_summary();
}
