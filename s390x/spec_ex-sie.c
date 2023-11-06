// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright IBM Corp. 2021
 *
 * Specification exception interception test.
 * Checks that specification exception interceptions occur as expected when
 * specification exception interpretation is off/on.
 */
#include <libcflat.h>
#include <stdlib.h>
#include <sclp.h>
#include <asm/page.h>
#include <asm/arch_def.h>
#include <alloc_page.h>
#include <sie.h>
#include <snippet.h>
#include <hardware.h>

static struct vm vm;
static bool strict;

static void setup_guest(void)
{
	extern const char SNIPPET_NAME_START(c, spec_ex)[];
	extern const char SNIPPET_NAME_END(c, spec_ex)[];

	setup_vm();

	snippet_setup_guest(&vm, false);
	snippet_init(&vm, SNIPPET_NAME_START(c, spec_ex),
		     SNIPPET_LEN(c, spec_ex), SNIPPET_UNPACK_OFF);
}

static void reset_guest(void)
{
	vm.sblk->gpsw = snippet_psw;
	vm.sblk->icptcode = 0;
}

static void test_spec_ex_sie(void)
{
	const char *msg;

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
	msg = "Interpreted initial exception, intercepted invalid program new PSW exception";
	if (strict)
		report(vm.sblk->gpsw.addr == 0xdeadbeee, "%s", msg);
	else if (vm.sblk->gpsw.addr == 0xdeadbeee)
		report_info("%s", msg);
	else
		report_info("Did not interpret initial exception");
	report_prefix_pop();
	report_prefix_pop();
}

static bool parse_strict(int argc, char **argv)
{
	uint16_t machine_id;
	char *list;
	bool ret;

	if (argc < 1)
		return false;
	if (strcmp("--strict", argv[0]))
		return false;

	machine_id = get_machine_id();
	if (argc < 2) {
		printf("No argument to --strict, ignoring\n");
		return false;
	}
	list = argv[1];
	if (list[0] == '!') {
		ret = true;
		list++;
	} else {
		ret = false;
	}
	while (true) {
		long input = 0;

		if (strlen(list) == 0)
			return ret;
		input = strtol(list, &list, 16);
		if (*list == ',')
			list++;
		else if (*list != '\0')
			break;
		if (input == machine_id)
			return !ret;
	}
	printf("Invalid --strict argument \"%s\", ignoring\n", list);
	return ret;
}

int main(int argc, char **argv)
{
	strict = parse_strict(argc - 1, argv + 1);
	if (!sclp_facilities.has_sief2) {
		report_skip("SIEF2 facility unavailable");
		goto out;
	}

	test_spec_ex_sie();
out:
	return report_summary();
}
