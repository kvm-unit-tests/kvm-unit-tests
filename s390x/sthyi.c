/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Tests exceptions and data validity for the emulated sthyi
 * instruction.
 *
 * Copyright 2018 IBM Corp.
 *
 * Authors:
 *    Janosch Frank <frankja@linux.vnet.ibm.com>
 */
#include <libcflat.h>
#include <asm/asm-offsets.h>
#include <asm/interrupt.h>
#include <asm/page.h>
#include <asm/facility.h>

#include "sthyi.h"

static uint8_t pagebuf[PAGE_SIZE] __attribute__((aligned(PAGE_SIZE)));
static char null_buf[32] = {};

static inline int sthyi(uint64_t vaddr, uint64_t fcode, uint64_t *rc,
			unsigned int r1, unsigned int r2)
{
	register uint64_t code asm("0") = fcode;
	register uint64_t addr asm("2") = vaddr;
	register uint64_t rc3 asm("3") = 0;
	int cc = 0;

	asm volatile(".insn rre,0xB2560000,%[r1],%[r2]\n"
		     "ipm	 %[cc]\n"
		     "srl	 %[cc],28\n"
		     : [cc] "=d" (cc)
		     : [code] "d" (code), [addr] "a" (addr), [r1] "i" (r1),
		       [r2] "i" (r2)
		     : "memory", "cc", "r3");
	if (rc)
		*rc = rc3;
	return cc;
}

static void test_exception_addr(void)
{
	report_prefix_push("Illegal address check");
	expect_pgm_int();
	sthyi(42042, 0, NULL, 0, 2);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static void test_exception_reg_odd(void)
{
	report_prefix_push("Register check odd R1");
	expect_pgm_int();
	sthyi((uint64_t)pagebuf, 0, NULL, 1, 2);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
	report_prefix_push("Register check odd R2");
	expect_pgm_int();
	sthyi((uint64_t)pagebuf, 0, NULL, 0, 3);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static void test_exception_reg_equal(void)
{
	report_prefix_push("Register check equal");
	expect_pgm_int();
	sthyi((uint64_t)pagebuf, 0, NULL, 0, 0);
	check_pgm_int_code(PGM_INT_CODE_SPECIFICATION);
	report_prefix_pop();
}

static void test_function_code(uint64_t addr)
{
	uint64_t urc = 0;
	int cc = sthyi((uint64_t)pagebuf, 42, &urc, 0, 2);

	report(cc == 3 && urc == CODE_UNSUPP, "Illegal fcode");
}

static void test_fcode0_hdr(struct sthyi_hdr_sctn *hdr)
{
	report_prefix_push("Header");

	report(hdr->INFHDLN >= sizeof(*hdr) && !(hdr->INFHDLN % 8), "length");
	report((hdr->INFMLEN >= sizeof(struct sthyi_mach_sctn) && !(hdr->INFMLEN % 8)),
	       "Machine sctn length");
	report((hdr->INFPLEN >= sizeof(struct sthyi_par_sctn) && !(hdr->INFPLEN % 8)),
	       "Partition section length");

	report(hdr->INFMOFF >= hdr->INFHDLN, "Machine offset");
	report(hdr->INFPOFF >= hdr->INFHDLN, "Partition offset");
	report_prefix_pop();
}

static void test_fcode0_mach(struct sthyi_mach_sctn *mach)
{
	int sum = mach->INFMSCPS + mach->INFMDCPS + mach->INFMSIFL + mach->INFMDIFL;

	report_prefix_push("Machine");
	if (mach->INFMVAL1 & MACH_ID_VLD) {
		report(memcmp(mach->INFMTYPE, null_buf, sizeof(mach->INFMTYPE)),
		       "type");
		report(memcmp(mach->INFMMANU, null_buf, sizeof(mach->INFMMANU)),
		       "manufacturer");
		report(memcmp(mach->INFMSEQ, null_buf, sizeof(mach->INFMSEQ)),
		       "sequence");
		report(memcmp(mach->INFMPMAN, null_buf, sizeof(mach->INFMPMAN)),
		       "plant");
	}

	if (mach->INFMVAL1 & MACH_NAME_VLD)
		report(memcmp(mach->INFMNAME, null_buf, sizeof(mach->INFMNAME)),
		       "name");

	if (mach->INFMVAL1 & MACH_CNT_VLD)
		report(sum, "core counts");
	report_prefix_pop();
}

static void test_fcode0_par(struct sthyi_par_sctn *par)
{
	int sum = par->INFPSCPS + par->INFPDCPS + par->INFPSIFL + par->INFPDIFL;

	report_prefix_push("Partition");
	if (par->INFPVAL1 & PART_CNT_VLD)
		report(sum, "core counts");

	if (par->INFPVAL1 & PART_STSI_SUC) {
		report(memcmp(par->INFPPNAM, null_buf, sizeof(par->INFPPNAM)),
		       "name");
	}
	report_prefix_pop();
}

static void test_fcode0(void)
{
	struct sthyi_hdr_sctn *hdr;
	struct sthyi_mach_sctn *mach;
	struct sthyi_par_sctn *par;

	/* Zero destination memory. */
	memset(pagebuf, 0, PAGE_SIZE);

	report_prefix_push("fcode 0");
	sthyi((uint64_t)pagebuf, 0, NULL, 0, 2);
	hdr = (void *)pagebuf;
	mach = (void *)pagebuf + hdr->INFMOFF;
	par = (void *)pagebuf + hdr->INFPOFF;

	test_fcode0_hdr(hdr);
	test_fcode0_mach(mach);
	test_fcode0_par(par);
	report_prefix_pop();
}

int main(void)
{
	bool has_sthyi = test_facility(74);

	report_prefix_push("sthyi");

	/* Test for availability */
	if (!has_sthyi) {
		report_skip("STHYI is not available");
		goto done;
	}

	/* Test register/argument checking. */
	report_prefix_push("Instruction");
	test_exception_addr();
	test_exception_reg_odd();
	test_exception_reg_equal();
	test_function_code((uint64_t) pagebuf);
	report_prefix_pop();

	/* Test function code 0 - CP and IFL Capacity Information */
	test_fcode0();

done:
	report_prefix_pop();
	return report_summary();
}
