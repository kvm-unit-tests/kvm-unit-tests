/*
 * Test Special Purpose Registers
 *
 * Copyright 2017  Thomas Huth, Red Hat Inc.
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 *
 * The basic idea of this test is to check whether the contents of the Special
 * Purpose Registers (SPRs) are preserved correctly during migration. So we
 * fill in the SPRs with a well-known value, read the values back (since not
 * all bits might be retained in the SPRs), then wait for a key or NMI (if the
 * '-w' option has been specified) so that the user has a chance to migrate the
 * VM. Alternatively, the test can also simply sleep a little bit with the
 * H_CEDE hypercall, in the hope that we'll get scheduled to another host CPU
 * and thus register contents might have changed, too (in case of bugs).
 * Finally, we read back the values from the SPRs and compare them with the
 * values before the migration. Mismatches are reported as test failures.
 * Note that we do not test all SPRs since some of the registers change their
 * content automatically, and some are only accessible with hypervisor privi-
 * leges or have bad side effects, so we have to omit those registers.
 */
#include <libcflat.h>
#include <util.h>
#include <alloc.h>
#include <asm/handlers.h>
#include <asm/hcall.h>
#include <asm/processor.h>
#include <asm/barrier.h>

#define mfspr(nr) ({ \
	uint64_t ret; \
	asm volatile("mfspr %0,%1" : "=r"(ret) : "i"(nr)); \
	ret; \
})

#define mtspr(nr, val) \
	asm volatile("mtspr %0,%1" : : "i"(nr), "r"(val))

uint64_t before[1024], after[1024];

volatile int nmi_occurred;

static void nmi_handler(struct pt_regs *regs __unused, void *opaque __unused)
{
	nmi_occurred = 1;
}

static int h_get_term_char(uint64_t termno)
{
	register uint64_t r3 asm("r3") = 0x54; /* H_GET_TERM_CHAR */
	register uint64_t r4 asm("r4") = termno;
	register uint64_t r5 asm("r5");

	asm volatile (" sc 1 "	: "+r"(r3), "+r"(r4), "=r"(r5)
				: "r"(r3),  "r"(r4));

	return r3 == H_SUCCESS && r4 > 0 ? r5 >> 48 : 0;
}

/* Common SPRs for all PowerPC CPUs */
static void set_sprs_common(uint64_t val)
{
	mtspr(9, val);		/* CTR */
	// mtspr(273, val);	/* SPRG1 */  /* Used by our exception handler */
	mtspr(274, val);	/* SPRG2 */
	mtspr(275, val);	/* SPRG3 */
}

/* SPRs from PowerPC Operating Environment Architecture, Book III, Vers. 2.01 */
static void set_sprs_book3s_201(uint64_t val)
{
	mtspr(18, val);		/* DSISR */
	mtspr(19, val);		/* DAR */
	mtspr(152, val);	/* CTRL */
	mtspr(256, val);	/* VRSAVE */
	mtspr(786, val);	/* MMCRA */
	mtspr(795, val);	/* MMCR0 */
	mtspr(798, val);	/* MMCR1 */
}

/* SPRs from PowerISA 2.07 Book III-S */
static void set_sprs_book3s_207(uint64_t val)
{
	mtspr(3, val);		/* DSCR */
	mtspr(13, val);		/* AMR */
	mtspr(17, val);		/* DSCR */
	mtspr(18, val);		/* DSISR */
	mtspr(19, val);		/* DAR */
	mtspr(29, val);		/* AMR */
	mtspr(61, val);		/* IAMR */
	// mtspr(152, val);	/* CTRL */  /* TODO: Needs a fix in KVM */
	mtspr(153, val);	/* FSCR */
	mtspr(157, val);	/* UAMOR */
	mtspr(159, val);	/* PSPB */
	mtspr(256, val);	/* VRSAVE */
	// mtspr(272, val);	/* SPRG0 */ /* Used by our exception handler */
	mtspr(769, val);	/* MMCR2 */
	mtspr(770, val);	/* MMCRA */
	mtspr(771, val);	/* PMC1 */
	mtspr(772, val);	/* PMC2 */
	mtspr(773, val);	/* PMC3 */
	mtspr(774, val);	/* PMC4 */
	mtspr(775, val);	/* PMC5 */
	mtspr(776, val);	/* PMC6 */
	mtspr(779, (val & 0xfffffffffbab3fffULL) | 0xfa0b2070);	/* MMCR0 */
	mtspr(784, val);	/* SIER */
	mtspr(785, val);	/* MMCR2 */
	mtspr(786, val);	/* MMCRA */
	mtspr(787, val);	/* PMC1 */
	mtspr(788, val);	/* PMC2 */
	mtspr(789, val);	/* PMC3 */
	mtspr(790, val);	/* PMC4 */
	mtspr(791, val);	/* PMC5 */
	mtspr(792, val);	/* PMC6 */
	mtspr(795, (val & 0xfffffffffbab3fffULL) | 0xfa0b2070);	/* MMCR0 */
	mtspr(796, val);	/* SIAR */
	mtspr(797, val);	/* SDAR */
	mtspr(798, val);	/* MMCR1 */
	mtspr(800, val);	/* BESCRS */
	mtspr(801, val);	/* BESCCRSU */
	mtspr(802, val);	/* BESCRR */
	mtspr(803, val);	/* BESCRRU */
	mtspr(804, val);	/* EBBHR */
	mtspr(805, val);	/* EBBRR */
	mtspr(806, val);	/* BESCR */
	mtspr(815, val);	/* TAR */
}

/* SPRs from PowerISA 3.00 Book III */
static void set_sprs_book3s_300(uint64_t val)
{
	set_sprs_book3s_207(val);
	mtspr(48, val);		/* PIDR */
	mtspr(144, val);	/* TIDR */
	mtspr(823, val);	/* PSSCR */
}

static void set_sprs(uint64_t val)
{
	uint32_t pvr = mfspr(287);	/* Processor Version Register */

	set_sprs_common(val);

	switch (pvr >> 16) {
	case 0x39:			/* PPC970 */
	case 0x3C:			/* PPC970FX */
	case 0x44:			/* PPC970MP */
		set_sprs_book3s_201(val);
		break;
	case 0x4b:			/* POWER8E */
	case 0x4c:			/* POWER8NVL */
	case 0x4d:			/* POWER8 */
		set_sprs_book3s_207(val);
		break;
	case 0x4e:			/* POWER9 */
		set_sprs_book3s_300(val);
		break;
	default:
		puts("Warning: Unknown processor version!\n");
	}
}

static void get_sprs_common(uint64_t *v)
{
	v[9] = mfspr(9);	/* CTR */
	// v[273] = mfspr(273);	/* SPRG1 */ /* Used by our exception handler */
	v[274] = mfspr(274);	/* SPRG2 */
	v[275] = mfspr(275);	/* SPRG3 */
}

static void get_sprs_book3s_201(uint64_t *v)
{
	v[18] = mfspr(18);	/* DSISR */
	v[19] = mfspr(19);	/* DAR */
	v[136] = mfspr(136);	/* CTRL */
	v[256] = mfspr(256);	/* VRSAVE */
	v[786] = mfspr(786);	/* MMCRA */
	v[795] = mfspr(795);	/* MMCR0 */
	v[798] = mfspr(798);	/* MMCR1 */
}

static void get_sprs_book3s_207(uint64_t *v)
{
	v[3] = mfspr(3);	/* DSCR */
	v[13] = mfspr(13);	/* AMR */
	v[17] = mfspr(17);	/* DSCR */
	v[18] = mfspr(18);	/* DSISR */
	v[19] = mfspr(19);	/* DAR */
	v[29] = mfspr(29);	/* AMR */
	v[61] = mfspr(61);	/* IAMR */
	// v[136] = mfspr(136);	/* CTRL */  /* TODO: Needs a fix in KVM */
	v[153] = mfspr(153);	/* FSCR */
	v[157] = mfspr(157);	/* UAMOR */
	v[159] = mfspr(159);	/* PSPB */
	v[256] = mfspr(256);	/* VRSAVE */
	v[259] = mfspr(259);	/* SPRG3 (read only) */
	// v[272] = mfspr(272);	/* SPRG0 */  /* Used by our exception handler */
	v[769] = mfspr(769);	/* MMCR2 */
	v[770] = mfspr(770);	/* MMCRA */
	v[771] = mfspr(771);	/* PMC1 */
	v[772] = mfspr(772);	/* PMC2 */
	v[773] = mfspr(773);	/* PMC3 */
	v[774] = mfspr(774);	/* PMC4 */
	v[775] = mfspr(775);	/* PMC5 */
	v[776] = mfspr(776);	/* PMC6 */
	v[779] = mfspr(779);	/* MMCR0 */
	v[780] = mfspr(780);	/* SIAR (read only) */
	v[781] = mfspr(781);	/* SDAR (read only) */
	v[782] = mfspr(782);	/* MMCR1 (read only) */
	v[784] = mfspr(784);	/* SIER */
	v[785] = mfspr(785);	/* MMCR2 */
	v[786] = mfspr(786);	/* MMCRA */
	v[787] = mfspr(787);	/* PMC1 */
	v[788] = mfspr(788);	/* PMC2 */
	v[789] = mfspr(789);	/* PMC3 */
	v[790] = mfspr(790);	/* PMC4 */
	v[791] = mfspr(791);	/* PMC5 */
	v[792] = mfspr(792);	/* PMC6 */
	v[795] = mfspr(795);	/* MMCR0 */
	v[796] = mfspr(796);	/* SIAR */
	v[797] = mfspr(797);	/* SDAR */
	v[798] = mfspr(798);	/* MMCR1 */
	v[800] = mfspr(800);	/* BESCRS */
	v[801] = mfspr(801);	/* BESCCRSU */
	v[802] = mfspr(802);	/* BESCRR */
	v[803] = mfspr(803);	/* BESCRRU */
	v[804] = mfspr(804);	/* EBBHR */
	v[805] = mfspr(805);	/* EBBRR */
	v[806] = mfspr(806);	/* BESCR */
	v[815] = mfspr(815);	/* TAR */
}

static void get_sprs_book3s_300(uint64_t *v)
{
	get_sprs_book3s_207(v);
	v[48] = mfspr(48);	/* PIDR */
	v[144] = mfspr(144);	/* TIDR */
	v[823] = mfspr(823);	/* PSSCR */
}

static void get_sprs(uint64_t *v)
{
	uint32_t pvr = mfspr(287);	/* Processor Version Register */

	get_sprs_common(v);

	switch (pvr >> 16) {
	case 0x39:			/* PPC970 */
	case 0x3C:			/* PPC970FX */
	case 0x44:			/* PPC970MP */
		get_sprs_book3s_201(v);
		break;
	case 0x4b:			/* POWER8E */
	case 0x4c:			/* POWER8NVL */
	case 0x4d:			/* POWER8 */
		get_sprs_book3s_207(v);
		break;
	case 0x4e:			/* POWER9 */
		get_sprs_book3s_300(v);
		break;
	}
}

int main(int argc, char **argv)
{
	int i;
	bool pause = false;
	uint64_t pat = 0xcafefacec0debabeULL;
	const uint64_t patterns[] = {
		0xcafefacec0debabeULL, ~0xcafefacec0debabeULL,
		0xAAAA5555AAAA5555ULL, 0x5555AAAA5555AAAAULL,
		0x1234567890ABCDEFULL, 0xFEDCBA0987654321ULL,
		-1ULL,
	};

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-w")) {
			pause = true;
		} else if (!strcmp(argv[i], "-p")) {
			i += 1;
			if (i >= argc || *argv[i] < '0'
			    || *argv[i] >= '0' + ARRAY_SIZE(patterns))
				report_abort("Error: bad value for -p");
			pat ^= patterns[*argv[i] - '0'];
		} else if (!strcmp(argv[i], "-t")) {
			/* Randomize with timebase register */
			asm volatile("mftb %0" : "=r"(i));
			pat ^= i;
			asm volatile("mftb %0" : "=r"(i));
			pat ^= ~(uint64_t)i << 32;
		} else {
			report_abort("Warning: Unsupported argument: %s",
			             argv[i]);
		}
	}

	printf("Settings SPRs to %#lx...\n", pat);
	set_sprs(pat);

	memset(before, 0, sizeof(before));
	memset(after, 0, sizeof(after));

	get_sprs(before);

	if (pause) {
		handle_exception(0x100, &nmi_handler, NULL);
		puts("Now migrate the VM, then press a key or send NMI...\n");
		while (!nmi_occurred && h_get_term_char(0) == 0)
			cpu_relax();
	} else {
		puts("Sleeping...\n");
		handle_exception(0x900, &dec_except_handler, NULL);
		asm volatile ("mtdec %0" : : "r" (0x3FFFFFFF));
		hcall(H_CEDE);
	}

	get_sprs(after);

	puts("Checking SPRs...\n");
	for (i = 0; i < 1024; i++) {
		if (before[i] != 0 || after[i] != 0)
			report("SPR %d:\t%#018lx <==> %#018lx",
				before[i] == after[i], i, before[i], after[i]);
	}

	return report_summary();
}
