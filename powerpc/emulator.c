/*
 * Test some powerpc instructions
 */

#include <libcflat.h>
#include <asm/processor.h>

static int verbose;
static int volatile is_invalid;
static int volatile alignment;

static void program_check_handler(struct pt_regs *regs, void *opaque)
{
	int *data = opaque;

	if (verbose) {
		printf("Detected invalid instruction %#018lx: %08x\n",
		       regs->nip, *(uint32_t*)regs->nip);
	}

	/* the result is bit 16 to 19 of SRR1
	 * bit 0: SRR0 contains the address of the next instruction
	 * bit 1: Trap
	 * bit 2: Privileged instruction
	 * bit 3: Illegal instruction
	 * bit 4: FP enabled exception type
	 */

	*data = regs->msr >> 16;

	regs->nip += 4;
}

static void alignment_handler(struct pt_regs *regs, void *opaque)
{
	int *data = opaque;

	if (verbose) {
		printf("Detected alignment exception %#018lx: %08x\n",
		       regs->nip, *(uint32_t*)regs->nip);
	}

	*data = 1;

	regs->nip += 4;
}

static void test_illegal(void)
{
	report_prefix_push("invalid");

	is_invalid = 0;

	asm volatile (".long 0");

	report("exception", is_invalid == 8); /* illegal instruction */

	report_prefix_pop();
}

static void test_64bit(void)
{
	uint64_t msr;

	report_prefix_push("64bit");

	asm("mfmsr %[msr]": [msr] "=r" (msr));

	report("detected", msr & 0x8000000000000000UL);

	report_prefix_pop();
}

/**
 * Test 'Load String Word Immediate' instruction
 */
static void test_lswi(void)
{
	int i;
	char addr[128];
	uint64_t regs[32];

	report_prefix_push("lswi");

	/* fill memory with sequence */
	for (i = 0; i < 128; i++)
		addr[i] = 1 + i;

	/* check incomplete register filling */
	alignment = 0;
	asm volatile ("li r12,-1;"
		      "mr r11, r12;"
		      "lswi r11, %[addr], %[len];"
		      "std r11, 0*8(%[regs]);"
		      "std r12, 1*8(%[regs]);"
		      ::
		      [len] "i" (3),
		      [addr] "b" (addr),
		      [regs] "r" (regs)
		      :
		      "r11", "r12", "memory");

#if  __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	/*
	 * lswi is supposed to cause an alignment exception in little endian
	 * mode, but QEMU does not support it. So in case we do not get an
	 * exception, this is an expected failure and we run the other tests
	 */
	report_xfail("alignment", !alignment, alignment);
	if (alignment) {
		report_prefix_pop();
		return;
	}
#endif
	report("partial", regs[0] == 0x01020300 && regs[1] == (uint64_t)-1);

	/* check NB = 0 ==> 32 bytes. */
	asm volatile ("li r19,-1;"
		      "mr r11, r19; mr r12, r19; mr r13, r19;"
		      "mr r14, r19; mr r15, r19; mr r16, r19;"
		      "mr r17, r19; mr r18, r19;"
		      "lswi r11, %[addr], %[len];"
		      "std r11, 0*8(%[regs]);"
		      "std r12, 1*8(%[regs]);"
		      "std r13, 2*8(%[regs]);"
		      "std r14, 3*8(%[regs]);"
		      "std r15, 4*8(%[regs]);"
		      "std r16, 5*8(%[regs]);"
		      "std r17, 6*8(%[regs]);"
		      "std r18, 7*8(%[regs]);"
		      "std r19, 8*8(%[regs]);"
		      ::
		      [len] "i" (0),
		      [addr] "b" (addr),
		      [regs] "r" (regs)
		      :
		      /* as 32 is the number of bytes,
		       * we should modify 32/4 = 8 regs, from r11 to r18
		       * We check r19 is unmodified by filling it with 1s
		       * before the instruction.
		       */
		      "r11", "r12", "r13", "r14", "r15", "r16", "r17",
		      "r18", "r19", "memory");

	report("length", regs[0] == 0x01020304 && regs[1] == 0x05060708 &&
			 regs[2] == 0x090a0b0c && regs[3] == 0x0d0e0f10 &&
			 regs[4] == 0x11121314 && regs[5] == 0x15161718 &&
			 regs[6] == 0x191a1b1c && regs[7] == 0x1d1e1f20 &&
			 regs[8] == (uint64_t)-1);

	/* check wrap around to r0 */
	asm volatile ("li r31,-1;"
		      "mr r0, r31;"
		      "lswi r31, %[addr], %[len];"
		      "std r31, 0*8(%[regs]);"
		      "std r0, 1*8(%[regs]);"
		      ::
		      [len] "i" (8),
		      [addr] "b" (addr),
		      [regs] "r" (regs)
		      :
		      /* modify two registers from r31, wrap around to r0 */
		      "r31", "r0", "memory");

	report("wrap around to r0", regs[0] == 0x01020304 &&
			            regs[1] == 0x05060708);

	/* check wrap around doesn't break RA */
	asm volatile ("mr r29,r1\n"
		      "li r31,-1\n"
		      "mr r0,r31\n"
		      "mr r1, %[addr]\n"
		      ".long 0x7fe154aa\n"       /* lswi r31, r1, 10 */
		      "std r31, 0*8(%[regs])\n"
		      "std r0, 1*8(%[regs])\n"
		      "std r1, 2*8(%[regs])\n"
		      "mr r1,r29\n"
		      ::
		      [addr] "r" (addr),
		      [regs] "r" (regs)
		      :
		      /* loading three registers from r31 wraps around to r1,
		       * r1 is saved to r29, as adding it to the clobber
		       * list doesn't protect it
		       */
		      "r0", "r29", "r31", "memory");

	/* doc says it is invalid, real proc stops when it comes to
	 * overwrite the register.
	 * In all the cases, the register must stay untouched
	 */
	report("Don't overwrite Ra", regs[2] == (uint64_t)addr);

	report_prefix_pop();
}

/*
 * lswx: Load String Word Indexed X-form
 *
 *     lswx RT,RA,RB
 *
 * EA = (RA|0) + RB
 * n  = XER
 *
 * Load n bytes from address EA into (n / 4) consecutive registers,
 * throught RT -> RT + (n / 4) - 1.
 * - Data are loaded into 4 low order bytes of registers (Word).
 * - The unfilled bytes are set to 0.
 * - The sequence of registers wraps around to GPR0.
 * - if n == 0, content of RT is undefined
 * - RT <= RA or RB < RT + (n + 4) is invalid or result is undefined
 * - RT == RA == 0 is invalid
 *
 * For lswx in little-endian mode, an alignment interrupt always occurs.
 *
 */

static void test_lswx(void)
{
	int i;
	char addr[128];
	uint64_t regs[32];

	report_prefix_push("lswx");

	/* fill memory with sequence */

	for (i = 0; i < 128; i++)
		addr[i] = 1 + i;

	/* check incomplete register filling */

	alignment = 0;
	asm volatile ("mtxer %[len];"
		      "li r12,-1;"
		      "mr r11, r12;"
		      "lswx r11, 0, %[addr];"
		      "std r11, 0*8(%[regs]);"
		      "std r12, 1*8(%[regs]);"
		      ::
		      [len] "r" (3),
		      [addr] "r" (addr),
		      [regs] "r" (regs)
		      :
		      "xer", "r11", "r12", "memory");

#if  __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	/*
	 * lswx is supposed to cause an alignment exception in little endian
	 * mode, but QEMU does not support it. So in case we do not get an
	 * exception, this is an expected failure and we run the other tests
	 */
	report_xfail("alignment", !alignment, alignment);
	if (alignment) {
		report_prefix_pop();
		return;
	}
#endif
	report("partial", regs[0] == 0x01020300 && regs[1] == (uint64_t)-1);

	/* check an old know bug: the number of bytes is used as
	 * the number of registers, so try 32 bytes.
	 */

	asm volatile ("mtxer %[len];"
		      "li r19,-1;"
		      "mr r11, r19; mr r12, r19; mr r13, r19;"
		      "mr r14, r19; mr r15, r19; mr r16, r19;"
		      "mr r17, r19; mr r18, r19;"
		      "lswx r11, 0, %[addr];"
		      "std r11, 0*8(%[regs]);"
		      "std r12, 1*8(%[regs]);"
		      "std r13, 2*8(%[regs]);"
		      "std r14, 3*8(%[regs]);"
		      "std r15, 4*8(%[regs]);"
		      "std r16, 5*8(%[regs]);"
		      "std r17, 6*8(%[regs]);"
		      "std r18, 7*8(%[regs]);"
		      "std r19, 8*8(%[regs]);"
		      ::
		      [len] "r" (32),
		      [addr] "r" (addr),
		      [regs] "r" (regs)
		      :
		      /* as 32 is the number of bytes,
		       * we should modify 32/4 = 8 regs, from r11 to r18
		       * We check r19 is unmodified by filling it with 1s
		       * before the instruction.
		       */
		      "xer", "r11", "r12", "r13", "r14", "r15", "r16", "r17",
		      "r18", "r19", "memory");

	report("length", regs[0] == 0x01020304 && regs[1] == 0x05060708 &&
			 regs[2] == 0x090a0b0c && regs[3] == 0x0d0e0f10 &&
			 regs[4] == 0x11121314 && regs[5] == 0x15161718 &&
			 regs[6] == 0x191a1b1c && regs[7] == 0x1d1e1f20 &&
			 regs[8] == (uint64_t)-1);

	/* check wrap around to r0 */

	asm volatile ("mtxer %[len];"
		      "li r31,-1;"
		      "mr r0, r31;"
		      "lswx r31, 0, %[addr];"
		      "std r31, 0*8(%[regs]);"
		      "std r0, 1*8(%[regs]);"
		      ::
		      [len] "r" (8),
		      [addr] "r" (addr),
		      [regs] "r" (regs)
		      :
		      /* modify two registers from r31, wrap around to r0 */
		      "xer", "r31", "r0", "memory");

	report("wrap around to r0", regs[0] == 0x01020304 &&
			            regs[1] == 0x05060708);

	/* check wrap around to r0 over RB doesn't break RB */

	asm volatile ("mtxer %[len];"
		      "mr r29,r1;"
		      "li r31,-1;"
		      "mr r1,r31;"
		      "mr r0, %[addr];"
		      "lswx r31, 0, r0;"
		      "std r31, 0*8(%[regs]);"
		      "std r0, 1*8(%[regs]);"
		      "std r1, 2*8(%[regs]);"
		      "mr r1,r29;"
		      ::
		      [len] "r" (12),
		      [addr] "r" (addr),
		      [regs] "r" (regs)
		      :
		      /* loading three registers from r31 wraps around to r1,
		       * r1 is saved to r29, as adding it to the clobber
		       * list doesn't protect it
		       */
		      "xer", "r31", "r0", "r29", "memory");

	/* doc says it is invalid, real proc stops when it comes to
	 * overwrite the register.
	 * In all the cases, the register must stay untouched
	 */
	report("Don't overwrite Rb", regs[1] == (uint64_t)addr);

	report_prefix_pop();
}

int main(int argc, char **argv)
{
	int i;

	handle_exception(0x700, program_check_handler, (void *)&is_invalid);
	handle_exception(0x600, alignment_handler, (void *)&alignment);

	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			verbose = 1;
		}
	}

	report_prefix_push("emulator");

	test_64bit();
	test_illegal();
	test_lswx();
	test_lswi();

	report_prefix_pop();

	return report_summary();
}
