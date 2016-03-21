/*
 * Test some powerpc instructions
 */

#include <libcflat.h>
#include <asm/processor.h>

static int verbose;
static int volatile is_invalid;

static void program_check_handler(struct pt_regs *regs, void *opaque)
{
	int *data = opaque;

	if (verbose) {
		printf("Detected invalid instruction 0x%016lx: %08x\n",
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

int main(int argc, char **argv)
{
	int i;

	handle_exception(0x700, program_check_handler, (void *)&is_invalid);

	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "-v") == 0) {
			verbose = 1;
		}
	}

	report_prefix_push("emulator");

	test_64bit();
	test_illegal();

	report_prefix_pop();

	return report_summary();
}
