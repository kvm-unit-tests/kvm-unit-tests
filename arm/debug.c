#include <libcflat.h>
#include <migrate.h>
#include <errata.h>
#include <asm/setup.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/smp.h>
#include <asm/barrier.h>
#include <asm/io.h>

#define MDSCR_KDE		(1 << 13)
#define MDSCR_MDE		(1 << 15)
#define MDSCR_SS		(1 << 0)

#define DBGBCR_LEN8		(0xff << 5)
#define DBGBCR_EXEC		(0x0 << 3)
#define DBGBCR_EL1		(0x1 << 1)
#define DBGBCR_E		(0x1 << 0)

#define DBGWCR_LEN8		(0xff << 5)
#define DBGWCR_RD		(0x1 << 3)
#define DBGWCR_WR		(0x2 << 3)
#define DBGWCR_EL1		(0x1 << 1)
#define DBGWCR_E		(0x1 << 0)

#define SPSR_D			(1 << 9)
#define SPSR_SS			(1 << 21)

#define ESR_EC_HW_BP_CURRENT    0x31
#define ESR_EC_SSTEP_CURRENT    0x33
#define ESR_EC_WP_CURRENT       0x35

#define ID_AA64DFR0_BRPS_SHIFT	12
#define ID_AA64DFR0_BRPS_MASK	0xf
#define ID_AA64DFR0_WRPS_SHIFT	20
#define ID_AA64DFR0_WRPS_MASK	0xf

static volatile uint64_t hw_bp_idx, hw_bp_addr[16];
static volatile uint64_t wp_idx, wp_data_addr[16];
static volatile uint64_t ss_addr[4], ss_idx;

static void hw_bp_handler(struct pt_regs *regs, unsigned int esr)
{
	hw_bp_addr[hw_bp_idx++] = regs->pc;
	regs->pstate |= SPSR_D;
}

static void wp_handler(struct pt_regs *regs, unsigned int esr)
{
	wp_data_addr[wp_idx++] = read_sysreg(far_el1);
	regs->pstate |= SPSR_D;
}

static void ss_handler(struct pt_regs *regs, unsigned int esr)
{
	ss_addr[ss_idx++] = regs->pc;
	regs->pstate |= SPSR_SS;
}

static int get_num_hw_bp(void)
{
	uint64_t reg = read_sysreg(id_aa64dfr0_el1);
	/* Number of breakpoints, minus 1 */
	uint8_t brps = (reg >> ID_AA64DFR0_BRPS_SHIFT) & ID_AA64DFR0_BRPS_MASK;

	return brps + 1;
}

static int get_num_wp(void)
{
	uint64_t reg = read_sysreg(id_aa64dfr0_el1);
	/* Number of watchpoints, minus 1 */
	uint8_t wrps = (reg >> ID_AA64DFR0_WRPS_SHIFT) & ID_AA64DFR0_WRPS_MASK;

	return wrps + 1;
}

static void write_dbgbcr(int n, uint32_t bcr)
{
	switch (n) {
	case 0:
		write_sysreg(bcr, dbgbcr0_el1); break;
	case 1:
		write_sysreg(bcr, dbgbcr1_el1); break;
	case 2:
		write_sysreg(bcr, dbgbcr2_el1); break;
	case 3:
		write_sysreg(bcr, dbgbcr3_el1); break;
	case 4:
		write_sysreg(bcr, dbgbcr4_el1); break;
	case 5:
		write_sysreg(bcr, dbgbcr5_el1); break;
	case 6:
		write_sysreg(bcr, dbgbcr6_el1); break;
	case 7:
		write_sysreg(bcr, dbgbcr7_el1); break;
	case 8:
		write_sysreg(bcr, dbgbcr8_el1); break;
	case 9:
		write_sysreg(bcr, dbgbcr9_el1); break;
	case 10:
		write_sysreg(bcr, dbgbcr10_el1); break;
	case 11:
		write_sysreg(bcr, dbgbcr11_el1); break;
	case 12:
		write_sysreg(bcr, dbgbcr12_el1); break;
	case 13:
		write_sysreg(bcr, dbgbcr13_el1); break;
	case 14:
		write_sysreg(bcr, dbgbcr14_el1); break;
	case 15:
		write_sysreg(bcr, dbgbcr15_el1); break;
	default:
		report_abort("Invalid bcr");
	}
}

static void write_dbgbvr(int n, uint64_t bvr)
{
	switch (n) {
	case 0:
		write_sysreg(bvr, dbgbvr0_el1); break;
	case 1:
		write_sysreg(bvr, dbgbvr1_el1); break;
	case 2:
		write_sysreg(bvr, dbgbvr2_el1); break;
	case 3:
		write_sysreg(bvr, dbgbvr3_el1); break;
	case 4:
		write_sysreg(bvr, dbgbvr4_el1); break;
	case 5:
		write_sysreg(bvr, dbgbvr5_el1); break;
	case 6:
		write_sysreg(bvr, dbgbvr6_el1); break;
	case 7:
		write_sysreg(bvr, dbgbvr7_el1); break;
	case 8:
		write_sysreg(bvr, dbgbvr8_el1); break;
	case 9:
		write_sysreg(bvr, dbgbvr9_el1); break;
	case 10:
		write_sysreg(bvr, dbgbvr10_el1); break;
	case 11:
		write_sysreg(bvr, dbgbvr11_el1); break;
	case 12:
		write_sysreg(bvr, dbgbvr12_el1); break;
	case 13:
		write_sysreg(bvr, dbgbvr13_el1); break;
	case 14:
		write_sysreg(bvr, dbgbvr14_el1); break;
	case 15:
		write_sysreg(bvr, dbgbvr15_el1); break;
	default:
		report_abort("invalid bvr");
	}
}

static void write_dbgwcr(int n, uint32_t wcr)
{
	switch (n) {
	case 0:
		write_sysreg(wcr, dbgwcr0_el1); break;
	case 1:
		write_sysreg(wcr, dbgwcr1_el1); break;
	case 2:
		write_sysreg(wcr, dbgwcr2_el1); break;
	case 3:
		write_sysreg(wcr, dbgwcr3_el1); break;
	case 4:
		write_sysreg(wcr, dbgwcr4_el1); break;
	case 5:
		write_sysreg(wcr, dbgwcr5_el1); break;
	case 6:
		write_sysreg(wcr, dbgwcr6_el1); break;
	case 7:
		write_sysreg(wcr, dbgwcr7_el1); break;
	case 8:
		write_sysreg(wcr, dbgwcr8_el1); break;
	case 9:
		write_sysreg(wcr, dbgwcr9_el1); break;
	case 10:
		write_sysreg(wcr, dbgwcr10_el1); break;
	case 11:
		write_sysreg(wcr, dbgwcr11_el1); break;
	case 12:
		write_sysreg(wcr, dbgwcr12_el1); break;
	case 13:
		write_sysreg(wcr, dbgwcr13_el1); break;
	case 14:
		write_sysreg(wcr, dbgwcr14_el1); break;
	case 15:
		write_sysreg(wcr, dbgwcr15_el1); break;
	default:
		report_abort("Invalid wcr");
	}
}

static void write_dbgwvr(int n, uint64_t wvr)
{
	switch (n) {
	case 0:
		write_sysreg(wvr, dbgwvr0_el1); break;
	case 1:
		write_sysreg(wvr, dbgwvr1_el1); break;
	case 2:
		write_sysreg(wvr, dbgwvr2_el1); break;
	case 3:
		write_sysreg(wvr, dbgwvr3_el1); break;
	case 4:
		write_sysreg(wvr, dbgwvr4_el1); break;
	case 5:
		write_sysreg(wvr, dbgwvr5_el1); break;
	case 6:
		write_sysreg(wvr, dbgwvr6_el1); break;
	case 7:
		write_sysreg(wvr, dbgwvr7_el1); break;
	case 8:
		write_sysreg(wvr, dbgwvr8_el1); break;
	case 9:
		write_sysreg(wvr, dbgwvr9_el1); break;
	case 10:
		write_sysreg(wvr, dbgwvr10_el1); break;
	case 11:
		write_sysreg(wvr, dbgwvr11_el1); break;
	case 12:
		write_sysreg(wvr, dbgwvr12_el1); break;
	case 13:
		write_sysreg(wvr, dbgwvr13_el1); break;
	case 14:
		write_sysreg(wvr, dbgwvr14_el1); break;
	case 15:
		write_sysreg(wvr, dbgwvr15_el1); break;
	default:
		report_abort("invalid wvr");
	}
}

static void reset_debug_state(void)
{
	int i, num_bp = get_num_hw_bp();
	int num_wp = get_num_wp();

	asm volatile("msr daifset, #8");

	write_sysreg(0, osdlr_el1);
	write_sysreg(0, oslar_el1);
	isb();

	write_sysreg(0, mdscr_el1);
	for (i = 0; i < num_bp; i++) {
		write_dbgbvr(i, 0);
		write_dbgbcr(i, 0);
	}
	for (i = 0; i < num_wp; i++) {
		write_dbgwvr(i, 0);
		write_dbgwcr(i, 0);
	}
	isb();
}

static noinline void test_hw_bp(bool migrate)
{
	extern unsigned char hw_bp0;
	uint32_t bcr;
	uint32_t mdscr;
	uint64_t addr;
	int num_bp = get_num_hw_bp();
	int i;

	install_exception_handler(EL1H_SYNC, ESR_EC_HW_BP_CURRENT, hw_bp_handler);

	reset_debug_state();

	bcr = DBGBCR_LEN8 | DBGBCR_EXEC | DBGBCR_EL1 | DBGBCR_E;
	for (i = 0, addr = (uint64_t)&hw_bp0; i < num_bp; i++, addr += 4) {
		write_dbgbcr(i, bcr);
		write_dbgbvr(i, addr);
	}
	isb();

	asm volatile("msr daifclr, #8");

	mdscr = read_sysreg(mdscr_el1) | MDSCR_KDE | MDSCR_MDE;
	write_sysreg(mdscr, mdscr_el1);
	isb();

	if (migrate) {
		migrate_once();
		report(num_bp == get_num_hw_bp(), "brps match after migrate");
	}

	hw_bp_idx = 0;

	/* Trap on up to 16 debug exception unmask instructions. */
	asm volatile(
		".globl hw_bp0\n"
		"hw_bp0:\n"
			"msr daifclr, #8; msr daifclr, #8; msr daifclr, #8; msr daifclr, #8\n"
			"msr daifclr, #8; msr daifclr, #8; msr daifclr, #8; msr daifclr, #8\n"
			"msr daifclr, #8; msr daifclr, #8; msr daifclr, #8; msr daifclr, #8\n"
			"msr daifclr, #8; msr daifclr, #8; msr daifclr, #8; msr daifclr, #8\n"
		);

	for (i = 0, addr = (uint64_t)&hw_bp0; i < num_bp; i++, addr += 4)
		report(hw_bp_addr[i] == addr, "hw breakpoint: %d", i);
}

static volatile char write_data[16];

static noinline void test_wp(bool migrate)
{
	uint32_t wcr;
	uint32_t mdscr;
	int num_wp = get_num_wp();
	int i;

	install_exception_handler(EL1H_SYNC, ESR_EC_WP_CURRENT, wp_handler);

	reset_debug_state();

	wcr = DBGWCR_LEN8 | DBGWCR_RD | DBGWCR_WR | DBGWCR_EL1 | DBGWCR_E;
	for (i = 0; i < num_wp; i++) {
		write_dbgwcr(i, wcr);
		write_dbgwvr(i, (uint64_t)&write_data[i]);
	}
	isb();

	asm volatile("msr daifclr, #8");

	mdscr = read_sysreg(mdscr_el1) | MDSCR_KDE | MDSCR_MDE;
	write_sysreg(mdscr, mdscr_el1);
	isb();

	if (migrate) {
		migrate_once();
		report(num_wp == get_num_wp(), "wrps match after migrate");
	}

	wp_idx = 0;

	for (i = 0; i < num_wp; i++) {
		write_data[i] = i;
		asm volatile("msr daifclr, #8");
	}

	for (i = 0; i < num_wp; i++) {
		report(wp_data_addr[i] == (uint64_t)&write_data[i],
			"watchpoint received: %d", i);
		report(write_data[i] == i, "watchpoint data: %d", i);
	}
}

static noinline void test_ss(bool migrate)
{
	extern unsigned char ss_start;
	uint32_t mdscr;

	install_exception_handler(EL1H_SYNC, ESR_EC_SSTEP_CURRENT, ss_handler);

	reset_debug_state();

	ss_idx = 0;

	mdscr = read_sysreg(mdscr_el1) | MDSCR_KDE | MDSCR_SS;
	write_sysreg(mdscr, mdscr_el1);
	isb();

	if (migrate)
		migrate_once();

	asm volatile("msr daifclr, #8");

	asm volatile(
		".globl ss_start\n"
		"ss_start:\n"
			"mrs x0, esr_el1\n"
			"add x0, x0, #1\n"
			"msr daifset, #8\n"
			: : : "x0"
		);

	report(ss_addr[0] == (uint64_t)&ss_start, "single step");
}

int main(int argc, char **argv)
{
	if (argc < 2)
		report_abort("no test specified");

	if (strcmp(argv[1], "bp") == 0) {
		report_prefix_push(argv[1]);
		test_hw_bp(false);
		report_prefix_pop();
	} else if (strcmp(argv[1], "bp-migration") == 0) {
		report_prefix_push(argv[1]);
		test_hw_bp(true);
		report_prefix_pop();
	} else if (strcmp(argv[1], "wp") == 0) {
		report_prefix_push(argv[1]);
		test_wp(false);
		report_prefix_pop();
	} else if (strcmp(argv[1], "wp-migration") == 0) {
		report_prefix_push(argv[1]);
		test_wp(true);
		report_prefix_pop();
	} else if (strcmp(argv[1], "ss") == 0) {
		report_prefix_push(argv[1]);
		test_ss(false);
		report_prefix_pop();
	} else if (strcmp(argv[1], "ss-migration") == 0) {
		report_prefix_push(argv[1]);
		test_ss(true);
		report_prefix_pop();
	} else {
		report_abort("Unknown subtest '%s'", argv[1]);
	}

	return report_summary();
}
