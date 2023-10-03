// SPDX-License-Identifier: GPL-2.0-only
#include <kbuild.h>
#include <elf.h>
#include <asm/ptrace.h>
#include <asm/smp.h>

int main(void)
{
#if __riscv_xlen == 32
	OFFSET(ELF_RELA_OFFSET, elf32_rela, r_offset);
	OFFSET(ELF_RELA_ADDEND, elf32_rela, r_addend);
	DEFINE(ELF_RELA_SIZE, sizeof(struct elf32_rela));
#elif __riscv_xlen == 64
	OFFSET(ELF_RELA_OFFSET, elf64_rela, r_offset);
	OFFSET(ELF_RELA_ADDEND, elf64_rela, r_addend);
	DEFINE(ELF_RELA_SIZE, sizeof(struct elf64_rela));
#endif
	OFFSET(PT_EPC, pt_regs, epc);
	OFFSET(PT_RA, pt_regs, ra);
	OFFSET(PT_SP, pt_regs, sp);
	OFFSET(PT_GP, pt_regs, gp);
	OFFSET(PT_TP, pt_regs, tp);
	OFFSET(PT_T0, pt_regs, t0);
	OFFSET(PT_T1, pt_regs, t1);
	OFFSET(PT_T2, pt_regs, t2);
	OFFSET(PT_S0, pt_regs, s0);
	OFFSET(PT_S1, pt_regs, s1);
	OFFSET(PT_A0, pt_regs, a0);
	OFFSET(PT_A1, pt_regs, a1);
	OFFSET(PT_A2, pt_regs, a2);
	OFFSET(PT_A3, pt_regs, a3);
	OFFSET(PT_A4, pt_regs, a4);
	OFFSET(PT_A5, pt_regs, a5);
	OFFSET(PT_A6, pt_regs, a6);
	OFFSET(PT_A7, pt_regs, a7);
	OFFSET(PT_S2, pt_regs, s2);
	OFFSET(PT_S3, pt_regs, s3);
	OFFSET(PT_S4, pt_regs, s4);
	OFFSET(PT_S5, pt_regs, s5);
	OFFSET(PT_S6, pt_regs, s6);
	OFFSET(PT_S7, pt_regs, s7);
	OFFSET(PT_S8, pt_regs, s8);
	OFFSET(PT_S9, pt_regs, s9);
	OFFSET(PT_S10, pt_regs, s10);
	OFFSET(PT_S11, pt_regs, s11);
	OFFSET(PT_T3, pt_regs, t3);
	OFFSET(PT_T4, pt_regs, t4);
	OFFSET(PT_T5, pt_regs, t5);
	OFFSET(PT_T6, pt_regs, t6);
	OFFSET(PT_STATUS, pt_regs, status);
	OFFSET(PT_BADADDR, pt_regs, badaddr);
	OFFSET(PT_CAUSE, pt_regs, cause);
	OFFSET(PT_ORIG_A0, pt_regs, orig_a0);
	DEFINE(PT_SIZE, sizeof(struct pt_regs));

	OFFSET(SECONDARY_STVEC, secondary_data, stvec);
	OFFSET(SECONDARY_FUNC, secondary_data, func);
	DEFINE(SECONDARY_DATA_SIZE, sizeof(struct secondary_data));

	return 0;
}
