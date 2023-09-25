// SPDX-License-Identifier: GPL-2.0-only
#include <kbuild.h>
#include <elf.h>

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
	return 0;
}
