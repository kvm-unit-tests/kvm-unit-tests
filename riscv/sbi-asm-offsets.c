// SPDX-License-Identifier: GPL-2.0-only
#include <kbuild.h>
#include <asm/sbi.h>

int main(void)
{
	DEFINE(ASM_SBI_EXT_HSM, SBI_EXT_HSM);
	DEFINE(ASM_SBI_EXT_HSM_HART_STOP, SBI_EXT_HSM_HART_STOP);

	return 0;
}
