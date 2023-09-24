/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_SBI_H_
#define _ASMRISCV_SBI_H_

enum sbi_ext_id {
	SBI_EXT_BASE = 0x10,
	SBI_EXT_SRST = 0x53525354,
};

enum sbi_ext_base_fid {
	SBI_EXT_BASE_GET_SPEC_VERSION = 0,
	SBI_EXT_BASE_GET_IMP_ID,
	SBI_EXT_BASE_GET_IMP_VERSION,
	SBI_EXT_BASE_PROBE_EXT,
	SBI_EXT_BASE_GET_MVENDORID,
	SBI_EXT_BASE_GET_MARCHID,
	SBI_EXT_BASE_GET_MIMPID,
};

struct sbiret {
	long error;
	long value;
};

struct sbiret sbi_ecall(int ext, int fid, unsigned long arg0,
			unsigned long arg1, unsigned long arg2,
			unsigned long arg3, unsigned long arg4,
			unsigned long arg5);

void sbi_shutdown(void);

#endif /* _ASMRISCV_SBI_H_ */
