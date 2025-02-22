/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_SBI_H_
#define _ASMRISCV_SBI_H_

#define SBI_SUCCESS			0
#define SBI_ERR_FAILURE			-1
#define SBI_ERR_NOT_SUPPORTED		-2
#define SBI_ERR_INVALID_PARAM		-3
#define SBI_ERR_DENIED			-4
#define SBI_ERR_INVALID_ADDRESS		-5
#define SBI_ERR_ALREADY_AVAILABLE	-6
#define SBI_ERR_ALREADY_STARTED		-7
#define SBI_ERR_ALREADY_STOPPED		-8
#define SBI_ERR_NO_SHMEM		-9
#define SBI_ERR_INVALID_STATE		-10
#define SBI_ERR_BAD_RANGE		-11
#define SBI_ERR_TIMEOUT			-12
#define SBI_ERR_IO			-13
#define SBI_ERR_DENIED_LOCKED		-14

#ifndef __ASSEMBLER__
#include <cpumask.h>

enum sbi_ext_id {
	SBI_EXT_BASE = 0x10,
	SBI_EXT_TIME = 0x54494d45,
	SBI_EXT_IPI = 0x735049,
	SBI_EXT_HSM = 0x48534d,
	SBI_EXT_SRST = 0x53525354,
	SBI_EXT_DBCN = 0x4442434E,
	SBI_EXT_SUSP = 0x53555350,
	SBI_EXT_FWFT = 0x46574654,
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

enum sbi_ext_hsm_fid {
	SBI_EXT_HSM_HART_START = 0,
	SBI_EXT_HSM_HART_STOP,
	SBI_EXT_HSM_HART_STATUS,
	SBI_EXT_HSM_HART_SUSPEND,
};

enum sbi_ext_time_fid {
	SBI_EXT_TIME_SET_TIMER = 0,
};

enum sbi_ext_ipi_fid {
	SBI_EXT_IPI_SEND_IPI = 0,
};

enum sbi_ext_hsm_sid {
	SBI_EXT_HSM_STARTED = 0,
	SBI_EXT_HSM_STOPPED,
	SBI_EXT_HSM_START_PENDING,
	SBI_EXT_HSM_STOP_PENDING,
	SBI_EXT_HSM_SUSPENDED,
	SBI_EXT_HSM_SUSPEND_PENDING,
	SBI_EXT_HSM_RESUME_PENDING,
};

enum sbi_ext_hsm_hart_suspend_type {
	SBI_EXT_HSM_HART_SUSPEND_RETENTIVE = 0,
	SBI_EXT_HSM_HART_SUSPEND_NON_RETENTIVE = 0x80000000,
};

enum sbi_ext_dbcn_fid {
	SBI_EXT_DBCN_CONSOLE_WRITE = 0,
	SBI_EXT_DBCN_CONSOLE_READ,
	SBI_EXT_DBCN_CONSOLE_WRITE_BYTE,
};


enum sbi_ext_fwft_fid {
	SBI_EXT_FWFT_SET = 0,
	SBI_EXT_FWFT_GET,
};

#define SBI_FWFT_MISALIGNED_EXC_DELEG		0x0
#define SBI_FWFT_LANDING_PAD			0x1
#define SBI_FWFT_SHADOW_STACK			0x2
#define SBI_FWFT_DOUBLE_TRAP			0x3
#define SBI_FWFT_PTE_AD_HW_UPDATING		0x4
#define SBI_FWFT_POINTER_MASKING_PMLEN		0x5
#define SBI_FWFT_LOCAL_RESERVED_START		0x6
#define SBI_FWFT_LOCAL_RESERVED_END		0x3fffffff
#define SBI_FWFT_LOCAL_PLATFORM_START		0x40000000
#define SBI_FWFT_LOCAL_PLATFORM_END		0x7fffffff

#define SBI_FWFT_GLOBAL_RESERVED_START		0x80000000
#define SBI_FWFT_GLOBAL_RESERVED_END		0xbfffffff
#define SBI_FWFT_GLOBAL_PLATFORM_START		0xc0000000
#define SBI_FWFT_GLOBAL_PLATFORM_END		0xffffffff

#define SBI_FWFT_PLATFORM_FEATURE_BIT		BIT(30)
#define SBI_FWFT_GLOBAL_FEATURE_BIT		BIT(31)

#define SBI_FWFT_SET_FLAG_LOCK			BIT(0)

struct sbiret {
	long error;
	long value;
};

struct sbiret sbi_ecall(int ext, int fid, unsigned long arg0,
			unsigned long arg1, unsigned long arg2,
			unsigned long arg3, unsigned long arg4,
			unsigned long arg5);

void sbi_shutdown(void);
struct sbiret sbi_hart_start(unsigned long hartid, unsigned long entry, unsigned long sp);
struct sbiret sbi_hart_stop(void);
struct sbiret sbi_hart_get_status(unsigned long hartid);
struct sbiret sbi_send_ipi(unsigned long hart_mask, unsigned long hart_mask_base);
struct sbiret sbi_send_ipi_cpu(int cpu);
struct sbiret sbi_send_ipi_cpumask(const cpumask_t *mask);
struct sbiret sbi_send_ipi_broadcast(void);
struct sbiret sbi_set_timer(unsigned long stime_value);
long sbi_probe(int ext);

#endif /* !__ASSEMBLER__ */
#endif /* _ASMRISCV_SBI_H_ */
