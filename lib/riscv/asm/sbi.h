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

#define SBI_IMPL_BBL		0
#define SBI_IMPL_OPENSBI	1
#define SBI_IMPL_XVISOR		2
#define SBI_IMPL_KVM		3
#define SBI_IMPL_RUSTSBI	4
#define SBI_IMPL_DIOSIX		5
#define SBI_IMPL_COFFER		6
#define SBI_IMPL_XEN		7
#define SBI_IMPL_POLARFIRE_HSS	8
#define SBI_IMPL_COREBOOT	9
#define SBI_IMPL_OREBOOT	10
#define SBI_IMPL_BHYVE		11

/* SBI spec version fields */
#define SBI_SPEC_VERSION_MAJOR_SHIFT	24
#define SBI_SPEC_VERSION_MAJOR_MASK	0x7f
#define SBI_SPEC_VERSION_MINOR_MASK	0xffffff
#define SBI_SPEC_VERSION_MASK		((SBI_SPEC_VERSION_MAJOR_MASK << SBI_SPEC_VERSION_MAJOR_SHIFT) | \
					 SBI_SPEC_VERSION_MINOR_MASK)

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
	SBI_EXT_SSE = 0x535345,
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

enum sbi_ext_sse_fid {
	SBI_EXT_SSE_READ_ATTRS = 0,
	SBI_EXT_SSE_WRITE_ATTRS,
	SBI_EXT_SSE_REGISTER,
	SBI_EXT_SSE_UNREGISTER,
	SBI_EXT_SSE_ENABLE,
	SBI_EXT_SSE_DISABLE,
	SBI_EXT_SSE_COMPLETE,
	SBI_EXT_SSE_INJECT,
	SBI_EXT_SSE_HART_UNMASK,
	SBI_EXT_SSE_HART_MASK,
};

/* SBI SSE Event Attributes. */
enum sbi_sse_attr_id {
	SBI_SSE_ATTR_STATUS		= 0x00000000,
	SBI_SSE_ATTR_PRIORITY		= 0x00000001,
	SBI_SSE_ATTR_CONFIG		= 0x00000002,
	SBI_SSE_ATTR_PREFERRED_HART	= 0x00000003,
	SBI_SSE_ATTR_ENTRY_PC		= 0x00000004,
	SBI_SSE_ATTR_ENTRY_ARG		= 0x00000005,
	SBI_SSE_ATTR_INTERRUPTED_SEPC	= 0x00000006,
	SBI_SSE_ATTR_INTERRUPTED_FLAGS	= 0x00000007,
	SBI_SSE_ATTR_INTERRUPTED_A6	= 0x00000008,
	SBI_SSE_ATTR_INTERRUPTED_A7	= 0x00000009,
};

#define SBI_SSE_ATTR_STATUS_STATE_OFFSET	0
#define SBI_SSE_ATTR_STATUS_STATE_MASK		0x3
#define SBI_SSE_ATTR_STATUS_PENDING_OFFSET	2
#define SBI_SSE_ATTR_STATUS_INJECT_OFFSET	3

#define SBI_SSE_ATTR_CONFIG_ONESHOT		BIT(0)

#define SBI_SSE_ATTR_INTERRUPTED_FLAGS_SSTATUS_SPP	BIT(0)
#define SBI_SSE_ATTR_INTERRUPTED_FLAGS_SSTATUS_SPIE	BIT(1)
#define SBI_SSE_ATTR_INTERRUPTED_FLAGS_HSTATUS_SPV	BIT(2)
#define SBI_SSE_ATTR_INTERRUPTED_FLAGS_HSTATUS_SPVP	BIT(3)
#define SBI_SSE_ATTR_INTERRUPTED_FLAGS_SSTATUS_SPELP	BIT(4)
#define SBI_SSE_ATTR_INTERRUPTED_FLAGS_SSTATUS_SDT	BIT(5)

enum sbi_sse_state {
	SBI_SSE_STATE_UNUSED		= 0,
	SBI_SSE_STATE_REGISTERED	= 1,
	SBI_SSE_STATE_ENABLED		= 2,
	SBI_SSE_STATE_RUNNING		= 3,
};

/* SBI SSE Event IDs. */
/* Range 0x00000000 - 0x0000ffff */
#define SBI_SSE_EVENT_LOCAL_HIGH_PRIO_RAS	0x00000000
#define SBI_SSE_EVENT_LOCAL_DOUBLE_TRAP		0x00000001
#define SBI_SSE_EVENT_LOCAL_RESERVED_0_START	0x00000002
#define SBI_SSE_EVENT_LOCAL_RESERVED_0_END	0x00003fff
#define SBI_SSE_EVENT_LOCAL_PLAT_0_START	0x00004000
#define SBI_SSE_EVENT_LOCAL_PLAT_0_END		0x00007fff

#define SBI_SSE_EVENT_GLOBAL_HIGH_PRIO_RAS	0x00008000
#define SBI_SSE_EVENT_GLOBAL_RESERVED_0_START	0x00008001
#define SBI_SSE_EVENT_GLOBAL_RESERVED_0_END	0x0000bfff
#define SBI_SSE_EVENT_GLOBAL_PLAT_0_START	0x0000c000
#define SBI_SSE_EVENT_GLOBAL_PLAT_0_END		0x0000ffff

/* Range 0x00010000 - 0x0001ffff */
#define SBI_SSE_EVENT_LOCAL_PMU_OVERFLOW	0x00010000
#define SBI_SSE_EVENT_LOCAL_RESERVED_1_START	0x00010001
#define SBI_SSE_EVENT_LOCAL_RESERVED_1_END	0x00013fff
#define SBI_SSE_EVENT_LOCAL_PLAT_1_START	0x00014000
#define SBI_SSE_EVENT_LOCAL_PLAT_1_END		0x00017fff

#define SBI_SSE_EVENT_GLOBAL_RESERVED_1_START	0x00018000
#define SBI_SSE_EVENT_GLOBAL_RESERVED_1_END	0x0001bfff
#define SBI_SSE_EVENT_GLOBAL_PLAT_1_START	0x0001c000
#define SBI_SSE_EVENT_GLOBAL_PLAT_1_END		0x0001ffff

/* Range 0x00100000 - 0x0010ffff */
#define SBI_SSE_EVENT_LOCAL_LOW_PRIO_RAS	0x00100000
#define SBI_SSE_EVENT_LOCAL_RESERVED_2_START	0x00100001
#define SBI_SSE_EVENT_LOCAL_RESERVED_2_END	0x00103fff
#define SBI_SSE_EVENT_LOCAL_PLAT_2_START	0x00104000
#define SBI_SSE_EVENT_LOCAL_PLAT_2_END		0x00107fff

#define SBI_SSE_EVENT_GLOBAL_LOW_PRIO_RAS	0x00108000
#define SBI_SSE_EVENT_GLOBAL_RESERVED_2_START	0x00108001
#define SBI_SSE_EVENT_GLOBAL_RESERVED_2_END	0x0010bfff
#define SBI_SSE_EVENT_GLOBAL_PLAT_2_START	0x0010c000
#define SBI_SSE_EVENT_GLOBAL_PLAT_2_END		0x0010ffff

/* Range 0xffff0000 - 0xffffffff */
#define SBI_SSE_EVENT_LOCAL_SOFTWARE		0xffff0000
#define SBI_SSE_EVENT_LOCAL_RESERVED_3_START	0xffff0001
#define SBI_SSE_EVENT_LOCAL_RESERVED_3_END	0xffff3fff
#define SBI_SSE_EVENT_LOCAL_PLAT_3_START	0xffff4000
#define SBI_SSE_EVENT_LOCAL_PLAT_3_END		0xffff7fff

#define SBI_SSE_EVENT_GLOBAL_SOFTWARE		0xffff8000
#define SBI_SSE_EVENT_GLOBAL_RESERVED_3_START	0xffff8001
#define SBI_SSE_EVENT_GLOBAL_RESERVED_3_END	0xffffbfff
#define SBI_SSE_EVENT_GLOBAL_PLAT_3_START	0xffffc000
#define SBI_SSE_EVENT_GLOBAL_PLAT_3_END		0xffffffff

#define SBI_SSE_EVENT_PLATFORM_BIT		BIT(14)
#define SBI_SSE_EVENT_GLOBAL_BIT		BIT(15)

struct sbiret {
	long error;
	long value;
};

static inline unsigned long sbi_mk_version(unsigned long major, unsigned long minor)
{
	return ((major & SBI_SPEC_VERSION_MAJOR_MASK) << SBI_SPEC_VERSION_MAJOR_SHIFT)
		| (minor & SBI_SPEC_VERSION_MINOR_MASK);
}

static inline unsigned long sbi_impl_opensbi_mk_version(unsigned long major, unsigned long minor)
{
	return (((major & 0xffff) << 16) | (minor & 0xffff));
}

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
struct sbiret sbi_get_spec_version(void);
struct sbiret sbi_get_imp_version(void);
struct sbiret sbi_get_imp_id(void);
long sbi_probe(int ext);
unsigned long __sbi_get_imp_version(void);
unsigned long __sbi_get_imp_id(void);

typedef void (*sbi_sse_handler_fn)(void *data, struct pt_regs *regs, unsigned int hartid);

struct sbi_sse_handler_arg {
	unsigned long reg_tmp;
	sbi_sse_handler_fn handler;
	void *handler_data;
	void *stack;
};

extern void sbi_sse_entry(void);

static inline bool sbi_sse_event_is_global(uint32_t event_id)
{
	return !!(event_id & SBI_SSE_EVENT_GLOBAL_BIT);
}

struct sbiret sbi_sse_read_attrs_raw(unsigned long event_id, unsigned long base_attr_id,
				     unsigned long attr_count, unsigned long phys_lo,
				     unsigned long phys_hi);
struct sbiret sbi_sse_read_attrs(unsigned long event_id, unsigned long base_attr_id,
				 unsigned long attr_count, unsigned long *values);
struct sbiret sbi_sse_write_attrs_raw(unsigned long event_id, unsigned long base_attr_id,
				      unsigned long attr_count, unsigned long phys_lo,
				      unsigned long phys_hi);
struct sbiret sbi_sse_write_attrs(unsigned long event_id, unsigned long base_attr_id,
				  unsigned long attr_count, unsigned long *values);
struct sbiret sbi_sse_register_raw(unsigned long event_id, unsigned long entry_pc,
				   unsigned long entry_arg);
struct sbiret sbi_sse_register(unsigned long event_id, struct sbi_sse_handler_arg *arg);
struct sbiret sbi_sse_unregister(unsigned long event_id);
struct sbiret sbi_sse_enable(unsigned long event_id);
struct sbiret sbi_sse_disable(unsigned long event_id);
struct sbiret sbi_sse_hart_mask(void);
struct sbiret sbi_sse_hart_unmask(void);
struct sbiret sbi_sse_inject(unsigned long event_id, unsigned long hart_id);

#endif /* !__ASSEMBLER__ */
#endif /* _ASMRISCV_SBI_H_ */
