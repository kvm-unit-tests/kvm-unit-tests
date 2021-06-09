/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CSS definitions
 *
 * Copyright IBM, Corp. 2020
 * Author: Pierre Morel <pmorel@linux.ibm.com>
 */

#ifndef _S390X_CSS_H_
#define _S390X_CSS_H_

#define lowcore_ptr ((struct lowcore *)0x0)

/* subchannel ID bit 16 must always be one */
#define SCHID_ONE	0x00010000

#define CCW_F_CD	0x80
#define CCW_F_CC	0x40
#define CCW_F_SLI	0x20
#define CCW_F_SKP	0x10
#define CCW_F_PCI	0x08
#define CCW_F_IDA	0x04
#define CCW_F_S		0x02
#define CCW_F_MIDA	0x01

#define CCW_C_NOP	0x03
#define CCW_C_TIC	0x08

struct ccw1 {
	uint8_t code;
	uint8_t flags;
	uint16_t count;
	uint32_t data_address;
} __attribute__ ((aligned(8)));

#define ORB_CTRL_KEY	0xf0000000
#define ORB_CTRL_SPND	0x08000000
#define ORB_CTRL_STR	0x04000000
#define ORB_CTRL_MOD	0x02000000
#define ORB_CTRL_SYNC	0x01000000
#define ORB_CTRL_FMT	0x00800000
#define ORB_CTRL_PFCH	0x00400000
#define ORB_CTRL_ISIC	0x00200000
#define ORB_CTRL_ALCC	0x00100000
#define ORB_CTRL_SSIC	0x00080000
#define ORB_CTRL_CPTC	0x00040000
#define ORB_CTRL_C64	0x00020000
#define ORB_CTRL_I2K	0x00010000
#define ORB_CTRL_LPM	0x0000ff00
#define ORB_CTRL_ILS	0x00000080
#define ORB_CTRL_MIDAW	0x00000040
#define ORB_CTRL_ORBX	0x00000001

#define ORB_LPM_DFLT	0x00008000

struct orb {
	uint32_t intparm;
	uint32_t ctrl;
	uint32_t cpa;
	uint32_t prio;
	uint32_t reserved[4];
} __attribute__ ((aligned(4)));

struct scsw {
#define SCSW_SC_PENDING		0x00000001
#define SCSW_SC_SECONDARY	0x00000002
#define SCSW_SC_PRIMARY		0x00000004
#define SCSW_SC_INTERMEDIATE	0x00000008
#define SCSW_SC_ALERT		0x00000010
	uint32_t ctrl;
	uint32_t ccw_addr;
#define SCSW_DEVS_DEV_END	0x04
#define SCSW_DEVS_SCH_END	0x08
	uint8_t  dev_stat;
#define SCSW_SCHS_PCI	0x80
#define SCSW_SCHS_IL	0x40
	uint8_t  sch_stat;
	uint16_t count;
};

struct pmcw {
	uint32_t intparm;
#define PMCW_DNV	0x0001
#define PMCW_ENABLE	0x0080
#define PMCW_MBUE	0x0010
#define PMCW_DCTME	0x0008
#define PMCW_ISC_MASK	0x3800
#define PMCW_ISC_SHIFT	11
	uint16_t flags;
	uint16_t devnum;
	uint8_t  lpm;
	uint8_t  pnom;
	uint8_t  lpum;
	uint8_t  pim;
	uint16_t mbi;
	uint8_t  pom;
	uint8_t  pam;
	uint8_t  chpid[8];
#define PMCW_MBF1	0x0004
	uint32_t flags2;
};
#define PMCW_CHANNEL_TYPE(pmcw) (pmcw->flags2 >> 21)

struct schib {
	struct pmcw pmcw;
	struct scsw scsw;
	uint64_t mbo;
	uint8_t  md[4];
} __attribute__ ((aligned(4)));
extern struct schib schib;

struct irb {
	struct scsw scsw;
	uint32_t esw[5];
	uint32_t ecw[8];
	uint32_t emw[8];
} __attribute__ ((aligned(4)));

#define CCW_CMD_SENSE_ID	0xe4
#define CSS_SENSEID_COMMON_LEN	8
struct senseid {
	/* common part */
	uint8_t reserved;        /* always 0x'FF' */
	uint16_t cu_type;        /* control unit type */
	uint8_t cu_model;        /* control unit model */
	uint16_t dev_type;       /* device type */
	uint8_t dev_model;       /* device model */
	uint8_t unused;          /* padding byte */
	uint8_t padding[256 - 8]; /* Extended part */
} __attribute__ ((aligned(4))) __attribute__ ((packed));

/* CSS low level access functions */

static inline int ssch(unsigned long schid, struct orb *addr)
{
	register long long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	ssch	0(%2)\n"
		"	ipm	%0\n"
		"	srl	%0,28\n"
		: "=d" (cc)
		: "d" (reg1), "a" (addr), "m" (*addr)
		: "cc", "memory");
	return cc;
}

static inline int stsch(unsigned long schid, struct schib *addr)
{
	register unsigned long reg1 asm ("1") = schid;
	int cc;

	asm volatile(
		"	stsch	0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc), "=m" (*addr)
		: "d" (reg1), "a" (addr)
		: "cc");
	return cc;
}

static inline int msch(unsigned long schid, struct schib *addr)
{
	register unsigned long reg1 asm ("1") = schid;
	int cc;

	asm volatile(
		"	msch	0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1), "m" (*addr), "a" (addr)
		: "cc");
	return cc;
}

static inline int tsch(unsigned long schid, struct irb *addr)
{
	register unsigned long reg1 asm ("1") = schid;
	int cc;

	asm volatile(
		"	tsch	0(%3)\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc), "=m" (*addr)
		: "d" (reg1), "a" (addr)
		: "cc");
	return cc;
}

static inline int hsch(unsigned long schid)
{
	register unsigned long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	hsch\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

static inline int xsch(unsigned long schid)
{
	register unsigned long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	xsch\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

static inline int csch(unsigned long schid)
{
	register unsigned long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	csch\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

static inline int rsch(unsigned long schid)
{
	register unsigned long reg1 asm("1") = schid;
	int cc;

	asm volatile(
		"	rsch\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

static inline int rchp(unsigned long chpid)
{
	register unsigned long reg1 asm("1") = chpid;
	int cc;

	asm volatile(
		"	rchp\n"
		"	ipm	%0\n"
		"	srl	%0,28"
		: "=d" (cc)
		: "d" (reg1)
		: "cc");
	return cc;
}

/* Debug functions */
char *dump_pmcw_flags(uint16_t f);
char *dump_scsw_flags(uint32_t f);

void dump_scsw(struct scsw *scsw);
void dump_irb(struct irb *irbp);
void dump_schib(struct schib *sch);
struct ccw1 *dump_ccw(struct ccw1 *cp);
void dump_irb(struct irb *irbp);
void dump_pmcw(struct pmcw *p);
void dump_orb(struct orb *op);

int css_enumerate(void);
#define MAX_ENABLE_RETRIES      5

#define IO_SCH_ISC      3
int css_enable(int schid, int isc);
bool css_enabled(int schid);

/* Library functions */
int start_ccw1_chain(unsigned int sid, struct ccw1 *ccw);
struct ccw1 *ccw_alloc(int code, void *data, int count, unsigned char flags);
void css_irq_io(void);
int css_residual_count(unsigned int schid);

void enable_io_isc(uint8_t isc);
int wait_and_check_io_completion(int schid);

/*
 * CHSC definitions
 */
struct chsc_header {
	uint16_t len;
	uint16_t code;
};

/* Store Channel Subsystem Characteristics */
struct chsc_scsc {
	struct chsc_header req;
	uint16_t req_fmt;
	uint8_t cssid;
	uint8_t reserved[9];
	struct chsc_header res;
	uint32_t res_fmt;
#define CSSC_EXTENDED_MEASUREMENT_BLOCK 48
	uint64_t general_char[255];
	uint64_t chsc_char[254];
};

extern struct chsc_scsc *chsc_scsc;
#define CHSC_SCSC	0x0010
#define CHSC_SCSC_LEN	0x0010

bool get_chsc_scsc(void);

#define CSS_GENERAL_FEAT_BITLEN	(255 * 64)
#define CSS_CHSC_FEAT_BITLEN	(254 * 64)

#define CHSC_SCSC	0x0010
#define CHSC_SCSC_LEN	0x0010

#define CHSC_ERROR	0x0000
#define CHSC_RSP_OK	0x0001
#define CHSC_RSP_INVAL	0x0002
#define CHSC_RSP_REQERR	0x0003
#define CHSC_RSP_ENOCMD	0x0004
#define CHSC_RSP_NODATA	0x0005
#define CHSC_RSP_SUP31B	0x0006
#define CHSC_RSP_EFRMT	0x0007
#define CHSC_RSP_ECSSID	0x0008
#define CHSC_RSP_ERFRMT	0x0009
#define CHSC_RSP_ESSID	0x000A
#define CHSC_RSP_EBUSY	0x000B
#define CHSC_RSP_MAX	0x000B

static inline int _chsc(void *p)
{
	int cc;

	asm volatile(" .insn   rre,0xb25f0000,%2,0\n"
		     " ipm     %0\n"
		     " srl     %0,28\n"
		     : "=d" (cc), "=m" (p)
		     : "d" (p), "m" (p)
		     : "cc");

	return cc;
}

bool chsc(void *p, uint16_t code, uint16_t len);

#include <bitops.h>
#define css_test_general_feature(bit) test_bit_inv(bit, chsc_scsc->general_char)
#define css_test_chsc_feature(bit) test_bit_inv(bit, chsc_scsc->chsc_char)

#define SCHM_DCTM	1 /* activate Device Connection TiMe */
#define SCHM_MBU	2 /* activate Measurement Block Update */

static inline void schm(void *mbo, unsigned int flags)
{
	register void *__gpr2 asm("2") = mbo;
	register long __gpr1 asm("1") = flags;

	asm("schm" : : "d" (__gpr2), "d" (__gpr1));
}

bool css_enable_mb(int sid, uint64_t mb, uint16_t mbi, uint16_t flg, bool fmt1);
bool css_disable_mb(int schid);

struct measurement_block_format0 {
	uint16_t ssch_rsch_count;
	uint16_t sample_count;
	uint32_t device_connect_time;
	uint32_t function_pending_time;
	uint32_t device_disconnect_time;
	uint32_t cu_queuing_time;
	uint32_t device_active_only_time;
	uint32_t device_busy_time;
	uint32_t initial_cmd_resp_time;
};

struct measurement_block_format1 {
	uint32_t ssch_rsch_count;
	uint32_t sample_count;
	uint32_t device_connect_time;
	uint32_t function_pending_time;
	uint32_t device_disconnect_time;
	uint32_t cu_queuing_time;
	uint32_t device_active_only_time;
	uint32_t device_busy_time;
	uint32_t initial_cmd_resp_time;
	uint32_t irq_delay_time;
	uint32_t irq_prio_delay_time;
};

#endif
