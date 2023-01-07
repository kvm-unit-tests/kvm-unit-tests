#ifndef _X86_APIC_H_
#define _X86_APIC_H_

#include <bitops.h>
#include <stdint.h>
#include "apic-defs.h"

extern u8 id_map[MAX_TEST_CPUS];

typedef struct {
    uint8_t vector;
    uint8_t delivery_mode:3;
    uint8_t dest_mode:1;
    uint8_t delivery_status:1;
    uint8_t polarity:1;
    uint8_t remote_irr:1;
    uint8_t trig_mode:1;
    uint8_t mask:1;
    uint8_t reserve:7;
    uint8_t reserved[4];
    uint8_t dest_id;
} ioapic_redir_entry_t;

typedef enum trigger_mode {
	TRIGGER_EDGE = 0,
	TRIGGER_LEVEL,
	TRIGGER_MAX,
} trigger_mode_t;

void mask_pic_interrupts(void);

void eoi(void);
uint8_t apic_get_tpr(void);
void apic_set_tpr(uint8_t tpr);

void ioapic_write_redir(unsigned line, ioapic_redir_entry_t e);
void ioapic_write_reg(unsigned reg, uint32_t value);
ioapic_redir_entry_t ioapic_read_redir(unsigned line);
uint32_t ioapic_read_reg(unsigned reg);

void ioapic_set_redir(unsigned line, unsigned vec,
		trigger_mode_t trig_mode);

void set_mask(unsigned line, int mask);

void set_irq_line(unsigned line, int val);

void enable_apic(void);
uint32_t apic_read(unsigned reg);
bool apic_read_bit(unsigned reg, int n);
void apic_write(unsigned reg, uint32_t val);
void apic_icr_write(uint32_t val, uint32_t dest);
uint32_t apic_id(void);
uint32_t pre_boot_apic_id(void);


int enable_x2apic(void);
void disable_apic(void);
void reset_apic(void);
void init_apic_map(void);

/* Converts byte-addressable APIC register offset to 4-byte offset. */
static inline u32 apic_reg_index(u32 reg)
{
	return reg >> 2;
}

static inline u32 x2apic_msr(u32 reg)
{
	return APIC_BASE_MSR + (reg >> 4);
}

static inline bool apic_lvt_entry_supported(int idx)
{
	return GET_APIC_MAXLVT(apic_read(APIC_LVR)) >= idx;
}

enum x2apic_reg_semantics {
	X2APIC_INVALID	= 0,
	X2APIC_READABLE	= BIT(0),
	X2APIC_WRITABLE	= BIT(1),
	X2APIC_RO	= X2APIC_READABLE,
	X2APIC_WO	= X2APIC_WRITABLE,
	X2APIC_RW	= X2APIC_READABLE | X2APIC_WRITABLE,
};

static inline enum x2apic_reg_semantics get_x2apic_reg_semantics(u32 reg)
{
	assert(!(reg & 0xf));

	switch (reg) {
	case APIC_ID:
	case APIC_LVR:
	case APIC_PROCPRI:
	case APIC_LDR:
	case APIC_ISR ... APIC_ISR + 0x70:
	case APIC_TMR ... APIC_TMR + 0x70:
	case APIC_IRR ... APIC_IRR + 0x70:
	case APIC_TMCCT:
		return X2APIC_RO;
	case APIC_TASKPRI:
	case APIC_SPIV:
	case APIC_ESR:
	case APIC_ICR:
	case APIC_LVTT:
	case APIC_LVTTHMR:
	case APIC_LVTPC:
	case APIC_LVT0:
	case APIC_LVT1:
	case APIC_LVTERR:
	case APIC_TMICT:
	case APIC_TDCR:
		return X2APIC_RW;
	case APIC_EOI:
	case APIC_SELF_IPI:
		return X2APIC_WO;
	case APIC_CMCI:
		if (apic_lvt_entry_supported(6))
			return X2APIC_RW;
		break;
	case APIC_RRR:
	case APIC_DFR:
	case APIC_ICR2:
	default:
		break;
	}
	return X2APIC_INVALID;
}

#endif
