/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _S390X_SIE_H_
#define _S390X_SIE_H_

#include <stdint.h>
#include <asm/arch_def.h>
#include <asm/sie-arch.h>

struct vm_uv {
	uint64_t vm_handle;
	uint64_t vcpu_handle;
	uint64_t asce;
	void *conf_base_stor;
	void *conf_var_stor;
	void *cpu_stor;
};

struct vm_save_regs {
	uint64_t asce;
	uint64_t grs[16];
	uint64_t fprs[16];
	uint32_t fpc;
};

/* We might be able to nestle all of this into the stack frame. But
 * having a dedicated save area that saves more than the s390 ELF ABI
 * defines leaves us more freedom in the implementation.
*/
struct vm_save_area {
	struct vm_save_regs guest;
	struct vm_save_regs host;
};

struct vm {
	struct kvm_s390_sie_block *sblk;
	struct vm_save_area save_area;
	struct esca_block *sca;			/* System Control Area */
	uint8_t *crycb;				/* Crypto Control Block */
	struct vm_uv uv;			/* PV UV information */
	/* Ptr to first guest page */
	uint8_t *guest_mem;
	bool validity_expected;
};

extern void sie_entry(void);
extern void sie_exit(void);
extern void sie_entry_gregs(void);
extern void sie_exit_gregs(void);
extern void sie64a(struct kvm_s390_sie_block *sblk, struct vm_save_area *save_area);
void sie(struct vm *vm);
void sie_expect_validity(struct vm *vm);
uint16_t sie_get_validity(struct vm *vm);
void sie_check_validity(struct vm *vm, uint16_t vir_exp);
void sie_handle_validity(struct vm *vm);

static inline bool sie_is_pv(struct vm *vm)
{
	return vm->sblk->sdf == 2;
}

void sie_guest_sca_create(struct vm *vm);
void sie_guest_create(struct vm *vm, uint64_t guest_mem, uint64_t guest_mem_len);
void sie_guest_destroy(struct vm *vm);

uint8_t *sie_guest_alloc(uint64_t guest_size);

#endif /* _S390X_SIE_H_ */
