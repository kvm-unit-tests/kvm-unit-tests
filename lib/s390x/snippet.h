/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Snippet definitions
 *
 * Copyright IBM Corp. 2021
 * Author: Janosch Frank <frankja@linux.ibm.com>
 */

#ifndef _S390X_SNIPPET_H_
#define _S390X_SNIPPET_H_

#include <sie.h>
#include <uv.h>
#include <asm/uv.h>

/* This macro cuts down the length of the pointers to snippets */
#define SNIPPET_NAME_START(type, file) \
	_binary_s390x_snippets_##type##_##file##_gbin_start
#define SNIPPET_NAME_END(type, file) \
	_binary_s390x_snippets_##type##_##file##_gbin_end
#define SNIPPET_HDR_START(type, file) \
	_binary_s390x_snippets_##type##_##file##_hdr_start
#define SNIPPET_HDR_END(type, file) \
	_binary_s390x_snippets_##type##_##file##_hdr_end


/* Returns the length of the snippet */
#define SNIPPET_LEN(type, file) \
	((uintptr_t)SNIPPET_NAME_END(type, file) - (uintptr_t)SNIPPET_NAME_START(type, file))
#define SNIPPET_HDR_LEN(type, file) \
	((uintptr_t)SNIPPET_HDR_END(type, file) - (uintptr_t)SNIPPET_HDR_START(type, file))

/*
 * Some of the UV memory needs to be allocated with >31 bit
 * addresses which means we need a lot more memory than other
 * tests.
 */
#define SNIPPET_PV_MIN_MEM_SIZE	(SZ_1M * 2200UL)

#define SNIPPET_PV_TWEAK0	0x42UL
#define SNIPPET_PV_TWEAK1	0UL
#define SNIPPET_UNPACK_OFF	0


/*
 * C snippet instructions start at 0x4000 due to the prefix and the
 * stack being before that. ASM snippets don't strictly need a stack
 * but keeping the starting address the same means less code.
 */
#define SNIPPET_ENTRY_ADDR 0x4000

/* Standard entry PSWs for snippets which can simply be copied into the guest PSW */
static const struct psw snippet_psw = {
	.mask = PSW_MASK_64,
	.addr = SNIPPET_ENTRY_ADDR,
};

/*
 * Sets up a snippet guest on top of an existing and initialized SIE
 * vm struct.
 * Once this function has finished without errors the guest can be started.
 *
 * @vm: VM that this function will populated, has to be initialized already
 * @gbin: Snippet gbin data pointer
 * @gbin_len: Length of the gbin data
 * @off: Offset from guest absolute 0x0 where snippet is copied to
 */
static inline void snippet_init(struct vm *vm, const char *gbin,
				uint64_t gbin_len, uint64_t off)
{
	uint64_t mso = vm->sblk->mso;

	/* Copy test image to guest memory */
	memcpy((void *)mso + off, gbin, gbin_len);

	/* Setup guest PSW */
	vm->sblk->gpsw = snippet_psw;

	/*
	 * We want to exit on PGM exceptions so we don't need
	 * exception handlers in the guest.
	 */
	vm->sblk->ictl = ICTL_OPEREXC | ICTL_PINT;
}

/*
 * Sets up a snippet UV/PV guest on top of an existing and initialized
 * SIE vm struct.
 * Once this function has finished without errors the guest can be started.
 *
 * @vm: VM that this function will populated, has to be initialized already
 * @gbin: Snippet gbin data pointer
 * @hdr: Snippet SE header data pointer
 * @gbin_len: Length of the gbin data
 * @hdr_len: Length of the hdr data
 * @off: Offset from guest absolute 0x0 where snippet is copied to
 */
static inline void snippet_pv_init(struct vm *vm, const char *gbin,
				   const char *hdr, uint64_t gbin_len,
				   uint64_t hdr_len, uint64_t off)
{
	uint64_t tweak[2] = {SNIPPET_PV_TWEAK0, SNIPPET_PV_TWEAK1};
	uint64_t mso = vm->sblk->mso;
	int i;

	snippet_init(vm, gbin, gbin_len, off);

	uv_create_guest(vm);
	uv_set_se_hdr(vm->uv.vm_handle, (void *)hdr, hdr_len);

	/* Unpack works on guest addresses so we only need off */
	uv_unpack(vm, off, gbin_len, tweak[0]);
	uv_verify_load(vm);

	/*
	 * Manually import:
	 * - lowcore 0x0 - 0x1000 (asm)
	 * - stack 0x3000 (C)
	 */
	for (i = 0; i < 4; i++) {
		uv_import(vm->uv.vm_handle, mso + PAGE_SIZE * i);
	}
}

/* Allocates and sets up a snippet based guest */
static inline void snippet_setup_guest(struct vm *vm, bool is_pv)
{
	const unsigned long guest_size = SZ_1M;
	uint8_t *guest_start = sie_guest_alloc(guest_size);

	/* Initialize the vm struct and allocate control blocks */
	sie_guest_create(vm, (uint64_t)guest_start, guest_size);

	if (is_pv) {
		/* FMT4 needs a ESCA */
		sie_guest_sca_create(vm);

		/*
		 * Initialize UV and setup the address spaces needed
		 * to run a PV guest.
		 */
		uv_init();
		uv_setup_asces();
	}
}

#endif
