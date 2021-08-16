/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Physical memory management related functions and definitions.
 *
 * Copyright IBM Corp. 2018
 * Author(s): Janosch Frank <frankja@linux.ibm.com>
 */
#ifndef _ASMS390X_MEM_H_
#define _ASMS390X_MEM_H_

#define SKEY_ACC	0xf0
#define SKEY_FP		0x08
#define SKEY_RF		0x04
#define SKEY_CH		0x02

union skey {
	struct {
		uint8_t acc : 4;
		uint8_t fp : 1;
		uint8_t rf : 1;
		uint8_t ch : 1;
		uint8_t pad : 1;
	} str;
	uint8_t val;
};

static inline void set_storage_key(void *addr, unsigned char skey, int nq)
{
	if (nq)
		asm volatile(".insn rrf,0xb22b0000,%0,%1,8,0"
			     : : "d" (skey), "a" (addr));
	else
		asm volatile("sske %0,%1" : : "d" (skey), "a" (addr));
}

static inline void *set_storage_key_mb(void *addr, unsigned char skey)
{
	assert(test_facility(8));

	asm volatile(".insn rrf,0xb22b0000,%[skey],%[addr],1,0"
		     : [addr] "+a" (addr) : [skey] "d" (skey));
	return addr;
}

static inline unsigned char get_storage_key(void *addr)
{
	unsigned char skey;

	asm volatile("iske %0,%1" : "=d" (skey) : "a" (addr));
	return skey;
}

#define PFMF_FSC_4K 0
#define PFMF_FSC_1M 1
#define PFMF_FSC_2G 2

union pfmf_r1 {
	struct {
		unsigned long pad0 : 32;
		unsigned long pad1 : 12;
		unsigned long pad_fmfi : 2;
		unsigned long sk : 1; /* set key*/
		unsigned long cf : 1; /* clear frame */
		unsigned long ui : 1; /* usage indication */
		unsigned long fsc : 3;
		unsigned long pad2 : 1;
		unsigned long mr : 1;
		unsigned long mc : 1;
		unsigned long pad3 : 1;
		unsigned long key : 8; /* storage keys */
	} reg;
	unsigned long val;
};

static inline void *pfmf(unsigned long r1, void *paddr)
{
	register void * addr asm("1") = paddr;

	asm volatile(".insn rre,0xb9af0000,%[r1],%[addr]"
		     : [addr] "+a" (addr) : [r1] "d" (r1) : "memory");
	return addr;
}
#endif
