/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * CP Assist for Cryptographic Functions (CPACF)
 *
 * Copyright IBM Corp. 2003, 2016
 * Author(s): Thomas Spatzier
 *	      Jan Glauber
 *	      Harald Freudenberger (freude@de.ibm.com)
 *	      Martin Schwidefsky <schwidefsky@de.ibm.com>
 */
#ifndef _ASMS390X_CPACF_H_
#define _ASMS390X_CPACF_H_

#include <asm/facility.h>
#include <linux/compiler.h>

/*
 * Instruction opcodes for the CPACF instructions
 */
#define CPACF_KMAC		0xb91e		/* MSA	*/
#define CPACF_KM		0xb92e		/* MSA	*/
#define CPACF_KMC		0xb92f		/* MSA	*/
#define CPACF_KIMD		0xb93e		/* MSA	*/
#define CPACF_KLMD		0xb93f		/* MSA	*/
#define CPACF_PCKMO		0xb928		/* MSA3 */
#define CPACF_KMF		0xb92a		/* MSA4 */
#define CPACF_KMO		0xb92b		/* MSA4 */
#define CPACF_PCC		0xb92c		/* MSA4 */
#define CPACF_KMCTR		0xb92d		/* MSA4 */
#define CPACF_PRNO		0xb93c		/* MSA5 */
#define CPACF_KMA		0xb929		/* MSA8 */

/*
 * En/decryption modifier bits
 */
#define CPACF_ENCRYPT		0x00
#define CPACF_DECRYPT		0x80

/*
 * Function codes for the KM (CIPHER MESSAGE) instruction
 */
#define CPACF_KM_QUERY		0x00
#define CPACF_KM_DEA		0x01
#define CPACF_KM_TDEA_128	0x02
#define CPACF_KM_TDEA_192	0x03
#define CPACF_KM_AES_128	0x12
#define CPACF_KM_AES_192	0x13
#define CPACF_KM_AES_256	0x14
#define CPACF_KM_PAES_128	0x1a
#define CPACF_KM_PAES_192	0x1b
#define CPACF_KM_PAES_256	0x1c
#define CPACF_KM_XTS_128	0x32
#define CPACF_KM_XTS_256	0x34
#define CPACF_KM_PXTS_128	0x3a
#define CPACF_KM_PXTS_256	0x3c

/*
 * Function codes for the KMC (CIPHER MESSAGE WITH CHAINING)
 * instruction
 */
#define CPACF_KMC_QUERY		0x00
#define CPACF_KMC_DEA		0x01
#define CPACF_KMC_TDEA_128	0x02
#define CPACF_KMC_TDEA_192	0x03
#define CPACF_KMC_AES_128	0x12
#define CPACF_KMC_AES_192	0x13
#define CPACF_KMC_AES_256	0x14
#define CPACF_KMC_PAES_128	0x1a
#define CPACF_KMC_PAES_192	0x1b
#define CPACF_KMC_PAES_256	0x1c
#define CPACF_KMC_PRNG		0x43

/*
 * Function codes for the KMCTR (CIPHER MESSAGE WITH COUNTER)
 * instruction
 */
#define CPACF_KMCTR_QUERY	0x00
#define CPACF_KMCTR_DEA		0x01
#define CPACF_KMCTR_TDEA_128	0x02
#define CPACF_KMCTR_TDEA_192	0x03
#define CPACF_KMCTR_AES_128	0x12
#define CPACF_KMCTR_AES_192	0x13
#define CPACF_KMCTR_AES_256	0x14
#define CPACF_KMCTR_PAES_128	0x1a
#define CPACF_KMCTR_PAES_192	0x1b
#define CPACF_KMCTR_PAES_256	0x1c

/*
 * Function codes for the KIMD (COMPUTE INTERMEDIATE MESSAGE DIGEST)
 * instruction
 */
#define CPACF_KIMD_QUERY	0x00
#define CPACF_KIMD_SHA_1	0x01
#define CPACF_KIMD_SHA_256	0x02
#define CPACF_KIMD_SHA_512	0x03
#define CPACF_KIMD_GHASH	0x41

/*
 * Function codes for the KLMD (COMPUTE LAST MESSAGE DIGEST)
 * instruction
 */
#define CPACF_KLMD_QUERY	0x00
#define CPACF_KLMD_SHA_1	0x01
#define CPACF_KLMD_SHA_256	0x02
#define CPACF_KLMD_SHA_512	0x03

/*
 * function codes for the KMAC (COMPUTE MESSAGE AUTHENTICATION CODE)
 * instruction
 */
#define CPACF_KMAC_QUERY	0x00
#define CPACF_KMAC_DEA		0x01
#define CPACF_KMAC_TDEA_128	0x02
#define CPACF_KMAC_TDEA_192	0x03

/*
 * Function codes for the PCKMO (PERFORM CRYPTOGRAPHIC KEY MANAGEMENT)
 * instruction
 */
#define CPACF_PCKMO_QUERY		0x00
#define CPACF_PCKMO_ENC_DES_KEY		0x01
#define CPACF_PCKMO_ENC_TDES_128_KEY	0x02
#define CPACF_PCKMO_ENC_TDES_192_KEY	0x03
#define CPACF_PCKMO_ENC_AES_128_KEY	0x12
#define CPACF_PCKMO_ENC_AES_192_KEY	0x13
#define CPACF_PCKMO_ENC_AES_256_KEY	0x14

/*
 * Function codes for the PRNO (PERFORM RANDOM NUMBER OPERATION)
 * instruction
 */
#define CPACF_PRNO_QUERY		0x00
#define CPACF_PRNO_SHA512_DRNG_GEN	0x03
#define CPACF_PRNO_SHA512_DRNG_SEED	0x83
#define CPACF_PRNO_TRNG_Q_R2C_RATIO	0x70
#define CPACF_PRNO_TRNG			0x72

typedef struct { unsigned char bytes[16]; } cpacf_mask_t;

static __always_inline void __cpacf_query_rre(u32 opc, u8 r1, u8 r2,
					      cpacf_mask_t *mask)
{
	asm volatile(
		"	la	%%r1,%[mask]\n"
		"	xgr	%%r0,%%r0\n"
		"	.insn	rre,%[opc] << 16,%[r1],%[r2]\n"
		: [mask] "=R" (*mask)
		: [opc] "i" (opc),
		  [r1] "i" (r1), [r2] "i" (r2)
		: "cc", "r0", "r1");
}

static __always_inline void __cpacf_query_rrf(u32 opc,
					      u8 r1, u8 r2, u8 r3, u8 m4,
					      cpacf_mask_t *mask)
{
	asm volatile(
		"	la	%%r1,%[mask]\n"
		"	xgr	%%r0,%%r0\n"
		"	.insn	rrf,%[opc] << 16,%[r1],%[r2],%[r3],%[m4]\n"
		: [mask] "=R" (*mask)
		: [opc] "i" (opc), [r1] "i" (r1), [r2] "i" (r2),
		  [r3] "i" (r3), [m4] "i" (m4)
		: "cc", "r0", "r1");
}

static __always_inline void __cpacf_query(unsigned int opcode,
					  cpacf_mask_t *mask)
{
	switch (opcode) {
	case CPACF_KIMD:
		__cpacf_query_rre(CPACF_KIMD, 0, 2, mask);
		break;
	case CPACF_KLMD:
		__cpacf_query_rre(CPACF_KLMD, 0, 2, mask);
		break;
	case CPACF_KM:
		__cpacf_query_rre(CPACF_KM, 2, 4, mask);
		break;
	case CPACF_KMA:
		__cpacf_query_rrf(CPACF_KMA, 2, 4, 6, 0, mask);
		break;
	case CPACF_KMAC:
		__cpacf_query_rre(CPACF_KMAC, 0, 2, mask);
		break;
	case CPACF_KMC:
		__cpacf_query_rre(CPACF_KMC, 2, 4, mask);
		break;
	case CPACF_KMCTR:
		__cpacf_query_rrf(CPACF_KMCTR, 2, 4, 6, 0, mask);
		break;
	case CPACF_KMF:
		__cpacf_query_rre(CPACF_KMF, 2, 4, mask);
		break;
	case CPACF_KMO:
		__cpacf_query_rre(CPACF_KMO, 2, 4, mask);
		break;
	case CPACF_PCC:
		__cpacf_query_rre(CPACF_PCC, 0, 0, mask);
		break;
	case CPACF_PCKMO:
		__cpacf_query_rre(CPACF_PCKMO, 0, 0, mask);
		break;
	case CPACF_PRNO:
		__cpacf_query_rre(CPACF_PRNO, 2, 4, mask);
		break;
	default:
		asm volatile(".error \"bad opcode\"");
	}
}

static inline int __cpacf_check_opcode(unsigned int opcode)
{
	switch (opcode) {
	case CPACF_KMAC:
	case CPACF_KM:
	case CPACF_KMC:
	case CPACF_KIMD:
	case CPACF_KLMD:
		return test_facility(17);	/* check for MSA */
	case CPACF_PCKMO:
		return test_facility(76);	/* check for MSA3 */
	case CPACF_KMF:
	case CPACF_KMO:
	case CPACF_PCC:
	case CPACF_KMCTR:
		return test_facility(77);	/* check for MSA4 */
	case CPACF_PRNO:
		return test_facility(57);	/* check for MSA5 */
	default:
		return 0;
	}
}

static __always_inline int cpacf_query(unsigned int opcode, cpacf_mask_t *mask)
{
	if (__cpacf_check_opcode(opcode)) {
		__cpacf_query(opcode, mask);
		return 1;
	}
	memset(mask, 0, sizeof(*mask));
	return 0;
}

static inline int cpacf_test_func(cpacf_mask_t *mask, unsigned int func)
{
	return (mask->bytes[func >> 3] & (0x80 >> (func & 7))) != 0;
}

/**
 * cpacf_query_func() - check if a specific CPACF function is available
 * @opcode: the opcode of the crypto instruction
 * @func: the function code to test for
 *
 * Executes the query function for the given crypto instruction @opcode
 * and checks if @func is available
 *
 * Returns 1 if @func is available for @opcode, 0 otherwise
 */
static inline int cpacf_query_func(unsigned int opcode, unsigned int func)
{
	cpacf_mask_t mask;

	if (cpacf_query(opcode, &mask))
		return cpacf_test_func(&mask, func);
	return 0;
}

/**
 * cpacf_km() - executes the KM (CIPHER MESSAGE) instruction
 * @func: the function code passed to KM; see CPACF_KM_xxx defines
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Returns 0 for the query func, number of processed bytes for
 * encryption/decryption funcs
 */
static inline int cpacf_km(unsigned long func, void *param,
			   u8 *dest, const u8 *src, long src_len)
{
	register unsigned long r0 asm("0") = (unsigned long) func;
	register unsigned long r1 asm("1") = (unsigned long) param;
	register unsigned long r2 asm("2") = (unsigned long) src;
	register unsigned long r3 asm("3") = (unsigned long) src_len;
	register unsigned long r4 asm("4") = (unsigned long) dest;

	asm volatile(
		"0:	.insn	rre,%[opc] << 16,%[dst],%[src]\n"
		"	brc	1,0b\n" /* handle partial completion */
		: [src] "+a" (r2), [len] "+d" (r3), [dst] "+a" (r4)
		: [fc] "d" (r0), [pba] "a" (r1), [opc] "i" (CPACF_KM)
		: "cc", "memory");

	return src_len - r3;
}

/**
 * cpacf_kmc() - executes the KMC (CIPHER MESSAGE WITH CHAINING) instruction
 * @func: the function code passed to KM; see CPACF_KMC_xxx defines
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Returns 0 for the query func, number of processed bytes for
 * encryption/decryption funcs
 */
static inline int cpacf_kmc(unsigned long func, void *param,
			    u8 *dest, const u8 *src, long src_len)
{
	register unsigned long r0 asm("0") = (unsigned long) func;
	register unsigned long r1 asm("1") = (unsigned long) param;
	register unsigned long r2 asm("2") = (unsigned long) src;
	register unsigned long r3 asm("3") = (unsigned long) src_len;
	register unsigned long r4 asm("4") = (unsigned long) dest;

	asm volatile(
		"0:	.insn	rre,%[opc] << 16,%[dst],%[src]\n"
		"	brc	1,0b\n" /* handle partial completion */
		: [src] "+a" (r2), [len] "+d" (r3), [dst] "+a" (r4)
		: [fc] "d" (r0), [pba] "a" (r1), [opc] "i" (CPACF_KMC)
		: "cc", "memory");

	return src_len - r3;
}

/**
 * cpacf_kimd() - executes the KIMD (COMPUTE INTERMEDIATE MESSAGE DIGEST)
 *		  instruction
 * @func: the function code passed to KM; see CPACF_KIMD_xxx defines
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 */
static inline void cpacf_kimd(unsigned long func, void *param,
			      const u8 *src, long src_len)
{
	register unsigned long r0 asm("0") = (unsigned long) func;
	register unsigned long r1 asm("1") = (unsigned long) param;
	register unsigned long r2 asm("2") = (unsigned long) src;
	register unsigned long r3 asm("3") = (unsigned long) src_len;

	asm volatile(
		"0:	.insn	rre,%[opc] << 16,0,%[src]\n"
		"	brc	1,0b\n" /* handle partial completion */
		: [src] "+a" (r2), [len] "+d" (r3)
		: [fc] "d" (r0), [pba] "a" (r1), [opc] "i" (CPACF_KIMD)
		: "cc", "memory");
}

/**
 * cpacf_klmd() - executes the KLMD (COMPUTE LAST MESSAGE DIGEST) instruction
 * @func: the function code passed to KM; see CPACF_KLMD_xxx defines
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 */
static inline void cpacf_klmd(unsigned long func, void *param,
			      const u8 *src, long src_len)
{
	register unsigned long r0 asm("0") = (unsigned long) func;
	register unsigned long r1 asm("1") = (unsigned long) param;
	register unsigned long r2 asm("2") = (unsigned long) src;
	register unsigned long r3 asm("3") = (unsigned long) src_len;

	asm volatile(
		"0:	.insn	rre,%[opc] << 16,0,%[src]\n"
		"	brc	1,0b\n" /* handle partial completion */
		: [src] "+a" (r2), [len] "+d" (r3)
		: [fc] "d" (r0), [pba] "a" (r1), [opc] "i" (CPACF_KLMD)
		: "cc", "memory");
}

/**
 * cpacf_kmac() - executes the KMAC (COMPUTE MESSAGE AUTHENTICATION CODE)
 *		  instruction
 * @func: the function code passed to KM; see CPACF_KMAC_xxx defines
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Returns 0 for the query func, number of processed bytes for digest funcs
 */
static inline int cpacf_kmac(unsigned long func, void *param,
			     const u8 *src, long src_len)
{
	register unsigned long r0 asm("0") = (unsigned long) func;
	register unsigned long r1 asm("1") = (unsigned long) param;
	register unsigned long r2 asm("2") = (unsigned long) src;
	register unsigned long r3 asm("3") = (unsigned long) src_len;

	asm volatile(
		"0:	.insn	rre,%[opc] << 16,0,%[src]\n"
		"	brc	1,0b\n" /* handle partial completion */
		: [src] "+a" (r2), [len] "+d" (r3)
		: [fc] "d" (r0), [pba] "a" (r1), [opc] "i" (CPACF_KMAC)
		: "cc", "memory");

	return src_len - r3;
}

/**
 * cpacf_kmctr() - executes the KMCTR (CIPHER MESSAGE WITH COUNTER) instruction
 * @func: the function code passed to KMCTR; see CPACF_KMCTR_xxx defines
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 * @counter: address of counter value
 *
 * Returns 0 for the query func, number of processed bytes for
 * encryption/decryption funcs
 */
static inline int cpacf_kmctr(unsigned long func, void *param, u8 *dest,
			      const u8 *src, long src_len, u8 *counter)
{
	register unsigned long r0 asm("0") = (unsigned long) func;
	register unsigned long r1 asm("1") = (unsigned long) param;
	register unsigned long r2 asm("2") = (unsigned long) src;
	register unsigned long r3 asm("3") = (unsigned long) src_len;
	register unsigned long r4 asm("4") = (unsigned long) dest;
	register unsigned long r6 asm("6") = (unsigned long) counter;

	asm volatile(
		"0:	.insn	rrf,%[opc] << 16,%[dst],%[src],%[ctr],0\n"
		"	brc	1,0b\n" /* handle partial completion */
		: [src] "+a" (r2), [len] "+d" (r3),
		  [dst] "+a" (r4), [ctr] "+a" (r6)
		: [fc] "d" (r0), [pba] "a" (r1), [opc] "i" (CPACF_KMCTR)
		: "cc", "memory");

	return src_len - r3;
}

/**
 * cpacf_prno() - executes the PRNO (PERFORM RANDOM NUMBER OPERATION)
 *		  instruction
 * @func: the function code passed to PRNO; see CPACF_PRNO_xxx defines
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @dest_len: size of destination memory area in bytes
 * @seed: address of seed data
 * @seed_len: size of seed data in bytes
 */
static inline void cpacf_prno(unsigned long func, void *param,
			      u8 *dest, unsigned long dest_len,
			      const u8 *seed, unsigned long seed_len)
{
	register unsigned long r0 asm("0") = (unsigned long) func;
	register unsigned long r1 asm("1") = (unsigned long) param;
	register unsigned long r2 asm("2") = (unsigned long) dest;
	register unsigned long r3 asm("3") = (unsigned long) dest_len;
	register unsigned long r4 asm("4") = (unsigned long) seed;
	register unsigned long r5 asm("5") = (unsigned long) seed_len;

	asm volatile (
		"0:	.insn	rre,%[opc] << 16,%[dst],%[seed]\n"
		"	brc	1,0b\n"	  /* handle partial completion */
		: [dst] "+a" (r2), [dlen] "+d" (r3)
		: [fc] "d" (r0), [pba] "a" (r1),
		  [seed] "a" (r4), [slen] "d" (r5), [opc] "i" (CPACF_PRNO)
		: "cc", "memory");
}

/**
 * cpacf_trng() - executes the TRNG subfunction of the PRNO instruction
 * @ucbuf: buffer for unconditioned data
 * @ucbuf_len: amount of unconditioned data to fetch in bytes
 * @cbuf: buffer for conditioned data
 * @cbuf_len: amount of conditioned data to fetch in bytes
 */
static inline void cpacf_trng(u8 *ucbuf, unsigned long ucbuf_len,
			      u8 *cbuf, unsigned long cbuf_len)
{
	register unsigned long r0 asm("0") = (unsigned long) CPACF_PRNO_TRNG;
	register unsigned long r2 asm("2") = (unsigned long) ucbuf;
	register unsigned long r3 asm("3") = (unsigned long) ucbuf_len;
	register unsigned long r4 asm("4") = (unsigned long) cbuf;
	register unsigned long r5 asm("5") = (unsigned long) cbuf_len;

	asm volatile (
		"0:	.insn	rre,%[opc] << 16,%[ucbuf],%[cbuf]\n"
		"	brc	1,0b\n"	  /* handle partial completion */
		: [ucbuf] "+a" (r2), [ucbuflen] "+d" (r3),
		  [cbuf] "+a" (r4), [cbuflen] "+d" (r5)
		: [fc] "d" (r0), [opc] "i" (CPACF_PRNO)
		: "cc", "memory");
}

/**
 * cpacf_pcc() - executes the PCC (PERFORM CRYPTOGRAPHIC COMPUTATION)
 *		 instruction
 * @func: the function code passed to PCC; see CPACF_KM_xxx defines
 * @param: address of parameter block; see POP for details on each func
 */
static inline void cpacf_pcc(unsigned long func, void *param)
{
	register unsigned long r0 asm("0") = (unsigned long) func;
	register unsigned long r1 asm("1") = (unsigned long) param;

	asm volatile(
		"0:	.insn	rre,%[opc] << 16,0,0\n" /* PCC opcode */
		"	brc	1,0b\n" /* handle partial completion */
		:
		: [fc] "d" (r0), [pba] "a" (r1), [opc] "i" (CPACF_PCC)
		: "cc", "memory");
}

/**
 * cpacf_pckmo() - executes the PCKMO (PERFORM CRYPTOGRAPHIC KEY
 *		  MANAGEMENT) instruction
 * @func: the function code passed to PCKMO; see CPACF_PCKMO_xxx defines
 * @param: address of parameter block; see POP for details on each func
 *
 * Returns 0.
 */
static inline void cpacf_pckmo(long func, void *param)
{
	register unsigned long r0 asm("0") = (unsigned long) func;
	register unsigned long r1 asm("1") = (unsigned long) param;

	asm volatile(
		"       .insn   rre,%[opc] << 16,0,0\n" /* PCKMO opcode */
		:
		: [fc] "d" (r0), [pba] "a" (r1), [opc] "i" (CPACF_PCKMO)
		: "cc", "memory");
}

#endif	/* _ASMS390X_CPACF_H_ */
