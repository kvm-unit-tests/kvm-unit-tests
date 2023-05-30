/* SPDX-License-Identifier: LGPL-2.0-or-later */
/*
 * Relevant definitions from uapi/linux/elf.h and asm/elf.h
 */

#ifndef _ELF_H_
#define _ELF_H_

#include <libcflat.h>

/* 64-bit ELF base types. */
typedef u64	Elf64_Addr;
typedef u64	Elf64_Xword;
typedef s64	Elf64_Sxword;

typedef struct {
	Elf64_Sxword d_tag;             /* entry tag value */
	union {
		Elf64_Xword d_val;
		Elf64_Addr d_ptr;
	} d_un;
} Elf64_Dyn;

typedef struct elf64_rel {
	Elf64_Addr r_offset;    /* Location at which to apply the action */
	Elf64_Xword r_info;     /* index and type of relocation */
} Elf64_Rel;

typedef struct elf64_rela {
	Elf64_Addr r_offset;    /* Location at which to apply the action */
	Elf64_Xword r_info;     /* index and type of relocation */
	Elf64_Sxword r_addend;  /* Constant addend used to compute value */
} Elf64_Rela;

/* This is the info that is needed to parse the dynamic section of the file */
#define DT_NULL		0
#define DT_RELA		7
#define DT_RELASZ	8
#define DT_RELAENT	9

/* x86 relocation types. */
#define R_X86_64_NONE		0       /* No reloc */
#define R_X86_64_RELATIVE	8       /* Adjust by program base */


/*
 * AArch64 static relocation types.
 */

/* Miscellaneous. */
#define R_AARCH64_NONE		256
#define R_AARCH64_RELATIVE	1027

/* The following are used with relocations */
#define ELF64_R_TYPE(i)		((i) & 0xffffffff)

#endif /* _ELF_H_ */
