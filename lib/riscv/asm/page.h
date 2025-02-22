/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_PAGE_H_
#define _ASMRISCV_PAGE_H_

#ifndef __ASSEMBLER__

typedef unsigned long pgd_t;
typedef unsigned long pte_t;
typedef unsigned long pgprot_t;
typedef unsigned long pteval_t;

#define pte_val(x)		((pteval_t)(x))
#define pgprot_val(x)		((pteval_t)(x))
#define __pte(x)		((pte_t)(x))
#define __pgprot(x)		((pgprot_t)(x))

#endif /* !__ASSEMBLER__ */

#include <asm-generic/page.h>

#endif /* _ASMRISCV_PAGE_H_ */
