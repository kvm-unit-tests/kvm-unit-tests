/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_STACK_H_
#define _ASMRISCV_STACK_H_

#ifndef _STACK_H_
#error Do not directly include <asm/stack.h>. Just use <stack.h>.
#endif

#define HAVE_ARCH_BACKTRACE_FRAME
#define HAVE_ARCH_BACKTRACE
#ifdef CONFIG_RELOC
#define HAVE_ARCH_BASE_ADDRESS
#endif

#endif
