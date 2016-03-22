#ifndef _X86ASM_STACK_H_
#define _X86ASM_STACK_H_

#ifndef _STACK_H_
#error Do not directly include <asm/stack.h>. Just use <stack.h>.
#endif

#define HAVE_ARCH_BACKTRACE_FRAME
int backtrace_frame(const void *frame, const void **return_addrs, int max_depth);

#define HAVE_ARCH_BACKTRACE
int backtrace(const void **return_addrs, int max_depth);

#endif
