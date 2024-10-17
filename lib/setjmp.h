/*
 * setjmp/longjmp prototypes
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#ifndef _LIBCFLAT_SETJMP_H_
#define _LIBCFLAT_SETJMP_H_

typedef struct jmp_buf_tag {
#if defined(__i386__) || defined(__x86_64__)
	long int regs[8];
#elif defined(__riscv)
	long int regs[16];
#endif
} jmp_buf[1];

extern int setjmp (struct jmp_buf_tag env[1]);
extern void longjmp (struct jmp_buf_tag env[1], int val)
     __attribute__ ((__noreturn__));

#endif /* setjmp.h  */
