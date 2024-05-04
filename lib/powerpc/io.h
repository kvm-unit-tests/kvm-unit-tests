/*
 * Prototypes for io.c
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 */

#ifndef _POWERPC_IO_H_
#define _POWERPC_IO_H_

extern void io_init(void);
extern int opal_init(void);
extern void opal_power_off(void);
extern void putchar(int c);
extern void opal_putchar(int c);
extern void papr_putchar(int c);
extern int __opal_getchar(void);
extern int __papr_getchar(void);

#endif
