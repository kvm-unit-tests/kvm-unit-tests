// SPDX-License-Identifier: GPL-2.0-only
/*
 * Each architecture must implement puts() and exit() with the I/O
 * devices exposed from QEMU, e.g. ns16550a.
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <config.h>
#include <asm/io.h>
#include <asm/spinlock.h>

/*
 * Use this guess for the uart base in order to make an attempt at
 * having earlier printf support. We'll overwrite it with the real
 * base address that we read from the device tree later. This is
 * the address we expect the virtual machine manager to put in
 * its generated device tree.
 */
#define UART_EARLY_BASE ((u8 *)(unsigned long)CONFIG_UART_EARLY_BASE)
static volatile u8 *uart0_base = UART_EARLY_BASE;
static struct spinlock uart_lock;

void puts(const char *s)
{
	spin_lock(&uart_lock);
	while (*s)
		writeb(*s++, uart0_base);
	spin_unlock(&uart_lock);
}

/*
 * Defining halt to take 'code' as an argument guarantees that it will
 * be in a0 when we halt. That gives us a final chance to see the exit
 * status while inspecting the halted unit test state.
 */
void halt(int code);

void exit(int code)
{
	printf("\nEXIT: STATUS=%d\n", ((code) << 1) | 1);
	halt(code);
	__builtin_unreachable();
}
