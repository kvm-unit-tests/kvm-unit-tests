/*
 * Each architecture must implement puts() and exit().
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <asm/spinlock.h>

extern void halt(int code);
extern void putchar(int c);

static struct spinlock print_lock;

void io_init(void)
{
}

void puts(const char *s)
{
	spin_lock(&print_lock);
	while (*s)
		putchar(*s++);
	spin_unlock(&print_lock);
}

void exit(int code)
{
	halt(code);
}
