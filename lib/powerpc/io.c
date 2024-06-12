/*
 * Each architecture must implement puts() and exit().
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <asm/spinlock.h>
#include <asm/rtas.h>
#include <asm/setup.h>
#include <asm/processor.h>
#include <asm/atomic.h>
#include <asm/smp.h>
#include "io.h"

static struct spinlock print_lock;

void putchar(int c)
{
	if (machine_is_powernv())
		opal_putchar(c);
	else
		papr_putchar(c);
}

int __getchar(void)
{
	if (machine_is_powernv())
		return __opal_getchar();
	else
		return __papr_getchar();
}

void io_init(void)
{
	if (machine_is_powernv())
		assert(!opal_init());
	else
		rtas_init();
}

void puts(const char *s)
{
	bool user = in_usermode();

	if (user)
		exit_usermode();
	spin_lock(&print_lock);
	while (*s)
		putchar(*s++);
	spin_unlock(&print_lock);
	if (user)
		enter_usermode();
}

/*
 * Defining halt to take 'code' as an argument guarantees that it will
 * be in r3 when we halt. That gives us a final chance to see the exit
 * status while inspecting the halted unit test state.
 */
extern void halt(int code);

void exit(int code)
{
	static int exited = 0;

// FIXME: change this print-exit/rtas-poweroff to chr_testdev_exit(),
//        maybe by plugging chr-testdev into a spapr-vty.
	if (atomic_fetch_inc(&exited) == 0) {
		printf("\nEXIT: STATUS=%d\n", ((code) << 1) | 1);
		if (machine_is_powernv())
			opal_power_off();
		else
			rtas_power_off();
	}
	halt(code);
	__builtin_unreachable();
}
