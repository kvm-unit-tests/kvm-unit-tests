/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * OPAL call helpers
 */
#include <asm/opal.h>
#include <libcflat.h>
#include <libfdt/libfdt.h>
#include <devicetree.h>
#include <asm/io.h>
#include "../powerpc/io.h"

struct opal {
	uint64_t base;
	uint64_t entry;
} opal;

extern int64_t opal_call(int64_t token, int64_t arg1, int64_t arg2, int64_t arg3);

int opal_init(void)
{
	const struct fdt_property *prop;
	int node, len;

	node = fdt_path_offset(dt_fdt(), "/ibm,opal");
	if (node < 0)
		return -1;

	prop = fdt_get_property(dt_fdt(), node, "opal-base-address", &len);
	if (!prop)
		return -1;
	opal.base = fdt64_to_cpu(*(uint64_t *)prop->data);

	prop = fdt_get_property(dt_fdt(), node, "opal-entry-address", &len);
	if (!prop)
		return -1;
	opal.entry = fdt64_to_cpu(*(uint64_t *)prop->data);

#if  __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	if (opal_call(OPAL_REINIT_CPUS, OPAL_REINIT_CPUS_HILE_LE, 0, 0) != OPAL_SUCCESS)
		return -1;
#endif

	return 0;
}

extern void opal_power_off(void)
{
	opal_call(OPAL_CEC_POWER_DOWN, 0, 0, 0);
	while (true)
		opal_call(OPAL_POLL_EVENTS, 0, 0, 0);
}

void opal_putchar(int c)
{
	unsigned long vty = 0;		/* 0 == default */
	unsigned long nr_chars = cpu_to_be64(1);
	char ch = c;

	opal_call(OPAL_CONSOLE_WRITE, (int64_t)vty, (int64_t)&nr_chars, (int64_t)&ch);
}

int __opal_getchar(void)
{
	unsigned long vty = 0;		/* 0 == default */
	unsigned long nr_chars = cpu_to_be64(1);
	char ch;
	int rc;

	rc = opal_call(OPAL_CONSOLE_READ, (int64_t)vty, (int64_t)&nr_chars, (int64_t)&ch);
	if (rc != OPAL_SUCCESS)
		return -1;
	if (nr_chars == 0)
		return -1;

	return ch;
}
