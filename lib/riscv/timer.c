// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024, James Raphael Tiovalen <jamestiotio@gmail.com>
 */
#include <libcflat.h>
#include <devicetree.h>
#include <asm/setup.h>
#include <asm/timer.h>

void timer_get_frequency(void)
{
	const struct fdt_property *prop;
	u32 *data;
	int cpus, len;

	assert_msg(dt_available(), "ACPI not yet supported");

	const void *fdt = dt_fdt();

	cpus = fdt_path_offset(fdt, "/cpus");
	assert(cpus >= 0);

	prop = fdt_get_property(fdt, cpus, "timebase-frequency", &len);
	assert(prop != NULL && len == 4);

	data = (u32 *)prop->data;
	timebase_frequency = fdt32_to_cpu(*data);
}
