// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2024, James Raphael Tiovalen <jamestiotio@gmail.com>
 */
#include <libcflat.h>
#include <devicetree.h>
#include <limits.h>
#include <asm/csr.h>
#include <asm/delay.h>
#include <asm/isa.h>
#include <asm/sbi.h>
#include <asm/setup.h>
#include <asm/smp.h>
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

void timer_start(unsigned long duration_us)
{
	uint64_t next = timer_get_cycles() + usec_to_cycles((uint64_t)duration_us);

	if (cpu_has_extension(smp_processor_id(), ISA_SSTC)) {
		csr_write(CSR_STIMECMP, (unsigned long)next);
		if (__riscv_xlen == 32)
			csr_write(CSR_STIMECMPH, (unsigned long)(next >> 32));
	} else if (sbi_probe(SBI_EXT_TIME)) {
		struct sbiret ret = sbi_set_timer(next);
		assert(ret.error == SBI_SUCCESS);
		assert(!(next >> 32));
	} else {
		assert_msg(false, "No timer to start!");
	}
}

void timer_stop(void)
{
	if (cpu_has_extension(smp_processor_id(), ISA_SSTC)) {
		/*
		 * Subtract one from ULONG_MAX to workaround QEMU using that
		 * exact number to decide *not* to update the timer. IOW, if
		 * we used ULONG_MAX, then we wouldn't stop the timer at all,
		 * but one less is still a big number ("infinity") and it gets
		 * QEMU to do what we want.
		 */
		csr_write(CSR_STIMECMP, ULONG_MAX - 1);
		if (__riscv_xlen == 32)
			csr_write(CSR_STIMECMPH, ULONG_MAX - 1);
	} else if (sbi_probe(SBI_EXT_TIME)) {
		struct sbiret ret = sbi_set_timer(ULONG_MAX);
		assert(ret.error == SBI_SUCCESS);
	} else {
		assert_msg(false, "No timer to stop!");
	}
}
