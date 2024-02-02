// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <bitops.h>
#include <devicetree.h>
#include <string.h>
#include <asm/isa.h>
#include <asm/setup.h>

typedef void (*isa_func_t)(const char *, int, void *);

struct isa_info {
	unsigned long hartid;
	isa_func_t func;
	void *data;
};

static bool isa_match(const char *ext, const char *name, int len)
{
	return len == strlen(ext) && !strncasecmp(name, ext, len);
}

struct isa_check {
	const char *ext;
	bool found;
};

static void isa_name(const char *name, int len, void *data)
{
	struct isa_check *check = (struct isa_check *)data;

	if (isa_match(check->ext, name, len))
		check->found = true;
}

static void isa_bit(const char *name, int len, void *data)
{
	struct thread_info *info = (struct thread_info *)data;

	if (isa_match("sstc", name, len))
		set_bit(ISA_SSTC, info->isa);
}

static void isa_parse(const char *isa_string, int len, struct isa_info *info)
{
	assert(isa_string[0] == 'r' && isa_string[1] == 'v');
#if __riscv_xlen == 32
	assert(isa_string[2] == '3' && isa_string[3] == '2');
#else
	assert(isa_string[2] == '6' && isa_string[3] == '4');
#endif

	for (int i = 4; i < len; ++i) {
		if (isa_string[i] == '_') {
			const char *multi = &isa_string[++i];
			int start = i;

			while (i < len - 1 && isa_string[i] != '_')
				++i;
			info->func(multi, i - start, info->data);
			if (i < len - 1)
				--i;
		} else {
			info->func(&isa_string[i], 1, info->data);
		}
	}
}

static void isa_parse_fdt(int cpu_node, u64 hartid, void *data)
{
	struct isa_info *info = (struct isa_info *)data;
	const struct fdt_property *prop;
	int len;

	if (hartid != info->hartid)
		return;

	prop = fdt_get_property(dt_fdt(), cpu_node, "riscv,isa", &len);
	assert(prop);

	isa_parse(prop->data, len, info);
}

static void isa_init_acpi(void)
{
	assert_msg(false, "ACPI not available");
}

void isa_init(struct thread_info *ti)
{
	struct isa_info info = {
		.hartid = ti->hartid,
		.func = isa_bit,
		.data = ti,
	};
	int ret;

	if (dt_available()) {
		ret = dt_for_each_cpu_node(isa_parse_fdt, &info);
		assert(ret == 0);
	} else {
		isa_init_acpi();
	}
}

bool cpu_has_extension_name(int cpu, const char *ext)
{
	struct isa_info info = {
		.hartid = cpus[cpu].hartid,
		.func = isa_name,
		.data = &(struct isa_check){ .ext = ext, },
	};
	struct isa_check *check = info.data;
	int ret;

	if (dt_available()) {
		ret = dt_for_each_cpu_node(isa_parse_fdt, &info);
		assert(ret == 0);
	} else {
		assert_msg(false, "ACPI not available");
	}

	return check->found;
}
