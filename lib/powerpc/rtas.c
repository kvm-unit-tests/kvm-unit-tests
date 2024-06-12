/*
 * powerpc RTAS
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <libfdt/libfdt.h>
#include <devicetree.h>
#include <asm/spinlock.h>
#include <asm/smp.h>
#include <asm/hcall.h>
#include <asm/io.h>
#include <asm/rtas.h>

extern void enter_rtas(unsigned long);

unsigned long rtas_entry;
static struct rtas_args rtas_args;
static struct spinlock rtas_lock;

static int rtas_node(void)
{
	int node = fdt_path_offset(dt_fdt(), "/rtas");

	if (node < 0) {
		printf("%s: /rtas: %s\n", __func__, fdt_strerror(node));
		abort();
	}

	return node;
}

void rtas_init(void)
{
	bool broken_sc1 = hcall_have_broken_sc1();
	int node = rtas_node(), len, words, i;
	const struct fdt_property *prop;
	u32 *data, *insns;

	if (!dt_available()) {
		printf("%s: No device tree!\n", __func__);
		abort();
	}

	prop = fdt_get_property(dt_fdt(), node,
				"linux,rtas-entry", &len);
	if (!prop) {
		/* We don't have a qemu provided RTAS blob, enter_rtas
		 * will use H_RTAS directly */
		return;
	}
	data = (u32 *)prop->data;
	rtas_entry = (unsigned long)fdt32_to_cpu(*data);
	insns = (u32 *)rtas_entry;

	prop = fdt_get_property(dt_fdt(), node, "rtas-size", &len);
	if (!prop) {
		printf("%s: /rtas/rtas-size: %s\n",
				__func__, fdt_strerror(len));
		abort();
	}
	data = (u32 *)prop->data;
	words = (int)fdt32_to_cpu(*data)/4;

	for (i = 0; i < words; ++i) {
		if (broken_sc1 && insns[i] == cpu_to_be32(SC1))
			insns[i] = cpu_to_be32(SC1_REPLACEMENT);
	}
}

int rtas_token(const char *service, uint32_t *token)
{
	const struct fdt_property *prop;
	u32 *data;

	if (!dt_available())
		return RTAS_UNKNOWN_SERVICE;

	prop = fdt_get_property(dt_fdt(), rtas_node(), service, NULL);
	if (!prop)
		return RTAS_UNKNOWN_SERVICE;

	data = (u32 *)prop->data;
	*token = fdt32_to_cpu(*data);

	return 0;
}

static void __rtas_call(struct rtas_args *args)
{
	enter_rtas(__pa(args));
}

static int rtas_call_unlocked_va(struct rtas_args *args,
			  int token, int nargs, int nret, int *outputs,
			  va_list list)
{
	int ret, i;

	args->token = cpu_to_be32(token);
	args->nargs = cpu_to_be32(nargs);
	args->nret = cpu_to_be32(nret);
	args->rets = &args->args[nargs];

	for (i = 0; i < nargs; ++i)
		args->args[i] = cpu_to_be32(va_arg(list, u32));

	for (i = 0; i < nret; ++i)
		args->rets[i] = 0;

	__rtas_call(args);

	if (nret > 1 && outputs != NULL)
		for (i = 0; i < nret - 1; ++i)
			outputs[i] = be32_to_cpu(args->rets[i + 1]);

	ret = nret > 0 ? be32_to_cpu(args->rets[0]) : 0;

	return ret;
}

int rtas_call_unlocked(struct rtas_args *args, int token, int nargs, int nret, int *outputs, ...)
{
	va_list list;
	int ret;

	va_start(list, outputs);
	ret = rtas_call_unlocked_va(args, token, nargs, nret, outputs, list);
	va_end(list);

	return ret;
}

int rtas_call(int token, int nargs, int nret, int *outputs, ...)
{
	va_list list;
	int ret;

	assert_msg(!in_usermode(), "May not make RTAS call from user mode\n");

	spin_lock(&rtas_lock);

	va_start(list, outputs);
	ret = rtas_call_unlocked_va(&rtas_args, token, nargs, nret, outputs, list);
	va_end(list);

	spin_unlock(&rtas_lock);

	return ret;
}

void rtas_stop_self(void)
{
	struct rtas_args args;
	uint32_t token;
	int ret;

	ret = rtas_token("stop-self", &token);
	if (ret) {
		puts("RTAS stop-self not available\n");
		return;
	}

	ret = rtas_call_unlocked(&args, token, 0, 1, NULL);
	printf("RTAS stop-self returned %d\n", ret);
}

void rtas_power_off(void)
{
	struct rtas_args args;
	uint32_t token;
	int ret;

	ret = rtas_token("power-off", &token);
	if (ret) {
		puts("RTAS power-off not available\n");
		return;
	}

	ret = rtas_call_unlocked(&args, token, 2, 1, NULL, -1, -1);
	printf("RTAS power-off returned %d\n", ret);
}
