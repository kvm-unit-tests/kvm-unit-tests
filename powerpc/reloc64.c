/*
 * relocate R_PPC_RELATIVE RELA entries. Normally this is done in
 * assembly code to avoid the risk of using absolute addresses before
 * they're relocated. We use C, but cautiously (no global references).
 *
 * Copyright (C) 2016, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#define DT_NULL		0
#define DT_RELA 	7
#define DT_RELACOUNT	0x6ffffff9
#define R_PPC_RELATIVE	22

struct elf64_dyn {
	signed long long tag;
	unsigned long long val;
};

#define RELA_GET_TYPE(rela_ptr) ((rela_ptr)->info & 0xffffffff)
struct elf64_rela {
	unsigned long long offset;
	unsigned long long info;
	signed long long addend;
};

void relocate(unsigned long load_addr, struct elf64_dyn *dyn_table)
{
	unsigned long long rela_addr = 0, rela_count = 0, *addr;
	struct elf64_dyn *d = dyn_table;
	struct elf64_rela *r;

	while (d && d->tag != DT_NULL) {
		if (d->tag == DT_RELA)
			rela_addr = d->val;
		else if (d->tag == DT_RELACOUNT)
			rela_count = d->val;
		if (rela_addr && rela_count)
			break;
		++d;
	}

	if (!rela_addr || !rela_count)
		return;

	r = (void *)(rela_addr + load_addr);

	while (rela_count--) {
		if (RELA_GET_TYPE(r) == R_PPC_RELATIVE) {
			addr = (void *)(r->offset + load_addr);
			*addr = r->addend + load_addr;
		}
		++r;
	}
}
