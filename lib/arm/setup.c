/*
 * Initialize machine setup information and I/O.
 *
 * After running setup() unit tests may query how many cpus they have
 * (nr_cpus), how much memory they have (PHYS_END - PHYS_OFFSET), may
 * use dynamic memory allocation (malloc, etc.), printf, and exit.
 * Finally, argc and argv are also ready to be passed to main().
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <libcflat.h>
#include <libfdt/libfdt.h>
#include <devicetree.h>
#include <memregions.h>
#include <alloc.h>
#include <alloc_phys.h>
#include <alloc_page.h>
#include <vmalloc.h>
#include <auxinfo.h>
#include <argv.h>
#include <asm/thread_info.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/smp.h>
#include <asm/timer.h>
#include <asm/psci.h>

#include "io.h"

#define MAX_DT_MEM_REGIONS	16
#define NR_EXTRA_MEM_REGIONS	128
#define NR_MEM_REGIONS		(MAX_DT_MEM_REGIONS + NR_EXTRA_MEM_REGIONS)

extern unsigned long _text, _etext, _data, _edata;
extern unsigned long stacktop;

char *initrd;
u32 initrd_size;

u64 cpus[NR_CPUS] = { [0 ... NR_CPUS-1] = (u64)~0 };
int nr_cpus;

static struct mem_region arm_mem_regions[NR_MEM_REGIONS + 1];
phys_addr_t __phys_offset = (phys_addr_t)-1, __phys_end = 0;

extern void exceptions_init(void);
extern void asm_mmu_disable(void);

int mpidr_to_cpu(uint64_t mpidr)
{
	int i;

	for (i = 0; i < nr_cpus; ++i)
		if (cpus[i] == (mpidr & MPIDR_HWID_BITMASK))
			return i;
	return -1;
}

static void cpu_set_fdt(int fdtnode __unused, u64 regval, void *info __unused)
{
	int cpu = nr_cpus++;

	assert_msg(cpu < NR_CPUS, "Number cpus exceeds maximum supported (%d).", NR_CPUS);

	cpus[cpu] = regval;
	set_cpu_present(cpu, true);
}

#ifdef CONFIG_EFI

#include <acpi.h>

static int cpu_set_acpi(struct acpi_subtable_header *header)
{
	int cpu = nr_cpus++;
	struct acpi_madt_generic_interrupt *gicc = (void *)header;

	assert_msg(cpu < NR_CPUS, "Number cpus exceeds maximum supported (%d).", NR_CPUS);

	cpus[cpu] = gicc->arm_mpidr;
	set_cpu_present(cpu, true);

	return 0;
}

static void cpu_init_acpi(void)
{
	acpi_table_parse_madt(ACPI_MADT_TYPE_GENERIC_INTERRUPT, cpu_set_acpi);
}

#else

static void cpu_init_acpi(void)
{
	assert_msg(false, "ACPI not available");
}

#endif

static void cpu_init(void)
{
	int ret;

	nr_cpus = 0;
	if (dt_available()) {
		ret = dt_for_each_cpu_node(cpu_set_fdt, NULL);
		assert(ret == 0);
	} else {
		cpu_init_acpi();
	}

	set_cpu_online(0, true);
}

static void arm_memregions_add_assumed(void)
{
	struct mem_region *code, *data;

	/* Split the region with the code into two regions; code and data */
	memregions_split((unsigned long)&_etext, &code, &data);
	assert(code);
	code->flags |= MR_F_CODE;

	/*
	 * mach-virt I/O regions:
	 *   - The first 1G (arm/arm64)
	 *   - 512M at 256G (arm64, arm uses highmem=off)
	 *   - 512G at 512G (arm64, arm uses highmem=off)
	 */
	memregions_add(&(struct mem_region){ 0, (1ul << 30), MR_F_IO });
#ifdef __aarch64__
	memregions_add(&(struct mem_region){ (1ul << 38), (1ul << 38) | (1ul << 29), MR_F_IO });
	memregions_add(&(struct mem_region){ (1ul << 39), (1ul << 40), MR_F_IO });
#endif
}

static void mem_allocator_init(phys_addr_t freemem_start, phys_addr_t freemem_end)
{
	phys_addr_t base, top;

	freemem_start = PAGE_ALIGN(freemem_start);
	freemem_end &= PAGE_MASK;

	phys_alloc_init(freemem_start, freemem_end - freemem_start);
	phys_alloc_set_minimum_alignment(SMP_CACHE_BYTES);

	phys_alloc_get_unused(&base, &top);
	base = PAGE_ALIGN(base);
	top &= PAGE_MASK;
	assert(sizeof(long) == 8 || !(base >> 32));
	if (sizeof(long) != 8 && (top >> 32) != 0)
		top = ((uint64_t)1 << 32);
	page_alloc_init_area(0, base >> PAGE_SHIFT, top >> PAGE_SHIFT);
	page_alloc_ops_enable();
}

static void mem_init(phys_addr_t freemem_start)
{
	struct mem_region *freemem, *r, mem = {
		.start = (phys_addr_t)-1,
	};

	freemem = memregions_find(freemem_start);
	assert(freemem && !(freemem->flags & (MR_F_IO | MR_F_CODE)));

	for (r = mem_regions; r->end; ++r) {
		if (!(r->flags & MR_F_IO)) {
			if (r->start < mem.start)
				mem.start = r->start;
			if (r->end > mem.end)
				mem.end = r->end;
		}
	}
	assert(mem.end && !(mem.start & ~PHYS_MASK));
	mem.end &= PHYS_MASK;

	/* Check for holes */
	r = memregions_find(mem.start);
	while (r && r->end != mem.end)
		r = memregions_find(r->end);
	assert(r);

	/* Ensure our selected freemem range is somewhere in our full range */
	assert(freemem_start >= mem.start && freemem->end <= mem.end);

	__phys_offset = mem.start;	/* PHYS_OFFSET */
	__phys_end = mem.end;		/* PHYS_END */

	mem_allocator_init(freemem_start, freemem->end);
}

static void freemem_push_fdt(void **freemem, const void *fdt)
{
	u32 fdt_size;
	int ret;

#ifndef CONFIG_EFI
	/*
	 * Ensure that the FDT was not overlapping with the uninitialised
	 * data that was overwritten.
	 */
	assert((unsigned long)fdt > (unsigned long)&stacktop);
#endif

	fdt_size = fdt_totalsize(fdt);
	ret = fdt_move(fdt, *freemem, fdt_size);
	assert(ret == 0);
	ret = dt_init(*freemem);
	assert(ret == 0);
	*freemem += fdt_size;
}

static void freemem_push_dt_initrd(void **freemem)
{
	const char *tmp;
	int ret;

	ret = dt_get_initrd(&tmp, &initrd_size);
	assert(ret == 0 || ret == -FDT_ERR_NOTFOUND);
	if (ret == 0) {
		initrd = *freemem;
		memmove(initrd, tmp, initrd_size);
		*freemem += initrd_size;
	}
}

static void initrd_setup(void)
{
	char *env;

	if (!initrd)
		return;

	/* environ is currently the only file in the initrd */
	env = malloc(initrd_size);
	memcpy(env, initrd, initrd_size);
	setup_env(env, initrd_size);
}

void setup(const void *fdt, phys_addr_t freemem_start)
{
	void *freemem;
	const char *bootargs;
	int ret;

	assert(sizeof(long) == 8 || freemem_start < (3ul << 30));
	freemem = (void *)(unsigned long)freemem_start;

	freemem_push_fdt(&freemem, fdt);
	freemem_push_dt_initrd(&freemem);

	memregions_init(arm_mem_regions, NR_MEM_REGIONS);
	memregions_add_dt_regions(MAX_DT_MEM_REGIONS);
	arm_memregions_add_assumed();
	mem_init(PAGE_ALIGN((unsigned long)freemem));

	psci_set_conduit();
	cpu_init();

	/* cpu_init must be called before thread_info_init */
	thread_info_init(current_thread_info(), 0);

	/* mem_init must be called before io_init */
	io_init();

	timer_save_state();

	ret = dt_get_bootargs(&bootargs);
	assert(ret == 0 || ret == -FDT_ERR_NOTFOUND);
	setup_args_progname(bootargs);

	initrd_setup();

	if (!(auxinfo.flags & AUXINFO_MMU_OFF))
		setup_vm();
}

#ifdef CONFIG_EFI

#include <efi.h>

static efi_status_t setup_rsdp(efi_bootinfo_t *efi_bootinfo)
{
	efi_status_t status;
	struct acpi_table_rsdp *rsdp;

	/*
	 * RSDP resides in an EFI_ACPI_RECLAIM_MEMORY region, which is not used
	 * by kvm-unit-tests arm64 memory allocator. So it is not necessary to
	 * copy the data structure to another memory region to prevent
	 * unintentional overwrite.
	 */
	status = efi_get_system_config_table(ACPI_20_TABLE_GUID, (void **)&rsdp);
	if (status != EFI_SUCCESS)
		return status;

	set_efi_rsdp(rsdp);

	return EFI_SUCCESS;
}

static efi_status_t efi_mem_init(efi_bootinfo_t *efi_bootinfo)
{
	struct mem_region *freemem_mr = NULL, *code, *data;
	phys_addr_t freemem_start;
	void *freemem;

	memregions_efi_init(&efi_bootinfo->mem_map, &freemem_mr);
	if (!freemem_mr)
		return EFI_OUT_OF_RESOURCES;

	memregions_split((unsigned long)&_etext, &code, &data);
	assert(code && (code->flags & MR_F_CODE));
	if (data)
		data->flags &= ~MR_F_CODE;

	for (struct mem_region *m = mem_regions; m->end; ++m) {
		if (m != code)
			assert(!(m->flags & MR_F_CODE));

		if (!(m->flags & MR_F_IO)) {
			if (m->start < __phys_offset)
				__phys_offset = m->start;
			if (m->end > __phys_end)
				__phys_end = m->end;
		}
	}
	__phys_end &= PHYS_MASK;

	freemem = (void *)PAGE_ALIGN(freemem_mr->start);

	if (efi_bootinfo->fdt)
		freemem_push_fdt(&freemem, efi_bootinfo->fdt);

	freemem_start = PAGE_ALIGN((unsigned long)freemem);
	assert(sizeof(long) == 8 || freemem_start < (3ul << 30));

	asm_mmu_disable();

	mem_allocator_init(freemem_start, freemem_mr->end);

	return EFI_SUCCESS;
}

efi_status_t setup_efi(efi_bootinfo_t *efi_bootinfo)
{
	efi_status_t status;

	exceptions_init();

	memregions_init(arm_mem_regions, NR_MEM_REGIONS);

	status = efi_mem_init(efi_bootinfo);
	if (status != EFI_SUCCESS) {
		printf("Failed to initialize memory: ");
		switch (status) {
		case EFI_OUT_OF_RESOURCES:
			printf("No free memory region\n");
			break;
		default:
			printf("Unknown error\n");
			break;
		}
		return status;
	}

	if (!dt_available()) {
		status = setup_rsdp(efi_bootinfo);
		if (status != EFI_SUCCESS) {
			printf("Cannot find RSDP in EFI system table\n");
			return status;
		}
	}

	psci_set_conduit();
	cpu_init();
	/* cpu_init must be called before thread_info_init */
	thread_info_init(current_thread_info(), 0);
	/* mem_init must be called before io_init */
	io_init();

	timer_save_state();

	initrd_setup();

	if (!(auxinfo.flags & AUXINFO_MMU_OFF))
		setup_vm();

	return EFI_SUCCESS;
}

#endif
