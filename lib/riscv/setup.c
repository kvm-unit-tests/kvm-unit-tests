// SPDX-License-Identifier: GPL-2.0-only
/*
 * Initialize machine setup information and I/O.
 *
 * Copyright (C) 2023, Ventana Micro Systems Inc., Andrew Jones <ajones@ventanamicro.com>
 */
#include <libcflat.h>
#include <alloc.h>
#include <alloc_page.h>
#include <alloc_phys.h>
#include <argv.h>
#include <auxinfo.h>
#include <cpumask.h>
#include <devicetree.h>
#include <memregions.h>
#include <on-cpus.h>
#include <vmalloc.h>
#include <asm/csr.h>
#include <asm/mmu.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/sbi.h>
#include <asm/setup.h>
#include <asm/timer.h>

#define VA_BASE			((phys_addr_t)3 * SZ_1G)
#if __riscv_xlen == 64
#define VA_TOP			((phys_addr_t)4 * SZ_1G)
#else
#define VA_TOP			((phys_addr_t)0)
#endif

#define MAX_DT_MEM_REGIONS	16
#ifdef CONFIG_EFI
#define NR_MEM_REGIONS		(MAX_DT_MEM_REGIONS + 128)
#else
#define NR_MEM_REGIONS		(MAX_DT_MEM_REGIONS + 16)
#endif

extern unsigned long _etext;

char *initrd;
u32 initrd_size;

struct thread_info cpus[NR_CPUS];
int nr_cpus;
uint64_t timebase_frequency;

static struct mem_region riscv_mem_regions[NR_MEM_REGIONS + 1];

static void cpu_set_fdt(int fdtnode __unused, u64 regval, void *info __unused)
{
	int cpu = nr_cpus++;

	assert_msg(cpu < NR_CPUS, "Number cpus exceeds maximum supported (%d).", NR_CPUS);

	cpus[cpu].cpu = cpu;
	cpus[cpu].hartid = regval;

	if (!sbi_hart_get_status(cpus[cpu].hartid).error)
		set_cpu_present(cpu, true);
}

static void cpu_init_acpi(void)
{
	assert_msg(false, "ACPI not available");
}

static void cpu_init(void)
{
	int ret, me;

	nr_cpus = 0;
	if (dt_available()) {
		ret = dt_for_each_cpu_node(cpu_set_fdt, NULL);
		assert(ret == 0);
	} else {
		cpu_init_acpi();
	}

	me = hartid_to_cpu(csr_read(CSR_SSCRATCH));
	assert(cpu_present(me));
	set_cpu_online(me, true);
	cpu0_calls_idle = true;
}

static void mem_allocator_init(struct mem_region *freemem, phys_addr_t freemem_start)
{
	phys_addr_t freemem_end = freemem->end;
	phys_addr_t base, top;

	freemem_start = PAGE_ALIGN(freemem_start);
	freemem_end &= PHYS_PAGE_MASK;

	/*
	 * The assert below is mostly checking that the free memory doesn't
	 * start in the 3G-4G range, which is reserved for virtual addresses,
	 * but it also confirms that there is some free memory (the amount
	 * is arbitrarily selected, but should be sufficient for a unit test)
	 *
	 * TODO: Allow the VA range to shrink and move.
	 */
	if (freemem_end > VA_BASE) {
		struct mem_region *curr, *rest;
		freemem_end = VA_BASE;
		memregions_split(VA_BASE, &curr, &rest);
		assert(curr == freemem);
		if (rest)
			rest->flags = MR_F_UNUSED;
	}
	assert(freemem_end - freemem_start >= SZ_1M * 16);

	init_alloc_vpage(__va(VA_TOP));

	/*
	 * TODO: Remove the need for this phys allocator dance, since, as we
	 * can see with the assert, we could have gone straight to the page
	 * allocator.
	 */
	phys_alloc_init(freemem_start, freemem_end - freemem_start);
	phys_alloc_set_minimum_alignment(PAGE_SIZE);
	phys_alloc_get_unused(&base, &top);
	assert(base == freemem_start && top == freemem_end);

	page_alloc_init_area(0, freemem_start >> PAGE_SHIFT, freemem_end >> PAGE_SHIFT);
	page_alloc_ops_enable();
}

static void mem_init(phys_addr_t freemem_start)
{
	struct mem_region *freemem, *code, *data;

	memregions_init(riscv_mem_regions, NR_MEM_REGIONS);
	memregions_add_dt_regions(MAX_DT_MEM_REGIONS);

	/* Split the region with the code into two regions; code and data */
	memregions_split((unsigned long)&_etext, &code, &data);
	assert(code);
	code->flags |= MR_F_CODE;

	freemem = memregions_find(freemem_start);
	assert(freemem && !(freemem->flags & (MR_F_IO | MR_F_CODE)));

	mem_allocator_init(freemem, freemem_start);
}

static void freemem_push_fdt(void **freemem, const void *fdt)
{
	u32 fdt_size;
	int ret;

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

static void banner(void)
{
	puts("\n");
	puts("##########################################################################\n");
	puts("#    kvm-unit-tests\n");
	puts("##########################################################################\n");
	puts("\n");
}

void setup(const void *fdt, phys_addr_t freemem_start)
{
	void *freemem;
	const char *bootargs;
	int ret;

	assert(freemem_start < VA_BASE);
	freemem = __va(freemem_start);

	freemem_push_fdt(&freemem, fdt);
	freemem_push_dt_initrd(&freemem);

	mem_init(PAGE_ALIGN(__pa(freemem)));
	cpu_init();
	timer_get_frequency();
	thread_info_init();
	local_hart_init();
	io_init();

	ret = dt_get_bootargs(&bootargs);
	assert(ret == 0 || ret == -FDT_ERR_NOTFOUND);
	setup_args_progname(bootargs);

	initrd_setup();

	if (!(auxinfo.flags & AUXINFO_MMU_OFF))
		setup_vm();

	banner();
}

#ifdef CONFIG_EFI
#include <efi.h>

extern unsigned long exception_vectors;
extern unsigned long boot_hartid;

static efi_status_t efi_mem_init(efi_bootinfo_t *efi_bootinfo)
{
	struct mem_region *freemem_mr = NULL, *code, *data;
	void *freemem;

	memregions_init(riscv_mem_regions, NR_MEM_REGIONS);

	memregions_efi_init(&efi_bootinfo->mem_map, &freemem_mr);
	if (!freemem_mr)
		return EFI_OUT_OF_RESOURCES;

	memregions_split((unsigned long)&_etext, &code, &data);
	assert(code && (code->flags & MR_F_CODE));
	if (data)
		data->flags &= ~MR_F_CODE;

	for (struct mem_region *m = mem_regions; m->end; ++m)
		assert(m == code || !(m->flags & MR_F_CODE));

	freemem = (void *)PAGE_ALIGN(freemem_mr->start);

	if (efi_bootinfo->fdt)
		freemem_push_fdt(&freemem, efi_bootinfo->fdt);

	mmu_disable();
	mem_allocator_init(freemem_mr, (unsigned long)freemem);

	return EFI_SUCCESS;
}

efi_status_t setup_efi(efi_bootinfo_t *efi_bootinfo)
{
	efi_status_t status;

	csr_write(CSR_STVEC, (unsigned long)&exception_vectors);
	csr_write(CSR_SSCRATCH, boot_hartid);

	status = efi_mem_init(efi_bootinfo);
	if (status != EFI_SUCCESS) {
		printf("Failed to initialize memory\n");
		return status;
	}

	cpu_init();
	timer_get_frequency();
	thread_info_init();
	local_hart_init();
	io_init();
	initrd_setup();

	if (!(auxinfo.flags & AUXINFO_MMU_OFF))
		setup_vm();

	banner();

	return EFI_SUCCESS;
}
#endif /* CONFIG_EFI */
