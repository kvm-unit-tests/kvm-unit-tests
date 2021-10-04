/*
 * Initialize machine setup information
 *
 * Copyright (C) 2017, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 * Copyright (C) 2021, Google Inc, Zixuan Wang <zixuanwang@google.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include "libcflat.h"
#include "fwcfg.h"
#include "alloc_phys.h"
#include "argv.h"
#include "desc.h"
#include "apic.h"
#include "apic-defs.h"
#include "asm/setup.h"

extern char edata;

struct mbi_bootinfo {
	u32 flags;
	u32 mem_lower;
	u32 mem_upper;
	u32 boot_device;
	u32 cmdline;
	u32 mods_count;
	u32 mods_addr;
	u32 reserved[4];   /* 28-43 */
	u32 mmap_length;
	u32 mmap_addr;
	u32 reserved0[3];  /* 52-63 */
	u32 bootloader;
	u32 reserved1[5];  /* 68-87 */
	u32 size;
};

struct mbi_module {
	u32 start, end;
	u32 cmdline;
	u32 unused;
};

struct mbi_mem {
	u32 size;
	u64 base_addr;
	u64 length;
	u32 type;
} __attribute__((packed));

#define ENV_SIZE 16384

void setup_env(char *env, int size);
void setup_multiboot(struct mbi_bootinfo *bootinfo);
void setup_libcflat(void);

char *initrd;
u32 initrd_size;

static char env[ENV_SIZE];
static struct mbi_bootinfo *bootinfo;

#define HUGEPAGE_SIZE (1 << 21)

#ifdef __x86_64__
void find_highmem(void)
{
	/* Memory above 4 GB is only supported on 64-bit systems.  */
	if (!(bootinfo->flags & 64))
	    	return;

	u64 upper_end = bootinfo->mem_upper * 1024ull;
	u64 best_start = (uintptr_t) &edata;
	u64 best_end = upper_end;
	u64 max_end = fwcfg_get_u64(FW_CFG_MAX_RAM);
	if (max_end == 0)
		max_end = -1ull;
	bool found = false;

	uintptr_t mmap = bootinfo->mmap_addr;
	while (mmap < bootinfo->mmap_addr + bootinfo->mmap_length) {
		struct mbi_mem *mem = (void *)mmap;
		mmap += mem->size + 4;
		if (mem->type != 1)
			continue;
		if (mem->base_addr <= (uintptr_t) &edata ||
		    (mem->base_addr <= upper_end && mem->base_addr + mem->length <= upper_end))
			continue;
		if (mem->length < best_end - best_start)
			continue;
		if (mem->base_addr >= max_end)
			continue;
		best_start = mem->base_addr;
		best_end = mem->base_addr + mem->length;
		if (best_end > max_end)
			best_end = max_end;
		found = true;
	}

	if (found) {
		best_start = (best_start + HUGEPAGE_SIZE - 1) & -HUGEPAGE_SIZE;
		best_end = best_end & -HUGEPAGE_SIZE;
		phys_alloc_init(best_start, best_end - best_start);
	}
}

/* Setup TSS for the current processor, and return TSS offset within GDT */
unsigned long setup_tss(u8 *stacktop)
{
	u32 id;
	tss64_t *tss_entry;

	id = apic_id();

	/* Runtime address of current TSS */
	tss_entry = &tss[id];

	/* Update TSS */
	memset((void *)tss_entry, 0, sizeof(tss64_t));

	/* Update TSS descriptors; each descriptor takes up 2 entries */
	set_gdt_entry(TSS_MAIN + id * 16, (unsigned long)tss_entry, 0xffff, 0x89, 0);

	return TSS_MAIN + id * 16;
}
#else
/* Setup TSS for the current processor, and return TSS offset within GDT */
unsigned long setup_tss(u8 *stacktop)
{
	u32 id;
	tss32_t *tss_entry;

	id = apic_id();

	/* Runtime address of current TSS */
	tss_entry = &tss[id];

	/* Update TSS */
	memset((void *)tss_entry, 0, sizeof(tss32_t));
	tss_entry->ss0 = KERNEL_DS;

	/* Update descriptors for TSS and percpu data segment.  */
	set_gdt_entry(TSS_MAIN + id * 8,
		      (unsigned long)tss_entry, 0xffff, 0x89, 0);
	set_gdt_entry(TSS_MAIN + MAX_TEST_CPUS * 8 + id * 8,
		      (unsigned long)stacktop - 4096, 0xfffff, 0x93, 0xc0);

	return TSS_MAIN + id * 8;
}
#endif

void setup_multiboot(struct mbi_bootinfo *bi)
{
	struct mbi_module *mods;

	bootinfo = bi;

	u64 best_start = (uintptr_t) &edata;
	u64 best_end = bootinfo->mem_upper * 1024ull;
	phys_alloc_init(best_start, best_end - best_start);

	if (bootinfo->mods_count != 1)
		return;

	mods = (struct mbi_module *)(uintptr_t) bootinfo->mods_addr;

	initrd = (char *)(uintptr_t) mods->start;
	initrd_size = mods->end - mods->start;
}

#ifdef TARGET_EFI

/* From x86/efi/efistart64.S */
extern void load_idt(void);
extern void load_gdt_tss(size_t tss_offset);

void setup_efi_bootinfo(efi_bootinfo_t *efi_bootinfo)
{
	efi_bootinfo->free_mem_size = 0;
	efi_bootinfo->free_mem_start = 0;
	efi_bootinfo->rsdp = NULL;
}

static efi_status_t setup_pre_boot_memory(unsigned long *mapkey, efi_bootinfo_t *efi_bootinfo)
{
	int i;
	unsigned long free_mem_total_pages;
	efi_status_t status;
	struct efi_boot_memmap map;
	efi_memory_desc_t *buffer, *d;
	unsigned long map_size, desc_size, buff_size;
	u32 desc_ver;

	map.map = &buffer;
	map.map_size = &map_size;
	map.desc_size = &desc_size;
	map.desc_ver = &desc_ver;
	map.buff_size = &buff_size;
	map.key_ptr = mapkey;

	status = efi_get_memory_map(&map);
	if (status != EFI_SUCCESS) {
		return status;
	}

	/*
	 * The 'buffer' contains multiple descriptors that describe memory
	 * regions maintained by UEFI. This code records the largest free
	 * EFI_CONVENTIONAL_MEMORY region which will be used to set up the
	 * memory allocator, so that the memory allocator can work in the
	 * largest free continuous memory region.
	 */
	free_mem_total_pages = 0;
	for (i = 0; i < map_size; i += desc_size) {
		d = (efi_memory_desc_t *)(&((u8 *)buffer)[i]);
		if (d->type == EFI_CONVENTIONAL_MEMORY) {
			if (free_mem_total_pages < d->num_pages) {
				free_mem_total_pages = d->num_pages;
				efi_bootinfo->free_mem_size = free_mem_total_pages << EFI_PAGE_SHIFT;
				efi_bootinfo->free_mem_start = d->phys_addr;
			}
		}
	}

	if (efi_bootinfo->free_mem_size == 0) {
		return EFI_OUT_OF_RESOURCES;
	}

	return EFI_SUCCESS;
}

static efi_status_t setup_pre_boot_rsdp(efi_bootinfo_t *efi_bootinfo)
{
	return efi_get_system_config_table(ACPI_TABLE_GUID, (void **)&efi_bootinfo->rsdp);
}

efi_status_t setup_efi_pre_boot(unsigned long *mapkey, efi_bootinfo_t *efi_bootinfo)
{
	efi_status_t status;

	status = setup_pre_boot_memory(mapkey, efi_bootinfo);
	if (status != EFI_SUCCESS) {
		printf("setup_pre_boot_memory() failed: ");
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

	status = setup_pre_boot_rsdp(efi_bootinfo);
	if (status != EFI_SUCCESS) {
		printf("Cannot find RSDP in EFI system table\n");
		return status;
	}

	return EFI_SUCCESS;
}

static void setup_gdt_tss(void)
{
	size_t tss_offset;

	/* 64-bit setup_tss does not use the stacktop argument.  */
	tss_offset = setup_tss(NULL);
	load_gdt_tss(tss_offset);
}

void setup_efi(efi_bootinfo_t *efi_bootinfo)
{
	reset_apic();
	setup_gdt_tss();
	setup_idt();
	load_idt();
	mask_pic_interrupts();
	enable_apic();
	enable_x2apic();
	smp_init();
	phys_alloc_init(efi_bootinfo->free_mem_start, efi_bootinfo->free_mem_size);
	setup_efi_rsdp(efi_bootinfo->rsdp);
}

#endif /* TARGET_EFI */

void setup_libcflat(void)
{
	if (initrd) {
		/* environ is currently the only file in the initrd */
		u32 size = MIN(initrd_size, ENV_SIZE);
		const char *str;

		memcpy(env, initrd, size);
		setup_env(env, size);
		if ((str = getenv("BOOTLOADER")) && atol(str) != 0)
			add_setup_arg("bootloader");
	}
}
