/*
 * MMU enable and page table manipulation functions
 *
 * Copyright (C) 2014, Red Hat Inc, Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */
#include <asm/setup.h>
#include <asm/thread_info.h>
#include <asm/cpumask.h>
#include <asm/mmu.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/io.h>

#include "alloc_page.h"
#include "vmalloc.h"
#include <asm/pgtable-hwdef.h>
#include <asm/pgtable.h>

#include <linux/compiler.h>

pgd_t *mmu_idmap;

/* CPU 0 starts with disabled MMU */
static cpumask_t mmu_enabled_cpumask;

bool mmu_enabled(void)
{
	/*
	 * mmu_enabled is called from places that are guarding the
	 * use of exclusive ops (which require the mmu to be enabled).
	 * That means we CANNOT call anything from here that may use a
	 * spinlock, atomic bitop, etc., otherwise we'll recurse.
	 * [cpumask_]test_bit is safe though.
	 */
	if (is_user()) {
		int cpu = current_thread_info()->cpu;
		return cpumask_test_cpu(cpu, &mmu_enabled_cpumask);
	}

	return __mmu_enabled();
}

void mmu_mark_enabled(int cpu)
{
	cpumask_set_cpu(cpu, &mmu_enabled_cpumask);
}

void mmu_mark_disabled(int cpu)
{
	cpumask_clear_cpu(cpu, &mmu_enabled_cpumask);
}

extern void asm_mmu_enable(phys_addr_t pgtable);
void mmu_enable(pgd_t *pgtable)
{
	struct thread_info *info = current_thread_info();

	asm_mmu_enable(__pa(pgtable));

	info->pgtable = pgtable;
	mmu_mark_enabled(info->cpu);
}

extern void asm_mmu_disable(void);
void mmu_disable(void)
{
	unsigned long sp = current_stack_pointer;
	int cpu = current_thread_info()->cpu;

	assert_msg(__virt_to_phys(sp) == sp,
			"Attempting to disable MMU with non-identity mapped stack");

	mmu_mark_disabled(cpu);

	asm_mmu_disable();
}

static pteval_t *get_pte(pgd_t *pgtable, uintptr_t vaddr)
{
	pgd_t *pgd = pgd_offset(pgtable, vaddr);
	pud_t *pud = pud_alloc(pgd, vaddr);
	pmd_t *pmd = pmd_alloc(pud, vaddr);
	pte_t *pte = pte_alloc(pmd, vaddr);

	return &pte_val(*pte);
}

static pteval_t *install_pte(pgd_t *pgtable, uintptr_t vaddr, pteval_t pte)
{
	pteval_t *p_pte = get_pte(pgtable, vaddr);

	WRITE_ONCE(*p_pte, pte);
	flush_tlb_page(vaddr);
	return p_pte;
}

static pteval_t *install_page_prot(pgd_t *pgtable, phys_addr_t phys,
				   uintptr_t vaddr, pgprot_t prot)
{
	pteval_t pte = phys;
	pte |= PTE_TYPE_PAGE | PTE_AF | PTE_SHARED;
	pte |= pgprot_val(prot);
	return install_pte(pgtable, vaddr, pte);
}

pteval_t *install_page(pgd_t *pgtable, phys_addr_t phys, void *virt)
{
	return install_page_prot(pgtable, phys, (uintptr_t)virt,
				 __pgprot(PTE_WBWA | PTE_USER));
}

phys_addr_t virt_to_pte_phys(pgd_t *pgtable, void *mem)
{
	return (*get_pte(pgtable, (uintptr_t)mem) & PHYS_MASK & -PAGE_SIZE)
		+ ((ulong)mem & (PAGE_SIZE - 1));
}

void mmu_set_range_ptes(pgd_t *pgtable, uintptr_t virt_offset,
			phys_addr_t phys_start, phys_addr_t phys_end,
			pgprot_t prot)
{
	phys_addr_t paddr = phys_start & PAGE_MASK;
	uintptr_t vaddr = virt_offset & PAGE_MASK;
	uintptr_t virt_end = phys_end - paddr + vaddr;

	for (; vaddr < virt_end; vaddr += PAGE_SIZE, paddr += PAGE_SIZE)
		install_page_prot(pgtable, paddr, vaddr, prot);
}

void mmu_set_range_sect(pgd_t *pgtable, uintptr_t virt_offset,
			phys_addr_t phys_start, phys_addr_t phys_end,
			pgprot_t prot)
{
	phys_addr_t paddr = phys_start & PMD_MASK;
	uintptr_t vaddr = virt_offset & PMD_MASK;
	uintptr_t virt_end = phys_end - paddr + vaddr;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pmd_t entry;

	for (; vaddr < virt_end; vaddr += PMD_SIZE, paddr += PMD_SIZE) {
		pmd_val(entry) = paddr;
		pmd_val(entry) |= PMD_TYPE_SECT | PMD_SECT_AF | PMD_SECT_S;
		pmd_val(entry) |= pgprot_val(prot);
		pgd = pgd_offset(pgtable, vaddr);
		pud = pud_alloc(pgd, vaddr);
		pmd = pmd_alloc(pud, vaddr);
		WRITE_ONCE(*pmd, entry);
		flush_tlb_page(vaddr);
	}
}

void *setup_mmu(phys_addr_t phys_end, void *unused)
{
	struct mem_region *r;

	/* 3G-4G region is reserved for vmalloc, cap phys_end at 3G */
	if (phys_end > (3ul << 30))
		phys_end = 3ul << 30;

#ifdef __aarch64__
	init_alloc_vpage((void*)(4ul << 30));

	assert_msg(system_supports_granule(PAGE_SIZE),
			"Unsupported translation granule %ld\n", PAGE_SIZE);
#endif

	if (!mmu_idmap)
		mmu_idmap = alloc_page();

	for (r = mem_regions; r->end; ++r) {
		if (r->flags & MR_F_IO) {
			continue;
		} else if (r->flags & MR_F_CODE) {
			/* armv8 requires code shared between EL1 and EL0 to be read-only */
			mmu_set_range_ptes(mmu_idmap, r->start, r->start, r->end,
					   __pgprot(PTE_WBWA | PTE_USER | PTE_RDONLY));
		} else {
			mmu_set_range_ptes(mmu_idmap, r->start, r->start, r->end,
					   __pgprot(PTE_WBWA | PTE_USER));
		}
	}

	mmu_enable(mmu_idmap);
	return mmu_idmap;
}

void __iomem *__ioremap(phys_addr_t phys_addr, size_t size)
{
	phys_addr_t paddr_aligned = phys_addr & PAGE_MASK;
	phys_addr_t paddr_end = PAGE_ALIGN(phys_addr + size);
	pgprot_t prot = __pgprot(PTE_UNCACHED | PTE_USER | PTE_UXN | PTE_PXN);
	pgd_t *pgtable;

	assert(sizeof(long) == 8 || !(phys_addr >> 32));

	if (mmu_enabled()) {
		pgtable = current_thread_info()->pgtable;
	} else {
		if (!mmu_idmap)
			mmu_idmap = alloc_page();
		pgtable = mmu_idmap;
	}

	mmu_set_range_ptes(pgtable, paddr_aligned, paddr_aligned,
			   paddr_end, prot);

	return (void __iomem *)(unsigned long)phys_addr;
}

phys_addr_t __virt_to_phys(unsigned long addr)
{
	if (mmu_enabled()) {
		pgd_t *pgtable = current_thread_info()->pgtable;
		return virt_to_pte_phys(pgtable, (void *)addr);
	}
	return addr;
}

unsigned long __phys_to_virt(phys_addr_t addr)
{
	/*
	 * We don't guarantee that phys_to_virt(virt_to_phys(vaddr)) == vaddr, but
	 * the default page tables do identity map all physical addresses, which
	 * means phys_to_virt(virt_to_phys((void *)paddr)) == paddr.
	 */
	assert(!mmu_enabled() || __virt_to_phys(addr) == addr);
	return addr;
}

/*
 * NOTE: The Arm architecture might require the use of a
 * break-before-make sequence before making changes to a PTE and
 * certain conditions are met (see Arm ARM D5-2669 for AArch64 and
 * B3-1378 for AArch32 for more details).
 */
pteval_t *mmu_get_pte(pgd_t *pgtable, uintptr_t vaddr)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (!mmu_enabled())
		return NULL;

	pgd = pgd_offset(pgtable, vaddr);
	assert(pgd_valid(*pgd));
	pud = pud_offset(pgd, vaddr);
	assert(pud_valid(*pud));
	pmd = pmd_offset(pud, vaddr);
	assert(pmd_valid(*pmd));

	if (pmd_huge(*pmd))
		return &pmd_val(*pmd);

	pte = pte_offset(pmd, vaddr);
	assert(pte_valid(*pte));

        return &pte_val(*pte);
}

void mmu_clear_user(pgd_t *pgtable, unsigned long vaddr)
{
	pteval_t *p_pte = mmu_get_pte(pgtable, vaddr);
	if (p_pte) {
		pteval_t entry = *p_pte & ~PTE_USER;
		WRITE_ONCE(*p_pte, entry);
		flush_tlb_page(vaddr);
	}
}
