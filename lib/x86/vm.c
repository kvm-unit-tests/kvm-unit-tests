#include "vm.h"
#include "libcflat.h"
#include "vmalloc.h"
#include "alloc_page.h"
#include "smp.h"

static pteval_t pte_opt_mask;

pteval_t *install_pte(pgd_t *cr3,
		      int pte_level,
		      void *virt,
		      pteval_t pte,
		      pteval_t *pt_page)
{
    int level;
    pteval_t *pt = cr3;
    unsigned offset;

    for (level = PAGE_LEVEL; level > pte_level; --level) {
	offset = PGDIR_OFFSET((uintptr_t)virt, level);
	if (!(pt[offset] & PT_PRESENT_MASK)) {
	    pteval_t *new_pt = pt_page;
            if (!new_pt)
                new_pt = alloc_page();
            else
                pt_page = 0;
	    memset(new_pt, 0, PAGE_SIZE);
	    pt[offset] = virt_to_phys(new_pt) | PT_PRESENT_MASK | PT_WRITABLE_MASK | pte_opt_mask;
#ifdef CONFIG_EFI
	    pt[offset] |= get_amd_sev_c_bit_mask();
#endif /* CONFIG_EFI */
	}
	pt = phys_to_virt(pt[offset] & PT_ADDR_MASK);
    }
    offset = PGDIR_OFFSET((uintptr_t)virt, level);
    pt[offset] = pte;
    return &pt[offset];
}

/*
 * Finds last PTE in the mapping of @virt that's at or above @lowest_level. The
 * returned PTE isn't necessarily present, but its parent is.
 */
struct pte_search find_pte_level(pgd_t *cr3, void *virt,
				 int lowest_level)
{
	pteval_t *pt = cr3, pte;
	unsigned offset;
	unsigned shift;
	struct pte_search r;

	assert(lowest_level >= 1 && lowest_level <= PAGE_LEVEL);

	for (r.level = PAGE_LEVEL;; --r.level) {
		shift = (r.level - 1) * PGDIR_WIDTH + 12;
		offset = ((uintptr_t)virt >> shift) & PGDIR_MASK;
		r.pte = &pt[offset];
		pte = *r.pte;

		if (!(pte & PT_PRESENT_MASK))
			return r;

		if ((r.level == 2 || r.level == 3) && (pte & PT_PAGE_SIZE_MASK))
			return r;

		if (r.level == lowest_level)
			return r;

		pt = phys_to_virt(pte & PT_ADDR_MASK);
	}
}

/*
 * Returns the leaf PTE in the mapping of @virt (i.e., 4K PTE or a present huge
 * PTE). Returns NULL if no leaf PTE exists.
 */
pteval_t *get_pte(pgd_t *cr3, void *virt)
{
	struct pte_search search;

	search = find_pte_level(cr3, virt, 1);
	return found_leaf_pte(search) ? search.pte : NULL;
}

/*
 * Returns the PTE in the mapping of @virt at the given level @pte_level.
 * Returns NULL if the PT at @pte_level isn't present (i.e., the mapping at
 * @pte_level - 1 isn't present).
 */
pteval_t *get_pte_level(pgd_t *cr3, void *virt, int pte_level)
{
	struct pte_search search;

	search = find_pte_level(cr3, virt, pte_level);
	return search.level == pte_level ? search.pte : NULL;
}

pteval_t *install_large_page(pgd_t *cr3, phys_addr_t phys, void *virt)
{
    phys_addr_t flags = PT_PRESENT_MASK | PT_WRITABLE_MASK | pte_opt_mask | PT_PAGE_SIZE_MASK;
#ifdef CONFIG_EFI
    flags |= get_amd_sev_c_bit_mask();
#endif /* CONFIG_EFI */
    return install_pte(cr3, 2, virt, phys | flags, 0);
}

pteval_t *install_page(pgd_t *cr3, phys_addr_t phys, void *virt)
{
    phys_addr_t flags = PT_PRESENT_MASK | PT_WRITABLE_MASK | pte_opt_mask;
#ifdef CONFIG_EFI
    flags |= get_amd_sev_c_bit_mask();
#endif /* CONFIG_EFI */
    return install_pte(cr3, 1, virt, phys | flags, 0);
}

void install_pages(pgd_t *cr3, phys_addr_t phys, size_t len, void *virt)
{
	phys_addr_t max = (u64)len + (u64)phys;
	assert(phys % PAGE_SIZE == 0);
	assert((uintptr_t) virt % PAGE_SIZE == 0);
	assert(len % PAGE_SIZE == 0);

	while (phys + PAGE_SIZE <= max) {
		install_page(cr3, phys, virt);
		phys += PAGE_SIZE;
		virt = (char *) virt + PAGE_SIZE;
	}
}

bool any_present_pages(pgd_t *cr3, void *virt, size_t len)
{
	uintptr_t max = (uintptr_t) virt + len;
	uintptr_t curr;

	for (curr = (uintptr_t) virt; curr < max; curr += PAGE_SIZE) {
		pteval_t *ptep = get_pte(cr3, (void *) curr);
		if (ptep && (*ptep & PT_PRESENT_MASK))
			return true;
	}
	return false;
}

void __setup_mmu_range(pgd_t *cr3, phys_addr_t start, size_t len,
		       enum x86_mmu_flags mmu_flags)
{
	u64 orig_opt_mask = pte_opt_mask;
	u64 max = (u64)len + (u64)start;
	u64 phys = start;

	if (mmu_flags & X86_MMU_MAP_USER)
		pte_opt_mask |= PT_USER_MASK;

	if (mmu_flags & X86_MMU_MAP_HUGE) {
		while (phys + LARGE_PAGE_SIZE <= max) {
			install_large_page(cr3, phys, (void *)(ulong)phys);
			phys += LARGE_PAGE_SIZE;
		}
	}
	install_pages(cr3, phys, max - phys, (void *)(ulong)phys);

	pte_opt_mask = orig_opt_mask;
}

static inline void setup_mmu_range(pgd_t *cr3, phys_addr_t start, size_t len)
{
	__setup_mmu_range(cr3, start, len, X86_MMU_MAP_HUGE);
}

static void set_additional_vcpu_vmregs(struct vm_vcpu_info *info)
{
	write_cr3(info->cr3);
	write_cr4(info->cr4);
	write_cr0(info->cr0);
}

void *setup_mmu(phys_addr_t end_of_memory, void *opt_mask)
{
    pgd_t *cr3 = alloc_page();
    struct vm_vcpu_info info;
    int i;

    if (opt_mask)
	pte_opt_mask = *(pteval_t *)opt_mask;
    else
	pte_opt_mask = PT_USER_MASK;

    memset(cr3, 0, PAGE_SIZE);

#ifdef __x86_64__
    if (end_of_memory < (1ul << 32))
        end_of_memory = (1ul << 32);  /* map mmio 1:1 */

    setup_mmu_range(cr3, 0, end_of_memory);
    /* skip the last page for out-of-bound and wrap-around reasons */
    init_alloc_vpage((void *)(~(PAGE_SIZE - 1)));
#else
    setup_mmu_range(cr3, 0, (2ul << 30));
    setup_mmu_range(cr3, 3ul << 30, (1ul << 30));
    init_alloc_vpage((void*)(3ul << 30));
#endif

    write_cr3(virt_to_phys(cr3));
#ifndef __x86_64__
    write_cr4(X86_CR4_PSE);
#endif
    write_cr0(X86_CR0_PG |X86_CR0_PE | X86_CR0_WP);

    printf("paging enabled\n");
    printf("cr0 = %lx\n", read_cr0());
    printf("cr3 = %lx\n", read_cr3());
    printf("cr4 = %lx\n", read_cr4());

    info.cr3 = read_cr3();
    info.cr4 = read_cr4();
    info.cr0 = read_cr0();

    for (i = 1; i < cpu_count(); i++)
        on_cpu(i, (void *)set_additional_vcpu_vmregs, &info);

    return cr3;
}

phys_addr_t virt_to_pte_phys(pgd_t *cr3, void *mem)
{
    return (*get_pte(cr3, mem) & PT_ADDR_MASK) + ((ulong)mem & (PAGE_SIZE - 1));
}

/*
 * split_large_page: Split a 2M/1G large page into 512 smaller PTEs.
 *   @ptep : large page table entry to split
 *   @level : level of ptep (2 or 3)
 */
void split_large_page(unsigned long *ptep, int level)
{
	unsigned long *new_pt;
	unsigned long pa;
	unsigned long pte;
	unsigned long prototype;
	int i;

	pte = *ptep;
	assert(pte & PT_PRESENT_MASK);
	assert(pte & PT_PAGE_SIZE_MASK);
	assert(level == 2 || level == 3);

	new_pt = alloc_page();
	assert(new_pt);

	prototype = pte & ~PT_ADDR_MASK;
	if (level == 2)
		prototype &= ~PT_PAGE_SIZE_MASK;

	pa = pte & PT_ADDR_MASK;
	for (i = 0; i < (1 << PGDIR_WIDTH); i++) {
		new_pt[i] = prototype | pa;
		pa += 1ul << PGDIR_BITS(level - 1);
	}

	pte &= ~PT_PAGE_SIZE_MASK;
	pte &= ~PT_ADDR_MASK;
	pte |= virt_to_phys(new_pt);

	/* Modify the relevant paging-structure entry */
	*ptep = pte;

	/*
	 * Flush the TLB to eradicate stale mappings.
	 *
	 * Note: Removing specific TLB mappings is tricky because
	 * split_large_page() can be called to split the active code page
	 * backing the next set of instructions to be fetched and executed.
	 * Furthermore, Intel SDM volume 3 recommends to clear the present bit
	 * for the page being split, before invalidating any mappings.
	 *
	 * But clearing the mapping from the page table and removing it from the
	 * TLB (where it's not actually guaranteed to reside anyway) makes it
	 * impossible to continue fetching instructions!
	 */
	flush_tlb();
}

/*
 * force_4k_page: Ensures that addr translate to a 4k page.
 *
 * This function uses split_large_page(), as needed, to ensure that target
 * address, addr, translates to a 4k page.
 *
 *   @addr: target address that should be mapped to a 4k page
 */
void force_4k_page(void *addr)
{
	unsigned long *ptep;
	unsigned long pte;
	unsigned long *cr3 = current_page_table();

	ptep = get_pte_level(cr3, addr, 3);
	assert(ptep);
	pte = *ptep;
	assert(pte & PT_PRESENT_MASK);
	if (pte & PT_PAGE_SIZE_MASK)
		split_large_page(ptep, 3);

	ptep = get_pte_level(cr3, addr, 2);
	assert(ptep);
	pte = *ptep;
	assert(pte & PT_PRESENT_MASK);
	if (pte & PT_PAGE_SIZE_MASK)
		split_large_page(ptep, 2);
}

/*
 * Call the callback on each page from virt to virt + len.
 */
void walk_pte(void *virt, size_t len, pte_callback_t callback)
{
    pgd_t *cr3 = current_page_table();
    uintptr_t start = (uintptr_t)virt;
    uintptr_t end = (uintptr_t)virt + len;
    struct pte_search search;
    size_t page_size;
    uintptr_t curr;

    for (curr = start; curr < end; curr = ALIGN_DOWN(curr + page_size, page_size)) {
        search = find_pte_level(cr3, (void *)curr, 1);
        assert(found_leaf_pte(search));
        page_size = 1ul << PGDIR_BITS(search.level);

        callback(search, (void *)curr);
    }
}
