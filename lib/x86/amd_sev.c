/*
 * AMD SEV support in kvm-unit-tests
 *
 * Copyright (c) 2021, Google Inc
 *
 * Authors:
 *   Zixuan Wang <zixuanwang@google.com>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "amd_sev.h"
#include "x86/processor.h"
#include "x86/vm.h"

static unsigned short amd_sev_c_bit_pos;

bool amd_sev_enabled(void)
{
	static bool sev_enabled;
	static bool initialized = false;

	/* Check CPUID and MSR for SEV status and store it for future function calls. */
	if (!initialized) {
		initialized = true;

		sev_enabled = this_cpu_has(X86_FEATURE_SEV) &&
			      rdmsr(MSR_SEV_STATUS) & SEV_ENABLED_MASK;
	}

	return sev_enabled;
}

efi_status_t setup_amd_sev(void)
{
	if (!amd_sev_enabled()) {
		return EFI_UNSUPPORTED;
	}

	amd_sev_c_bit_pos = this_cpu_property(X86_PROPERTY_SEV_C_BIT);

	return EFI_SUCCESS;
}

bool amd_sev_es_enabled(void)
{
	static bool sev_es_enabled;
	static bool initialized = false;

	if (!initialized) {
		initialized = true;

		sev_es_enabled = amd_sev_enabled() &&
				 this_cpu_has(X86_FEATURE_SEV_ES) &&
				 rdmsr(MSR_SEV_STATUS) & SEV_ES_ENABLED_MASK;
	}

	return sev_es_enabled;
}

efi_status_t setup_amd_sev_es(void)
{
	struct descriptor_table_ptr idtr;
	idt_entry_t *idt;
	idt_entry_t vc_handler_idt;

	if (!amd_sev_es_enabled()) {
		return EFI_UNSUPPORTED;
	}

	/*
	 * Copy UEFI's #VC IDT entry, so KVM-Unit-Tests can reuse it and does
	 * not have to re-implement a #VC handler. Also update the #VC IDT code
	 * segment to use KVM-Unit-Tests segments, KERNEL_CS, so that we do not
	 * have to copy the UEFI GDT entries into KVM-Unit-Tests GDT.
	 *
	 * TODO: Reusing UEFI #VC handler is a temporary workaround to simplify
	 * the boot up process, the long-term solution is to implement a #VC
	 * handler in kvm-unit-tests and load it, so that kvm-unit-tests does
	 * not depend on specific UEFI #VC handler implementation.
	 */
	sidt(&idtr);
	idt = (idt_entry_t *)idtr.base;
	vc_handler_idt = idt[VC_VECTOR];
	vc_handler_idt.selector = KERNEL_CS;
	boot_idt[VC_VECTOR] = vc_handler_idt;

	return EFI_SUCCESS;
}

void setup_ghcb_pte(pgd_t *page_table)
{
	/*
	 * SEV-ES guest uses GHCB page to communicate with the host. This page
	 * must be unencrypted, i.e. its c-bit should be unset. To do so, this
	 * function searches GHCB's L1 pte, creates corresponding L1 ptes if not
	 * found, and unsets the c-bit of GHCB's L1 pte.
	 */
	phys_addr_t ghcb_addr, ghcb_base_addr;
	pteval_t *pte;

	/* Read the current GHCB page addr */
	ghcb_addr = rdmsr(SEV_ES_GHCB_MSR_INDEX);

	/* Search Level 1 page table entry for GHCB page */
	pte = get_pte_level(page_table, (void *)ghcb_addr, 1);

	/* Create Level 1 pte for GHCB page if not found */
	if (pte == NULL) {
		/* Find Level 2 page base address */
		ghcb_base_addr = ghcb_addr & ~(LARGE_PAGE_SIZE - 1);
		/* Install Level 1 ptes */
		install_pages(page_table, ghcb_base_addr, LARGE_PAGE_SIZE, (void *)ghcb_base_addr);
		/* Find Level 2 pte, set as 4KB pages */
		pte = get_pte_level(page_table, (void *)ghcb_addr, 2);
		assert(pte);
		*pte &= ~(PT_PAGE_SIZE_MASK);
		/* Find Level 1 GHCB pte */
		pte = get_pte_level(page_table, (void *)ghcb_addr, 1);
		assert(pte);
	}

	/* Unset c-bit in Level 1 GHCB pte */
	*pte &= ~(get_amd_sev_c_bit_mask());
}

unsigned long long get_amd_sev_c_bit_mask(void)
{
	if (amd_sev_enabled()) {
		return 1ull << amd_sev_c_bit_pos;
	} else {
		return 0;
	}
}

unsigned long long get_amd_sev_addr_upperbound(void)
{
	if (amd_sev_enabled()) {
		return amd_sev_c_bit_pos - 1;
	} else {
		/* Default memory upper bound */
		return PT_ADDR_UPPER_BOUND_DEFAULT;
	}
}
