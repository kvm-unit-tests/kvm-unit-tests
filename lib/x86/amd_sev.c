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

static unsigned short amd_sev_c_bit_pos;

bool amd_sev_enabled(void)
{
	struct cpuid cpuid_out;
	static bool sev_enabled;
	static bool initialized = false;

	/* Check CPUID and MSR for SEV status and store it for future function calls. */
	if (!initialized) {
		sev_enabled = false;
		initialized = true;

		/* Test if we can query SEV features */
		cpuid_out = cpuid(CPUID_FN_LARGEST_EXT_FUNC_NUM);
		if (cpuid_out.a < CPUID_FN_ENCRYPT_MEM_CAPAB) {
			return sev_enabled;
		}

		/* Test if SEV is supported */
		cpuid_out = cpuid(CPUID_FN_ENCRYPT_MEM_CAPAB);
		if (!(cpuid_out.a & SEV_SUPPORT_MASK)) {
			return sev_enabled;
		}

		/* Test if SEV is enabled */
		if (rdmsr(MSR_SEV_STATUS) & SEV_ENABLED_MASK) {
			sev_enabled = true;
		}
	}

	return sev_enabled;
}

efi_status_t setup_amd_sev(void)
{
	struct cpuid cpuid_out;

	if (!amd_sev_enabled()) {
		return EFI_UNSUPPORTED;
	}

	/*
	 * Extract C-Bit position from ebx[5:0]
	 * AMD64 Architecture Programmer's Manual Volume 3
	 *   - Section " Function 8000_001Fh - Encrypted Memory Capabilities"
	 */
	cpuid_out = cpuid(CPUID_FN_ENCRYPT_MEM_CAPAB);
	amd_sev_c_bit_pos = (unsigned short)(cpuid_out.b & 0x3f);

	return EFI_SUCCESS;
}

bool amd_sev_es_enabled(void)
{
	static bool sev_es_enabled;
	static bool initialized = false;

	if (!initialized) {
		sev_es_enabled = false;
		initialized = true;

		if (!amd_sev_enabled()) {
			return sev_es_enabled;
		}

		/* Test if SEV-ES is enabled */
		if (rdmsr(MSR_SEV_STATUS) & SEV_ES_ENABLED_MASK) {
			sev_es_enabled = true;
		}
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
	vc_handler_idt = idt[SEV_ES_VC_HANDLER_VECTOR];
	vc_handler_idt.selector = KERNEL_CS;
	boot_idt[SEV_ES_VC_HANDLER_VECTOR] = vc_handler_idt;

	return EFI_SUCCESS;
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
