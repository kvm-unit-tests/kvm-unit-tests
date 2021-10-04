#ifndef _X86_ASM_SETUP_H_
#define _X86_ASM_SETUP_H_

unsigned long setup_tss(u8 *stacktop);

#ifdef TARGET_EFI
#include "x86/apic.h"
#include "x86/smp.h"
#include "efi.h"

/*
 * efi_bootinfo_t: stores EFI-related machine info retrieved by
 * setup_efi_pre_boot(), and is then used by setup_efi(). setup_efi() cannot
 * retrieve this info as it is called after ExitBootServices and thus some EFI
 * resources are not available.
 */
typedef struct {
	phys_addr_t free_mem_start;
	phys_addr_t free_mem_size;
} efi_bootinfo_t;

void setup_efi_bootinfo(efi_bootinfo_t *efi_bootinfo);
void setup_efi(efi_bootinfo_t *efi_bootinfo);
efi_status_t setup_efi_pre_boot(unsigned long *mapkey, efi_bootinfo_t *efi_bootinfo);
#endif /* TARGET_EFI */

#endif /* _X86_ASM_SETUP_H_ */
