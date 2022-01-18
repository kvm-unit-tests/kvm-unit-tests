#ifndef _X86_ASM_SETUP_H_
#define _X86_ASM_SETUP_H_

unsigned long setup_tss(u8 *stacktop);

#ifdef TARGET_EFI
#include "x86/acpi.h"
#include "x86/apic.h"
#include "x86/processor.h"
#include "x86/smp.h"
#include "asm/page.h"
#include "efi.h"
#include "x86/amd_sev.h"

efi_status_t setup_efi(efi_bootinfo_t *efi_bootinfo);
void setup_5level_page_table(void);
#endif /* TARGET_EFI */

#endif /* _X86_ASM_SETUP_H_ */
