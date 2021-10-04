#ifndef _X86_ASM_SETUP_H_
#define _X86_ASM_SETUP_H_

unsigned long setup_tss(u8 *stacktop);

#ifdef TARGET_EFI
#include "x86/apic.h"
#include "x86/smp.h"

void setup_efi(void);
#endif /* TARGET_EFI */

#endif /* _X86_ASM_SETUP_H_ */
