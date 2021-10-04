# Build kvm-unit-tests and run under UEFI

## Introduction

This dir provides code to build kvm-unit-tests test cases and run them under
QEMU and UEFI.

### Install dependencies

The following dependencies should be installed:

- [UEFI firmware](https://github.com/tianocore/edk2): to run test cases in QEMU

### Build

To build:

    ./configure --target-efi
    make

### Run test cases with UEFI

To run a test case with UEFI:

    ./x86/efi/run ./x86/msr.efi

By default the runner script loads the UEFI firmware `/usr/share/ovmf/OVMF.fd`;
please install UEFI firmware to this path, or specify the correct path through
the env variable `EFI_UEFI`:

    EFI_UEFI=/path/to/OVMF.fd ./x86/efi/run ./x86/msr.efi

## Code structure

### Code from GNU-EFI

This dir contains source code and linker script copied from
[GNU-EFI](https://sourceforge.net/projects/gnu-efi/):
   - crt0-efi-x86_64.S: startup code of an EFI application
   - elf_x86_64_efi.lds: linker script to build an EFI application
   - reloc_x86_64.c: position independent x86_64 ELF shared object relocator

EFI application binaries should be relocatable as UEFI loads binaries to dynamic
runtime addresses. To build such relocatable binaries, GNU-EFI utilizes the
above-mentioned files in its build process:

   1. build an ELF shared object and link it using linker script
      `elf_x86_64_efi.lds` to organize the sections in a way UEFI recognizes
   2. link the shared object with self-relocator `reloc_x86_64.c` that applies
      dynamic relocations that may be present in the shared object
   3. link the entry point code `crt0-efi-x86_64.S` that invokes self-relocator
      and then jumps to EFI application's `efi_main()` function
   4. convert the shared object to an EFI binary

More details can be found in `GNU-EFI/README.gnuefi`, section "Building
Relocatable Binaries".

kvm-unit-tests follows a similar build process, but does not link with GNU-EFI
library.
### Startup code for kvm-unit-tests in UEFI

This dir also contains kvm-unit-tests startup code in UEFI:
   - efistart64.S: startup code for kvm-unit-tests in UEFI
