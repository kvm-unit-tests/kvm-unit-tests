#
# riscv makefile
#
# Authors: Andrew Jones <ajones@ventanamicro.com>
#

ifeq ($(CONFIG_EFI),y)
exe = efi
else
exe = flat
endif

tests =
tests += $(TEST_DIR)/sbi.$(exe)
tests += $(TEST_DIR)/selftest.$(exe)
tests += $(TEST_DIR)/sieve.$(exe)

all: $(tests)

$(TEST_DIR)/sbi-deps += $(TEST_DIR)/sbi-asm.o
$(TEST_DIR)/sbi-deps += $(TEST_DIR)/sbi-fwft.o
$(TEST_DIR)/sbi-deps += $(TEST_DIR)/sbi-sse.o

all_deps += $($(TEST_DIR)/sbi-deps)

# When built for EFI sieve needs extra memory, run with e.g. '-m 256' on QEMU
$(TEST_DIR)/sieve.$(exe): AUXFLAGS = 0x1

cstart.o = $(TEST_DIR)/cstart.o

cflatobjs += lib/alloc.o
cflatobjs += lib/alloc_page.o
cflatobjs += lib/alloc_phys.o
cflatobjs += lib/devicetree.o
cflatobjs += lib/memregions.o
cflatobjs += lib/on-cpus.o
cflatobjs += lib/vmalloc.o
cflatobjs += lib/riscv/bitops.o
cflatobjs += lib/riscv/delay.o
cflatobjs += lib/riscv/io.o
cflatobjs += lib/riscv/isa.o
cflatobjs += lib/riscv/mmu.o
cflatobjs += lib/riscv/processor.o
cflatobjs += lib/riscv/sbi.o
cflatobjs += lib/riscv/setjmp.o
cflatobjs += lib/riscv/setup.o
cflatobjs += lib/riscv/smp.o
cflatobjs += lib/riscv/stack.o
cflatobjs += lib/riscv/timer.o
cflatobjs += lib/riscv/sbi-sse-asm.o
ifeq ($(ARCH),riscv32)
cflatobjs += lib/ldiv32.o
endif

########################################

OBJDIRS += lib/riscv
FLATLIBS = $(libcflat) $(LIBFDT_archive)

AUXFLAGS ?= 0x0

# stack.o relies on frame pointers.
KEEP_FRAME_POINTER := y

# We want to keep intermediate files
.PRECIOUS: %.elf %.o

define arch_elf_check =
	$(if $(shell ! $(READELF) -rW $(1) >&/dev/null && echo "nok"),
		$(error $(shell $(READELF) -rW $(1) 2>&1)))
	$(if $(shell $(READELF) -rW $(1) | grep R_ | grep -v R_RISCV_RELATIVE),
		$(error $(1) has unsupported reloc types))
endef

ISA_COMMON = imac_zicsr_zifencei_zihintpause

ifeq ($(ARCH),riscv64)
CFLAGS  += -DCONFIG_64BIT
CFLAGS  += -mabi=lp64 -march=rv64$(ISA_COMMON)
LDFLAGS += -melf64lriscv
else ifeq ($(ARCH),riscv32)
CFLAGS  += -mabi=ilp32 -march=rv32$(ISA_COMMON)
LDFLAGS += -melf32lriscv
endif
CFLAGS += -DCONFIG_RELOC
CFLAGS += -mcmodel=medany
# Unaligned accesses are allowed, but may be emulated by M-mode.
# Enable -mstrict-align if that's troublesome (only supported by gcc).
#CFLAGS += -mstrict-align
CFLAGS += -std=gnu99
CFLAGS += -ffreestanding
CFLAGS += -O2
CFLAGS += -I $(SRCDIR)/lib -I $(SRCDIR)/lib/libfdt -I lib -I $(SRCDIR)/riscv

asm-offsets = lib/riscv/asm-offsets.h riscv/sbi-asm-offsets.h
include $(SRCDIR)/scripts/asm-offsets.mak

.PRECIOUS: %.aux.o
%.aux.o: $(SRCDIR)/lib/auxinfo.c
	$(CC) $(CFLAGS) -c -o $@ $< \
		-DPROGNAME=\"$(notdir $(@:.aux.o=.$(exe)))\" -DAUXFLAGS=$(AUXFLAGS)

.SECONDEXPANSION:
ifeq ($(CONFIG_EFI),y)
# avoid jump tables before all relocations have been processed
riscv/efi/reloc_riscv64.o: CFLAGS += -fno-jump-tables
cflatobjs += riscv/efi/reloc_riscv64.o
cflatobjs += lib/acpi.o
cflatobjs += lib/efi.o

.PRECIOUS: %.so

%.so: EFI_LDFLAGS += -defsym=EFI_SUBSYSTEM=0xa --no-undefined
%.so: %.o $(FLATLIBS) $(SRCDIR)/riscv/efi/elf_riscv64_efi.lds $(cstart.o) %.aux.o $$($$*-deps)
	$(LD) $(EFI_LDFLAGS) -o $@ -T $(SRCDIR)/riscv/efi/elf_riscv64_efi.lds \
		$(filter %.o, $^) $(FLATLIBS) $(EFI_LIBS)

%.efi: %.so
	$(call arch_elf_check, $^)
	$(OBJCOPY) --only-keep-debug $^ $@.debug
	$(OBJCOPY) --strip-debug $^
	$(OBJCOPY) --add-gnu-debuglink=$@.debug $^
	$(OBJCOPY) \
		-j .text -j .sdata -j .data -j .rodata -j .dynamic -j .dynsym \
		-j .rel -j .rela -j .rel.* -j .rela.* -j .rel* -j .rela* \
		-j .reloc \
		-O binary $^ $@
else
%.elf: LDFLAGS += -pie -n -z notext
%.elf: %.o $(FLATLIBS) $(SRCDIR)/riscv/flat.lds $(cstart.o) %.aux.o $$($$*-deps)
	$(LD) $(LDFLAGS) -o $@ -T $(SRCDIR)/riscv/flat.lds \
		$(filter %.o, $^) $(FLATLIBS)
	@chmod a-x $@

%.flat: %.elf
	$(call arch_elf_check, $^)
	$(OBJCOPY) -O binary $^ $@
	@chmod a-x $@
endif

generated-files = $(asm-offsets)
$(tests:.$(exe)=.o) $(cstart.o) $(cflatobjs) $(all_deps): $(generated-files)

arch_clean: asm_offsets_clean
	$(RM) $(TEST_DIR)/*.{o,flat,elf,so,efi,debug} \
	      $(TEST_DIR)/.*.d $(TEST_DIR)/efi/.*.d lib/riscv/.*.d
