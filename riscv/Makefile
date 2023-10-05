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
#tests += $(TEST_DIR)/sieve.$(exe)

all: $(tests)

$(TEST_DIR)/sieve.elf: AUXFLAGS = 0x1

cstart.o = $(TEST_DIR)/cstart.o

cflatobjs += lib/alloc.o
cflatobjs += lib/alloc_phys.o
cflatobjs += lib/devicetree.o
cflatobjs += lib/riscv/bitops.o
cflatobjs += lib/riscv/io.o
cflatobjs += lib/riscv/processor.o
cflatobjs += lib/riscv/sbi.o
cflatobjs += lib/riscv/setup.o
cflatobjs += lib/riscv/smp.o
cflatobjs += lib/riscv/stack.o
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

ISA_COMMON = mafdc_zicsr_zifencei_zihintpause

ifeq ($(ARCH),riscv64)
CFLAGS += -march=rv64i$(ISA_COMMON)
CFLAGS += -DCONFIG_64BIT
else ifeq ($(ARCH),riscv32)
CFLAGS += -march=rv32i$(ISA_COMMON)
endif
CFLAGS += -DCONFIG_RELOC
CFLAGS += -mcmodel=medany
CFLAGS += -mstrict-align
CFLAGS += -std=gnu99
CFLAGS += -ffreestanding
CFLAGS += -O2
CFLAGS += -I $(SRCDIR)/lib -I $(SRCDIR)/lib/libfdt

asm-offsets = lib/riscv/asm-offsets.h
include $(SRCDIR)/scripts/asm-offsets.mak

%.aux.o: $(SRCDIR)/lib/auxinfo.c
	$(CC) $(CFLAGS) -c -o $@ $< \
		-DPROGNAME=\"$(notdir $(@:.aux.o=.$(exe)))\" -DAUXFLAGS=$(AUXFLAGS)

ifeq ($(CONFIG_EFI),y)
	# TODO
else
%.elf: LDFLAGS += -pie -n -z notext
%.elf: %.o $(FLATLIBS) $(SRCDIR)/riscv/flat.lds $(cstart.o) %.aux.o
	$(LD) $(LDFLAGS) -o $@ -T $(SRCDIR)/riscv/flat.lds \
		$(filter %.o, $^) $(FLATLIBS)
	@chmod a-x $@

%.flat: %.elf
	$(call arch_elf_check, $^)
	$(OBJCOPY) -O binary $^ $@
	@chmod a-x $@
endif

generated-files = $(asm-offsets)
$(tests:.$(exe)=.o) $(cstart.o) $(cflatobjs): $(generated-files)

arch_clean: asm_offsets_clean
	$(RM) $(TEST_DIR)/*.{o,flat,elf,so,efi,debug} \
	      $(TEST_DIR)/.*.d $(TEST_DIR)/efi/.*.d lib/riscv/.*.d
