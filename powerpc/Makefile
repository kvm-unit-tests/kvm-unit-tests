#
# powerpc makefile
#
# Authors: Andrew Jones <drjones@redhat.com>
#
tests = \
	$(TEST_DIR)/selftest.elf \
	$(TEST_DIR)/selftest-migration.elf \
	$(TEST_DIR)/memory-verify.elf \
	$(TEST_DIR)/sieve.elf \
	$(TEST_DIR)/spapr_vpa.elf \
	$(TEST_DIR)/spapr_hcall.elf \
	$(TEST_DIR)/rtas.elf \
	$(TEST_DIR)/emulator.elf \
	$(TEST_DIR)/atomics.elf \
	$(TEST_DIR)/tm.elf \
	$(TEST_DIR)/smp.elf \
	$(TEST_DIR)/sprs.elf \
	$(TEST_DIR)/timebase.elf \
	$(TEST_DIR)/interrupts.elf \
	$(TEST_DIR)/mmu.elf \
	$(TEST_DIR)/pmu.elf

all: directories $(TEST_DIR)/boot_rom.bin $(tests)

cstart.o = $(TEST_DIR)/cstart64.o
reloc.o  = $(TEST_DIR)/reloc64.o

OBJDIRS += lib/powerpc
cflatobjs += lib/powerpc/stack.o
cflatobjs += lib/powerpc/mmu.o
cflatobjs += lib/powerpc/opal.o
cflatobjs += lib/powerpc/opal-calls.o
cflatobjs += lib/util.o
cflatobjs += lib/getchar.o
cflatobjs += lib/alloc_phys.o
cflatobjs += lib/alloc.o
cflatobjs += lib/alloc_page.o
cflatobjs += lib/vmalloc.o
cflatobjs += lib/devicetree.o
cflatobjs += lib/migrate.o
cflatobjs += lib/powerpc/io.o
cflatobjs += lib/powerpc/hcall.o
cflatobjs += lib/powerpc/setup.o
cflatobjs += lib/powerpc/rtas.o
cflatobjs += lib/powerpc/processor.o
cflatobjs += lib/powerpc/handlers.o
cflatobjs += lib/powerpc/smp.o

##################################################################

bits = 64

ifeq ($(ENDIAN),little)
    arch_CFLAGS = -mlittle-endian
    arch_LDFLAGS = -EL
else
    arch_CFLAGS = -mbig-endian
    arch_LDFLAGS = -EB
endif

mabi_no_altivec := $(call cc-option,-mabi=no-altivec,"")

CFLAGS += -std=gnu99
CFLAGS += -ffreestanding
CFLAGS += -O2 -msoft-float -mno-altivec $(mabi_no_altivec)
CFLAGS += -I $(SRCDIR)/lib -I $(SRCDIR)/lib/libfdt -I lib
CFLAGS += -Wa,-mregnames

# We want to keep intermediate files
.PRECIOUS: %.o

asm-offsets = lib/powerpc/asm-offsets.h
include $(SRCDIR)/scripts/asm-offsets.mak

%.aux.o: $(SRCDIR)/lib/auxinfo.c
	$(CC) $(CFLAGS) -c -o $@ $< -DPROGNAME=\"$(@:.aux.o=.elf)\"

FLATLIBS = $(libcflat) $(LIBFDT_archive)
%.elf: CFLAGS += $(arch_CFLAGS)
%.elf: LDFLAGS += $(arch_LDFLAGS) -pie -n
%.elf: %.o $(FLATLIBS) $(SRCDIR)/powerpc/flat.lds $(cstart.o) $(reloc.o) %.aux.o
	$(LD) $(LDFLAGS) -o $@ \
		-T $(SRCDIR)/powerpc/flat.lds --build-id=none \
		$(filter %.o, $^) $(FLATLIBS)
	@chmod a-x $@
	@echo -n Checking $@ for unsupported reloc types...
	@if $(OBJDUMP) -R $@ | grep R_ | grep -v R_PPC64_RELATIVE; then	\
		false;							\
	else								\
		echo " looks good.";					\
	fi

$(TEST_DIR)/boot_rom.bin: $(TEST_DIR)/boot_rom.elf
	dd if=/dev/zero of=$@ bs=256 count=1
	$(OBJCOPY) -O binary $^ $@.tmp
	cat $@.tmp >> $@
	$(RM) $@.tmp

$(TEST_DIR)/boot_rom.elf: CFLAGS = -mbig-endian
$(TEST_DIR)/boot_rom.elf: $(TEST_DIR)/boot_rom.o
	$(LD) -EB -nostdlib -Ttext=0x100 --entry=start --build-id=none -o $@ $<
	@chmod a-x $@

arch_clean: asm_offsets_clean
	$(RM) $(TEST_DIR)/*.{o,elf} $(TEST_DIR)/boot_rom.bin \
		  $(TEST_DIR)/.*.d lib/powerpc/.*.d

generated-files = $(asm-offsets)
$(tests:.elf=.o) $(cstart.o) $(cflatobjs): $(generated-files)
