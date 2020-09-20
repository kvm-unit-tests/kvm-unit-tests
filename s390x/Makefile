tests = $(TEST_DIR)/selftest.elf
tests += $(TEST_DIR)/intercept.elf
tests += $(TEST_DIR)/emulator.elf
tests += $(TEST_DIR)/sieve.elf
tests += $(TEST_DIR)/sthyi.elf
tests += $(TEST_DIR)/skey.elf
tests += $(TEST_DIR)/diag10.elf
tests += $(TEST_DIR)/diag308.elf
tests += $(TEST_DIR)/pfmf.elf
tests += $(TEST_DIR)/cmm.elf
tests += $(TEST_DIR)/vector.elf
tests += $(TEST_DIR)/gs.elf
tests += $(TEST_DIR)/iep.elf
tests += $(TEST_DIR)/cpumodel.elf
tests += $(TEST_DIR)/diag288.elf
tests += $(TEST_DIR)/stsi.elf
tests += $(TEST_DIR)/skrf.elf
tests += $(TEST_DIR)/smp.elf
tests += $(TEST_DIR)/sclp.elf
tests += $(TEST_DIR)/css.elf
tests += $(TEST_DIR)/uv-guest.elf
tests_binary = $(patsubst %.elf,%.bin,$(tests))

all: directories test_cases test_cases_binary

test_cases: $(tests)
test_cases_binary: $(tests_binary)

CFLAGS += -std=gnu99
CFLAGS += -ffreestanding
CFLAGS += -I $(SRCDIR)/lib -I $(SRCDIR)/lib/s390x -I lib
CFLAGS += -O2
CFLAGS += -march=zEC12
CFLAGS += -fno-delete-null-pointer-checks
LDFLAGS += -nostdlib -Wl,--build-id=none

# We want to keep intermediate files
.PRECIOUS: %.o

asm-offsets = lib/$(ARCH)/asm-offsets.h
include $(SRCDIR)/scripts/asm-offsets.mak

cflatobjs += lib/util.o
cflatobjs += lib/alloc.o
cflatobjs += lib/alloc_phys.o
cflatobjs += lib/alloc_page.o
cflatobjs += lib/vmalloc.o
cflatobjs += lib/alloc_phys.o
cflatobjs += lib/s390x/io.o
cflatobjs += lib/s390x/stack.o
cflatobjs += lib/s390x/sclp.o
cflatobjs += lib/s390x/sclp-console.o
cflatobjs += lib/s390x/interrupt.o
cflatobjs += lib/s390x/mmu.o
cflatobjs += lib/s390x/smp.o
cflatobjs += lib/s390x/vm.o
cflatobjs += lib/s390x/css_dump.o
cflatobjs += lib/s390x/css_lib.o

OBJDIRS += lib/s390x

cstart.o = $(TEST_DIR)/cstart64.o

FLATLIBS = $(libcflat)
%.elf: %.o $(FLATLIBS) $(SRCDIR)/s390x/flat.lds $(cstart.o)
	$(CC) $(CFLAGS) -c -o $(@:.elf=.aux.o) \
		$(SRCDIR)/lib/auxinfo.c -DPROGNAME=\"$@\"
	$(CC) $(LDFLAGS) -o $@ -T $(SRCDIR)/s390x/flat.lds \
		$(filter %.o, $^) $(FLATLIBS) $(@:.elf=.aux.o)
	$(RM) $(@:.elf=.aux.o)
	@chmod a-x $@

%.bin: %.elf
	$(OBJCOPY) -O binary  $< $@

arch_clean: asm_offsets_clean
	$(RM) $(TEST_DIR)/*.{o,elf,bin} $(TEST_DIR)/.*.d lib/s390x/.*.d

generated-files = $(asm-offsets)
$(tests:.elf=.o) $(cstart.o) $(cflatobjs): $(generated-files)
