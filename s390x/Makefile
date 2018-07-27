tests = $(TEST_DIR)/selftest.elf
tests += $(TEST_DIR)/intercept.elf
tests += $(TEST_DIR)/emulator.elf
tests += $(TEST_DIR)/sieve.elf
tests += $(TEST_DIR)/sthyi.elf
tests += $(TEST_DIR)/skey.elf
tests += $(TEST_DIR)/diag10.elf
tests += $(TEST_DIR)/pfmf.elf
tests += $(TEST_DIR)/cmm.elf
tests += $(TEST_DIR)/vector.elf
tests += $(TEST_DIR)/gs.elf
tests += $(TEST_DIR)/iep.elf

all: directories test_cases

test_cases: $(tests)

CFLAGS += -std=gnu99
CFLAGS += -ffreestanding
CFLAGS += -I $(SRCDIR)/lib -I $(SRCDIR)/lib/s390x -I lib
CFLAGS += -O2
CFLAGS += -march=z900
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
cflatobjs += lib/s390x/sclp-ascii.o
cflatobjs += lib/s390x/interrupt.o
cflatobjs += lib/s390x/mmu.o

OBJDIRS += lib/s390x

cstart.o = $(TEST_DIR)/cstart64.o

FLATLIBS = $(libcflat)
%.elf: %.o $(FLATLIBS) $(SRCDIR)/s390x/flat.lds $(cstart.o)
	$(CC) $(CFLAGS) -c -o $(@:.elf=.aux.o) \
		$(SRCDIR)/lib/auxinfo.c -DPROGNAME=\"$@\"
	$(CC) $(LDFLAGS) -o $@ -T $(SRCDIR)/s390x/flat.lds -Ttext=0x10000 \
		$(filter %.o, $^) $(FLATLIBS) $(@:.elf=.aux.o)
	$(RM) $(@:.elf=.aux.o)
	@chmod a-x $@

arch_clean: asm_offsets_clean
	$(RM) $(TEST_DIR)/*.{o,elf} $(TEST_DIR)/.*.d lib/s390x/.*.d

generated-files = $(asm-offsets)
$(tests:.elf=.o) $(cstart.o) $(cflatobjs): $(generated-files)
