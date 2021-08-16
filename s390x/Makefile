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
tests += $(TEST_DIR)/sie.elf
tests += $(TEST_DIR)/mvpg.elf
tests += $(TEST_DIR)/uv-host.elf
tests += $(TEST_DIR)/edat.elf
tests += $(TEST_DIR)/mvpg-sie.elf

tests_binary = $(patsubst %.elf,%.bin,$(tests))
ifneq ($(HOST_KEY_DOCUMENT),)
tests_pv_binary = $(patsubst %.bin,%.pv.bin,$(tests_binary))
else
tests_pv_binary =
endif

all: directories test_cases test_cases_binary test_cases_pv

test_cases: $(tests)
test_cases_binary: $(tests_binary)
test_cases_pv: $(tests_pv_binary)

CFLAGS += -std=gnu99
CFLAGS += -ffreestanding
CFLAGS += -I $(SRCDIR)/lib -I $(SRCDIR)/lib/s390x -I lib
CFLAGS += -O2
CFLAGS += -march=zEC12
CFLAGS += -mbackchain
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
cflatobjs += lib/s390x/malloc_io.o
cflatobjs += lib/s390x/uv.o
cflatobjs += lib/s390x/sie.o

OBJDIRS += lib/s390x

asmlib = $(TEST_DIR)/cstart64.o $(TEST_DIR)/cpu.o

FLATLIBS = $(libcflat)

SNIPPET_DIR = $(TEST_DIR)/snippets
snippet_asmlib = $(SNIPPET_DIR)/c/cstart.o

# perquisites (=guests) for the snippet hosts.
# $(TEST_DIR)/<snippet-host>.elf: snippets = $(SNIPPET_DIR)/<c/asm>/<snippet>.gbin
$(TEST_DIR)/mvpg-sie.elf: snippets = $(SNIPPET_DIR)/c/mvpg-snippet.gbin

$(SNIPPET_DIR)/asm/%.gbin: $(SNIPPET_DIR)/asm/%.o $(FLATLIBS)
	$(OBJCOPY) -O binary $(patsubst %.gbin,%.o,$@) $@
	$(OBJCOPY) -I binary -O elf64-s390 -B "s390:64-bit" $@ $@

$(SNIPPET_DIR)/c/%.gbin: $(SNIPPET_DIR)/c/%.o $(snippet_asmlib) $(FLATLIBS)
	$(CC) $(LDFLAGS) -o $@ -T $(SRCDIR)/s390x/snippets/c/flat.lds $(patsubst %.gbin,%.o,$@) $(snippet_asmlib) $(FLATLIBS)
	$(OBJCOPY) -O binary $@ $@
	$(OBJCOPY) -I binary -O elf64-s390 -B "s390:64-bit" $@ $@

.SECONDEXPANSION:
%.elf: $$(snippets) %.o $(FLATLIBS) $(SRCDIR)/s390x/flat.lds $(asmlib)
	$(CC) $(CFLAGS) -c -o $(@:.elf=.aux.o) $(SRCDIR)/lib/auxinfo.c -DPROGNAME=\"$@\"
	$(CC) $(LDFLAGS) -o $@ -T $(SRCDIR)/s390x/flat.lds $(filter %.o, $^) $(FLATLIBS) $(snippets) $(@:.elf=.aux.o)
	$(RM) $(@:.elf=.aux.o)
	@chmod a-x $@

%.bin: %.elf
	$(OBJCOPY) -O binary  $< $@

%selftest.pv.bin: %selftest.bin $(HOST_KEY_DOCUMENT) $(patsubst %.pv.bin,%.parmfile,$@)
	$(GENPROTIMG) --host-key-document $(HOST_KEY_DOCUMENT) --parmfile $(patsubst %.pv.bin,%.parmfile,$@) --no-verify --image $< -o $@

%.pv.bin: %.bin $(HOST_KEY_DOCUMENT)
	$(GENPROTIMG) --host-key-document $(HOST_KEY_DOCUMENT) --no-verify --image $< -o $@

arch_clean: asm_offsets_clean
	$(RM) $(TEST_DIR)/*.{o,elf,bin} $(TEST_DIR)/.*.d $(SNIPPET_DIR)/c/*.{o,gbin} $(SNIPPET_DIR)/c/.*.d lib/s390x/.*.d

generated-files = $(asm-offsets)
$(tests:.elf=.o) $(asmlib) $(cflatobjs): $(generated-files)
