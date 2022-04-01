tests = $(TEST_DIR)/selftest.elf
tests += $(TEST_DIR)/intercept.elf
tests += $(TEST_DIR)/emulator.elf
tests += $(TEST_DIR)/sieve.elf
tests += $(TEST_DIR)/sthyi.elf
tests += $(TEST_DIR)/tprot.elf
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
tests += $(TEST_DIR)/sck.elf
tests += $(TEST_DIR)/css.elf
tests += $(TEST_DIR)/uv-guest.elf
tests += $(TEST_DIR)/sie.elf
tests += $(TEST_DIR)/mvpg.elf
tests += $(TEST_DIR)/uv-host.elf
tests += $(TEST_DIR)/edat.elf
tests += $(TEST_DIR)/mvpg-sie.elf
tests += $(TEST_DIR)/spec_ex-sie.elf
tests += $(TEST_DIR)/firq.elf
tests += $(TEST_DIR)/epsw.elf

pv-tests += $(TEST_DIR)/pv-diags.elf

ifneq ($(HOST_KEY_DOCUMENT),)
ifneq ($(GEN_SE_HEADER),)
tests += $(pv-tests)
endif
endif

tests_binary = $(patsubst %.elf,%.bin,$(tests))
ifneq ($(HOST_KEY_DOCUMENT),)
tests_pv_binary = $(patsubst %.bin,%.pv.bin,$(tests_binary))
else
tests_pv_binary =
GEN_SE_HEADER =
endif
snippets-obj = $(patsubst %.gbin,%.gobj,$(snippets))

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
cflatobjs += lib/s390x/hardware.o
cflatobjs += lib/s390x/css_dump.o
cflatobjs += lib/s390x/css_lib.o
cflatobjs += lib/s390x/malloc_io.o
cflatobjs += lib/s390x/uv.o
cflatobjs += lib/s390x/sie.o
cflatobjs += lib/s390x/fault.o

OBJDIRS += lib/s390x

asmlib = $(TEST_DIR)/cstart64.o $(TEST_DIR)/cpu.o

FLATLIBS = $(libcflat)

SNIPPET_DIR = $(TEST_DIR)/snippets
snippet_asmlib = $(SNIPPET_DIR)/c/cstart.o
snippet_lib = $(snippet_asmlib) lib/auxinfo.o

# perquisites (=guests) for the snippet hosts.
# $(TEST_DIR)/<snippet-host>.elf: snippets = $(SNIPPET_DIR)/<c/asm>/<snippet>.gbin
$(TEST_DIR)/mvpg-sie.elf: snippets = $(SNIPPET_DIR)/c/mvpg-snippet.gbin
$(TEST_DIR)/spec_ex-sie.elf: snippets = $(SNIPPET_DIR)/c/spec_ex.gbin

$(TEST_DIR)/pv-diags.elf: pv-snippets += $(SNIPPET_DIR)/asm/snippet-pv-diag-yield.gbin
$(TEST_DIR)/pv-diags.elf: pv-snippets += $(SNIPPET_DIR)/asm/snippet-pv-diag-288.gbin
$(TEST_DIR)/pv-diags.elf: pv-snippets += $(SNIPPET_DIR)/asm/snippet-pv-diag-500.gbin

ifneq ($(GEN_SE_HEADER),)
snippets += $(pv-snippets)
tests += $(pv-tests)
snippet-hdr-obj = $(patsubst %.gbin,%.hdr.obj,$(pv-snippets))
else
snippet-hdr-obj =
endif

# the asm/c snippets %.o have additional generated files as dependencies
$(SNIPPET_DIR)/asm/%.o: $(SNIPPET_DIR)/asm/%.S $(asm-offsets)
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $<

$(SNIPPET_DIR)/c/%.o: $(SNIPPET_DIR)/c/%.c $(asm-offsets)
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $<

$(SNIPPET_DIR)/asm/%.gbin: $(SNIPPET_DIR)/asm/%.o
	$(OBJCOPY) -O binary -j ".rodata" -j ".text" -j ".data" -j ".bss" --set-section-flags .bss=alloc,load,contents $(patsubst %.gbin,%.o,$@) $@
	truncate -s '%4096' $@

$(SNIPPET_DIR)/c/%.gbin: $(SNIPPET_DIR)/c/%.o $(snippet_lib) $(FLATLIBS)
	$(CC) $(LDFLAGS) -o $@ -T $(SRCDIR)/s390x/snippets/c/flat.lds $(patsubst %.gbin,%.o,$@) $(snippet_lib) $(FLATLIBS)
	$(OBJCOPY) -O binary -j ".rodata" -j ".lowcore" -j ".text" -j ".data" -j ".bss" --set-section-flags .bss=alloc,load,contents $@ $@
	truncate -s '%4096' $@

$(SNIPPET_DIR)/asm/%.hdr: $(SNIPPET_DIR)/asm/%.gbin $(HOST_KEY_DOCUMENT)
	$(GEN_SE_HEADER) -k $(HOST_KEY_DOCUMENT) -c $<,0x4000,0x00000000000000420000000000000000 --psw-addr 0x4000 -o $@

$(SNIPPET_DIR)/c/%.hdr: $(SNIPPET_DIR)/c/%.gbin $(HOST_KEY_DOCUMENT)
	$(GEN_SE_HEADER) -k $(HOST_KEY_DOCUMENT) -c $<,0x0,0x00000000000000420000000000000000 --psw-addr 0x4000 -o $@

.SECONDARY:
%.gobj: %.gbin
	$(OBJCOPY) -I binary -O elf64-s390 -B "s390:64-bit" $< $@

.SECONDARY:
%.hdr.obj: %.hdr
	$(OBJCOPY) -I binary -O elf64-s390 -B "s390:64-bit" $< $@


.SECONDEXPANSION:
%.elf: $(FLATLIBS) $(asmlib) $(SRCDIR)/s390x/flat.lds $$(snippets-obj) $$(snippet-hdr-obj) %.o
	$(CC) $(CFLAGS) -c -o $(@:.elf=.aux.o) $(SRCDIR)/lib/auxinfo.c -DPROGNAME=\"$@\"
	@$(CC) $(LDFLAGS) -o $@ -T $(SRCDIR)/s390x/flat.lds \
		$(filter %.o, $^) $(FLATLIBS) $(snippets-obj) $(snippet-hdr-obj) $(@:.elf=.aux.o) || \
		{ echo "Failure probably caused by missing definition of gen-se-header executable"; exit 1; }
	$(RM) $(@:.elf=.aux.o)
	@chmod a-x $@

%.bin: %.elf
	$(OBJCOPY) -O binary  $< $@

%selftest.pv.bin: %selftest.bin $(HOST_KEY_DOCUMENT) $(patsubst %.pv.bin,%.parmfile,$@)
	$(GENPROTIMG) --host-key-document $(HOST_KEY_DOCUMENT) --parmfile $(patsubst %.pv.bin,%.parmfile,$@) --no-verify --image $< -o $@

%.pv.bin: %.bin $(HOST_KEY_DOCUMENT)
	$(GENPROTIMG) --host-key-document $(HOST_KEY_DOCUMENT) --no-verify --image $< -o $@

$(snippet_asmlib): $$(patsubst %.o,%.S,$$@) $(asm-offsets)
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $<


arch_clean: asm_offsets_clean
	$(RM) $(TEST_DIR)/*.{o,elf,bin} $(SNIPPET_DIR)/*/*.{o,elf,*bin,*obj,hdr} $(SNIPPET_DIR)/asm/.*.d $(TEST_DIR)/.*.d lib/s390x/.*.d

generated-files = $(asm-offsets)
$(tests:.elf=.o) $(asmlib) $(cflatobjs): $(generated-files)
