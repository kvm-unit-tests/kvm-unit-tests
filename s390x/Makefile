tests = $(TEST_DIR)/selftest.elf
tests += $(TEST_DIR)/selftest-migration.elf
tests += $(TEST_DIR)/memory-verify.elf
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
tests += $(TEST_DIR)/spec_ex.elf
tests += $(TEST_DIR)/firq.elf
tests += $(TEST_DIR)/epsw.elf
tests += $(TEST_DIR)/adtl-status.elf
tests += $(TEST_DIR)/migration.elf
tests += $(TEST_DIR)/pv-attest.elf
tests += $(TEST_DIR)/migration-cmm.elf
tests += $(TEST_DIR)/migration-skey.elf
tests += $(TEST_DIR)/panic-loop-extint.elf
tests += $(TEST_DIR)/panic-loop-pgm.elf
tests += $(TEST_DIR)/migration-sck.elf
tests += $(TEST_DIR)/exittime.elf
tests += $(TEST_DIR)/ex.elf
tests += $(TEST_DIR)/topology.elf
tests += $(TEST_DIR)/sie-dat.elf
tests += $(TEST_DIR)/diag258.elf
tests += $(TEST_DIR)/stfle-sie.elf

pv-tests += $(TEST_DIR)/pv-diags.elf
pv-tests += $(TEST_DIR)/pv-icptcode.elf
pv-tests += $(TEST_DIR)/pv-ipl.elf

# Add PV host tests if we're able to generate them
# The host key document and a tool to generate SE headers are the prerequisite
ifneq ($(HOST_KEY_DOCUMENT),)
ifneq ($(GEN_SE_HEADER),)
tests += $(pv-tests)
endif
endif

# Add binary flat images for use in non-KVM hypervisors
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

SNIPPET_INCLUDE :=
INCLUDE_PATHS = $(SNIPPET_INCLUDE) $(SRCDIR)/lib $(SRCDIR)/lib/s390x $(SRCDIR)/s390x
# Include generated header files (e.g. in case of out-of-source builds)
INCLUDE_PATHS += lib
CPPFLAGS = $(addprefix -I,$(INCLUDE_PATHS))

CFLAGS += -std=gnu99
CFLAGS += -ffreestanding
CFLAGS += $(CPPFLAGS)
CFLAGS += -O2
CFLAGS += -march=zEC12
CFLAGS += -mbackchain
CFLAGS += -fno-delete-null-pointer-checks
LDFLAGS += -Wl,--build-id=none

# We want to keep intermediate files
.PRECIOUS: %.o %.lds

asm-offsets = lib/$(ARCH)/asm-offsets.h
include $(SRCDIR)/scripts/asm-offsets.mak

cflatobjs += lib/auxinfo.o
cflatobjs += lib/util.o
cflatobjs += lib/alloc.o
cflatobjs += lib/alloc_phys.o
cflatobjs += lib/alloc_page.o
cflatobjs += lib/vmalloc.o
cflatobjs += lib/alloc_phys.o
cflatobjs += lib/getchar.o
cflatobjs += lib/migrate.o
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
cflatobjs += lib/s390x/sie-icpt.o
cflatobjs += lib/s390x/fault.o

OBJDIRS += lib/s390x

asmlib = $(TEST_DIR)/cstart64.o $(TEST_DIR)/cpu.o $(TEST_DIR)/cpu-sie.o

FLATLIBS = $(libcflat)

# Snippets
SNIPPET_DIR = $(TEST_DIR)/snippets
SNIPPET_SRC_DIR = $(SRCDIR)/s390x/snippets
snippet_asmlib = $(SNIPPET_DIR)/c/cstart.o
snippet_lib = $(snippet_asmlib) lib/auxinfo.o
include $(SNIPPET_SRC_DIR)/Makefile

# perquisites (=guests) for the snippet hosts.
# $(TEST_DIR)/<snippet-host>.elf: snippets = $(SNIPPET_DIR)/<c/asm>/<snippet>.gbin
$(TEST_DIR)/mvpg-sie.elf: snippets = $(SNIPPET_DIR)/c/mvpg-snippet.gbin
$(TEST_DIR)/sie-dat.elf: snippets = $(SNIPPET_DIR)/c/sie-dat.gbin
$(TEST_DIR)/spec_ex-sie.elf: snippets = $(SNIPPET_DIR)/c/spec_ex.gbin
$(TEST_DIR)/stfle-sie.elf: snippets = $(SNIPPET_DIR)/c/stfle.gbin

$(TEST_DIR)/pv-diags.elf: pv-snippets += $(SNIPPET_DIR)/asm/pv-diag-yield.gbin
$(TEST_DIR)/pv-diags.elf: pv-snippets += $(SNIPPET_DIR)/asm/pv-diag-288.gbin
$(TEST_DIR)/pv-diags.elf: pv-snippets += $(SNIPPET_DIR)/asm/pv-diag-500.gbin
$(TEST_DIR)/pv-icptcode.elf: pv-snippets += $(SNIPPET_DIR)/asm/pv-icpt-112.gbin
$(TEST_DIR)/pv-icptcode.elf: pv-snippets += $(SNIPPET_DIR)/asm/icpt-loop.gbin
$(TEST_DIR)/pv-icptcode.elf: pv-snippets += $(SNIPPET_DIR)/asm/loop.gbin
$(TEST_DIR)/pv-icptcode.elf: pv-snippets += $(SNIPPET_DIR)/asm/pv-icpt-vir-timing.gbin
$(TEST_DIR)/pv-ipl.elf: pv-snippets += $(SNIPPET_DIR)/asm/pv-diag-308.gbin

# Add PV tests and snippets if GEN_SE_HEADER is set
ifneq ($(GEN_SE_HEADER),)
snippets += $(pv-snippets)
tests += $(pv-tests)
snippet-hdr-obj = $(patsubst %.gbin,%.hdr.obj,$(pv-snippets))
else
snippet-hdr-obj =
endif

# Generate loader script
lds-autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d -MT $@
%.lds: %.lds.S $(asm-offsets)
	$(CPP) $(lds-autodepend-flags) $(CPPFLAGS) -P -C -o $@ $<

%.aux.o: $(SRCDIR)/lib/auxinfo.c
	$(CC) $(CFLAGS) -c -o $@ $< -DPROGNAME=\"$(@:.aux.o=.elf)\"

.SECONDEXPANSION:
%.elf: $(FLATLIBS) $(asmlib) $(TEST_DIR)/flat.lds $$(snippets-obj) $$(snippet-hdr-obj) %.o %.aux.o
	@$(CC) $(LDFLAGS) -o $@ -T $(TEST_DIR)/flat.lds \
		$(filter %.o, $^) $(FLATLIBS) $(snippets-obj) $(snippet-hdr-obj) || \
		{ echo "Failure probably caused by missing definition of gen-se-header executable"; exit 1; }
	@chmod a-x $@

# Secure Execution Customer Communication Key file
# 32 bytes of key material, uses existing one if available
comm-key = $(TEST_DIR)/comm.key
$(comm-key):
	dd if=/dev/urandom of=$@ bs=32 count=1 status=none

%.bin: %.elf
	$(OBJCOPY) -O binary  $< $@

define test_genprotimg_opt
$(shell $(GENPROTIMG) --help | grep -q -- "$1" && echo yes || echo no)
endef

GENPROTIMG_DEFAULT_ARGS := --no-verify
ifneq ($(HOST_KEY_DOCUMENT),)
# The genprotimg arguments for the cck changed over time so we need to
# figure out which argument to use in order to set the cck
ifeq ($(call test_genprotimg_opt,--comm-key),yes)
	GENPROTIMG_COMM_OPTION := --comm-key
else
	GENPROTIMG_COMM_OPTION := --x-comm-key
endif
# Newer version of the genprotimg command checks if the given image/kernel is a
# s390x Linux kernel and it does not overwrite the output file by default.
# Disable the component check, since a KUT test is being prepared, and always
# overwrite the output.
ifeq ($(call test_genprotimg_opt,--overwrite),yes)
	GENPROTIMG_DEFAULT_ARGS += --overwrite --no-component-check
endif
endif

ifeq ($(CONFIG_DUMP),yes)
	# allow dumping + PCKMO
	GENPROTIMG_PCF := 0x200000e0
else
	# allow PCKMO
	GENPROTIMG_PCF := 0x000000e0
endif

$(patsubst %.parmfile,%.pv.bin,$(wildcard s390x/*.parmfile)): %.pv.bin: %.parmfile
%.pv.bin: %.bin $(HOST_KEY_DOCUMENT) $(comm-key)
	$(eval parmfile_args = $(if $(filter %.parmfile,$^),--parmfile $(filter %.parmfile,$^),))
	$(GENPROTIMG) $(GENPROTIMG_DEFAULT_ARGS) --host-key-document $(HOST_KEY_DOCUMENT) $(GENPROTIMG_COMM_OPTION) $(comm-key) --x-pcf $(GENPROTIMG_PCF) $(parmfile_args) --image $(filter %.bin,$^) -o $@

$(snippet_asmlib): $$(patsubst %.o,%.S,$$@) $(asm-offsets)
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $<


arch_clean: asm_offsets_clean snippet_clean
	$(RM) $(TEST_DIR)/*.{o,elf,bin,lds} $(TEST_DIR)/.*.d lib/s390x/.*.d $(comm-key)

generated-files = $(asm-offsets)
$(tests:.elf=.o) $(asmlib) $(cflatobjs): $(generated-files)
