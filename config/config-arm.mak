#
# arm makefile
#
# Authors: Andrew Jones <drjones@redhat.com>
#

tests-common = \
	$(TEST_DIR)/selftest.flat

tests =

all: test_cases

##################################################################
bits = 32
ldarch = elf32-littlearm

ifeq ($(LOADADDR),)
	LOADADDR = 0x40000000
endif
phys_base = $(LOADADDR)
kernel_offset = 0x10000

CFLAGS += -D__arm__
CFLAGS += -marm
CFLAGS += -mcpu=$(PROCESSOR)
CFLAGS += -std=gnu99
CFLAGS += -ffreestanding
CFLAGS += -Wextra
CFLAGS += -O2
CFLAGS += -I lib -I lib/libfdt

asm-offsets = lib/arm/asm-offsets.h
include config/asm-offsets.mak

cflatobjs += \
	lib/alloc.o \
	lib/devicetree.o \
	lib/virtio.o \
	lib/virtio-mmio.o \
	lib/chr-testdev.o \
	lib/arm/io.o \
	lib/arm/setup.o \
	lib/arm/spinlock.o \
	lib/arm/processor.o

libeabi = lib/arm/libeabi.a
eabiobjs = lib/arm/eabi_compat.o

libgcc := $(shell $(CC) -m$(ARCH) --print-libgcc-file-name)
start_addr := $(shell printf "%x\n" $$(( $(phys_base) + $(kernel_offset) )))

FLATLIBS = $(libcflat) $(LIBFDT_archive) $(libgcc) $(libeabi)
%.elf: LDFLAGS = $(CFLAGS) -nostdlib
%.elf: %.o $(FLATLIBS) arm/flat.lds
	$(CC) $(LDFLAGS) -o $@ \
		-Wl,-T,arm/flat.lds,--build-id=none,-Ttext=$(start_addr) \
		$(filter %.o, $^) $(FLATLIBS)

%.flat: %.elf
	$(OBJCOPY) -O binary $^ $@

$(libeabi): $(eabiobjs)
	$(AR) rcs $@ $^

arch_clean: libfdt_clean asm_offsets_clean
	$(RM) $(TEST_DIR)/*.{o,flat,elf} $(libeabi) $(eabiobjs) \
	      $(TEST_DIR)/.*.d lib/arm/.*.d

##################################################################

tests_and_config = $(TEST_DIR)/*.flat $(TEST_DIR)/unittests.cfg

cstart.o = $(TEST_DIR)/cstart.o

generated_files = $(asm-offsets)

test_cases: $(generated_files) $(tests-common) $(tests)

$(TEST_DIR)/selftest.elf: $(cstart.o) $(TEST_DIR)/selftest.o

