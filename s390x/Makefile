tests = $(TEST_DIR)/selftest.elf

all: directories test_cases

test_cases: $(tests)

CFLAGS += -std=gnu99
CFLAGS += -ffreestanding
CFLAGS += -Wextra
CFLAGS += -I $(SRCDIR)/lib
CFLAGS += -O2
CFLAGS += -march=z900
LDFLAGS += -nostdlib

# We want to keep intermediate files
.PRECIOUS: %.o

cflatobjs += lib/util.o
cflatobjs += lib/alloc.o
cflatobjs += lib/s390x/io.o
cflatobjs += lib/s390x/stack.o

OBJDIRS += lib/s390x

cstart.o = $(TEST_DIR)/cstart64.o

FLATLIBS = $(libcflat)
%.elf: %.o $(FLATLIBS) $(SRCDIR)/s390x/flat.lds $(cstart.o)
	$(CC) $(CFLAGS) -c -o $(@:.elf=.aux.o) \
		$(SRCDIR)/lib/auxinfo.c -DPROGNAME=\"$@\"
	$(CC) $(LDFLAGS) -o $@ -T $(SRCDIR)/s390x/flat.lds -Ttext=0x10000 \
		$(filter %.o, $^) $(FLATLIBS) $(@:.elf=.aux.o)
	$(RM) $(@:.elf=.aux.o)

arch_clean:
	$(RM) $(TEST_DIR)/*.{o,elf} $(TEST_DIR)/.*.d lib/s390x/.*.d
