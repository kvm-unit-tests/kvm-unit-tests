
include config.mak

DESTDIR := $(PREFIX)/share/qemu/tests

.PHONY: arch_clean clean

#make sure env CFLAGS variable is not used
CFLAGS = -g

libgcc := $(shell $(CC) --print-libgcc-file-name)

libcflat := lib/libcflat.a
cflatobjs := \
	lib/printf.o \
	lib/string.o \
	lib/report.o
cflatobjs += lib/argv.o

#include architecure specific make rules
include config-$(ARCH).mak

# cc-option
# Usage: OP_CFLAGS+=$(call cc-option, -falign-functions=0, -malign-functions=0)

cc-option = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
              > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi ;)

CFLAGS += -O1
CFLAGS += $(autodepend-flags) -g -fomit-frame-pointer -Wall
CFLAGS += $(call cc-option, -fno-stack-protector, "")
CFLAGS += $(call cc-option, -fno-stack-protector-all, "")
CFLAGS += -I.

CXXFLAGS += $(CFLAGS)

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

LDFLAGS += $(CFLAGS)
LDFLAGS += -pthread -lrt

$(libcflat): $(cflatobjs)
	$(AR) rcs $@ $^

%.o: %.S
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $<

-include .*.d */.*.d */*/.*.d

install:
	mkdir -p $(DESTDIR)
	install $(tests_and_config) $(DESTDIR)

clean: arch_clean
	$(RM) *.o *.a .*.d $(libcflat) $(cflatobjs)
