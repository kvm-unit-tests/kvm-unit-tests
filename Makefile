
ifeq ($(wildcard config.mak),)
$(error run ./configure first. See ./configure -h)
endif

include config.mak

DESTDIR := $(PREFIX)/share/qemu/tests

.PHONY: arch_clean clean distclean

#make sure env CFLAGS variable is not used
CFLAGS =

libgcc := $(shell $(CC) --print-libgcc-file-name)

libcflat := lib/libcflat.a
cflatobjs := \
	lib/argv.o \
	lib/printf.o \
	lib/string.o \
	lib/report.o

#include architecure specific make rules
include config/config-$(ARCH).mak

# cc-option
# Usage: OP_CFLAGS+=$(call cc-option, -falign-functions=0, -malign-functions=0)

cc-option = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
              > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi ;)

CFLAGS += -g
CFLAGS += $(autodepend-flags) -Wall
CFLAGS += $(call cc-option, -fomit-frame-pointer, "")
CFLAGS += $(call cc-option, -fno-stack-protector, "")
CFLAGS += $(call cc-option, -fno-stack-protector-all, "")

CXXFLAGS += $(CFLAGS)

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

LDFLAGS += $(CFLAGS)
LDFLAGS += -pthread -lrt

$(libcflat): $(cflatobjs)
	$(AR) rcs $@ $^

%.o: %.S
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $<

-include */.*.d */*/.*.d

install:
	mkdir -p $(DESTDIR)
	install $(tests_and_config) $(DESTDIR)

clean: arch_clean
	$(RM) lib/.*.d $(libcflat) $(cflatobjs)

distclean: clean
	$(RM) config.mak $(TEST_DIR)-run test.log msr.out
