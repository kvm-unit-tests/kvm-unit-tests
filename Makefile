
SHELL := /bin/bash

ifeq ($(wildcard config.mak),)
$(error run ./configure first. See ./configure -h)
endif

include config.mak

DESTDIR := $(PREFIX)/share/kvm-unit-tests/

.PHONY: arch_clean clean distclean cscope

#make sure env CFLAGS variable is not used
CFLAGS =

libgcc := $(shell $(CC) --print-libgcc-file-name)

libcflat := lib/libcflat.a
cflatobjs := \
	lib/argv.o \
	lib/printf.o \
	lib/string.o \
	lib/abort.o \
	lib/report.o

# libfdt paths
LIBFDT_objdir = lib/libfdt
LIBFDT_srcdir = lib/libfdt
LIBFDT_archive = $(LIBFDT_objdir)/libfdt.a
LIBFDT_include = $(addprefix $(LIBFDT_srcdir)/,$(LIBFDT_INCLUDES))
LIBFDT_version = $(addprefix $(LIBFDT_srcdir)/,$(LIBFDT_VERSION))

#include architecure specific make rules
include $(TEST_DIR)/Makefile

# cc-option
# Usage: OP_CFLAGS+=$(call cc-option, -falign-functions=0, -malign-functions=0)

cc-option = $(shell if $(CC) $(1) -S -o /dev/null -xc /dev/null \
              > /dev/null 2>&1; then echo "$(1)"; else echo "$(2)"; fi ;)

CFLAGS += -g
CFLAGS += $(autodepend-flags) -Wall -Werror

fomit_frame_pointer := $(call cc-option, -fomit-frame-pointer, "")
fnostack_protector := $(call cc-option, -fno-stack-protector, "")
fnostack_protector_all := $(call cc-option, -fno-stack-protector-all, "")
CFLAGS += $(fomit_frame_pointer)
CFLAGS += $(fno_stack_protector)
CFLAGS += $(fno_stack_protector_all)

CXXFLAGS += $(CFLAGS)

autodepend-flags = -MMD -MF $(dir $*).$(notdir $*).d

LDFLAGS += $(CFLAGS)
LDFLAGS += -pthread -lrt

$(libcflat): $(cflatobjs)
	$(AR) rcs $@ $^

include $(LIBFDT_srcdir)/Makefile.libfdt
$(LIBFDT_archive): CFLAGS += -ffreestanding -I lib -I lib/libfdt -Wno-sign-compare
$(LIBFDT_archive): $(addprefix $(LIBFDT_objdir)/,$(LIBFDT_OBJS))
	$(AR) rcs $@ $^

%.o: %.S
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $<

-include */.*.d */*/.*.d

all: $(shell git rev-parse --verify --short=8 HEAD >build-head 2>/dev/null)

standalone: all
	@scripts/mkstandalone.sh

install: standalone
	mkdir -p $(DESTDIR)
	install tests/* $(DESTDIR)

clean: arch_clean
	$(RM) lib/.*.d $(libcflat) $(cflatobjs)

libfdt_clean:
	$(RM) $(LIBFDT_archive) \
	$(addprefix $(LIBFDT_objdir)/,$(LIBFDT_OBJS)) \
	$(LIBFDT_objdir)/.*.d

distclean: clean libfdt_clean
	$(RM) lib/asm config.mak $(TEST_DIR)-run test.log msr.out cscope.*
	$(RM) -r tests

cscope: cscope_dirs = lib lib/libfdt lib/linux
cscope: cscope_dirs += lib/$(ARCH)/asm lib/$(TEST_DIR)/asm lib/asm-generic
cscope: cscope_dirs += $(TEST_DIR) lib/$(TEST_DIR) lib/$(ARCH)
cscope:
	$(RM) ./cscope.*
	find -L $(cscope_dirs) -maxdepth 1 \
		-name '*.[chsS]' -print | sed 's,^\./,,' | sort -u > ./cscope.files
	cscope -bk
