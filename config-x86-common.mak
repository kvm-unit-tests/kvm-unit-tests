#This is a make file with common rules for both x86 & x86-64

CFLAGS += -I../include/x86

all: test_cases

cflatobjs += \
	lib/x86/io.o \
	lib/x86/smp.o

cflatobjs += lib/x86/fwcfg.o
cflatobjs += lib/x86/apic.o
cflatobjs += lib/x86/atomic.o

$(libcflat): LDFLAGS += -nostdlib
$(libcflat): CFLAGS += -ffreestanding -I lib

CFLAGS += -m$(bits)

libgcc := $(shell $(CC) -m$(bits) --print-libgcc-file-name)

FLATLIBS = lib/libcflat.a $(libgcc)
%.elf: %.o $(FLATLIBS) flat.lds
	$(CC) $(CFLAGS) -nostdlib -o $@ -Wl,-T,flat.lds $(filter %.o, $^) $(FLATLIBS)

%.flat: %.elf
	objcopy -O elf32-i386 $^ $@

tests-common = $(TEST_DIR)/vmexit.flat $(TEST_DIR)/tsc.flat \
               $(TEST_DIR)/smptest.flat  $(TEST_DIR)/port80.flat \
               $(TEST_DIR)/realmode.flat $(TEST_DIR)/msr.flat \
               $(TEST_DIR)/hypercall.flat $(TEST_DIR)/sieve.flat \
               $(TEST_DIR)/kvmclock_test.flat

tests-common += api/api-sample

tests_and_config = $(TEST_DIR)/*.flat $(TEST_DIR)/unittests.cfg

test_cases: $(tests-common) $(tests)

$(TEST_DIR)/%.o: CFLAGS += -std=gnu99 -ffreestanding -I lib -I lib/x86

$(TEST_DIR)/access.elf: $(cstart.o) $(TEST_DIR)/access.o

$(TEST_DIR)/hypercall.elf: $(cstart.o) $(TEST_DIR)/hypercall.o

$(TEST_DIR)/sieve.elf: $(cstart.o) $(TEST_DIR)/sieve.o \
		$(TEST_DIR)/vm.o

$(TEST_DIR)/vmexit.elf: $(cstart.o) $(TEST_DIR)/vmexit.o

$(TEST_DIR)/smptest.elf: $(cstart.o) $(TEST_DIR)/smptest.o

$(TEST_DIR)/emulator.elf: $(cstart.o) $(TEST_DIR)/emulator.o \
			   $(TEST_DIR)/vm.o $(TEST_DIR)/idt.o

$(TEST_DIR)/port80.elf: $(cstart.o) $(TEST_DIR)/port80.o

$(TEST_DIR)/tsc.elf: $(cstart.o) $(TEST_DIR)/tsc.o

$(TEST_DIR)/apic.elf: $(cstart.o) $(TEST_DIR)/apic.o $(TEST_DIR)/vm.o

$(TEST_DIR)/realmode.elf: $(TEST_DIR)/realmode.o
	$(CC) -m32 -nostdlib -o $@ -Wl,-T,$(TEST_DIR)/realmode.lds $^

$(TEST_DIR)/realmode.o: bits = 32

$(TEST_DIR)/msr.elf: $(cstart.o) $(TEST_DIR)/msr.o

$(TEST_DIR)/idt_test.elf: $(cstart.o) $(TEST_DIR)/idt.o $(TEST_DIR)/idt_test.o

$(TEST_DIR)/xsave.elf: $(cstart.o) $(TEST_DIR)/idt.o $(TEST_DIR)/xsave.o

$(TEST_DIR)/rmap_chain.elf: $(cstart.o) $(TEST_DIR)/rmap_chain.o \
			     $(TEST_DIR)/vm.o

$(TEST_DIR)/svm.elf: $(cstart.o) $(TEST_DIR)/vm.o

$(TEST_DIR)/kvmclock_test.elf: $(cstart.o) $(TEST_DIR)/kvmclock.o \
                                $(TEST_DIR)/kvmclock_test.o

arch_clean:
	$(RM) $(TEST_DIR)/*.o $(TEST_DIR)/*.flat $(TEST_DIR)/*.elf \
	$(TEST_DIR)/.*.d $(TEST_DIR)/lib/.*.d $(TEST_DIR)/lib/*.o

api/%.o: CFLAGS += -m32

api/api-sample: LDLIBS += -lstdc++
api/api-sample: LDFLAGS += -m32

api/api-sample: api/api-sample.o api/kvmxx.o api/identity.o api/exception.o
