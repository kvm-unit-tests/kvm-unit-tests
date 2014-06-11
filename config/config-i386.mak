cstart.o = $(TEST_DIR)/cstart.o
bits = 32
ldarch = elf32-i386
CFLAGS += -D__i386__
CFLAGS += -I $(KERNELDIR)/include

tests = $(TEST_DIR)/taskswitch.flat $(TEST_DIR)/taskswitch2.flat

include config/config-x86-common.mak

$(TEST_DIR)/taskswitch.elf: $(cstart.o) $(TEST_DIR)/taskswitch.o
$(TEST_DIR)/taskswitch2.elf: $(cstart.o) $(TEST_DIR)/taskswitch2.o
