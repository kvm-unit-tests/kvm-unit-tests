# the asm/c snippets %.o have additional generated files as dependencies
$(SNIPPET_DIR)/asm/%.o: $(SNIPPET_SRC_DIR)/asm/%.S $(asm-offsets)
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $<

$(SNIPPET_DIR)/c/%.o: SNIPPET_INCLUDE := $(SNIPPET_SRC_DIR)/lib
$(SNIPPET_DIR)/c/%.o: $(SNIPPET_SRC_DIR)/c/%.c $(asm-offsets)
	$(CC) $(CFLAGS) -c -nostdlib -o $@ $<

$(SNIPPET_DIR)/asm/%.elf: $(SNIPPET_DIR)/asm/%.o $(SNIPPET_DIR)/asm/flat.lds
	$(CC) $(LDFLAGS) -o $@ -T $(SNIPPET_SRC_DIR)/asm/flat.lds $<

$(SNIPPET_DIR)/asm/%.gbin: $(SNIPPET_DIR)/asm/%.elf
	$(OBJCOPY) -O binary -j ".rodata" -j ".lowcore" -j ".text" -j ".data" -j ".bss" --set-section-flags .bss=alloc,load,contents $< $@
	truncate -s '%4096' $@

$(SNIPPET_DIR)/c/%.elf: $(SNIPPET_DIR)/c/%.o $(snippet_lib) $(FLATLIBS) $(SNIPPET_DIR)/c/flat.lds
	$(CC) $(LDFLAGS) -o $@ -T $(SNIPPET_DIR)/c/flat.lds $< $(snippet_lib) $(FLATLIBS)

$(SNIPPET_DIR)/c/%.gbin: $(SNIPPET_DIR)/c/%.elf
	$(OBJCOPY) -O binary -j ".rodata" -j ".lowcore" -j ".text" -j ".data" -j ".bss" --set-section-flags .bss=alloc,load,contents $< $@
	truncate -s '%4096' $@

%.hdr: %.gbin $(HOST_KEY_DOCUMENT)
	$(GEN_SE_HEADER) -k $(HOST_KEY_DOCUMENT) -c $<,0x0,0x00000000000000420000000000000000 --psw-addr 0x4000 -o $@

.SECONDARY:
%.gobj: %.gbin
	$(OBJCOPY) -I binary -O elf64-s390 -B "s390:64-bit" $< $@

.SECONDARY:
%.hdr.obj: %.hdr
	$(OBJCOPY) -I binary -O elf64-s390 -B "s390:64-bit" $< $@

snippet_clean:
	$(RM) $(SNIPPET_DIR)/*/*.{o,elf,*bin,*obj,hdr,lds} $(SNIPPET_DIR)/asm/.*.d
