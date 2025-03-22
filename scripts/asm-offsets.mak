#
# asm-offsets adapted from the kernel, see
#   Kbuild
#   scripts/Kbuild.include
#   scripts/Makefile.build
#
#   Authors: Andrew Jones <drjones@redhat.com>
#

define sed-y
	's:^[[:space:]]*\.ascii[[:space:]]*"\(.*\)".*:\1:; \
	/^->/{s:->#\(.*\):/* \1 */:; \
	s:^->\([^ ]*\) [\$$#]*\([-0-9]*\) \(.*\):#define \1 \2 /* \3 */:; \
	s:^->\([^ ]*\) [\$$#]*\([^ ]*\) \(.*\):#define \1 \2 /* \3 */:; \
	s:->::; p;}'
endef

define asm_offset_name
	$(shell echo $(notdir $(1)) | tr [:lower:]- [:upper:]_)
endef

define make_asm_offsets
	(set -e; \
	 echo "#ifndef __$(strip $(asm_offset_name))_H__"; \
	 echo "#define __$(strip $(asm_offset_name))_H__"; \
	 echo "/*"; \
	 echo " * Generated file. DO NOT MODIFY."; \
	 echo " *"; \
	 echo " */"; \
	 echo ""; \
	 sed -ne $(sed-y) $<; \
	 echo ""; \
	 echo "#endif" ) > $@
endef

define gen_asm_offsets_rules
$(1).s: $(1).c
	$(CC) $(CFLAGS) -fverbose-asm -S -o $$@ $$<

$(1).h: $(1).s
	$$(call make_asm_offsets,$(1))
	cp -f $$@ lib/generated/
endef

$(foreach o,$(asm-offsets),$(eval $(call gen_asm_offsets_rules, $(o:.h=))))

OBJDIRS += lib/generated

asm_offsets_clean:
	$(RM) $(asm-offsets) $(asm-offsets:.h=.s) \
	      $(addprefix lib/generated/,$(notdir $(asm-offsets)))

