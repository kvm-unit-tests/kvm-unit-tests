/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _ASMRISCV_ISA_H_
#define _ASMRISCV_ISA_H_
#include <bitops.h>
#include <asm/setup.h>

/*
 * We assume and use several extensions, such as Zicsr and Zifencei.
 * Here we only track extensions which we don't assume and the
 * framework may want to use. Unit tests may check for extensions
 * by name not tracked here with cpu_has_extension_name()
 */
enum {
	ISA_SSTC,
	ISA_MAX,
};
_Static_assert(ISA_MAX <= __riscv_xlen, "Need to increase thread_info.isa");

static inline bool cpu_has_extension(int cpu, int ext)
{
	return test_bit(ext, cpus[cpu].isa);
}

bool cpu_has_extension_name(int cpu, const char *ext);

static inline bool has_ext(const char *ext)
{
	return cpu_has_extension_name(current_thread_info()->cpu, ext);
}

void isa_init(struct thread_info *info);

#endif /* _ASMRISCV_ISA_H_ */
