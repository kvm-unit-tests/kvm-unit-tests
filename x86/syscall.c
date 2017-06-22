/* msr tests */

#include "libcflat.h"
#include "processor.h"
#include "msr.h"
#include "desc.h"

static void test_syscall_lazy_load(void)
{
    extern void syscall_target();
    u16 cs = read_cs(), ss = read_ss();
    ulong tmp;

    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | EFER_SCE);
    wrmsr(MSR_LSTAR, (ulong)syscall_target);
    wrmsr(MSR_STAR, (uint64_t)cs << 32);
    asm volatile("pushf; syscall; syscall_target: popf" : "=c"(tmp) : : "r11");
    write_ss(ss);
    // will crash horribly if broken
    report("MSR_*STAR eager loading", true);
}

int main(int ac, char **av)
{
    test_syscall_lazy_load();

    return report_summary();
}
