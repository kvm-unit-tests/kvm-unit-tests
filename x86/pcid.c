/* Basic PCID & INVPCID functionality test */

#include "libcflat.h"
#include "processor.h"
#include "desc.h"

struct invpcid_desc {
    u64 pcid : 12;
    u64 rsv  : 52;
    u64 addr : 64;
};

static int invpcid_safe(unsigned long type, void *desc)
{
    asm volatile (ASM_TRY("1f")
                  ".byte 0x66,0x0f,0x38,0x82,0x18 \n\t" /* invpcid (%rax), %rbx */
                  "1:" : : "a" (desc), "b" (type));
    return exception_vector();
}

static void test_pcid_enabled(void)
{
    int passed = 0;
    ulong cr0 = read_cr0(), cr3 = read_cr3(), cr4 = read_cr4();

    /* try setting CR4.PCIDE, no exception expected */
    if (write_cr4_safe(cr4 | X86_CR4_PCIDE) != 0)
        goto report;

    /* try clearing CR0.PG when CR4.PCIDE=1, #GP expected */
    if (write_cr0_safe(cr0 & ~X86_CR0_PG) != GP_VECTOR)
        goto report;

    write_cr4(cr4);

    /* try setting CR4.PCIDE when CR3[11:0] != 0 , #GP expected */
    write_cr3(cr3 | 0x001);
    if (write_cr4_safe(cr4 | X86_CR4_PCIDE) != GP_VECTOR)
        goto report;
    write_cr3(cr3);

    passed = 1;

report:
    report(passed, "Test on PCID when enabled");
}

static void test_pcid_disabled(void)
{
    int passed = 0;
    ulong cr4 = read_cr4();

    /* try setting CR4.PCIDE, #GP expected */
    if (write_cr4_safe(cr4 | X86_CR4_PCIDE) != GP_VECTOR)
        goto report;

    passed = 1;

report:
    report(passed, "Test on PCID when disabled");
}

static void test_invpcid_enabled(int pcid_enabled)
{
    int passed = 0, i;
    ulong cr4 = read_cr4();
    struct invpcid_desc desc;

    memset(&desc, 0, sizeof(desc));

    /* try executing invpcid when CR4.PCIDE=0, desc.pcid=0 and type=0..3
     * no exception expected
     */
    for (i = 0; i < 4; i++) {
        if (invpcid_safe(i, &desc) != 0)
            goto report;
    }

    /* try executing invpcid when CR4.PCIDE=0, desc.pcid=1 and type=0..1
     * #GP expected
     */
    desc.pcid = 1;
    for (i = 0; i < 2; i++) {
        if (invpcid_safe(i, &desc) != GP_VECTOR)
            goto report;
    }

    /* Skip tests that require the PCIDE=1 if PCID isn't supported. */
    if (!pcid_enabled)
        goto success;

    if (write_cr4_safe(cr4 | X86_CR4_PCIDE) != 0)
        goto report;

    /* try executing invpcid when CR4.PCIDE=1
     * no exception expected
     */
    desc.pcid = 10;
    if (invpcid_safe(2, &desc) != 0)
        goto report;

success:
    passed = 1;

report:
    report(passed, "Test on INVPCID when enabled");
}

static void test_invpcid_disabled(void)
{
    int passed = 0;
    struct invpcid_desc desc;

    /* try executing invpcid, #UD expected */
    if (invpcid_safe(2, &desc) != UD_VECTOR)
        goto report;

    passed = 1;

report:
    report(passed, "Test on INVPCID when disabled");
}

int main(int ac, char **av)
{
    int pcid_enabled = 0, invpcid_enabled = 0;

    if (this_cpu_has(X86_FEATURE_PCID))
        pcid_enabled = 1;
    if (this_cpu_has(X86_FEATURE_INVPCID))
        invpcid_enabled = 1;

    if (pcid_enabled)
        test_pcid_enabled();
    else
        test_pcid_disabled();

    if (invpcid_enabled)
        test_invpcid_enabled(pcid_enabled);
    else
        test_invpcid_disabled();

    return report_summary();
}
