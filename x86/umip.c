
#include "libcflat.h"
#include "desc.h"
#include "processor.h"


/* GP handler to skip over faulting instructions */

static unsigned long expected_rip;
static int skip_count;
static volatile int gp_count;

static void gp_handler(struct ex_regs *regs)
{
    if (regs->rip == expected_rip) {
        gp_count++;
        regs->rip += skip_count;
    } else {
        unhandled_exception(regs, false);
    }
}


#define GP_ASM(stmt, in, clobber)                  \
    asm volatile (                                 \
          "mov" W " $1f, %[expected_rip]\n\t"      \
          "movl $2f-1f, %[skip_count]\n\t"         \
          "1: " stmt "\n\t"                        \
          "2: "                                    \
          : [expected_rip] "=m" (expected_rip),    \
            [skip_count] "=m" (skip_count)         \
          : in : clobber)

static void do_smsw(void)
{
    gp_count = 0;
    GP_ASM("smsw %%ax", , "eax");
}

static void do_sldt(void)
{
    gp_count = 0;
    GP_ASM("sldt %%ax", , "eax");
}

static void do_str(void)
{
    gp_count = 0;
    GP_ASM("str %%ax", , "eax");
}

static void do_sgdt(void)
{
    struct descriptor_table_ptr dt;
    gp_count = 0;
    GP_ASM("sgdt %[dt]", [dt]"m"(dt), );
}

static void do_sidt(void)
{
    struct descriptor_table_ptr dt;
    gp_count = 0;
    GP_ASM("sidt %[dt]", [dt]"m"(dt), );
}

static void do_movcr(void)
{
    gp_count = 0;
    GP_ASM("mov %%cr0, %%" R "ax", , "eax");
}

static void test_umip_nogp(const char *msg)
{
    puts(msg);

    do_smsw();
    report(gp_count == 0, "no exception from smsw");
    do_sgdt();
    report(gp_count == 0, "no exception from sgdt");
    do_sidt();
    report(gp_count == 0, "no exception from sidt");
    do_sldt();
    report(gp_count == 0, "no exception from sldt");
    do_str();
    report(gp_count == 0, "no exception from str");
    if (read_cs() & 3) {
        do_movcr();
        report(gp_count == 1, "exception from mov %%cr0, %%eax");
    }
}

static void test_umip_gp(const char *msg)
{
    puts(msg);

#if 0
    /* Skip this, because it cannot be emulated correctly.  */
    do_smsw();
    report(gp_count == 1, "exception from smsw");
#endif
    do_sgdt();
    report(gp_count == 1, "exception from sgdt");
    do_sidt();
    report(gp_count == 1, "exception from sidt");
    do_sldt();
    report(gp_count == 1, "exception from sldt");
    do_str();
    report(gp_count == 1, "exception from str");
    if (read_cs() & 3) {
        do_movcr();
        report(gp_count == 1, "exception from mov %%cr0, %%eax");
    }
}

/* The ugly mode switching code */

static noinline int do_ring3(void (*fn)(const char *), const char *arg)
{
    static unsigned char user_stack[4096];
    int ret;

    asm volatile ("mov %[user_ds], %%" R "dx\n\t"
		  "mov %%dx, %%ds\n\t"
		  "mov %%dx, %%es\n\t"
		  "mov %%dx, %%fs\n\t"
		  "mov %%dx, %%gs\n\t"
		  "mov %%" R "sp, %%" R "cx\n\t"
		  "push" W " %%" R "dx \n\t"
		  "lea %[user_stack_top], %%" R "dx \n\t"
		  "push" W " %%" R "dx \n\t"
		  "pushf" W "\n\t"
		  "push" W " %[user_cs] \n\t"
		  "push" W " $1f \n\t"
		  "iret" W "\n"
		  "1: \n\t"
		  "push %%" R "cx\n\t"   /* save kernel SP */

#ifndef __x86_64__
		  "push %[arg]\n\t"
#endif
		  "call *%[fn]\n\t"
#ifndef __x86_64__
		  "pop %%ecx\n\t"
#endif

		  "pop %%" R "cx\n\t"
		  "mov $1f, %%" R "dx\n\t"
		  "int %[kernel_entry_vector]\n\t"
		  ".section .text.entry \n\t"
		  "kernel_entry: \n\t"
		  "mov %%" R "cx, %%" R "sp \n\t"
		  "mov %[kernel_ds], %%cx\n\t"
		  "mov %%cx, %%ds\n\t"
		  "mov %%cx, %%es\n\t"
		  "mov %%cx, %%fs\n\t"
		  "mov %%cx, %%gs\n\t"
		  "jmp *%%" R "dx \n\t"
		  ".section .text\n\t"
		  "1:\n\t"
		  : [ret] "=&a" (ret)
		  : [user_ds] "i" (USER_DS),
		    [user_cs] "i" (USER_CS),
		    [user_stack_top]"m"(user_stack[sizeof(user_stack) -
						   sizeof(long)]),
		    [fn]"r"(fn),
		    [arg]"D"(arg),
		    [kernel_ds]"i"(KERNEL_DS),
		    [kernel_entry_vector]"i"(0x20)
		  : "rcx", "rdx");
    return ret;
}

int main(void)
{
    extern unsigned char kernel_entry;

    set_idt_entry(0x20, &kernel_entry, 3);
    handle_exception(13, gp_handler);
    set_iopl(3);

    test_umip_nogp("UMIP=0, CPL=0\n");
    do_ring3(test_umip_nogp, "UMIP=0, CPL=3\n");

    if (!this_cpu_has(X86_FEATURE_UMIP)) {
        printf("UMIP not available\n");
        return report_summary();
    }
    write_cr4(read_cr4() | X86_CR4_UMIP);

    test_umip_nogp("UMIP=1, CPL=0\n");
    do_ring3(test_umip_gp, "UMIP=1, CPL=3\n");

    return report_summary();
}
