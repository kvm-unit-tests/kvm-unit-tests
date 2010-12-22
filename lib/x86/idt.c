#include "idt.h"
#include "libcflat.h"
#include "processor.h"

typedef struct {
    unsigned short offset0;
    unsigned short selector;
    unsigned short ist : 3;
    unsigned short : 5;
    unsigned short type : 4;
    unsigned short : 1;
    unsigned short dpl : 2;
    unsigned short p : 1;
    unsigned short offset1;
#ifdef __x86_64__
    unsigned offset2;
    unsigned reserved;
#endif
} idt_entry_t;

static idt_entry_t idt[256];

void load_lidt(idt_entry_t *idt, int nentries)
{
    struct descriptor_table_ptr dt;

    dt.limit = nentries * sizeof(*idt) - 1;
    dt.base = (unsigned long)idt;
    lidt(&dt);
    asm volatile ("lidt %0" : : "m"(dt));
}

void set_idt_entry(int vec, void *addr, int dpl)
{
    idt_entry_t *e = &idt[vec];
    memset(e, 0, sizeof *e);
    e->offset0 = (unsigned long)addr;
    e->selector = read_cs();
    e->ist = 0;
    e->type = 14;
    e->dpl = dpl;
    e->p = 1;
    e->offset1 = (unsigned long)addr >> 16;
#ifdef __x86_64__
    e->offset2 = (unsigned long)addr >> 32;
#endif
}

struct ex_regs {
    unsigned long rax, rcx, rdx, rbx;
    unsigned long dummy, rbp, rsi, rdi;
#ifdef __x86_64__
    unsigned long r8, r9, r10, r11;
    unsigned long r12, r13, r14, r15;
#endif
    unsigned long vector;
    unsigned long error_code;
    unsigned long rip;
    unsigned long cs;
    unsigned long rflags;
};

struct ex_record {
    unsigned long rip;
    unsigned long handler;
};

extern struct ex_record exception_table_start, exception_table_end;

void do_handle_exception(struct ex_regs *regs)
{
    struct ex_record *ex;
    unsigned ex_val;

    ex_val = regs->vector | (regs->error_code << 16);

    asm("mov %0, %%gs:4" : : "r"(ex_val));

    for (ex = &exception_table_start; ex != &exception_table_end; ++ex) {
        if (ex->rip == regs->rip) {
            regs->rip = ex->handler;
            return;
        }
    }
    printf("unhandled excecption\n");
    exit(7);
}

#ifdef __x86_64__
#  define R "r"
#  define W "q"
#  define S "8"
#else
#  define R "e"
#  define W "l"
#  define S "4"
#endif

asm (".pushsection .text \n\t"
     "ud_fault: \n\t"
     "push"W" $0 \n\t"
     "push"W" $6 \n\t"
     "jmp handle_exception \n\t"

     "gp_fault: \n\t"
     "push"W" $13 \n\t"
     "jmp handle_exception \n\t"

     "de_fault: \n\t"
     "push"W" $0 \n\t"
     "push"W" $0 \n\t"
     "jmp handle_exception \n\t"

     "handle_exception: \n\t"
#ifdef __x86_64__
     "push %r15; push %r14; push %r13; push %r12 \n\t"
     "push %r11; push %r10; push %r9; push %r8 \n\t"
#endif
     "push %"R"di; push %"R"si; push %"R"bp; sub $"S", %"R"sp \n\t"
     "push %"R"bx; push %"R"dx; push %"R"cx; push %"R"ax \n\t"
     "mov %"R"sp, %"R"di \n\t"
     "call do_handle_exception \n\t"
     "pop %"R"ax; pop %"R"cx; pop %"R"dx; pop %"R"bx \n\t"
     "add $"S", %"R"sp; pop %"R"bp; pop %"R"si; pop %"R"di \n\t"
#ifdef __x86_64__
     "pop %r8; pop %r9; pop %r10; pop %r11 \n\t"
     "pop %r12; pop %r13; pop %r14; pop %r15 \n\t"
#endif
     "add $"S", %"R"sp \n\t"
     "add $"S", %"R"sp \n\t"
     "iret"W" \n\t"
     ".popsection");


void setup_idt(void)
{
    extern char ud_fault, gp_fault, de_fault;

    load_lidt(idt, 256);
    set_idt_entry(0, &de_fault, 0);
    set_idt_entry(6, &ud_fault, 0);
    set_idt_entry(13, &gp_fault, 0);
}

unsigned exception_vector(void)
{
    unsigned short vector;

    asm("mov %%gs:4, %0" : "=rm"(vector));
    return vector;
}

unsigned exception_error_code(void)
{
    unsigned short error_code;

    asm("mov %%gs:6, %0" : "=rm"(error_code));
    return error_code;
}
