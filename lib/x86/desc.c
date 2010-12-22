#include "libcflat.h"
#include "desc.h"
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

typedef struct {
	u16 limit_low;
	u16 base_low;
	u8 base_middle;
	u8 access;
	u8 granularity;
	u8 base_high;
} gdt_entry_t;

typedef struct {
	u16 prev;
	u16 res1;
	u32 esp0;
	u16 ss0;
	u16 res2;
	u32 esp1;
	u16 ss1;
	u16 res3;
	u32 esp2;
	u16 ss2;
	u16 res4;
	u32 cr3;
	u32 eip;
	u32 eflags;
	u32 eax, ecx, edx, ebx, esp, ebp, esi, edi;
	u16 es;
	u16 res5;
	u16 cs;
	u16 res6;
	u16 ss;
	u16 res7;
	u16 ds;
	u16 res8;
	u16 fs;
	u16 res9;
	u16 gs;
	u16 res10;
	u16 ldt;
	u16 res11;
	u16 t:1;
	u16 res12:15;
	u16 iomap_base;
} tss32_t;

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

#ifndef __x86_64__
__attribute__((regparm(1)))
#endif
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
#ifdef __x86_64__
     "mov %"R"sp, %"R"di \n\t"
#else
     "mov %"R"sp, %"R"ax \n\t"
#endif
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

#ifndef __x86_64__
/*
 * GDT, with 6 entries:
 * 0x00 - NULL descriptor
 * 0x08 - Code segment
 * 0x10 - Data segment
 * 0x18 - Not presend code segment
 * 0x20 - Primery task
 * 0x28 - Interrupt task
 */

static gdt_entry_t gdt[6];
#define TSS_GDT_OFFSET 4

void set_gdt_entry(int num, u32 base,  u32 limit, u8 access, u8 gran)
{
	/* Setup the descriptor base address */
	gdt[num].base_low = (base & 0xFFFF);
	gdt[num].base_middle = (base >> 16) & 0xFF;
	gdt[num].base_high = (base >> 24) & 0xFF;

	/* Setup the descriptor limits */
	gdt[num].limit_low = (limit & 0xFFFF);
	gdt[num].granularity = ((limit >> 16) & 0x0F);

	/* Finally, set up the granularity and access flags */
	gdt[num].granularity |= (gran & 0xF0);
	gdt[num].access = access;
}

void setup_gdt(void)
{
	struct descriptor_table_ptr gp;
	/* Setup the GDT pointer and limit */
	gp.limit = sizeof(gdt) - 1;
	gp.base = (ulong)&gdt;

	memset(gdt, 0, sizeof(gdt));

	/* Our NULL descriptor */
	set_gdt_entry(0, 0, 0, 0, 0);

	/* The second entry is our Code Segment. The base address
	 *  is 0, the limit is 4GBytes, it uses 4KByte granularity,
	 *  uses 32-bit opcodes, and is a Code Segment descriptor. */
	set_gdt_entry(1, 0, 0xFFFFFFFF, 0x9A, 0xcf);

	/* The third entry is our Data Segment. It's EXACTLY the
	 *  same as our code segment, but the descriptor type in
	 *  this entry's access byte says it's a Data Segment */
	set_gdt_entry(2, 0, 0xFFFFFFFF, 0x92, 0xcf);

	/* Same as code register above but not present */
	set_gdt_entry(3, 0, 0xFFFFFFFF, 0x1A, 0xcf);


	/* Flush out the old GDT and install the new changes! */
	lgdt(&gp);

	asm volatile ("mov %0, %%ds\n\t"
		      "mov %0, %%es\n\t"
		      "mov %0, %%fs\n\t"
		      "mov %0, %%gs\n\t"
		      "mov %0, %%ss\n\t"
		      "jmp $0x08, $.Lflush2\n\t"
		      ".Lflush2: "::"r"(0x10));
}

static void set_idt_task_gate(int vec, u16 sel)
{
    idt_entry_t *e = &idt[vec];

    memset(e, 0, sizeof *e);

    e->selector = sel;
    e->ist = 0;
    e->type = 5;
    e->dpl = 0;
    e->p = 1;
}

/*
 * 0 - main task
 * 1 - interrupt task
 */

static tss32_t tss[2];
static char tss_stack[2][4096];

void setup_tss32(void)
{
	u16 desc_size = sizeof(tss32_t);
	int i;

	for (i = 0; i < 2; i++) {
		tss[i].cr3 = read_cr3();
		tss[i].ss0 = tss[i].ss1 = tss[i].ss2 = 0x10;
		tss[i].esp = tss[i].esp0 = tss[i].esp1 = tss[i].esp2 =
			(u32)tss_stack[i];
		tss[i].cs = 0x08;
		tss[i].ds = tss[i].es = tss[i].fs = tss[i].gs = tss[i].ss = 0x10;
		tss[i].iomap_base = (u16)desc_size;
		set_gdt_entry(TSS_GDT_OFFSET + i, (u32)&tss[i],
			     desc_size - 1, 0x89, 0x0f);
	}

	ltr(TSS_MAIN);
}

void set_intr_task_gate(int e, void *fn)
{
	tss[1].eip = (u32)fn;
	set_idt_task_gate(e, TSS_INTR);
}

void print_current_tss_info(void)
{
	u16 tr = str();
	int i = (tr == TSS_MAIN) ? 0 : 1;

	if (tr != TSS_MAIN && tr != TSS_INTR)
		printf("Unknown TSS %x\n", tr);
	else
		printf("TR=%x Main TSS back link %x. Current TSS back link %x\n",
               tr, tss[0].prev, tss[i].prev);
}
#endif
