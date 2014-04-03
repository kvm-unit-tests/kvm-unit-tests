#ifndef __IDT_TEST__
#define __IDT_TEST__

void setup_idt(void);
#ifndef __x86_64__
void setup_gdt(void);
void setup_tss32(void);
#else
static inline void setup_gdt(void){}
static inline void setup_tss32(void){}
#endif

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

#define ASM_TRY(catch)                                  \
    "movl $0, %%gs:4 \n\t"                              \
    ".pushsection .data.ex \n\t"                        \
    ".quad 1111f, " catch "\n\t"                        \
    ".popsection \n\t"                                  \
    "1111:"

#define DB_VECTOR   1
#define BP_VECTOR   3
#define UD_VECTOR   6
#define GP_VECTOR   13

#define KERNEL_CS 0x08
#define KERNEL_DS 0x10
#define NP_SEL 0x18
#define TSS_MAIN 0x20
#define TSS_INTR 0x28
#define FIRST_SPARE_SEL 0x30

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

extern idt_entry_t boot_idt[256];

unsigned exception_vector(void);
unsigned exception_error_code(void);
void set_idt_entry(int vec, void *addr, int dpl);
void set_idt_sel(int vec, u16 sel);
void set_gdt_entry(int sel, u32 base,  u32 limit, u8 access, u8 gran);
void set_idt_task_gate(int vec, u16 sel);
void set_intr_task_gate(int e, void *fn);
void print_current_tss_info(void);
void handle_exception(u8 v, void (*func)(struct ex_regs *regs));

bool test_for_exception(unsigned int ex, void (*trigger_func)(void *data),
			void *data);
void set_exception_return(void *addr);

#endif
