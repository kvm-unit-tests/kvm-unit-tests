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

#define ASM_TRY(catch)                                  \
    "movl $0, %%gs:4 \n\t"                              \
    ".pushsection .data.ex \n\t"                        \
    ".quad 1111f, " catch "\n\t"                        \
    ".popsection \n\t"                                  \
    "1111:"

#define UD_VECTOR   6
#define GP_VECTOR   13

#define TSS_MAIN 0x20
#define TSS_INTR 0x28

unsigned exception_vector(void);
unsigned exception_error_code(void);
void set_idt_entry(int vec, void *addr, int dpl);
void set_gdt_entry(int num, u32 base,  u32 limit, u8 access, u8 gran);
void set_intr_task_gate(int e, void *fn);
void print_current_tss_info(void);

#endif
