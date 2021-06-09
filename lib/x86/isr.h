#ifndef _X86_ISR_H_
#define _X86_ISR_H_

typedef struct {
    ulong regs[sizeof(ulong)*2];
    ulong func;
    ulong rip;
    ulong cs;
    ulong rflags;
} isr_regs_t;

void handle_irq(unsigned vec, void (*func)(isr_regs_t *regs));
void handle_external_interrupt(int vector);
#endif
