#ifndef INTERRUPT_H
#define INTERRUPT_H
#include <asm/interrupt.h>

int register_io_int_func(void (*f)(void));
int unregister_io_int_func(void (*f)(void));

#endif /* INTERRUPT_H */
