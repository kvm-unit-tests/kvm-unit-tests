#ifndef _S390X_INTERRUPT_H_
#define _S390X_INTERRUPT_H_
#include <asm/interrupt.h>

int register_io_int_func(void (*f)(void));
int unregister_io_int_func(void (*f)(void));

#endif /* INTERRUPT_H */
