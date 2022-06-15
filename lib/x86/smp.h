#ifndef _X86_SMP_H_
#define _X86_SMP_H_

#include <stddef.h>
#include <asm/spinlock.h>
#include "libcflat.h"
#include "atomic.h"
#include "apic-defs.h"

/* Address where to store the address of realmode GDT descriptor. */
#define REALMODE_GDT_LOWMEM (PAGE_SIZE - 2)

/* Offsets into the per-cpu page. */
struct percpu_data {
	uint32_t  smp_id;
	union {
		struct {
			uint8_t   exception_vector;
			uint8_t   exception_rflags_rf;
			uint16_t  exception_error_code;
		};
		uint32_t exception_data;
	};
	void *apic_ops;
};

#define typeof_percpu(name) typeof(((struct percpu_data *)0)->name)
#define offsetof_percpu(name) offsetof(struct percpu_data, name)

#define BUILD_PERCPU_OP(name)								\
static inline typeof_percpu(name) this_cpu_read_##name(void)				\
{											\
	typeof_percpu(name) val;							\
											\
	switch (sizeof(val)) {								\
	case 1:										\
		asm("movb %%gs:%c1, %0" : "=q" (val) : "i" (offsetof_percpu(name)));	\
		break;									\
	case 2:										\
		asm("movw %%gs:%c1, %0" : "=r" (val) : "i" (offsetof_percpu(name)));	\
		break;									\
	case 4:										\
		asm("movl %%gs:%c1, %0" : "=r" (val) : "i" (offsetof_percpu(name)));	\
		break;									\
	case 8:										\
		asm("movq %%gs:%c1, %0" : "=r" (val) : "i" (offsetof_percpu(name)));	\
		break;									\
	default:									\
		asm volatile("ud2");							\
	}										\
	return val;									\
}											\
static inline void this_cpu_write_##name(typeof_percpu(name) val)			\
{											\
	switch (sizeof(val)) {								\
	case 1:										\
		asm("movb %0, %%gs:%c1" :: "q" (val), "i" (offsetof_percpu(name)));	\
		break;									\
	case 2:										\
		asm("movw %0, %%gs:%c1" :: "r" (val), "i" (offsetof_percpu(name)));	\
		break;									\
	case 4:										\
		asm("movl %0, %%gs:%c1" :: "r" (val), "i" (offsetof_percpu(name)));	\
		break;									\
	case 8:										\
		asm("movq %0, %%gs:%c1" :: "r" (val), "i" (offsetof_percpu(name)));	\
		break;									\
	default:									\
		asm volatile("ud2");							\
	}										\
}
BUILD_PERCPU_OP(smp_id);
BUILD_PERCPU_OP(exception_vector);
BUILD_PERCPU_OP(exception_rflags_rf);
BUILD_PERCPU_OP(exception_error_code);
BUILD_PERCPU_OP(apic_ops);

void smp_init(void);

int cpu_count(void);
int smp_id(void);
int cpus_active(void);
void on_cpu(int cpu, void (*function)(void *data), void *data);
void on_cpu_async(int cpu, void (*function)(void *data), void *data);
void on_cpus(void (*function)(void *data), void *data);
void smp_reset_apic(void);
void ap_init(void);

extern atomic_t cpu_online_count;
extern unsigned char online_cpus[(MAX_TEST_CPUS + 7) / 8];

#endif
