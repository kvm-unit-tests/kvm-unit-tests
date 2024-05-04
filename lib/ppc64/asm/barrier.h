#ifndef _ASMPPC64_BARRIER_H_
#define _ASMPPC64_BARRIER_H_

#define pause_short() asm volatile(".long 0x7c40003c" ::: "memory")

#define mb() asm volatile("sync":::"memory")
#define rmb() asm volatile("sync":::"memory")
#define wmb() asm volatile("sync":::"memory")

#include <asm-generic/barrier.h>
#endif
