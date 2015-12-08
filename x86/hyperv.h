#ifndef __HYPERV_H
#define __HYPERV_H

#include "libcflat.h"
#include "processor.h"
#include "io.h"

#define HYPERV_CPUID_FEATURES                   0x40000003

#define HV_X64_MSR_SYNIC_AVAILABLE              (1 << 2)

/* Define synthetic interrupt controller model specific registers. */
#define HV_X64_MSR_SCONTROL                     0x40000080
#define HV_X64_MSR_SVERSION                     0x40000081
#define HV_X64_MSR_SIEFP                        0x40000082
#define HV_X64_MSR_SIMP                         0x40000083
#define HV_X64_MSR_EOM                          0x40000084
#define HV_X64_MSR_SINT0                        0x40000090
#define HV_X64_MSR_SINT1                        0x40000091
#define HV_X64_MSR_SINT2                        0x40000092
#define HV_X64_MSR_SINT3                        0x40000093
#define HV_X64_MSR_SINT4                        0x40000094
#define HV_X64_MSR_SINT5                        0x40000095
#define HV_X64_MSR_SINT6                        0x40000096
#define HV_X64_MSR_SINT7                        0x40000097
#define HV_X64_MSR_SINT8                        0x40000098
#define HV_X64_MSR_SINT9                        0x40000099
#define HV_X64_MSR_SINT10                       0x4000009A
#define HV_X64_MSR_SINT11                       0x4000009B
#define HV_X64_MSR_SINT12                       0x4000009C
#define HV_X64_MSR_SINT13                       0x4000009D
#define HV_X64_MSR_SINT14                       0x4000009E
#define HV_X64_MSR_SINT15                       0x4000009F

#define HV_SYNIC_CONTROL_ENABLE                 (1ULL << 0)
#define HV_SYNIC_SIMP_ENABLE                    (1ULL << 0)
#define HV_SYNIC_SIEFP_ENABLE                   (1ULL << 0)
#define HV_SYNIC_SINT_MASKED                    (1ULL << 16)
#define HV_SYNIC_SINT_AUTO_EOI                  (1ULL << 17)
#define HV_SYNIC_SINT_VECTOR_MASK               (0xFF)
#define HV_SYNIC_SINT_COUNT                     16

enum {
    HV_TEST_DEV_SINT_ROUTE_CREATE = 1,
    HV_TEST_DEV_SINT_ROUTE_DESTROY,
    HV_TEST_DEV_SINT_ROUTE_SET_SINT
};

static inline bool synic_supported(void)
{
   return cpuid(HYPERV_CPUID_FEATURES).a & HV_X64_MSR_SYNIC_AVAILABLE;
}

void synic_sint_create(int vcpu, int sint, int vec, bool auto_eoi);
void synic_sint_set(int vcpu, int sint);
void synic_sint_destroy(int vcpu, int sint);

#endif
