#ifndef QSC_CPUID_H
#define QSC_CPUID_H

#include "common.h"

#if defined(QSC_SYSTEM_COMPILER_MSC) && defined(QSC_SYSTEM_ARCH_X86_X64)
#	include <intrin.h>
#	pragma intrinsic(__cpuid)
#elif defined(QSC_SYSTEM_COMPILER_GCC)
#	include <cpuid.h>
#	pragma GCC target ("aes")
#include <x86intrin.h>
#endif

QSC_EXPORT_API typedef struct qsc_cpu_features
{
    bool aesni;
    bool avx;
    bool avx2;
    bool avx512;
    bool hyperthread;
    bool pcmul;
    bool rdrand;
    bool rdtcsp;
    uint32_t cacheline;
    uint32_t cores;
    uint32_t cpus;
    uint32_t freqbase;
    uint32_t l1cache;
    uint32_t l2cache;
    char serial[8];
    char vendor[12];
} qsc_cpu_features;


/**
* \brief Get a list of supported CPU features
*
* \param features: A qsc_cpu_features structure
* \return Returns true for success, false if CPU is not recognized
*/
QSC_EXPORT_API bool qsc_runtime_features(qsc_cpu_features* const features);

#endif