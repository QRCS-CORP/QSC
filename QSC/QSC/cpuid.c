#include "cpuid.h"
#include "stringutils.h"

#define CPUID_EBX_AVX2      0x00000020
#define CPUID_EBX_AVX2      0x00000020
#define CPUID_EBX_AVX2      0x00000020
#define CPUID_EBX_AVX2      0x00000020

#define CPUID_EBX_AVX2      0x00000020
#define CPUID_EBX_AVX512F   0x00010000
#define CPUID_ECX_SSE3      0x00000001
#define CPUID_ECX_PCLMUL    0x00000002
#define CPUID_ECX_SSSE3     0x00000200
#define CPUID_ECX_SSE41     0x00080000
#define CPUID_ECX_AESNI     0x02000000
#define CPUID_ECX_XSAVE     0x04000000
#define CPUID_ECX_OSXSAVE   0x08000000
#define CPUID_ECX_AVX       0x10000000
#define CPUID_ECX_RDRAND    0x40000000
#define CPUID_EDX_SSE2      0x04000000
#define CPUID_EDX_RDTCSP    0x0000001B
#define XCR0_SSE            0x00000002
#define XCR0_AVX            0x00000004
#define XCR0_OPMASK         0x00000020
#define XCR0_ZMM_HI256      0x00000040
#define XCR0_HI16_ZMM       0x00000080

/* for future use */
enum cpuid_flags
{
    /* eax=1 */
    CPUID_SSE3 = 0,
    CPUID_CMUL = 1,
    CPUID_SSSE3 = 9,
    CPUID_SSE41 = 19,
    CPUID_SSE42 = 20,
    CPUID_AESNI = 25,
    CPUID_AVX = 28,
    CPUID_RDRAND = 30,
    CPUID_SSE2 = 32 + 26,
    CPUID_HYPERTHREAD = 32 + 28,
    CPUID_X86EMU = 32 + 30,
    /* eax=7 */
    CPUID_SGX = 64 + 2,
    CPUID_AVX2 = 64 + 5,
    CPUID_BMI2 = 64 + 8,
    CPUID_RTM = 64 + 11,
    CPUID_PQM = 64 + 12,
    CPUID_PQE = 64 + 15,
    CPUID_AVX512F = 64 + 16,
    CPUID_RDSEED = 64 + 18,
    CPUID_ADX = 64 + 19,
    CPUID_SMAP = 64 + 20,
    CPUID_SHA = 64 + 29,
    CPUID_PREFETCH = 64 + 32,
    //* eax=80000001 */
    CPUID_ABM = 128 + 5,
    CPUID_SSE4A = 128 + 6,
    CPUID_XOP = 128 + 11,
    CPUID_FMA4 = 128 + 16,
    CPUID_RDTSCP = 160 + 27,
    CPUID_X64 = 160 + 29,
};

static uint32_t qsc_read_bits(uint32_t value, int32_t index, int32_t length)
{
    int32_t mask = (((int32_t)1 << length) - 1) << index;
    return (value & mask) >> index;
}

static void qsc_cpuid_info(uint32_t info[4], const uint32_t infotype)
{
    memset(info, 0x00, sizeof(info));

#if defined(QSC_SYSTEM_COMPILER_MSC)
    __cpuid((int32_t*)info, infotype);
#elif defined(QSC_SYSTEM_COMPILER_GCC)
    __get_cpuid(infotype, &info[0], &info[1], &info[2], &info[3])
#endif
}

bool qsc_runtime_features(qsc_cpu_features* const features)
{
    uint32_t info[4] = { 0 };
    uint32_t xcr0;
    bool res;

    features->aesni = false;
    features->avx = false;
    features->avx2 = false;
    features->avx512 = false;
    features->hyperthread = false;
    features->pcmul = false;
    features->rdrand = false;
    features->rdtcsp = false;
    features->cacheline = 0;
    features->cores = 1;
    features->cpus = 1;
    features->freqbase = 0;
    features->l1cache = 0;
    features->l2cache = 0;

    memset(features->serial, 0x00, sizeof(features->serial));
    memset(features->vendor, 0x00, sizeof(features->vendor));
    res = true;
    xcr0 = 0;

    qsc_cpuid_info(info, 0x00000000UL);

    if (info[0] != 0)
    {
        features->freqbase = info[0];
        memcpy(&features->vendor[0], &info[1], 4);
        memcpy(&features->vendor[4], &info[3], 4);
        memcpy(&features->vendor[8], &info[2], 4);

        qsc_cpuid_info(info, 0x00000003UL);
        memcpy(&features->serial[0], &info[3], 4);
        memcpy(&features->serial[4], &info[2], 4);

        qsc_cpuid_info(info, 0x80000006UL);
        features->l1cache = qsc_read_bits(info[2], 0, 8);
        features->cacheline = qsc_read_bits(info[2], 0, 11);
        features->l2cache = qsc_read_bits(info[2], 16, 16);
        features->cacheline *= 1024;

        if (qsc_stringutils_find_string(features->vendor,"Intel") > 0)
        {
            qsc_cpuid_info(info, 0x00000004UL);
            features->cores = ((info[0] >> 26) & 0x3F) + 1;
        }
        else if (qsc_stringutils_find_string(features->vendor, "AMD") > 0)
        {
            qsc_cpuid_info(info, 0x80000008UL);
            features->cores = (info[2] & 0xFF) + 1;
        }

        qsc_cpuid_info(info, 0x00000001UL);
        features->hyperthread = qsc_read_bits(info[3], 28, 1);
        features->cpus = features->hyperthread ? features->cores / 2 : features->cores;

#if defined(QSC_WMMINTRIN_H)
        features->pcmul = ((info[2] & CPUID_ECX_PCLMUL) != 0x0);
        features->aesni = ((info[2] & CPUID_ECX_AESNI) != 0x0);
#endif

        features->rdrand = ((info[2] & CPUID_ECX_RDRAND) != 0x0);
        features->rdtcsp = ((info[3] & CPUID_EDX_RDTCSP) != 0x0);

#if defined(QSC_SYSTEM_HAS_AVX)
        if ((info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) == (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE))
        {
            xcr0 = (uint32_t)_xgetbv(0);
        }

        if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX))
        {
            features->avx = true;
        }
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
        if (features->avx == true)
        {
            uint32_t info7[4] = { 0 };

            qsc_cpuid_info(info7, 0x00000007UL);
            features->avx2 = ((info7[1] & CPUID_EBX_AVX2) != 0x0);
        }
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
        if (features->avx2 == true)
        {
            uint32_t info7x[4] = { 0 };

            qsc_cpuid_info(info7x, 0x00000007UL);

            if ((info7x[1] & CPUID_EBX_AVX512F) == CPUID_EBX_AVX512F && (xcr0 & (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM))
                == (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM))
            {
                features->avx512 = true;
            }
        }
#endif
    }
    else
    {
        res = false;
    }

    return res;
}