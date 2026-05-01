#include "memutils.h"

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#   include "intrinsics.h"
#endif

#if defined(QSC_SYSTEM_OS_POSIX)
#   include <errno.h>
#   include <unistd.h>
#   include <string.h>
#   include <stdlib.h>
#   include <sys/types.h>
#   include <sys/resource.h>
#   include <sys/mman.h>
#   include <signal.h>
#   include <setjmp.h>
#elif defined(QSC_SYSTEM_OS_WINDOWS)
#   include <stdlib.h>
#   include <string.h>
#   include <windows.h>
#endif

#if defined(QSC_SYSTEM_COMPILER_MSC)
#   pragma intrinsic(_ReadWriteBarrier)
#   define QSC_COMPILER_BARRIER() _ReadWriteBarrier()
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_CLANG)
#   define QSC_COMPILER_BARRIER() __asm__ __volatile__("" : : : "memory")
#else
#   define QSC_COMPILER_BARRIER() do { } while (0)
#endif

void qsc_memutils_flush_cache_line(void* address)
{
    QSC_ASSERT(address != NULL);

    if (address != NULL)
    {
#if defined(QSC_SYSTEM_ARCH_IX86) && defined(QSC_SYSTEM_AVX_INTRINSICS)
        _mm_clflush(address);
#elif defined(QSC_SYSTEM_ARCH_ARM) || defined(QSC_SYSTEM_ARCH_ARM64)
        __asm__ __volatile__("dc civac, %0" :: "r"(address) : "memory");
#else
        (void)address;
#endif
    }
}

void qsc_memutils_prefetch_l1(uint8_t* address, size_t length)
{
    QSC_ASSERT(address != NULL);
    QSC_ASSERT(length != 0U);

    if (address != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
        for (size_t offset = 0U; offset < length; offset += QSC_MEMUTILS_CACHE_LINE_SIZE)
        {
            _mm_prefetch((const char*)address + offset, _MM_HINT_T0);
        }
#else
        volatile uint8_t tmp;

        tmp = 0U;

        for (size_t i = 0U; i < length; ++i) 
        { 
            tmp |= address[i]; 
        }

        (void)tmp;
#endif
    }
}

void qsc_memutils_prefetch_l2(uint8_t* address, size_t length)
{
    QSC_ASSERT(address != NULL);
    QSC_ASSERT(length != 0U);

    if (address != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
        for (size_t offset = 0U; offset < length; offset += QSC_MEMUTILS_CACHE_LINE_SIZE)
        {
            _mm_prefetch((const char*)address + offset, _MM_HINT_T1);
        }
#else
        volatile uint8_t tmp;

        tmp = 0U;

        for (size_t i = 0U; i < length; ++i) 
        { 
            tmp |= address[i]; 
        }

        (void)tmp;
#endif
    }
}

void qsc_memutils_prefetch_l3(uint8_t* address, size_t length)
{
    QSC_ASSERT(address != NULL);
    QSC_ASSERT(length != 0U);

    if (address != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
        for (size_t offset = 0U; offset < length; offset += QSC_MEMUTILS_CACHE_LINE_SIZE)
        {
            _mm_prefetch((const char*)address + offset, _MM_HINT_T2);
        }
#else
        volatile uint8_t tmp;

        tmp = 0U;

        for (size_t i = 0U; i < length; ++i) 
        { 
            tmp |= address[i]; 
        }

        (void)tmp;
#endif
    }
}

void* qsc_memutils_malloc(size_t length)
{
    QSC_ASSERT(length != 0U);

    void* ret;

    ret = NULL;

    if (length != 0U) 
    { 
        ret = malloc(length); 
    }

    return ret;
}

size_t qsc_memutils_page_size(void)
{
    int64_t pagelen;

#if defined(QSC_SYSTEM_OS_POSIX)
    pagelen = sysconf(_SC_PAGESIZE);

    if (pagelen < 1) 
    { 
        pagelen = QSC_SYSTEM_SECMEMALLOC_DEFAULT; 
    }
#elif defined(QSC_SYSTEM_OS_WINDOWS)
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    pagelen = (int64_t)sysinfo.dwPageSize;
#else
    pagelen = 0x00001000LL;
#endif

    return (size_t)pagelen;
}

void* qsc_memutils_realloc(void* block, size_t length)
{
    QSC_ASSERT(block != NULL);
    QSC_ASSERT(length != 0U);

    void* ret;

    ret = NULL;

    if (block != NULL && length != 0U) 
    { 
        ret = realloc(block, length); 
    }

    return ret;
}

void qsc_memutils_alloc_free(void* block)
{
    QSC_ASSERT(block != NULL);

    if (block != NULL) 
    { 
        free(block); 
    }
}

void* qsc_memutils_aligned_alloc(int32_t align, size_t length)
{
    QSC_ASSERT(align != 0);
    QSC_ASSERT(length != 0U);

    void* ret;

    ret = NULL;

    if (align != 0 && length != 0U)
    {
#if defined(QSC_SYSTEM_AVX_INTRINSICS) && defined(QSC_SYSTEM_OS_WINDOWS)
        ret = _aligned_malloc(length, align);
#elif defined(QSC_SYSTEM_OS_POSIX)
        QSC_ASSERT((align & (align - 1)) == 0);
        QSC_ASSERT((size_t)align >= sizeof(void*));

        int32_t res;

        res = posix_memalign(&ret, (size_t)align, length);

        if (res != 0) 
        { 
            ret = NULL; 
        }
#else
        ret = malloc(length);
#endif
    }

    return ret;
}

void* qsc_memutils_aligned_realloc(void* block, size_t length)
{
    QSC_ASSERT(block != NULL);
    QSC_ASSERT(length != 0U);

    void* ret;

    ret = NULL;

    if (block != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_AVX_INTRINSICS) && defined(QSC_SYSTEM_OS_WINDOWS)
        ret = _aligned_realloc(block, length, QSC_SIMD_ALIGNMENT);
#else
        ret = realloc(block, length);
#endif
    }

    return ret;
}

void qsc_memutils_aligned_free(void* block)
{
    QSC_ASSERT(block != NULL);

    if (block != NULL)
    {
#if defined(QSC_SYSTEM_AVX_INTRINSICS) && defined(QSC_SYSTEM_OS_WINDOWS)
        _aligned_free(block);
#else
        free(block);
#endif
    }
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void memutils_clear128(volatile void* output)
{
    _mm_storeu_si128((__m128i*)output, _mm_setzero_si128());
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_clear256(volatile void* output)
{
    _mm256_storeu_si256((__m256i*)output, _mm256_setzero_si256());
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_clear512(volatile void* output)
{
    _mm512_storeu_si512((__m512i*)output, _mm512_setzero_si512());
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON) && !defined(QSC_SYSTEM_HAS_AVX)
static void memutils_clear128(volatile void* output)
{
    vst1q_u8((uint8_t*)output, vdupq_n_u8(0U));
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON)
static void memutils_clear256_neon(volatile void* output)
{
    uint8x16_t zeros = vdupq_n_u8(0U);
    vst1q_u8((uint8_t*)output, zeros);
    vst1q_u8((uint8_t*)output + 16U, zeros);
}

static void memutils_clear512_neon(volatile void* output)
{
    uint8x16_t zeros = vdupq_n_u8(0U);
    vst1q_u8((uint8_t*)output, zeros);
    vst1q_u8((uint8_t*)output + 16U, zeros);
    vst1q_u8((uint8_t*)output + 32U, zeros);
    vst1q_u8((uint8_t*)output + 48U, zeros);
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_SVE)
static void memutils_clear_sve(volatile void* output, size_t length)
{
    volatile uint8_t* ptr;
    size_t rmd;
    svbool_t pg;

    ptr = (volatile uint8_t*)output;
    rmd = length;

    while (rmd >= svcntb())
    {
        pg = svptrue_b8();
        svst1_u8(pg, (uint8_t*)ptr, svdup_n_u8(0U));
        ptr += svcntb();
        rmd -= svcntb();
    }

    if (rmd > 0U)
    {
        pg = svwhilelt_b8_u64(0ULL, (uint64_t)rmd);
        svst1_u8(pg, (uint8_t*)ptr, svdup_n_u8(0U));
    }
}
#endif

#if defined(QSC_SYSTEM_HAS_RVV)
static void memutils_clear_rvv(volatile void* output, size_t length)
{
    volatile uint8_t* ptr;
    size_t rmd;

    ptr = (volatile uint8_t*)output;
    rmd = length;

    while (rmd > 0U)
    {
        size_t vl = __riscv_vsetvl_e8m8(rmd);
        vuint8m8_t vzero = __riscv_vmv_v_x_u8m8(0U, vl);
        __riscv_vse8_v_u8m8((uint8_t*)ptr, vzero, vl);
        ptr += vl;
        rmd -= vl;
    }
}
#endif

void qsc_memutils_clear(void* output, size_t length)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(length != 0U);

    if (output != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_HAS_RVV)
        memutils_clear_rvv(output, length);
#elif defined(QSC_SYSTEM_HAS_ARM_SVE)
        memutils_clear_sve(output, length);
#else
        size_t pctr;

        pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#   if defined(QSC_SYSTEM_HAS_AVX512)
        const size_t SMDBLK = 64U;
#   elif defined(QSC_SYSTEM_HAS_AVX2)
        const size_t SMDBLK = 32U;
#   else
        const size_t SMDBLK = 16U;
#   endif
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        /* use 32-byte blocks on NEON via the 256-bit helper */
        const size_t SMDBLK = 32U;
#endif

#if defined(QSC_SYSTEM_AVX_INTRINSICS) || defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (SMDBLK > 0U && length >= SMDBLK)
        {
            const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

            while (pctr != ALNLEN)
            {
#   if defined(QSC_SYSTEM_HAS_AVX512)
                memutils_clear512((volatile uint8_t*)output + pctr);
#   elif defined(QSC_SYSTEM_HAS_AVX2)
                memutils_clear256((volatile uint8_t*)output + pctr);
#   elif defined(QSC_SYSTEM_HAS_AVX)
                memutils_clear128((volatile uint8_t*)output + pctr);
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
                memutils_clear256_neon((volatile uint8_t*)output + pctr);
#   endif
                pctr += SMDBLK;
            }
        }

        /* fill remaining bytes smaller than one SIMD block */
#   if defined(QSC_SYSTEM_HAS_AVX512)
        if (length - pctr >= 32U)
        {
            memutils_clear256((volatile uint8_t*)output + pctr);
            pctr += 32U;
        }
        else if (length - pctr >= 16U)
        {
            memutils_clear128((volatile uint8_t*)output + pctr);
            pctr += 16U;
        }
#   elif defined(QSC_SYSTEM_HAS_AVX2)
        if (length - pctr >= 16U)
        {
            memutils_clear128((volatile uint8_t*)output + pctr);
            pctr += 16U;
        }
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (length - pctr >= 16U)
        {
            memutils_clear128((volatile uint8_t*)output + pctr);
            pctr += 16U;
        }
#   endif
#endif
        for (size_t i = pctr; i < length; ++i)
        {
            ((volatile uint8_t*)output)[i] = 0x00U;
        }
#endif
    }

    QSC_COMPILER_BARRIER();
}

#if defined(QSC_SYSTEM_HAS_AVX)
static bool memutils_equal128(const uint8_t* a, const uint8_t* b)
{
    __m128i wa = _mm_loadu_si128((const __m128i*)a);
    __m128i wb = _mm_loadu_si128((const __m128i*)b);
    __m128i wc = _mm_cmpeq_epi64(wa, wb);
    uint64_t ra[2U] = { 0U };

    _mm_storeu_si128((__m128i*)ra, wc);

    return ((~ra[0U] + ~ra[1U]) == 0U);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static bool memutils_equal256(const uint8_t* a, const uint8_t* b)
{
    __m256i wa = _mm256_loadu_si256((const __m256i*)a);
    __m256i wb = _mm256_loadu_si256((const __m256i*)b);
    __m256i wc = _mm256_cmpeq_epi64(wa, wb);
    uint64_t ra[4U] = { 0U };

    _mm256_storeu_si256((__m256i*)ra, wc);

    return ((~ra[0U] + ~ra[1U] + ~ra[2U] + ~ra[3U]) == 0U);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static bool memutils_equal512(const uint8_t* a, const uint8_t* b)
{
    __m512i va = _mm512_loadu_si512(a);
    __m512i vb = _mm512_loadu_si512(b);
    __mmask8 eq64 = _mm512_cmpeq_epi64_mask(va, vb);

    return (eq64 == 0xFFU);
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON) && !defined(QSC_SYSTEM_HAS_AVX)
static bool memutils_equal128(const uint8_t* a, const uint8_t* b)
{
    uint8x16_t va = vld1q_u8(a);
    uint8x16_t vb = vld1q_u8(b);
    uint8x16_t cmp = vceqq_u8(va, vb);

    return (vminvq_u8(cmp) == 0xFFU);
}
#endif

/* --- ARM NEON 256-bit helper (two 128-bit loads) --- */
#if defined(QSC_SYSTEM_HAS_ARM_NEON)
static bool memutils_equal256_neon(const uint8_t* a, const uint8_t* b)
{
    uint8x16_t va0 = vld1q_u8(a);
    uint8x16_t vb0 = vld1q_u8(b);
    uint8x16_t va1 = vld1q_u8(a + 16U);
    uint8x16_t vb1 = vld1q_u8(b + 16U);
    uint8x16_t combined = vandq_u8(vceqq_u8(va0, vb0), vceqq_u8(va1, vb1));

    return (vminvq_u8(combined) == 0xFFU);
}

static bool memutils_equal512_neon(const uint8_t* a, const uint8_t* b)
{
    uint8x16_t c0 = vceqq_u8(vld1q_u8(a), vld1q_u8(b));
    uint8x16_t c1 = vceqq_u8(vld1q_u8(a + 16U), vld1q_u8(b + 16U));
    uint8x16_t c2 = vceqq_u8(vld1q_u8(a + 32U), vld1q_u8(b + 32U));
    uint8x16_t c3 = vceqq_u8(vld1q_u8(a + 48U), vld1q_u8(b + 48U));
    uint8x16_t combined = vandq_u8(vandq_u8(c0, c1), vandq_u8(c2, c3));

    return (vminvq_u8(combined) == 0xFFU);
}
#endif

#if defined(QSC_SYSTEM_HAS_RVV)
static bool memutils_equal_rvv(const uint8_t* a, const uint8_t* b, size_t length)
{
    size_t rmd;
    uint8_t acc;

    rmd = length;
    acc = 0U;

    while (rmd > 0U)
    {
        size_t vl = __riscv_vsetvl_e8m8(rmd);
        vuint8m8_t va = __riscv_vle8_v_u8m8(a, vl);
        vuint8m8_t vb = __riscv_vle8_v_u8m8(b, vl);
        vuint8m8_t vxor = __riscv_vxor_vv_u8m8(va, vb, vl);

        /* reduce: max of all XOR bytes; nonzero means mismatch */
        vuint8m1_t vred = __riscv_vredmaxu_vs_u8m8_u8m1(vxor, __riscv_vmv_v_x_u8m1(0U, 1U), vl);
        acc |= __riscv_vmv_x_s_u8m1_u8(vred);
        a += vl;
        b += vl;
        rmd -= vl;
    }

    return (acc == 0U);
}
#endif /* QSC_SYSTEM_HAS_RVV */

bool qsc_memutils_array_uniform(const uint8_t* input, size_t length)
{
    QSC_ASSERT(input != NULL);

    uint8_t ref;
    uint8_t res;

    res = 0U;

    if (length > 0U)
    {
        ref = input[0U];

        for (size_t i = 1U; i < length; ++i)
        {
            res |= (input[i] ^ ref);
        }
    }

    return (res == 0U);
}

bool qsc_memutils_are_equal(const uint8_t* a, const uint8_t* b, size_t length)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);
    QSC_ASSERT(length > 0U);

    bool res;

    res = false;

    if (a != NULL && b != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_HAS_RVV)
        return memutils_equal_rvv(a, b, length);
#else
        size_t pctr = 0U;
        int32_t mctr = 0;

#   if defined(QSC_SYSTEM_AVX_INTRINSICS)
#   if defined(QSC_SYSTEM_HAS_AVX512)
        const size_t SMDBLK = 64U;
#   elif defined(QSC_SYSTEM_HAS_AVX2)
        const size_t SMDBLK = 32U;
#   else
        const size_t SMDBLK = 16U;
#   endif
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        const size_t SMDBLK = 32U;
#   endif

#if defined(QSC_SYSTEM_AVX_INTRINSICS) || defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (SMDBLK > 0U && length >= SMDBLK)
        {
            const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

            while (pctr != ALNLEN)
            {
#   if defined(QSC_SYSTEM_HAS_AVX512)
                mctr |= ((int32_t)memutils_equal512(a + pctr, b + pctr) - 1);
#   elif defined(QSC_SYSTEM_HAS_AVX2)
                mctr |= ((int32_t)memutils_equal256(a + pctr, b + pctr) - 1);
#   elif defined(QSC_SYSTEM_HAS_AVX)
                mctr |= ((int32_t)memutils_equal128(a + pctr, b + pctr) - 1);
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
                mctr |= ((int32_t)memutils_equal256_neon(a + pctr, b + pctr) - 1);
#   endif
                pctr += SMDBLK;
            }
        }
#endif

        for (size_t i = pctr; i < length; ++i)
        {
            mctr |= (a[i] ^ b[i]);
        }

        res = (mctr == 0);
    }
#endif

    return res;
}

bool qsc_memutils_are_equal_128(const uint8_t* a, const uint8_t* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res;

    res = false;

    if (a != NULL && b != NULL)
    {

#if defined(QSC_SYSTEM_HAS_AVX)
        return memutils_equal128(a, b);
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        return memutils_equal128(a, b);
#elif defined(QSC_SYSTEM_HAS_RVV)
        return memutils_equal_rvv(a, b, 16U);
#else
        int32_t mctr;

        mctr = 0;

        for (size_t i = 0U; i < 16U; ++i) 
        {
            mctr |= (a[i] ^ b[i]); 
        }

        res = (mctr == 0);
#endif
    }

    return res;
}

bool qsc_memutils_are_equal_256(const uint8_t* a, const uint8_t* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res;

    res = false;

    if (a != NULL && b != NULL)
    {
#if defined(QSC_SYSTEM_HAS_AVX2)
        res = memutils_equal256(a, b);
#elif defined(QSC_SYSTEM_HAS_AVX)
        res = (memutils_equal128(a, b) && memutils_equal128(a + 16U, b + 16U));
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        res = memutils_equal256_neon(a, b);
#elif defined(QSC_SYSTEM_HAS_RVV)
        res = memutils_equal_rvv(a, b, 32U);
#else
        int32_t mctr;

        mctr = 0;

        for (size_t i = 0U; i < 32U; ++i) 
        { 
            mctr |= (a[i] ^ b[i]); 
        }

        res = (mctr == 0);
#endif
    }

    return res;
}

bool qsc_memutils_are_equal_512(const uint8_t* a, const uint8_t* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res;

    res = false;

    if (a != NULL && b != NULL)
    {
#if defined(QSC_SYSTEM_HAS_AVX512)
        res = memutils_equal512(a, b);
#elif defined(QSC_SYSTEM_HAS_AVX2)
        res = (memutils_equal256(a, b) && memutils_equal256(a + 32U, b + 32U));
#elif defined(QSC_SYSTEM_HAS_AVX)
        res = (memutils_equal128(a, b) &&
            memutils_equal128(a + 16U, b + 16U) &&
            memutils_equal128(a + 32U, b + 32U) &&
            memutils_equal128(a + 48U, b + 48U));
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        res = memutils_equal512_neon(a, b);
#elif defined(QSC_SYSTEM_HAS_RVV)
        res = memutils_equal_rvv(a, b, 64U);
#else
        int32_t mctr;

        mctr = 0;

        for (size_t i = 0U; i < 64U; ++i) 
        { 
            mctr |= (a[i] ^ b[i]); 
        }

        res = (mctr == 0);
#endif
    }

    return res;
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void memutils_copy128(void* output, const void* input)
{
    _mm_storeu_si128((__m128i*)output, _mm_loadu_si128((const __m128i*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_copy256(void* output, const void* input)
{
    _mm256_storeu_si256((__m256i*)output, _mm256_loadu_si256((const __m256i*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_copy512(void* output, const void* input)
{
    _mm512_storeu_si512((__m512i*)output, _mm512_loadu_si512((const __m512i*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON) && !defined(QSC_SYSTEM_HAS_AVX)
static void memutils_copy128(void* output, const void* input)
{
    vst1q_u8((uint8_t*)output, vld1q_u8((const uint8_t*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON)
static void memutils_copy256_neon(void* output, const void* input)
{
    vst1q_u8((uint8_t*)output, vld1q_u8((const uint8_t*)input));
    vst1q_u8((uint8_t*)output + 16U, vld1q_u8((const uint8_t*)input + 16U));
}

static void memutils_copy512_neon(void* output, const void* input)
{
    vst1q_u8((uint8_t*)output, vld1q_u8((const uint8_t*)input));
    vst1q_u8((uint8_t*)output + 16U, vld1q_u8((const uint8_t*)input + 16U));
    vst1q_u8((uint8_t*)output + 32U, vld1q_u8((const uint8_t*)input + 32U));
    vst1q_u8((uint8_t*)output + 48U, vld1q_u8((const uint8_t*)input + 48U));
}
#endif

#if defined(QSC_SYSTEM_HAS_RVV)
static void memutils_copy_rvv(void* output, const void* input, size_t length)
{
    uint8_t* dst;
    const uint8_t* src;
    size_t rmd;

    dst = (uint8_t*)output;
    src = (const uint8_t*)input;
    rmd = length;

    while (rmd > 0U)
    {
        size_t vl = __riscv_vsetvl_e8m8(rmd);
        vuint8m8_t v = __riscv_vle8_v_u8m8(src, vl);
        __riscv_vse8_v_u8m8(dst, v, vl);
        src += vl;
        dst += vl;
        rmd -= vl;
    }
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_SVE)
static void memutils_copy_sve(void* output, const void* input, size_t length)
{
    uint8_t* dst;
    const uint8_t* src;
    size_t rmd;
    svbool_t pg;

    dst = (uint8_t*)output;
    src = (const uint8_t*)input;
    rmd = length;

    while (rmd >= svcntb())
    {
        pg = svptrue_b8();
        svst1_u8(pg, dst, svld1_u8(pg, src));
        src += svcntb();
        dst += svcntb();
        rmd -= svcntb();
    }

    if (rmd > 0U)
    {
        pg = svwhilelt_b8_u64(0ULL, (uint64_t)rmd);
        svst1_u8(pg, dst, svld1_u8(pg, src));
    }
}
#endif

void qsc_memutils_copy(void* output, const void* input, size_t length)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(input != NULL);

    if (output != NULL && input != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_HAS_RVV)
        memutils_copy_rvv(output, input, length);
#elif defined(QSC_SYSTEM_HAS_ARM_SVE)
        memutils_copy_sve(output, input, length);
#else
        size_t pctr;

        pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#   if defined(QSC_SYSTEM_HAS_AVX512)
        const size_t SMDBLK = 64U;
#   elif defined(QSC_SYSTEM_HAS_AVX2)
        const size_t SMDBLK = 32U;
#   else
        const size_t SMDBLK = 16U;
#   endif
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        const size_t SMDBLK = 32U;
#endif

#if defined(QSC_SYSTEM_AVX_INTRINSICS) || defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (SMDBLK > 0U && length >= SMDBLK)
        {
            const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

            while (pctr != ALNLEN)
            {
#   if defined(QSC_SYSTEM_HAS_AVX512)
                memutils_copy512((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
#   elif defined(QSC_SYSTEM_HAS_AVX2)
                memutils_copy256((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
#   elif defined(QSC_SYSTEM_HAS_AVX)
                memutils_copy128((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
                memutils_copy256_neon((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
#   endif
                pctr += SMDBLK;
            }
        }

#   if defined(QSC_SYSTEM_HAS_AVX512)
        if (length - pctr >= 32U)
        {
            memutils_copy256((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
            pctr += 32U;
        }
        else if (length - pctr >= 16U)
        {
            memutils_copy128((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
            pctr += 16U;
        }
#   elif defined(QSC_SYSTEM_HAS_AVX2)
        if (length - pctr >= 16U)
        {
            memutils_copy128((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
            pctr += 16U;
        }
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (length - pctr >= 16U)
        {
            memutils_copy128((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
            pctr += 16U;
        }
#   endif
#endif

        for (size_t i = pctr; i < length; ++i)
        {
            ((uint8_t*)output)[i] = ((const uint8_t*)input)[i];
        }
#endif
    }
}

static inline void memutils_clmulepi64(uint64_t r[2U], uint64_t x, uint64_t y)
{
    uint64_t bit;
    uint64_t hc;
    uint64_t mask;
    uint64_t mi;
    uint64_t nz;
    uint64_t ss;

    r[0U] = 0U;
    r[1U] = 0U;

    for (size_t i = 0U; i < 64U; ++i)
    {
        bit = (x >> i) & 1ULL;
        mask = 0U - bit;
        r[0U] ^= (y << i) & mask;
        nz = (uint64_t)(i != 0U);
        mi = 0U - nz;
        ss = (64U - i) & mi;
        hc = (y >> ss) & mi;
        r[1U] ^= hc & mask;
    }
}

void qsc_memutils_clmulepi64_si128(uint64_t r[2U], const uint64_t a[2U], const uint64_t b[2U], int32_t imm8)
{
    size_t inda = (imm8 & 0x01) ? 1U : 0U;
    size_t indb = (imm8 & 0x10) ? 1U : 0U;
    memutils_clmulepi64(r, a[inda], b[indb]);
}

#if defined(QSC_SYSTEM_HAS_AVX) && defined(QSC_SYSTEM_X86)

static inline void memutils_clmul128(__m128i a, __m128i b, __m128i* low, __m128i* high)
{
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i mid = _mm_xor_si128(_mm_xor_si128(p01, p10), _mm_xor_si128(p00, p11));

    *low = _mm_xor_si128(p00, _mm_slli_si128(mid, 8));
    *high = _mm_xor_si128(p11, _mm_srli_si128(mid, 8));
}

void qsc_memutils_clmulepi64_si256_avx(__m128i r[4U], const __m128i a[2U], const __m128i b[2U])
{
    __m128i p0low = _mm_setzero_si128(), p0high = _mm_setzero_si128();
    __m128i p1low = _mm_setzero_si128(), p1high = _mm_setzero_si128();
    __m128i p2low = _mm_setzero_si128(), p2high = _mm_setzero_si128();

    memutils_clmul128(a[0U], b[0U], &p0low, &p0high);
    memutils_clmul128(a[1U], b[1U], &p1low, &p1high);
    memutils_clmul128(_mm_xor_si128(a[0U], a[1U]), _mm_xor_si128(b[0U], b[1U]), &p2low, &p2high);

    __m128i mlow = _mm_xor_si128(p0low, _mm_xor_si128(p1low, p2low));
    __m128i mhigh = _mm_xor_si128(p0high, _mm_xor_si128(p1high, p2high));

    r[0U] = p0low;
    r[1U] = _mm_xor_si128(p0high, mlow);
    r[2U] = _mm_xor_si128(mhigh, p1low);
    r[3U] = p1high;
}

void qsc_memutils_clmulepi64_si256(uint64_t r[8U], const uint64_t a[4U], const uint64_t b[4U])
{
    __m128i ma[2U] = { 0U };
    __m128i mb[2U] = { 0U };
    __m128i mr[4U] = { 0U };

    ma[0U] = _mm_loadu_si128((const __m128i*)(a));
    ma[1U] = _mm_loadu_si128((const __m128i*)(a + 2U));
    mb[0U] = _mm_loadu_si128((const __m128i*)(b));
    mb[1U] = _mm_loadu_si128((const __m128i*)(b + 2U));

    qsc_memutils_clmulepi64_si256_avx(mr, ma, mb);

    _mm_storeu_si128((__m128i*)(r + 0U), mr[0U]);
    _mm_storeu_si128((__m128i*)(r + 2U), mr[1U]);
    _mm_storeu_si128((__m128i*)(r + 4U), mr[2U]);
    _mm_storeu_si128((__m128i*)(r + 6U), mr[3U]);
}

#else

static inline void memutils_clmul128(uint64_t r[4U], const uint64_t a[2U], const uint64_t b[2U])
{
    uint64_t p00[2U];
    uint64_t p11[2U];
    uint64_t p10[2U];
    uint64_t p01[2U];
    uint64_t t2[2U];
    uint64_t t2l[2U];
    uint64_t t2r[2U];

    memutils_clmulepi64(p00, a[0U], b[0U]);
    memutils_clmulepi64(p11, a[1U], b[1U]);
    memutils_clmulepi64(p10, a[1U], b[0U]);
    memutils_clmulepi64(p01, a[0U], b[1U]);

    t2[0U] = p10[0U] ^ p01[0U] ^ p00[0U] ^ p11[0U];
    t2[1U] = p10[1U] ^ p01[1U] ^ p00[1U] ^ p11[1U];

    t2l[0U] = 0U;          t2l[1U] = t2[0U];
    t2r[0U] = t2[1U];      t2r[1U] = 0U;

    r[0U] = p00[0U] ^ t2l[0U];
    r[1U] = p00[1U] ^ t2l[1U];
    r[2U] = p11[0U] ^ t2r[0U];
    r[3U] = p11[1U] ^ t2r[1U];
}

void qsc_memutils_clmulepi64_si256(uint64_t r[8U], const uint64_t a[4U], const uint64_t b[4U])
{
    uint64_t a0[2U] = { a[0U], a[1U] };
    uint64_t a1[2U] = { a[2U], a[3U] };
    uint64_t b0[2U] = { b[0U], b[1U] };
    uint64_t b1[2U] = { b[2U], b[3U] };
    uint64_t p0[4U];
    uint64_t p1[4U];
    uint64_t p2[4U];
    uint64_t mid[4U];

    memutils_clmul128(p0, a0, b0);
    memutils_clmul128(p1, a1, b1);

    uint64_t a0xa1[2U] = { a0[0U] ^ a1[0U], a0[1U] ^ a1[1U] };
    uint64_t b0xb1[2U] = { b0[0U] ^ b1[0U], b0[1U] ^ b1[1U] };

    memutils_clmul128(p2, a0xa1, b0xb1);

    for (size_t i = 0U; i < 4U; ++i)
    {
        mid[i] = p0[i] ^ p1[i] ^ p2[i];
    }

    r[0U] = p0[0U];              r[1U] = p0[1U];
    r[2U] = p0[2U] ^ mid[0U];   r[3U] = p0[3U] ^ mid[1U];
    r[4U] = mid[2U] ^ p1[0U];   r[5U] = mid[3U] ^ p1[1U];
    r[6U] = p1[2U];              r[7U] = p1[3U];
}

#endif

bool qsc_memutils_greater_than_be128(const uint8_t* a, const uint8_t* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res = false;

    if (a != NULL && b != NULL)
    {
#if defined(QSC_SYSTEM_HAS_AVX)
        __m128i wa = _mm_loadu_si128((const __m128i*)a);
        __m128i wb = _mm_loadu_si128((const __m128i*)b);
        __m128i im = _mm_min_epu8(wa, wb);
        __m128i le = _mm_cmpeq_epi8(im, wa);
        __m128i ge = _mm_cmpeq_epi8(im, wb);

        uint32_t m1 = (uint32_t)_mm_movemask_epi8(le);
        uint32_t m2 = (uint32_t)_mm_movemask_epi8(ge);
        uint32_t diff = m1 ^ m2;
        uint32_t lsb = diff & (0U - diff);

        res = ((m2 & lsb) != 0U);
#else
        for (int32_t i = 0; i < 16; ++i)
        {
            if (a[i] > b[i]) { res = true;  break; }
            if (a[i] < b[i]) { res = false; break; }
        }
#endif
    }

    return res;
}

bool qsc_memutils_greater_than_be256(const uint8_t* a, const uint8_t* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res = false;

    if (a != NULL && b != NULL)
    {
#if defined(QSC_SYSTEM_HAS_AVX2)
        __m256i wa = _mm256_loadu_si256((const __m256i*)a);
        __m256i wb = _mm256_loadu_si256((const __m256i*)b);
        __m256i im = _mm256_min_epu8(wa, wb);
        __m256i le = _mm256_cmpeq_epi8(im, wa);
        __m256i ge = _mm256_cmpeq_epi8(im, wb);

        uint32_t m1 = (uint32_t)_mm256_movemask_epi8(le);
        uint32_t m2 = (uint32_t)_mm256_movemask_epi8(ge);
        uint32_t diff = m1 ^ m2;
        uint32_t lsb = diff & (0U - diff);

        res = ((m2 & lsb) != 0U);
#else
        if (qsc_memutils_are_equal_128(a, b))
        {
            res = qsc_memutils_greater_than_be128(a + 16U, b + 16U);
        }
        else
        {
            res = qsc_memutils_greater_than_be128(a, b);
        }
#endif
    }

    return res;
}

bool qsc_memutils_greater_than_be512(const uint8_t* a, const uint8_t* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res;

    res = false;

    if (a != NULL && b != NULL)
    {
#if defined(QSC_SYSTEM_HAS_AVX2)
        if (qsc_memutils_are_equal_256(a, b))
        {
            res = qsc_memutils_greater_than_be256(a + 32U, b + 32U);
        }
        else
        {
            res = qsc_memutils_greater_than_be256(a, b);
        }
#else
        if (!qsc_memutils_are_equal_128(a, b)) 
        { 
            res = qsc_memutils_greater_than_be128(a, b); 
        }
        else if (!qsc_memutils_are_equal_128(a + 16U, b + 16U)) 
        { 
            res = qsc_memutils_greater_than_be128(a + 16U, b + 16U); 
        }
        else if (!qsc_memutils_are_equal_128(a + 32U, b + 32U)) 
        { 
            res = qsc_memutils_greater_than_be128(a + 32U, b + 32U); 
        }
        else 
        { 
            res = qsc_memutils_greater_than_be128(a + 48U, b + 48U); 
        }
#endif
    }

    return res;
}

bool qsc_memutils_greater_than_le128(const uint8_t* a, const uint8_t* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res = false;

    if (a != NULL && b != NULL)
    {
#if defined(QSC_SYSTEM_HAS_AVX)
        __m128i wa = _mm_set_epi8(a[0U], a[1U], a[2U], a[3U], a[4U], a[5U], a[6U], a[7U],
            a[8U], a[9U], a[10U], a[11U], a[12U], a[13U], a[14U], a[15U]);

        __m128i wb = _mm_set_epi8(b[0U], b[1U], b[2U], b[3U], b[4U], b[5U], b[6U], b[7U],
            b[8U], b[9U], b[10U], b[11U], b[12U], b[13U], b[14U], b[15U]);

        __m128i im = _mm_min_epu8(wa, wb);

        uint32_t m1 = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(im, wa));
        uint32_t m2 = (uint32_t)_mm_movemask_epi8(_mm_cmpeq_epi8(im, wb));

        res = (m2 >= m1);
#else
        for (int32_t i = 15; i >= 0; --i)
        {
            if (a[i] > b[i]) 
            { 
                res = true; 
                break; 
            }

            if (a[i] < b[i]) 
            { 
                res = false; 
                break; 
            }
        }
#endif
    }

    return res;
}

bool qsc_memutils_greater_than_le256(const uint8_t* a, const uint8_t* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res = false;

    if (a != NULL && b != NULL)
    {
#if defined(QSC_SYSTEM_HAS_AVX2)
        __m256i wa = _mm256_set_epi8(
            a[0U], a[1U], a[2U], a[3U], a[4U], a[5U], a[6U], a[7U],
            a[8U], a[9U], a[10U], a[11U], a[12U], a[13U], a[14U], a[15U],
            a[16U], a[17U], a[18U], a[19U], a[20U], a[21U], a[22U], a[23U],
            a[24U], a[25U], a[26U], a[27U], a[28U], a[29U], a[30U], a[31U]);

        __m256i wb = _mm256_set_epi8(
            b[0U], b[1U], b[2U], b[3U], b[4U], b[5U], b[6U], b[7U],
            b[8U], b[9U], b[10U], b[11U], b[12U], b[13U], b[14U], b[15U],
            b[16U], b[17U], b[18U], b[19U], b[20U], b[21U], b[22U], b[23U],
            b[24U], b[25U], b[26U], b[27U], b[28U], b[29U], b[30U], b[31U]);

        __m256i im = _mm256_min_epu8(wa, wb);

        uint32_t m1 = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(im, wa));
        uint32_t m2 = (uint32_t)_mm256_movemask_epi8(_mm256_cmpeq_epi8(im, wb));

        res = (m2 >= m1);
#else
        if (qsc_memutils_are_equal_128(a + 16U, b + 16U))
        {
            res = qsc_memutils_greater_than_le128(a, b);
        }
        else
        {
            res = qsc_memutils_greater_than_le128(a + 16U, b + 16U);
        }
#endif
    }

    return res;
}

bool qsc_memutils_greater_than_le512(const uint8_t* a, const uint8_t* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res;

    res = false;

    if (a != NULL && b != NULL)
    {
#if defined(QSC_SYSTEM_HAS_AVX2)
        if (qsc_memutils_are_equal_256(a + 32U, b + 32U))
        {
            res = qsc_memutils_greater_than_le256(a, b);
        }
        else
        {
            res = qsc_memutils_greater_than_le256(a + 32U, b + 32U);
        }
#else
        if (!qsc_memutils_are_equal_128(a + 48U, b + 48U)) 
        { 
            res = qsc_memutils_greater_than_le128(a + 48U, b + 48U); 
        }
        else if (!qsc_memutils_are_equal_128(a + 32U, b + 32U)) 
        { 
            res = qsc_memutils_greater_than_le128(a + 32U, b + 32U); 
        }
        else if (!qsc_memutils_are_equal_128(a + 16U, b + 16U)) 
        { 
            res = qsc_memutils_greater_than_le128(a + 16U, b + 16U); 
        }
        else 
        { 
            res = qsc_memutils_greater_than_le128(a, b); 
        }
#endif
    }

    return res;
}

void qsc_memutils_move(void* output, const void* input, size_t length)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(length != 0U);

    if (output != NULL && input != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_OS_WINDOWS)
        memmove_s(output, length, input, length);
#else
        memmove(output, input, length);
#endif
    }
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void memutils_setval128(void* output, uint8_t value)
{
    _mm_storeu_si128((__m128i*)output, _mm_set1_epi8((char)value));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_setval256(void* output, uint8_t value)
{
    _mm256_storeu_si256((__m256i*)output, _mm256_set1_epi8((char)value));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_setval512(void* output, uint8_t value)
{
    _mm512_storeu_si512((__m512i*)output, _mm512_set1_epi8((char)value));
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON) && !defined(QSC_SYSTEM_HAS_AVX)
static void memutils_setval128(void* output, uint8_t value)
{
    vst1q_u8((uint8_t*)output, vdupq_n_u8(value));
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON)
static void memutils_setval256_neon(void* output, uint8_t value)
{
    uint8x16_t v = vdupq_n_u8(value);

    vst1q_u8((uint8_t*)output, v);
    vst1q_u8((uint8_t*)output + 16U, v);
}
#endif

#if defined(QSC_SYSTEM_HAS_RVV)
static void memutils_setval_rvv(void* output, uint8_t value, size_t length)
{
    uint8_t* ptr;
    size_t rmd;

    ptr = (uint8_t*)output;
    rmd = length;

    while (rmd > 0U)
    {
        size_t vl = __riscv_vsetvl_e8m8(rmd);

        vuint8m8_t v = __riscv_vmv_v_x_u8m8(value, vl);
        __riscv_vse8_v_u8m8(ptr, v, vl);
        ptr += vl;
        rmd -= vl;
    }
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_SVE)
static void memutils_setval_sve(void* output, uint8_t value, size_t length)
{
    uint8_t* ptr;
    size_t rmd;
    svbool_t pg;

    svuint8_t v = svdup_n_u8(value);
    ptr = (uint8_t*)output;
    rmd = length;

    while (rmd >= svcntb())
    {
        pg = svptrue_b8();
        svst1_u8(pg, ptr, v);
        ptr += svcntb();
        rmd -= svcntb();
    }

    if (rmd > 0U)
    {
        pg = svwhilelt_b8_u64(0ULL, (uint64_t)rmd);
        svst1_u8(pg, ptr, v);
    }
}
#endif

void qsc_memutils_set_value(void* output, size_t length, uint8_t value)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(length != 0U);

    if (output != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_HAS_RVV)
        memutils_setval_rvv(output, value, length);
#elif defined(QSC_SYSTEM_HAS_ARM_SVE)
        memutils_setval_sve(output, value, length);
#else
        size_t pctr;

        pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#   if defined(QSC_SYSTEM_HAS_AVX512)
        const size_t SMDBLK = 64U;
#   elif defined(QSC_SYSTEM_HAS_AVX2)
        const size_t SMDBLK = 32U;
#   else
        const size_t SMDBLK = 16U;
#   endif
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        const size_t SMDBLK = 32U;
#endif

#if defined(QSC_SYSTEM_AVX_INTRINSICS) || defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (SMDBLK > 0U && length >= SMDBLK)
        {
            const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

            while (pctr != ALNLEN)
            {
#   if defined(QSC_SYSTEM_HAS_AVX512)
                memutils_setval512((uint8_t*)output + pctr, value);
#   elif defined(QSC_SYSTEM_HAS_AVX2)
                memutils_setval256((uint8_t*)output + pctr, value);
#   elif defined(QSC_SYSTEM_HAS_AVX)
                memutils_setval128((uint8_t*)output + pctr, value);
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
                memutils_setval256_neon((uint8_t*)output + pctr, value);
#   endif
                pctr += SMDBLK;
            }
        }

#   if defined(QSC_SYSTEM_HAS_AVX512)
        if (length - pctr >= 32U) 
        { 
            memutils_setval256((uint8_t*)output + pctr, value); 
            pctr += 32U; 
        }
        else if (length - pctr >= 16U) 
        {
            memutils_setval128((uint8_t*)output + pctr, value); 
            pctr += 16U; 
        }
#   elif defined(QSC_SYSTEM_HAS_AVX2)
        if (length - pctr >= 16U)
        {
            memutils_setval128((uint8_t*)output + pctr, value); 
            pctr += 16U; 
        }
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (length - pctr >= 16U) 
        { 
            memutils_setval128((uint8_t*)output + pctr, value); 
            pctr += 16U; 
        }
#   endif
#endif

        for (size_t i = pctr; i < length; ++i)
        {
            ((uint8_t*)output)[i] = value;
        }
#endif
    }
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void memutils_xor128(uint8_t* output, const uint8_t* input)
{
    _mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*)input), _mm_loadu_si128((const __m128i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_xor256(uint8_t* output, const uint8_t* input)
{
    _mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)input), _mm256_loadu_si256((const __m256i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_xor512(uint8_t* output, const uint8_t* input)
{
    _mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)input), _mm512_loadu_si512((const __m512i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON) && !defined(QSC_SYSTEM_HAS_AVX)
static void memutils_xor128(uint8_t* output, const uint8_t* input)
{
    vst1q_u8(output, veorq_u8(vld1q_u8(input), vld1q_u8(output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON)
static void memutils_xor256_neon(uint8_t* output, const uint8_t* input)
{
    vst1q_u8(output, veorq_u8(vld1q_u8(input), vld1q_u8(output)));
    vst1q_u8(output + 16U, veorq_u8(vld1q_u8(input + 16U), vld1q_u8(output + 16U)));
}
#endif

#if defined(QSC_SYSTEM_HAS_RVV)
static void memutils_xor_rvv(uint8_t* output, const uint8_t* input, size_t length)
{
    size_t rmd;

    rmd = length;

    while (rmd > 0U)
    {
        size_t vl = __riscv_vsetvl_e8m8(rmd);
        vuint8m8_t va = __riscv_vle8_v_u8m8(output, vl);
        vuint8m8_t vb = __riscv_vle8_v_u8m8(input, vl);
        __riscv_vse8_v_u8m8(output, __riscv_vxor_vv_u8m8(va, vb, vl), vl);
        output += vl;
        input += vl;
        rmd -= vl;
    }
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_SVE)
static void memutils_xor_sve(uint8_t* output, const uint8_t* input, size_t length)
{
    size_t rmd;
    svbool_t pg;

    rmd = length;

    while (rmd >= svcntb())
    {
        pg = svptrue_b8();
        svst1_u8(pg, output, sveor_u8_z(pg, svld1_u8(pg, output), svld1_u8(pg, input)));
        output += svcntb();
        input += svcntb();
        rmd -= svcntb();
    }

    if (rmd > 0U)
    {
        pg = svwhilelt_b8_u64(0ULL, (uint64_t)rmd);
        svst1_u8(pg, output, sveor_u8_z(pg, svld1_u8(pg, output), svld1_u8(pg, input)));
    }
}
#endif

void qsc_memutils_xor(uint8_t* output, const uint8_t* input, size_t length)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(length != 0U);

    if (output != NULL && input != NULL && length != 0U)
    {
        size_t pctr;

#if defined(QSC_SYSTEM_HAS_RVV)
        memutils_xor_rvv(output, input, length);
#elif defined(QSC_SYSTEM_HAS_ARM_SVE)
        memutils_xor_sve(output, input, length);
#else
        pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#   if defined(QSC_SYSTEM_HAS_AVX512)
        const size_t SMDBLK = 64U;
#   elif defined(QSC_SYSTEM_HAS_AVX2)
        const size_t SMDBLK = 32U;
#   else
        const size_t SMDBLK = 16U;
#   endif
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        const size_t SMDBLK = 32U;
#endif

#if defined(QSC_SYSTEM_AVX_INTRINSICS) || defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (SMDBLK > 0U && length >= SMDBLK)
        {
            const size_t ALNLEN = length - (length % SMDBLK);

            while (pctr != ALNLEN)
            {
#   if defined(QSC_SYSTEM_HAS_AVX512)
                memutils_xor512(output + pctr, input + pctr);
#   elif defined(QSC_SYSTEM_HAS_AVX2)
                memutils_xor256(output + pctr, input + pctr);
#   elif defined(QSC_SYSTEM_HAS_AVX)
                memutils_xor128(output + pctr, input + pctr);
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
                memutils_xor256_neon(output + pctr, input + pctr);
#   endif
                pctr += SMDBLK;
            }
        }
#endif

#   if defined(QSC_SYSTEM_HAS_AVX512)
        if (length - pctr >= 32U) 
        {
            memutils_xor256(output + pctr, input + pctr); 
            pctr += 32U; 
        }
        else if (length - pctr >= 16U)
        { 
            memutils_xor128(output + pctr, input + pctr); 
            pctr += 16U; 
        }
#   elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (length - pctr >= 16U) 
        {
            memutils_xor128(output + pctr, input + pctr); 
            pctr += 16U; 
        }
#   endif

        for (size_t i = pctr; i < length; ++i)
        {
            output[i] ^= input[i];
        }
#endif
    }
}

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_xorv512(uint8_t* output, uint8_t value)
{
    __m512i v = _mm512_set1_epi8((char)value);

    _mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(v, _mm512_loadu_si512((const __m512i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_xorv256(uint8_t* output, uint8_t value)
{
    __m256i v = _mm256_set1_epi8((char)value);

    _mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(v, _mm256_loadu_si256((const __m256i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX)
static void memutils_xorv128(uint8_t* output, uint8_t value)
{
    __m128i v = _mm_set1_epi8((char)value);

    _mm_storeu_si128((__m128i*)output, _mm_xor_si128(v, _mm_loadu_si128((const __m128i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON) && !defined(QSC_SYSTEM_HAS_AVX)
static void memutils_xorv128(uint8_t* output, uint8_t value)
{
    vst1q_u8(output, veorq_u8(vdupq_n_u8(value), vld1q_u8(output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_ARM_NEON)
static void memutils_xorv256_neon(uint8_t* output, uint8_t value)
{
    uint8x16_t v = vdupq_n_u8(value);
    vst1q_u8(output, veorq_u8(v, vld1q_u8(output)));
    vst1q_u8(output + 16U, veorq_u8(v, vld1q_u8(output + 16U)));
}
#endif

#if defined(QSC_SYSTEM_HAS_RVV)
static void memutils_xorv_rvv(uint8_t* output, uint8_t value, size_t length)
{
    size_t rmd = length;

    while (rmd > 0U)
    {
        size_t vl = __riscv_vsetvl_e8m8(rmd);
        vuint8m8_t vout = __riscv_vle8_v_u8m8(output, vl);
        vuint8m8_t vval = __riscv_vmv_v_x_u8m8(value, vl);
        __riscv_vse8_v_u8m8(output, __riscv_vxor_vv_u8m8(vout, vval, vl), vl);
        output += vl;
        rmd -= vl;
    }
}
#endif

void qsc_memutils_xorv(uint8_t* output, const uint8_t value, size_t length)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(length != 0U);

    if (output != NULL && length != 0U)
    {
        size_t pctr;

#if defined(QSC_SYSTEM_HAS_RVV)
        memutils_xorv_rvv(output, value, length);
#else
        pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#   if defined(QSC_SYSTEM_HAS_AVX512)
        const size_t SMDBLK = 64U;
#   elif defined(QSC_SYSTEM_HAS_AVX2)
        const size_t SMDBLK = 32U;
#   else
        const size_t SMDBLK = 16U;
#   endif
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
        const size_t SMDBLK = 32U;
#endif

#if defined(QSC_SYSTEM_AVX_INTRINSICS) || defined(QSC_SYSTEM_HAS_ARM_NEON)
        if (SMDBLK > 0U && length >= SMDBLK)
        {
            const size_t ALNLEN = length - (length % SMDBLK);

            while (pctr != ALNLEN)
            {
#   if defined(QSC_SYSTEM_HAS_AVX512)
                memutils_xorv512(output + pctr, value);
#   elif defined(QSC_SYSTEM_HAS_AVX2)
                memutils_xorv256(output + pctr, value);
#   elif defined(QSC_SYSTEM_HAS_AVX)
                memutils_xorv128(output + pctr, value);
#   elif defined(QSC_SYSTEM_HAS_ARM_NEON)
                memutils_xorv256_neon(output + pctr, value);
#   endif
                pctr += SMDBLK;
            }
        }

        if (length - pctr >= 16U) 
        { 
            memutils_xorv128(output + pctr, value); pctr += 16U; 
        }
#endif

        for (size_t i = pctr; i < length; ++i)
        {
            output[i] ^= value;
        }
#endif
    }
}

void qsc_memutils_secure_erase(void* block, size_t length)
{
    QSC_ASSERT(block != NULL);
    QSC_ASSERT(length != 0U);

    if (block != NULL && length != 0U)
    {
#if defined(__STDC_LIB_EXT1__)
        (void)memset_s(block, length, 0, length);
#elif defined(QSC_RTL_SECURE_MEMORY)
        RtlSecureZeroMemory(block, length);
#else
        volatile unsigned char* p = (volatile unsigned char*)block;

        while (length != 0U)
        {
            *p++ = 0U;
            --length;
        }

        QSC_COMPILER_BARRIER();
#endif
    }
}

void qsc_memutils_secure_free(void* block, size_t length)
{
    QSC_ASSERT(block != NULL);
    QSC_ASSERT(length != 0U);

    if (block != NULL && length != 0U)
    {
#if defined(QSC_SYSTEM_OS_POSIX)

        qsc_memutils_secure_erase(block, length);

#   if defined(QSC_SYSTEM_POSIX_MLOCK)
        munlock(block, length);
#   endif

        munmap(block, length);

#elif defined(QSC_SYSTEM_VIRTUAL_LOCK)

        qsc_memutils_secure_erase(block, length);

        if (block != NULL)
        {
            VirtualUnlock(block, length);
            VirtualFree(block, 0U, MEM_RELEASE);
        }

#else
        free(block);
#endif
    }
}

void* qsc_memutils_secure_malloc(size_t length)
{
    QSC_ASSERT(length != 0U);

    const size_t PGESZE = qsc_memutils_page_size();
    void* ptr;

    ptr = NULL;

    if (length != 0U)
    {
        if (length % PGESZE != 0U)
        {
            length = (length + PGESZE - (length % PGESZE));
        }

#if defined(QSC_SYSTEM_OS_POSIX)

#   if !defined(MAP_NOCORE)
#       define MAP_NOCORE 0
#   endif

#   if !defined(MAP_ANONYMOUS)
#       define MAP_ANONYMOUS 0x0002
#   endif

        ptr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NOCORE, -1, 0);

        if (ptr == MAP_FAILED) 
        { 
            ptr = NULL; 
        }

        if (ptr != NULL)
        {
#   if defined(MADV_DONTDUMP)
            madvise(ptr, length, MADV_DONTDUMP);
#   endif

#   if defined(QSC_SYSTEM_POSIX_MLOCK)
            if (mlock(ptr, length) != 0)
            {
                qsc_memutils_clear(ptr, length);
                munmap(ptr, length);
                ptr = NULL;
            }
#   endif
        }

#elif defined(QSC_SYSTEM_VIRTUAL_LOCK)

        ptr = VirtualAlloc(NULL, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

        if (ptr != NULL && VirtualLock((LPVOID)ptr, length) == 0U)
        {
            VirtualFree((LPVOID)ptr, 0U, MEM_RELEASE);
            ptr = NULL;
        }

#else
        ptr = malloc(length);
#endif
    }

    return ptr;
}

bool qsc_memutils_zeroed(const void* input, size_t length)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(length != 0U);

    bool res;

    res = false;

    if (input != NULL && length != 0U)
    {
        const uint8_t* pinp = (const uint8_t*)input;
        size_t j = 0U;

        for (size_t i = 0U; i < length; ++i)
        {
            j |= pinp[i];
        }

        res = (j == 0U);
    }

    return res;
}
