#include "memutils.h"
#include <stdlib.h>
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	include "intrinsics.h"
#endif
#if defined(QSC_SYSTEM_OS_OPENBSD)
#	include <string.h>
#endif
#if defined(QSC_SYSTEM_OS_POSIX)
#	include <sys/types.h>
#	include <sys/resource.h>
#	include <sys/mman.h>
#	include <signal.h>
#	include <setjmp.h>
#	include <unistd.h>
#	include <errno.h>
#elif defined(QSC_SYSTEM_OS_WINDOWS)
#	include <windows.h>
#endif

void qsc_memutils_flush_cache_line(void *address) 
{
	QSC_ASSERT(address != NULL);

	if (address != NULL)
	{
#if defined(__GNUC__) || defined(__clang__)
		__builtin___clear_cache((char*)address, (char*)address + QSC_MEMUTILS_CACHE_LINE_SIZE);
#elif defined(_MSC_VER)
		_mm_clflush(address);
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
		_mm_prefetch(((char*)address + length), _MM_HINT_T0);
#else
		volatile uint8_t tmp;
		size_t i;

		tmp = 0U;

		for (i = 0U; i < length; ++i)
		{
			tmp |= address[i];
		}
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
		_mm_prefetch(((char*)address + length), _MM_HINT_T1);
#else
		volatile uint8_t tmp;
		size_t i;

		tmp = 0U;

		for (i = 0U; i < length; ++i)
		{
			tmp |= address[i];
		}
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
		_mm_prefetch(((char*)address + length), _MM_HINT_T2);
#else
		volatile uint8_t tmp;
		size_t i;

		tmp = 0U;

		for (i = 0U; i < length; ++i)
		{
			tmp |= address[i];
		}
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

size_t qsc_memutils_page_size()
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
	pagelen = (size_t)sysinfo.dwPageSize;
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

		res = posix_memalign(&ret, align, length);

		if (res != 0)
		{
			ret = NULL;
		}
#else
		ret = (void*)malloc(length);
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
#	else
		free(block);
#	endif
	}
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void memutils_clear128(volatile void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_setzero_si128());
}
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
static void memutils_clear128(volatile void* output)
{
    // Create a 128-bit vector with all bytes set to 0.
    uint8x16_t zeros = vdupq_n_u8(0);
    // Store the 128-bit vector into the output buffer.
    vst1q_u8((uint8_t*)output, zeros);
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

void qsc_memutils_clear(void* output, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);

	size_t pctr;

	if (output != NULL && length != 0U)
	{
		pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32U;
#	else
		const size_t SMDBLK = 16U;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#	if defined(QSC_SYSTEM_HAS_AVX512)
				memutils_clear512((volatile uint8_t*)output + pctr);
#	elif defined(QSC_SYSTEM_HAS_AVX2)
				memutils_clear256((volatile uint8_t*)output + pctr);
#	elif defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_HAS_ARM_NEON)
				memutils_clear128((volatile uint8_t*)output + pctr);
#	endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
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
#elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_HAS_ARM_NEON)
		if (length - pctr >= 16U)
		{
			memutils_clear128((volatile uint8_t*)output + pctr);
			pctr += 16U;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((volatile uint8_t*)output)[i] = 0x00U;
			}
		}
	}
}


#if defined(QSC_SYSTEM_HAS_AVX)
static bool memutils_equal128(const uint8_t* a, const uint8_t* b)
{
	__m128i wa;
	__m128i wb;
	__m128i wc;
	uint64_t ra[sizeof(__m128i) / sizeof(uint64_t)] = { 0U };

	wa = _mm_loadu_si128((const __m128i*)a);
	wb = _mm_loadu_si128((const __m128i*)b);
	wc = _mm_cmpeq_epi64(wa, wb);
	_mm_storeu_si128((__m128i*)ra, wc);

	return ((~ra[0U] + ~ra[1U]) == 0);
}
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
static bool memutils_equal128(const uint8_t* a, const uint8_t* b)
{
    // Load 128-bit vectors from memory (unaligned loads are allowed)
    uint8x16_t va = vld1q_u8(a);
    uint8x16_t vb = vld1q_u8(b);

    // Compare each byte for equality. For each byte, the result is 0xFF if equal, 0x00 otherwise.
    uint8x16_t cmp = vceqq_u8(va, vb);

    // Compute the minimum value of all lanes. If all lanes are 0xFF then the minimum will be 0xFF.
    uint8_t minval = vminvq_u8(cmp);

    return (minval == 0xFFU);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static bool memutils_equal256(const uint8_t* a, const uint8_t* b)
{
	__m256i wa;
	__m256i wb;
	__m256i wc;
	uint64_t ra[sizeof(__m256i) / sizeof(uint64_t)] = { 0U };

	wa = _mm256_loadu_si256((const __m256i*)a);
	wb = _mm256_loadu_si256((const __m256i*)b);
	wc = _mm256_cmpeq_epi64(wa, wb);
	_mm256_storeu_si256((__m256i*)ra, wc);

	return ((~ra[0U] + ~ra[1U] + ~ra[2U] + ~ra[3U]) == 0);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static bool memutils_equal512(const uint8_t* a, const uint8_t* b)
{
	__m512i va;
	__m512i vb;
	__mmask8 eq64;

    va = _mm512_loadu_si512(a);
    vb = _mm512_loadu_si512(b);
    eq64 = _mm512_cmpeq_epi64_mask(va, vb);

    return (eq64 == 0xFFU);
}
#endif

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

	size_t pctr;
	int32_t mctr;
	bool res;

	mctr = 0;
	pctr = 0U;
	res = false;

	if (a != NULL && b != NULL && length != 0U)
	{

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64U;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32U;
#	else
		const size_t SMDBLK = 16U;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#if defined(QSC_SYSTEM_HAS_AVX512)
				mctr |= ((int32_t)memutils_equal512(a + pctr, b + pctr) - 1);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				mctr |= ((int32_t)memutils_equal256(a + pctr, b + pctr) - 1);
#elif defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_HAS_ARM_NEON)
				mctr |= ((int32_t)memutils_equal128(a + pctr, b + pctr) - 1);
#endif
				pctr += SMDBLK;
			}
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				mctr |= (a[i] ^ b[i]);
			}
		}

		res = (mctr == 0U);
	}

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
		res = memutils_equal128(a, b);
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
#elif defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_HAS_ARM_NEON)
		res = (memutils_equal128(a, b) &&
			memutils_equal128(a + sizeof(__m128i), b + sizeof(__m128i)));
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
		res = memutils_equal256(a, b) &&
			memutils_equal256(a + sizeof(__m256i), b + sizeof(__m256i));
#elif defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_HAS_ARM_NEON)
		res = (memutils_equal128(a, b) &&
			memutils_equal128(a + sizeof(__m128i), b + sizeof(__m128i)) &&
			memutils_equal128(a + (2 * sizeof(__m128i)), b + (2 * sizeof(__m128i))) &&
			memutils_equal128(a + (3 * sizeof(__m128i)), b + (3 * sizeof(__m128i))));
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
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
static void memutils_copy128(void* output, const void* input)
{
    uint8x16_t data = vld1q_u8((const uint8_t*)input);
    vst1q_u8((uint8_t*)output, data);
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

void qsc_memutils_copy(void* output, const void* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	size_t pctr;

	if (output != NULL && input != NULL && length != 0U)
	{
		pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64U;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32U;
#	else
		const size_t SMDBLK = 16U;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#if defined(QSC_SYSTEM_HAS_AVX512)
				memutils_copy512((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				memutils_copy256((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_HAS_ARM_NEON)
				memutils_copy128((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32U)
		{
			memutils_copy256((uint8_t*)output + pctr, (uint8_t*)input + pctr);
			pctr += 32U;
		}
		else if (length - pctr >= 16U)
		{
			memutils_copy128((uint8_t*)output + pctr, (uint8_t*)input + pctr);
			pctr += 16U;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_HAS_ARM_NEON)
		if (length - pctr >= 16U)
		{
			memutils_copy128((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
			pctr += 16U;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = ((const uint8_t*)input)[i];
			}
		}
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
        bit  = (x >> i) & 1ULL;
        mask = 0U - bit;
        /* add the contribution of y shifted left by i */
        r[0U] ^= (y << i) & mask;

        /* compute the overflow (high) contribution in constant time. */
        nz = (uint64_t)(i != 0U);
        mi = 0U - nz;
        ss = (64U - i) & mi;
        hc = (y >> ss) & mi;

        r[1U] ^= hc & mask;
    }
}

void qsc_memutils_clmulepi64_si128(uint64_t r[2U], const uint64_t a[2U], const uint64_t b[2U], int32_t imm8) 
{
    size_t inda = (imm8 & 0x01)  ? 1U : 0U;
    size_t indb = (imm8 & 0x10) ? 1U : 0U;

    memutils_clmulepi64(r, a[inda], b[indb]);
}

#if defined(QSC_SYSTEM_HAS_AVX) && defined(QSC_SYSTEM_X86)

static inline void memutils_clmul128(__m128i a, __m128i b, __m128i* low, __m128i* high)
{
    /* partial products */
    __m128i p00 = _mm_clmulepi64_si128(a, b, 0x00); /* low × low */
    __m128i p11 = _mm_clmulepi64_si128(a, b, 0x11); /* high × high */
    __m128i p01 = _mm_clmulepi64_si128(a, b, 0x01); /* low × high */
    __m128i p10 = _mm_clmulepi64_si128(a, b, 0x10); /* high × low */

    __m128i mid = _mm_xor_si128(p01, p10); /* cross terms */
    mid = _mm_xor_si128(mid, _mm_xor_si128(p00, p11));

    /* combine the lower 128 bits is p00; the upper 128 bits is p11 */
    /* the cross term 'mid' is split between the two */
    __m128i mid_lo = _mm_slli_si128(mid, 8);    /* shift left by 8 bytes */
    __m128i mid_hi = _mm_srli_si128(mid, 8);    /* shift right by 8 bytes */

    *low  = _mm_xor_si128(p00, mid_lo);
    *high = _mm_xor_si128(p11, mid_hi);
}

void qsc_memutils_clmulepi64_si256_avx(__m128i r[4U], const __m128i a[2U], const __m128i b[2U])
{
	/* compute the three partial products */
    __m128i p0low = _mm_setzero_si128();
    __m128i p0high = _mm_setzero_si128();

    // p0 = a0 * b0
    memutils_clmul128(a[0U], b[0U], &p0low, &p0high);

    __m128i p1low = _mm_setzero_si128();
    __m128i p1high = _mm_setzero_si128();
    // p1 = a1 * b1
    memutils_clmul128(a[1U], b[1U], &p1low, &p1high);

    __m128i a0xa1 = _mm_xor_si128(a[0U], a[1U]);
    __m128i b0xb1 = _mm_xor_si128(b[0U], b[1U]);
    __m128i p2low = _mm_setzero_si128();
    __m128i p2high = _mm_setzero_si128();

    /* p2 = (a0 ^ a1) * (b0 ^ b1) */
    memutils_clmul128(a0xa1, b0xb1, &p2low, &p2high);

    /* compute the 'middle' term : m = p0 ^ p1 ^ p2 */
    __m128i mlow  = _mm_xor_si128(p0low,  _mm_xor_si128(p1low,  p2low));
    __m128i mhigh = _mm_xor_si128(p0high, _mm_xor_si128(p1high, p2high));

    /* assemble the final 512-bit product from 4× 128-bit pieces */
    /* r0 = lower 128 bits of p0 */
    r[0U] = p0low;
    /* r1 = (upper 128 bits of p0) ^ (lower 128 bits of m) */
    r[1U] = _mm_xor_si128(p0high, mlow);
    /* r2 = (upper 128 bits of m) ^ (lower 128 bits of p1) */
    r[2U] = _mm_xor_si128(mhigh, p1low);
    /* r3 = upper 128 bits of p1 */
    r[3U] = p1high;
}

void qsc_memutils_clmulepi64_si256(uint64_t r[8U], const uint64_t a[4U], const uint64_t b[4U])
{
	__m128i ma[2U] = { 0U };
	__m128i mb[2U] = { 0U };
	__m128i mr[4U] = { 0U };

    /* load 256-bit operands as two 128-bit pieces each */
    ma[0U] = _mm_loadu_si128((const __m128i*)(a));      /* lower 128 bits of A */
    ma[1U] = _mm_loadu_si128((const __m128i*)(a + 2U));  /* upper 128 bits of A */
    mb[0U] = _mm_loadu_si128((const __m128i*)(b));      /* lower 128 bits of B */
    mb[1U] = _mm_loadu_si128((const __m128i*)(b + 2U));  /* upper 128 bits of B */

	qsc_memutils_clmulepi64_si256_avx(mr, ma, mb);

    /* store the result */
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
    uint64_t low[2U];
    uint64_t high[2U];

    /* compute partial products. */
    memutils_clmulepi64(p00, a[0U], b[0U]);
    memutils_clmulepi64(p11, a[1U], b[1U]);
    memutils_clmulepi64(p10, a[1U], b[0U]);
    memutils_clmulepi64(p01, a[0U], b[1U]);

    /* t2 = p10 xor p01 */
    t2[0U] = p10[0U] ^ p01[0U];
    t2[1U] = p10[1U] ^ p01[1U];

    /* xor in (p00 ^ p11) */
    t2[0U] ^= p00[0U] ^ p11[0U];
    t2[1U] ^= p00[1U] ^ p11[1U];

    /* shift t2 left by 64 bits: lower word becomes 0, upper word becomes t2[0U] */
    t2l[0U] = 0U;
    t2l[1U] = t2[0U];

    /* shift t2 right by 64 bits: lower word becomes t2[1U], upper word becomes 0 */
    t2r[0U] = t2[1U];
    t2r[1U] = 0U;

    /* combine the lower 128 bits is p00; the upper 128 bits is p11 */
    /* the cross term 'mid' is split between the two */
    low[0U]  = p00[0U] ^ t2l[0U];
    low[1U]  = p00[1U] ^ t2l[1U];
    high[0U] = p11[0U] ^ t2r[0U];
    high[1U] = p11[1U] ^ t2r[1U];

    r[0U] = low[0U];
    r[1U] = low[1U];
    r[2U] = high[0U];
    r[3U] = high[1U];
}

void qsc_memutils_clmulepi64_si256(uint64_t r[8U], const uint64_t a[4U], const uint64_t b[4U])
{
    /* split the 256-bit operands into 128-bit halves */
    uint64_t a0[2U] = { a[0U], a[1U] };  /* lower 128 bits of a */
    uint64_t a1[2U] = { a[2U], a[3U] };  /* upper 128 bits of a */
    uint64_t b0[2U] = { b[0U], b[1U] };  /* lower 128 bits of b */
    uint64_t b1[2U] = { b[2U], b[3U] };  /* upper 128 bits of b */
    uint64_t p0[4U];  /* p0 = a0 * b0, 256 bits */
    uint64_t p1[4U];  /* p1 = a1 * b1, 256 bits */
    uint64_t p2[4U];  /* p2 = (a0 ^ a1) * (b0 ^ b1), 256 bits */
    uint64_t mid[4U];   /* middle term */

    /* Compute the three 256-bit partial products using clmul128. */
    memutils_clmul128(p0, a0, b0);
    memutils_clmul128(p1, a1, b1);

    uint64_t a0xa1[2U] = { a0[0U] ^ a1[0U], a0[1U] ^ a1[1U] };
    uint64_t b0xb1[2U] = { b0[0U] ^ b1[0U], b0[1U] ^ b1[1U] };
    memutils_clmul128(p2, a0xa1, b0xb1);

    /* compute mid = p0 ^ p1 ^ p2 */
    mid[0U] = p0[0U] ^ p1[0U] ^ p2[0U];
    mid[1U] = p0[1U] ^ p1[1U] ^ p2[1U];
    mid[2U] = p0[2U] ^ p1[2U] ^ p2[2U];
    mid[3U] = p0[3U] ^ p1[3U] ^ p2[3U];

    uint64_t r0[2U];
    uint64_t r1[2U];
    uint64_t r2[2U];
    uint64_t r3[2U];

    /* assemble the final 512‑bit product as four 128‑bit words */
    /* r0 = lower 128 bits of p0 = { p0[0U], p0[1U] } */
    r0[0U] = p0[0U];
    r0[1U] = p0[1U];
    /* r1 = (upper 128 bits of p0) ^ (lower 128 bits of mid) = { p0[2U] ^ mid[0U], p0[3U] ^ mid[1U] } */
    r1[0U] = p0[2U] ^ mid[0U];
    r1[1U] = p0[3U] ^ mid[1U];
    /* r2 = (upper 128 bits of mid) ^ (lower 128 bits of p1) = { mid[2U] ^ p1[0U], mid[3U] ^ p1[1U] } */
    r2[0U] = mid[2U]  ^ p1[0U];
    r2[1U] = mid[3U] ^ p1[1U];
    /* r3 = upper 128 bits of p1 = { p1[2U], p1[3U] } */
    r3[0U] = p1[2U];
    r3[1U] = p1[3U];

    /* pack the four 128-bit words into the 512-bit result r[8U] */
    r[0U] = r0[0U];
    r[1U] = r0[1U];
    r[2U] = r1[0U];
    r[3U] = r1[1U];
    r[4U] = r2[0U];
    r[5U] = r2[1U];
    r[6U] = r3[0U];
    r[7U] = r3[1U];
}

#endif

bool qsc_memutils_greater_than_be128(const uint8_t* a, const uint8_t* b)
{
	QSC_ASSERT(a != NULL);
	QSC_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX)

		__m128i ge;
		__m128i im;
		__m128i le;
		__m128i wa;
		__m128i wb;
		uint32_t m1;
		uint32_t m2;

		wa = _mm_loadu_si128((const __m128i*)a);
		wb = _mm_loadu_si128((const __m128i*)b);
		im = _mm_min_epu8(wa, wb);
		le = _mm_cmpeq_epi8(im, wa);
		ge = _mm_cmpeq_epi8(im, wb);
		m1 = (uint32_t)_mm_movemask_epi8(le);
		m2 = (uint32_t)_mm_movemask_epi8(ge);
		res = (m2 >= m1);

#else

		for (int32_t i = 15; i >= 0; --i)
		{
			if (a[i] > b[i])
			{
				res = true;
				break;
			}
			else if (a[i] < b[i])
			{
				res = false;
				break;
			}
		}

#endif
	}

	return res;
}

bool qsc_memutils_greater_than_be256(const uint8_t* a, const uint8_t* b)
{
	QSC_ASSERT(a != NULL);
	QSC_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)

		__m256i ge;
		__m256i im;
		__m256i le;
		__m256i wa;
		__m256i wb;
		uint32_t m1;
		uint32_t m2;

		wa = _mm256_loadu_si256((const __m256i*)a);
		wb = _mm256_loadu_si256((const __m256i*)b);
		im = _mm256_min_epu8(wa, wb);
		le = _mm256_cmpeq_epi8(im, wa);
		ge = _mm256_cmpeq_epi8(im, wb);
		m1 = (uint32_t)_mm256_movemask_epi8(le);
		m2 = (uint32_t)_mm256_movemask_epi8(ge);
		res = (m2 >= m1);

#else
		res = qsc_memutils_greater_than_be128(a, b);
		res |= qsc_memutils_greater_than_be128(a + 16, b + 16);
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
		res = qsc_memutils_greater_than_be256(a, b);
		res |= qsc_memutils_greater_than_be256(a + 32U, b + 32U);
#else
		res = qsc_memutils_greater_than_be128(a, b);
		res |= qsc_memutils_greater_than_be128(a + 16U, b + 16U);
		res |= qsc_memutils_greater_than_be128(a + 32U, b + 32U);
		res |= qsc_memutils_greater_than_be128(a + 48U, b + 48U);
#endif
	}

	return res;
}

bool qsc_memutils_greater_than_le128(const uint8_t* a, const uint8_t* b)
{
	QSC_ASSERT(a != NULL);
	QSC_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX)

		__m128i ge;
		__m128i im;
		__m128i le;
		__m128i wa;
		__m128i wb;
		uint32_t m1;
		uint32_t m2;

		wa = _mm_set_epi8(a[0U], a[1U], a[2U], a[3U], a[4U], a[5U], a[6U], a[7U], a[8U], a[9U], a[10U], a[11U], a[12U], a[13U], a[14U], a[15U]);
		wb = _mm_set_epi8(b[0U], b[1U], b[2U], b[3U], b[4U], b[5U], b[6U], b[7U], b[8U], b[9U], b[10U], b[11U], b[12U], b[13U], b[14U], b[15U]);
		im = _mm_min_epu8(wa, wb);
		le = _mm_cmpeq_epi8(im, wa);
		ge = _mm_cmpeq_epi8(im, wb);
		m1 = (uint32_t)_mm_movemask_epi8(le);
		m2 = (uint32_t)_mm_movemask_epi8(ge);
		res = (m2 >= m1);

#else

		for (size_t i = 0U; i < 16U; ++i)
		{
			if (a[i] > b[i])
			{
				res = true;
				break;
			}
			else if (a[i] < b[i])
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

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)

		__m256i ge;
		__m256i im;
		__m256i le;
		__m256i wa;
		__m256i wb;
		uint32_t m1;
		uint32_t m2;

		wa = _mm256_set_epi8(a[0U], a[1U], a[2U], a[3U], a[4U], a[5U], a[6U], a[7U], a[8U], a[9U], a[10U], a[11U], a[12U], a[13U], a[14U], a[15U],
			a[16U], a[17U], a[18U], a[19U], a[20U], a[21U], a[22U], a[23U], a[24U], a[25U], a[26U], a[27U], a[28U], a[29U], a[30U], a[31U]);
		wb = _mm256_set_epi8(b[0U], b[1U], b[2U], b[3U], b[4U], b[5U], b[6U], b[7U], b[8U], b[9U], b[10U], b[11U], b[12U], b[13U], b[14U], b[15U],
			b[16U], b[17U], b[18U], b[19U], b[20U], b[21U], b[22U], b[23U], b[24U], b[25U], b[26U], b[27U], b[28U], b[29U], b[30U], b[31U]);
		im = _mm256_min_epu8(wa, wb);
		le = _mm256_cmpeq_epi8(im, wa);
		ge = _mm256_cmpeq_epi8(im, wb);
		m1 = (uint32_t)_mm256_movemask_epi8(le);
		m2 = (uint32_t)_mm256_movemask_epi8(ge);
		res = (m2 >= m1);

#else
		res = qsc_memutils_greater_than_be128(a, b);
		res |= qsc_memutils_greater_than_be128(a + 16U, b + 16U);
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
		res = qsc_memutils_greater_than_le256(a, b);
		res |= qsc_memutils_greater_than_le256(a + 32U, b + 32U);
#else
		res = qsc_memutils_greater_than_le128(a, b);
		res |= qsc_memutils_greater_than_le128(a + 16U, b + 16U);
		res |= qsc_memutils_greater_than_le128(a + 32U, b + 32U);
		res |= qsc_memutils_greater_than_le128(a + 48U, b + 48U);
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
	_mm_storeu_si128((__m128i*)output, _mm_set1_epi8(value));
}
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
static void memutils_setval128(void* output, uint8_t value)
{
    uint8x16_t v = vdupq_n_u8(value);
    vst1q_u8((uint8_t*)output, v);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_setval256(void* output, uint8_t value)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_set1_epi8(value));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_setval512(void* output, uint8_t value)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_set1_epi8(value));
}
#endif

void qsc_memutils_set_value(void* output, size_t length, uint8_t value)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);

	size_t pctr;

	if (output != NULL && length != 0U)
	{
		pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64U;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32U;
#	else
		const size_t SMDBLK = 16U;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#if defined(QSC_SYSTEM_HAS_AVX512)
				memutils_setval512((uint8_t*)output + pctr, value);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				memutils_setval256((uint8_t*)output + pctr, value);
#elif defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_HAS_ARM_NEON)
				memutils_setval128((uint8_t*)output + pctr, value);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
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
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16U)
		{
			memutils_setval128((uint8_t*)output + pctr, value);
			pctr += 16U;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = value;
			}
		}
	}
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void memutils_xor128(uint8_t* output, const uint8_t* input)
{
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*)input), _mm_loadu_si128((const __m128i*)output)));
}
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
static void memutils_xor128(uint8_t* output, const uint8_t* input)
{
    uint8x16_t in_vec = vld1q_u8(input);
    uint8x16_t out_vec = vld1q_u8(output);
    uint8x16_t result  = veorq_u8(in_vec, out_vec);
    vst1q_u8(output, result);
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
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)input), _mm512_loadu_si512((__m512i*)output)));
}
#endif

void qsc_memutils_xor(uint8_t* output, const uint8_t* input, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(length != 0U);

	size_t pctr;

	if (output != NULL && input != NULL && length != 0U)
	{
		pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64U;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32U;
#	else
		const size_t SMDBLK = 16U;
#	endif

		if (output != NULL && input != NULL && length >= SMDBLK)
		{
			const size_t ALNLEN = length - (length % SMDBLK);

			while (pctr != ALNLEN)
			{
#if defined(QSC_SYSTEM_HAS_AVX512)
				memutils_xor512(output + pctr, input + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				memutils_xor256(output + pctr, input + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_HAS_ARM_NEON)
				memutils_xor128(output + pctr, input + pctr);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
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
#elif defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_HAS_ARM_NEON)
		if (length - pctr >= 16U)
		{
			memutils_xor128(output + pctr, input + pctr);
			pctr += 16U;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				output[i] ^= input[i];
			}
		}
	}
}

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_xorv512(uint8_t* output, const uint8_t value)
{
	__m512i v = _mm512_set1_epi8(value);
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)&v), _mm512_loadu_si512((__m512i*)output)));
}
#elif defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_xorv256(uint8_t* output, const uint8_t value)
{
	__m256i v = _mm256_set1_epi8(value);
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*) & v), _mm256_loadu_si256((const __m256i*)output)));
}
#elif defined(QSC_SYSTEM_HAS_AVX)
static void memutils_xorv128(uint8_t* output, const uint8_t value)
{
	__m128i v = _mm_set1_epi8(value);
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*) & v), _mm_loadu_si128((const __m128i*)output)));
}
#endif

void qsc_memutils_secure_erase(void* block, size_t length)
{
	QSC_ASSERT(block != NULL);
	QSC_ASSERT(length != 0U);

	if (block != NULL && length != 0U)
	{
#if defined(QSC_RTL_SECURE_MEMORY)
		RtlSecureZeroMemory(block, length);
#elif defined(QSC_OS_OPENBSD)
		explicit_bzero(block, length);
#else
		qsc_memutils_clear(block, length);
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

		memset(block,  0x00U, length);

#	if defined(QSC_SYSTEM_POSIX_MLOCK)
		munlock(block, length);
#	endif

		munmap(block, length);

#elif defined(QSC_SYSTEM_VIRTUAL_LOCK)

		qsc_memutils_clear(block, length);

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

#	if !defined(MAP_NOCORE)
#		define MAP_NOCORE 0
#	endif

#	if !defined(MAP_ANONYMOUS)
#		define MAP_ANONYMOUS 0x0002
#	endif

		ptr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE, -1, 0);

		if (ptr == MAP_FAILED)
		{
			ptr = NULL;
		}

		if (ptr != NULL)
		{
#	if defined(MADV_DONTDUMP)
			madvise(ptr, length, MADV_DONTDUMP);
#	endif

#	if defined(QSC_SYSTEM_POSIX_MLOCK)
			if (mlock(ptr, length) != 0)
			{
				qsc_memutils_clear(ptr, length);
				munmap(ptr, length);

				/* failed to lock */
				ptr = NULL;
			}
#	endif
		}

#elif defined(QSC_SYSTEM_VIRTUAL_LOCK)

		ptr = VirtualAlloc(NULL, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		/* test virtual lock */
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

void qsc_memutils_xorv(uint8_t* output, const uint8_t value, size_t length)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(length != 0U);

	size_t pctr;

	if (output != NULL && length != 0U)
	{
		pctr = 0U;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64U;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32U;
#	else
		const size_t SMDBLK = 16U;
#	endif

		if (output != NULL && length >= SMDBLK)
		{
			const size_t ALNLEN = length - (length % SMDBLK);

			while (pctr != ALNLEN)
			{
#if defined(QSC_SYSTEM_HAS_AVX512)
				memutils_xorv512(output + pctr, value);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				memutils_xorv256(output + pctr, value);
#elif defined(QSC_SYSTEM_HAS_AVX)
				memutils_xorv128(output + pctr, value);
#endif
				pctr += SMDBLK;
			}
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				output[i] ^= value;
			}
		}
	}
}

bool qsc_memutils_zeroed(const void* input, size_t length)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(length != 0U);

	size_t i;
	size_t j;
	bool res;

	res = false;

	if (input != NULL && length != 0U)
	{
		const uint8_t* pinp = (uint8_t*)input;
		i = 0U;
		j = 0U;

		while (i < length)
		{
			j |= pinp[i];
			++i;
		}

		res = (j == 0U);
	}

	return res;
}

