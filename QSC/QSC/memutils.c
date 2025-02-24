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
	assert(address != NULL);

#if defined(__GNUC__) || defined(__clang__)
    __builtin___clear_cache((char*)address, (char*)address + QSC_MEMUTILS_CACHE_LINE_SIZE);
#elif defined(_MSC_VER)
    _mm_clflush(address);
#endif
}

void qsc_memutils_prefetch_l1(uint8_t* address, size_t length)
{
	assert(address != NULL);
	assert(length != 0);

	if (address != NULL)
	{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
		_mm_prefetch(((char*)address + length), _MM_HINT_T0);
#else
		volatile uint8_t tmp;
		size_t i;

		tmp = 0;

		for (i = 0; i < length; ++i)
		{
			tmp |= address[i];
		}
#endif
	}
}

void qsc_memutils_prefetch_l2(uint8_t* address, size_t length)
{
	assert(address != NULL);
	assert(length != 0);

	if (address != NULL)
	{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
		_mm_prefetch(((char*)address + length), _MM_HINT_T1);
#else
		volatile uint8_t tmp;
		size_t i;

		tmp = 0;

		for (i = 0; i < length; ++i)
		{
			tmp |= address[i];
		}
#endif
	}
}

void qsc_memutils_prefetch_l3(uint8_t* address, size_t length)
{
	assert(address != NULL);
	assert(length != 0);

	if (address != NULL)
	{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
		_mm_prefetch(((char*)address + length), _MM_HINT_T2);
#else
		volatile uint8_t tmp;
		size_t i;

		tmp = 0;

		for (i = 0; i < length; ++i)
		{
			tmp |= address[i];
		}
#endif
	}
}

void* qsc_memutils_malloc(size_t length)
{
	assert(length != 0);

	void* ret;

	ret = NULL;

	if (length != 0)
	{
		ret = malloc(length);
	}

	return ret;
}

size_t qsc_memutils_page_size()
{
	int64_t pagelen;

	pagelen = 0x00001000LL;

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

#endif

	return (size_t)pagelen;
}

void* qsc_memutils_realloc(void* block, size_t length)
{
	assert(block != NULL);
	assert(length != 0);

	void* ret;

	ret = NULL;

	if (block != NULL && length != 0)
	{
		ret = realloc(block, length);
	}

	return ret;
}

void qsc_memutils_alloc_free(void* block)
{
	assert(block != NULL);

	if (block != NULL)
	{
		free(block);
	}
}

void* qsc_memutils_aligned_alloc(int32_t align, size_t length)
{
	assert(align != 0);
	assert(length != 0);

	void* ret;

	ret = NULL;

	if (length != 0)
	{
#if defined(QSC_SYSTEM_AVX_INTRINSICS) && defined(QSC_SYSTEM_OS_WINDOWS)
		ret = _aligned_malloc(length, align);
#elif defined(QSC_SYSTEM_OS_POSIX)
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
	assert(block != NULL);
	assert(length != 0);

	void* ret;

	ret = NULL;

	if (block != NULL && length != 0)
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
	assert(block != NULL);

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
	assert(output != NULL);
	assert(length != 0);

	size_t pctr;

	if (output != NULL && length != 0)
	{
		pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
#	endif

		if (length >= SMDBLK)
		{
			const size_t ALNLEN = (length / SMDBLK) * SMDBLK;

			while (pctr != ALNLEN)
			{
#	if defined(QSC_SYSTEM_HAS_AVX512)
				memutils_clear512(((volatile uint8_t*)output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX2)
				memutils_clear256(((volatile uint8_t*)output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX)
				memutils_clear128(((volatile uint8_t*)output + pctr));
#	endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			memutils_clear256(((volatile uint8_t*)output + pctr));
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			memutils_clear128(((volatile uint8_t*)output + pctr));
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			memutils_clear128(((volatile uint8_t*)output + pctr));
			pctr += 16;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((volatile uint8_t*)output)[i] = 0x00;
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
	uint64_t ra[sizeof(__m128i) / sizeof(uint64_t)] = { 0 };

	wa = _mm_loadu_si128((const __m128i*)a);
	wb = _mm_loadu_si128((const __m128i*)b);
	wc = _mm_cmpeq_epi64(wa, wb);
	_mm_storeu_si128((__m128i*)ra, wc);

	return ((~ra[0] + ~ra[1]) == 0);
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
    uint8_t min_val = vminvq_u8(cmp);

    return (min_val == 0xFF);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static bool memutils_equal256(const uint8_t* a, const uint8_t* b)
{
	__m256i wa;
	__m256i wb;
	__m256i wc;
	uint64_t ra[sizeof(__m256i) / sizeof(uint64_t)] = { 0 };

	wa = _mm256_loadu_si256((const __m256i*)a);
	wb = _mm256_loadu_si256((const __m256i*)b);
	wc = _mm256_cmpeq_epi64(wa, wb);
	_mm256_storeu_si256((__m256i*)ra, wc);

	return ((~ra[0] + ~ra[1] + ~ra[2] + ~ra[3]) == 0);
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static bool memutils_equal512(const uint8_t* a, const uint8_t* b)
{
	__m512i wa;
	__m512i wb;
	__mmask8 mr;

	wa = _mm512_loadu_si512((const __m512i*)a);
	wb = _mm512_loadu_si512((const __m512i*)b);
	mr = _mm512_cmpeq_epi64_mask(wa, wb); // NOTE: test this.

	return ((const char)mr == 0);
}
#endif

bool qsc_memutils_array_uniform(const uint8_t* input, size_t length)
{
	assert(input != NULL);
	
    uint8_t ref;
    uint8_t res;

    res = 0;

	if (length > 0)
	{
		ref = input[0];

		for (size_t i = 1; i < length; ++i)
		{
			res |= (input[i] ^ ref);
		}
	}

    return (res == 0);
}

bool qsc_memutils_are_equal(const uint8_t* a, const uint8_t* b, size_t length)
{
	assert(a != NULL);
	assert(b != NULL);
	assert(length > 0);

	size_t pctr;
	int32_t mctr;

	if (a != NULL && b != NULL && length != 0)
	{
		mctr = 0;
		pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
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
#elif defined(QSC_SYSTEM_HAS_AVX)
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
	}

	return (mctr == 0);
}

bool qsc_memutils_are_equal_128(const uint8_t* a, const uint8_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

#if defined(QSC_SYSTEM_HAS_AVX)

	return memutils_equal128(a, b);

#else

	int32_t mctr;

	mctr = 0;

	for (size_t i = 0; i < 16; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0);

#endif
}

bool qsc_memutils_are_equal_256(const uint8_t* a, const uint8_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

#if defined(QSC_SYSTEM_HAS_AVX2)

	return memutils_equal256(a, b);

#elif defined(QSC_SYSTEM_HAS_AVX)

	return (memutils_equal128(a, b) && 
		memutils_equal128(a + sizeof(__m128i), b + sizeof(__m128i)));

#else

	int32_t mctr;

	mctr = 0;

	for (size_t i = 0; i < 32; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0);

#endif
}

bool qsc_memutils_are_equal_512(const uint8_t* a, const uint8_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

#if defined(QSC_SYSTEM_HAS_AVX512)

	return memutils_equal512(a, b);

#elif defined(QSC_SYSTEM_HAS_AVX2)

	return memutils_equal256(a, b) && 
		memutils_equal256(a + sizeof(__m256i), b + sizeof(__m256i));

#elif defined(QSC_SYSTEM_HAS_AVX)

	return (memutils_equal128(a, b) && 
		memutils_equal128(a + sizeof(__m128i), b + sizeof(__m128i)) &&
		memutils_equal128(a + (2 * sizeof(__m128i)), b + (2 * sizeof(__m128i))) &&
		memutils_equal128(a + (3 * sizeof(__m128i)), b + (3 * sizeof(__m128i))));

#else

	int32_t mctr;

	mctr = 0;

	for (size_t i = 0; i < 64; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0);

#endif
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
	assert(output != NULL);
	assert(input != NULL);

	size_t pctr;

	if (length != 0)
	{
		pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
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
#elif defined(QSC_SYSTEM_HAS_AVX)
				memutils_copy128((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			memutils_copy256((uint8_t*)output + pctr, (uint8_t*)input + pctr);
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			memutils_copy128((uint8_t*)output + pctr, (uint8_t*)input + pctr);
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			memutils_copy128((uint8_t*)output + pctr, (const uint8_t*)input + pctr);
			pctr += 16;
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

static inline void memutils_clmulepi64(uint64_t r[2], uint64_t x, uint64_t y) 
{
    uint64_t bit;
    uint64_t hc;
    uint64_t mask;
    uint64_t mi;
    uint64_t nz;
    uint64_t ss;

    r[0] = 0;
    r[1] = 0;

    for (size_t i = 0; i < 64; ++i)
    {
        bit  = (x >> i) & 1ULL;
        mask = 0 - bit;
        /* add the contribution of y shifted left by i */
        r[0] ^= (y << i) & mask;

        /* compute the overflow (high) contribution in constant time. */
        nz = (uint64_t)(i != 0);
        mi = 0 - nz;
        ss = (64 - i) & mi;
        hc = (y >> ss) & mi;

        r[1] ^= hc & mask;
    }
}

void qsc_memutils_clmulepi64_si128(uint64_t r[2], const uint64_t a[2], const uint64_t b[2], int32_t imm8) 
{
    size_t inda = (imm8 & 0x01)  ? 1 : 0;
    size_t indb = (imm8 & 0x10) ? 1 : 0;

    memutils_clmulepi64(r, a[inda], b[indb]);
}

#if defined(QSC_SYSTEM_HAS_AVX)

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

void qsc_memutils_clmulepi64_si256_avx(__m128i r[4], const __m128i a[2], const __m128i b[2])
{
	/* compute the three partial products */
    __m128i p0low = _mm_setzero_si128();
    __m128i p0high = _mm_setzero_si128();

    // p0 = a0 * b0
    memutils_clmul128(a[0], b[0], &p0low, &p0high);

    __m128i p1low = _mm_setzero_si128();
    __m128i p1high = _mm_setzero_si128();
    // p1 = a1 * b1
    memutils_clmul128(a[1], b[1], &p1low, &p1high);

    __m128i a0xa1 = _mm_xor_si128(a[0], a[1]);
    __m128i b0xb1 = _mm_xor_si128(b[0], b[1]);
    __m128i p2low = _mm_setzero_si128();
    __m128i p2high = _mm_setzero_si128();

    /* p2 = (a0 ^ a1) * (b0 ^ b1) */
    memutils_clmul128(a0xa1, b0xb1, &p2low, &p2high);

    /* compute the 'middle' term : m = p0 ^ p1 ^ p2 */
    __m128i mlow  = _mm_xor_si128(p0low,  _mm_xor_si128(p1low,  p2low));
    __m128i mhigh = _mm_xor_si128(p0high, _mm_xor_si128(p1high, p2high));

    /* assemble the final 512-bit product from 4× 128-bit pieces */
    /* r0 = lower 128 bits of p0 */
    r[0] = p0low;
    /* r1 = (upper 128 bits of p0) ^ (lower 128 bits of m) */
    r[1] = _mm_xor_si128(p0high, mlow);
    /* r2 = (upper 128 bits of m) ^ (lower 128 bits of p1) */
    r[2] = _mm_xor_si128(mhigh, p1low);
    /* r3 = upper 128 bits of p1 */
    r[3] = p1high;
}

void qsc_memutils_clmulepi64_si256(uint64_t r[8], const uint64_t a[4], const uint64_t b[4])
{
	__m128i ma[2] = { 0 };
	__m128i mb[2] = { 0 };
	__m128i mr[4] = { 0 };

    /* load 256-bit operands as two 128-bit pieces each */
    ma[0] = _mm_loadu_si128((const __m128i*)(a));      /* lower 128 bits of A */
    ma[1] = _mm_loadu_si128((const __m128i*)(a + 2));  /* upper 128 bits of A */
    mb[0] = _mm_loadu_si128((const __m128i*)(b));      /* lower 128 bits of B */
    mb[1] = _mm_loadu_si128((const __m128i*)(b + 2));  /* upper 128 bits of B */

	qsc_memutils_clmulepi64_si256_avx(mr, ma, mb);

    /* store the result */
    _mm_storeu_si128((__m128i*)(r + 0), mr[0]);
    _mm_storeu_si128((__m128i*)(r + 2), mr[1]);
    _mm_storeu_si128((__m128i*)(r + 4), mr[2]);
    _mm_storeu_si128((__m128i*)(r + 6), mr[3]);
}

#else

static inline void memutils_clmul128(uint64_t r[4], const uint64_t a[2], const uint64_t b[2])
{
    uint64_t p00[2];
    uint64_t p11[2];
    uint64_t p10[2];
    uint64_t p01[2];
    uint64_t t2[2];
    uint64_t t2l[2];
    uint64_t t2r[2];
    uint64_t low[2];
    uint64_t high[2];

    /* compute partial products. */
    memutils_clmulepi64(p00, a[0], b[0]);
    memutils_clmulepi64(p11, a[1], b[1]);
    memutils_clmulepi64(p10, a[1], b[0]);
    memutils_clmulepi64(p01, a[0], b[1]);

    /* t2 = p10 xor p01 */
    t2[0] = p10[0] ^ p01[0];
    t2[1] = p10[1] ^ p01[1];

    /* xor in (p00 ^ p11) */
    t2[0] ^= p00[0] ^ p11[0];
    t2[1] ^= p00[1] ^ p11[1];

    /* shift t2 left by 64 bits: lower word becomes 0, upper word becomes t2[0] */
    t2l[0] = 0;
    t2l[1] = t2[0];

    /* shift t2 right by 64 bits: lower word becomes t2[1], upper word becomes 0 */
    t2r[0] = t2[1];
    t2r[1] = 0;

    /* combine the lower 128 bits is p00; the upper 128 bits is p11 */
    /* the cross term 'mid' is split between the two */
    low[0]  = p00[0] ^ t2l[0];
    low[1]  = p00[1] ^ t2l[1];
    high[0] = p11[0] ^ t2r[0];
    high[1] = p11[1] ^ t2r[1];

    r[0] = low[0];
    r[1] = low[1];
    r[2] = high[0];
    r[3] = high[1];
}

void qsc_memutils_clmulepi64_si256(uint64_t r[8], const uint64_t a[4], const uint64_t b[4])
{
    /* split the 256-bit operands into 128-bit halves */
    uint64_t a0[2] = { a[0], a[1] };  /* lower 128 bits of a */
    uint64_t a1[2] = { a[2], a[3] };  /* upper 128 bits of a */
    uint64_t b0[2] = { b[0], b[1] };  /* lower 128 bits of b */
    uint64_t b1[2] = { b[2], b[3] };  /* upper 128 bits of b */
    uint64_t p0[4];  /* p0 = a0 * b0, 256 bits */
    uint64_t p1[4];  /* p1 = a1 * b1, 256 bits */
    uint64_t p2[4];  /* p2 = (a0 ^ a1) * (b0 ^ b1), 256 bits */
    uint64_t mid[4];   /* middle term */

    /* Compute the three 256-bit partial products using clmul128. */
    memutils_clmul128(p0, a0, b0);
    memutils_clmul128(p1, a1, b1);

    uint64_t a0xa1[2] = { a0[0] ^ a1[0], a0[1] ^ a1[1] };
    uint64_t b0xb1[2] = { b0[0] ^ b1[0], b0[1] ^ b1[1] };
    memutils_clmul128(p2, a0xa1, b0xb1);

    /* compute mid = p0 ^ p1 ^ p2 */
    mid[0] = p0[0] ^ p1[0] ^ p2[0];
    mid[1] = p0[1] ^ p1[1] ^ p2[1];
    mid[2] = p0[2] ^ p1[2] ^ p2[2];
    mid[3] = p0[3] ^ p1[3] ^ p2[3];

    uint64_t r0[2];
    uint64_t r1[2];
    uint64_t r2[2];
    uint64_t r3[2];

    /* assemble the final 512‑bit product as four 128‑bit words */
    /* r0 = lower 128 bits of p0 = { p0[0], p0[1] } */
    r0[0] = p0[0];
    r0[1] = p0[1];
    /* r1 = (upper 128 bits of p0) ^ (lower 128 bits of mid) = { p0[2] ^ mid[0], p0[3] ^ mid[1] } */
    r1[0] = p0[2] ^ mid[0];
    r1[1] = p0[3] ^ mid[1];
    /* r2 = (upper 128 bits of mid) ^ (lower 128 bits of p1) = { mid[2] ^ p1[0], mid[3] ^ p1[1] } */
    r2[0] = mid[2]  ^ p1[0];
    r2[1] = mid[3] ^ p1[1];
    /* r3 = upper 128 bits of p1 = { p1[2], p1[3] } */
    r3[0] = p1[2];
    r3[1] = p1[3];

    /* pack the four 128-bit words into the 512-bit result r[8] */
    r[0] = r0[0];
    r[1] = r0[1];
    r[2] = r1[0];
    r[3] = r1[1];
    r[4] = r2[0];
    r[5] = r2[1];
    r[6] = r3[0];
    r[7] = r3[1];
}

#endif

bool qsc_memutils_greater_than_be128(const uint8_t* a, const uint8_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

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

	return res;
}

bool qsc_memutils_greater_than_be256(const uint8_t* a, const uint8_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

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

	return res;
}

bool qsc_memutils_greater_than_be512(const uint8_t* a, const uint8_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

#if defined(QSC_SYSTEM_HAS_AVX2)
	res = qsc_memutils_greater_than_be256(a, b);
	res |= qsc_memutils_greater_than_be256(a + 32, b + 32);
#else
	res = qsc_memutils_greater_than_be128(a, b);
	res |= qsc_memutils_greater_than_be128(a + 16, b + 16);
	res |= qsc_memutils_greater_than_be128(a + 32, b + 32);
	res |= qsc_memutils_greater_than_be128(a + 48, b + 48);
#endif

	return res;
}

bool qsc_memutils_greater_than_le128(const uint8_t* a, const uint8_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

#if defined(QSC_SYSTEM_HAS_AVX)

    __m128i ge;
	__m128i im;
    __m128i le;
	__m128i wa;
	__m128i wb;
	uint32_t m1;
	uint32_t m2;

	wa = _mm_set_epi8(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
	wb = _mm_set_epi8(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
	im = _mm_min_epu8(wa, wb);
	le = _mm_cmpeq_epi8(im, wa);
	ge = _mm_cmpeq_epi8(im, wb);
	m1 = (uint32_t)_mm_movemask_epi8(le);
    m2 = (uint32_t)_mm_movemask_epi8(ge);
    res = (m2 >= m1);

#else

	for (size_t i = 0; i < 16; ++i)
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

	return res;
}

bool qsc_memutils_greater_than_le256(const uint8_t* a, const uint8_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

#if defined(QSC_SYSTEM_HAS_AVX2)

    __m256i ge;
	__m256i im;
    __m256i le;
	__m256i wa;
	__m256i wb;
	uint32_t m1;
	uint32_t m2;

	wa = _mm256_set_epi8(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15],
		a[16], a[17], a[18], a[19], a[20], a[21], a[22], a[23], a[24], a[25], a[26], a[27], a[28], a[29], a[30], a[31]);
	wb = _mm256_set_epi8(b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
		b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23], b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]);
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

	return res;
}

bool qsc_memutils_greater_than_le512(const uint8_t* a, const uint8_t* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

#if defined(QSC_SYSTEM_HAS_AVX2)
	res = qsc_memutils_greater_than_le256(a, b);
	res |= qsc_memutils_greater_than_le256(a + 32, b + 32);
#else
	res = qsc_memutils_greater_than_le128(a, b);
	res |= qsc_memutils_greater_than_le128(a + 16, b + 16);
	res |= qsc_memutils_greater_than_le128(a + 32, b + 32);
	res |= qsc_memutils_greater_than_le128(a + 48, b + 48);
#endif

	return res;
}

void qsc_memutils_move(void* output, const void* input, size_t length)
{
	assert(output != NULL);
	assert(input != NULL);
	assert(length != 0);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	memmove_s(output, length, input, length);
#else
	memmove(output, input, length);
#endif
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
	assert(output != NULL);
	assert(length != 0);

	size_t pctr;

	if (output != NULL && length != 0)
	{
		pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
		const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
		const size_t SMDBLK = 32;
#	else
		const size_t SMDBLK = 16;
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
#elif defined(QSC_SYSTEM_HAS_AVX)
				memutils_setval128((uint8_t*)output + pctr, value);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			memutils_setval256((uint8_t*)output + pctr, value);
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			memutils_setval128((uint8_t*)output + pctr, value);
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			memutils_setval128((uint8_t*)output + pctr, value);
			pctr += 16;
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
	assert(output != NULL);
	assert(input != NULL);
	assert(length != 0);

	size_t pctr;

	pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
	const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
	const size_t SMDBLK = 32;
#	else
	const size_t SMDBLK = 16;
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
#elif defined(QSC_SYSTEM_HAS_AVX)
			memutils_xor128(output + pctr, input + pctr);
#endif
			pctr += SMDBLK;
		}
	}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
	if (length - pctr >= 32)
	{
		memutils_xor256(output + pctr, input + pctr);
		pctr += 32;
	}
	else if (length - pctr >= 16)
	{
		memutils_xor128(output + pctr, input + pctr);
		pctr += 16;
	}
#elif defined(QSC_SYSTEM_HAS_AVX2)
	if (length - pctr >= 16)
	{
		memutils_xor128(output + pctr, input + pctr);
		pctr += 16;
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
	assert(block != NULL);

#if defined(QSC_RTL_SECURE_MEMORY)
	RtlSecureZeroMemory(block, length);
#elif defined(QSC_OS_OPENBSD)
	explicit_bzero(block, length);
#else
	qsc_memutils_clear(block, length);
#endif
}

void qsc_memutils_secure_free(void* block, size_t length)
{
	assert(block != NULL);
	assert(length != 0);

	if (block != NULL || length != 0)
	{
#if defined(QSC_SYSTEM_OS_POSIX)

		memset(block,  0x00, length);

#	if defined(QSC_SYSTEM_POSIX_MLOCK)
		munlock(block, length);
#	endif

		munmap(block, length);

#elif defined(QSC_SYSTEM_VIRTUAL_LOCK)

		qsc_memutils_clear(block, length);

		if (block != NULL)
		{
			VirtualUnlock(block, length);
			VirtualFree(block, 0, MEM_RELEASE);
		}

#else
		free(block);
#endif
	}
}

void* qsc_memutils_secure_malloc(size_t length)
{
	assert(length != 0);

	const size_t PGESZE = qsc_memutils_page_size();
	void* ptr;

	ptr = NULL;

	if (length % PGESZE != 0)
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
	if (ptr != NULL && VirtualLock((LPVOID)ptr, length) == 0)
	{
		VirtualFree((LPVOID)ptr, 0, MEM_RELEASE);
		ptr = NULL;
	}

#else

	ptr = malloc(length);

#endif

	return ptr;
}

void qsc_memutils_xorv(uint8_t* output, const uint8_t value, size_t length)
{
	assert(output != NULL);
	assert(length != 0);

	size_t pctr;

	pctr = 0;

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_HAS_AVX512)
	const size_t SMDBLK = 64;
#	elif defined(QSC_SYSTEM_HAS_AVX2)
	const size_t SMDBLK = 32;
#	else
	const size_t SMDBLK = 16;
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

bool qsc_memutils_zeroed(const void* input, size_t length)
{
	assert(input != NULL);
	assert(length != 0);

	size_t i;
	size_t j;

	i = 0;
	j = 0;

	if (input != NULL && length != 0)
	{
		const uint8_t* pinp = (uint8_t*)input;

		while (i < length)
		{
			j |= pinp[i];
			++i;
		}
	}

	return (j == 0);
}

