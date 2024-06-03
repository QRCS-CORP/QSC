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
#	include <cstdlib>
#	include <signal.h>
#	include <setjmp.h>
#	include <unistd.h>
#	include <errno.h>
#elif defined(QSC_SYSTEM_OS_WINDOWS)
#	include <windows.h>
#endif

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
		pagelen = CEX_SECMEMALLOC_DEFAULT;
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
		int res;

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
static void memutils_clear128(void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_setzero_si128());
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_clear256(void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_setzero_si256());
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_clear512(void* output)
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
				memutils_clear512(((uint8_t*)output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX2)
				memutils_clear256(((uint8_t*)output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX)
				memutils_clear128(((uint8_t*)output + pctr));
#	endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			memutils_clear256(((uint8_t*)output + pctr));
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			memutils_clear128(((uint8_t*)output + pctr));
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			memutils_clear128(((uint8_t*)output + pctr));
			pctr += 16;
		}
#endif

		if (pctr != length)
		{
			for (size_t i = pctr; i < length; ++i)
			{
				((uint8_t*)output)[i] = 0x00;
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
	__m512i wc;
	__mmask8 mr;

	wa = _mm512_loadu_si512((const __m512i*)a);
	wb = _mm512_loadu_si512((const __m512i*)b);
	mr = _mm512_cmpeq_epi64_mask(wa, wb); // NOTE: test this.

	return ((const char)mr == 0);
}
#endif

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
#if defined(QSC_SYSTEM_HAS_AVX)

	return memutils_equal128(a, b);

#else

	int32_t mctr;

	for (size_t i = 0; i < 16; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0);

#endif
}

bool qsc_memutils_are_equal_256(const uint8_t* a, const uint8_t* b)
{
#if defined(QSC_SYSTEM_HAS_AVX2)

	return memutils_equal256(a, b);

#elif defined(QSC_SYSTEM_HAS_AVX)

	return (memutils_equal128(a, b) && 
		memutils_equal128(a + sizeof(__m128i), b + sizeof(__m128i)));

#else

	int32_t mctr;

	for (size_t i = 0; i < 32; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0);

#endif
}

bool qsc_memutils_are_equal_512(const uint8_t* a, const uint8_t* b)
{
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

	for (size_t i = 0; i < 64; ++i)
	{
		mctr |= (a[i] ^ b[i]);
	}

	return (mctr == 0);

#endif
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void memutils_copy128(const void* input, void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_loadu_si128((const __m128i*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_copy256(const void* input, void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_loadu_si256((const __m256i*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_copy512(const void* input, void* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_loadu_si512((const __m512i*)input));
}
#endif

void qsc_memutils_copy(void* output, const void* input, size_t length)
{
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
				memutils_copy512((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				memutils_copy256((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX)
				memutils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			memutils_copy256((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			memutils_copy128((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			memutils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
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

bool qsc_memutils_greater_than_be128(const uint8_t* a, const uint8_t* b)
{
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

void qsc_memutils_setvalue(void* output, uint8_t value, size_t length)
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
static void memutils_xor128(const uint8_t* input, uint8_t* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*)input), _mm_loadu_si128((const __m128i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_xor256(const uint8_t* input, uint8_t* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)input), _mm256_loadu_si256((const __m256i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void memutils_xor512(const uint8_t* input, uint8_t* output)
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
			memutils_xor512((input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
			memutils_xor256((input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX)
			memutils_xor128((input + pctr), output + pctr);
#endif
			pctr += SMDBLK;
		}
	}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
	if (length - pctr >= 32)
	{
		memutils_xor256((input + pctr), output + pctr);
		pctr += 32;
	}
	else if (length - pctr >= 16)
	{
		memutils_xor128((input + pctr), output + pctr);
		pctr += 16;
	}
#elif defined(QSC_SYSTEM_HAS_AVX2)
	if (length - pctr >= 16)
	{
		memutils_xor128((input + pctr), output + pctr);
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
static void memutils_xorv512(const uint8_t value, uint8_t* output)
{
	__m512i v = _mm512_set1_epi8(value);
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)&v), _mm512_loadu_si512((__m512i*)output)));
}
#elif defined(QSC_SYSTEM_HAS_AVX2)
static void memutils_xorv256(const uint8_t value, uint8_t* output)
{
	__m256i v = _mm256_set1_epi8(value);
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*) & v), _mm256_loadu_si256((const __m256i*)output)));
}
#elif defined(QSC_SYSTEM_HAS_AVX)
static void memutils_xorv128(const uint8_t value, uint8_t* output)
{
	__m128i v = _mm_set1_epi8(value);
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*) & v), _mm_loadu_si128((const __m128i*)output)));
}
#endif

void qsc_memutils_secure_erase(void* block, size_t length)
{
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

		qsc_secmem_erase(block, length);

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
			memutils_xorv512(value, (output + pctr));
#elif defined(QSC_SYSTEM_HAS_AVX2)
			memutils_xorv256(value, (output + pctr));
#elif defined(QSC_SYSTEM_HAS_AVX)
			memutils_xorv128(value, (output + pctr));
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

