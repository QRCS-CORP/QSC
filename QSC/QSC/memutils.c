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
// TODO: Add secmem alloc and free

void qsc_memutils_prefetch_l1(uint8_t* address, size_t length)
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

void qsc_memutils_prefetch_l2(uint8_t* address, size_t length)
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

void qsc_memutils_prefetch_l3(uint8_t* address, size_t length)
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

void* qsc_memutils_malloc(size_t length)
{
	void* ret;

	ret = NULL;

	if (length != 0)
	{
#if defined(QSC_SYSTEM_COMPILER_MSC)
		ret = _aligned_malloc(length, QSC_SIMD_ALIGNMENT);
#else
		ret = malloc(length);
#endif
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

size_t qsc_memutils_secure_malloc(void* block, size_t length)
{
	uint32_t nlen;
	const size_t pagesize = qsc_memutils_page_size();

	nlen = length;

	if (nlen % pagesize != 0)
	{
		nlen = (nlen + pagesize - (nlen % pagesize));
	}

#if defined(QSC_SYSTEM_OS_POSIX)

#	if !defined(MAP_NOCORE)
#		define MAP_NOCORE 0
#	endif

#	if !defined(MAP_ANONYMOUS)
#		define MAP_ANONYMOUS MAP_ANON
#	endif

	block = mmap(NULL, nlen, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED | MAP_NOCORE, -1, 0);

	if (block != MAP_FAILED)
	{
#	if defined(MADV_DONTDUMP)
		madvise(block, nlen, MADV_DONTDUMP);
#	endif

#	if defined(CEX_HAS_POSIXMLOCK)
		if (mlock(block, nlen) != 0)
		{
			qsc_memutils_clear(block, nlen);
			munmap(block, nlen);
		}
#	endif
	}
	else
	{
		block = NULL;
	}

#elif defined(QSC_SYSTEM_VIRTUAL_LOCK)

	block = VirtualAlloc(NULL, nlen, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (block != NULL)
	{
		if (VirtualLock((LPVOID)block, nlen) == 0)
		{
			qsc_memutils_clear(block, nlen);
			VirtualFree((LPVOID)block, 0, MEM_RELEASE);
		}
	}

#else

	block = (uint8_t*)qsc_memutils_malloc(nlen);

#endif

	if (block == NULL)
	{
		nlen = 0;
	}

	return (size_t)nlen;
}

void qsc_memutils_secure_free(void* block, size_t length)
{
	if (block != NULL || length != 0)
	{
#if defined(QSC_SYSTEM_OS_POSIX)

		qsc_memutils_clear(block, length);

#	if defined(CEX_HAS_POSIXMLOCK)
		munlock(block, length);
#	endif
		munmap(block, length);

#elif defined(QSC_SYSTEM_VIRTUAL_LOCK)

		if (block != NULL)
		{
			qsc_memutils_clear(block, length);

			VirtualUnlock((LPVOID)block, length);
			VirtualFree((LPVOID)block, 0, MEM_RELEASE);
		}

#else
		free((uint8_t*)block);
#endif
	}
}

void* qsc_memutils_realloc(void* block, size_t length)
{
	void* ret;

	ret = NULL;

	if (length != 0)
	{
#if defined(QSC_SYSTEM_COMPILER_MSC)
		ret = _aligned_realloc(block, length, QSC_SIMD_ALIGNMENT);
#else
		ret = realloc(block, length);
#endif
	}

	return ret;
}

void qsc_memutils_alloc_free(void* block)
{
	if (block != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_aligned_free(block);
#else
		free(block);
#endif
	}
}

void* qsc_memutils_aligned_alloc(int32_t align, size_t length)
{
	void* ret;

	ret = NULL;

	if (length != 0)
	{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_OS_WINDOWS)
		ret = _aligned_malloc(length, align);
#	elif defined(QSC_SYSTEM_OS_POSIX)
		int res;

		res = posix_memalign(&ret, align, length);

		if (res != 0)
		{
			ret = NULL;
		}
#	else
		ret = (void*)malloc(length);
#	endif
#else
		ret = (void*)malloc(length);
#endif
	}

	return ret;
}

void qsc_memutils_aligned_free(void* block)
{
	if (block != NULL)
	{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
#	if defined(QSC_SYSTEM_OS_WINDOWS)
		_aligned_free(block);
#	else
		free(block);
#	endif
#else
		free(block);
#endif
	}
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void qsc_memutils_clear128(void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_setzero_si128());
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void qsc_memutils_clear256(void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_setzero_si256());
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void qsc_memutils_clear512(void* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_setzero_si512());
}
#endif

void qsc_memutils_clear(void* output, size_t length)
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
#	if defined(QSC_SYSTEM_HAS_AVX512)
				qsc_memutils_clear512(((uint8_t*)output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX2)
				qsc_memutils_clear256(((uint8_t*)output + pctr));
#	elif defined(QSC_SYSTEM_HAS_AVX)
				qsc_memutils_clear128(((uint8_t*)output + pctr));
#	endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			qsc_memutils_clear256(((uint8_t*)output + pctr));
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			qsc_memutils_clear128(((uint8_t*)output + pctr));
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			qsc_memutils_clear128(((uint8_t*)output + pctr));
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
static void qsc_memutils_copy128(const void* input, void* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_loadu_si128((const __m128i*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void qsc_memutils_copy256(const void* input, void* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_loadu_si256((const __m256i*)input));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void qsc_memutils_copy512(const void* input, void* output)
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
				qsc_memutils_copy512((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				qsc_memutils_copy256((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX)
				qsc_memutils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			qsc_memutils_copy256((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			qsc_memutils_copy128((uint8_t*)input + pctr, (uint8_t*)output + pctr);
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			qsc_memutils_copy128((const uint8_t*)input + pctr, (uint8_t*)output + pctr);
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

void qsc_memutils_move(void* output, const void* input, size_t length)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	memmove_s(output, length, input, length);
#else
	memmove(output, input, length);
#endif
}

#if defined(QSC_SYSTEM_HAS_AVX)
static void qsc_memutils_setval128(void* output, uint8_t value)
{
	_mm_storeu_si128((__m128i*)output, _mm_set1_epi8(value));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void qsc_memutils_setval256(void* output, uint8_t value)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_set1_epi8(value));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void qsc_memutils_setval512(void* output, uint8_t value)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_set1_epi8(value));
}
#endif

void qsc_memutils_setvalue(void* output, uint8_t value, size_t length)
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
				qsc_memutils_setval512((uint8_t*)output + pctr, value);
#elif defined(QSC_SYSTEM_HAS_AVX2)
				qsc_memutils_setval256((uint8_t*)output + pctr, value);
#elif defined(QSC_SYSTEM_HAS_AVX)
				qsc_memutils_setval128((uint8_t*)output + pctr, value);
#endif
				pctr += SMDBLK;
			}
		}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		if (length - pctr >= 32)
		{
			qsc_memutils_setval256((uint8_t*)output + pctr, value);
			pctr += 32;
		}
		else if (length - pctr >= 16)
		{
			qsc_memutils_setval128((uint8_t*)output + pctr, value);
			pctr += 16;
		}
#elif defined(QSC_SYSTEM_HAS_AVX2)
		if (length - pctr >= 16)
		{
			qsc_memutils_setval128((uint8_t*)output + pctr, value);
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
static void qsc_memutils_xor128(const uint8_t* input, uint8_t* output)
{
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*)input), _mm_loadu_si128((const __m128i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX2)
static void qsc_memutils_xor256(const uint8_t* input, uint8_t* output)
{
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*)input), _mm256_loadu_si256((const __m256i*)output)));
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void qsc_memutils_xor512(const uint8_t* input, uint8_t* output)
{
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)input), _mm512_loadu_si512((__m512i*)output)));
}
#endif

void qsc_memutils_xor(uint8_t* output, const uint8_t* input, size_t length)
{
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

	if (length >= SMDBLK)
	{
		const size_t ALNLEN = length - (length % SMDBLK);

		while (pctr != ALNLEN)
		{
#if defined(QSC_SYSTEM_HAS_AVX512)
			qsc_memutils_xor512((input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX2)
			qsc_memutils_xor256((input + pctr), output + pctr);
#elif defined(QSC_SYSTEM_HAS_AVX)
			qsc_memutils_xor128((input + pctr), output + pctr);
#endif
			pctr += SMDBLK;
		}
	}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
	if (length - pctr >= 32)
	{
		qsc_memutils_xor256((input + pctr), output + pctr);
		pctr += 32;
	}
	else if (length - pctr >= 16)
	{
		qsc_memutils_xor128((input + pctr), output + pctr);
		pctr += 16;
	}
#elif defined(QSC_SYSTEM_HAS_AVX2)
	if (length - pctr >= 16)
	{
		qsc_memutils_xor128((input + pctr), output + pctr);
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
inline static void qsc_memutils_xorv512(const uint8_t value, uint8_t* output)
{
	__m512i v = _mm512_set1_epi8(value);
	_mm512_storeu_si512((__m512i*)output, _mm512_xor_si512(_mm512_loadu_si512((const __m512i*)&v), _mm512_loadu_si512((__m512i*)output)));
}
#elif defined(QSC_SYSTEM_HAS_AVX2)
inline static void qsc_memutils_xorv256(const uint8_t value, uint8_t* output)
{
	__m256i v = _mm256_set1_epi8(value);
	_mm256_storeu_si256((__m256i*)output, _mm256_xor_si256(_mm256_loadu_si256((const __m256i*) & v), _mm256_loadu_si256((const __m256i*)output)));
}
#elif defined(QSC_SYSTEM_HAS_AVX)
inline static void qsc_memutils_xorv128(const uint8_t value, uint8_t* output)
{
	__m128i v = _mm_set1_epi8(value);
	_mm_storeu_si128((__m128i*)output, _mm_xor_si128(_mm_loadu_si128((const __m128i*) & v), _mm_loadu_si128((const __m128i*)output)));
}
#endif

void qsc_memutils_xorv(uint8_t* output, const uint8_t value, size_t length)
{
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

	if (length >= SMDBLK)
	{
		const size_t ALNLEN = length - (length % SMDBLK);

		while (pctr != ALNLEN)
		{
#if defined(QSC_SYSTEM_HAS_AVX512)
			qsc_memutils_xorv512(value, (output + pctr));
#elif defined(QSC_SYSTEM_HAS_AVX2)
			qsc_memutils_xorv256(value, (output + pctr));
#elif defined(QSC_SYSTEM_HAS_AVX)
			qsc_memutils_xorv128(value, (output + pctr));
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
	const uint8_t* pinp = (uint8_t*)input;
	size_t i;

	i = 0;

	while (i < length && pinp[i] == 0)
	{
		++i;
	}

	return (i == length);
}

