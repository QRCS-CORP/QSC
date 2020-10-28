#include "secmem.h"

#if defined(QSC_OS_OPENBSD)
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

uint8_t* qsc_secmem_alloc(size_t length)
{
	const size_t PGESZE = qsc_secmem_page_size();
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
#		define MAP_ANONYMOUS MAP_ANON
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

#	if defined(QSC_SYSTEM_HAS_POSIXMLOCK)
		if (mlock(ptr, length) != 0)
		{
			memset(ptr, 0, length);
			munmap(ptr, length);

			// failed to lock
			ptr = NULL;
		}
#	endif
	}

#elif defined(QSC_SYSTEM_HAS_VIRTUALLOCK)

	(LPVOID)ptr = VirtualAlloc(NULL, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (ptr != NULL)
	{
		if (VirtualLock((LPVOID)ptr, length) == 0)
		{
			memset(ptr, 0, length);
			VirtualFree((LPVOID)ptr, 0, MEM_RELEASE);

			// failed to lock
			ptr = NULL;
		}
	}

#else

	ptr = malloc(length);

#endif

	return ptr;
}

void qsc_secmem_erase(uint8_t* block, size_t length)
{
#if defined(QSC_HAS_RTLSECUREMEMORY)

	RtlSecureZeroMemory(block, length);

#elif defined(QSC_OS_OPENBSD)

	explicit_bzero(block, length);

#elif defined(QSC_VOLATILE_MEMSET)

	static void* (*const memsetptr)(void*, int, size_t) = memset;
	(memsetptr)(block, 0, length);

#else

	char* ptr = (char*)block;
	size_t i;

	for (i = 0; i != length; ++i)
	{
		ptr[i] = 0;
	}

#endif
}

void qsc_secmem_free(uint8_t* block, size_t length)
{
	if (block != NULL || length != 0)
	{

#if defined(QSC_SYSTEM_OS_POSIX)

		qsc_secmem_erase(block, length);

#	if defined(QSC_SYSTEM_HAS_POSIXMLOCK)
		munlock(block, length);
#	endif

		munmap(block, length);

#elif defined(QSC_SYSTEM_HAS_VIRTUALLOCK)

		qsc_secmem_erase(block, length);

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

size_t qsc_secmem_page_size()
{
	size_t pagelen;

	pagelen = 0x00001000LL;

#if defined(QSC_SYSTEM_OS_POSIX)

	pagelen = (size_t)sysconf(_SC_PAGESIZE);

	if (pagelen < 1)
	{
		pagelen = (size_t)QSC_SYSTEM_SECMEMALLOC_DEFAULT;
	}

#elif defined(QSC_SYSTEM_OS_WINDOWS)

	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	pagelen = (size_t)sysinfo.dwPageSize;

#endif

	return pagelen;
}
