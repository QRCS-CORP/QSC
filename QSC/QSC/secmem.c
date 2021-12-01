#include "secmem.h"
#include "memutils.h"

#if defined(QSC_OS_OPENBSD)
#	include <string.h>
#endif
#if defined(QSC_SYSTEM_OS_POSIX)
#	include <sys/types.h>
#	include <sys/resource.h>
#	include <sys/mman.h>
#	include <stdlib.h>
#	include <signal.h>
#	include <setjmp.h>
#	include <unistd.h>
#	include <errno.h>
#elif defined(QSC_SYSTEM_OS_WINDOWS)
#	include <Windows.h>
#endif

uint8_t* qsc_secmem_alloc(size_t length)
{
	const size_t PGESZE = qsc_secmem_page_size();
	char* ptr;

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

#	if defined(QSC_SYSTEM_HAS_POSIXMLOCK)
		if (mlock(ptr, length) != 0)
		{
			qsc_memutils_clear(ptr, length);
			munmap(ptr, length);

			// failed to lock
			ptr = NULL;
		}
#	endif
	}

#elif defined(QSC_SYSTEM_HAS_VIRTUALLOCK)

	ptr = (char*)VirtualAlloc(NULL, length, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

	if (ptr != NULL && VirtualLock((LPVOID)ptr, length) == 0)
	{
		qsc_memutils_clear(ptr, length);
		VirtualFree((LPVOID)ptr, 0, MEM_RELEASE);
		ptr = NULL;
	}

#else

	ptr = malloc(length);

#endif

	return (uint8_t*)ptr;
}

void qsc_secmem_erase(uint8_t* block, size_t length)
{
#if defined(QSC_HAS_RTLSECUREMEMORY)
	RtlSecureZeroMemory(block, length);
#elif defined(QSC_OS_OPENBSD)
	explicit_bzero(block, length);
#else
	qsc_memutils_clear(block, length);
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
