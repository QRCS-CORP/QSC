#include "sysutils.h"
#include "intrinsics.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	pragma intrinsic(__cpuid)
#	define _WINSOCKAPI_
#	include <Windows.h>
#	pragma comment(lib, "IPHLPAPI.lib")
#	include <iphlpapi.h>
#	include <intrin.h>  
#	include <Sddl.h>
#	include <tlhelp32.h>
#elif defined(QSC_SYSTEM_OS_UNIX)
#	include <time.h>
#	include <unistd.h>
#elif defined(QSC_SYSTEM_OS_APPLE)
#	include <mach/mach.h>
#	include <mach/mach_time.h>
#	include <time.h>
#endif
#if defined(QSC_SYSTEM_OS_POSIX)
#	include <cpuid.h>
#	include <dirent.h>
#	include <fstream>
#	include <ios>
#	include <iostream>
#	include <limits.h>
#	include <pwd.h>
#	include <stdio.h>
#	include <stdlib.h>
#	include <sys/resource.h>
#	include <sys/statvfs.h>
#	include <sys/sysctl.h>
#	include <sys/sysinfo.h>
#	include <sys/time.h>
#	include <sys/types.h>
#	include <unistd.h>
#endif

size_t qsc_sysutils_computer_name(char* name)
{
	size_t res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	TCHAR buf[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD bufflen = sizeof(buf) / sizeof(TCHAR);
	GetComputerName(buf, &bufflen);
	res = strlen(buf);
	memcpy(name, (char*)buf, res);


#elif defined(QSC_SYSTEM_OS_POSIX)

	char buf[HOST_NAME_MAX];
	gethostname(buf, HOST_NAME_MAX);
	res = strlen(buf);
	memcpy(name, buf, res);

#endif

	return res;
}

void qsc_sysutils_drive_space(const char* drive, qsc_sysutils_drive_space_state* state)
{
	state->free = 0;
	state->total = 0;
	state->avail = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	ULARGE_INTEGER freebt;
	ULARGE_INTEGER totalbt;
	ULARGE_INTEGER availbt;

	UINT drvtype = GetDriveType(drive);

	if (drvtype == 3 || drvtype == 6)
	{
		if (GetDiskFreeSpaceEx(drive, &freebt, &totalbt, &availbt))
		{
			state->free = freebt.QuadPart;
			state->total = totalbt.QuadPart;
			state->avail = availbt.QuadPart;
		}
	}

#elif defined(QSC_SYSTEM_OS_POSIX)

	struct statvfs fsinfo;
	statvfs("/", &fsinfo);

	state->free = fsinfo.f_frsize * fsinfo.f_blocks;
	state->total = fsinfo.f_bsize * fsinfo.f_bfree;
	state->avail = total - free;

#endif
}

bool qsc_sysutils_rdrand_available()
{
#if defined(QSC_SYSTEM_AVX_INTRINSICS)
	const uint32_t RDRAND_FLAG = (1 << 30);

#	if defined(QSC_SYSTEM_OS_WINDOWS)

	int32_t info[4] = { 0 };

	__cpuid(info, 1);

	return (((uint32_t)info[2] & RDRAND_FLAG) == RDRAND_FLAG);

#	else

	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;

	__cpuid(1, eax, ebx, ecx, edx);

	return ((ecx & RDRAND_FLAG) == RDRAND_FLAG);

#	endif
#else
	return false;
#endif
}

bool qsc_sysutils_rdseed_available()
{
	const uint32_t RDSEED_FLAG = 18;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	int32_t info[4] = { 0 };

	__cpuid(info, 1);

	return (((uint32_t)info[2] & RDSEED_FLAG) == RDSEED_FLAG);

#else

	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;

	__cpuid(1, eax, ebx, ecx, edx);

	return ((ebx & RDSEED_FLAG) == RDSEED_FLAG);

#endif
}

bool qsc_sysutils_rdtsc_available()
{
	const uint32_t RDTSC_FLAG = 27;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	int32_t info[4] = { 0 };

	__cpuid(info, 1);

	return (((uint32_t)info[3] & RDTSC_FLAG) == RDTSC_FLAG);

#else

	uint32_t eax;
	uint32_t ebx;
	uint32_t ecx;
	uint32_t edx;

	__cpuid(1, eax, ebx, ecx, edx);

	return ((edx & RDTSC_FLAG) == RDTSC_FLAG);

#endif

}

void qsc_sysutils_memory_statistics(qsc_sysutils_memory_statistics_state* state)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

	MEMORYSTATUSEX memInfo;

	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	GlobalMemoryStatusEx(&memInfo);

	state->phystotal = (uint64_t)memInfo.ullTotalPhys;
	state->physavail = (uint64_t)memInfo.ullAvailPhys;
	state->virttotal = (uint64_t)memInfo.ullTotalVirtual;
	state->virtavail = (uint64_t)memInfo.ullAvailVirtual;

#elif defined(QSC_SYSTEM_OS_POSIX)

	struct sysinfo memInfo;

	sysinfo(&memInfo);
	state->phystotal = (uint64_t)memInfo.totalram * memInfo.mem_unit;
	state->physavail = (uint64_t)((memInfo.totalram - memInfo.freeram) * memInfo.mem_unit);
	state->virttotal = (uint64_t)((memInfo.totalram + memInfo.totalswap) * memInfo.mem_unit);
	state->virtavail = (uint64_t)(((memInfo.totalram - memInfo.freeram) + (memInfo.totalswap - memInfo.freeswap)) * memInfo.mem_unit);

#endif
}

uint32_t qsc_sysutils_process_id()
{
	uint32_t res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (uint32_t)GetCurrentProcessId();
#else
	res = (uint32_t)::getpid();
#endif

	return res;
}

size_t qsc_sysutils_user_name(char* name)
{
	size_t res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	TCHAR buf[UNLEN + 1];
	DWORD bufflen = sizeof(buf) / sizeof(TCHAR);
	GetUserName(buf, &bufflen);
	res = strlen(buf);
	memcpy(name, (char*)buf, res);


#elif defined(QSC_SYSTEM_OS_POSIX)

	char buf[LOGIN_NAME_MAX];
	getlogin_r(buf, LOGIN_NAME_MAX);
	size_t bufflen = sizeof(buf) / sizeof(char);
	res = strlen(buf);
	memcpy(name, buf, res);

#endif

	return res;
}

uint64_t qsc_sysutils_system_uptime()
{
	uint64_t res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	res = GetTickCount64();

#elif defined(QSC_SYSTEM_OS_POSIX)

	struct timespec ts;

	if (clock_gettime(CLOCK_UPTIME_PRECISE, &ts) == 0)
	{
		res = (uint64_t)((ts.tv_sec * 1000ULL) + (ts.tv_nsec / 1000000ULL));
	}

#endif

	return res;
}

uint64_t qsc_sysutils_system_timestamp()
{
	uint64_t rtme;

	rtme = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	if (qsc_sysutils_rdtsc_available())
	{
		// use tsc if available
		rtme = (uint64_t)__rdtsc();
	}
	else
	{
		int64_t ctr1 = 0;
		int64_t freq = 0;

		if (QueryPerformanceCounter((LARGE_INTEGER*)&ctr1) != 0)
		{
			QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
			// return microseconds to milliseconds
			if (freq > 0)
			{
				rtme = (uint64_t)(ctr1 * 1000ULL / freq);
			}
		}
		else
		{
			FILETIME ft;
			LARGE_INTEGER li;
			// Get the amount of 100 nano seconds intervals elapsed since January 1, 1601 (UTC) and copy it to a LARGE_INTEGER structure
			GetSystemTimeAsFileTime(&ft);
			li.LowPart = ft.dwLowDateTime;
			li.HighPart = ft.dwHighDateTime;
			rtme = (uint64_t)li.QuadPart;
			// Convert from file time to UNIX epoch time.
			rtme -= 116444736000000000LL;
			// From 100 nano seconds (10^-7) to 1 millisecond (10^-3) intervals
			rtme /= 10000;
		}
	}

#elif (defined(QSC_SYSTEM_OS_HPUX) || defined(QSC_SYSTEM_OS_SUNUX)) && (defined(__SVR4) || defined(__svr4__))

	// HP-UX, Solaris
	rtme = (uint64_t)gethrtime();

#elif defined(QSC_SYSTEM_OS_APPLE)
	// OSX
	static double timeConvert = 0.0;
	mach_timebase_info_data_t timeBase;
	(void)mach_timebase_info(&timeBase);
	timeConvert = timeBase.numer / timeBase.denom;
	rtme = (uint64_t)(mach_absolute_time() * timeConvert);

#elif defined(QSC_SYSTEM_OS_POSIX)

	// POSIX
#	if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0)
	struct timespec ts;

#		if defined(CLOCK_MONOTONIC_PRECISE)
	// BSD
	const clockid_t id = CLOCK_MONOTONIC_PRECISE;
#		elif defined(CLOCK_MONOTONIC_RAW)
	// Linux
	const clockid_t id = CLOCK_MONOTONIC_RAW;
#		elif defined(CLOCK_HIGHRES)
	// Solaris
	const clockid_t id = CLOCK_HIGHRES;
#		elif defined(CLOCK_MONOTONIC)
	// AIX, BSD, Linux, POSIX, Solaris
	const clockid_t id = CLOCK_MONOTONIC;
#		elif defined(CLOCK_REALTIME)
	// AIX, BSD, HP-UX, Linux, POSIX
	const clockid_t id = CLOCK_REALTIME;
#		else
	// Unknown
	const clockid_t id = (clockid_t)-1;
#		endif
#	endif

	if (id != (clockid_t)-1 && clock_gettime(id, &ts) != -1)
	{
		rtme = static_cast<ulong>(ts.tv_sec + ts.tv_nsec);
	}

#else
#	error Time not available on this system!
#endif

	return rtme;
}