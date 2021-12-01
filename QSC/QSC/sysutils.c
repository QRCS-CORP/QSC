#include "sysutils.h"
#include "cpuidex.h"
#include "intrinsics.h"
#include "memutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	define WIN32_LEAN_AND_MEAN
#	define _WINSOCKAPI_
#	include <Windows.h>
#	include <iphlpapi.h>
#	include <intrin.h>
#	include <sddl.h>
#	include <TlHelp32.h>
#   if defined(QSC_SYSTEM_COMPILER_MSC)
#	    pragma intrinsic(__cpuid)
#	    pragma comment(lib, "IPHLPAPI.lib")
#   endif
#elif defined(QSC_SYSTEM_OS_UNIX)
#	include <time.h>
#	include <unistd.h>
#elif defined(QSC_SYSTEM_OS_APPLE)
#	include <stdio.h>
#	include <sys/types.h>
#	include <mach/mach.h>
#	include <mach/mach_time.h>
#	include <sys/sysctl.h>
#	include <time.h>
#endif
#if defined(QSC_SYSTEM_OS_POSIX)
#	include <cpuid.h>
#	include <dirent.h>
#	include <time.h>
#if !defined(HOST_NAME_MAX)
#   define HOST_NAME_MAX 256
#endif
#if !defined(LOGIN_NAME_MAX)
#   define LOGIN_NAME_MAX 256
#endif
#	include <limits.h>
#	include <pwd.h>
#	include <stdio.h>
#	include <stdlib.h>
#	include <sys/resource.h>
#	include <sys/statvfs.h>
#	if defined(QSC_SYSTEM_OS_APPLE)
#		include <sys/sysctl.h>
#		include <mach/vm_statistics.h>
#		include <mach/mach_types.h>
#		include <mach/mach_init.h>
#		include <mach/mach_host.h>
#	else
#		include <sys/sysinfo.h>
#	endif
#	include <sys/time.h>
#	include <sys/types.h>
#	include <unistd.h>
#endif
#if defined(QSC_SYSTEM_COMPILER_GCC)
#	elif defined(QSC_SYSTEM_COMPILER_GCC)
#endif

size_t qsc_sysutils_computer_name(char* name)
{
	size_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	TCHAR buf[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD bufflen = sizeof(buf) / sizeof(TCHAR);
	GetComputerName(buf, &bufflen);
	res = strlen(buf);
	qsc_memutils_copy(name, (char*)buf, res);
#elif defined(QSC_SYSTEM_OS_POSIX)
	char buf[HOST_NAME_MAX];
	gethostname(buf, HOST_NAME_MAX);
	res = strlen(buf);
	qsc_memutils_copy(name, buf, res);
#else
	res = 0;
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

	if ((drvtype == 3 || drvtype == 6) &&
		GetDiskFreeSpaceEx(drive, &freebt, &totalbt, &availbt))
	{
		state->free = freebt.QuadPart;
		state->total = totalbt.QuadPart;
		state->avail = availbt.QuadPart;
	}

#elif defined(QSC_SYSTEM_OS_POSIX)

	struct statvfs fsinfo;
	statvfs("/", &fsinfo);

	state->free = fsinfo.f_frsize * fsinfo.f_blocks;
	state->total = fsinfo.f_bsize * fsinfo.f_bfree;
	state->avail = state->total - state->free;

#endif
}

void qsc_sysutils_memory_statistics(qsc_sysutils_memory_statistics_state* state)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

	MEMORYSTATUSEX memInfo;

	memInfo.dwLength = sizeof(MEMORYSTATUSEX);
	GlobalMemoryStatusEx(&memInfo);

	state->phystotal = memInfo.ullTotalPhys;
	state->physavail = memInfo.ullAvailPhys;
	state->virttotal = memInfo.ullTotalVirtual;
	state->virtavail = memInfo.ullAvailVirtual;

#elif defined(QSC_SYSTEM_OS_APPLE)

	vm_size_t page_size;
	mach_port_t mach_port;
	mach_msg_type_number_t count;
	vm_statistics64_data_t vm_stats;

	mach_port = mach_host_self();
	count = sizeof(vm_stats) / sizeof(natural_t);

	if (KERN_SUCCESS == host_page_size(mach_port, &page_size) && KERN_SUCCESS == host_statistics64(mach_port, HOST_VM_INFO, (host_info64_t)&vm_stats, &count))
	{
		state->physavail = (uint64_t)vm_stats.free_count * (uint64_t)page_size;
		state->phystotal = state->physavail + ((uint64_t)vm_stats.active_count + (uint64_t)vm_stats.inactive_count + (uint64_t)vm_stats.wire_count) *  (uint64_t)page_size;
	}

	size_t pgf;
	size_t pgn;
	size_t pgs;

	pgn = 0;
	pgs = 0;
	pgf = 0;

	if (sysctlbyname("vm.pages", &pgn, NULL, NULL, 0) == 0)
	{
		if (sysctlbyname("vm.pagesize", &pgs, NULL, NULL, 0) == 0)
		{
			state->virttotal = pgn * pgs;
		}

		if (state->virttotal != 0 && sysctlbyname("vm.page_free_count", &pgf, NULL, NULL, 0) == 0)
		{
			state->virtavail = state->virttotal - (pgf * pgn);
		}
	}

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

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (uint32_t)GetCurrentProcessId();
#else//QSC_SYSTEM_OS_POSIX
	res = (uint32_t)getpid();
#endif

	return res;
}

bool qsc_sysutils_rdtsc_available()
{
	qsc_cpuidex_cpu_features cfeat;
	bool hfeat;
	bool ret;

	ret = false;
	hfeat = qsc_cpuidex_features_set(&cfeat);

	if (hfeat == true)
	{
		ret = cfeat.rdtcsp;
	}

	return ret;
}

size_t qsc_sysutils_user_name(char* name)
{
	size_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	TCHAR buf[UNLEN + 1];
	DWORD bufflen = sizeof(buf) / sizeof(TCHAR);
	GetUserName(buf, &bufflen);
	res = strlen(buf);
	qsc_memutils_copy(name, (char*)buf, res);


#elif defined(QSC_SYSTEM_OS_POSIX)

	char buf[LOGIN_NAME_MAX];
	getlogin_r(buf, LOGIN_NAME_MAX);
	res = strlen(buf);
	qsc_memutils_copy(name, buf, res);

#endif

	return res;
}

uint64_t qsc_sysutils_system_uptime()
{
	uint64_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = GetTickCount64();
#elif defined(QSC_SYSTEM_OS_POSIX)

	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
	{
		res = (uint64_t)((ts.tv_sec * 1000ULL) + (ts.tv_nsec / 1000000ULL));
	}

#else
	res = 0;
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
		rtme = __rdtsc();
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
				rtme = (ctr1 * 1000ULL / freq);
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
		rtme = (uint64_t)(ts.tv_sec + ts.tv_nsec);
	}

#else
#	error "Time not available on this system!"
#endif

	return rtme;
}

#if defined(QSC_SYSTEM_OS_WINDOWS)
void qsc_sysutils_user_identity(const char* name, char* id)
{
	LPCSTR accname = TEXT(name);
	LPTSTR domname = (LPTSTR)GlobalAlloc(GPTR, sizeof(TCHAR) * 1024);
	DWORD cchdomname = 1024;
	SID_NAME_USE esidtype;
	char sidbuf[1024] = { 0 };
	DWORD cbsid = 1024;
	SID* sid = (SID*)sidbuf;

	if (LookupAccountNameA(NULL, accname, sidbuf, &cbsid, domname, &cchdomname, &esidtype))
	{
		ConvertSidToStringSidA(sid, (LPSTR*)id);
	}
}
#endif

#if defined(QSC_DEBUG_MODE)
void qsc_system_values_print()
{
	const char* drv = "C:";
	char tname[QSC_SYSUTILS_SYSTEM_NAME_MAX] = { 0 };
	qsc_sysutils_drive_space_state dstate;
	qsc_sysutils_memory_statistics_state mstate;
	uint64_t ts;
	size_t len;
	uint32_t id;

	qsc_consoleutils_print_line("System visual verification test");
	qsc_consoleutils_print_line("Printing system values..");

	qsc_consoleutils_print_safe("Computer name: ");
	len = qsc_sysutils_computer_name(tname);
	qsc_consoleutils_print_line(tname);

	qsc_consoleutils_print_safe("Process Id: ");
	id = qsc_sysutils_process_id();
	qsc_consoleutils_print_uint(id);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("User name: ");
	len = qsc_sysutils_user_name(tname);
	qsc_consoleutils_print_line(tname);

	qsc_consoleutils_print_safe("Computer up-time: ");
	ts = qsc_sysutils_system_uptime();
	qsc_consoleutils_print_ulong(id);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("Time stamp: ");
	ts = qsc_sysutils_system_timestamp();
	qsc_consoleutils_print_ulong(ts);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("Drive statistics");
	qsc_sysutils_drive_space(drv, &dstate);
	qsc_consoleutils_print_safe("Free bytes: ");
	qsc_consoleutils_print_ulong(dstate.free);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("Available bytes: ");
	qsc_consoleutils_print_ulong(dstate.avail);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("Total bytes: ");
	qsc_consoleutils_print_ulong(dstate.total);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_line("Memory statistics");
	qsc_sysutils_memory_statistics(&mstate);
	qsc_consoleutils_print_safe("Physical Available: ");
	qsc_consoleutils_print_ulong(mstate.physavail);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("Physical total: ");
	qsc_consoleutils_print_ulong(mstate.phystotal);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("Virtual available: ");
	qsc_consoleutils_print_ulong(mstate.virtavail);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("Virtual total: ");
	qsc_consoleutils_print_ulong(mstate.virttotal);
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("");
}
#endif

