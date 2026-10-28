/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "sysutils.h"
#include "cpuidex.h"
#include "intrinsics.h"
#include "memutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	if !defined(WIN32_LEAN_AND_MEAN)
#		define WIN32_LEAN_AND_MEAN
#	endif
#	if !defined(NOMINMAX)
#		define NOMINMAX
#	endif
#	define _WINSOCKAPI_
#	include <Windows.h>
#	include <iphlpapi.h>
#	include <intrin.h>
#	include <sddl.h>
#	include <TlHelp32.h>
#   if defined(QSC_SYSTEM_COMPILER_MSC)
#	    pragma intrinsic(__cpuid)
#	    pragma comment(lib, "IPHLPAPI.lib")
#		pragma comment(lib, "advapi32.lib")
#   endif
#elif defined(QSC_SYSTEM_OS_MAC)
#	include <stdio.h>
#	include <sys/types.h>
#	include <mach/mach.h>
#	include <mach/mach_time.h>
#	include <sys/sysctl.h>
#	include <time.h>
#	include <pthread.h>
static pthread_once_t qsc_tc_once = PTHREAD_ONCE_INIT;
static double qsc_tc_ratio = 1.0;

static void qsc_tc_init(void)
{
	mach_timebase_info_data_t tb;
	mach_timebase_info(&tb);
	if (tb.denom != 0U)
	{
		qsc_tc_ratio = ((double)tb.numer / (double)tb.denom) / 1000000.0;
	}
}

#elif defined(QSC_SYSTEM_OS_UNIX)
#	include <time.h>
#	include <unistd.h>
#endif
#if defined(QSC_SYSTEM_OS_POSIX)
#	include <string.h>
#	if defined(QSC_HAS_CPUID)
#		include <cpuid.h>
#	endif
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
#	if defined(QSC_SYSTEM_OS_MAC)
#		include <sys/sysctl.h>
#		include <mach/vm_statistics.h>
#		include <mach/mach_types.h>
#		include <mach/mach_init.h>
#		include <mach/mach_host.h>
#	elif defined(QSC_SYSTEM_OS_BSD)
#		include <sys/sysctl.h>
#	elif defined(QSC_SYSTEM_OS_LINUX)
#		include <sys/sysinfo.h>
#	endif
#	include <sys/time.h>
#	include <sys/types.h>
#	include <unistd.h>
#endif

size_t qsc_sysutils_computer_name_bounded(char* name, size_t namelen)
{
	size_t res;

	res = 0U;
	if (name != NULL && namelen > 0U)
	{
		name[0U] = '\0';
#if defined(QSC_SYSTEM_OS_WINDOWS)
		char buf[MAX_COMPUTERNAME_LENGTH + 1U] = { 0U };
		DWORD blen;

		blen = (DWORD)sizeof(buf);
		if (GetComputerNameA(buf, &blen) != 0)
		{
			res = (size_t)blen;
			if (res >= namelen)
			{
				res = namelen - 1U;
			}
			qsc_memutils_copy(name, buf, res);
		}
#elif defined(QSC_SYSTEM_OS_POSIX)
		char buf[QSC_SYSUTILS_SYSTEM_NAME_MAX] = { 0U };

		if (gethostname(buf, sizeof(buf)) == 0)
		{
			buf[sizeof(buf) - 1U] = '\0';
			res = strlen(buf);
			if (res >= namelen)
			{
				res = namelen - 1U;
			}
			qsc_memutils_copy(name, buf, res);
		}
#endif
		name[res] = '\0';
	}
	return res;
}

size_t qsc_sysutils_computer_name(char* name)
{
	return qsc_sysutils_computer_name_bounded(name, QSC_SYSUTILS_SYSTEM_NAME_MAX);
}

size_t qsc_sysutils_cpu_count(void)
{
	size_t count;

	count = 1U;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	count = (size_t)sysinfo.dwNumberOfProcessors;
#if defined(ALL_PROCESSOR_GROUPS)
	{
		DWORD online;

		online = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
		if (online != 0U)
		{
			count = (size_t)online;
		}
	}
#endif

#elif defined(QSC_SYSTEM_OS_MAC)
	int nm[2U];
	size_t len;
	uint32_t tmpc;

	tmpc = 0U;
	len = 4U;
	nm[0U] = CTL_HW;
	nm[1U] = HW_AVAILCPU;

	sysctl(nm, 2, &tmpc, &len, NULL, 0);

	if (tmpc < 1U)
	{
		nm[1] = HW_NCPU;
		sysctl(nm, 2, &tmpc, &len, NULL, 0);

		if (tmpc < 1U)
		{
			count = 1U;
		}
		else
		{
			count = (size_t)tmpc;
		}
	}
	else
	{
		count = (size_t)tmpc;
	}
#elif defined(QSC_SYSTEM_OS_POSIX)
	long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
	count = (nprocs > 0U) ? (size_t)nprocs : 1U;
#endif

	return count;
}

void qsc_sysutils_drive_space(const char* drive, qsc_sysutils_drive_space_state* state)
{
	QSC_ASSERT(drive != NULL);
	QSC_ASSERT(state != NULL);

	if (drive != NULL && state != NULL)
	{
		state->free = 0U;
		state->total = 0U;
		state->avail = 0U;

#if defined(QSC_SYSTEM_OS_WINDOWS)

		ULARGE_INTEGER freebt;
		ULARGE_INTEGER totalbt;
		ULARGE_INTEGER availbt;

		UINT drvtype = GetDriveType(drive);

		if ((drvtype == 3U || drvtype == 6U) &&
			GetDiskFreeSpaceEx(drive, &freebt, &totalbt, &availbt))
		{
			state->free = freebt.QuadPart;
			state->total = totalbt.QuadPart;
			state->avail = availbt.QuadPart;
		}

#elif defined(QSC_SYSTEM_OS_POSIX)

		struct statvfs fsinfo;

		if (statvfs(drive, &fsinfo) == 0)
		{
			state->total = (uint64_t)fsinfo.f_frsize * (uint64_t)fsinfo.f_blocks;
			state->free = (uint64_t)fsinfo.f_frsize * (uint64_t)fsinfo.f_bfree;
			state->avail = (uint64_t)fsinfo.f_frsize * (uint64_t)fsinfo.f_bavail;
		}

#endif
	}
}

void qsc_sysutils_memory_statistics(qsc_sysutils_memory_statistics_state* state)
{
	QSC_ASSERT(state != NULL);

	if (state != NULL)
	{
		qsc_memutils_clear(state, sizeof(qsc_sysutils_memory_statistics_state));

#if defined(QSC_SYSTEM_OS_WINDOWS)

		MEMORYSTATUSEX memInfo;

		memInfo.dwLength = sizeof(MEMORYSTATUSEX);

		if (GlobalMemoryStatusEx(&memInfo) != 0)
		{
			state->phystotal = memInfo.ullTotalPhys;
			state->physavail = memInfo.ullAvailPhys;
			state->virttotal = memInfo.ullTotalVirtual;
			state->virtavail = memInfo.ullAvailVirtual;
		}

#elif defined(QSC_SYSTEM_OS_MAC)

		vm_size_t page_size;
		mach_port_t mach_port;
		mach_msg_type_number_t count;
		vm_statistics64_data_t vm_stats;

		mach_port = mach_host_self();
		count = sizeof(vm_stats) / sizeof(natural_t);

		if (KERN_SUCCESS == host_page_size(mach_port, &page_size) && KERN_SUCCESS == host_statistics64(mach_port, HOST_VM_INFO, (host_info64_t)&vm_stats, &count))
		{
			state->physavail = (uint64_t)vm_stats.free_count * (uint64_t)page_size;
			state->phystotal = state->physavail + ((uint64_t)vm_stats.active_count + (uint64_t)vm_stats.inactive_count + (uint64_t)vm_stats.wire_count) * (uint64_t)page_size;
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
				state->virtavail = state->virttotal - (pgf * pgs);
			}
		}

#elif defined(QSC_SYSTEM_OS_LINUX)

		struct sysinfo memInfo;

		if (sysinfo(&memInfo) == 0)
		{
			state->phystotal = (uint64_t)memInfo.totalram * (uint64_t)memInfo.mem_unit;
			state->physavail = (uint64_t)memInfo.freeram * (uint64_t)memInfo.mem_unit;
			state->virttotal = ((uint64_t)memInfo.totalram + (uint64_t)memInfo.totalswap) * (uint64_t)memInfo.mem_unit;
			state->virtavail = ((uint64_t)memInfo.freeram + (uint64_t)memInfo.freeswap) * (uint64_t)memInfo.mem_unit;
		}

#elif defined(QSC_SYSTEM_OS_BSD)

		uint64_t phtotal;
		size_t slen;

		phtotal = 0U;
		slen = sizeof(phtotal);

		if (sysctlbyname("hw.physmem", &phtotal, &slen, NULL, 0) == 0)
		{
			state->phystotal = phtotal;
			state->virttotal = phtotal;
		}
		else
		{
			unsigned long phtotal32;

			phtotal32 = 0UL;
			slen = sizeof(phtotal32);

			if (sysctlbyname("hw.physmem", &phtotal32, &slen, NULL, 0) == 0)
			{
				state->phystotal = (uint64_t)phtotal32;
				state->virttotal = (uint64_t)phtotal32;
			}
		}

		/* Portable BSD free/swap accounting is OS-specific; leave unavailable fields zeroed if not provided. */
		state->physavail = 0U;
		state->virtavail = 0U;

#endif
	}
}

char qsc_sysutils_get_os_drive_letter(void)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	char buffer[MAX_PATH] = { 0 };

	if (GetWindowsDirectoryA(buffer, MAX_PATH) == 0)
	{
		return '\0';
	}

	return buffer[0U];
#else
	return '/';
#endif
}

uint32_t qsc_sysutils_process_id(void)
{
	uint32_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (uint32_t)GetCurrentProcessId();
#elif defined(QSC_SYSTEM_OS_POSIX)
	res = (uint32_t)getpid();
#else
	res = 0;
#endif

	return res;
}

bool qsc_sysutils_rdtsc_available(void)
{
	bool ret;

#if defined(QSC_HAS_CPUID)
	qsc_cpuidex_cpu_features cfeat;
	bool hfeat;

	hfeat = qsc_cpuidex_features_set(&cfeat);

	if (hfeat == true)
	{
		ret = cfeat.rdtcsp;
	}
	else
	{
		ret = false;
	}
#else
	ret = false;
#endif

	return ret;
}

size_t qsc_sysutils_user_name_bounded(char* name, size_t namelen)
{
	size_t res;

	res = 0U;
	if (name != NULL && namelen > 0U)
	{
		name[0U] = '\0';
#if defined(QSC_SYSTEM_OS_WINDOWS)
		char buf[QSC_SYSUTILS_SYSTEM_NAME_MAX] = { 0U };
		DWORD blen;

		blen = (DWORD)sizeof(buf);
		if (GetUserNameA(buf, &blen) != 0 && blen > 0U)
		{
			res = (size_t)blen - 1U;
			if (res >= namelen)
			{
				res = namelen - 1U;
			}
			qsc_memutils_copy(name, buf, res);
		}
#elif defined(QSC_SYSTEM_OS_POSIX)
		char buf[QSC_SYSUTILS_SYSTEM_NAME_MAX] = { 0U };
		char pwbuf[QSC_SYSUTILS_SYSTEM_NAME_MAX * 4U];
		struct passwd passwdstate;
		struct passwd* pw;

		if (getlogin_r(buf, sizeof(buf)) != 0 || buf[0U] == '\0')
		{
			pw = NULL;
			if (getpwuid_r(getuid(), &passwdstate, pwbuf, sizeof(pwbuf), &pw) == 0 && pw != NULL)
			{
				res = strlen(pw->pw_name);
				if (res >= namelen)
				{
					res = namelen - 1U;
				}
				qsc_memutils_copy(name, pw->pw_name, res);
			}
		}
		else
		{
			res = strlen(buf);
			if (res >= namelen)
			{
				res = namelen - 1U;
			}
			qsc_memutils_copy(name, buf, res);
		}
#endif
		name[res] = '\0';
	}
	return res;
}

size_t qsc_sysutils_user_name(char* name)
{
	return qsc_sysutils_user_name_bounded(name, QSC_SYSUTILS_SYSTEM_NAME_MAX);
}

uint64_t qsc_sysutils_system_uptime(void)
{
	uint64_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = GetTickCount64();
#elif defined(QSC_SYSTEM_OS_POSIX)

	struct timespec ts;

	res = 0U;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
	{
		res = (uint64_t)((ts.tv_sec * 1000ULL) + (ts.tv_nsec / 1000000ULL));
	}

#else
	res = 0U;
#endif

	return res;
}

uint64_t qsc_sysutils_system_timestamp(void)
{
	uint64_t rtme;

	rtme = 0U;

#if defined(QSC_SYSTEM_OS_WINDOWS)

#if defined(QSC_SYSTEM_ARCH_IX86_32)
	if (qsc_sysutils_rdtsc_available(void))
	{
		rtme = __rdtsc();
	}
	else
#endif
	{
		int64_t ctr1 = 0;
		int64_t freq = 0;

		if (QueryPerformanceCounter((LARGE_INTEGER*)&ctr1))
		{
			QueryPerformanceFrequency((LARGE_INTEGER*)&freq);

			if (freq > 0)
			{
				rtme = ((uint64_t)(ctr1 / freq) * 1000ULL) +
					((uint64_t)(ctr1 % freq) * 1000ULL / (uint64_t)freq);
			}
		}
		else
		{
			FILETIME ft;
			LARGE_INTEGER li;

			GetSystemTimeAsFileTime(&ft);
			li.LowPart = ft.dwLowDateTime;
			li.HighPart = ft.dwHighDateTime;
			rtme = (uint64_t)li.QuadPart;
			rtme -= 116444736000000000ULL;
			rtme /= 10000ULL;
		}
	}

#elif (defined(QSC_SYSTEM_OS_HPUX) || defined(QSC_SYSTEM_OS_SUNUX)) && (defined(__SVR4) || defined(__svr4__))

	/* HP-UX, Solaris */
	rtme = (uint64_t)gethrtime();

#elif defined(QSC_SYSTEM_OS_MAC)

	/* OSX */
	pthread_once(&qsc_tc_once, qsc_tc_init);
	rtme = (uint64_t)((double)mach_absolute_time() * qsc_tc_ratio);

#elif defined(QSC_SYSTEM_OS_POSIX)

	/* POSIX */
#	if defined(_POSIX_TIMERS) && (_POSIX_TIMERS > 0)
	struct timespec ts;
	clockid_t id = (clockid_t)-1;
#		if defined(CLOCK_MONOTONIC_PRECISE)
	/* BSD */
	id = CLOCK_MONOTONIC_PRECISE;
#		elif defined(CLOCK_MONOTONIC_RAW)
	/* Linux */
	id = CLOCK_MONOTONIC_RAW;
#		elif defined(CLOCK_HIGHRES)
	/* Solaris */
	id = CLOCK_HIGHRES;
#		elif defined(CLOCK_MONOTONIC)
	/* AIX, BSD, Linux, POSIX, Solaris */
	id = CLOCK_MONOTONIC;
#		elif defined(CLOCK_REALTIME)
	/* AIX, BSD, HP - UX, Linux, POSIX */
	id = CLOCK_REALTIME;
#		endif
#	endif

	if (id != (clockid_t)-1 && clock_gettime(id, &ts) != -1)
	{
		rtme = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
	}

#else
#	error "Time not available on this system!"
#endif

	return rtme;
}

#if defined(QSC_SYSTEM_OS_WINDOWS)
void qsc_sysutils_user_identity(const char* name, char* id)
{
	if (name != NULL && id != NULL)
	{
		char domain[QSC_SYSUTILS_SYSTEM_NAME_MAX];
		uint8_t sidbuf[1024U];
		DWORD cbsid;
		DWORD cchdomain;
		SID_NAME_USE use;
		LPSTR sidstr;

		id[0U] = '\0';
		cbsid = (DWORD)sizeof(sidbuf);
		cchdomain = (DWORD)sizeof(domain);
		sidstr = NULL;
		if (LookupAccountNameA(NULL, name, sidbuf, &cbsid, domain, &cchdomain, &use) != 0)
		{
			if (ConvertSidToStringSidA((PSID)sidbuf, &sidstr) != 0 && sidstr != NULL)
			{
				size_t nlen;

				nlen = strlen(sidstr);
				if (nlen < QSC_SYSUTILS_SYSTEM_NAME_MAX)
				{
					qsc_memutils_copy(id, sidstr, nlen + 1U);
				}
				LocalFree(sidstr);
			}
		}
	}
}
#else
void qsc_sysutils_user_identity(const char* name, char* id)
{
	if (name != NULL && id != NULL)
	{
		struct passwd state;
		struct passwd* pw;
		char pbuf[QSC_SYSUTILS_SYSTEM_NAME_MAX * 4U];

		id[0U] = '\0';
		pw = NULL;
		if (getpwnam_r(name, &state, pbuf, sizeof(pbuf), &pw) == 0 && pw != NULL)
		{
			(void)snprintf(id, QSC_SYSUTILS_SYSTEM_NAME_MAX, "%u", (unsigned int)pw->pw_uid);
		}
	}
}

#endif

#if defined(QSC_DEBUG_MODE)
void qsc_system_values_print()
{
	const char* drv = "C:";
	char tname[QSC_SYSUTILS_SYSTEM_NAME_MAX] = { 0U };
	qsc_sysutils_drive_space_state dstate;
	qsc_sysutils_memory_statistics_state mstate;
	uint64_t ts;
	size_t len;
	uint32_t id;

	qsc_consoleutils_print_line("System visual verification test");
	qsc_consoleutils_print_line("Printing system values..");

	qsc_consoleutils_print_safe("Computer name: ");
	len = qsc_sysutils_computer_name(tname);

	if (len > 0U)
	{
		qsc_consoleutils_print_line(tname);
	}

	qsc_consoleutils_print_safe("Process Id: ");
	id = qsc_sysutils_process_id();
	qsc_consoleutils_print_uint(id);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("User name: ");
	len = qsc_sysutils_user_name(tname);

	if (len > 0)
	{
		qsc_consoleutils_print_line(tname);
	}

	qsc_consoleutils_print_safe("Computer up-time: ");
	ts = qsc_sysutils_system_uptime();
	qsc_consoleutils_print_ulong(ts);
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

