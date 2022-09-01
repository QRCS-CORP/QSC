#include "cpuidex.h"
#include "consoleutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdio.h>

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <Windows.h>
#	if defined(QSC_SYSTEM_ARCH_IX86)
#		include <intrin.h>
#		pragma intrinsic(__cpuid)
#	elif defined(QSC_SYSTEM_ARCH_ARM)
#		include <processthreadsapi.h>
#	endif
#elif defined(QSC_SYSTEM_OS_POSIX)
#	if defined(QSC_SYSTEM_OS_BSD)
#   	include <sys/param.h>
#   	include <sys/sysctl.h>
#		include <sys/types.h>
#		include <unistd.h>
#	else
#		include <cpuid.h>
#   	include <limits.h>
#		include <x86intrin.h>
#   	include <unistd.h>
#		include <xsaveintrin.h>
#	endif
#	if defined(_AIX)
#		include <sys/systemcfg.h>
#	endif
#endif

static uint32_t cpuidex_cpu_count()
{
	uint32_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	res = (uint32_t)sysinfo.dwNumberOfProcessors;
#else
	res = (uint32_t)sysconf(_SC_NPROCESSORS_CONF);
#endif

	if (res < 1)
	{
		res = 1;
	}

	return res;
}

#if defined(QSC_SYSTEM_ARCH_ARM)
#	if !defined(HWCAP_ARMv7)
#		define HWCAP_ARMv7 (1 << 29)
#	endif
#	if !defined(HWCAP_ASIMD)
#		define HWCAP_ASIMD (1 << 1)
#	endif
#	if !defined(HWCAP_NEON)
#		define HWCAP_NEON (1 << 12)
#	endif
#	if !defined(HWCAP_CRC32)
#		define HWCAP_CRC32 (1 << 7)
#	endif
#	if !defined(HWCAP2_CRC32)
#		define HWCAP2_CRC32 (1 << 4)
#	endif
#	if !defined(HWCAP_PMULL)
#		define HWCAP_PMULL (1 << 4)
#	endif
#	if !defined(HWCAP2_PMULL)
#		define HWCAP2_PMULL (1 << 1)
#	endif
#	if !defined(HWCAP_AES)
#		define HWCAP_AES (1 << 3)
#	endif
#	if !defined(HWCAP2_AES)
#		define HWCAP2_AES (1 << 0)
#	endif
#	if !defined(HWCAP_SHA1)
#		define HWCAP_SHA1 (1 << 5)
#	endif
#	if !defined(HWCAP_SHA2)
#		define HWCAP_SHA2 (1 << 6)
#	endif
#	if !defined(HWCAP2_SHA1)
#		define HWCAP2_SHA1 (1 << 2)
#	endif
#	if !defined(HWCAP2_SHA2)
#		define HWCAP2_SHA2 (1 << 3)
#	endif
#	if !defined(HWCAP_SM3)
#		define HWCAP_SM3 (1 << 18)
#	endif
#	if !defined(HWCAP_SM4)
#		define HWCAP_SM4 (1 << 19)
#	endif

static bool cpuidex_is_armv7()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_ARMv7) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_ARMv7) != 0 ||
		(getauxval(AT_HWCAP) & HWCAP_NEON) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__arm__)
	res = true;
#elif defined(_WIN32) && defined(_M_ARM64)
	res = true;
#endif

	return res;
}

static bool cpuidex_has_neon()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_ASIMD) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_ASIMD) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_ASIMD) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_NEON) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv8())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool cpuidex_has_pmull()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_PMULL) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_PMULL) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_PMULL) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_PMULL) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	/* M1 processor */
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool cpuidex_has_aes()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_AES) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_AES) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_AES) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_AES) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool cpuidex_has_sha256()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA2) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA2) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA2) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA2) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0)
	{
		res = true;
	}
#endif

	return res;
}

static bool cpuidex_has_sha512()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA512) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA512) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA512) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA512) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
}
#endif

	return res;
}

static bool cpuidex_has_sha3()
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA3) != 0))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__) && 0
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA3) != 0))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA3) != 0)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA3) != 0)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	if (IsAppleMachineARMv82())
	{
		res = true;
	}
#endif

	return res;
}

static void cpuidex_arm_features(qsc_cpuidex_cpu_features* features)
{
	features->aesni = cpuidex_has_aes();
	features->armv7 = cpuidex_is_armv7();
	features->neon = cpuidex_has_neon();
	features->pcmul = cpuidex_has_pmull();
	features->sha256 = cpuidex_has_sha256();
	features->sha512 = cpuidex_has_sha512();
	features->sha3 = cpuidex_has_sha3();
}

#endif

#if defined(QSC_SYSTEM_ARCH_IX86) && !defined(QSC_SYSTEM_OS_BSD)

#	define CPUID_EBX_AVX2 0x00000020UL
#	define CPUID_EBX_AVX512F 0x00010000UL
#	define CPUID_EBX_ADX 0x00080000UL
#	define CPUID_ECX_PCLMUL 0x00000002UL
#	define CPUID_ECX_AESNI 0x02000000UL
#	define CPUID_ECX_XSAVE 0x04000000UL
#	define CPUID_ECX_OSXSAVE 0x08000000UL
#	define CPUID_ECX_AVX 0x10000000UL
#	define CPUID_ECX_RDRAND 0x40000000UL
#	define CPUID_EDX_RDTCSP 0x0000001BUL
#	define CPUID_EBX_SHA2 0x20000000UL
#	define XCR0_SSE 0x00000002UL
#	define XCR0_AVX 0x00000004UL
#	define XCR0_OPMASK 0x00000020UL
#	define XCR0_ZMM_HI256 0x00000040UL
#	define XCR0_HI16_ZMM 0x00000080UL

static void cpuidex_cpu_info(uint32_t info[4], const uint32_t infotype)
{
#if defined(QSC_SYSTEM_COMPILER_MSC)
	__cpuid((int*)info, infotype);
#elif defined(QSC_SYSTEM_COMPILER_GCC)
	__get_cpuid(infotype, &info[0], &info[1], &info[2], &info[3]);
#endif
}

static uint32_t cpuidex_read_bits(uint32_t value, int index, int length)
{
	int mask = ((1L << length) - 1) << index;

	return (value & mask) >> index;
}

static void cpuidex_vendor_name(qsc_cpuidex_cpu_features* features)
{
	uint32_t info[4] = { 0 };

	cpuidex_cpu_info(info, 0x00000000UL);
	qsc_memutils_clear(features->vendor, QSC_CPUIDEX_VENDOR_LENGTH);
	qsc_memutils_copy(&features->vendor[0], &info[1], sizeof(uint32_t));
	qsc_memutils_copy(&features->vendor[4], &info[3], sizeof(uint32_t));
	qsc_memutils_copy(&features->vendor[8], &info[2], sizeof(uint32_t));
}

static void cpuidex_bus_info(qsc_cpuidex_cpu_features* features)
{
	uint32_t info[4] = { 0 };
	cpuidex_cpu_info(info, 0x00000000UL);

	if (info[0] >= 0x00000016UL)
	{
		qsc_memutils_clear(info, sizeof(info));
		cpuidex_cpu_info(info, 0x00000016UL);
		features->freqbase = info[0];
		features->freqmax = info[1];
		features->freqref = info[2];
	}
}

static void cpuidex_cpu_cache(qsc_cpuidex_cpu_features* features)
{
	uint32_t info[4] = { 0 };

	cpuidex_cpu_info(info, 0x80000006UL);

	features->l1cache = cpuidex_read_bits(info[2], 0, 8);
	features->l1cacheline = cpuidex_read_bits(info[2], 0, 11);
	features->l2associative = cpuidex_read_bits(info[2], 12, 4);
	features->l2cache = cpuidex_read_bits(info[2], 16, 16);
}

static void cpuidex_cpu_topology(qsc_cpuidex_cpu_features* features)
{
	uint32_t info[4] = { 0 };

	/* total cpu cores */
	features->cores = cpuidex_cpu_count();

	/* hyperthreading and actual cpus */
	cpuidex_cpu_info(info, 0x00000001UL);
	features->hyperthread = cpuidex_read_bits(info[3], 28, 1) != 0;
	features->cpus = (features->hyperthread == true && features->cores > 1) ? (features->cores / 2) : features->cores;

	/* cache line size */
	cpuidex_cpu_info(info, 0x00000001UL);

	/* cpu features */
	features->pcmul = ((info[2] & CPUID_ECX_PCLMUL) != 0x00000000UL);
	features->aesni = ((info[2] & CPUID_ECX_AESNI) != 0x00000000UL);
	features->rdrand = ((info[2] & CPUID_ECX_RDRAND) != 0x00000000UL);
	features->rdtcsp = ((info[3] & CPUID_EDX_RDTCSP) != 0x00000000UL);

#if defined(QSC_SYSTEM_HAS_AVX)
	bool havx;

	havx = (info[2] & CPUID_ECX_AVX) != 0x00000000UL;

	if (havx == true)
	{
		uint32_t xcr0;

		xcr0 = 0;

		if ((info[2] & (CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
			(CPUID_ECX_AVX | CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE))
		{
			xcr0 = (uint32_t)_xgetbv(0);
		}

		if ((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX))
		{
			features->avx = true;
		}
	}
#endif

	if (features->cputype == qsc_cpuid_intel)
	{
		features->cacheline = cpuidex_read_bits(info[1], 16, 8) * 8;
	}
	else if (features->cputype == qsc_cpuid_amd)
	{
		cpuidex_cpu_info(info, 0x80000005UL);
		features->cacheline = cpuidex_read_bits(info[2], 24, 8);
	}

	if (features->avx == true)
	{
#if defined(QSC_SYSTEM_HAS_AVX2)
		bool havx2;

		qsc_memutils_clear(info, sizeof(info));
		cpuidex_cpu_info(info, 0x00000007UL);

#	if defined(QSC_SYSTEM_COMPILER_GCC)
		__builtin_cpu_init();
		havx2 = __builtin_cpu_supports("avx2") != 0;
#	else
		havx2 = ((info[1] & CPUID_EBX_AVX2) != 0x00000000UL);
#	endif

		features->adx = ((info[1] & CPUID_EBX_ADX) != 0x00000000UL);
		features->avx2 = havx2 && ((uint32_t)_xgetbv(0) & 0x000000E6UL) != 0x00000000UL;
		features->sha256 = ((info[1] & CPUID_EBX_SHA2) != 0x00000000UL);
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
		bool havx512;
#	if defined(QSC_SYSTEM_COMPILER_GCC)
		havx512 = __builtin_cpu_supports("avx512f") != 0;
#	else
		havx512 = ((info[1] & CPUID_EBX_AVX512F) != 0x00000000UL);
#	endif
		if (havx512 == true)
		{
			uint32_t xcr2 = (uint32_t)_xgetbv(0);

			if ((xcr2 & (XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)) ==
				(XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM))
			{
				features->avx512f = true;
			}
		}
#endif
	}
}

static void cpuidex_cpu_type(qsc_cpuidex_cpu_features* features)
{
	char tmpn[QSC_CPUIDEX_VENDOR_LENGTH + 1] = { 0 };

	cpuidex_vendor_name(features);
	qsc_memutils_copy(tmpn, features->vendor, QSC_CPUIDEX_VENDOR_LENGTH);
	qsc_stringutils_to_lowercase(tmpn);

	if (qsc_stringutils_string_contains(tmpn, "intel") == true)
	{
		features->cputype = qsc_cpuid_intel;
	}
	else if (qsc_stringutils_string_contains(tmpn, "amd") == true)
	{
		features->cputype = qsc_cpuid_amd;
	}
	else if (qsc_stringutils_string_contains(tmpn, "centaur") == true)
	{
		features->cputype = qsc_cpuid_via;
	}
	else if (qsc_stringutils_string_contains(tmpn, "via") == true)
	{
		features->cputype = qsc_cpuid_via;
	}
	else if (qsc_stringutils_string_contains(tmpn, "hygon") == true)
	{
		features->cputype = qsc_cpuid_hygion;
	}
	else
	{
		features->cputype = qsc_cpuid_unknown;
	}
}

static void cpuidex_serial_number(qsc_cpuidex_cpu_features* features)
{
	uint32_t info[4] = { 0 };

	cpuidex_cpu_info(info, 0x00000003UL);
	qsc_memutils_clear(features->serial, QSC_CPUIDEX_SERIAL_LENGTH);
	qsc_memutils_copy(&features->serial[0], &info[1], sizeof(uint32_t));
	qsc_memutils_copy(&features->serial[4], &info[3], sizeof(uint32_t));
	qsc_memutils_copy(&features->serial[8], &info[2], sizeof(uint32_t));
}

#endif

#if defined(QSC_SYSTEM_OS_BSD)

static void cpuidex_bsd_topology(qsc_cpuidex_cpu_features* features)
{
	size_t plen;
	uint64_t pval;

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.physicalcpu", &pval, &plen, NULL, 0) == 0)
	{
		features->cpus = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.logicalcpu", &pval, &plen, NULL, 0) == 0)
	{
		features->cores = pval;
		features->hyperthread = (pval > features->cpus);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0) == 0)
	{
		features->cacheline = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency", &pval, &plen, NULL, 0) == 0)
	{
		features->freqbase = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_max", &pval, &plen, NULL, 0) == 0)
	{
		features->freqmax = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_min", &pval, &plen, NULL, 0) == 0)
	{
		features->freqref = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l1dcachesize", &pval, &plen, NULL, 0) == 0)
	{
		features->l1cache = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0) == 0)
	{
		features->cacheline = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l2cachesize", &pval, &plen, NULL, 0) == 0)
	{
		features->l2cache = pval;
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.adx", &pval, &plen, NULL, 0) == 0)
	{
		features->adx = (pval == 1);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.aes", &pval, &plen, NULL, 0) == 0)
	{
		features->aesni = (pval == 1);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx1_0", &pval, &plen, NULL, 0) == 0)
	{
		features->avx = (pval == 1);
	}


	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx2_0", &pval, &plen, NULL, 0) == 0)
	{
		features->avx2 = (pval == 1);
	}

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx512f", &pval, &plen, NULL, 0) == 0)
	{
		features->avx512f = (pval == 1);
	}

	features->pcmul = features->avx;

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdrand", &pval, &plen, NULL, 0) == 0)
	{
		features->rdrand = (pval == 1);
	}

	features->rdtcsp = features->avx;

	pval = 0;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdrand", &pval, &plen, NULL, 0) == 0)
	{
		features->rdrand = (pval == 1);
	}

	char vend[1024] = { 0 };
	plen = sizeof(vend);

	if (sysctlbyname("machdep.cpu.brand_string", vend, &plen, NULL, 0) >= 0)
	{
		qsc_memutils_copy(features->vendor, vend, QSC_CPUIDEX_VENDOR_LENGTH - 1);
		qsc_stringutils_to_lowercase(vend);

		if (qsc_stringutils_string_contains(vend, "intel") == true)
		{
			features->cputype = qsc_cpuid_intel;
		}
		else if (qsc_stringutils_string_contains(vend, "amd") == true)
		{
			features->cputype = qsc_cpuid_amd;
		}
		else
		{
			features->cputype = qsc_cpuid_unknown;
		}
	}
}

#elif defined(QSC_SYSTEM_OS_POSIX)

static void cpuidex_posix_topology(qsc_cpuidex_cpu_features* features)
{
#	if defined(QSC_SYSTEM_ARCH_IX86) && defined(QSC_SYSTEM_COMPILER_GCC)

	cpuidex_cpu_type(features);

	if (features->cputype == qsc_cpuid_intel || features->cputype == qsc_cpuid_amd)
	{
		cpuidex_bus_info(features);
		cpuidex_cpu_cache(features);
		cpuidex_cpu_topology(features);
		cpuidex_serial_number(features);
	}

#	else

	int32_t res;

	res = sysconf(_SC_NPROCESSORS_CONF);

	if (res > 0)
	{
		features->cpus = (uint32_t)res;
	}

	res = sysconf(_SC_NPROCESSORS_ONLN);

	if (res > 0)
	{
		features->cores = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL1_ICACHE_SIZE);

	if (res > 0)
	{
		features->l1cache = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL1_ICACHE_LINESIZE);

	if (res > 0)
	{
		features->l1cacheline = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL2_CACHE_SIZE);

	if (res > 0)
	{
		features->l2cache = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL2_CACHE_ASSOC);

	if (res > 0)
	{
		features->l2associative = (uint32_t)res;
	}


	res = sysconf(_SC_LEVEL2_CACHE_LINESIZE);

	if (res > 0)
	{
		features->cacheline = (uint32_t)res;
	}
#	endif
}

#elif defined(QSC_SYSTEM_OS_WINDOWS)

static void cpuidex_windows_topology(qsc_cpuidex_cpu_features* features)
{
#	if defined(QSC_SYSTEM_ARCH_IX86)
	cpuidex_cpu_type(features);

	if (features->cputype == qsc_cpuid_intel || features->cputype == qsc_cpuid_amd)
	{
		cpuidex_bus_info(features);
		cpuidex_cpu_cache(features);
		cpuidex_cpu_topology(features);
		cpuidex_serial_number(features);
	}
#	else

	features->cpus = cpuidex_cpu_count();
	features->cores = features->cpus;

#	endif
}

#endif

bool qsc_cpuidex_features_set(qsc_cpuidex_cpu_features* features)
{
    bool res;

    features->adx = false;
    features->aesni = false;
    features->pcmul = false;
	/* ARM features */
	features->armv7 = false;
	features->neon = false;
	features->sha256 = false;
	features->sha512 = false;
	features->sha3 = false;
	/* Intel features */
    features->avx = false;
    features->avx2 = false;
    features->avx512f = false;
    features->hyperthread = false;
    features->rdrand = false;
    features->rdtcsp = false;
	/* cpu topology */
    features->cacheline = 0;
    features->cores = 0;
    features->cpus = 1;
    features->freqbase = 0;
    features->freqmax = 0;
    features->freqref = 0;
    features->l1cache = 0;
    features->l1cacheline = 0;
    features->l2associative = 4;
    features->l2cache = 0;
    qsc_memutils_clear(features->serial, QSC_CPUIDEX_SERIAL_LENGTH);

#if defined(QSC_SYSTEM_OS_POSIX)
#	if defined(QSC_SYSTEM_OS_BSD)
	cpuidex_bsd_topology(features);
    res = true;
#else
	cpuidex_posix_topology(features);
	res = true;
#endif
#elif defined(QSC_SYSTEM_OS_WINDOWS)
	cpuidex_windows_topology(features);
	res = true;
#else
	res = false;
#endif

#if defined(QSC_SYSTEM_ARCH_ARM)
	cpuidex_arm_features(features);
#endif

    return res;
}

void qsc_cpuidex_print_stats()
{
	qsc_cpuidex_cpu_features cfeat;
	const char sf[] = "false";
	const char st[] = "true";
	char vstr[16] = {0};
	bool hfeat;

	hfeat = qsc_cpuidex_features_set(&cfeat);

	if (hfeat == true)
	{
		qsc_consoleutils_print_safe("ADX: ");
		qsc_consoleutils_print_line(cfeat.adx == true ? st : sf);

		qsc_consoleutils_print_safe("AESNI: ");
		qsc_consoleutils_print_line(cfeat.aesni == true ? st : sf);

		qsc_consoleutils_print_safe("PCLMULQDQ: ");
		qsc_consoleutils_print_line(cfeat.pcmul == true ? st : sf);

#if defined(QSC_SYSTEM_ARCH_ARM)

		qsc_consoleutils_print_safe("ARMV7: ");
		qsc_consoleutils_print_line(cfeat.armv7 == true ? st : sf);

		qsc_consoleutils_print_safe("NEON: ");
		qsc_consoleutils_print_line(cfeat.neon == true ? st : sf);

		qsc_consoleutils_print_safe("SHA256: ");
		qsc_consoleutils_print_line(cfeat.sha256 == true ? st : sf);

		qsc_consoleutils_print_safe("SHA512: ");
		qsc_consoleutils_print_line(cfeat.sha512 == true ? st : sf);

		qsc_consoleutils_print_safe("SHA3: ");
		qsc_consoleutils_print_line(cfeat.sha3 == true ? st : sf);

#else

		qsc_consoleutils_print_safe("AVX: ");
		qsc_consoleutils_print_line(cfeat.avx == true ? st : sf);

		qsc_consoleutils_print_safe("AVX2: ");
		qsc_consoleutils_print_line(cfeat.avx2 == true ? st : sf);

		qsc_consoleutils_print_safe("AVX512: ");
		qsc_consoleutils_print_line(cfeat.avx512f == true ? st : sf);

		qsc_consoleutils_print_safe("Hyperthread: ");
		qsc_consoleutils_print_line(cfeat.hyperthread == true ? st : sf);

		qsc_consoleutils_print_safe("RDRAND: ");
		qsc_consoleutils_print_line(cfeat.rdrand == true ? st : sf);

		qsc_consoleutils_print_safe("RDTCSP: ");
		qsc_consoleutils_print_line(cfeat.rdtcsp == true ? st : sf);

#endif

		qsc_consoleutils_print_safe("Cacheline size: ");
		qsc_stringutils_int_to_string((int32_t)cfeat.cacheline, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("CPUs: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.cpus, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("CPU cores: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.cores, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("Frequency base: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.freqbase, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("Frequency max: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.freqmax, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("Frequency ref: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.freqref, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("L1 cache size: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.l1cache, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("L2 cache size: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.l2cache, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("L2 associative: ");
		qsc_memutils_clear(vstr, sizeof(vstr));
		qsc_stringutils_int_to_string((int32_t)cfeat.l2associative, vstr, sizeof(vstr));
		qsc_consoleutils_print_line(vstr);

		qsc_consoleutils_print_safe("CPU Vendor: ");
		qsc_consoleutils_print_line(cfeat.vendor);
	}
}
