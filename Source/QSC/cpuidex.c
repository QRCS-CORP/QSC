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

#include "cpuidex.h"

/* Runtime feature detection is supported on x86 through CPUID and on ARM through OS feature interfaces. */
#if defined(QSC_HAS_CPUID) || defined(QSC_SYSTEM_ARCH_ARM)

#include "consoleutils.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

#if defined(QSC_SYSTEM_OS_WINDOWS)
#if !defined(WIN32_LEAN_AND_MEAN)
#	define WIN32_LEAN_AND_MEAN
#endif
#if !defined(NOMINMAX)
#	define NOMINMAX
#endif
#	include <Windows.h>
#	if defined(QSC_SYSTEM_ARCH_IX86)
#		include <intrin.h>
#	elif defined(QSC_SYSTEM_ARCH_ARM)
#		include <processthreadsapi.h>
#	endif
#elif defined(QSC_SYSTEM_OS_POSIX)
/* common POSIX headers */
#   include <unistd.h>
#   include <pthread.h>
#   include <sys/types.h>
/* for getauxval()/AT_HWCAP on Linux */
#   if defined(QSC_SYSTEM_OS_LINUX)
#       include <sys/auxv.h>
#   endif
#   if defined(QSC_SYSTEM_OS_BSD)
/* BSD topology via sysctl */
#       include <sys/param.h>
#       include <sys/sysctl.h>
#   endif
/* only pull in x86 CPUID intrinsics on x86/Linux */
#   if defined(QSC_SYSTEM_ARCH_IX86) && !defined(QSC_SYSTEM_OS_BSD)
#       include <cpuid.h>
#       include <limits.h>
#       include <x86intrin.h>
#       include <xsaveintrin.h>
#   endif
#   if defined(_AIX)
#       include <sys/systemcfg.h>
#   endif
#endif

#if defined(QSC_SYSTEM_ARCH_ARM)
#	if defined(__ANDROID__)
#		include <cpu-features.h>
#	endif
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
#	if !defined(HWCAP_SHA512)
#		define HWCAP_SHA512 (1UL << 21U)
#	endif
#	if !defined(HWCAP_SHA3)
#		define HWCAP_SHA3 (1UL << 17U)
#	endif
#	if !defined(HWCAP2_ASIMD)
#		define HWCAP2_ASIMD 0UL
#	endif
#	if !defined(HWCAP2_SHA512)
#		define HWCAP2_SHA512 0UL
#	endif
#	if !defined(HWCAP2_SHA3)
#		define HWCAP2_SHA3 0UL
#	endif
#	if !defined(HWCAP_SM3)
#		define HWCAP_SM3 (1 << 18)
#	endif
#	if !defined(HWCAP_SM4)
#		define HWCAP_SM4 (1 << 19)
#	endif

static bool cpuidex_is_armv7(void)
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_ARMv7) != 0U))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_ARMv7) != 0U ||
		(getauxval(AT_HWCAP) & HWCAP_NEON) != 0U)
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

static bool cpuidex_has_neon(void)
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_ASIMD) != 0U))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__arm__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_NEON) != 0U))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_ASIMD) != 0U)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_ASIMD) != 0U)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__arm__)
	if ((getauxval(AT_HWCAP) & HWCAP_NEON) != 0U)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	res = true;
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_INSTRUCTIONS_AVAILABLE) != 0U)
	{
		res = true;
	}
#endif

	return res;
}

static bool cpuidex_has_pmull(void)
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_PMULL) != 0U))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_PMULL) != 0U))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_PMULL) != 0U)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_PMULL) != 0U)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	res = true;
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0U)
	{
		res = true;
	}
#endif

	return res;
}

static bool cpuidex_has_aes(void)
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_AES) != 0U))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_AES) != 0U))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_AES) != 0U)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_AES) != 0U)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	res = true;
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0U)
	{
		res = true;
	}
#endif

	return res;
}

static bool cpuidex_has_sha256(void)
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA2) != 0U))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA2) != 0U))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA2) != 0U)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA2) != 0U)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	res = true;
#elif defined(_WIN32) && defined(_M_ARM64)
	if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0U)
	{
		res = true;
	}
#endif

	return res;
}

static bool cpuidex_has_sha512(void)
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA512) != 0U))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__)
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA512) != 0U))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA512) != 0U)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA512) != 0U)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	res = true;
#endif

	return res;
}

static bool cpuidex_has_sha3(void)
{
	bool res;

	res = false;

#if defined(__ANDROID__) && defined(__aarch64__) && 0U
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM64) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM64_FEATURE_SHA3) != 0U))
	{
		res = true;
	}
#elif defined(__ANDROID__) && defined(__aarch32__) && 0U
	if (((android_getCpuFamily() & ANDROID_CPU_FAMILY_ARM) != 0U) &&
		((android_getCpuFeatures() & ANDROID_CPU_ARM_FEATURE_SHA3) != 0U))
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch64__)
	if ((getauxval(AT_HWCAP) & HWCAP_SHA3) != 0U)
	{
		res = true;
	}
#elif defined(__linux__) && defined(__aarch32__)
	if ((getauxval(AT_HWCAP2) & HWCAP2_SHA3) != 0U)
	{
		res = true;
	}
#elif defined(__APPLE__) && defined(__aarch64__)
	res = true;
#endif

	return res;
}

static void cpuidex_arm_features(qsc_cpuidex_cpu_features* features)
{
	QSC_ASSERT(features != NULL);

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
#	define CPUID_EDX_RDTCSP 0x08000000UL
#	define CPUID_EBX_SHA2 0x20000000UL
#	define XCR0_SSE 0x00000002UL
#	define XCR0_AVX 0x00000004UL
#	define XCR0_OPMASK 0x00000020UL
#	define XCR0_ZMM_HI256 0x00000040UL
#	define XCR0_HI16_ZMM 0x00000080UL

/**
 * \brief Execute CPUID with an explicitly initialized subleaf.
 * \param info Output register array in EAX, EBX, ECX, EDX order.
 * \param infotype Basic or extended CPUID leaf.
 * \param subleaf Requested CPUID subleaf.
 */
static void cpuidex_cpu_info_ex(int32_t info[4U], const uint32_t infotype, const uint32_t subleaf)
{
	info[0U] = 0;
	info[1U] = 0;
	info[2U] = 0;
	info[3U] = 0;

#if defined(QSC_SYSTEM_COMPILER_MSC) || defined(QSC_SYSTEM_COMPILER_INTEL)
	__cpuidex(info, (int32_t)infotype, (int32_t)subleaf);
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_CLANG)
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;

	if (__get_cpuid_count(infotype, subleaf, &eax, &ebx, &ecx, &edx) != 0U)
	{
		info[0U] = (int32_t)eax;
		info[1U] = (int32_t)ebx;
		info[2U] = (int32_t)ecx;
		info[3U] = (int32_t)edx;
	}
#endif
}

/**
 * \brief Execute the base subleaf of a CPUID leaf.
 * \param info Output register array.
 * \param infotype CPUID leaf.
 */
static void cpuidex_cpu_info(int32_t info[4U], const uint32_t infotype)
{
	cpuidex_cpu_info_ex(info, infotype, 0U);
}

/**
 * \brief Read enabled x86 extended processor state only after checking OSXSAVE.
 * \return XCR0 enabled-state bitmap.
 */
static uint64_t cpuidex_xcr0(void)
{
	uint64_t res;

	res = 0U;
#if defined(QSC_SYSTEM_COMPILER_MSC) || defined(QSC_SYSTEM_COMPILER_INTEL)
	res = (uint64_t)_xgetbv(0U);
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_CLANG)
	uint32_t eax;
	uint32_t edx;
	__asm__ volatile ("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0U));
	res = ((uint64_t)edx << 32U) | (uint64_t)eax;
#endif
	return res;
}

static uint32_t cpuidex_cpu_count(void)
{
	uint32_t resu;

	resu = 1U;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	uint32_t resl;
	SYSTEM_INFO sysinfo;

	GetSystemInfo(&sysinfo);
	resl = (uint32_t)sysinfo.dwNumberOfProcessors;
#if defined(ALL_PROCESSOR_GROUPS)
	{
		DWORD online;

		online = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
		if (online != 0U)
		{
			resl = (uint32_t)online;
		}
	}
#endif

	if (resl > 1U)
	{
		resu = resl;
	}
#else
	long resl;

	resl = sysconf(_SC_NPROCESSORS_ONLN);

	if (resl > 1L)
	{
		resu = (uint32_t)resl;
	}
#endif

	return resu;
}

/**
 * \brief Extract a bounded bit field from a 32-bit unsigned word.
 * \param value Source word.
 * \param index First bit position.
 * \param length Bit count.
 * \return Extracted value, or zero for an invalid range.
 */
static uint32_t cpuidex_read_bits(uint32_t value, int32_t index, int32_t length)
{
	uint32_t res;

	res = 0U;
	if (index >= 0 && index < 32 && length > 0 && length <= (32 - index))
	{
		res = (value >> (uint32_t)index) & (UINT32_MAX >> (32U - (uint32_t)length));
	}

	return res;
}

static void cpuidex_vendor_name(qsc_cpuidex_cpu_features* features)
{
	QSC_ASSERT(features != NULL);

	int32_t info[4U] = { 0U };

	cpuidex_cpu_info(info, 0x00000000UL);
	qsc_memutils_clear(features->vendor, QSC_CPUIDEX_VENDOR_SIZE);
	qsc_intutils_le32to8((uint8_t*)&features->vendor[0U], (uint32_t)info[1U]);
	qsc_intutils_le32to8((uint8_t*)&features->vendor[4U], (uint32_t)info[3U]);
	qsc_intutils_le32to8((uint8_t*)&features->vendor[8U], (uint32_t)info[2U]);
}

static void cpuidex_bus_info(qsc_cpuidex_cpu_features* features)
{
	QSC_ASSERT(features != NULL);

	int32_t info[4U] = { 0U };
	cpuidex_cpu_info(info, 0x00000000UL);

	if ((uint32_t)info[0U] >= 0x00000016UL)
	{
		qsc_memutils_clear(info, sizeof(info));
		cpuidex_cpu_info(info, 0x00000016UL);
		features->freqbase = info[0U];
		features->freqmax = info[1U];
		features->freqref = info[2U];
	}
}

/**
 * \brief Inspect deterministic cache parameters and extended AMD cache leaves.
 * \param features Populated CPU capabilities structure.
 */
static void cpuidex_cpu_cache(qsc_cpuidex_cpu_features* features)
{
	int32_t info[4U];
	uint32_t maxbasic;
	uint32_t maxextended;
	uint32_t i;

	cpuidex_cpu_info(info, 0U);
	maxbasic = (uint32_t)info[0U];
	cpuidex_cpu_info(info, 0x80000000UL);
	maxextended = (uint32_t)info[0U];

	if (maxbasic >= 4U)
	{
		for (i = 0U; i < 16U; ++i)
		{
			uint32_t ctype;
			uint32_t clevel;
			uint64_t csize;
			uint32_t linesize;

			cpuidex_cpu_info_ex(info, 4U, i);
			ctype = (uint32_t)info[0U] & 0x1FU;
			clevel = ((uint32_t)info[0U] >> 5U) & 0x07U;
			if (ctype == 0U)
			{
				break;
			}

			linesize = ((uint32_t)info[1U] & 0xFFFU) + 1U;
			csize = (uint64_t)linesize * ((((uint32_t)info[1U] >> 12U) & 0x3FFU) + 1U);
			csize *= ((uint64_t)(uint32_t)info[2U] + 1ULL);
			csize *= (uint64_t)((((uint32_t)info[1U] >> 22U) & 0x3FFU) + 1U);

			if (clevel == 1U && ctype == 1U)
			{
				features->l1cache = csize <= UINT32_MAX ? (uint32_t)csize : 0U;
				features->l1cacheline = linesize;
				features->cacheline = linesize;
			}
			else if (clevel == 2U && csize <= UINT32_MAX)
			{
				features->l2cache = (uint32_t)csize;
				features->l2associative = (((uint32_t)info[1U] >> 22U) & 0x3FFU) + 1U;
			}
		}
	}

	if (maxextended >= 0x80000005UL && features->l1cache == 0U)
	{
		cpuidex_cpu_info(info, 0x80000005UL);
		features->l1cacheline = cpuidex_read_bits((uint32_t)info[2U], 0, 8);
		features->l1cache = cpuidex_read_bits((uint32_t)info[2U], 24, 8) * 1024U;
	}

	if (maxextended >= 0x80000006UL && features->l2cache == 0U)
	{
		cpuidex_cpu_info(info, 0x80000006UL);
		features->l2cache = cpuidex_read_bits((uint32_t)info[2U], 16, 16) * 1024U;
		if (features->cacheline == 0U)
		{
			features->cacheline = cpuidex_read_bits((uint32_t)info[2U], 0, 8);
		}
	}
}

/**
 * \brief Determine processor capabilities, OS-enabled vector state, and topology.
 * \param features Populated CPU capabilities structure.
 */
static void cpuidex_cpu_topology(qsc_cpuidex_cpu_features* features)
{
	int32_t info[4U];
	uint32_t basicmax;
	uint32_t extendedmax;
	uint32_t tpc;
	uint32_t lpp;
	uint32_t cpp;
	uint64_t xcr0;

	features->cores = cpuidex_cpu_count();
	features->cpus = features->cores;
	features->hyperthread = false;
	features->avx = false;
	features->avx2 = false;
	features->avx512f = false;
	features->adx = false;
	features->sha256 = false;
	features->rdtcsp = false;
	xcr0 = 0U;
	tpc = 1U;
	cpuidex_cpu_info(info, 0U);
	basicmax = (uint32_t)info[0U];
	cpuidex_cpu_info(info, 0x80000000UL);
	extendedmax = (uint32_t)info[0U];

	if (basicmax >= 1U)
	{
		cpuidex_cpu_info(info, 1U);
		features->pcmul = ((uint32_t)info[2U] & CPUID_ECX_PCLMUL) != 0U;
		features->aesni = ((uint32_t)info[2U] & CPUID_ECX_AESNI) != 0U;
		features->rdrand = ((uint32_t)info[2U] & CPUID_ECX_RDRAND) != 0U;
		features->cacheline = cpuidex_read_bits((uint32_t)info[1U], 8, 8) * 8U;
		lpp = cpuidex_read_bits((uint32_t)info[1U], 16, 8);
		if (((uint32_t)info[2U] & (CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE)) ==
			(CPUID_ECX_XSAVE | CPUID_ECX_OSXSAVE))
		{
			xcr0 = cpuidex_xcr0();
		}
		features->avx = (((uint32_t)info[2U] & CPUID_ECX_AVX) != 0U) &&
			((xcr0 & (XCR0_SSE | XCR0_AVX)) == (XCR0_SSE | XCR0_AVX));
		features->hyperthread = (((uint32_t)info[3U] >> 28U) & 1U) != 0U;
	}
	else
	{
		lpp = 1U;
	}

	if (extendedmax >= 0x80000001UL)
	{
		cpuidex_cpu_info(info, 0x80000001UL);
		features->rdtcsp = (((uint32_t)info[3U] & CPUID_EDX_RDTCSP) != 0U);
	}

	if (basicmax >= 7U)
	{
		cpuidex_cpu_info_ex(info, 7U, 0U);
		features->adx = ((uint32_t)info[1U] & CPUID_EBX_ADX) != 0U;
		features->sha256 = ((uint32_t)info[1U] & CPUID_EBX_SHA2) != 0U;
		features->avx2 = features->avx && (((uint32_t)info[1U] & CPUID_EBX_AVX2) != 0U);
		features->avx512f = features->avx && (((uint32_t)info[1U] & CPUID_EBX_AVX512F) != 0U) &&
			((xcr0 & (XCR0_SSE | XCR0_AVX | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM)) ==
			(XCR0_SSE | XCR0_AVX | XCR0_OPMASK | XCR0_ZMM_HI256 | XCR0_HI16_ZMM));
	}

	/* Determine physical cores from topology where the package count is available. */
	
	if (features->hyperthread == true && basicmax >= 0xBU)
	{
		cpuidex_cpu_info_ex(info, 0xBU, 0U);
		if ((((uint32_t)info[2U] >> 8U) & 0xFFU) == 1U)
		{
			tpc = (uint32_t)info[1U] & 0xFFFFU;
		}
	}

	if (tpc <= 1U && features->hyperthread == true)
	{
		if (basicmax >= 4U)
		{
			cpuidex_cpu_info_ex(info, 4U, 0U);
			cpp = (((uint32_t)info[0U] >> 26U) & 0x3FU) + 1U;
			if (cpp > 0U && lpp >= cpp)
			{
				tpc = lpp / cpp;
			}
		}
		else if (extendedmax >= 0x80000008UL)
		{
			cpuidex_cpu_info(info, 0x80000008UL);
			cpp = ((uint32_t)info[2U] & 0xFFU) + 1U;
			if (cpp > 0U && lpp >= cpp)
			{
				tpc = lpp / cpp;
			}
		}
	}

	if (tpc > 1U && features->cores > 0U)
	{
		features->cpus = (features->cores + tpc - 1U) / tpc;
	}
	features->hyperthread = (tpc > 1U);
}

static void cpuidex_cpu_type(qsc_cpuidex_cpu_features* features)
{
	QSC_ASSERT(features != NULL);

	char tmpn[QSC_CPUIDEX_VENDOR_SIZE + 1U] = { 0U };

	cpuidex_vendor_name(features);
	qsc_memutils_copy(tmpn, features->vendor, QSC_CPUIDEX_VENDOR_SIZE);
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

/**
 * \brief Read the legacy CPU serial number only when CPUID explicitly advertises it.
 * \param features Feature structure receiving the twelve-byte serial, or all zeros.
 */
static void cpuidex_serial_number(qsc_cpuidex_cpu_features* features)
{
	int32_t info[4U];

	qsc_memutils_clear(features->serial, QSC_CPUIDEX_SERIAL_SIZE);
	cpuidex_cpu_info(info, 1U);
	if (((uint32_t)info[3U] & 0x00040000UL) != 0U)
	{
		cpuidex_cpu_info(info, 3U);
		qsc_intutils_le32to8((uint8_t*)&features->serial[0U], (uint32_t)info[1U]);
		qsc_intutils_le32to8((uint8_t*)&features->serial[4U], (uint32_t)info[3U]);
		qsc_intutils_le32to8((uint8_t*)&features->serial[8U], (uint32_t)info[2U]);
	}
}

#endif

#if defined(QSC_SYSTEM_OS_BSD)

static void cpuidex_bsd_topology(qsc_cpuidex_cpu_features* features)
{
	QSC_ASSERT(features != NULL);

	size_t plen;
	uint64_t pval;

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.physicalcpu", &pval, &plen, NULL, 0U) == 0U)
	{
		features->cpus = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.logicalcpu", &pval, &plen, NULL, 0U) == 0U)
	{
		features->cores = pval;
		features->hyperthread = (pval > features->cpus);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0U) == 0U)
	{
		features->cacheline = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency", &pval, &plen, NULL, 0U) == 0U)
	{
		features->freqbase = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_max", &pval, &plen, NULL, 0U) == 0U)
	{
		features->freqmax = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cpufrequency_min", &pval, &plen, NULL, 0U) == 0U)
	{
		features->freqref = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l1dcachesize", &pval, &plen, NULL, 0U) == 0U)
	{
		features->l1cache = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.cachelinesize", &pval, &plen, NULL, 0U) == 0U)
	{
		features->cacheline = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.l2cachesize", &pval, &plen, NULL, 0U) == 0U)
	{
		features->l2cache = pval;
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.adx", &pval, &plen, NULL, 0U) == 0U)
	{
		features->adx = (pval == 1U);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.aes", &pval, &plen, NULL, 0U) == 0U)
	{
		features->aesni = (pval == 1U);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx1_0", &pval, &plen, NULL, 0U) == 0U)
	{
		features->avx = (pval == 1U);
	}


	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx2_0", &pval, &plen, NULL, 0U) == 0U)
	{
		features->avx2 = (pval == 1U);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.avx512f", &pval, &plen, NULL, 0U) == 0U)
	{
		features->avx512f = (pval == 1U);
	}

	pval = 0U;
	plen = sizeof(pval);
	if (sysctlbyname("hw.optional.pclmulqdq", &pval, &plen, NULL, 0U) == 0)
	{
		features->pcmul = (pval == 1U);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdrand", &pval, &plen, NULL, 0U) == 0U)
	{
		features->rdrand = (pval == 1U);
	}

	pval = 0U;
	plen = sizeof(pval);

	if (sysctlbyname("hw.optional.rdtscp", &pval, &plen, NULL, 0U) == 0)
	{
		features->rdtcsp = (pval == 1U);
	}

	char vend[1024U] = { 0U };
	plen = sizeof(vend);

	if (sysctlbyname("machdep.cpu.brand_string", vend, &plen, NULL, 0U) == 0)
	{
		qsc_memutils_copy(features->vendor, vend, QSC_CPUIDEX_VENDOR_SIZE - 1U);
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
	QSC_ASSERT(features != NULL);

#	if defined(QSC_SYSTEM_ARCH_IX86)

	cpuidex_cpu_type(features);

	{
		cpuidex_bus_info(features);
		cpuidex_cpu_cache(features);
		cpuidex_cpu_topology(features);
		cpuidex_serial_number(features);
	}

#	else

	int32_t res;

	res = sysconf(_SC_NPROCESSORS_CONF);

	if (res > 0U)
	{
		features->cpus = (uint32_t)res;
	}

	res = sysconf(_SC_NPROCESSORS_ONLN);

	if (res > 0U)
	{
		features->cores = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL1_ICACHE_SIZE);

	if (res > 0U)
	{
		features->l1cache = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL1_ICACHE_LINESIZE);

	if (res > 0U)
	{
		features->l1cacheline = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL2_CACHE_SIZE);

	if (res > 0U)
	{
		features->l2cache = (uint32_t)res;
	}

	res = sysconf(_SC_LEVEL2_CACHE_ASSOC);

	if (res > 0U)
	{
		features->l2associative = (uint32_t)res;
	}


	res = sysconf(_SC_LEVEL2_CACHE_LINESIZE);

	if (res > 0U)
	{
		features->cacheline = (uint32_t)res;
	}
#	endif
}

#elif defined(QSC_SYSTEM_OS_WINDOWS)

static void cpuidex_windows_topology(qsc_cpuidex_cpu_features* features)
{
	QSC_ASSERT(features != NULL);

#	if defined(QSC_SYSTEM_ARCH_IX86)
	cpuidex_cpu_type(features);

	{
		cpuidex_bus_info(features);
		cpuidex_cpu_cache(features);
		cpuidex_cpu_topology(features);
		cpuidex_serial_number(features);
	}
#	else

	SYSTEM_INFO sinfo;
	GetSystemInfo(&sinfo);
	features->cpus = (uint32_t)sinfo.dwNumberOfProcessors;
#if defined(ALL_PROCESSOR_GROUPS)
	{
		DWORD online;

		online = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
		if (online != 0U)
		{
			features->cpus = (uint32_t)online;
		}
	}
#endif
	features->cores = features->cpus;

#	endif
}

#endif

bool qsc_cpuidex_features_set(qsc_cpuidex_cpu_features* features)
{
	QSC_ASSERT(features != NULL);

	bool res;

	res = false;

	if (features != NULL)
	{
		features->cputype = qsc_cpuid_unknown;
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
		features->cacheline = 0U;
		features->cores = 0U;
		features->cpus = 1U;
		features->freqbase = 0U;
		features->freqmax = 0U;
		features->freqref = 0U;
		features->l1cache = 0U;
		features->l1cacheline = 0U;
		features->l2associative = 4U;
		features->l2cache = 0U;
		qsc_memutils_clear(features->serial, QSC_CPUIDEX_SERIAL_SIZE);
		qsc_memutils_clear(features->vendor, QSC_CPUIDEX_VENDOR_SIZE);

#if defined(QSC_SYSTEM_OS_POSIX)
#	if defined(QSC_SYSTEM_OS_BSD)
		cpuidex_bsd_topology(features);
		res = true;
#	else
		cpuidex_posix_topology(features);
		res = true;
#	endif
#elif defined(QSC_SYSTEM_OS_WINDOWS)
		cpuidex_windows_topology(features);
		res = true;
#else
		res = false;
#endif

#if defined(QSC_SYSTEM_ARCH_ARM)
		cpuidex_arm_features(features);
#endif
	}

	return res;
}

/* Cached CPU capabilities are a process-lifetime snapshot. Live topology and
 * virtual CPU features can change; use the noncached API when that matters. */
static qsc_cpuidex_cpu_features cpuidex_cached_state;
static bool cpuidex_cached_ready = false;

/** \brief Initialize the immutable process-lifetime feature snapshot once. */
static void cpuidex_cached_initialize(void)
{
	cpuidex_cached_ready = qsc_cpuidex_features_set(&cpuidex_cached_state);
}

#if defined(QSC_SYSTEM_OS_WINDOWS)
static INIT_ONCE cpuidex_cached_once = INIT_ONCE_STATIC_INIT;

/** \brief Windows one-time initialization callback. \param once Once control. \param parameter Unused. \param context Unused. \return TRUE. */
static BOOL CALLBACK cpuidex_cached_windows_once(PINIT_ONCE once, PVOID parameter, PVOID* context)
{
	(void)once;
	(void)parameter;
	(void)context;
	cpuidex_cached_initialize();
	return TRUE;
}
#elif defined(QSC_SYSTEM_OS_POSIX)
static pthread_once_t cpuidex_cached_once = PTHREAD_ONCE_INIT;
#endif

bool qsc_cpuidex_features_set_cached(qsc_cpuidex_cpu_features* features)
{
	bool res;

	res = false;
	if (features != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (InitOnceExecuteOnce(&cpuidex_cached_once, cpuidex_cached_windows_once, NULL, NULL) != 0)
		{
			res = cpuidex_cached_ready;
		}
#elif defined(QSC_SYSTEM_OS_POSIX)
		if (pthread_once(&cpuidex_cached_once, cpuidex_cached_initialize) == 0)
		{
			res = cpuidex_cached_ready;
		}
#else
		res = qsc_cpuidex_features_set(features);
#endif
#if defined(QSC_SYSTEM_OS_WINDOWS) || defined(QSC_SYSTEM_OS_POSIX)
		if (res == true)
		{
			qsc_memutils_copy(features, &cpuidex_cached_state, sizeof(qsc_cpuidex_cpu_features));
		}
#endif
	}
	return res;
}

void qsc_cpuidex_print_stats(void)
{
	qsc_cpuidex_cpu_features cfeat;
	const char sf[] = "false";
	const char st[] = "true";
	char vstr[16U] = { 0U };
	bool hfeat;

	hfeat = qsc_cpuidex_features_set(&cfeat);

	if (hfeat)
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
#endif
