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
#include "benchmark_extended.h"
#include "testutils.h"
#include "qsccommon.h"
#include "cpuidex.h"
#include "memutils.h"
#include <stdio.h>

#if defined(_M_IX86) || defined(_M_X64) || defined(__i386__) || defined(__x86_64__)
/*! \def QSCTEST_PROFILE_X86
 * \brief Enables the CPUID and XGETBV feature assessment for x86 processors.
 */
#define QSCTEST_PROFILE_X86
#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif
#endif

/*! \struct qsctest_benchmark_cpu_extensions
 * \brief Usable x86 features after checking OS-maintained vector register state.
 * \details Zero-initialized on unsupported architectures or failed discovery.
 */
typedef struct
{
	bool sse2; /*!< OS-usable SSE2. */
	bool sse41; /*!< OS-usable SSE4.1. */
	bool sse42; /*!< OS-usable SSE4.2. */
	bool avx; /*!< OS-usable AVX. */
	bool avx2; /*!< OS-usable AVX2. */
	bool avx512f; /*!< OS-usable AVX-512 foundation. */
	bool avx512bw; /*!< OS-usable AVX-512 byte/word instructions. */
	bool avx512dq; /*!< OS-usable AVX-512 double/quadword instructions. */
	bool avx512vl; /*!< OS-usable AVX-512 vector length instructions. */
	bool avx512ifma; /*!< OS-usable AVX-512 integer FMA. */
	bool aesni; /*!< AES-NI instruction support. */
	bool pclmul; /*!< PCLMULQDQ instruction support. */
	bool vaes; /*!< VAES instruction support with YMM state enabled. */
	bool vaes512; /*!< VAES usable with AVX-512 vector state. */
	bool vpclmul; /*!< VPCLMULQDQ support with YMM state enabled. */
	bool vpclmul512; /*!< VPCLMULQDQ usable with AVX-512 vector state. */
	bool gfni; /*!< Galois field instruction support. */
	bool bmi1; /*!< BMI1 support. */
	bool bmi2; /*!< BMI2 support. */
	bool adx; /*!< ADX support. */
	bool sha; /*!< SHA-NI instructions. */
	bool rdrand; /*!< RDRAND support. */
	bool rdseed; /*!< RDSEED support. */
} qsctest_benchmark_cpu_extensions;

#if defined(QSCTEST_PROFILE_X86)
/*! \brief Execute an x86 CPUID leaf and subleaf.
 * \param leaf: CPUID leaf.
 * \param subleaf: CPUID subleaf.
 * \param regs: Four 32-bit output registers, owned by caller.
 * \return True when the leaf was available.
 */
static bool qsctest_profile_cpuid(uint32_t leaf, uint32_t subleaf, uint32_t regs[4U])
{
	bool result;

	result = false;
	qsc_memutils_clear(regs, 4U * sizeof(uint32_t));
#if defined(_MSC_VER)
	{
		int vals[4U];
		__cpuidex(vals, (int)leaf, (int)subleaf);
		regs[0U] = (uint32_t)vals[0U];
		regs[1U] = (uint32_t)vals[1U];
		regs[2U] = (uint32_t)vals[2U];
		regs[3U] = (uint32_t)vals[3U];
		result = true;
	}
#else
	{
		unsigned int eax;
		unsigned int ebx;
		unsigned int ecx;
		unsigned int edx;

		if (__get_cpuid_count(leaf, subleaf, &eax, &ebx, &ecx, &edx) != 0U)
		{
			regs[0U] = eax;
			regs[1U] = ebx;
			regs[2U] = ecx;
			regs[3U] = edx;
			result = true;
		}
	}
#endif
	return result;
}

/*! \brief Read OS-enabled extended registers only when OSXSAVE is supported.
 * \return XCR0 bitmap; caller must verify CPUID XSAVE/OSXSAVE first.
 */
static uint64_t qsctest_profile_xgetbv(void)
{
	uint64_t value;

	value = 0U;
#if defined(_MSC_VER)
	value = (uint64_t)_xgetbv(0U);
#else
	{
		uint32_t eax;
		uint32_t edx;
		__asm__ volatile("xgetbv" : "=a" (eax), "=d" (edx) : "c" (0U));
		value = ((uint64_t)edx << 32U) | (uint64_t)eax;
	}
#endif
	return value;
}
#endif

/*! \brief Collect usable processor extensions without executing unsupported instructions.
 * \param features: Caller-owned zero-initialized output structure.
 * \return True when the current architecture's feature query succeeded.
 * \details X86 vectors additionally require OS-enabled register state.
 */
static bool qsctest_profile_detect(qsctest_benchmark_cpu_extensions* features)
{
	bool result;

	result = false;
	qsc_memutils_clear(features, sizeof(*features));
#if defined(QSCTEST_PROFILE_X86)
	{
		uint32_t r0[4U];
		uint32_t r1[4U];
		uint32_t r7[4U];
		uint64_t xcr0;
		bool ymm;
		bool zmm;

		if (qsctest_profile_cpuid(0U, 0U, r0) == true && r0[0U] >= 1U &&
			qsctest_profile_cpuid(1U, 0U, r1) == true)
		{
			xcr0 = 0U;
			if ((r1[2U] & (1UL << 26U)) != 0U && (r1[2U] & (1UL << 27U)) != 0U)
			{
				xcr0 = qsctest_profile_xgetbv();
			}

			ymm = (xcr0 & UINT64_C(0x6)) == UINT64_C(0x6);
			zmm = ymm && (xcr0 & UINT64_C(0xE0)) == UINT64_C(0xE0);
			features->sse2 = (r1[3U] & (1UL << 26U)) != 0U;
			features->sse41 = (r1[2U] & (1UL << 19U)) != 0U;
			features->sse42 = (r1[2U] & (1UL << 20U)) != 0U;
			features->aesni = (r1[2U] & (1UL << 25U)) != 0U;
			features->pclmul = (r1[2U] & (1UL << 1U)) != 0U;
			features->rdrand = (r1[2U] & (1UL << 30U)) != 0U;
			features->avx = ymm && (r1[2U] & (1UL << 28U)) != 0U;
			result = true;

			if (r0[0U] >= 7U && qsctest_profile_cpuid(7U, 0U, r7) == true)
			{
				features->avx2 = features->avx && (r7[1U] & (1UL << 5U)) != 0U;
				features->avx512f = zmm && (r7[1U] & (1UL << 16U)) != 0U;
				features->avx512bw = features->avx512f && (r7[1U] & (1UL << 30U)) != 0U;
				features->avx512dq = features->avx512f && (r7[1U] & (1UL << 17U)) != 0U;
				features->avx512vl = features->avx512f && (r7[1U] & (1UL << 31U)) != 0U;
				features->avx512ifma = features->avx512f && (r7[1U] & (1UL << 21U)) != 0U;
				features->vaes = features->avx && (r7[2U] & (1UL << 9U)) != 0U;
				features->vpclmul = features->avx && (r7[2U] & (1UL << 10U)) != 0U;
				features->vaes512 = features->vaes && features->avx512f;
				features->vpclmul512 = features->vpclmul && features->avx512f;
				features->gfni = (r7[2U] & (1UL << 8U)) != 0U;
				features->bmi1 = (r7[1U] & (1UL << 3U)) != 0U;
				features->bmi2 = (r7[1U] & (1UL << 8U)) != 0U;
				features->adx = (r7[1U] & (1UL << 19U)) != 0U;
				features->sha = (r7[1U] & (1UL << 29U)) != 0U;
				features->rdseed = (r7[1U] & (1UL << 18U)) != 0U;
			}
		}
	}
#endif
	return result;
}

#if defined(QSCTEST_PROFILE_X86)
/*! \brief Retrieve the 48-character processor brand string where CPUID supports it.
 * \param brand: Caller-owned 49-byte output including terminating NUL.
 * \return True when a brand string was retrieved.
 */
static bool qsctest_profile_brand(char brand[49U])
{
	uint32_t ext[4U];
	uint32_t words[4U];
	uint32_t leaf;
	bool result;

	result = false;
	qsc_memutils_clear(brand, 49U);
	if (qsctest_profile_cpuid(UINT32_C(0x80000000), 0U, ext) == true && ext[0U] >= UINT32_C(0x80000004))
	{
		for (leaf = 0U; leaf < 3U; ++leaf)
		{
			if (qsctest_profile_cpuid(UINT32_C(0x80000002) + leaf, 0U, words) == true)
			{
				qsc_memutils_copy(&brand[16U * leaf], words, sizeof(words));
			}
		}
		result = true;
	}

	return result;
}
#endif

/*! \brief Print a single capability as usable/not usable and compile-enabled/unknown.
 * \param label: Feature name, borrowed immutable string.
 * \param available: Hardware and OS feature availability.
 * \param compiled: Build state, Y or N or ? if library flags cannot be inferred.
 */
static void qsctest_profile_row(const char* label, bool available, const char* compiled)
{
	char line[128U];

	(void)snprintf(line, sizeof(line), "  %-17s | %-11s | %s", label, available == true ? "YES" : "NO", compiled);
	qsctest_print_line(line);
}

/*! \brief Print CPU and the QSCTest translation-unit feature profile.
 * \details The local macro profile is not proof of the linked QSC binary configuration.
 */
void qsctest_benchmark_profile_run(void)
{
	qsctest_benchmark_cpu_extensions f;
	qsc_cpuidex_cpu_features cpu;
	char line[192U];
#if defined(QSCTEST_PROFILE_X86)
	char brand[49U];
#endif
	const char* simd;
	const char* advice;
	const char* build_avx;
	const char* build_avx2;
	const char* build_avx512;
	const char* build_aes;
	const char* build_pclmul;
	const char* build_vaes;
	const char* build_vaes512;
	const char* build_sse41;
	const char* build_sse42;
	bool cpu_ok;
	bool has_cpuid;

	cpu_ok = qsctest_profile_detect(&f);
	has_cpuid = false;
	qsc_memutils_clear(&cpu, sizeof(cpu));
#if defined(QSC_HAS_CPUID) || defined(QSC_SYSTEM_ARCH_ARM)
	has_cpuid = qsc_cpuidex_features_set(&cpu);
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
	build_avx512 = "YES";
#else
	build_avx512 = "NO";
#endif
#if defined(QSC_SYSTEM_HAS_AVX2)
	build_avx2 = "YES";
#else
	build_avx2 = "NO";
#endif
#if defined(QSC_SYSTEM_HAS_AVX)
	build_avx = "YES";
#else
	build_avx = "NO";
#endif
#if defined(QSC_SYSTEM_AESNI_ENABLED)
	build_aes = "YES";
#else
	build_aes = "NO";
#endif
#if defined(QSC_SYSTEM_HAS_PCLMUL)
	build_pclmul = "YES";
#else
	build_pclmul = "NO";
#endif
#if defined(QSC_AES_HAS_VAES256)
	build_vaes = "YES";
#else
	build_vaes = "?";
#endif
#if defined(QSC_SYSTEM_HAS_VAES512)
	build_vaes512 = "YES";
#else
	build_vaes512 = "?";
#endif
#if defined(QSC_SYSTEM_HAS_SSE41)
	build_sse41 = "YES";
#else
	build_sse41 = "NO";
#endif
#if defined(QSC_SYSTEM_HAS_SSE42)
	build_sse42 = "YES";
#else
	build_sse42 = "NO";
#endif

	simd = "Scalar";
#if defined(QSC_SYSTEM_HAS_AVX512)
	simd = "AVX-512";
#elif defined(QSC_SYSTEM_HAS_AVX2)
	simd = "AVX2";
#elif defined(QSC_SYSTEM_HAS_AVX)
	simd = "AVX";
#elif defined(QSC_SYSTEM_HAS_ARM_NEON)
	simd = "ARM NEON";
#endif

	qsctest_print_section("07.00", "CPU / OS / COMPILATION PROFILE");
	(void)snprintf(line, sizeof(line), "  Build SIMD           : %s (QSCTest compilation unit)", simd);
	qsctest_print_line(line);
#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsctest_print_line("  Operating system     : Windows");
#elif defined(QSC_SYSTEM_OS_LINUX)
	qsctest_print_line("  Operating system     : Linux");
#elif defined(QSC_SYSTEM_OS_MAC)
	qsctest_print_line("  Operating system     : macOS");
#elif defined(QSC_SYSTEM_OS_BSD)
	qsctest_print_line("  Operating system     : BSD");
#else
	qsctest_print_line("  Operating system     : Unknown");
#endif
#if defined(_MSC_VER)
	(void)snprintf(line, sizeof(line), "  Compiler             : MSVC-compatible %u", (unsigned int)_MSC_VER);
#elif defined(__clang__)
	(void)snprintf(line, sizeof(line), "  Compiler             : Clang %u.%u", (unsigned int)__clang_major__, (unsigned int)__clang_minor__);
#elif defined(__GNUC__)
	(void)snprintf(line, sizeof(line), "  Compiler             : GCC %u.%u", (unsigned int)__GNUC__, (unsigned int)__GNUC_MINOR__);
#else
	(void)snprintf(line, sizeof(line), "  Compiler             : Unknown");
#endif
	qsctest_print_line(line);
#if defined(QSCTEST_PROFILE_X86)
	if (qsctest_profile_brand(brand) == true)
	{
		(void)snprintf(line, sizeof(line), "  Processor            : %.48s", brand);
		qsctest_print_line(line);
	}
#endif
#if defined(_DEBUG) || defined(QSC_DEBUG_MODE)
	qsctest_print_line("  Build configuration  : DEBUG (not suitable for comparative benchmarks)");
#else
	qsctest_print_line("  Build configuration  : non-Debug (confirm compiler optimization flags)");
#endif
	if (has_cpuid == true)
	{
		(void)snprintf(line, sizeof(line), "  CPU vendor           : %.12s", cpu.vendor);
		qsctest_print_line(line);
		(void)snprintf(line, sizeof(line), "  Logical processors   : %u", (unsigned int)cpu.cpus);
		qsctest_print_line(line);
	}

	qsctest_print_line("  Feature            | CPU + OS    | QSCTest compile");
	qsctest_print_line("  -------------------+-------------+----------------");
	if (cpu_ok == true)
	{
		qsctest_profile_row("SSE2", f.sse2, "compiler target");
		qsctest_profile_row("SSE4.1", f.sse41, build_sse41);
		qsctest_profile_row("SSE4.2", f.sse42, build_sse42);
		qsctest_profile_row("AVX", f.avx, build_avx);
		qsctest_profile_row("AVX2", f.avx2, build_avx2);
		qsctest_profile_row("AVX-512F", f.avx512f, build_avx512);
		qsctest_profile_row("AVX-512BW/DQ/VL", f.avx512bw && f.avx512dq && f.avx512vl, "target flags");
		qsctest_profile_row("AVX-512IFMA", f.avx512ifma, "target flags");
		qsctest_profile_row("AES-NI", f.aesni, build_aes);
		qsctest_profile_row("PCLMULQDQ", f.pclmul, build_pclmul);
		qsctest_profile_row("VAES-256", f.vaes, build_vaes);
		qsctest_profile_row("VAES-512", f.vaes512, build_vaes512);
		qsctest_profile_row("VPCLMUL-256", f.vpclmul, "?");
		qsctest_profile_row("VPCLMUL-512", f.vpclmul512, "?");
		qsctest_profile_row("GFNI", f.gfni, "?");
		qsctest_profile_row("BMI1 / BMI2", f.bmi1 && f.bmi2, "?");
		qsctest_profile_row("ADX", f.adx, "?");
		qsctest_profile_row("SHA-NI", f.sha, "?");
		qsctest_profile_row("RDRAND", f.rdrand, "?");
		qsctest_profile_row("RDSEED", f.rdseed, "?");
	}
	else if (has_cpuid == true)
	{
		qsctest_profile_row("ARM NEON", cpu.neon, "target flags");
		qsctest_profile_row("ARM AES", cpu.aesni, build_aes);
		qsctest_profile_row("ARM PMULL", cpu.pcmul, build_pclmul);
		qsctest_profile_row("ARM SHA-256", cpu.sha256, "target flags");
		qsctest_profile_row("ARM SHA-512", cpu.sha512, "target flags");
		qsctest_profile_row("ARM SHA-3", cpu.sha3, "target flags");
	}
	else
	{
		qsctest_print_line("  [WARN] Runtime CPU feature detection is unavailable.");
	}

	advice = "Scalar fallback / no higher SIMD profile detected";
	if (cpu_ok == true)
	{
		if (f.avx512f == true && f.avx512bw == true && f.avx512dq == true && f.avx512vl == true)
		{
			advice = "Compare AVX-512 vs AVX2; include VAES/VPCLMUL where supported";
		}
		else if (f.avx2 == true)
		{
			if (f.vaes == true && f.vpclmul == true)
			{
				advice = "Benchmark AVX2 + VAES-256 + VPCLMUL + AES-NI";
			}
			else
			{
				advice = "Benchmark AVX2 + AES-NI / PCLMUL where implemented";
			}
		}
		else if (f.avx == true)
		{
			advice = "Benchmark AVX with supported AES-NI / PCLMUL paths";
		}
	}
	else if (has_cpuid == true && cpu.neon == true)
	{
		advice = "Benchmark ARM NEON and implemented crypto extensions";
	}
	(void)snprintf(line, sizeof(line), "  Recommended          : %s", advice);
	qsctest_print_line(line);
	qsctest_print_line("  [INFO] Build flags above describe QSCTest, NOT necessarily the linked QSC library.");
	qsctest_print_line("  [INFO] Compile-selected KEM/signature parameter sets require separate builds.");
	qsctest_print_line("  [INFO] Hardware maximum is not necessarily the fastest path for each primitive.");
	qsctest_print_line("");
}
