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

#ifndef QSC_INTRINSICS_H
#define QSC_INTRINSICS_H

/* \cond NO_DOCUMENT */

/*!
 * \file intrinsics.h
 * \brief SIMD and platform intrinsic header includes.
 *
 * \details
 * Includes the appropriate SIMD intrinsic headers for the detected compiler
 * and target architecture, as identified by the capability macros defined in
 * qsccommon.h.
 *
 * This file must never include x86 SIMD headers when the target architecture
 * is ARM or ARM64. Apple Clang on Apple Silicon will hard-fail if x86
 * intrinsic umbrellas such as immintrin.h or x86intrin.h are included in an
 * arm64 translation unit.
 */

#include "qsccommon.h"

/*
 * Architecture families.
 *
 * QSC_SYSTEM_ARCH_IX86 is assumed to mean the x86 family used elsewhere in the
 * code base. If qsccommon.h distinguishes 32-bit and 64-bit x86 separately,
 * add the x64 macro to QSC_X86_FAMILY below as needed.
 */
#if defined(QSC_SYSTEM_ARCH_IX86)
#	define QSC_X86_FAMILY
#endif

#if defined(QSC_SYSTEM_ARCH_ARM) || defined(QSC_SYSTEM_ARCH_ARM64)
#	define QSC_ARM_FAMILY
#endif

#if defined(QSC_SYSTEM_ARCH_PPC)
#	define QSC_PPC_FAMILY
#endif

/*
 * MSVC
 *
 * <intrin.h> is the MSVC umbrella for x86/x64 intrinsics.
 * <arm_neon.h> provides ARM/ARM64 NEON intrinsics.
 */
#if defined(QSC_SYSTEM_COMPILER_MSC)

#	if defined(QSC_X86_FAMILY) && (defined(QSC_SYSTEM_AVX_INTRINSICS) || defined(QSC_SHA2_SHANI_ENABLED))
#		include <intrin.h>
#	endif

#	if defined(QSC_ARM_FAMILY) && defined(QSC_SYSTEM_HAS_ARM_NEON)
#		include <arm_neon.h>
#	endif

/*
 * Intel C/C++
 *
 * ICC/ICX on x86/x64 uses immintrin.h.
 * Do not include x86 intrinsic headers for non-x86 targets.
 */
#elif defined(QSC_SYSTEM_COMPILER_INTEL)

#	if defined(QSC_X86_FAMILY) && (defined(QSC_SYSTEM_AVX_INTRINSICS) || defined(QSC_SHA2_SHANI_ENABLED))
#		include <immintrin.h>
#	endif

#	if defined(QSC_ARM_FAMILY) && defined(QSC_SYSTEM_HAS_ARM_NEON)
#		include <arm_neon.h>
#	endif

/*
 * GCC / Clang / GCC-compatible front-ends
 *
 * Use x86intrin.h only for x86-family targets.
 * Use ARM/other vector headers only for those targets.
 */
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_CLANG)

#	if defined(QSC_X86_FAMILY) && (defined(QSC_SYSTEM_AVX_INTRINSICS) || defined(QSC_SHA2_SHANI_ENABLED))
#		include <x86intrin.h>
#	endif

#	if defined(QSC_ARM_FAMILY) && defined(QSC_SYSTEM_HAS_ARM_NEON)
#		include <arm_neon.h>
#	endif

#	if defined(QSC_ARM_FAMILY) && defined(QSC_SYSTEM_HAS_ARM_SVE)
#		include <arm_sve.h>
#	endif

#	if defined(QSC_SYSTEM_HAS_RVV)
#		include <riscv_vector.h>
#	endif

#	if defined(QSC_PPC_FAMILY)
#		include <altivec.h>
#		undef vector
#		undef pixel
#		undef bool
#	endif

/*
 * Arm Compiler
 */
#elif defined(QSC_SYSTEM_COMPILER_ARM) && defined(QSC_SYSTEM_HAS_ARM_NEON)

#	if defined(QSC_ARM_FAMILY)
#		include <arm_neon.h>
#	endif

/*
 * IBM XL C / XL C++
 */
#elif defined(QSC_SYSTEM_COMPILER_IBM)

#	if defined(QSC_PPC_FAMILY)
#		include <altivec.h>
#		undef vector
#		undef pixel
#		undef bool
#	endif

#endif

/*
 * Internal helper cleanup.
 */
#if defined(QSC_X86_FAMILY)
#	undef QSC_X86_FAMILY
#endif

#if defined(QSC_ARM_FAMILY)
#	undef QSC_ARM_FAMILY
#endif

#if defined(QSC_PPC_FAMILY)
#	undef QSC_PPC_FAMILY
#endif

/* \endcond */

#endif
