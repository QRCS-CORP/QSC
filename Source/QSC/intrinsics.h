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

/* \cond */

/**
* \file intrinsics.h
* \brief SIMD include files
*/

#include "qsccommon.h"

/*
 * SIMD support wrapper
 * Detects target architecture and includes appropriate intrinsics header.
 * Defines nothing if SIMD is not supported.
 */

#if defined(_MSC_VER)

#  if defined(_M_ARM) || defined(_M_ARM64)
#    include <arm_neon.h>  /* MSVC targeting ARM with NEON */
#  else
#    include <intrin.h>    /* MSVC targeting x86/x64 */
#  endif
#elif defined(__GNUC__) || defined(__clang__)
/* ??? x86 / x86_64 ?????????????????????????????????????????????????????????? */
#  if defined(__x86_64__) || defined(__i386__)
#    include <x86intrin.h>   /* Covers SSE, AVX, etc. */
#  endif
/* ??? ARM NEON ?????????????????????????????????????????????????????????????? */
#  if defined(__ARM_NEON) || defined(__ARM_NEON__)
#    include <arm_neon.h>
#  endif
/* ??? ARM WMMX ?????????????????????????????????????????????????????????????? */
#  if defined(__IWMMXT__)
#    include <mmintrin.h>
#  endif
/* ??? PowerPC VMX / AltiVec ????????????????????????????????????????????????? */
#  if defined(__VEC__) || defined(__ALTIVEC__)
#    include <altivec.h>
#    /* Prevent name conflicts from altivec macros */
#    undef vector
#    undef pixel
#    undef bool
#  endif
/* ??? PowerPC SPE ??????????????????????????????????????????????????????????? */
#  if defined(__SPE__)
#    include <spe.h>
#  endif
#endif

/* \endcond */

#endif
