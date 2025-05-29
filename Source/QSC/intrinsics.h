/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
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
