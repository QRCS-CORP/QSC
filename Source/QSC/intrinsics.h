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

#include "common.h"

#if defined(QSC_SYSTEM_COMPILER_MSC)
#	if defined(QSC_SYSTEM_ARCH_ARM)
#		include <arm_neon.h>
#	else
#		include <intrin.h>	/* Microsoft C/C++ compatible compiler */
#	endif
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#	include <x86intrin.h>	/* GCC-compatible compiler, targeting x86/x86-64 */
#elif defined(__GNUC__) && defined(__ARM_NEON__)
#	include <arm_neon.h>	/* GCC-compatible compiler, targeting ARM with NEON */
#elif defined(__GNUC__) && defined(__IWMMXT__)
#	include <mmintrin.h>	/* GCC-compatible compiler, targeting ARM with WMMX */
#elif (defined(__GNUC__) || defined(__xlC__)) && (defined(__VEC__) || defined(__ALTIVEC__))
#	include <altivec.h>		/* XLC or GCC-compatible compiler, targeting PowerPC with VMX/VSX */
#elif defined(__GNUC__) && defined(__SPE__)
#	include <spe.h>			/* GCC-compatible compiler, targeting PowerPC with SPE */
#endif

/* \endcond */

#endif
