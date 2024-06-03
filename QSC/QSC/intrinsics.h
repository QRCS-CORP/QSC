
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSC_INTRINSICS_H
#define QSC_INTRINSICS_H

/* \cond DOXYGEN_IGNORE */

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

/* \endcond DOXYGEN_IGNORE */

#endif
