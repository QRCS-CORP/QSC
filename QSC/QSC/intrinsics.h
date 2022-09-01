/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
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
