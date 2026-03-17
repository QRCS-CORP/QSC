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
  * qsccommon.h. All intrinsic header selection is driven exclusively by those
  * macros; no raw compiler or architecture predefined macros are referenced here.
  *
  * Compiler priority order (highest to lowest):
  *   1. QSC_SYSTEM_COMPILER_MSC   - Microsoft Visual C++
  *   2. QSC_SYSTEM_COMPILER_INTEL - Intel ICC / ICL (also defines QSC_SYSTEM_COMPILER_GCC)
  *   3. QSC_SYSTEM_COMPILER_GCC   - GCC, Clang, MinGW, and all GCC-compatible front-ends
  *      QSC_SYSTEM_COMPILER_CLANG   (Clang sets both QSC_SYSTEM_COMPILER_GCC and QSC_SYSTEM_COMPILER_CLANG simultaneously)
  *   4. QSC_SYSTEM_COMPILER_ARM   - Arm Compiler (armcc / armclang legacy)
  *   5. QSC_SYSTEM_COMPILER_IBM   - IBM XL C / XL C++
  */

#include "qsccommon.h"

  /*==============================================================================
      Microsoft Visual C++ (MSVC)
      QSC_SYSTEM_COMPILER_MSC
      -----------------------------------------------------------------------
      <intrin.h> is MSVC's umbrella intrinsic header and implicitly pulls in
      all SSE, AVX, AVX-512, AES-NI, PCLMUL, and platform intrinsics for the
      current target.  No individual sub-headers are required.
  ==============================================================================*/

#if defined(QSC_SYSTEM_COMPILER_MSC)

  /* x86 / x86-64: <intrin.h> covers SSE2 through AVX-512, AES-NI, CLMUL */
#   if defined(QSC_SYSTEM_ARCH_IX86)
#       include <intrin.h>
#   endif

    /* ARM / ARM64: ARM NEON intrinsics */
#   if defined(QSC_SYSTEM_ARCH_ARM) || defined(QSC_SYSTEM_ARCH_ARM64)
#       include <arm_neon.h>
#   endif

/*==============================================================================
    Intel C/C++ Compiler (ICC / ICL)
    QSC_SYSTEM_COMPILER_INTEL
    -----------------------------------------------------------------------
    ICC defines __GNUC__ for compatibility, which would also set
    QSC_SYSTEM_COMPILER_GCC.  This block must therefore precede the
    GCC/Clang block so that ICC receives its own correct header set.

    <immintrin.h> is ICC's comprehensive x86 intrinsic umbrella, covering
    SSE through AVX-512, AES-NI, and CLMUL.
==============================================================================*/

#elif defined(QSC_SYSTEM_COMPILER_INTEL)

  /* x86 / x86-64: <immintrin.h> is the ICC umbrella for all SIMD levels */
#   if defined(QSC_SYSTEM_ARCH_IX86)
#       include <immintrin.h>
#   endif

    /* ARM NEON (cross-compilation with ICC) */
#   if defined(QSC_SYSTEM_HAS_ARM_NEON)
#       include <arm_neon.h>
#   endif

/*==============================================================================
    GCC, Clang, and all GCC-compatible compilers
    QSC_SYSTEM_COMPILER_GCC  |  QSC_SYSTEM_COMPILER_CLANG
    -----------------------------------------------------------------------
    This block covers:
      - GCC on Linux, macOS, *BSD
      - Clang (defines both QSC_SYSTEM_COMPILER_GCC and QSC_SYSTEM_COMPILER_CLANG)
      - MinGW (defines both QSC_SYSTEM_COMPILER_MINGW and QSC_SYSTEM_COMPILER_GCC)
      - Open64 (defines QSC_SYSTEM_COMPILER_OPEN64 and is GCC-compatible)

    <x86intrin.h> is the GCC/Clang umbrella for all x86 SIMD: it transitively
    includes the individual SSE, AVX, AVX-512, AES-NI (wmmintrin.h), CLMUL,
    and XOP headers that are enabled by the current -march / target flags.
    Individual level headers are therefore not required here.
==============================================================================*/

#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_CLANG)

  /* x86 / x86-64: umbrella header for all x86 SIMD extensions */
#   if defined(QSC_SYSTEM_ARCH_IX86)
#       include <x86intrin.h>
#   endif

    /* ARM NEON (AArch32 and AArch64) */
#   if defined(QSC_SYSTEM_HAS_ARM_NEON)
#       include <arm_neon.h>
#   endif

    /* ARM SVE - Scalable Vector Extension (ARMv8.2-A and later) */
#   if defined(QSC_SYSTEM_HAS_ARM_SVE)
#       include <arm_sve.h>
#   endif

    /* RISC-V Vector extension (RVV 1.0, requires -march=rv64gcv or equivalent) */
#   if defined(QSC_SYSTEM_HAS_RVV)
#       include <riscv_vector.h>
#   endif

    /* PowerPC AltiVec / VMX / VSX
     * <altivec.h> injects the 'vector', 'pixel', and 'bool' keywords as macros,
     * which conflict with standard C++ names.  They are undefined immediately
     * after inclusion to prevent downstream macro contamination. */
#   if defined(QSC_SYSTEM_ARCH_PPC)
#       include <altivec.h>
#       undef vector
#       undef pixel
#       undef bool
#   endif

     /*==============================================================================
         Arm Compiler (armcc / legacy armclang targeting bare-metal)
         QSC_SYSTEM_COMPILER_ARM
         -----------------------------------------------------------------------
         The Arm Compiler toolchain targets ARM and ARM64 exclusively.
         <arm_neon.h> provides NEON intrinsics for both AArch32 and AArch64.
     ==============================================================================*/

#elif defined(QSC_SYSTEM_COMPILER_ARM)

#   include <arm_neon.h>

  /*==============================================================================
      IBM XL C / XL C++
      QSC_SYSTEM_COMPILER_IBM
      -----------------------------------------------------------------------
      IBM XL C targets PowerPC.  <altivec.h> provides AltiVec / VMX / VSX
      intrinsics.  As with GCC, the injected AltiVec keyword macros are
      undefined immediately after inclusion.
  ==============================================================================*/

#elif defined(QSC_SYSTEM_COMPILER_IBM)

#   if defined(QSC_SYSTEM_ARCH_PPC)
#       include <altivec.h>
#       undef vector
#       undef pixel
#       undef bool
#   endif

#endif

/* \cond NO_DOCUMENT */

#endif
