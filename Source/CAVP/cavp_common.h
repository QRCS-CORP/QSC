/* 2026 Quantum Resistant Cryptographic Solutions Corporation
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

#ifndef CAVP_COMMON_H
#define CAVP_COMMON_H

/* \cond */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*==============================================================================
    Operating System Identification Macros
==============================================================================*/

#if defined(_WIN64) || defined(_WIN32) || defined(__WIN64__) || defined(__WIN32__)
  /*!
   * \def CAVP_SYSTEM_OS_WINDOWS
   * \brief Defined when the target operating system is Windows.
   */
#	if !defined(CAVP_SYSTEM_OS_WINDOWS)
#		define CAVP_SYSTEM_OS_WINDOWS
#	endif
#   if defined(_WIN64)
    /*!
     * \def CAVP_SYSTEM_ISWIN64
     * \brief Defined when building for 64-bit Windows.
     */
#		define CAVP_SYSTEM_ISWIN64
#   elif defined(_WIN32)
    /*!
     * \def CAVP_SYSTEM_ISWIN32
     * \brief Defined when building for 32-bit Windows.
     */
#		define CAVP_SYSTEM_ISWIN32
#   endif
#else
    typedef int errno_t;
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64)
#   define CAVP_HAS_CPUID
#endif

#if defined(__ANDROID__)
  /*!
   * \def CAVP_SYSTEM_OS_ANDROID
   * \brief Defined when the target operating system is Android.
   */
#	define CAVP_SYSTEM_OS_ANDROID
#endif

#if defined(__APPLE__) || defined(__MACH__)
#   if defined(__MACH__)
      /*!
       * \def CAVP_SYSTEM_OS_MAC
       * \brief Defined when the target operating system is Apple (macOS or iOS).
       */
    #	define CAVP_SYSTEM_OS_MAC
#   endif
  /*!
   * \def CAVP_SYSTEM_OS_BSD
   * \brief Also defined for BSD-based operating systems (macOS is BSD-based).
   */
#	define CAVP_SYSTEM_OS_BSD

#   if defined(TARGET_OS_IPHONE) && defined(TARGET_IPHONE_SIMULATOR)
        /*!
         * \def CAVP_SYSTEM_ISIPHONESIM
         * \brief Defined when building for the iPhone Simulator.
         */
#		define CAVP_SYSTEM_ISIPHONESIM
#   elif defined(TARGET_OS_IPHONE)
        /*!
         * \def CAVP_SYSTEM_ISIPHONE
         * \brief Defined when building for iPhone.
         */
#		define CAVP_SYSTEM_ISIPHONE
#   else
        /*!
         * \def CAVP_SYSTEM_ISOSX
         * \brief Defined when building for macOS.
         */
#		define CAVP_SYSTEM_ISOSX
#   endif
#endif

#define CAVP_ASSERT(expr) assert(expr)

/* \endcond */

#endif