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