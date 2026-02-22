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

#ifndef QSC_COMMON_H
#define QSC_COMMON_H

#if defined(__posix) || defined(__posix__) || defined(__USE_POSIX) || defined(_POSIX_VERSION) || defined(__MACH__) || \
    defined(__linux) || defined(__linux__) || defined(__gnu_linux__) || defined(__unix) || defined(__unix__) || \
    defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__bsdi__) || defined(__DragonFly__)
#   if defined(__linux__)
#       if !defined(_DEFAULT_SOURCE)
#           define _DEFAULT_SOURCE
#       endif
#       if !defined(_XOPEN_SOURCE)
#           define _XOPEN_SOURCE 700
#       endif
#       if !defined(_GNU_SOURCE)
#           define _GNU_SOURCE
#       endif
#   elif defined(__APPLE__) && defined(__MACH__)
#       if !defined(_DARWIN_C_SOURCE)
#           define _DARWIN_C_SOURCE
#       endif
#   elif defined(__sun) && defined(__SVR4)
#       if !defined(__EXTENSIONS__)
#           define __EXTENSIONS__
#       endif
#   elif defined(__FreeBSD__)   || defined(__NetBSD__) || defined(__OpenBSD__)   || defined(__DragonFly__)
#       if !defined(_BSD_SOURCE)
#           define _BSD_SOURCE
#       endif
#endif

#   if !defined(_POSIX_C_SOURCE)
#           define _POSIX_C_SOURCE 200809L
#   endif
#endif

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
#   define QSC_CPLUSPLUS_ENABLED_START extern "C" {
#   define QSC_CPLUSPLUS_ENABLED_END }
#else
#   define QSC_CPLUSPLUS_ENABLED_START
#   define QSC_CPLUSPLUS_ENABLED_END
#endif

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file qsccommon.h
 * \brief Contains common definitions for the Quantum Secure Cryptographic (QSC) library.
 *
 * \details
 * This file provides common macros, type definitions, compiler/OS/architecture detection,
 * API export macros, alignment macros, secure memory allocation definitions, and other utility macros.
 * These definitions are used throughout the QSC library to ensure portability and performance.
 */

/*==============================================================================
    Compiler Identification Macros
==============================================================================*/

#if defined(_MSC_VER)
  /*!
   * \def QSC_SYSTEM_COMPILER_MSC
   * \brief Defined when the Microsoft Visual C++ compiler is detected.
   */
#	define QSC_SYSTEM_COMPILER_MSC
#endif

#if defined(__MINGW32__)
  /*!
   * \def QSC_SYSTEM_COMPILER_MINGW
   * \brief Defined when using the MinGW compiler.
   */
#	define QSC_SYSTEM_COMPILER_MINGW
  /*!
   * \def QSC_SYSTEM_COMPILER_GCC
   * \brief Also defined for MinGW as it uses GCC.
   */
#	define QSC_SYSTEM_COMPILER_GCC
#endif

#if defined(__CC_ARM)
  /*!
   * \def QSC_SYSTEM_COMPILER_ARM
   * \brief Defined when using the ARM Compiler.
   */
#	define QSC_SYSTEM_COMPILER_ARM
#endif

#if defined(__BORLANDC__)
  /*!
   * \def QSC_SYSTEM_COMPILER_BORLAND
   * \brief Defined when using the Borland C compiler.
   */
#	define QSC_SYSTEM_COMPILER_BORLAND
#endif

#if defined(__GNUC__) && !defined(__MINGW32__)
  /*!
   * \def QSC_SYSTEM_COMPILER_GCC
   * \brief Defined when the GNU Compiler Collection (GCC) is detected.
   */
#	define QSC_SYSTEM_COMPILER_GCC
#endif

#if defined(__clang__)
  /*!
   * \def QSC_SYSTEM_COMPILER_CLANG
   * \brief Defined when the Clang compiler is detected.
   */
#	define QSC_SYSTEM_COMPILER_CLANG
#endif

#if defined(__IBMC__) || defined(__IBMCPP__)
  /*!
   * \def QSC_SYSTEM_COMPILER_IBM
   * \brief Defined when using the IBM compiler.
   */
#	define QSC_SYSTEM_COMPILER_IBM
#endif

#if defined(__INTEL_COMPILER) || defined(__ICL)
  /*!
   * \def QSC_SYSTEM_COMPILER_INTEL
   * \brief Defined when using the Intel compiler.
   */
#	define QSC_SYSTEM_COMPILER_INTEL
#endif

#if defined(__MWERKS__)
  /*!
   * \def QSC_SYSTEM_COMPILER_MWERKS
   * \brief Defined when using the Metrowerks compiler.
   */
#	define QSC_SYSTEM_COMPILER_MWERKS
#endif

#if defined(__OPEN64__)
  /*!
   * \def QSC_SYSTEM_COMPILER_OPEN64
   * \brief Defined when using the Open64 compiler.
   */
#	define QSC_SYSTEM_COMPILER_OPEN64
#endif

#if defined(__SUNPRO_C)
  /*!
   * \def QSC_SYSTEM_COMPILER_SUNPRO
   * \brief Defined when using the SunPro C compiler.
   */
#	define QSC_SYSTEM_COMPILER_SUNPRO
#endif

#if defined(__TURBOC__)
  /*!
   * \def QSC_SYSTEM_COMPILER_TURBO
   * \brief Defined when using the Turbo C compiler.
   */
#	define QSC_SYSTEM_COMPILER_TURBO
#endif

/*==============================================================================
    Operating System Identification Macros
==============================================================================*/

#if defined(_WIN64) || defined(_WIN32) || defined(__WIN64__) || defined(__WIN32__)
  /*!
   * \def QSC_SYSTEM_OS_WINDOWS
   * \brief Defined when the target operating system is Windows.
   */
#	if !defined(QSC_SYSTEM_OS_WINDOWS)
#		define QSC_SYSTEM_OS_WINDOWS
#	endif
#   if defined(_WIN64)
    /*!
     * \def QSC_SYSTEM_ISWIN64
     * \brief Defined when building for 64-bit Windows.
     */
#		define QSC_SYSTEM_ISWIN64
#   elif defined(_WIN32)
    /*!
     * \def QSC_SYSTEM_ISWIN32
     * \brief Defined when building for 32-bit Windows.
     */
#		define QSC_SYSTEM_ISWIN32
#   endif
#else
    typedef int errno_t;
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64)
#   define QSC_HAS_CPUID
#endif

#if defined(__ANDROID__)
  /*!
   * \def QSC_SYSTEM_OS_ANDROID
   * \brief Defined when the target operating system is Android.
   */
#	define QSC_SYSTEM_OS_ANDROID
#endif

#if defined(__APPLE__) || defined(__MACH__)
#   if defined(__MACH__)
      /*!
       * \def QSC_SYSTEM_OS_MAC
       * \brief Defined when the target operating system is Apple (macOS or iOS).
       */
    #	define QSC_SYSTEM_OS_MAC
#   endif
  /*!
   * \def QSC_SYSTEM_OS_BSD
   * \brief Also defined for BSD-based operating systems (macOS is BSD-based).
   */
#	define QSC_SYSTEM_OS_BSD

#   if defined(TARGET_OS_IPHONE) && defined(TARGET_IPHONE_SIMULATOR)
        /*!
         * \def QSC_SYSTEM_ISIPHONESIM
         * \brief Defined when building for the iPhone Simulator.
         */
#		define QSC_SYSTEM_ISIPHONESIM
#   elif defined(TARGET_OS_IPHONE)
        /*!
         * \def QSC_SYSTEM_ISIPHONE
         * \brief Defined when building for iPhone.
         */
#		define QSC_SYSTEM_ISIPHONE
#   else
        /*!
         * \def QSC_SYSTEM_ISOSX
         * \brief Defined when building for macOS.
         */
#		define QSC_SYSTEM_ISOSX
#   endif
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__bsdi__) || defined(__DragonFly__) || defined(QSC_SYSTEM_ISOSX)
  /*!
   * \def QSC_SYSTEM_OS_BSD
   * \brief Defined when the target operating system is a BSD variant.
   */
#	define QSC_SYSTEM_OS_BSD
#endif

#if defined(__linux) || defined(__linux__) || defined(__gnu_linux__)
  /*!
   * \def QSC_SYSTEM_OS_LINUX
   * \brief Defined when the target operating system is Linux.
   */
#	define QSC_SYSTEM_OS_LINUX
#endif

#if defined(__unix) || defined(__unix__)
  /*!
   * \def QSC_SYSTEM_OS_UNIX
   * \brief Defined when the target operating system is Unix.
   */
#	define QSC_SYSTEM_OS_UNIX
#   if defined(__hpux) || defined(hpux)
    /*!
     * \def QSC_SYSTEM_OS_HPUX
     * \brief Defined when the target operating system is HP-UX.
     */
#		define QSC_SYSTEM_OS_HPUX
#   endif
#   if defined(__sun__) || defined(__sun) || defined(sun)
    /*!
     * \def QSC_SYSTEM_OS_SUNUX
     * \brief Defined when the target operating system is Solaris.
     */
#		define QSC_SYSTEM_OS_SUNUX
#   endif
#endif

#if defined(__posix) || defined(__posix__) || defined(__USE_POSIX) || defined(_POSIX_VERSION) || defined(QSC_SYSTEM_OS_UNIX) || defined(QSC_SYSTEM_OS_LINUX) || defined(QSC_SYSTEM_OS_BSD)
  /*!
   * \def QSC_SYSTEM_OS_POSIX
   * \brief Defined when the operating system is POSIX-compliant.
   */
#	define QSC_SYSTEM_OS_POSIX

#endif

#if defined(QSC_SYSTEM_OS_WINDOWS) && defined(QSC_SYSTEM_COMPILER_MSC)
  /*!
   * \def QSC_WINDOWS_VSTUDIO_BUILD
   * \brief Defined when building on Windows using Visual Studio.
   */
#   define QSC_WINDOWS_VSTUDIO_BUILD
#endif

#if defined(_OPENMP)
  /*!
   * \def QSC_SYSTEM_OPENMP
   * \brief Defined when OpenMP support is enabled.
   */
#	define QSC_SYSTEM_OPENMP
#endif

#if defined(DEBUG) || defined(_DEBUG) || defined(__DEBUG__) || (defined(__GNUC__) && !defined(__OPTIMIZE__))
  /*!
   * \def QSC_DEBUG_MODE
   * \brief Defined when the build is in debug mode.
   */
#	define QSC_DEBUG_MODE
#endif

#ifdef QSC_DEBUG_MODE
  /*!
   * \def QSC_ASSERT
   * \brief Define the assert function and guarantee it as debug only.
   */
#  define QSC_ASSERT(expr) assert(expr)
#else
#  define QSC_ASSERT(expr) ((void)0)
#endif

/*==============================================================================
    CPU Architecture Identification Macros
==============================================================================*/
#if defined(QSC_SYSTEM_COMPILER_MSC)
#   if defined(_M_X64) || defined(_M_AMD64)
    /*!
     * \def QSC_SYSTEM_ARCH_IX86_64
     * \brief Defined when building for 64-bit x86 (AMD64/Intel 64).
     */
#		define QSC_SYSTEM_ARCH_IX86_64
    /*!
     * \def QSC_SYSTEM_ARCH_IX86
     * \brief Also defined when building for x86 architectures.
     */
#		define QSC_SYSTEM_ARCH_IX86
#   if defined(_M_AMD64)
      /*!
       * \def QSC_SYSTEM_ARCH_AMD64
       * \brief Defined when the processor is AMD64.
       */
#			define QSC_SYSTEM_ARCH_AMD64
#   endif
#   elif defined(_M_IX86) || defined(_X86_)
    /*!
     * \def QSC_SYSTEM_ARCH_IX86_32
     * \brief Defined when building for 32-bit x86.
     */
#		define QSC_SYSTEM_ARCH_IX86_32
    /*!
     * \def QSC_SYSTEM_ARCH_IX86
     * \brief Also defined for x86 architectures.
     */
#		define QSC_SYSTEM_ARCH_IX86
#   elif defined(_M_ARM)
    /*!
     * \def QSC_SYSTEM_ARCH_ARM
     * \brief Defined when building for ARM architectures.
     */
#		define QSC_SYSTEM_ARCH_ARM
#       if defined(_M_ARM_ARMV7VE)
      /*!
       * \def QSC_SYSTEM_ARCH_ARMV7VE
       * \brief Defined when building for ARM V7VE.
       */
#			define QSC_SYSTEM_ARCH_ARMV7VE
#       elif defined(_M_ARM_FP)
      /*!
       * \def QSC_SYSTEM_ARCH_ARMFP
       * \brief Defined when building for ARM with floating point support.
       */
#			define QSC_SYSTEM_ARCH_ARMFP
#       elif defined(_M_ARM64)
      /*!
       * \def QSC_SYSTEM_ARCH_ARM64
       * \brief Defined when building for ARM64.
       */
#			define QSC_SYSTEM_ARCH_ARM64
#       endif
#   elif defined(_M_IA64)
    /*!
     * \def QSC_SYSTEM_ARCH_IA64
     * \brief Defined when building for Itanium (IA-64).
     */
#		define QSC_SYSTEM_ARCH_IA64
#   endif
#elif defined(QSC_SYSTEM_COMPILER_GCC)
#   if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
    /*!
     * \def QSC_SYSTEM_ARCH_IX86_64
     * \brief Defined when building for 64-bit x86 (AMD64/Intel 64) using GCC.
     */
#		define QSC_SYSTEM_ARCH_IX86_64
    /*!
     * \def QSC_SYSTEM_ARCH_IX86
     * \brief Also defined for x86 architectures.
     */
#		define QSC_SYSTEM_ARCH_IX86
#       if defined(_M_AMD64)
      /*!
       * \def QSC_SYSTEM_ARCH_AMD64
       * \brief Defined when the processor is AMD64.
       */
#			define QSC_SYSTEM_ARCH_AMD64
#       endif
#   elif defined(i386) || defined(__i386) || defined(__i386__)
    /*!
     * \def QSC_SYSTEM_ARCH_IX86_32
     * \brief Defined when building for 32-bit x86 using GCC.
     */
#		define QSC_SYSTEM_ARCH_IX86_32
    /*!
     * \def QSC_SYSTEM_ARCH_IX86
     * \brief Also defined for x86 architectures.
     */
#		define QSC_SYSTEM_ARCH_IX86
#   elif defined(__arm__)
    /*!
     * \def QSC_SYSTEM_ARCH_ARM
     * \brief Defined when building for ARM architectures using GCC.
     */
#		define QSC_SYSTEM_ARCH_ARM
#       if defined(__aarch64__)
      /*!
       * \def QSC_SYSTEM_ARCH_ARM64
       * \brief Defined when building for ARM64.
       */
#			define QSC_SYSTEM_ARCH_ARM64
#       endif
#   elif defined(__ia64) || defined(__ia64__) || defined(__itanium__)
    /*!
     * \def QSC_SYSTEM_ARCH_IA64
     * \brief Defined when building for Itanium (IA-64) using GCC.
     */
#		define QSC_SYSTEM_ARCH_IA64
#   elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || defined(__64BIT__) || defined(_LP64) || defined(__LP64__)
    /*!
     * \def QSC_SYSTEM_ARCH_PPC
     * \brief Defined when building for PowerPC 64-bit.
     */
#		define QSC_SYSTEM_ARCH_PPC
#   elif defined(__sparc) || defined(__sparc__)
    /*!
     * \def QSC_SYSTEM_ARCH_SPARC
     * \brief Defined when building for SPARC architectures.
     */
#		define QSC_SYSTEM_ARCH_SPARC
#       if defined(__sparc64__)
      /*!
       * \def QSC_SYSTEM_ARCH_SPARC64
       * \brief Defined when building for 64-bit SPARC.
       */
#			define QSC_SYSTEM_ARCH_SPARC64
#       endif
#   endif
#endif

#if (defined(__x86_64__) || defined(_M_X64))
#   define QSC_SYSTEM_X86
#endif

/*==============================================================================
    Sockets and Other System Macros
==============================================================================*/

/*!
 * \def QSC_NO_INLINE
 * \brief Tells the compiler not to inline a function.
 */
#if defined(_MSC_VER)
#   define QSC_NO_INLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#   define QSC_NO_INLINE __attribute__((noinline))
#else
#   define QSC_NO_INLINE
#endif

#if defined(_WIN64) || defined(_WIN32) || defined(__CYGWIN__)
  /*!
   * \def QSC_SYSTEM_SOCKETS_WINDOWS
   * \brief Defined when using Windows sockets.
   */
#	define QSC_SYSTEM_SOCKETS_WINDOWS
#else
  /*!
   * \def QSC_SYSTEM_SOCKETS_BERKELY
   * \brief Defined when using Berkeley sockets.
   */
#	define QSC_SYSTEM_SOCKETS_BERKELY
#endif

#if defined(__attribute__)
#   define QSC_ATTRIBUTE __attribute__
#else
#   define QSC_ATTRIBUTE(a)
#endif

#if defined(_DLL)
  /*!
   * \def QSC_DLL_API
   * \brief Defined when building as a DLL.
   */
#	define QSC_DLL_API
#endif

/*!
* \def QSC_EXPORT_API
* \brief API export macro for Microsoft compilers when importing from a DLL.
*/
#if defined(QSC_DLL_API)

#if defined(QSC_SYSTEM_COMPILER_MSC)
#   if defined(QSC_DLL_IMPORT)
#		define QSC_EXPORT_API __declspec(dllimport)
#   else
#	    define QSC_EXPORT_API __declspec(dllexport)
#   endif
#elif defined(QSC_SYSTEM_COMPILER_GCC)
#   if defined(QSC_DLL_IMPORT)
#		define QSC_EXPORT_API QSC_ATTRIBUTE((dllimport))
#   else
#		define QSC_EXPORT_API QSC_ATTRIBUTE((dllexport))
#   endif
#else
#   if defined(__SUNPRO_C)
#       if !defined(__GNU_C__)
#		    define QSC_EXPORT_API QSC_ATTRIBUTE (visibility(__global))
#       else
#			define QSC_EXPORT_API QSC_ATTRIBUTE __global
#       endif
#   elif defined(_MSG_VER)
#		define QSC_EXPORT_API extern __declspec(dllexport)
#   else
#		define QSC_EXPORT_API QSC_ATTRIBUTE ((visibility ("default")))
#   endif
#endif
#else
#	define QSC_EXPORT_API
#endif

/*!
* \def QSC_CACHE_ALIGNED
* \brief Defines cache-line alignment using GCC's QSC_ATTRIBUTE syntax.
*/
#if defined(__GNUC__)
#	define QSC_CACHE_ALIGNED QSC_ATTRIBUTE((aligned(64)))
#elif defined(_MSC_VER)
#	define QSC_CACHE_ALIGNED __declspec(align(64U))
#endif

#if defined(QSC_SYSTEM_ARCH_IX86_64) || defined(QSC_SYSTEM_ARCH_ARM64) || defined(QSC_SYSTEM_ARCH_IA64) || defined(QSC_SYSTEM_ARCH_AMD64) || defined(QSC_SYSTEM_ARCH_SPARC64)
  /*!
   * \def QSC_SYSTEM_IS_X64
   * \brief Defined when the target system is 64-bit.
   */
#	define QSC_SYSTEM_IS_X64
#else
  /*!
   * \def QSC_SYSTEM_IS_X86
   * \brief Defined when the target system is 32-bit.
   */
#	define QSC_SYSTEM_IS_X86
#endif

#if defined(QSC_SYSTEM_IS_X64)
  /*!
   * \def QSC_SIZE_MAX
   * \brief The maximum integer size for a 64-bit system.
   */
#	define QSC_SIZE_MAX UINT64_MAX
#else
  /*!
   * \def QSC_SIZE_MAX
   * \brief The maximum integer size for a 32-bit system.
   */
#	define QSC_SIZE_MAX UINT32_MAX
#endif

/*!
 * \def QSC_SYSTEM_IS_LITTLE_ENDIAN
 * \brief Defined if the system is little endian.
 */
#if !defined(__BIG_ENDIAN__)
#   if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#       define QSC_SYSTEM_IS_LITTLE_ENDIAN 1U
#   elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#       define QSC_SYSTEM_IS_LITTLE_ENDIAN 0U
#   elif defined(_WIN32) || defined(__LITTLE_ENDIAN__)
#       define QSC_SYSTEM_IS_LITTLE_ENDIAN 1U
#   endif
#endif

#if (!defined(QSC_SYSTEM_IS_LITTLE_ENDIAN))
#	if defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__PPC__) || defined(__mips__) || (defined(__MWERKS__) && !defined(__INTEL__))
    /*!
     * \def QSC_SYSTEM_IS_BIG_ENDIAN
     * \brief Defined if the system is big endian.
     */
#		define QSC_SYSTEM_IS_BIG_ENDIAN
#	else
    /*!
     * \def QSC_SYSTEM_IS_LITTLE_ENDIAN
     * \brief Defined if the system is little endian.
     */
#		define QSC_SYSTEM_IS_LITTLE_ENDIAN
#	endif
#endif

#if defined(__SIZEOF_INT128__) && defined(QSC_SYSTEM_IS_X64) && !defined(__xlc__) && !defined(uint128_t)
  /*!
   * \def QSC_SYSTEM_NATIVE_UINT128
   * \brief Defined when the system supports a native 128-bit integer type.
   */
#	define QSC_SYSTEM_NATIVE_UINT128
#	if defined(__GNUC__)
    /*!
     * \typedef uint128_t
     * \brief A 128-bit unsigned integer type using GCC's mode(TI) attribute.
     */
		typedef uint32_t uint128_t QSC_ATTRIBUTE((mode(TI)));
#	else
		typedef __int128 uint128_t;
#	endif
#endif

/*!
* \def QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)
* \brief Performs fast 64-bit multiplication using a native 128-bit integer.
*/
#if defined(QSC_SYSTEM_NATIVE_UINT128)
#	define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)			\
	do {													\
      const uint128_t r = (uint128_t)(X) * (Y);	\
      *(High) = (r >> 64) & 0xFFFFFFFFFFFFFFFFULL;			\
      *(Low) = (r) & 0xFFFFFFFFFFFFFFFFULL;					\
	} while(0U)
#elif defined(QSC_SYSTEM_COMPILER_MSC) && defined(QSC_SYSTEM_IS_X64)
#	include <intrin.h>
#	pragma intrinsic(_umul128)
#	define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)			\
	do {													\
		*(Low) = _umul128((X), (Y), (High));				\
	} while(0U)
#elif defined(QSC_SYSTEM_COMPILER_GCC)
#	if defined(QSC_SYSTEM_ARCH_IX86)
#		define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							    \
		do {																	    \
		asm("mulq %3" : "=d" (*(High)), "=X" (*(Low)) : "X" (X), "rm" (Y) : "cc");	\
		} while(0U)
#	elif defined(QSC_SYSTEM_ARCH_ALPHA)
#		define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("umulh %1,%2,%0U" : "=r" (*(High)) : "r" (X), "r" (Y));				\
		*(Low) = (X) * (Y);														\
		} while(0U)
#	elif defined(QSC_SYSTEM_ARCH_IA64)
#		define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("xmpy.hu %0U=%1,%2" : "=f" (*(High)) : "f" (X), "f" (Y));			\
		*(Low) = (X) * (Y);														\
		} while(0U)
#	elif defined(QSC_SYSTEM_ARCH_PPC)
#		define QSC_SYSTEM_FAST_64X64_MUL(X,Y,Low,High)							\
		do {																	\
		asm("mulhdu %0U,%1,%2" : "=r" (*(High)) : "r" (X), "r" (Y) : "cc");		\
		*(Low) = (X) * (Y);														\
		} while(0U)
#	endif
#endif

/*!
 * \def QSC_SYSTEM_MAX_PATH
 * \brief The maximum path length supported by the system.
 */
#define QSC_SYSTEM_MAX_PATH 260ULL

/*!
 * \def QSC_SYSTEM_SECMEMALLOC_DEFAULT
 * \brief Default secure memory buffer allocation size (in bytes).
 */
#define QSC_SYSTEM_SECMEMALLOC_DEFAULT 4096ULL

/*!
 * \def QSC_SYSTEM_SECMEMALLOC_MIN
 * \brief Minimum secure memory allocation size (in bytes).
 */
#define QSC_SYSTEM_SECMEMALLOC_MIN 16ULL

/*!
 * \def QSC_SYSTEM_SECMEMALLOC_MAX
 * \brief Maximum secure memory allocation size (in bytes).
 */
#define QSC_SYSTEM_SECMEMALLOC_MAX 128ULL

/*!
 * \def QSC_SYSTEM_SECMEMALLOC_MAXKB
 * \brief Maximum secure memory allocation in kilobytes.
 */
#define QSC_SYSTEM_SECMEMALLOC_MAXKB 512ULL

#if defined(_WIN32)
  /*!
   * \def QSC_SYSTEM_VIRTUAL_LOCK
   * \brief Defined if the system supports virtual memory locking on Windows.
   */
#	define QSC_SYSTEM_VIRTUAL_LOCK

  /*!
   * \def QSC_RTL_SECURE_MEMORY
   * \brief Defined if the system supports secure memory allocation on Windows.
   */
#	define QSC_RTL_SECURE_MEMORY
#endif

#if defined(_POSIX_MEMLOCK_RANGE)
  /*!
   * \def QSC_SYSTEM_POSIX_MLOCK
   * \brief Defined if the system supports the POSIX mlock function.
   */
#	define QSC_SYSTEM_POSIX_MLOCK
#endif

#if defined(QSC_SYSTEM_VIRTUAL_LOCK) || defined(QSC_SYSTEM_POSIX_MLOCK)
  /*!
   * \def QSC_SYSTEM_SECURE_ALLOCATOR
   * \brief Defined if the system has a secure memory allocator.
   */
#	define QSC_SYSTEM_SECURE_ALLOCATOR
#endif

/*!
* \def QSC_SYSTEM_OPTIMIZE_IGNORE
* \brief Compiler hint to disable optimization in MSVC.
*/
#if defined(QSC_SYSTEM_COMPILER_MSC)
#	define QSC_SYSTEM_OPTIMIZE_IGNORE __pragma(optimize("", off))
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_MINGW)
#   if defined(__clang__)
    /*!
     * \def QSC_SYSTEM_OPTIMIZE_IGNORE
     * \brief Compiler hint to disable optimization in Clang.
     */
#		define QSC_SYSTEM_OPTIMIZE_IGNORE QSC_ATTRIBUTE((optnone))
#   else
    /*!
     * \def QSC_SYSTEM_OPTIMIZE_IGNORE
     * \brief Compiler hint to disable optimization in GCC.
     */
#		define QSC_SYSTEM_OPTIMIZE_IGNORE QSC_ATTRIBUTE((optimize("O0")))
#   endif
#elif defined(QSC_SYSTEM_COMPILER_CLANG)
  /*!
   * \def QSC_SYSTEM_OPTIMIZE_IGNORE
   * \brief Compiler hint to disable optimization in Clang.
   */
#	define QSC_SYSTEM_OPTIMIZE_IGNORE QSC_ATTRIBUTE((optnone))
#elif defined(QSC_SYSTEM_COMPILER_INTEL)
  /*!
   * \def QSC_SYSTEM_OPTIMIZE_IGNORE
   * \brief Compiler hint to disable optimization in the Intel compiler.
   */
#	define QSC_SYSTEM_OPTIMIZE_IGNORE pragma optimize("", off)
#else
#	define QSC_SYSTEM_OPTIMIZE_IGNORE
#endif

/*!
* \def QSC_SYSTEM_OPTIMIZE_RESUME
* \brief Compiler hint to resume optimization in MSVC.
*/
#if defined(QSC_SYSTEM_COMPILER_MSC)
#	define QSC_SYSTEM_OPTIMIZE_RESUME __pragma(optimize("", on))
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_MINGW)
#   if defined(__clang__)
#		define QSC_SYSTEM_OPTIMIZE_RESUME
#   else
#		define QSC_SYSTEM_OPTIMIZE_RESUME _Pragma("GCC diagnostic pop")
#   endif
#elif defined(QSC_SYSTEM_COMPILER_INTEL)
#	define QSC_SYSTEM_OPTIMIZE_RESUME pragma optimize("", on)
#else
#	define QSC_SYSTEM_OPTIMIZE_RESUME
#endif

/*!
* \def QSC_SYSTEM_CONDITION_IGNORE(x)
* \brief MSVC-specific macro to disable a specific warning condition.
*/
#if defined(QSC_SYSTEM_COMPILER_MSC)
#	define QSC_SYSTEM_CONDITION_IGNORE(x) __pragma(warning(disable : x))
#elif defined(QSC_SYSTEM_COMPILER_GCC) || defined(QSC_SYSTEM_COMPILER_MINGW)
#	define QSC_SYSTEM_CONDITION_IGNORE(x) _Pragma("GCC diagnostic push") _Pragma("GCC diagnostic ignored \"-Wunused-parameter\"")
#elif defined(QSC_SYSTEM_COMPILER_INTEL)
#	define QSC_SYSTEM_CONDITION_IGNORE(x)
#else
#	define QSC_SYSTEM_CONDITION_IGNORE(x)
#endif

#if (_MSC_VER >= 1600)
  /*!
   * \def QSC_WMMINTRIN_H
   * \brief Defined when the CPU supports SIMD instructions (MSVC).
   */
#	define QSC_WMMINTRIN_H 1
#endif

#if (_MSC_VER >= 1700) && (defined(_M_X64))
  /*!
   * \def QSC_HAVE_AVX2INTRIN_H
   * \brief Defined when the CPU supports AVX2 (MSVC, 64-bit).
   */
#	define QSC_HAVE_AVX2INTRIN_H 1
#endif

/*==============================================================================
    AVX512 Capabilities
==============================================================================*/

#if defined(QSC_SYSTEM_X86)

#   if defined(__AVX512F__) && (__AVX512F__ == 1)
      /*!
       * \def __AVX512__
       * \brief Defined when the system supports AVX512 instructions.
       */
#	    include <immintrin.h>
#	    if (!defined(__AVX512__))
#		    define __AVX512__
#	    endif
#   endif

#   if defined(__SSE2__)
      /*!
       * \def QSC_SYSTEM_HAS_SSE2
       * \brief Defined if the system supports SSE2 instructions.
       */
#	    define QSC_SYSTEM_HAS_SSE2
#   endif

#   if defined(__SSE3__)
      /*!
       * \def QSC_SYSTEM_HAS_SSE3
       * \brief Defined if the system supports SSE3 instructions.
       */
#	    define QSC_SYSTEM_HAS_SSE3
#   endif

#   if defined(__SSSE3__)
      /*!
       * \def QSC_SYSTEM_HAS_SSSE3
       * \brief Defined if the system supports SSSE3 instructions.
       */
#	    define QSC_SYSTEM_HAS_SSSE3
#   endif

#   if defined(__SSE4_1__)
      /*!
       * \def QSC_SYSTEM_HAS_SSE41
       * \brief Defined if the system supports SSE4.1 instructions.
       */
#	    define QSC_SYSTEM_HAS_SSE41
#   endif

#   if defined(__SSE4_2__)
      /*!
       * \def QSC_SYSTEM_HAS_SSE42
       * \brief Defined if the system supports SSE4.2 instructions.
       */
#	    define QSC_SYSTEM_HAS_SSE42
#   endif

#   if defined(__ARM_NEON__)
      /*!
       * \def QSC_SYSTEM_HAS_ARM_NEON
       * \brief Defined if the system supports ARM NEON instructions.
       */
#       define QSC_SYSTEM_HAS_ARM_NEON
    #endif

#   if defined(__AVX__)
      /*!
       * \def QSC_SYSTEM_HAS_AVX
       * \brief Defined if the system supports AVX instructions.
       */
#	    define QSC_SYSTEM_HAS_AVX
#   endif

#   if defined(__AVX2__)
      /*!
       * \def QSC_SYSTEM_HAS_AVX2
       * \brief Defined if the system supports AVX2 instructions.
       */
#	    define QSC_SYSTEM_HAS_AVX2
#   endif

#   if defined(__AVX512__)
      /*!
       * \def QSC_SYSTEM_HAS_AVX512
       * \brief Defined if the system supports AVX512 instructions.
       */
#	    define QSC_SYSTEM_HAS_AVX512
#   endif

#   if defined(__XOP__)
      /*!
       * \def QSC_SYSTEM_HAS_XOP
       * \brief Defined if the system supports XOP instructions.
       */
#	    define QSC_SYSTEM_HAS_XOP
#endif

#   if defined(QSC_SYSTEM_HAS_AVX) || defined(QSC_SYSTEM_HAS_AVX2) || defined(QSC_SYSTEM_HAS_AVX512)
      /*!
       * \def QSC_SYSTEM_AVX_INTRINSICS
       * \brief Defined if the system supports AVX intrinsics.
       */
#	define QSC_SYSTEM_AVX_INTRINSICS
#   endif
#endif

/*==============================================================================
    Assembly and SIMD Alignment Macros
==============================================================================*/

/*!
* \def QSC_ASM_ENABLED
* \brief Global flag for enabling ASM compilation (user-modifiable).
*/
/*#define QSC_ASM_ENABLED */

/*!
* \def QSC_MISRA_FULL_COMPLIANCE
* \brief Enable full MISRA compliant cryptographic module compliance.
*/
//#define QSC_MISRA_FULL_COMPLIANCE

#if defined(QSC_SYSTEM_AVX_INTRINSICS) && defined(QSC_SYSTEM_COMPILER_GCC) && defined(QSC_ASM_ENABLED)
  // #define QSC_GCC_ASM_ENABLED  /* Uncomment to enable GCC ASM processing */
#endif

/*!
* \def QSC_ALIGN(x)
* \brief Macro for aligning data to 'x' bytes using GCC/Clang.
*/
#if !defined(QSC_ALIGN)
    /* If compiling in C23 or later, use the built-in 'alignas' keyword. */
    #if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 202311L)
        #define QSC_ALIGN(x) alignas(x)
#	elif defined(_MSC_VER)
#		define QSC_ALIGN(x) __declspec(align(x))
#	elif defined(__GNUC__) || defined(__clang__)
#		define QSC_ALIGN(x) __attribute__((aligned(x)))
#	else
#		define QSC_ALIGN(x)
#	endif
#endif

  /*!
   * \def QSC_SIMD_ALIGNMENT
   * \brief Alignment value for enabled intrinsic.
   */
#if defined(QSC_SYSTEM_HAS_AVX512)
#  define QSC_SIMD_ALIGNMENT 64
#elif defined(QSC_SYSTEM_HAS_AVX2)
#  define QSC_SIMD_ALIGNMENT 32
#elif defined(QSC_SYSTEM_HAS_AVX)
#  define QSC_SIMD_ALIGNMENT 16
#else
#  define QSC_SIMD_ALIGNMENT 8
#endif

  /*!
   * \def QSC_SIMD_ALIGN
   * \brief Macro to align data on supported intrinsics size
   */
#if defined(_MSC_VER)
#  define QSC_SIMD_ALIGN __declspec(align(QSC_SIMD_ALIGNMENT))
#elif defined(__GNUC__) || defined(__clang__)
#  define QSC_SIMD_ALIGN _Alignas(QSC_SIMD_ALIGNMENT)
#else
#  define QSC_SIMD_ALIGN
#endif

#if defined(QSC_SYSTEM_AVX_INTRINSICS)
  /*!
   * \def QSC_RDRAND_COMPATIBLE
   * \brief Defined if the CPU is RDRAND compatible.
   */
#	define QSC_RDRAND_COMPATIBLE
#endif

/*!
 * \def QSC_STATUS_SUCCESS
 * \brief Function return value indicating successful operation.
 */
#define QSC_STATUS_SUCCESS 0LL

/*!
 * \def QSC_STATUS_FAILURE
 * \brief Function return value indicating failed operation.
 */
#define QSC_STATUS_FAILURE -1LL

/*==============================================================================
    User Modifiable Values and Cryptographic Parameter Sets
==============================================================================*/

#if !defined(QSC_SYSTEM_AESNI_ENABLED)
#	if defined(QSC_SYSTEM_AVX_INTRINSICS)
    /*!
     * \def QSC_SYSTEM_AESNI_ENABLED
     * \brief Enable the use of intrinsics and the AES-NI implementation.
     */
#		define QSC_SYSTEM_AESNI_ENABLED
#	endif
#endif

///*!
// * \def QSC_KECCAK_UNROLLED_PERMUTATION
// * \brief Define to use the unrolled form of the Keccak permutation function.
// */
//#define QSC_KECCAK_UNROLLED_PERMUTATION

/*** Asymmetric Ciphers ***/

/*** ECDH ***/

/**
* \def QSC_RFC_7748_COMPLIANT
* \brief Controls the key derivation method used in qsc_x25519_generate_keypair.
*
* When defined, the function uses the RFC 7748 Section 6.1 compliant method:
* the private key scalar is derived by copying the seed directly, with clamping
* applied internally during scalar multiplication. This produces keypairs that are
* interoperable with any standard-conforming X25519 implementation, including
* OpenSSL, BoringSSL, and the Go standard library, when those implementations
* are given the same 32-byte seed as raw key material.
*
* When not defined, the function uses the libsodium seeded-keypair convention:
* the private key scalar is derived by computing SHA-512(seed) and taking the
* first 32 bytes. This provides domain separation between the seed and the
* scalar, ensuring that the private key is not trivially related to the seed
* even if the seed has low entropy or is reused in another context. Keypairs
* produced by this method are interoperable with libsodium's
* crypto_box_seed_keypair function when given the same seed, but are NOT
* interoperable with raw RFC 7748 implementations using the same seed.
*
* Note: both methods produce cryptographically secure keypairs. The choice
* affects only interoperability and key derivation provenance, not security
* strength. If keypairs must be compatible with a specific peer implementation,
* the selection here must match the convention used by that implementation.
*
* https://www.rfc-editor.org/rfc/rfc7748
*/
#define QSC_ECDH_RFC_7748_COMPLIANT

/*!
 * \def QSC_ECDH_S1EC25519
 * \brief Enable the ECDH S1EC25519 parameter set.
 */
#define QSC_ECDH_S1EC25519

/*** ML-KEM Kyber ***/

///*!
// * \def QSC_KYBER_S1K2P512
// * \brief Enable the Kyber S1K2P512 parameter set.
// */
//#define QSC_KYBER_S1K2P512

///*!
// * \def QSC_KYBER_S3K3P768
// * \brief Enable the Kyber S3K3P768 parameter set.
// */
//#define QSC_KYBER_S3K3P768

/*!
 * \def QSC_KYBER_S5K4P1024
 * \brief Enable the Kyber S5K5P1024 parameter set.
 */
#define QSC_KYBER_S5K4P1024

///*!
// * \def QSC_KYBER_S6K5P1280
// * \brief Enable the Kyber S6K5P1280 parameter set (experimental).
// */
//#define QSC_KYBER_S6K5P1280

/*** McEliece ***/

///*!
// * \def QSC_MCELIECE_S1N3488T64
// * \brief Enable the McEliece S1-N3488T64 parameter set.
// */
//#define QSC_MCELIECE_S1N3488T64

///*!
// * \def QSC_MCELIECE_S3N4608T96
// * \brief Enable the McEliece S3-N4608T96 parameter set.
// */
//#define QSC_MCELIECE_S3N4608T96

/*!
 * \def QSC_MCELIECE_S5N6688T128
 * \brief Enable the McEliece S5-N6688T128 parameter set.
 */
#define QSC_MCELIECE_S5N6688T128

///*!
// * \def QSC_MCELIECE_S6N6960T119
// * \brief Enable the McEliece S6-N6960T119 parameter set.
// */
//#define QSC_MCELIECE_S6N6960T119

///*!
// * \def QSC_MCELIECE_S7N8192T128
// * \brief Enable the McEliece S7-N8192T128 parameter set.
// */
//#define QSC_MCELIECE_S7N8192T128

/*** Signature Schemes ***/

/*!
 * \def QSC_DILITHIUM_S1P44
 * \brief Enable the Dilithium S1P44 parameter set.
 */
#define QSC_DILITHIUM_S1P44

///*!
// * \def QSC_DILITHIUM_S3P65
// * \brief Enable the Dilithium S3P65 parameter set.
// */
//#define QSC_DILITHIUM_S3P65

/*!
 * \def QSC_DILITHIUM_S5P87
 * \brief Enable the Dilithium S5P87 parameter set.
 */
#define QSC_DILITHIUM_S5P87

/*** ECDSA ***/

/*!
 * \def QSC_ECDSA_S1EC25519
 * \brief Enable the ECDSA S1EC25519 parameter set.
 */
#define QSC_ECDSA_S1EC25519

/*** SphincsPlus ***/

///*!
// * \def QSC_SPHINCSPLUS_S1S128SHAKERS
// * \brief Enable the SphincsPlus S1S128SHAKERS robust small parameter set.
// */
//#define QSC_SPHINCSPLUS_S1S128SHAKERS

///*!
// * \def QSC_SPHINCSPLUS_S3S192SHAKERS
// * \brief Enable the SphincsPlus S3S192SHAKERS robust small parameter set.
// */
//#define QSC_SPHINCSPLUS_S3S192SHAKERS

/*!
 * \def QSC_SPHINCSPLUS_S5S256SHAKERS
 * \brief Enable the SphincsPlus S5S256SHAKERS robust small parameter set.
 */
#define QSC_SPHINCSPLUS_S5S256SHAKERS

///*!
// * \def QSC_SPHINCSPLUS_S6S512SHAKERS
// * \brief Enable the SphincsPlus S6S512SHAKERS robust small parameter set.
// */
//#define QSC_SPHINCSPLUS_S6S512SHAKERS

QSC_CPLUSPLUS_ENABLED_END

#endif
