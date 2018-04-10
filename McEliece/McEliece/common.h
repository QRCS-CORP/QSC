/**
* \file common.h
* \brief <b>Contains global includes and enumerations</b> \n
* This is an internal class.
*
* \date April 3, 2018
*/
#ifndef MQC_COMMON_H
#define MQC_COMMON_H

/* compiler types; not all will be supported (targets are msvc, mingw, gcc, intel, and clang) */
#if defined(_MSC_VER)
#	define MQC_COMPILER_MSC
#elif defined(__MINGW32__)
#	define MQC_COMPILER_MINGW
#elif defined(__CC_ARM)
#	define MQC_COMPILER_ARM
#elif defined(__BORLANDC__)
#	define MQC_COMPILER_BORLAND
#elif defined(__clang__)
#	define MQC_COMPILER_CLANG
#elif defined(__GNUC__)
#	define MQC_COMPILER_GCC
#elif defined(__IBMC__) || defined(__IBMCPP__)
#	define MQC_COMPILER_IBM
#elif defined(__INTEL_COMPILER) || defined(__ICL)
#	define MQC_COMPILER_INTEL
#elif defined(__MWERKS__)
#	define MQC_COMPILER_MWERKS
#elif defined(__OPEN64__)
#	define MQC_COMPILER_OPEN64
#elif defined(__SUNPRO_C)
#	define MQC_COMPILER_SUNPRO
#elif defined(__TURBOC__)
#	define MQC_COMPILER_TURBO
#endif

/* preprocessor os selection (not all OS's will be supported; targets are win/android/linux/ios) */
#if defined(_WIN64) || defined(_WIN32)
#	define MQC_OS_WINDOWS
#	if defined(_WIN64)
#		define MQC_ISWIN64
#	elif defined(_WIN32)
#		define MQC_ISWIN32
#	endif
#elif defined(__ANDROID__)
#	define MQC_OS_ANDROID
#elif defined(__APPLE__) || defined(__MACH__)
#	include "TargetConditionals.h"
#	define MQC_OS_APPLE
#	if defined(TARGET_OS_IPHONE) && defined(TARGET_IPHONE_SIMULATOR)
#		define MQC_ISIPHONESIM
#	elif TARGET_OS_IPHONE
#		define MQC_ISIPHONE
#	else
#		define MQC_ISOSX
#	endif
#elif defined(__linux)
#	define MQC_OS_LINUX
#elif defined(__unix)
#	define MQC_OS_UNIX
#	if defined(__hpux) || defined(hpux)
#		define MQC_OS_HPUX
#	endif
#	if defined(__sun__) || defined(__sun) || defined(sun)
#		define MQC_OS_SUNUX
#	endif
#endif

/* cpu type (only intel/amd/arm are targeted for support) */
#if defined(MQC_COMPILER_MSC)
#	if defined(_M_X64) || defined(_M_AMD64)
#		define MQC_ARCH_X64
#		define MQC_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define MQC_ARCH_AMD64
#		endif
#	elif defined(_M_IX86) || defined(_X86_)
#		define MQC_ARCH_IX86
#		define MQC_ARCH_X86_X64
#	elif defined(_M_ARM)
#		define MQC_ARCH_ARM
#		if defined(_M_ARM_ARMV7VE)
#			define MQC_ARCH_ARMV7VE
#		elif defined(_M_ARM_FP)
#			define MQC_ARCH_ARMFP
#		elif defined(_M_ARM64)
#			define MQC_ARCH_ARM64
#		endif
#	elif defined(_M_IA64)
#		define MQC_ARCH_IA64
#	endif
#elif defined(MQC_COMPILER_GCC)
#	if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
#		define MQC_ARCH_X64
#		define MQC_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define MQC_ARCH_AMD64
#		endif
#	elif defined(i386) || defined(__i386) || defined(__i386__)
#		define MQC_ARCH_IX86
#		define MQC_ARCH_X86_X64
#	elif defined(__arm__)
#		define MQC_ARCH_ARM
#		if defined(__aarch64__)
#			define MQC_ARCH_ARM64
#		endif
#	elif defined(__ia64) || defined(__ia64__) || defined(__itanium__)
#		define MQC_ARCH_IA64
#	elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || defined(__64BIT__) || defined(_LP64) || defined(__LP64__)
#		define MQC_ARCH_PPC
#	elif defined(__sparc) || defined(__sparc__)
#		define MQC_ARCH_SPARC
#		if defined(__sparc64__)
#			define MQC_ARCH_SPARC64
#		endif
#	endif
#endif

#if defined(MQC_ARCH_X64) || defined(MQC_ARCH_ARM64) || defined(MQC_ARCH_IA64) || defined(MQC_ARCH_AMD64) || defined(MQC_ARCH_ARM64) || defined(MQC_ARCH_SPARC64)
#	define MQC_IS_X64
#else
#	define MQC_IS_X86
#endif

/* detect endianess */
#define MQC_IS_LITTLE_ENDIAN (((union { unsigned x; unsigned char c; }){1}).c)

/* define endianess of CPU */
#if (!defined(MQC_IS_LITTLE_ENDIAN))
#	if defined(__sparc) || defined(__sparc__) || defined(__hppa__) || defined(__PPC__) || defined(__mips__) || defined(__MWERKS__) && (!defined(__INTEL__))
#		define MQC_IS_BIG_ENDIAN
#	else
#		define MQC_IS_LITTLE_ENDIAN
#	endif
#endif

#if !defined(__GNUC__)
#	if defined(__attribute__)
#		undef __attribute__
#	endif
#	define __attribute__(a)
#endif

#include <cstdbool>

#if defined(MQC_OS_WINDOWS)
#	include <stdint.h>
#else
#	include "inttypes.h"
#endif

// Note: AVX512 is currently untested, this flag enables support on a compliant system
//#define MQC_AVX512_SUPPORTED

#if defined(__AVX512F__) && (__AVX512F__ == 1) && defined(MQC_AVX512_SUPPORTED)
#	include <immintrin.h>
#	if (!defined(__AVX512__))
#		define __AVX512__
#	endif
#endif

/*! \enum mqc_status
* Contains state and error return codes
*/
typedef enum
{
	MQC_STATUS_FAILURE = 0,	/*!< signals operation failure */
	MQC_STATUS_SUCCESS = 1,	/*!< signals operation success */
	MQC_ERROR_AUTHFAIL = 2,	/*!< seed authentication failure */
	MQC_ERROR_RANDFAIL = 3,	/*!< system random failure */
	MQC_ERROR_INVALID = 4,	/*!< invalid parameter input */
	MQC_ERROR_INTERNAL = 5,	/*!< anonymous internal failure  */
	MQC_ERROR_KEYGEN = 6	/*!< key generation failure  */
} mqc_status;

#endif
