/**
* \file common.h
* \brief <b>Contains global includes and enumerations</b> \n
* This is an internal class.
*
* \date June 14, 2019
*/

#ifndef QCX_COMMON_H
#define QCX_COMMON_H

#include <assert.h>
#include <stdint.h>

//////////////////////////////////////////////////////
//		 *** Constants and System Macros ***		//
// Settings in this section can not be modified		//
//////////////////////////////////////////////////////

// the libraries formal name 'Q,C,X'
#define QCX_LIBRARY_NAME = { 0x51, 0x43, 0x58 };
// the libraries prefix 'C,E,X,-'
#define QCX_LIBRARY_PREFIX = { 0x51, 0x43, 0x58, 0x2D };
// the libraries version number: Major, Minor, Patch, and Release
#define QCX_LIBRARY_VERSION = { 0x00, 0x00, 0x00, 0x01 };

// compiler types; not all will be supported (targets are msvc, mingw, gcc, intel, and clang)
#if defined(_MSC_VER)
#	define QCX_COMPILER_MSC
#elif defined(__MINGW32__)
#	define QCX_COMPILER_MINGW
#elif defined(__CC_ARM)
#	define QCX_COMPILER_ARM
#elif defined(__BORLANDC__)
#	define QCX_COMPILER_BORLAND
#elif defined(__clang__)
#	define QCX_COMPILER_CLANG
#elif defined(__GNUC__)
#	define QCX_COMPILER_GCC
#elif defined(__IBMC__) || defined(__IBMCPP__)
#	define QCX_COMPILER_IBM
#elif defined(__INTEL_COMPILER) || defined(__ICL)
#	define QCX_COMPILER_INTEL
#elif defined(__MWERKS__)
#	define QCX_COMPILER_MWERKS
#elif defined(__OPEN64__)
#	define QCX_COMPILER_OPEN64
#elif defined(__SUNPRO_C)
#	define QCX_COMPILER_SUNPRO
#elif defined(__TURBOC__)
#	define QCX_COMPILER_TURBO
#endif

// is a supported compiler target
#if defined(QCX_COMPILER_MSC) || defined(QCX_COMPILER_MINGW) || defined(QCX_COMPILER_CLANG) || defined(QCX_COMPILER_GCC) || defined(QCX_COMPILER_INTEL)
#	define QCX_SUPPORTED_COMPILER
#else
#	error compiler is incompatible with this library!
#endif

// preprocessor os selection (not all OS's will be supported; targets are win/android/linux/ios)
#if defined(_WIN64) || defined(_WIN32)
#	define QCX_OS_WINDOWS
#	if defined(_WIN64)
#		define QCX_ISWIN64
#	elif defined(_WIN32)
#		define QCX_ISWIN32
#	endif
#elif defined(__ANDROID__)
#	define QCX_OS_ANDROID
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__bsdi__) || defined(__DragonFly__) || defined(_SYSTYPE_BSD)
#	define QCX_OS_BSD
#elif defined(__OpenBSD__)
#	define QCX_OS_OPENBSD
#elif defined(__APPLE__) || defined(__MACH__)
#	include "TargetConditionals.h"
#	define QCX_OS_APPLE
#	if defined(TARGET_OS_IPHONE) && defined(TARGET_IPHONE_SIMULATOR)
#		define QCX_ISIPHONESIM
#	elif TARGET_OS_IPHONE
#		define QCX_ISIPHONE
#	else
#		define QCX_ISOSX
#	endif
#elif defined(__linux)
#	define QCX_OS_LINUX
#elif defined(__unix)
#	define QCX_OS_UNIX
#	if defined(__hpux) || defined(hpux)
#		define QCX_OS_HPUX
#	endif
#	if defined(__sun__) || defined(__sun) || defined(sun)
#		define QCX_OS_SUNUX
#	endif
#endif
#if defined(__posix) || defined(_POSIX_VERSION)
#	define QCX_OS_POSIX
#	define <unistd.h>
#endif

// cpu type (only intel/amd/arm are targeted for support)
#if defined(QCX_COMPILER_MSC)
#	if defined(_M_X64) || defined(_M_AMD64)
#		define QCX_ARCH_X64
#		define QCX_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define QCX_ARCH_AMD64
#		endif
#	elif defined(_M_IX86) || defined(_X86_)
#		define QCX_ARCH_IX86
#		define QCX_ARCH_X86_X64
#	elif defined(_M_ARM)
#		define QCX_ARCH_ARM
#		if defined(_M_ARM_ARMV7VE)
#			define QCX_ARCH_ARMV7VE
#		elif defined(_M_ARM_FP)
#			define QCX_ARCH_ARMFP
#		elif defined(_M_ARM64)
#			define QCX_ARCH_ARM64
#		endif
#	elif defined(_M_IA64)
#		define QCX_ARCH_IA64
#	endif
#elif defined(QCX_COMPILER_GCC)
#	if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64)
#		define QCX_ARCH_X64
#		define QCX_ARCH_X86_X64
#		if defined(_M_AMD64)
#			define QCX_ARCH_AMD64
#		endif
#	elif defined(i386) || defined(__i386) || defined(__i386__)
#		define QCX_ARCH_IX86
#		define QCX_ARCH_X86_X64
#	elif defined(__arm__)
#		define QCX_ARCH_ARM
#		if defined(__aarch64__)
#			define QCX_ARCH_ARM64
#		endif
#	elif defined(__ia64) || defined(__ia64__) || defined(__itanium__)
#		define QCX_ARCH_IA64
#	elif defined(__powerpc64__) || defined(__ppc64__) || defined(__PPC64__) || defined(__64BIT__) || defined(_LP64) || defined(__LP64__)
#		define QCX_ARCH_PPC
#	elif defined(__sparc) || defined(__sparc__)
#		define QCX_ARCH_SPARC
#		if defined(__sparc64__)
#			define QCX_ARCH_SPARC64
#		endif
#	elif defined(__alpha)
#		define QCX_ARCH_ALPHA
#	endif
#endif

// detect endianess
#define QCX_IS_LITTLE_ENDIAN (((union { unsigned x; unsigned char c; }){1}).c)

/*!
\def QCX_STATUS_SUCCESS
* Function return value indicates successful operation
*/
static const int32_t QCX_STATUS_SUCCESS = 0;

/*!
\def QCX_STATUS_FAILURE
* Function return value indicates failed operation
*/
static const int32_t QCX_STATUS_FAILURE = -1;

/*!
\def QCX_ERROR_AUTHENTICATION
* Function return value indicates internal failure
*/
static const int32_t QCX_ERROR_INTERNAL = -2;

/*!
\def QCX_ERROR_AUTHENTICATION
* Function return value indicates authntication failure
*/
static const int32_t QCX_ERROR_AUTHENTICATION = -3;

/*!
\def QCX_ERROR_PROVIDER
* Function return value indicates a random provider failure
*/
static const int32_t QCX_ERROR_PROVIDER = -4;

/*!
\def QCX_MEMORY_ALLOCATION
* Function return value indicates memory allocation failure
*/
static const int32_t QCX_MEMORY_ALLOCATION = -5;

#endif