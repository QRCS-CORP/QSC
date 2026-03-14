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

#ifndef QSC_MEMUTILS_H
#define QSC_MEMUTILS_H

#include "qsccommon.h"
#include "intrinsics.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file memutils.h
 * \brief Contains common memory-related functions implemented using SIMD instructions.
 *
 * \details
 * This header defines utility functions for memory allocation, reallocation, secure memory operations,
 * and memory comparisons. It provides functions to flush cache lines, prefetch memory at various cache levels,
 * clear memory blocks, and perform constant-time comparisons.
 *
 * \section memutils_links Reference Links:
 * - <a href="https://software.intel.com/content/www/us/en/develop/articles/intel-intrinsics-guide.html">Intel Intrinsics Guide (AVX/AVX2/AVX512)</a>
 * - <a href="https://developer.amd.com/resources/developer-guides-manuals/">AMD Developer Guides for SIMD Optimization</a>
 */

/*!
 * \def QSC_MEMUTILS_MEMORY_FENCE
 * \brief A memory fence macro.
 */
#if defined(QSC_SYSTEM_COMPILER_MSC)
	#include <intrin.h>
	#define QSC_MEMUTILS_MEMORY_FENCE() _ReadWriteBarrier()
#elif defined(QSC_SYSTEM_COMPILER_GCC)
	#define QSC_MEMUTILS_MEMORY_FENCE() __asm__ __volatile__ ("" ::: "memory")
#else
	#define QSC_MEMUTILS_MEMORY_FENCE()
#endif

/*!
 * \def QSC_MEMUTILS_CACHE_LINE_SIZE
 * \brief The default cache line size.
 */
#define QSC_MEMUTILS_CACHE_LINE_SIZE 64ULL

/*!
 * \def QSC_MEMUTILS_MEMORY_PAGE_SIZE
 * \brief The default memory page size.
 */
#define QSC_MEMUTILS_MEMORY_PAGE_SIZE 4096ULL

/**
 * \brief Flush a cache line.
 *
 * \param address:	[void*] The memory address.
 */
QSC_EXPORT_API void qsc_memutils_flush_cache_line(void *address);

/**
 * \brief Prefetch memory to L1 cache.
 *
 * \param address:	[uint8_t*] The array memory address.
 * \param length:	[size_t] The number of bytes to prefetch.
 */
QSC_EXPORT_API void qsc_memutils_prefetch_l1(uint8_t* address, size_t length);

/**
 * \brief Prefetch memory to L2 cache.
 *
 * \param address:	[uint8_t*] The array memory address.
 * \param length:	[size_t]	The number of bytes to prefetch.
 */
QSC_EXPORT_API void qsc_memutils_prefetch_l2(uint8_t* address, size_t length);

/**
 * \brief Prefetch memory to L3 cache.
 *
 * \param address:	[uint8_t*] The array memory address.
 * \param length:	[size_t] The number of bytes to prefetch.
 */
QSC_EXPORT_API void qsc_memutils_prefetch_l3(uint8_t* address, size_t length);

/**
 * \brief Allocate a block of memory.
 *
 * \param length:	[size_t] The length of the requested block.
 *
 * \return			[void*] Returns the aligned array of bytes, or NULL on failure.
 */
QSC_EXPORT_API void* qsc_memutils_malloc(size_t length);

/**
 * \brief Get the system oage size.
 *
 * \return			[void*] Returns the system page size.
 */
QSC_EXPORT_API size_t qsc_memutils_page_size(void);

/**
 * \brief Resize a block of memory.
 *
 * \param block:	[void*] The current memory block.
 * \param length:	[size_t] The new length of the block.
 *
 * \return			[void*] Returns the aligned array of bytes, or NULL on failure.
 */
QSC_EXPORT_API void* qsc_memutils_realloc(void* block, size_t length);

/**
 * \brief Free a memory block created with malloc.
 *
 * \param block:	[void*] A pointer to the memory block to release.
 */
QSC_EXPORT_API void qsc_memutils_alloc_free(void* block);

/**
 * \brief Allocate an aligned 8-bit integer array.
 *
 * \param align:	[int32_t] The memory alignment boundary.
 * \param length:	[size_t]  The length of the requested block.
 *
 * \return			[void*] Returns the aligned array of bytes, or NULL on failure.
 */
QSC_EXPORT_API void* qsc_memutils_aligned_alloc(int32_t align, size_t length);

/**
 * \brief Reallocate an aligned 8-bit integer array.
 *
 * \param block:	[void*] The current memory block.
 * \param length:	[size_t] The new length of the block.
 *
 * \return			[void*] Returns the aligned array of bytes, or NULL on failure.
 */
QSC_EXPORT_API void* qsc_memutils_aligned_realloc(void* block, size_t length);

/**
 * \brief Free an aligned memory block.
 *
 * \param block:	[void*] A pointer to the memory block to release.
 */
QSC_EXPORT_API void qsc_memutils_aligned_free(void* block);

/**
 * \brief Erase a block of memory.
 *
 * \param output:	[void*] A pointer to the memory block to erase.
 * \param length:	[size_t] The number of bytes to erase.
 */
QSC_EXPORT_API void qsc_memutils_clear(void* output, size_t length);

/**
 * \brief Check if all array members are the same.
 *
 * \param input:	[const uint8_t*] A pointer to the array to test.
 * \param length:	[size_t] The number of bytes in the array.
 *
 * \return			[bool] Returns true if array members are all equivalent.
 */
QSC_EXPORT_API bool qsc_memutils_array_uniform(const uint8_t* input, size_t length);

/**
 * \brief Compare two byte arrays for equality.
 *
 * \param a:		[const uint8_t*] A pointer to the first array.
 * \param b:		[const uint8_t*] A pointer to the second array.
 * \param length:	[size_t] The number of bytes to compare.
 *
 * \return			[bool] Returns true if the arrays are equivalent.
 */
QSC_EXPORT_API bool qsc_memutils_are_equal(const uint8_t* a, const uint8_t* b, size_t length);

/**
 * \brief Compare two 16-byte arrays for equality.
 *
 * \param a:		[const uint8_t*] A pointer to the first array.
 * \param b:		[const uint8_t*] A pointer to the second array.
 *
 * \return			[bool] Returns true if the arrays are equivalent.
 */
QSC_EXPORT_API bool qsc_memutils_are_equal_128(const uint8_t* a, const uint8_t* b);

/**
 * \brief Compare two 32-byte arrays for equality.
 *
 * \param a:		[const uint8_t*] A pointer to the first array.
 * \param b:		[const uint8_t*] A pointer to the second array.
 *
 * \return			[bool] Returns true if the arrays are equivalent.
 */
QSC_EXPORT_API bool qsc_memutils_are_equal_256(const uint8_t* a, const uint8_t* b);

/**
 * \brief Compare two 64-byte arrays for equality.
 *
 * \param a:		[const uint8_t*] A pointer to the first array.
 * \param b:		[const uint8_t*] A pointer to the second array.
 *
 * \return			[bool] Returns true if the arrays are equivalent.
 */
QSC_EXPORT_API bool qsc_memutils_are_equal_512(const uint8_t* a, const uint8_t* b);

/**
 * \brief Copy a block of memory.
 *
 * \param output:	[void*] A pointer to the destination array.
 * \param input:	[const void*] A pointer to the source array.
 * \param length:	[size_t] The number of bytes to copy.
 */
QSC_EXPORT_API void qsc_memutils_copy(void* output, const void* input, size_t length);

/**
 * \brief Emulate the _mm_clmulepi64_si128 intrinsic.
 *
 * \param r:		[uint64_t[2]] Output array of two 64-bit integers representing the 128-bit result.
 * \param a:		[const uint64_t[2]] Input 128-bit operand, represented as an array of two 64-bit values.
 * \param b:		[const uint64_t[2]] Input 128-bit operand, represented as an array of two 64-bit values.
 * \param imm8:		[int32_t] Controls which 64-bit halves to use.
 */
QSC_EXPORT_API void qsc_memutils_clmulepi64_si128(uint64_t r[2U], const uint64_t a[2U], const uint64_t b[2U], int32_t imm8);

#if defined(QSC_SYSTEM_HAS_AVX) && defined(QSC_SYSTEM_X86)
/**
 * \brief Multiply two 256-bit field elements (each represented as two 128-bit integers) 
 * to produce a 512-bit product.
 *
 * \param r:		[__m128i[4]] 512-bit product (r[0] = least-significant 128 bits, r[3] = most-significant 128 bits).
 * \param a:		[const __m128i[2]] First 256-bit operand (a[0] = lower 128 bits, a[1] = upper 128 bits).
 * \param b:		[const __m128i[2]] Second 256-bit operand (same ordering).
 */
QSC_EXPORT_API void qsc_memutils_clmulepi64_si256_avx(__m128i r[4U], const __m128i a[2U], const __m128i b[2U]);
#endif

/**
 * \brief Multiply two 256-bit field elements (each represented as two 128-bit integers) 
 * to produce a 512-bit product.
 *
 * \param r:		[uint64_t[8]] 512-bit product (r[0] = least-significant 64 bits, r[7] = most-significant 64 bits).
 * \param a:		[const uint64_t[4]]  First 256-bit operand (a[0] = lower 64 bits, a[3] = upper 64 bits).
 * \param b:		[const uint64_t[4]]  Second 256-bit operand (same ordering).
 */
QSC_EXPORT_API void qsc_memutils_clmulepi64_si256(uint64_t r[8U], const uint64_t a[4U], const uint64_t b[4U]);

/**
 * \brief Compare two 16-byte arrays as 128-bit big-endian integers to determine if A is greater than B.
 *
 * \param a:		[const uint8_t*] Pointer to the primary array.
 * \param b:		[const uint8_t*] Pointer to the comparison array.
 *
 * \return			[bool] Returns true if array A is greater than array B.
 */
QSC_EXPORT_API bool qsc_memutils_greater_than_be128(const uint8_t* a, const uint8_t* b);

/**
 * \brief Compare two 32-byte arrays as 256-bit big-endian integers to determine if A is greater than B.
 *
 * \param a:		[const uint8_t*] Pointer to the primary array.
 * \param b:		[const uint8_t*] Pointer to the comparison array.
 *
 * \return			[bool] Returns true if array A is greater than array B.
 */
QSC_EXPORT_API bool qsc_memutils_greater_than_be256(const uint8_t* a, const uint8_t* b);

/**
 * \brief Compare two 64-byte arrays as 512-bit big-endian integers to determine if A is greater than B.
 *
 * \param a:		[const uint8_t*] Pointer to the primary array.
 * \param b:		[const uint8_t*] Pointer to the comparison array.
 *
 * \return			[bool] Returns true if array A is greater than array B.
 */
QSC_EXPORT_API bool qsc_memutils_greater_than_be512(const uint8_t* a, const uint8_t* b);

/**
 * \brief Compare two 16-byte arrays as 128-bit little-endian integers to determine if A is greater than B.
 *
 * \param a:		[const uint8_t*] Pointer to the primary array.
 * \param b:		[const uint8_t*] Pointer to the comparison array.
 *
 * \return			[bool] Returns true if array A is greater than array B.
 */
QSC_EXPORT_API bool qsc_memutils_greater_than_le128(const uint8_t* a, const uint8_t* b);

/**
 * \brief Compare two 32-byte arrays as 256-bit little-endian integers to determine if A is greater than B.
 *
 * \param a:		[const uint8_t*] Pointer to the primary array.
 * \param b:		[const uint8_t*] Pointer to the comparison array.
 *
 * \return			[bool] Returns true if array A is greater than array B.
 */
QSC_EXPORT_API bool qsc_memutils_greater_than_le256(const uint8_t* a, const uint8_t* b);

/**
 * \brief Compare two 64-byte arrays as 512-bit little-endian integers to determine if A is greater than B.
 *
 * \param a:		[const uint8_t*] Pointer to the primary array.
 * \param b:		[const uint8_t*] Pointer to the comparison array.
 *
 * \return			[bool] Returns true if array A is greater than array B.
 */
QSC_EXPORT_API bool qsc_memutils_greater_than_le512(const uint8_t* a, const uint8_t* b);

/**
 * \brief Move a block of memory, erasing the previous location.
 *
 * \param output:	[void*] Pointer to the destination array.
 * \param input:	[const void*] Pointer to the source array.
 * \param length:	[size_t] The number of bytes to copy.
 */
QSC_EXPORT_API void qsc_memutils_move(void* output, const void* input, size_t length);

/**
 * \brief Securely erase a block of memory.
 *
 * \param block:	[void*]  Pointer to the memory block.
 * \param length:	[size_t] The length of the block.
 */
QSC_EXPORT_API void qsc_memutils_secure_erase(void* block, size_t length);

/**
 * \brief Free a secure memory block.
 *
 * \param block:	[void*]  Pointer to the memory block.
 * \param length:	[size_t] The length of the requested block.
 */
QSC_EXPORT_API void qsc_memutils_secure_free(void* block, size_t length);

/**
 * \brief Allocate a secure 8-bit integer array.
 *
 * \param length:	[size_t] The length of the requested block.
 *
 * \return			[void*] Returns the secure allocated memory block, or NULL on failure.
 */
QSC_EXPORT_API void* qsc_memutils_secure_malloc(size_t length);

/**
 * \brief Set a block of memory to a specific value.
 *
 * \param output:	[void*] Pointer to the destination array.
 * \param length:	[size_t] The number of bytes to change.
 * \param value:	[uint8_t] The value to set each byte.
 */
QSC_EXPORT_API void qsc_memutils_set_value(void* output, size_t length, uint8_t value);

/**
 * \brief Bitwise XOR two blocks of memory.
 *
 * \param output:	[uint8_t*] Pointer to the destination array.
 * \param input:	[const uint8_t*] Pointer to the source array.
 * \param length:	[size_t] The number of bytes to XOR.
 */
QSC_EXPORT_API void qsc_memutils_xor(uint8_t* output, const uint8_t* input, size_t length);

/**
 * \brief Bitwise XOR a block of memory with a byte value.
 *
 * \param output:	[uint8_t*] Pointer to the destination array.
 * \param value:	[uint8_t] The byte value.
 * \param length:	[size_t] The number of bytes to XOR.
 */
QSC_EXPORT_API void qsc_memutils_xorv(uint8_t* output, const uint8_t value, size_t length);

/**
 * \brief Test if an array is entirely zeroed.
 *
 * \param input:	[const void*] Pointer to the input array.
 * \param length:	[size_t] The length of the array.
 *
 * \return			[bool] Returns true if the array is zeroed.
 */
QSC_EXPORT_API bool qsc_memutils_zeroed(const void* input, size_t length);

QSC_CPLUSPLUS_ENABLED_END

#endif
