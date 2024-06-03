
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

#ifndef QSC_MEMUTILS_H
#define QSC_MEMUTILS_H

#include "common.h"

/*
* \file memutils.h
* \brief Contains common memory related functions implemented using SIMD instructions
*/

/**
* \brief Pre-fetch memory to L1 cache
*
* \param address: The array memory address
* \param length: The number of bytes to pre-fetch
*/
QSC_EXPORT_API void qsc_memutils_prefetch_l1(uint8_t* address, size_t length);

/**
* \brief Pre-fetch memory to L2 cache
*
* \param address: The array memory address
* \param length: The number of bytes to pre-fetch
*/
QSC_EXPORT_API void qsc_memutils_prefetch_l2(uint8_t* address, size_t length);

/**
* \brief Pre-fetch memory to L3 cache
*
* \param address: The array memory address
* \param length: The number of bytes to pre-fetch
*/
QSC_EXPORT_API void qsc_memutils_prefetch_l3(uint8_t* address, size_t length);

/**
* \brief Allocate a block of memory
*
* \param length: The length of the requested block
*
* \return Returns the aligned array of bytes, or NULL on failure
*/
QSC_EXPORT_API void* qsc_memutils_malloc(size_t length);

/**
* \brief Resize a block of memory
*
* \param length: The length of the requested block
*
* \return Returns the aligned array of bytes, or NULL on failure
*/
QSC_EXPORT_API void* qsc_memutils_realloc(void* block, size_t length);

/**
* \brief Free a memory block created with alloc
*
* \param block: A pointer to the memory block to release
*/
QSC_EXPORT_API void qsc_memutils_alloc_free(void* block);

/**
* \brief Allocate an aligned 8-bit integer array
*
* \param align: The memory alignment boundary
* \param length: The length of the requested block
*
* \return Returns the aligned array of bytes, or NULL on failure
*/
QSC_EXPORT_API void* qsc_memutils_aligned_alloc(int32_t align, size_t length);

/**
* \brief reallocate an aligned 8-bit integer array
*
* \param align: The memory alignment boundary
* \param length: The length of the requested block
*
* \return Returns the aligned array of bytes, or NULL on failure
*/
QSC_EXPORT_API void* qsc_memutils_aligned_realloc(void* block, size_t length);

/**
* \brief Free an aligned memory block
*
* \param block: A pointer to the memory block to release
*/
QSC_EXPORT_API void qsc_memutils_aligned_free(void* block);

/**
* \brief Erase a block of memory
*
* \param output: A pointer to the memory block to erase
* \param length: The number of bytes to erase
*/
QSC_EXPORT_API void qsc_memutils_clear(void* output, size_t length);

/**
* \brief Compare two byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
* \param length: The number of bytes to compare
*
* \return Returns if the arrays are equivalent
*/
QSC_EXPORT_API bool qsc_memutils_are_equal(const uint8_t* a, const uint8_t* b, size_t length);

/**
* \brief Compare two 16 byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
*
* \return Returns true if the arrays are equivalent
*/
QSC_EXPORT_API bool qsc_memutils_are_equal_128(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 32 byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
*
* \return Returns true if the arrays are equivalent
*/
QSC_EXPORT_API bool qsc_memutils_are_equal_256(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 64 byte arrays for equality
*
* \param a: A pointer to the first array
* \param b: A pointer to the second array
*
* \return Returns true if the arrays are equivalent
*/
QSC_EXPORT_API bool qsc_memutils_are_equal_512(const uint8_t* a, const uint8_t* b);

/**
* \brief Copy a block of memory
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to copy
*/
QSC_EXPORT_API void qsc_memutils_copy(void* output, const void* input, size_t length);

/**
* \brief Compare two 16 byte arrays as 128-bit big endian integers as A is greater than B
*
* \param a: A pointer to the primary array
* \param b: A pointer to the comparison array
*
* \return Returns true if A array is greater than B
*/
QSC_EXPORT_API bool qsc_memutils_greater_than_be128(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 32 byte arrays as 256-bit big endian integers as A is greater than B
*
* \param a: A pointer to the primary array
* \param b: A pointer to the comparison array
*
* \return Returns true if A array is greater than B
*/
QSC_EXPORT_API bool qsc_memutils_greater_than_be256(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 64 byte arrays as 512-bit big endian integers as A is greater than B
*
* \param a: A pointer to the primary array
* \param b: A pointer to the comparison array
*
* \return Returns true if A array is greater than B
*/
QSC_EXPORT_API bool qsc_memutils_greater_than_be512(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 16 byte arrays as 128-bit little endian integers as A is greater than B
*
* \param a: A pointer to the primary array
* \param b: A pointer to the comparison array
*
* \return Returns true if A array is greater than B
*/
QSC_EXPORT_API bool qsc_memutils_greater_than_le128(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 32 byte arrays as 256-bit little endian integers as A is greater than B
*
* \param a: A pointer to the primary array
* \param b: A pointer to the comparison array
*
* \return Returns true if A array is greater than B
*/
QSC_EXPORT_API bool qsc_memutils_greater_than_le256(const uint8_t* a, const uint8_t* b);

/**
* \brief Compare two 64 byte arrays as 512-bit little endian integers as A is greater than B
*
* \param a: A pointer to the primary array
* \param b: A pointer to the comparison array
*
* \return Returns true if A array is greater than B
*/
QSC_EXPORT_API bool qsc_memutils_greater_than_le512(const uint8_t* a, const uint8_t* b);

/**
* \brief Move a block of memory, erasing the previous location
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to copy
*/
QSC_EXPORT_API void qsc_memutils_move(void* output, const void* input, size_t length);

/**
* \brief Erase a memory block securely
*
* \param block: A pointer to the memory block
* \param length: The length of the block
*/
QSC_EXPORT_API void qsc_memutils_secure_erase(void* block, size_t length);

/**
* \brief Free a secure memory block
*
* \param block: A pointer to the memory block
* \param length: The length of the requested block
*/
QSC_EXPORT_API void qsc_memutils_secure_free(void* block, size_t length);

/**
* \brief Allocate an secure 8-bit integer array
*
* \param block: The memory block pointer
* \param length: The length of the requested block
*
* \return Returns the length of the memory block or zero
*/
QSC_EXPORT_API void* qsc_memutils_secure_malloc(size_t length);

/**
* \brief Set a block of memory to a value
*
* \param output: A pointer to the destination array
* \param value: The value to set each byte
* \param length: The number of bytes to change
*/
QSC_EXPORT_API void qsc_memutils_setvalue(void* output, uint8_t value, size_t length);

/**
* \brief Bitwise XOR two blocks of memory
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to XOR
*/
QSC_EXPORT_API void qsc_memutils_xor(uint8_t* output, const uint8_t* input, size_t length);

/**
* \brief Bitwise XOR a block of memory with a byte value
*
* \param output: A pointer to the destination array
* \param value: A byte value
* \param length: The number of bytes to XOR
*/
QSC_EXPORT_API void qsc_memutils_xorv(uint8_t* output, const uint8_t value, size_t length);

/**
* \brief Tests an array for all zeroed elements
*
* \param input: The input array to test
* \param length: The length of the input array
*
* \return Returns true if the array is zeroed
*/
QSC_EXPORT_API bool qsc_memutils_zeroed(const void* input, size_t length);

#endif
