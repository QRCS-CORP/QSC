/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
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
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_INTUTILS_H
#define QSC_INTUTILS_H

#include "common.h"
#include "intrinsics.h"

/*!
 * \file intutils.h
 * \brief This file contains common integer manipulation and conversion functions.
 *
 * \details
 * The functions in this file provide a variety of operations on integers and arrays of integers,
 * including byte-swapping, bit-reversal, rotation, constant-time comparisons, and conversions between
 * different endianness. Additional utility functions such as computing the absolute value, exponential,
 * natural logarithm, and square root are also provided using series approximations and iterative methods.
 */

/*!
 * \def QSC_INTUTILS_KB_SIZE
 * \brief The number of bytes in a kilobyte.
 */
#define QSC_INTUTILS_KB_SIZE 1000ULL

/*!
 * \def QSC_INTUTILS_KIB_SIZE
 * \brief The number of bytes in a kibibyte.
 */
#define QSC_INTUTILS_KIB_SIZE 1024ULL

/*!
 * \def QSC_INTUTILS_MB_SIZE
 * \brief The number of bytes in a megabyte.
 */
#define QSC_INTUTILS_MB_SIZE 1000000ULL

/*!
 * \def QSC_INTUTILS_MIB_SIZE
 * \brief The number of bytes in a mebibyte.
 */
#define QSC_INTUTILS_MIB_SIZE 1048576ULL

/*!
 * \def QSC_INTUTILS_GB_SIZE
 * \brief The number of bytes in a gigabyte.
 */
#define QSC_INTUTILS_GB_SIZE 1000000000ULL

/*!
 * \def QSC_INTUTILS_GIB_SIZE
 * \brief The number of bytes in a gibibyte.
 */
#define QSC_INTUTILS_GIB_SIZE 1073741824ULL

/*!
 * \def QSC_INTUTILS_TB_SIZE
 * \brief The number of bytes in a terabyte.
 */
#define QSC_INTUTILS_TB_SIZE 1000000000000ULL

/*!
 * \def QSC_INTUTILS_TIB_SIZE
 * \brief The number of bytes in a tebibyte.
 */
#define QSC_INTUTILS_TIB_SIZE 1099511627776ULL

/*!
 * \def QSC_INTUTILS_PB_SIZE
 * \brief The number of bytes in a petabyte.
 */
#define QSC_INTUTILS_PB_SIZE 1000000000000000ULL

/*!
 * \def QSC_INTUTILS_PIB_SIZE
 * \brief The number of bytes in a pebibyte.
 */
#define QSC_INTUTILS_PIB_SIZE 1125899906842624ULL

/*!
 * \def QSC_INTUTILS_EB_SIZE
 * \brief The number of bytes in an exabyte.
 */
#define QSC_INTUTILS_EB_SIZE 1000000000000000000ULL

/*!
 * \def QSC_INTUTILS_EIB_SIZE
 * \brief The number of bytes in an exbibyte.
 */
#define QSC_INTUTILS_EIB_SIZE 1152921504606846976ULL

/**
 * \brief Compare two arrays of 8-bit integers for equality.
 * \ warning This function is not constant time. 
 * Use the \c qsc_intutils_verify for constant time operations.
 *
 * \param a:		[const uint8_t*] The first array.
 * \param b:		[const uint8_t*] The second array.
 * \param length:	[size_t] The number of bytes to compare.
 * \return			[bool] Returns true if the arrays are equal.
 */
QSC_EXPORT_API bool qsc_intutils_are_equal8(const uint8_t* a, const uint8_t* b, size_t length);

/**
 * \brief Convert an 8-bit integer array to a 16-bit big-endian integer.
 *
 * \param input:	[const uint8_t*] The source 8-bit array.
 * \return			[uint16_t] Returns the 16-bit big-endian integer.
 */
QSC_EXPORT_API uint16_t qsc_intutils_be8to16(const uint8_t* input);

/**
 * \brief Convert an 8-bit integer array to a 32-bit big-endian integer.
 *
 * \param input:	[const uint8_t*] The source 8-bit array.
 * \return			[uint32_t] Returns the 32-bit big-endian integer.
 */
QSC_EXPORT_API uint32_t qsc_intutils_be8to32(const uint8_t* input);

/**
 * \brief Convert an 8-bit integer array to a 64-bit big-endian integer.
 *
 * \param input:	[const uint8_t*] The source 8-bit array.
 * \return			[uint64_t] Returns the 64-bit big-endian integer.
 */
QSC_EXPORT_API uint64_t qsc_intutils_be8to64(const uint8_t* input);

/**
 * \brief Convert a 16-bit integer to a big-endian 8-bit integer array.
 *
 * \param output:	[uint8_t*] The destination array.
 * \param value:	[uint16_t] The 16-bit integer.
 */
QSC_EXPORT_API void qsc_intutils_be16to8(uint8_t* output, uint16_t value);

/**
 * \brief Convert a 32-bit integer to a big-endian 8-bit integer array.
 *
 * \param output:	[uint8_t*] The destination array.
 * \param value:	[uint32_t] The 32-bit integer.
 */
QSC_EXPORT_API void qsc_intutils_be32to8(uint8_t* output, uint32_t value);

/**
 * \brief Convert a 64-bit integer to a big-endian 8-bit integer array.
 *
 * \param output:	[uint8_t*] The destination array.
 * \param value:	[uint64_t] The 64-bit integer.
 */
QSC_EXPORT_API void qsc_intutils_be64to8(uint8_t* output, uint64_t value);

/**
 * \brief Increment an 8-bit integer array as a segmented big-endian integer.
 *
 * \param output:	[uint8_t*] The counter array.
 * \param otplen:	[size_t] The length of the counter array.
 */
QSC_EXPORT_API void qsc_intutils_be8increment(uint8_t* output, size_t otplen);

/**
 * \brief Reverse the bits of an integer.
 *
 * \param x: The integer.
 * \param bits:		[size_t] The number of bits to reverse.
 * \return			[size_t] Returns the integer with its bits reversed.
 */
QSC_EXPORT_API size_t qsc_intutils_bit_reverse(size_t x, uint32_t bits);

/**
 * \brief Reverse the bits of a 64-bit integer.
 *
 * \param x:		[uint64_t] The 64-bit integer.
 * \return			[uint64_t] Returns the 64-bit integer with its bits reversed.
 */
QSC_EXPORT_API uint64_t qsc_intutils_bit_reverse_u64(uint64_t x);

/**
 * \brief Reverse the bits of a 32-bit integer.
 *
 * \param x:		[uint32_t] The 32-bit integer.
 * \return			[uint32_t] Returns the 32-bit integer with its bits reversed.
 */
QSC_EXPORT_API uint32_t qsc_intutils_bit_reverse_u32(uint32_t x);

/**
 * \brief Reverse the bits of a 16-bit integer.
 *
 * \param x:		[uint16_t] The 16-bit integer.
 * \return			[uint16_t] Returns the 16-bit integer with its bits reversed.
 */
QSC_EXPORT_API uint16_t qsc_intutils_bit_reverse_u16(uint16_t x);

#if defined(QSC_SYSTEM_HAS_AVX)
/**
 * \brief Byte-swap an array of 32-bit integers.
 *
 * \param dest:		[uint32_t*] The destination array.
 * \param source:	[const uint32_t*] The source array.
 * \param length:	[size_t] The number of 32-bit integers to swap.
 */
QSC_EXPORT_API void qsc_intutils_bswap32(uint32_t* dest, const uint32_t* source, size_t length);

/**
 * \brief Byte-swap an array of 64-bit integers.
 *
 * \param dest:		[uint64_t*] The destination array.
 * \param source:	[const uint64_t*] The source array.
 * \param length:	[size_t] The number of 64-bit integers to swap.
 */
QSC_EXPORT_API void qsc_intutils_bswap64(uint64_t* dest, const uint64_t* source, size_t length);
#endif

/*!
 * \brief Computes the absolute value of a double.
 *
 * \param a:		[double] The input value.
 * 
 * \return			[double] The absolute value of \c a.
 */
QSC_EXPORT_API double qsc_intutils_calculate_abs(double a);

/*!
 * \brief Computes the exponential function exp(x) using a Taylor series.
 *
 * Special cases:
 * - If x is NaN, the function returns NaN.
 * - If x is greater than approximately 709.782712893384, the function returns positive infinity.
 * - If x is less than approximately -745.133219101941, the function returns 0.
 *
 * The function computes exp(x) via the Taylor series:
 *   exp(x) = 1 + x/1! + x^2/2! + x^3/3! + ...
 * and stops when the absolute value of the term is less than a relative tolerance.
 *
 * \param x		[double] The exponent.
 * 
 * \return		[double] The computed exp(x) value.
 */
QSC_EXPORT_API double qsc_intutils_calculate_exp(double x);

/**
 * \brief Return the absolute value of a double.
 *
 * \param x:		[double] The input double.
 * \return			[double] Returns the absolute value.
 */
QSC_EXPORT_API double qsc_intutils_calculate_fabs(double x);

/*!
 * \brief Computes the natural logarithm ln(x) without using math.h.
 *
 * Special cases:
 *  - If x is NaN, returns NaN.
 *  - If x < 0, returns NaN.
 *  - If x == 0, returns negative infinity.
 *  - If x is extremely large, returns positive infinity.
 *
 * For 0 < x < 1e300, this function first scales x into the interval [1,2)
 * by repeatedly dividing or multiplying by 2, and then computes ln(x) using the
 * series expansion:
 *
 *    ln(x) = 2 * ( y + y^3/3 + y^5/5 + ... )
 *
 * where y = (x - 1)/(x + 1). The series continues until the current term falls
 * below a fixed tolerance.
 *
 * \param x:		[double] The input value.
 * \return			[double] The natural logarithm of x.
 */
QSC_EXPORT_API double qsc_intutils_calculate_log(double x);

/*!
 * \brief Computes the square root of a nonnegative number without using math.h.
 *
 * Special cases:
 * - If x is negative, the function returns NaN.
 * - If x is 0, the function returns 0.
 *
 * For x > 0, Newton-Raphson iteration is used:
 *   guess_{n+1} = 0.5 * (guess_n + x / guess_n)
 * The iteration stops when the absolute difference between successive guesses is
 * less than a small fraction of the guess (relative tolerance).
 *
 * \param x:		[double] The input value.
 * \return			[double] The square root of x, or NaN if x is negative.
 */
QSC_EXPORT_API double qsc_intutils_calculate_sqrt(double x);

/**
 * \brief Set an array of 8-bit integers to zero.
 *
 * \param a:		[uint8_t*] The array to zeroize.
 * \param count:	[size_t] The number of elements to zeroize.
 */
QSC_EXPORT_API void qsc_intutils_clear8(uint8_t* a, size_t count);

/**
 * \brief Set an array of 16-bit integers to zero.
 *
 * \param a:		[uint16_t*] The array to zeroize.
 * \param count:	[size_t] The number of elements to zeroize.
 */
QSC_EXPORT_API void qsc_intutils_clear16(uint16_t* a, size_t count);

/**
 * \brief Set an array of 32-bit integers to zero.
 *
 * \param a:		[uint32_t*] The array to zeroize.
 * \param count:	[size_t] The number of elements to zeroize.
 */
QSC_EXPORT_API void qsc_intutils_clear32(uint32_t* a, size_t count);

/**
 * \brief Set an array of 64-bit integers to zero.
 *
 * \param a:		[uint64_t*] The array to zeroize.
 * \param count:	[size_t] The number of elements to zeroize.
 */
QSC_EXPORT_API void qsc_intutils_clear64(uint64_t* a, size_t count);

/**
 * \brief Perform a constant-time conditional move on two arrays of 8-bit integers.
 *
 * \param dest:		[uint8_t*] The destination array.
 * \param source:	[const uint8_t*] The source array.
 * \param length:	[size_t] The number of bytes to move.
 * \param cond:		[uint8_t] The condition (1 to move, 0 to leave unchanged).
 */
QSC_EXPORT_API void qsc_intutils_cmov(uint8_t* dest, const uint8_t* source, size_t length, uint8_t cond);

/**
 * \brief Expand an integer mask in constant time.
 *
 * \param x:		[size_t] The N-bit word.
 * \return			[size_t] Returns the expanded mask.
 */
QSC_EXPORT_API size_t qsc_intutils_expand_mask(size_t x);

/**
 * \brief Check if two integers are equal.
 *
 * \param x:		[size_t] The first integer.
 * \param y:		[size_t] The second integer.
 * \return			[bool] Returns true if x equals y.
 */
QSC_EXPORT_API bool qsc_intutils_are_equal(size_t x, size_t y);

/**
 * \brief Check if an integer is greater than or equal to another.
 *
 * \param x:		[size_t] The base integer.
 * \param y:		[size_t] The comparison integer.
 * \return			[bool] Returns true if x is greater than or equal to y.
 */
QSC_EXPORT_API bool qsc_intutils_is_gte(size_t x, size_t y);

/**
 * \brief Convert a hexadecimal string to a byte array.
 *
 * \param hexstr:	[const char*] The hexadecimal string.
 * \param output:	[uint8_t*] The output array.
 * \param otplen:	[size_t] The length of the output array.
 */
QSC_EXPORT_API void qsc_intutils_hex_to_bin(const char* hexstr, uint8_t* output, size_t otplen);

/**
 * \brief Convert a byte array to a hexadecimal string.
 *
 * \param input:	[const uint8_t*] The input array.
 * \param hexstr:	[char*] The output hexadecimal string; must be twice the size of the input array.
 * \param inplen:	[size_t] The length of the input array.
 */
QSC_EXPORT_API void qsc_intutils_bin_to_hex(const uint8_t* input, char* hexstr, size_t inplen);

/**
 * \brief Increment an 8-bit integer array as a segmented little-endian integer.
 *
 * \param output:	[uint8_t*] The counter array.
 * \param otplen:	[size_t] The length of the counter array.
 */
QSC_EXPORT_API void qsc_intutils_le8increment(uint8_t* output, size_t otplen);

#if defined(QSC_SYSTEM_HAS_AVX)
/**
 * \brief Increment the low 64-bit integer of a 128-bit vector (little-endian) by one.
 *
 * \param counter:	[__m128i*] Pointer to the counter vector.
 */
QSC_EXPORT_API void qsc_intutils_leincrement_x128(__m128i* counter);
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
/**
 * \brief Increment the low 64-bit integer of a 512-bit vector (little-endian) by one.
 *
 * \param counter:	[__m512i*] Pointer to the counter vector.
 */
QSC_EXPORT_API void qsc_intutils_leincrement_x512(__m512i* counter);
#endif

/**
 * \brief Convert an 8-bit integer array to a 16-bit little-endian integer.
 *
 * \param input:	[const uint8_t*] The source array.
 * \return			[uint16_t] Returns the 16-bit little-endian integer.
 */
QSC_EXPORT_API uint16_t qsc_intutils_le8to16(const uint8_t* input);

/**
 * \brief Convert an 8-bit integer array to a 32-bit little-endian integer.
 *
 * \param input:	[const uint8_t*] The source array.
 * \return			[uint32_t] Returns the 32-bit little-endian integer.
 */
QSC_EXPORT_API uint32_t qsc_intutils_le8to32(const uint8_t* input);

/**
 * \brief Convert an 8-bit integer array to a 64-bit little-endian integer.
 *
 * \param input:	[const uint8_t*] The source array.
 * \return			[uint64_t] Returns the 64-bit little-endian integer.
 */
QSC_EXPORT_API uint64_t qsc_intutils_le8to64(const uint8_t* input);

/**
 * \brief Convert a 16-bit integer to a little-endian 8-bit integer array.
 *
 * \param output:	[uint8_t*] The destination array.
 * \param value:	[uint16_t] The 16-bit integer.
 */
QSC_EXPORT_API void qsc_intutils_le16to8(uint8_t* output, uint16_t value);

/**
 * \brief Convert a 32-bit integer to a little-endian 8-bit integer array.
 *
 * \param output:	[uint8_t*] The destination array.
 * \param value:	[uint32_t] The 32-bit integer.
 */
QSC_EXPORT_API void qsc_intutils_le32to8(uint8_t* output, uint32_t value);

/**
 * \brief Convert a 64-bit integer to a little-endian 8-bit integer array.
 *
 * \param output:	[uint8_t*] The destination array.
 * \param value:	[uint64_t] The 64-bit integer.
 */
QSC_EXPORT_API void qsc_intutils_le64to8(uint8_t* output, uint64_t value);

/**
 * \brief Return the larger of two integers.
 *
 * \param a:		[size_t] The first integer.
 * \param b:		[size_t] The second integer.
 * \return			[size_t] Returns the larger integer.
 */
QSC_EXPORT_API size_t qsc_intutils_max(size_t a, size_t b);

/**
 * \brief Return the smaller of two integers.
 *
 * \param a:		[size_t] The first integer.
 * \param b:		[size_t] The second integer.
 * \return			[size_t] Returns the smaller integer.
 */
QSC_EXPORT_API size_t qsc_intutils_min(size_t a, size_t b);

/**
 * \brief Count the number of bits set in a 32-bit unsigned integer.
 *
 * \param v:		[uint32_t] The 32-bit integer.
 * \return			[uint32_t] Returns the number of bits set.
 */
QSC_EXPORT_API uint32_t qsc_intutils_popcount32(uint32_t v);

#if defined(QSC_SYSTEM_HAS_AVX)
/**
 * \brief Reverse the bytes of a 128-bit integer vector.
 *
 * \param input:	[const __m128i*] The source vector.
 * \param output:	[__m128i*] The destination vector.
 */
QSC_EXPORT_API void qsc_intutils_reverse_bytes_x128(const __m128i* input, __m128i* output);
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
/**
 * \brief Reverse the bytes of a 512-bit integer vector.
 *
 * \param input:	[const __m512i*] The source vector.
 * \param output:	[__m512i*] The destination vector.
 */
QSC_EXPORT_API void qsc_intutils_reverse_bytes_x512(const __m512i* input, __m512i* output);
#endif

/**
 * \brief Rotate an unsigned 32-bit integer to the left.
 *
 * \param value:	[uint32_t] The integer value.
 * \param shift:	[size_t] The number of bits to shift.
 * \return			[uint32_t] Returns the rotated integer.
 */
QSC_EXPORT_API uint32_t qsc_intutils_rotl32(uint32_t value, size_t shift);

/**
 * \brief Rotate an unsigned 64-bit integer to the left.
 *
 * \param value:	[uint64_t] The integer value.
 * \param shift:	[size_t] The number of bits to shift.
 * \return			[uint64_t] Returns the rotated integer.
 */
QSC_EXPORT_API uint64_t qsc_intutils_rotl64(uint64_t value, size_t shift);

/**
 * \brief Rotate an unsigned 32-bit integer to the right.
 *
 * \param value:	[uint32_t] The integer value.
 * \param shift:	[size_t] The number of bits to shift.
 * \return			[uint32_t] Returns the rotated integer.
 */
QSC_EXPORT_API uint32_t qsc_intutils_rotr32(uint32_t value, size_t shift);

/**
 * \brief Rotate an unsigned 64-bit integer to the right.
 *
 * \param value:	[uint64_t] The integer value.
 * \param shift:	[size_t] The number of bits to shift.
 * \return			[uint64_t] Returns the rotated integer.
 */
QSC_EXPORT_API uint64_t qsc_intutils_rotr64(uint64_t value, size_t shift);

/**
 * \brief Constant-time comparison of two 8-bit integer arrays.
 *
 * \param a:		[const uint8_t*] The first array.
 * \param b:		[const uint8_t*] The second array.
 * \param length:	[size_t] The number of bytes to compare.
 * \return			[int32_t] Returns zero if the arrays are equivalent.
 */
QSC_EXPORT_API int32_t qsc_intutils_verify(const uint8_t* a, const uint8_t* b, size_t length);

#endif
