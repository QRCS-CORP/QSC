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
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_DONNA128_H
#define QSC_DONNA128_H

#include "common.h"

/**
 * \file donna128.h
 * \brief Donna128 128-bit Integer Arithmetic Functions
 *
 * \details
 * This module provides a comprehensive set of operations for performing arithmetic on
 * 128-bit integers using a software-based implementation. The Donna128 arithmetic
 * functions include operations such as addition, subtraction, multiplication, and
 * modular reduction of 128-bit integers. This implementation is optimized for use in
 * cryptographic applications where high-precision arithmetic is required, particularly
 * in environments where native hardware support for 128-bit integers may be limited.
 *
 * The functions are designed to operate in constant-time to mitigate timing attacks in 
 * sensitive cryptographic computations. 
 * They are integral to cryptographic primitives such as digital signatures, 
 * key exchange protocols, and other schemes that depend on multiprecision arithmetic.
 *
 * \par Example Usage:
 * \code
 * #include "donna128.h"
 *
 * // Initialize two 128-bit integers (of type donna128)
 * donna128 a, b, result;
 * 
 * // Assume that 'a' and 'b' have been assigned appropriate 128-bit values.
 * 
 * // Perform addition
 * donna128_add(&result, &a, &b);
 *
 * // Perform multiplication
 * donna128_mul(&result, &a, &b);
 *
 * // Perform modular reduction with a given modulus (if applicable)
 * donna128_mod(&result, &a, &modulus);
 * \endcode
 *
 * \section donna_links Reference Links:
 * - <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">NIST FIPS 186-4: Digital Signature Standard (DSS) for background on multiprecision arithmetic</a>
 * - <a href="https://ieeexplore.ieee.org/document/8766229">IEEE Standard for Floating-Point Arithmetic (IEEE 754) for details on numerical representations</a>
 */

/*!
 * \struct uint128
 * \brief 128-bit integer structure.
 */
QSC_EXPORT_API typedef struct
{
    uint64_t high; /*!< The high-order 64-bit value. */
    uint64_t low;  /*!< The low-order 64-bit value. */
} uint128;

/**
 * \brief Right shift a 128-bit integer.
 *
 * \param x:        [const uint128*] Pointer to the input integer.
 * \param shift:    [size_t] Number of bits to shift right.
 *
 * \return [uint128] The shifted value.
 */
QSC_EXPORT_API uint128 qsc_donna128_shift_right(const uint128* x, size_t shift);

/**
 * \brief Left shift a 128-bit integer.
 *
 * \param x:        [const uint128*] Pointer to the input integer.
 * \param shift:    [size_t] Number of bits to shift left.
 *
 * \return          [uint128] The shifted value.
 */
QSC_EXPORT_API uint128 qsc_donna128_shift_left(const uint128* x, size_t shift);

/**
 * \brief Bitwise AND the low part of a 128-bit integer.
 *
 * \param x:        [const uint128*] Pointer to the input integer.
 * \param mask:     [uint64_t] The bitmask for the operation.
 *
 * \return          [uint64_t] The result of the AND operation on the low 64 bits.
 */
QSC_EXPORT_API uint64_t qsc_donna128_andl(const uint128* x, uint64_t mask);

/**
 * \brief Bitwise AND the high part of a 128-bit integer.
 *
 * \param x:        [const uint128*] Pointer to the input integer.
 * \param mask:     [uint64_t] The bitmask for the operation.
 *
 * \return          [uint64_t] The result of the AND operation on the high 64 bits.
 */
QSC_EXPORT_API uint64_t qsc_donna128_andh(const uint128* x, uint64_t mask);

/**
 * \brief Add two 128-bit integers.
 *
 * \param x:        [const uint128*] Pointer to the first integer.
 * \param y:        [const uint128*] Pointer to the second integer.
 *
 * \return          [uint128] The sum of the two 128-bit integers.
 */
QSC_EXPORT_API uint128 qsc_donna128_add(const uint128* x, const uint128* y);

/**
 * \brief Multiply a 128-bit integer by a 64-bit integer.
 *
 * \param x:        [const uint128*] Pointer to the first integer.
 * \param y:        [uint64_t] The second integer.
 *
 * \return          [uint128] The product of the multiplication.
 */
QSC_EXPORT_API uint128 qsc_donna128_multiply(const uint128* x, uint64_t y);

/**
 * \brief Bitwise OR of two 128-bit integers.
 *
 * \param x:        [const uint128*] Pointer to the first integer.
 * \param y:        [const uint128*] Pointer to the second integer.
 *
 * \return          [uint128] The result of the OR operation.
 */
QSC_EXPORT_API uint128 qsc_donna128_or(const uint128* x, const uint128* y);

#endif
