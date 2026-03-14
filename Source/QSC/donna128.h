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

#ifndef QSC_DONNA128_H
#define QSC_DONNA128_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

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
 * \brief Add two 128-bit integers.
 *
 * \param x:        [const uint128*] Pointer to the first integer.
 * \param y:        [const uint128*] Pointer to the second integer.
 *
 * \return          [uint128] The sum of the two 128-bit integers.
 */
QSC_EXPORT_API uint128 qsc_donna128_add(const uint128* x, const uint128* y);

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
 * \brief Bitwise AND the low part of a 128-bit integer.
 *
 * \param x:        [const uint128*] Pointer to the input integer.
 * \param mask:     [uint64_t] The bitmask for the operation.
 *
 * \return          [uint64_t] The result of the AND operation on the low 64 bits.
 */
QSC_EXPORT_API uint64_t qsc_donna128_andl(const uint128* x, uint64_t mask);

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
 * \brief Right shift a 128-bit integer.
 *
 * \param x:        [const uint128*] Pointer to the input integer.
 * \param shift:    [size_t] Number of bits to shift right.
 *
 * \return [uint128] The shifted value.
 */
QSC_EXPORT_API uint128 qsc_donna128_shift_right(const uint128* x, size_t shift);

/**
 * \brief Subtract one 128-bit integer from another.
 *
 * \param x:        [const uint128*] Pointer to the minuend.
 * \param y:        [const uint128*] Pointer to the subtrahend.
 *
 * \return          [uint128] The difference (x - y), wrapping on underflow.
 */
QSC_EXPORT_API uint128 qsc_donna128_subtract(const uint128* x, const uint128* y);

QSC_CPLUSPLUS_ENABLED_END

#endif
