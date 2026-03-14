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

#ifndef QSC_SECRAND_H
#define QSC_SECRAND_H

#include "qsccommon.h"
#include "async.h"
#include "csg.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file secrand.h
 * \brief Secure pseudo-random generator (PRNG) function definitions.
 *
 * \details
 * This module implements a secure pseudo-random generator that must be pre-keyed using the 
 * qsc_secrand_initialize() function before any random output is generated. The generator 
 * provides functions to generate random numbers of various data types (signed/unsigned integers 
 * of 8, 16, 32, and 64 bits, as well as double-precision floating point numbers) and to generate 
 * arbitrary arrays of random bytes. It relies on the underlying CSG (Custom SHAKE Generator) 
 * for cryptographic strength.
 *
 * \section secrand_links Reference Links:
 * - <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">NIST Pseudorandom Generator Guidelines (SP 800-90A)</a>
 */

/*!
 * \def QSC_SECRAND_SEED_SIZE
 * \brief The input seed size.
 */
#define QSC_SECRAND_SEED_SIZE 32ULL

/*!
 * \def QSC_SECRAND_CACHE_SIZE
 * \brief The internal cache size of the generator.
 */
#define QSC_SECRAND_CACHE_SIZE 1024ULL

/*!
 * \struct qsc_secrand_state
 * \brief The internal secrand state array.
 */
QSC_EXPORT_API typedef struct
{
    qsc_csg_state hstate;                   /*!< The CSG state. */
    uint8_t cache[QSC_SECRAND_CACHE_SIZE];  /*!< The cache buffer. */
    size_t cpos;                            /*!< The cache position. */
    bool init;                              /*!< The initialized flag. */
    qsc_mutex opmtx;                        /*!< The implementation mutex. */
} qsc_secrand_state;

/**
 * \brief Generate a signed 8-bit random integer.
 *
 * \return          [int8_t] Returns a signed 8-bit random integer.
 */
QSC_EXPORT_API int8_t qsc_secrand_next_char(void);

/**
 * \brief Generate an unsigned 8-bit random integer.
 *
 * \return          [uint8_t] Returns an unsigned 8-bit random integer.
 */
QSC_EXPORT_API uint8_t qsc_secrand_next_uchar(void);

/**
 * \brief Generate a random double-precision floating-point number.
 *
 * \return          [double] Returns a random double value.
 */
QSC_EXPORT_API double qsc_secrand_next_double(void);

/**
 * \brief Generate a signed 16-bit random integer.
 *
 * \return          [int16_t] Returns a signed 16-bit random integer.
 */
QSC_EXPORT_API int16_t qsc_secrand_next_int16(void);

/**
 * \brief Generate a signed 16-bit random integer of a maximum value.
 *
 * \param maximum:  [int16_t] The maximum value of the integer.
 * \return          [int16_t] Returns a signed 16-bit random integer in the range [-maximum, maximum].
 */
QSC_EXPORT_API int16_t qsc_secrand_next_int16_max(int16_t maximum);

/**
 * \brief Generate a signed 16-bit random integer of a maximum and minimum value.
 *
 * \param maximum:  [int16_t] The maximum value of the integer.
 * \param minimum:  [int16_t] The minimum value of the integer.
 * \return          [int16_t] Returns a signed 16-bit random integer in the range [minimum, maximum].
 */
QSC_EXPORT_API int16_t qsc_secrand_next_int16_maxmin(int16_t maximum, int16_t minimum);

/**
 * \brief Generate an unsigned 16-bit random integer.
 *
 * \return          [uint16_t] Returns an unsigned 16-bit random integer.
 */
QSC_EXPORT_API uint16_t qsc_secrand_next_uint16(void);

/**
 * \brief Generate an unsigned 16-bit random integer of a maximum value.
 *
 * \param maximum:  [uint16_t] The maximum value of the integer.
 * \return          [uint16_t] Returns an unsigned 16-bit random integer in the range [0, maximum].
 */
QSC_EXPORT_API uint16_t qsc_secrand_next_uint16_max(uint16_t maximum);

/**
 * \brief Generate an unsigned 16-bit random integer of a maximum and minimum value.
 *
 * \param maximum:  [uint16_t] The maximum value of the integer.
 * \param minimum:  [uint16_t] The minimum value of the integer.
 * \return          [uint16_t] Returns an unsigned 16-bit random integer in the range [minimum, maximum].
 */
QSC_EXPORT_API uint16_t qsc_secrand_next_uint16_maxmin(uint16_t maximum, uint16_t minimum);

/**
 * \brief Generate a signed 32-bit random integer.
 *
 * \return          [int32_t] Returns a signed 32-bit random integer.
 */
QSC_EXPORT_API int32_t qsc_secrand_next_int32(void);

/**
 * \brief Generate a signed 32-bit random integer of a maximum value.
 *
 * \param maximum:  [int32_t] The maximum value of the integer.
 * \return          [int32_t] Returns a signed 32-bit random integer in the range [-minimum, maximum].
 */
QSC_EXPORT_API int32_t qsc_secrand_next_int32_max(int32_t maximum);

/**
 * \brief Generate a signed 32-bit random integer of a maximum and minimum value.
 *
 * \param maximum:  [int32_t] The maximum value of the integer.
 * \param minimum:  [int32_t] The minimum value of the integer.
 * \return          [int32_t] Returns a signed 32-bit random integer in the range [minimum, maximum].
 */
QSC_EXPORT_API int32_t qsc_secrand_next_int32_maxmin(int32_t maximum, int32_t minimum);

/**
 * \brief Generate an unsigned 32-bit random integer.
 *
 * \return          [uint32_t] Returns an unsigned 32-bit random integer.
 */
QSC_EXPORT_API uint32_t qsc_secrand_next_uint32(void);

/**
 * \brief Generate an unsigned 32-bit random integer of a maximum value.
 *
 * \param maximum:  [uint32_t] The maximum value of the integer.
 * \return          [uint32_t] Returns an unsigned 32-bit random integer in the range [0, maximum].
 */
QSC_EXPORT_API uint32_t qsc_secrand_next_uint32_max(uint32_t maximum);

/**
 * \brief Generate an unsigned 32-bit random integer of a maximum and minimum value.
 *
 * \param maximum:  [uint32_t] The maximum value of the integer.
 * \param minimum:  [uint32_t] The minimum value of the integer.
 * \return          [uint32_t] Returns an unsigned 32-bit random integer in the range [minimum, maximum].
 */
QSC_EXPORT_API uint32_t qsc_secrand_next_uint32_maxmin(uint32_t maximum, uint32_t minimum);

/**
 * \brief Generate a signed 64-bit random integer.
 *
 * \return          [int64_t] Returns a signed 64-bit random integer.
 */
QSC_EXPORT_API int64_t qsc_secrand_next_int64(void);

/**
 * \brief Generate a signed 64-bit random integer of a maximum value.
 *
 * \param maximum:  [int64_t] The maximum value of the integer.
 * \return          [int64_t] Returns a signed 64-bit random integer in the range [-minimum, maximum].
 */
QSC_EXPORT_API int64_t qsc_secrand_next_int64_max(int64_t maximum);

/**
 * \brief Generate a signed 64-bit random integer of a maximum and minimum value.
 *
 * \param maximum:  [int64_t] The maximum value of the integer.
 * \param minimum:  [int64_t] The minimum value of the integer.
 * \return          [int64_t] Returns a signed 64-bit random integer in the range [minimum, maximum].
 */
QSC_EXPORT_API int64_t qsc_secrand_next_int64_maxmin(int64_t maximum, int64_t minimum);

/**
 * \brief Generate an unsigned 64-bit random integer.
 *
 * \return          [uint64_t] Returns an unsigned 64-bit random integer.
 */
QSC_EXPORT_API uint64_t qsc_secrand_next_uint64(void);

/**
 * \brief Generate an unsigned 64-bit random integer of a maximum value.
 *
 * \param maximum:  [uint64_t] The maximum value of the integer.
 * \return          [uint64_t] Returns an unsigned 64-bit random integer in the range [0, maximum].
 */
QSC_EXPORT_API uint64_t qsc_secrand_next_uint64_max(uint64_t maximum);

/**
 * \brief Generate an unsigned 64-bit random integer of a maximum and minimum value.
 *
 * \param maximum:  [uint64_t] The maximum value of the integer.
 * \param minimum:  [uint64_t] The minimum value of the integer.
 * \return          [uint64_t] Returns an unsigned 64-bit random integer in the range [minimum, maximum].
 */
QSC_EXPORT_API uint64_t qsc_secrand_next_uint64_maxmin(uint64_t maximum, uint64_t minimum);

/**
 * \brief Clear the buffer and destroy the internal state.
 */
QSC_EXPORT_API void qsc_secrand_dispose(void);

/**
 * \brief Initialize the random generator with a seed and optional customization array.
 *
 * \param seed:     [const uint8_t*] The primary seed; must be 32 or 64 bytes in length.
 * \param seedlen:  [size_t]           The byte length of the seed.
 * \param custom:   [const uint8_t*]   The optional customization parameter (can be NULL).
 * \param custlen:  [size_t]           The length of the customization array.
 */
QSC_EXPORT_API void qsc_secrand_initialize(const uint8_t* seed, size_t seedlen, const uint8_t* custom, size_t custlen);

/**
 * \brief Generate an array of pseudo-random bytes.
 *
 * \param output:   [uint8_t*] The destination array.
 * \param length:   [size_t]   The number of bytes to generate.
 * \return          [bool] Returns true if the operation succeeded.
 */
QSC_EXPORT_API bool qsc_secrand_generate(uint8_t* output, size_t length);

QSC_CPLUSPLUS_ENABLED_END

#endif
