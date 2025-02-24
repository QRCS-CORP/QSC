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
 * Written by: John Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_SECRAND_H
#define QSC_SECRAND_H

#include "common.h"
#include "csg.h"

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
 * \return          [int16_t] Returns a signed 16-bit random integer in the range [0, maximum].
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
 * \return          [int32_t] Returns a signed 32-bit random integer in the range [0, maximum].
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
 * \return          [int64_t] Returns a signed 64-bit random integer in the range [0, maximum].
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

#endif
