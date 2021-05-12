/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* An implementation of the secure random PRNG
* Written by John G. Underhill
* Updated on August 1, 2020
* Contact: develop@vtdev.com */

/**
* \file secrand.h
* \author John Underhill
* \date August 15, 2020
*
* \brief <b>n implementation of an secure pseudo-random generator</b> \n
* Contains the public api and documentation for the secrand pseudo-random bytes generator.
*/

#ifndef QSC_SECRAND_H
#define QSC_SECRAND_H

#include "common.h"
#include "acp.h"
#include "csg.h"

/*!
* \def QSC_SECRAND_CACHE_SIZE
* \brief The internal cache size of the generator
*/
#define QSC_SECRAND_CACHE_SIZE 1024

/*! 
* \struct qsc_secrand_state
* \brief The internal secrand state array
*/
QSC_EXPORT_API typedef struct
{
    qsc_csg_state hstate;
    uint8_t cache[QSC_SECRAND_CACHE_SIZE];
    size_t cpos;
    bool init;
} qsc_secrand_state;

/**
* \brief Generate a signed 8-bit random integer
*
* \return Returns an signed 8-bit random integer
*/
QSC_EXPORT_API int8_t qsc_secrand_next_char();

/**
* \brief Generate a unsigned 8-bit random integer
*
* \return Returns an unsigned 8-bit random integer
*/
QSC_EXPORT_API uint8_t qsc_secrand_next_uchar();

/**
* \brief Generate a random double integer
*
* \return Returns a random double integer
*/
QSC_EXPORT_API double qsc_secrand_next_double();

/**
* \brief Generate a signed 16-bit random integer
*
* \return Returns a signed 16-bit random integer
*/
QSC_EXPORT_API int16_t qsc_secrand_next_int16();

/**
* \brief Generate a signed 16-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a signed 16-bit random integer
*/
QSC_EXPORT_API int16_t qsc_secrand_next_int16_max(int16_t maximum);

/**
* \brief Generate a signed 16-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a signed 16-bit random integer
*/
QSC_EXPORT_API int16_t qsc_secrand_next_int16_maxmin(int16_t maximum, int16_t minimum);

/**
* \brief Generate a unsigned 16-bit random integer
*
* \return Returns a unsigned 16-bit random integer
*/
QSC_EXPORT_API uint16_t qsc_secrand_next_uint16();

/**
* \brief Generate a unsigned 16-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a unsigned 16-bit random integer
*/
QSC_EXPORT_API uint16_t qsc_secrand_next_uint16_max(uint16_t maximum);

/**
* \brief Generate a unsigned 16-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a unsigned 16-bit random integer
*/
QSC_EXPORT_API uint16_t qsc_secrand_next_uint16_maxmin(uint16_t maximum, uint16_t minimum);

/**
* \brief Generate a signed 32-bit random integer
*
* \return Returns a signed 32-bit random integer
*/
QSC_EXPORT_API int32_t qsc_secrand_next_int32();

/**
* \brief Generate a signed 32-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a signed 32-bit random integer
*/
QSC_EXPORT_API int32_t qsc_secrand_next_int32_max(int32_t maximum);

/**
* \brief Generate a signed 32-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a signed 32-bit random integer
*/
QSC_EXPORT_API int32_t qsc_secrand_next_int32_maxmin(int32_t maximum, int32_t minimum);

/**
* \brief Generate a unsigned 32-bit random integer
*
* \return Returns a unsigned 32-bit random integer
*/
QSC_EXPORT_API uint32_t qsc_secrand_next_uint32();

/**
* \brief Generate a unsigned 32-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a unsigned 32-bit random integer
*/
QSC_EXPORT_API uint32_t qsc_secrand_next_uint32_max(uint32_t maximum);

/**
* \brief Generate a unsigned 32-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a unsigned 32-bit random integer
*/
QSC_EXPORT_API uint32_t qsc_secrand_next_uint32_maxmin(uint32_t maximum, uint32_t minimum);

/**
* \brief Generate a signed 64-bit random integer
*
* \return Returns a signed 64-bit random integer
*/
QSC_EXPORT_API int64_t qsc_secrand_next_int64();

/**
* \brief Generate a signed 64-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a signed 64-bit random integer
*/
QSC_EXPORT_API int64_t qsc_secrand_next_int64_max(int64_t maximum);

/**
* \brief Generate a signed 64-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a signed 64-bit random integer
*/
QSC_EXPORT_API int64_t qsc_secrand_next_int64_maxmin(int64_t maximum, int64_t minimum);

/**
* \brief Generate a unsigned 64-bit random integer
*
* \return Returns a unsigned 64-bit random integer
*/
QSC_EXPORT_API uint64_t qsc_secrand_next_uint64();

/**
* \brief Generate a unsigned 64-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a unsigned 64-bit random integer
*/
QSC_EXPORT_API uint64_t qsc_secrand_next_uint64_max(uint64_t maximum);

/**
* \brief Generate a unsigned 64-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a unsigned 64-bit random integer
*/
QSC_EXPORT_API uint64_t qsc_secrand_next_uint64_maxmin(uint64_t maximum, uint64_t minimum);

/**
* \brief Initialize the random generator with a seed and optional customization array
*
* \param seed: The primary seed, must be 32 or 64 bytes in length
* \param seedlen: The byte length of the seed
* \param custom: The optional customization parameter (can be NULL)
* \param custlen: The length of the customization array
*/
QSC_EXPORT_API void qsc_secrand_initialize(uint8_t* seed, size_t seedlen, uint8_t* custom, size_t custlen);

/**
* \brief Generate an array of pseudo-random bytes
*
* \param output: The destination array
* \param length: The number of bytes to generate
*/
QSC_EXPORT_API void qsc_secrand_generate(uint8_t* output, size_t length);

#endif