/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
*/

#ifndef QSC_CSP_H
#define QSC_CSP_H

/**
* \file csp.h
* \brief Cryptographic System entropy Provider
* Provides access to either the Windows CryptGenRandom provider or
* the /dev/urandom pool on Posix systems.
* This provider is not recommended for stand-alone use, but should be combined
* with another entropy provider to seed a MAC or DRBG function to provide quality
* random output.
* The ACP entropy provider is the recommended provider in this library.
*
* \author John Underhill
* \date June 05, 2019
*/

#include "common.h"

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/*!
* \def QSC_CSP_SEED_MAX
* \brief The maximum seed size that can be extracted from a single generate call
*/
#define QSC_CSP_SEED_MAX 1024000

/**
* \brief Get an array of pseudo-random bytes from the system entropy provider.
*
* \param output: Pointer to the output byte array
* \param length: The number of bytes to copy
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_csp_generate(uint8_t* output, size_t length);

#endif
