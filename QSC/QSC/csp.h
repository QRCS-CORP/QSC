/*
* Copyright (c) 2023 Quantum Secure Cryptographic Solutions QSCS Corp. (QSCS.ca).
* This file is part of the QSC Cryptographic library.
* The QSC library was written as a prototyping library for post-quantum primitives,
* in the hopes that it would be useful for educational purposes only.
* Any use of the QSC library in a commercial context, or reproduction of original material
* contained in this library is strictly forbidden unless prior written consent is obtained
* from the QSCS Corporation.
*
* The AGPL version 3 License (AGPLv3)
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
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
