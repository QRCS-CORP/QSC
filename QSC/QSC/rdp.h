/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
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

#ifndef QSC_RDP_H
#define QSC_RDP_H

#include "common.h"

/**
* \file rdp.h
* \brief The RDRAND entropy Provider: RDP \n
* Provides access to the Intel RDRAND entropy provider.
* This provider is not recommended for stand-alone use, but should be combined
* with another entropy provider to seed a MAC or DRBG function to provide quality
* random output.
* The ACP entropy provider is the recommended provider in this library.
*/

/*!
* \def QSC_RDP_SEED_MAX
* \brief The maximum seed size that can be extracted from a single generate call
*/
#define QSC_RDP_SEED_MAX 1024000

/**
* \brief Get an array of random bytes from the RDRAND entropy provider.
*
* \param output: Pointer to the output byte array
* \param length: The number of bytes to copy
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_rdp_generate(uint8_t* output, size_t length);

#endif
