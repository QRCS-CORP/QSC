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
*
*
* Implementation Details:
* An implementation of the auto entropy collection provider
* Written by John G. Underhill
* Updated on January 20, 2020
* Contact: develop@vtdev.com 
*/

/**
* \file acp.h
* \brief <b>The Auto entropy Collection Provider: ACP</b> \n
* ACP is the recommended entropy provider. \n
* ACP uses a hashed collection of system timers, statistics, 
* the RDRAND, and the system random providers, to seed an instance of cSHAKE-512.
*
* \author John Underhill
* \date August 17, 2020
*/

#ifndef QSC_ACP_H
#define QSC_ACP_H

#include "common.h"

/*!
* \def QSC_ACP_SEED_MAX
* \brief The maximum seed size that can be extracted from a single generate call
*/
#define QSC_ACP_SEED_MAX 10240000

/**
* \brief Get an array of random bytes from the auto entropy collection provider.
*
* \param output: Pointer to the output byte array
* \param length: The number of bytes to copy
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_acp_generate(uint8_t* output, size_t length);

#endif
