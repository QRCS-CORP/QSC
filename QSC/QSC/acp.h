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

#ifndef QSC_ACP_H
#define QSC_ACP_H

#include "common.h"

/**
* \file acp.h
* \brief The Auto entropy Collection Provider: ACP
* ACP is the recommended entropy provider.
* ACP uses a hashed collection of system timers, statistics, 
* the RDRAND provider, and the system random provider, to seed an instance of cSHAKE-512.
*
* \author John Underhill
* \date August 17, 2020
*/

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
