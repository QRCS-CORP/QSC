
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
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
