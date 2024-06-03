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
 *
 * Reference implementations:
 * LibSodium by Frank Denis
 * https://github.com/jedisct1/libsodium
 * curve25519-donna by Adam Langley
 * https://github.com/agl/curve25519-donna
 * NaCI by Daniel J. Bernstein, Tanja Lange, Peter Schwabe
 * https://nacl.cr.yp.to
 * Rewritten for Misra compliance and optimizations by John G. Underhill
 */

#ifndef QSC_ECDHBASE_H
#define QSC_ECDHBASE_H

#include "common.h"

/* \cond DOXYGEN_IGNORE */

/**
* \brief Combine and external public key with an internal private key to produce a shared secret
*
* \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
*
* \param secret: The shared secret
* \param publickey: [const] Pointer to the output public-key array
* \param privatekey: [const] Pointer to output private-key array
*/
bool qsc_ed25519_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

/**
* \brief Generates public and private key for the ECDH key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param seed: [const] A pointer to the random seed
*/
void qsc_ed25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/* \endcond DOXYGEN_IGNORE */

#endif
