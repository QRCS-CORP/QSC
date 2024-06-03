
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

#ifndef QSC_ECDSABASE_H
#define QSC_ECDSABASE_H

/* \cond DOXYGEN_IGNORE */

#include "common.h"

/**
* \brief Combine and external public key with an internal private key to produce a shared secret
*
* \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param secret: The shared secret
*/
void qsc_ed25519_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: [const] The message to be signed
* \param msglen: The message length
* \param secretkey: [const] The private signature key
* \return Returns 0 for success
*/
int32_t qsc_ed25519_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: The message to be signed
* \param msglen: The message length
* \param signedmsg: [const] The signed message
* \param smsglen: The signed message length
* \param publickey: [const] The public verification key
* \return Returns 0 for success
*/
int32_t qsc_ed25519_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/* \endcond DOXYGEN_IGNORE */

#endif
