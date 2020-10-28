#ifndef QSC_SPHINCSPLUSBASE_H
#define QSC_SPHINCSPLUSBASE_H

#include "common.h"

/* sign.h */

/**
* \brief Generates a SphincsPlus public/private key-pair.
* Arrays must be sized to SPHINCSPLUS_PUBLICKEY_SIZE and SPHINCS_SECRETKEY_SIZE.
*
* \param publickey The public verification key
* \param secretkey The private signature key
*/
void sphincsplus_generate(uint8_t* publickey, uint8_t* secretkey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param message The message to be signed
* \param msglen The message length
* \param secretkey The private signature key
*/
void sphincsplus_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* secretkey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message The message to be signed
* \param msglen The message length
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param publickey The public verification key
* \return Returns true for success
*/
bool sphincsplus_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

#endif