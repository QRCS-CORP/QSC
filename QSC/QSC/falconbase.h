#ifndef QSC_FALCONBASE_H
#define QSC_FALCONBASE_H

#include "common.h"

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to FALCON_PUBLICKEY_SIZE and FALCON_SECRETKEY_SIZE.
*
* \param publickey: The public verification key
* \param secretkey: The private signature key
* \param rng_generate: The random generator
*/
int32_t qsc_falcon_ref_generate_keypair(uint8_t *pk, uint8_t *sk, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: The message to be signed
* \param msglen: The message length
* \param privatekey: The private signature key
* \param rng_generate: The random generator
*/
void qsc_falcon_ref_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: The message to be signed
* \param msglen: The message length
* \param privatekey: The private signature key
* \param rng_generate: The random generator
*/
int32_t qsc_falcon_ref_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: The message to be signed
* \param msglen: The message length
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param publickey: The public verification key
* \return Returns true for success
*/
bool qsc_falcon_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: The message to be signed
* \param msglen: The message length
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param publickey: The public verification key
* \return Returns true for success
*/
bool qsc_falcon_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);

#endif