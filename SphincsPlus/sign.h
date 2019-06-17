/**
* \file sign.h
* \date June 14, 2018
*
* \brief <b>The SphincsPlus API definitions</b> \n
* Contains the primary public api for the SphincsPlus asymmetric signature scheme implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* const uint32_t MSGLEN = 32;
* uint8_t pk[SPHINCSPLUS_PUBLICKEY_SIZE];
* uint8_t sk[SPHINCSPLUS_SECRETKEY_SIZE];
* uint8_t msg[32];
* uint8_t smsg[SPHINCSPLUS_SIGNATURE_SIZE + MSGLEN];
* uint8_t rmsg[32];

* uint32_t rmsglen = 0;
* uint32_t smsglen = 0;
*
* // create the public and secret keys
* sphincsplus_generate(pk, sk);
* // returns the signed the message in smsg, and the signaure length in smsglen
* sphincsplus_sign(smsg, &smsglen, msg, MSGLEN, sk);
* // test the signature and return the message bytes in rmsg, and the message length in rmsglen
* if (sphincsplus_verify(rmsg, &rmsglen, smsg, smsglen, pk) != QCX_STATUS_SUCCESS)
* {
*     // authentication failed, do something..
* }
* \endcode
*
* \remarks Based entirely on the C reference branch of SHINCS+; including base code, comments, and api. \n
* The <a href="https://sphincs.org/data/sphincs+-specification.pdf">SPHINCS+</a>: specification. \n
* Sphincs+ entry in the <a href="https://csrc.nist.gov/projects/post-quantum-cryptography/round-1-submissions">NIST PQ Round 1</a> repository.
* Github source code: <a href="https://github.com/sphincs/sphincsplus">SHINCS+</a> code reference.
*/

#ifndef QCX_SPHINCSPLUS_SIGN_H
#define QCX_SPHINCSPLUS_SIGN_H

#include "common.h"
#include "params.h"

/*
 * Generates a SPHINCS+ key pair given a seed.
 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
 * Format pk: [root || PUB_SEED]
 */
int32_t sphincsplus_sign_seed_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

/**
 * Returns an array containing a detached signature.
 */
int32_t sphincsplus_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);

/**
 * Verifies a detached signature and message under a given public key.
 */
int32_t sphincsplus_sign_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);

/**
* \brief Generates a SphincsPlus public/private key-pair.
* Arrays must be sized to SPHINCSPLUS_PUBLICKEY_SIZE and SPHINCS_SECRETKEY_SIZE.
*
* \param publickey The pubic verification key
* \param secretkey The private signature key
*/
int32_t sphincsplus_generate(uint8_t* publickey, uint8_t* secretkey);

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param message The message to be signed
* \param msglen The message length
* \param secretkey The private signature key
*/
int32_t sphincsplus_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* secretkey);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message The message to be signed
* \param msglen The message length
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param publickey The pubic verification key
* \return Returns one (QCX_STATUS_SUCCESS) for success, QCX_ERROR_AUTHFAIL for authentication failure
*/
int32_t sphincsplus_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

#endif
