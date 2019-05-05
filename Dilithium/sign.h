/**
* \file sign.h
* \date November 13, 2018
*
* \brief <b>The Dilithium API definitions</b> \n
* Contains the primary public api for the Dilithium asymmetric signature scheme implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* const uint32_t MSGLEN = 32;
* uint8_t pk[DILITHIUM_PUBLICKEY_SIZE];
* uint8_t sk[DILITHIUM_SECRETKEY_SIZE];
* uint8_t msg[32];
* uint8_t smsg[DILITHIUM_SIGNATURE_SIZE + MSGLEN];
* uint8_t rmsg[32];

* uint32_t rmsglen = 0;
* uint32_t smsglen = 0;
*
* // create the public and secret keys
* dilithium_generate(pk, sk);
* // returns the signed the message in smsg
* dilithium_sign(smsg, &smsglen, msg, MSGLEN, sk);
* // test the signature and return the message bytes in rmsg
* if (dilithium_verify(rmsg, &rmsglen, smsg, smsglen, pk) != QCC_STATUS_SUCCESS)
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

#ifndef DILITHIUM_SIGN_H
#define DILITHIUM_SIGN_H

#include <stdint.h>
#include "params.h"
#include "poly.h"
#include "polyvec.h"

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to DILITHIUM_PUBLICKEY_SIZE and SPHINCS_SECRETKEY_SIZE.
*
* \param publickey The pubic verification key
* \param secretkey The private signature key
* \return Returns one (QCC_STATUS_SUCCESS) for success
*/
int32_t dilithium_generate(uint8_t* publickey, uint8_t* secretkey);

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param message The message to be signed
* \param msglen The message length
* \param secretkey The private signature key
* \return Returns one (QCC_STATUS_SUCCESS) for success
*/
int32_t dilithium_sign(uint8_t* signedmsg, uint64_t* smsglen, const uint8_t* message, uint64_t msglen, const uint8_t* secretkey);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message The message to be signed
* \param msglen The message length
* \param signedmsg The signed message
* \param smsglen The signed message length
* \param publickey The pubic verification key
* \return Returns one (QCC_STATUS_SUCCESS) for success, QCC_ERROR_AUTHFAIL for authentication failure
*/
int32_t dilithium_verify(uint8_t* message, uint64_t* msglen, const uint8_t* signedmsg, uint64_t smsglen, const uint8_t* publickey);

#endif
