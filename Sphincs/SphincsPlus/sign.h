/**
* \file sign.h
* \date Ontober 30, 2018
*
* \brief <b>The SHINCS+ API definitions</b> \n
* Contains the primary public api for the SHINCS+ asymmetric signature scheme implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* const uint32_t MSGLEN = 32;
* uint8_t pk[SPHINCS_PUBLICKEY_SIZE];
* uint8_t sk[SPHINCS_SECRETKEY_SIZE];
* uint8_t msg[32];
* uint8_t sgnmsg[SPHINCS_SIGNATURE_SIZE + MSGLEN];
* uint8_t rmsg[32];

* uint32_t rmsglen = 0;
* uint32_t smsglen = 0;
*
* // create the public and secret keys
* sphincs_generate(pk, sk);
* // returns the signed the message in smsg
* sphincs_sign(sgnmsg, &smsglen, msg, MSGLEN, sk);
* // test the signature and return the message bytes in rmsg
* if (sphincs_verify(rmsg, &rmsglen, sgnmsg, smsglen, pk) != QCC_STATUS_SUCCESS)
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

#ifndef SPHINCS_SIGN_H
#define SPHINCS_SIGN_H

#include "common.h"
#include "params.h"

/*!
\def SPHINCS_ALG_NAME
* Read Only: The algorithm description
*/
#define SPHINCS_ALG_NAME SPHINCS_PARAM_NAME

/*!
\def SPHINCS_PUBLICKEY_SIZE
* Read Only: The Public Key size
*/
#define SPHINCS_PUBLICKEY_SIZE SPX_PK_BYTES

/*!
\def SPHINCS_SECRETKEY_SIZE
* Read Only: The Private Key size
*/
#define SPHINCS_SECRETKEY_SIZE SPX_SK_BYTES

/*!
\def SPHINCS_SIGNATURE_SIZE
* Read Only: The Signature size
*/
#define SPHINCS_SIGNATURE_SIZE SPX_BYTES

 /**
 * \brief Generates a SPHINCS+ public/private key-pair.
 * Arrays must be sized to SPHINCS_PUBLICKEY_SIZE and SPHINCS_SECRETKEY_SIZE.
 *
 * \param publickey The pubic verification key
 * \param secretkey The private signature key
 * \return Returns one (QCC_STATUS_SUCCESS) for success
 */
qcc_status sphincs_generate(uint8_t* publicKey, uint8_t* secretkey);

 /**
 * \brief Takes the message as input and returns an array containing the signature followed by the message.
 *
 * \param signedmsg The signed message
 * \param signedmsglen The signed message length
 * \param message The message to be signed
 * \param messagelen The message length
 * \param secretkey The private signature key
 * \return Returns one (QCC_STATUS_SUCCESS) for success
 */
qcc_status sphincs_sign(uint8_t* signedmsg, uint64_t* signedmsglen, const uint8_t* message, uint64_t messagelen, const uint8_t* secretkey);

 /**
 * \brief Verifies a signature-message pair with the public key.
 *
 * \param message The message to be signed
 * \param messagelen The message length
 * \param signedmsg The signed message
 * \param signedmsglen The signed message length
 * \param publickey The pubic verification key
 * \return Returns one (QCC_STATUS_SUCCESS) for success, QCC_ERROR_AUTHFAIL for authentication failure
 */
qcc_status sphincs_verify(uint8_t* message, uint64_t* messagelen, const uint8_t* signedmsg, uint64_t signedmsglen, const uint8_t* publickey);

#endif
