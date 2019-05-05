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
#define SPHINCS_PARAM_NAME "SPHINCS+_SHAKE256F256"

/* Hash output length in bytes. */
#define SPHINCS_N 32
/* Height of the hypertree. */
#define SPHINCS_FULL_HEIGHT 64
/* Number of subtree layer. */
#define SPHINCS_D 8
/* FORS tree dimensions. */
#define SPHINCS_FORS_HEIGHT 14
#define SPHINCS_FORS_TREES 22
/* Winternitz parameter, */
#define SPHINCS_WOTS_W 16

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

   /* For clarity */
#define SPHINCS_ADDR_BYTES 32

/* WOTS parameters. */
#if SPHINCS_WOTS_W == 256
#define SPHINCS_WOTS_LOGW 8
#elif SPHINCS_WOTS_W == 16
#define SPHINCS_WOTS_LOGW 4
#else
#error SPHINCS_WOTS_W assumed 16 or 256
#endif

#define SPHINCS_WOTS_LEN1 (8 * SPHINCS_N / SPHINCS_WOTS_LOGW)

/* SPHINCS_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#if SPHINCS_WOTS_W == 256
#if SPHINCS_N <= 1
#define SPHINCS_WOTS_LEN2 1
#elif SPHINCS_N <= 256
#define SPHINCS_WOTS_LEN2 2
#else
#error Did not precompute SPHINCS_WOTS_LEN2 for n outside {2, .., 256}
#endif
#elif SPHINCS_WOTS_W == 16
#if SPHINCS_N <= 8
#define SPHINCS_WOTS_LEN2 2
#elif SPHINCS_N <= 136
#define SPHINCS_WOTS_LEN2 3
#elif SPHINCS_N <= 256
#define SPHINCS_WOTS_LEN2 4
#else
#error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#endif
#endif

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
#error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* FORS parameters. */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */
#define SPX_OPTRAND_BYTES 32

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
 * \param smsglen The signed message length
 * \param message The message to be signed
 * \param msglen The message length
 * \param secretkey The private signature key
 * \return Returns one (QCC_STATUS_SUCCESS) for success
 */
qcc_status sphincs_sign(uint8_t* signedmsg, uint64_t* smsglen, const uint8_t* message, uint64_t msglen, const uint8_t* secretkey);

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
qcc_status sphincs_verify(uint8_t* message, uint64_t* msglen, const uint8_t* signedmsg, uint64_t smsglen, const uint8_t* publickey);

#endif
