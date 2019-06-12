/**
* \file kem.h
* \date April 7, 2019
*
* \brief <b>The McEliece KEM definitions</b> \n
* Contains the primary public api for the Niederreiter dual form of the McEliece asymmetric cipher implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* uint8_t pk[MCELIECE_PUBLICKEY_SIZE];
* uint8_t sk[MCELIECE_SECRETKEY_SIZE];
* uint8_t key_a[MCELIECE_KEY_SIZE];
* uint8_t key_b[MCELIECE_KEY_SIZE];
* uint8_t sendb[MCELIECE_CIPHERTEXT_SIZE];
*
* // create the public and secret keys
* crypto_kem_keypair(pk, sk);
* // output the cipher-text (sendb), and bobs shared key
* crypto_kem_enc(sendb, key_b, pk);
* // decrypt the cipher-text, and output alice's shared key
* if (crypto_kem_dec(key_a, sendb, sk) == MQC_ERROR_AUTHFAIL)
* {
*     // authentication failed, do something..
* }
* \endcode
*
* \remarks
* Classic McElice is an IND-CCA2 Secure KEM, that is secure against all known ROM attacks. \n
* Based on the C reference branch of Classic McEliece; including base code, comments, and api. \n
* Classic McEliece: <a href="https://classic.mceliece.org/nist/mceliece-20171129.pdf">McEliece</a> conservatice code-based cryptography. \n
* Principal Authors: Daniel J. Bernstein, Tung Chou, Tanja Lange, and Peter Schwabe. \n
* Updated by John Underhill, April 2019. \n
* Source code <a href="https://classic.mceliece.org/software.html">Classic McEliece</a> software.
*/

#ifndef KEM_H
#define KEM_H

#include "common.h"

#define KEYGEN_RETRIES_MAX 100

/**
* \brief Extracts the shared-secret for a given cipher-text and private key
*
* \param ss pointer to output shared-secret (an array of MCELIECE_KEY_SIZE bytes)
* \param ct pointer to input cipher-text (an array of MCELIECE_CIPHERTEXT_SIZE bytes)
* \param sk pointer to input private key (an array of MCELIECE_SECRETKEY_SIZE bytes)
* \return Returns true for success
*/
bool crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

/**
* \brief Generates the cipher-text and shared-secret for a given public key
*
* \param ct Pointer to output cipher-text (an array of MCELIECE_CIPHERTEXT_SIZE bytes)
* \param ss Pointer to output shared-secret (secret array must be MCELIECE_KEY_SIZE bytes in length)
* \param pk Pointer to input public key (an array of MCELIECE_PUBLICKEY_SIZE bytes)
* \return Returns true for success
*/
bool crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk);

/**
* \brief Generates public and private keys for the McEliece key encapsulation mechanism
*
* \param pk Pointer to output public key (an array of MCELIECE_PUBLICKEY_SIZE bytes)
* \param sk Pointer to output private key (an array of MCELIECE_SECRETKEY_SIZE bytes)
* \return Returns true for success
*/
bool crypto_kem_keypair(uint8_t* pk, uint8_t* sk);

#endif

