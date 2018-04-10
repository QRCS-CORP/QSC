/**
* \file kem.h
* \date April 10, 2018
*
* \brief <b>The McEliece KEM definitions</b> \n
* Contains the primary public api for the Niederreiter dual form of the McEliece asymmetric cipher implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* uint8_t pk[MCELIECE_PUBLICKEYBYTES];
* uint8_t sk[MCELIECE_SECRETKEYBYTES];
* uint8_t key_a[MCELIECE_KEYBYTES];
* uint8_t key_b[MCELIECE_KEYBYTES];
* uint8_t sendb[MCELIECE_CIPHERTEXTBYTES];
*
* // create the public and secret keys
* crypto_kem_keypair(pk, sk);
* // create the key
* sysrand_getbytes(key_b, MCELIECE_KEYBYTES);
* // output the cipher-text (sendb), and bobs shared key
* crypto_kem_enc(sendb, key_b, pk);
* // decrypt the cipher-text, and output alices shared key
* if (crypto_kem_dec(key_a, sendb, sk) == MQC_ERROR_AUTHFAIL)
* {
*     // authentication failed, do something..
* }
* \endcode
*
* \remarks 
* A NewHope style encapsulation KEM, in which the intial symmetric cipher key is generated internally rather than input through the ss parameter 
* of the encryption function, can be enabled by defining the MCELIECE_ENCPASULATE constant. \n
* Based on the C reference branch of McEliece; including base code, comments, and api. \n
* McBits: <a href="https://eprint.iacr.org/2015/1092">McEliece</a> fast constant-time code-based cryptography. \n
* Authors: Daniel J. Bernstein, Tung Chou, and Peter Schwabe. \n
* Updated by John Underhill, April 2018. \n
* Source code <a href="https://www.win.tue.nl/~tchou/mcbits/">McBits</a> repository.
*/

#ifndef MCELIECE_KEM_H
#define MCELIECE_KEM_H

#include "common.h"
#include "params.h"

/**
* \brief Generates public and private key for the McEliece key encapsulation mechanism
*
* \param pk Pointer to output public key (an array of MCELIECE_PUBLICKEYBYTES bytes)
* \param sk Pointer to output private key (an array of MCELIECE_SECRETKEYBYTES bytes)
* \return Returns one (MQC_STATUS_SUCCESS) for success
*/
mqc_status crypto_kem_keypair(uint8_t* pk, uint8_t* sk);

/**
* \brief Generates cipher text and shared secret for given public key
*
* \param ct Pointer to output cipher text (an array of MCELIECE_CIPHERTEXTBYTES bytes)
* \param ss Pointer to output shared secret (secret array must be MCELIECE_KEYBYTES bytes in length)
* \param pk Pointer to input public key (an array of MCELIECE_PUBLICKEYBYTES bytes)
* \return Returns one (MQC_STATUS_SUCCESS) for success
*/
mqc_status crypto_kem_enc(uint8_t* ct, uint8_t* ss, const uint8_t* pk);

/**
* \brief Extracts the shared secret for given cipher text and private key
*
* \param ss pointer to output shared secret (an array of MCELIECE_KEYBYTES bytes)
* \param ct pointer to input cipher text (an array of MCELIECE_CIPHERTEXTBYTES bytes)
* \param sk pointer to input private key (an array of MCELIECE_SECRETKEYBYTES bytes)
* \return Returns one (MQC_STATUS_SUCCESS) for success
*/
mqc_status crypto_kem_dec(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

#endif
