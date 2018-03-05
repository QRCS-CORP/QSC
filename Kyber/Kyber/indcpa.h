/**
* \file indcpa.h
* \brief <b>Kyber IND-CPA header definition</b> \n
* Contains the public api for the Kyber IND-CPA implementation.
*
* \date January 10, 2018
*/

#ifndef KYBER_INDCPA_H
#define KYBER_INDCPA_H

#include "common.h"

/**
* \brief Decryption function of the CPA-secure public-key encryption scheme underlying Kyber.
*
* \param m Pointer to output decrypted message
* \param c Pointer to input ciphertext
* \param sk Pointer to input secret key
*/
void indcpa_dec(uint8_t* m, const uint8_t* c, const uint8_t* sk);

/**
* \brief Encryption function of the CPA-secure public-key encryption scheme underlying Kyber.
*
* \param c Pointer to output ciphertext
* \param m Pointer to input message (of length KYBER_KEYBYTES bytes)
* \param pk Pointer to input public key
* \param coins Pointer to input random coins used as seed to deterministically generate all randomness
*/
void indcpa_enc(uint8_t* c, const uint8_t* m, const uint8_t* pk, const uint8_t* coins);

/**
* \brief Generates public and private key for the CPA-secure public-key encryption scheme underlying Kyber.
*
* \param pk Pointer to output public key
* \param sk Pointer to output private key
* \return Returns one (KYBER_CRYPTO_SUCCESS) for success
*/
qcc_status indcpa_keypair(uint8_t* pk, uint8_t* sk);

#endif
