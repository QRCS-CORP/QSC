#ifndef NEWHOPE_CPAPKE_H
#define NEWHOPE_CPAPKE_H

#include <stdint.h>

/**
* \brief Generates public and private key for the CPA public-key encryption scheme underlying the NewHope KEMs
*
* \param pk pointer to output public key
* \param sk pointer to output private key
* \return Returns true for success
*/
void cpapke_keypair(uint8_t* pk, uint8_t* sk);

/**
* \brief Encryption function of the CPA public-key encryption scheme underlying the NewHope KEMs
*
* \param c pointer to output ciphertext
* \param m pointer to input message (of length NEWHOPE_SYMKEY_SIZE bytes)
* \param pk pointer to input public key
* \param coins pointer to input random coins used as seed to deterministically generate all randomness
*/
void cpapke_enc(uint8_t* c, const uint8_t* m, const uint8_t* pk, const uint8_t* coins);

/**
* \brief Decryption function of the CPA public-key encryption scheme underlying the NewHope KEMs
*
* \param m pointer to output decrypted message
* \param c pointer to input ciphertext
* \param sk pointer to input secret key
*/
void cpapke_dec(uint8_t* m, const uint8_t* c, const uint8_t* sk);

#endif
