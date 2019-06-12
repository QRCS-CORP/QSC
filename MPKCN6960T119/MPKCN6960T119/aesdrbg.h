#ifndef AESDRBG_H
#define AESDRBG_H

#include "common.h"

/**
* \brief Generate an array of pseudo-random bytes using an AES-128 CTR generator.
*
* \param output The output array
* \param outlen The number of output bytes to generate
* \param nonce A 16 byte nonce array (for best security, should be random)
* \param key A 16 byte cipher-key array
*/
mqc_status aes128_generate(uint8_t* output, size_t outlen, uint8_t* nonce, const uint8_t* key);

/**
* \brief Generate an array of pseudo-random bytes using an AES-256 CTR generator.
*
* \param output The output array
* \param outlen The number of output bytes to generate
* \param nonce A 16 byte nonce array (for best security, should be random)
* \param key A 32 byte cipher-key array
*/
mqc_status aes256_generate(uint8_t* output, size_t outlen, uint8_t* nonce, const uint8_t* key);

#endif