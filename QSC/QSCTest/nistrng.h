#ifndef QSCTEST_NISTRNG_H
#define QSCTEST_NISTRNG_H
/**
* \file nistrng.h
* \brief This is not a secure rng, and should ber used for testing purposes only.
*
* \endcode
*/

#include <stdbool.h>
#include <stdint.h>

#define QSCTEST_NIST_RNG_SEED_SIZE 48
#define QSCTEST_NIST_RNG_SUCCESS 0
#define QSCTEST_NIST_RNG_BAD_MAXLEN -1
#define QSCTEST_NIST_RNG_BAD_OUTBUF -2
#define QSCTEST_NIST_RNG_BAD_REQ_LEN -3

typedef struct 
{
    uint8_t state[16];
    size_t bpos;
    size_t rmdr;
    uint8_t key[32];
    uint8_t ctr[16];
} qsctest_nist_rng_state;

typedef struct 
{
    uint8_t key[32];
    uint8_t ctr[16];
	uint32_t rctr;
} qsctest_nist_aes256_state;

 /**
 * \brief Initialize a user supplied kdf state instance
 *
 * \param ctx stores the current state of an instance of the seed expander
 * \param seed a 32 byte random value
 * \param diversifier an 8 byte diversifier
 * \param maxlen maximum number of bytes (less than 2**32) generated under this seed and diversifier
 * \return 0 for success
 */
int32_t qsctest_nistrng_kdf_initialize(qsctest_nist_rng_state* ctx, const uint8_t* seed, const uint8_t* diversifier, uint32_t maxlen);

 /**
 * \brief Expand a seed into a larger array with a user supplied state instance
 *
 * \param ctx stores the current state of an instance of the seed expander
 * \param output the expanded seed
 * \param outlen the requested size of the expanded seed
 * \return 0 for success
 */
int32_t qsctest_nistrng_kdf_generate(qsctest_nist_rng_state* ctx, uint8_t* output, size_t outlen);

/**
* \brief Initialize the random provider state with a seed 
* and optional personalization string
*
* \param seed 48 bytes of random seed
* \param info the optional personalization string
* \param infolen the length of the personalization string, can not exceed 48 bytes
* \return 0 for success
*/
void qsctest_nistrng_prng_initialize(const uint8_t* seed, const uint8_t* info, size_t infolen);

/**
* \brief Generate pseudo-random bytes using the random provider
* Initialize must first be called with a random seed
*
* \param output the pseudo-random output array
* \param outlen the requested number of bytes to generate
* \return true for success
*/
bool qsctest_nistrng_prng_generate(uint8_t* output, size_t outlen);

/**
* \brief Update the random provider with new keying material
*
* \param key the drbg key
* \param counter the drbg counter
* \param info the optional personalization string
* \param infolen the length of the personalization string, can not exceed 48 bytes
*/
void qsctest_nistrng_prng_update(uint8_t* key, uint8_t* counter, const uint8_t* info, size_t infolen);

#endif
