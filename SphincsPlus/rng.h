#ifndef QCX_AES256_DRBG
#define QCX_AES256_DRBG

#include "common.h"

#define RNG_SEED_SIZE 48
#define RNG_SUCCESS 0
#define RNG_BAD_MAXLEN -1
#define RNG_BAD_OUTBUF -2
#define RNG_BAD_REQ_LEN -3

typedef struct 
{
    uint8_t state[16];
    size_t bpos;
    size_t rmdr;
    uint8_t key[32];
    uint8_t ctr[16];
} aes256_drbg_state;

typedef struct 
{
    uint8_t key[32];
    uint8_t ctr[16];
	uint32_t rctr;
} aes256_state;

 /**
 * \brief Initialize a user supplied drbg state instance
 *
 * \param ctx stores the current state of an instance of the seed expander
 * \param seed a 32 byte random value
 * \param diversifier an 8 byte diversifier
 * \param maxlen maximum number of bytes (less than 2**32) generated under this seed and diversifier
 * \return 0 for success
 */
int32_t aes_drbg_initialize(aes256_drbg_state* ctx, const uint8_t* seed, const uint8_t* diversifier, uint32_t maxlen);

 /**
 * \brief Expand a seed into a larger array with a user supplied state instance
 *
 * \param ctx stores the current state of an instance of the seed expander
 * \param output the expanded seed
 * \param outlen the requested size of the expanded seed
 * \return 0 for success
 */
int32_t aes_drbg_generate(aes256_drbg_state* ctx, uint8_t* output, size_t outlen);

/**
* \brief Initialize the random provider state with a seed 
* and optional personalization string
*
* \param seed 48 bytes of random seed
* \param info the optional personalization string
* \param infolen the length of the personalization string, can not exceed 48 bytes
* \return 0 for success
*/
void randombytes_init(const uint8_t* seed, const uint8_t* info, size_t infolen);

/**
* \brief Generate pseudo-random bytes using the random provider
* Initialize must first be called with a random seed
*
* \param output the pseudo-random output array
* \param outlen the requested number of bytes to generate
* \return 0 for success
*/
int32_t randombytes(uint8_t* output, size_t outlen);

/**
* \brief Update the random provider with new keying material
*
* \param key the drbg key
* \param counter the drbg counter
* \param info the optional personalization string
* \param infolen the length of the personalization string, can not exceed 48 bytes
*/
void randombytes_update(uint8_t* key, uint8_t* counter, const uint8_t* info, size_t infolen);

#endif
