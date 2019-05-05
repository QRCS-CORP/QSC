#ifndef NIST_AES_DRBG
#define NIST_AES_DRBG

#include <stdint.h>

typedef struct 
{
    uint8_t buffer[16];
    size_t bpos;
    size_t remainder;
    uint8_t key[32];
    uint8_t ctr[16];
} AES_XOF_struct;

typedef struct 
{
    uint8_t Key[32];
    uint8_t V[16];
	uint32_t reseed_counter;
} AES256_CTR_DRBG_struct;

 /**
 * \brief Initialize a user supplied drbg state instance
 *
 * \param ctx stores the current state of an instance of the seed expander
 * \param seed a 32 byte random value
 * \param diversifier an 8 byte diversifier
 * \param maxlen maximum number of bytes (less than 2**32) generated under this seed and diversifier
 * \return 0 for success
 */
int32_t seedexpander_init(AES_XOF_struct* ctx, const uint8_t* seed, const uint8_t* diversifier, uint32_t maxlen);

 /**
 * \brief Expand a seed into a larger array with a user supplied state instance
 *
 * \param ctx stores the current state of an instance of the seed expander
 * \param output the expanded seed
 * \param outlen the requested size of the expanded seed
 * \return 0 for success
 */
int32_t seedexpander(AES_XOF_struct* ctx, uint8_t* output, size_t outlen);

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
