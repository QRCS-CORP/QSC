//
//  rng.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include <string.h>
#include "rng2.h"
#include "aes.h"

AES256_CTR_DRBG_struct2 DRBG_ctx;

//void AES256_ECB(uint8_t *key, uint8_t *ctr, uint8_t *buffer);

static void aes256_ecb(const uint8_t* key, const uint8_t* counter, uint8_t* buffer)
{
#ifdef AES_AESNI_ENABLED
	__m128i rkeys[AES256_ROUNDKEY_DIMENSION];
#else
	uint32_t rkeys[AES256_ROUNDKEY_DIMENSION] = { 0 };
#endif

	/* jgu checked false warning */
	/*lint -save -e747 */
	aes_initialize(rkeys, key, true, AES256);
	/*lint -restore */
	aes_ecb_encrypt(buffer, counter, rkeys, AES256_ROUNDKEY_DIMENSION);
}

/*void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}*/

// Use whatever AES implementation you have. This uses AES from openSSL library
//    key - 256-bit AES key
//    ctr - a 128-bit plaintext value
//    buffer - a 128-bit ciphertext value
/*void AES256_ECB(uint8_t *key, uint8_t *ctr, uint8_t *buffer)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    // Create and initialise the context 
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, buffer, &len, ctr, 16))
        handleErrors();
    ciphertext_len = len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}*/

void randombytes2_init(uint8_t* entropy_input, uint8_t* personalization_string, int security_strength)
{
	uint8_t seed_material[48];

	memcpy(seed_material, entropy_input, 48);

	if (personalization_string)
	{
		for (int i = 0; i < 48; i++)
		{
			seed_material[i] ^= personalization_string[i];
		}
	}

    memset(DRBG_ctx.Key, 0x00, 32);
    memset(DRBG_ctx.V, 0x00, 16);
    AES256_CTR_DRBG_Update2(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter = 1;
}

int randombytes2(uint8_t* x, unsigned long long xlen)
{
	uint8_t block[16];
	int i = 0;

	while (xlen > 0)
	{
		//increment V
		for (int j = 15; j >= 0; j--)
		{
			if (DRBG_ctx.V[j] == 0xff)
			{
				DRBG_ctx.V[j] = 0x00;
			}
			else
			{
				DRBG_ctx.V[j]++;
				break;
			}
		}
		aes256_ecb(DRBG_ctx.Key, DRBG_ctx.V, block);
		if (xlen > 15)
		{
			memcpy(x + i, block, 16);
			i += 16;
			xlen -= 16;
		}
		else
		{
			memcpy(x + i, block, xlen);
			xlen = 0;
		}
	}

	AES256_CTR_DRBG_Update2(NULL, DRBG_ctx.Key, DRBG_ctx.V);
	DRBG_ctx.reseed_counter++;

	return RNG_SUCCESS;
}

void AES256_CTR_DRBG_Update2(uint8_t* provided_data, uint8_t* Key, uint8_t* V)
{
    uint8_t temp[48];

	for (int i = 0; i < 3; i++)
	{
		//increment V
		for (int j = 15; j >= 0; j--)
		{
			if (V[j] == 0xFF)
			{
				V[j] = 0x00;
			}
			else
			{
				V[j]++;
				break;
			}
		}

		aes256_ecb(Key, V, (uint8_t*)(temp + 16 * i));
	}

	if (provided_data != NULL)
	{
		for (int i = 0; i < 48; i++)
		{
			temp[i] ^= provided_data[i];
		}
	}

    memcpy(Key, temp, 32);
    memcpy(V, temp+32, 16);
}









