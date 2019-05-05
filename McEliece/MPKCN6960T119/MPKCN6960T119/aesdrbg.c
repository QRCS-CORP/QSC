#include "aesdrbg.h"
#include "aes.h"
#include <string.h>

static void clear8(uint8_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

static void clear32(uint32_t* a, size_t count)
{
	size_t i;

	for (i = 0; i < count; ++i)
	{
		a[i] = 0;
	}
}

static void increment8(uint8_t* output)
{
	int i = 16;
	while (--i >= 0 && ++output[i] == 0)
	{
	}
}

mqc_status aes128_generate(uint8_t* output, size_t outlen, uint8_t* nonce, const uint8_t* key)
{
	uint8_t input[16];
	size_t offset;
	mqc_status status;

#if defined(AES_AESNI_ENABLED)
	__m128i rks[AES128_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[AES128_ROUNDKEY_DIMENSION];
	clear32(rks, AES128_ROUNDKEY_DIMENSION);
#endif

	clear8(input, 16);
	status = aes_initialize(rks, key, true, AES128);
	offset = 0;

	while (outlen >= 16)
	{
		aes_ctr_transform(output + offset, nonce, input, rks, AES128_ROUNDKEY_DIMENSION);
		increment8(nonce);
		offset += 16;
		outlen -= 16;
	}

	if (outlen > 0)
	{
		uint8_t tmp[16];
		clear8(tmp, 16);
		increment8(nonce);
		aes_ctr_transform(tmp, nonce, input, rks, AES128_ROUNDKEY_DIMENSION);
		memcpy(output + offset, tmp, outlen);
	}

	return status;
}

mqc_status aes256_generate(uint8_t* output, size_t outlen, uint8_t* nonce, const uint8_t* key)
{
	uint8_t input[16];
	size_t offset;
	mqc_status status;

#if defined(AES_AESNI_ENABLED)
	__m128i rks[AES256_ROUNDKEY_DIMENSION];
#else
	uint32_t rks[AES256_ROUNDKEY_DIMENSION];
	clear32(rks, AES256_ROUNDKEY_DIMENSION);
#endif

	clear8(input, 16);
	status = aes_initialize(rks, key, true, AES256);
	offset = 0;

	while (outlen >= 16)
	{
		aes_ctr_transform(output + offset, nonce, input, rks, AES256_ROUNDKEY_DIMENSION);
		increment8(nonce);
		offset += 16;
		outlen -= 16;
	}

	if (outlen > 0)
	{
		uint8_t tmp[16];
		clear8(tmp, 16);
		increment8(nonce);
		aes_ctr_transform(tmp, nonce, input, rks, AES256_ROUNDKEY_DIMENSION);
		memcpy(output + offset, tmp, outlen);
	}

	return status;
}