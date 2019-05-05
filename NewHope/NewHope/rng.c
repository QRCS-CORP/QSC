#include "rng.h"
#include "aes.h"
/* no other option but to use memcpy here */
/*lint -save -e829 */
#include <string.h>
/*lint -restore */

/*lint -e747 */

#define RNG_SUCCESS 0
#define RNG_BAD_MAXLEN -1
#define RNG_BAD_OUTBUF -2
#define RNG_BAD_REQ_LEN -3

AES256_CTR_DRBG_struct  DRBG_ctx;

static void aes256_ecb(const uint8_t* key, const uint8_t* counter, uint8_t* buffer)
{
	uint32_t roundkeys[AES256_ROUNDKEY_DIMENSION] = { 0 };

	/* jgu checked false warning */
	/*lint -save -e747 */
	aes_initialize(roundkeys, key, true, AES256);
	/*lint -restore */
	aes_ecb_encrypt(buffer, counter, roundkeys, AES256_ROUNDKEY_DIMENSION);
}

int32_t seedexpander_init(AES_XOF_struct* ctx, const uint8_t* seed, const uint8_t* diversifier, uint32_t maxlen)
{
	int32_t ret;

	if (maxlen < 0x10000000UL)
	{
		ctx->remainder = maxlen;
		memcpy(ctx->key, seed, 32);
		memcpy(ctx->ctr, diversifier, 8);

		ctx->ctr[11] = maxlen % 256;
		maxlen >>= 8;
		ctx->ctr[10] = maxlen % 256;
		maxlen >>= 8;
		ctx->ctr[9] = maxlen % 256;
		maxlen >>= 8;
		ctx->ctr[8] = maxlen % 256;
		memset(ctx->ctr + 12, 0x00, 4);

		ctx->bpos = 16;
		memset(ctx->buffer, 0x00, 16);
		ret = RNG_SUCCESS;
	}
	else
	{
		ret = RNG_BAD_MAXLEN;
	}

	return ret;
}

int32_t seedexpander(AES_XOF_struct* ctx, uint8_t* output, size_t outlen)
{
	size_t i;
	size_t offset;
	int32_t ret;

	if (output == NULL)
	{
		ret = RNG_BAD_OUTBUF;
	}
	else
	{
		if (outlen >= ctx->remainder)
		{
			ret = RNG_BAD_REQ_LEN;
		}
		else
		{
			ctx->remainder -= outlen;
			offset = 0;

			while (outlen > 0)
			{
				if (outlen <= (16 - ctx->bpos))
				{
					/* buffer has what we need */
					memcpy(output + offset, ctx->buffer + ctx->bpos, outlen);
					ctx->bpos += outlen;
					break;
				}

				/* take what's in the buffer */
				memcpy(output + offset, ctx->buffer + ctx->bpos, 16 - ctx->bpos);
				outlen -= 16 - ctx->bpos;
				offset += 16 - ctx->bpos;

				aes256_ecb(ctx->key, ctx->ctr, ctx->buffer);
				ctx->bpos = 0;

				/* increment the counter */
				for (i = 15; i >= 12; i--)
				{
					if (ctx->ctr[i] == 0xff)
					{
						ctx->ctr[i] = 0x00;
					}
					else
					{
						ctx->ctr[i]++;
						break;
					}
				}
			}

			ret = RNG_SUCCESS;
		}
	}

	return ret;
}

void randombytes_init(const uint8_t* seed, const uint8_t* info, size_t infolen)
{
    uint8_t tmps[48];
    size_t i;
    
    memcpy(tmps, seed, 48);

	for (i = 0; i < infolen; ++i)
	{
		tmps[i] ^= info[i];
	}

    memset(DRBG_ctx.Key, 0x00, 32);
    memset(DRBG_ctx.V, 0x00, 16);
	randombytes_update(DRBG_ctx.Key, DRBG_ctx.V, tmps, 48);
    DRBG_ctx.reseed_counter = 1;
}

int32_t randombytes(uint8_t* output, size_t outlen)
{
	uint8_t block[16];
	size_t i;
	size_t j;
	size_t rmdlen;

	i = 0;

	while (outlen > 0)
	{
		/* increment counter */
		j = 16;

		do
		{
			--j;

			if (DRBG_ctx.V[j] == 0xFF)
			{
				DRBG_ctx.V[j] = 0x00;
			}
			else 
			{
				++DRBG_ctx.V[j];
				break;
			}
		} 
		while (j != 0);

		aes256_ecb(DRBG_ctx.Key, DRBG_ctx.V, block);

		rmdlen = outlen > 15 ? 16 : outlen;
		memcpy(output + i, block, rmdlen);
		i += rmdlen;
		outlen -= rmdlen;
	}

	randombytes_update(DRBG_ctx.Key, DRBG_ctx.V, NULL, 0);
	DRBG_ctx.reseed_counter++;

	return RNG_SUCCESS;
}

void randombytes_update(uint8_t* key, uint8_t* counter, const uint8_t* info, size_t infolen)
{
	uint8_t temp[48];
	size_t i;
	size_t j;

	for (i = 0; i < 3; i++) 
	{
		j = 16;

		/* increment counter */
		do
		{
			--j;

			if (counter[j] == 0xff)
			{
				counter[j] = 0x00;
			}
			else 
			{
				++counter[j];
				break;
			}
		} 
		while (j != 0);

		/* generate output */
		aes256_ecb(key, counter, temp + 16 * i);
	}

	for (i = 0; i < infolen; ++i)
	{
		temp[i] ^= info[i];
	}

	memcpy(key, temp, 32);
	memcpy(counter, temp + 32, 16);
}
