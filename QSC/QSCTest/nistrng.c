#include "nistrng.h"
#include "../QSC/intutils.h"
#include "../QSC/aes.h"

/*lint -e747 */

qsctest_nist_aes256_state rng_ctx;

static void aes256_ecb(const uint8_t* key, const uint8_t* counter, uint8_t* buffer)
{
	qsc_aes_state state;

	/* jgu checked false warning */
	/*lint -save -e747 */
	const qsc_aes_keyparams kp = { key, 32, NULL };
	qsc_aes_initialize(&state, &kp, true, AES256);
	/*lint -restore */
	qsc_aes_ecb_encrypt_block(&state, buffer, counter);
}

static void increment_counter(uint8_t* counter)
{
	size_t i;

	for (i = 15; i >= 12; i--)
	{
		if (counter[i] == 0xFF)
		{
			counter[i] = 0x00;
		}
		else
		{
			++counter[i];
			break;
		}
	}
}

int32_t qsctest_nistrng_kdf_initialize(qsctest_nist_rng_state* ctx, const uint8_t* seed, const uint8_t* diversifier, uint32_t maxlen)
{
	size_t i;
	int32_t ret;

	if (maxlen < 0x10000000UL)
	{
		ctx->rmdr = maxlen;

		for (i = 0; i < 32; ++i)
		{
			ctx->key[i] = seed[i];
		}

		for (i = 0; i < 8; ++i)
		{
			ctx->ctr[i] = diversifier[i];
		}

		ctx->ctr[11] = (uint8_t)(maxlen % 256);
		maxlen >>= 8;
		ctx->ctr[10] = (uint8_t)(maxlen % 256);
		maxlen >>= 8;
		ctx->ctr[9] = (uint8_t)(maxlen % 256);
		maxlen >>= 8;
		ctx->ctr[8] = (uint8_t)(maxlen % 256);

		for (i = 12; i < 16; ++i)
		{
			ctx->ctr[i] = 0x00;
		}

		ctx->bpos = 16;

		for (i = 0; i < 16; ++i)
		{
			ctx->state[i] = 0x00;
		}

		ret = QSCTEST_NIST_RNG_SUCCESS;
	}
	else
	{
		ret = QSCTEST_NIST_RNG_BAD_MAXLEN;
	}

	return ret;
}

int32_t qsctest_nistrng_kdf_generate(qsctest_nist_rng_state* ctx, uint8_t* output, size_t outlen)
{
	size_t i;
	size_t oft;
	int32_t ret;

	if (output == NULL)
	{
		ret = QSCTEST_NIST_RNG_BAD_OUTBUF;
	}
	else
	{
		if (outlen >= ctx->rmdr)
		{
			ret = QSCTEST_NIST_RNG_BAD_REQ_LEN;
		}
		else
		{
			ctx->rmdr -= outlen;
			oft = 0;

			while (outlen > 0)
			{
				if (outlen <= (16 - ctx->bpos))
				{
					/* buffer has what we need */
					for (i = 0; i < outlen; ++i)
					{
						output[oft + i] = ctx->state[ctx->bpos + i];
					}

					ctx->bpos += outlen;

					break;
				}

				/* take what's in the buffer */
				for (i = 0; i < 16 - ctx->bpos; ++i)
				{
					output[oft + i] = ctx->state[ctx->bpos + i];
				}

				outlen -= 16 - ctx->bpos;
				oft += 16 - ctx->bpos;
				/* generate the encrypted key-stream */
				aes256_ecb(ctx->key, ctx->ctr, ctx->state);
				ctx->bpos = 0;

				/* increment the counter */
				increment_counter(ctx->ctr);
			}

			ret = QSCTEST_NIST_RNG_SUCCESS;
		}
	}

	return ret;
}

void qsctest_nistrng_prng_initialize(const uint8_t* seed, const uint8_t* info, size_t infolen)
{
	uint8_t tmps[48];
    size_t i;

	for (i = 0; i < 48; ++i)
	{
		tmps[i] = seed[i];
	}

	for (i = 0; i < infolen; ++i)
	{
		tmps[i] ^= info[i];
	}

	for (i = 0; i < 32; ++i)
	{
		rng_ctx.key[i] = 0x00;
	}

	for (i = 0; i < 16; ++i)
	{
		rng_ctx.ctr[i] = 0x00;
	}

	qsctest_nistrng_prng_update(rng_ctx.key, rng_ctx.ctr, tmps, 48);
    rng_ctx.rctr = 1;
}

bool qsctest_nistrng_prng_generate(uint8_t* output, size_t outlen)
{
	uint8_t tmpb[16] = { 0 };
	size_t i;
	size_t j;
	size_t rmd;

	i = 0;

	while (outlen > 0)
	{
		/* increment counter */
		increment_counter(rng_ctx.ctr);

		aes256_ecb(rng_ctx.key, rng_ctx.ctr, tmpb);
		rmd = outlen > 15 ? 16 : outlen;

		for (j = 0; j < rmd; ++j)
		{
			output[i + j] = tmpb[j];
		}

		i += rmd;
		outlen -= rmd;
	}

	qsctest_nistrng_prng_update(rng_ctx.key, rng_ctx.ctr, NULL, 0);
	++rng_ctx.rctr;

	return true;
}

void qsctest_nistrng_prng_update(uint8_t* key, uint8_t* counter, const uint8_t* info, size_t infolen)
{
	uint8_t tmpk[48] = { 0 };
	size_t i;

	for (i = 0; i < 3; i++) 
	{
		increment_counter(counter);
		/* generate output */
		aes256_ecb(key, counter, (uint8_t*)tmpk + (16 * i));
	}

	for (i = 0; i < infolen; ++i)
	{
		tmpk[i] ^= info[i];
	}

	for (i = 0; i < 32; ++i)
	{
		key[i] = tmpk[i];
	}

	for (i = 0; i < 16; ++i)
	{
		counter[i] = tmpk[32 + i];
	}
}
