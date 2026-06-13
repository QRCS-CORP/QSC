#include "pbmac1.h"
#include "memutils.h"

static bool pbmac1_keyparams_valid(const qsc_pbmac1_keyparams* keyparams)
{
	bool res;

	res = false;

	if (keyparams != (const qsc_pbmac1_keyparams*)NULL)
	{
		if ((keyparams->password != (const uint8_t*)NULL || keyparams->passwordlen == 0U) &&
			(keyparams->salt != (const uint8_t*)NULL || keyparams->saltlen == 0U) &&
			keyparams->iterations != 0U && keyparams->iterations <= QSC_PBMAC1_MAX_ITERATIONS &&
			qsc_pbmac1_mac_size(keyparams->hash) != 0U)
		{
			res = true;
		}
	}

	return res;
}

static size_t pbmac1_default_key_size(qsc_pbmac1_hash_type hash)
{
	return qsc_pbmac1_mac_size(hash);
}

static void pbmac1_hmac_compute(qsc_pbmac1_hash_type hash, uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen)
{
	switch (hash)
	{
		case qsc_pbmac1_hash_sha256:
		{
			qsc_hmac256_compute(output, message, msglen, key, keylen);
			break;
		}
		case qsc_pbmac1_hash_sha384:
		{
			qsc_hmac384_compute(output, message, msglen, key, keylen);
			break;
		}
		case qsc_pbmac1_hash_sha512:
		{
			qsc_hmac512_compute(output, message, msglen, key, keylen);
			break;
		}
		default:
		{
			break;
		}
	}
}

static void pbmac1_hmac_finalize(qsc_pbmac1_state* ctx, uint8_t* output)
{
	switch (ctx->hash)
	{
		case qsc_pbmac1_hash_sha256:
		{
			qsc_hmac256_finalize(&ctx->state.h256, output);
			break;
		}
		case qsc_pbmac1_hash_sha384:
		{
			qsc_hmac384_finalize(&ctx->state.h384, output);
			break;
		}
		case qsc_pbmac1_hash_sha512:
		{
			qsc_hmac512_finalize(&ctx->state.h512, output);
			break;
		}
		default:
		{
			break;
		}
	}
}

static void pbmac1_hmac_initialize(qsc_pbmac1_state* ctx, const uint8_t* key, size_t keylen)
{
	switch (ctx->hash)
	{
		case qsc_pbmac1_hash_sha256:
		{
			qsc_hmac256_initialize(&ctx->state.h256, key, keylen);
			break;
		}
		case qsc_pbmac1_hash_sha384:
		{
			qsc_hmac384_initialize(&ctx->state.h384, key, keylen);
			break;
		}
		case qsc_pbmac1_hash_sha512:
		{
			qsc_hmac512_initialize(&ctx->state.h512, key, keylen);
			break;
		}
		default:
		{
			break;
		}
	}
}

static void pbmac1_hmac_update(qsc_pbmac1_state* ctx, const uint8_t* message, size_t msglen)
{
	switch (ctx->hash)
	{
		case qsc_pbmac1_hash_sha256:
		{
			qsc_hmac256_update(&ctx->state.h256, message, msglen);
			break;
		}
		case qsc_pbmac1_hash_sha384:
		{
			qsc_hmac384_update(&ctx->state.h384, message, msglen);
			break;
		}
		case qsc_pbmac1_hash_sha512:
		{
			qsc_hmac512_update(&ctx->state.h512, message, msglen);
			break;
		}
		default:
		{
			break;
		}
	}
}

static bool pbmac1_pbkdf2(uint8_t* output, size_t outlen, const qsc_pbmac1_keyparams* keyparams)
{
	uint8_t block[QSC_PBMAC1_MAX_MAC_SIZE] = { 0U };
	uint8_t ctr[4U] = { 0U };
	uint8_t u[QSC_PBMAC1_MAX_MAC_SIZE] = { 0U };
	size_t blockindex;
	size_t offset;
	size_t rmd;
	size_t hlen;
	size_t i;
	size_t j;
	bool res;

	res = false;

	if (output != (uint8_t*)NULL && outlen != 0U && pbmac1_keyparams_valid(keyparams) == true)
	{
		hlen = qsc_pbmac1_mac_size(keyparams->hash);

		if (outlen <= (((size_t)UINT32_MAX) * hlen))
		{
			offset = 0U;

			for (blockindex = 1U; offset < outlen; ++blockindex)
			{
				ctr[0U] = (uint8_t)((blockindex >> 24U) & 0xFFU);
				ctr[1U] = (uint8_t)((blockindex >> 16U) & 0xFFU);
				ctr[2U] = (uint8_t)((blockindex >> 8U) & 0xFFU);
				ctr[3U] = (uint8_t)(blockindex & 0xFFU);

				qsc_pbmac1_state hctx = { 0 };
				hctx.hash = keyparams->hash;
				pbmac1_hmac_initialize(&hctx, keyparams->password, keyparams->passwordlen);

				if (keyparams->saltlen != 0U)
				{
					pbmac1_hmac_update(&hctx, keyparams->salt, keyparams->saltlen);
				}

				pbmac1_hmac_update(&hctx, ctr, sizeof(ctr));
				pbmac1_hmac_finalize(&hctx, u);
				qsc_memutils_copy(block, u, hlen);

				for (i = 1U; i < (size_t)keyparams->iterations; ++i)
				{
					pbmac1_hmac_compute(keyparams->hash, u, u, hlen, keyparams->password, keyparams->passwordlen);

					for (j = 0U; j < hlen; ++j)
					{
						block[j] ^= u[j];
					}
				}

				rmd = (outlen - offset < hlen) ? (outlen - offset) : hlen;
				qsc_memutils_copy(output + offset, block, rmd);
				offset += rmd;
			}

			res = true;
		}
	}

	qsc_memutils_secure_erase(block, sizeof(block));
	qsc_memutils_secure_erase(u, sizeof(u));

	return res;
}

bool qsc_pbmac1_compute(uint8_t* output, const qsc_pbmac1_keyparams* keyparams, const uint8_t* message, size_t msglen)
{
	qsc_pbmac1_state ctx = { 0 };
	bool res;

	QSC_ASSERT(output != NULL);
	QSC_ASSERT(keyparams != NULL);
	QSC_ASSERT(message != NULL || msglen == 0U);

	res = false;

	if (qsc_pbmac1_initialize(&ctx, keyparams) == true)
	{
		if (qsc_pbmac1_update(&ctx, message, msglen) == true)
		{
			res = qsc_pbmac1_finalize(&ctx, output);
		}
		else
		{
			qsc_pbmac1_dispose(&ctx);
		}
	}

	return res;
}

bool qsc_pbmac1_derive_key(uint8_t* output, size_t outlen, const qsc_pbmac1_keyparams* keyparams)
{
	bool res;

	QSC_ASSERT(output != NULL);
	QSC_ASSERT(keyparams != NULL);

	res = false;

	if (outlen != 0U && outlen <= QSC_PBMAC1_MAX_KEY_SIZE)
	{
		res = pbmac1_pbkdf2(output, outlen, keyparams);
	}

	return res;
}

void qsc_pbmac1_dispose(qsc_pbmac1_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != (qsc_pbmac1_state*)NULL)
	{
		switch (ctx->hash)
		{
			case qsc_pbmac1_hash_sha256:
			{
				qsc_hmac256_dispose(&ctx->state.h256);
				break;
			}
			case qsc_pbmac1_hash_sha384:
			{
				qsc_hmac384_dispose(&ctx->state.h384);
				break;
			}
			case qsc_pbmac1_hash_sha512:
			{
				qsc_hmac512_dispose(&ctx->state.h512);
				break;
			}
			default:
			{
				break;
			}
		}

		qsc_memutils_secure_erase(ctx, sizeof(qsc_pbmac1_state));
	}
}

bool qsc_pbmac1_finalize(qsc_pbmac1_state* ctx, uint8_t* output)
{
	bool res;

	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	res = false;

	if (ctx != (qsc_pbmac1_state*)NULL && output != (uint8_t*)NULL && ctx->initialized == true)
	{
		pbmac1_hmac_finalize(ctx, output);
		ctx->initialized = false;
		res = true;
		qsc_pbmac1_dispose(ctx);
	}

	return res;
}

bool qsc_pbmac1_initialize(qsc_pbmac1_state* ctx, const qsc_pbmac1_keyparams* keyparams)
{
	uint8_t key[QSC_PBMAC1_MAX_KEY_SIZE] = { 0U };
	size_t keylen;
	bool res;

	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(keyparams != NULL);

	res = false;

	if (ctx != (qsc_pbmac1_state*)NULL && pbmac1_keyparams_valid(keyparams) == true)
	{
		keylen = (keyparams->keylen == 0U) ? pbmac1_default_key_size(keyparams->hash) : keyparams->keylen;

		if (keylen != 0U && keylen <= QSC_PBMAC1_MAX_KEY_SIZE)
		{
			qsc_memutils_clear(ctx, sizeof(qsc_pbmac1_state));

			if (qsc_pbmac1_derive_key(key, keylen, keyparams) == true)
			{
				ctx->hash = keyparams->hash;
				pbmac1_hmac_initialize(ctx, key, keylen);
				ctx->initialized = true;
				res = true;
			}
		}
	}

	qsc_memutils_secure_erase(key, sizeof(key));

	return res;
}

size_t qsc_pbmac1_mac_size(qsc_pbmac1_hash_type hash)
{
	size_t res;

	res = 0U;

	switch (hash)
	{
		case qsc_pbmac1_hash_sha256:
		{
			res = QSC_PBMAC1_256_MAC_SIZE;
			break;
		}
		case qsc_pbmac1_hash_sha384:
		{
			res = QSC_PBMAC1_384_MAC_SIZE;
			break;
		}
		case qsc_pbmac1_hash_sha512:
		{
			res = QSC_PBMAC1_512_MAC_SIZE;
			break;
		}
		default:
		{
			break;
		}
	}

	return res;
}

bool qsc_pbmac1_update(qsc_pbmac1_state* ctx, const uint8_t* message, size_t msglen)
{
	bool res;

	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(message != NULL || msglen == 0U);

	res = false;

	if (ctx != (qsc_pbmac1_state*)NULL && ctx->initialized == true && (message != (const uint8_t*)NULL || msglen == 0U))
	{
		pbmac1_hmac_update(ctx, message, msglen);
		res = true;
	}

	return res;
}

bool qsc_pbmac1_verify(const uint8_t* code, size_t codelen, const qsc_pbmac1_keyparams* keyparams, const uint8_t* message, size_t msglen)
{
	uint8_t mac[QSC_PBMAC1_MAX_MAC_SIZE] = { 0U };
	size_t mlen;
	bool res;

	QSC_ASSERT(code != NULL);
	QSC_ASSERT(keyparams != NULL);
	QSC_ASSERT(message != NULL || msglen == 0U);

	res = false;

	if (code != (const uint8_t*)NULL && keyparams != (const qsc_pbmac1_keyparams*)NULL)
	{
		mlen = qsc_pbmac1_mac_size(keyparams->hash);

		if (mlen != 0U && codelen == mlen)
		{
			if (qsc_pbmac1_compute(mac, keyparams, message, msglen) == true)
			{
				res = qsc_memutils_are_equal(mac, code, mlen);
			}
		}
	}

	qsc_memutils_secure_erase(mac, sizeof(mac));

	return res;
}
