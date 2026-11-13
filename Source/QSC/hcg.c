#include "hcg.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"

/* \cond DOXYGEN_NO_DOCUMENT */

static void hcg_hmac_v(qsc_hcg_state* ctx)
{
	/* replace V with HMAC(Key, V), securely disposing temporary HMAC state */
	qsc_hmac512_state hstate = { 0U };

	qsc_hmac512_initialize(&hstate, ctx->key, QSC_HCG_KEY_SIZE);
	qsc_hmac512_update(&hstate, ctx->value, QSC_HCG_KEY_SIZE);
	qsc_hmac512_finalize(&hstate, ctx->value);
	qsc_hmac512_dispose(&hstate);
}

static void hcg_drbg_update(qsc_hcg_state* ctx, const uint8_t* data1, size_t len1, const uint8_t* data2, size_t len2, const uint8_t* data3, size_t len3)
{
	/* update Key and V according to SP 800-90A 10.1.2.2 */
	qsc_hmac512_state hstate = { 0U };
	uint8_t sep;
	bool provided;

	provided = (len1 != 0U || len2 != 0U || len3 != 0U);
	sep = 0U;
	qsc_hmac512_initialize(&hstate, ctx->key, QSC_HCG_KEY_SIZE);
	qsc_hmac512_update(&hstate, ctx->value, QSC_HCG_KEY_SIZE);
	qsc_hmac512_update(&hstate, &sep, sizeof(sep));

	if (len1 != 0U)
	{
		qsc_hmac512_update(&hstate, data1, len1);
	}

	if (len2 != 0U)
	{
		qsc_hmac512_update(&hstate, data2, len2);
	}

	if (len3 != 0U)
	{
		qsc_hmac512_update(&hstate, data3, len3);
	}

	qsc_hmac512_finalize(&hstate, ctx->key);
	qsc_hmac512_dispose(&hstate);
	hcg_hmac_v(ctx);

	if (provided == true)
	{
		sep = 1U;
		qsc_hmac512_initialize(&hstate, ctx->key, QSC_HCG_KEY_SIZE);
		qsc_hmac512_update(&hstate, ctx->value, QSC_HCG_KEY_SIZE);
		qsc_hmac512_update(&hstate, &sep, sizeof(sep));

		if (len1 != 0U)
		{
			qsc_hmac512_update(&hstate, data1, len1);
		}

		if (len2 != 0U)
		{
			qsc_hmac512_update(&hstate, data2, len2);
		}

		if (len3 != 0U)
		{
			qsc_hmac512_update(&hstate, data3, len3);
		}

		qsc_hmac512_finalize(&hstate, ctx->key);
		qsc_hmac512_dispose(&hstate);
		hcg_hmac_v(ctx);
	}
}

static bool hcg_valid_input(const uint8_t* input, size_t length)
{
	/* check an optional buffer against the implementation input bound */
	bool res;

	res = (length <= QSC_HCG_MAX_INPUT_SIZE && (length == 0U || input != NULL));

	return res;
}

static bool hcg_auto_reseed(qsc_hcg_state* ctx, const uint8_t* additional, size_t addlen)
{
	/* acquire ACP entropy and perform a standardized reseed */
	uint8_t entropy[QSC_HCG_MIN_ENTROPY_SIZE] = { 0U };
	bool res;

	res = false;

	if (qsc_acp_generate(entropy, sizeof(entropy)) == true)
	{
		res = qsc_hcg_reseed(ctx, entropy, sizeof(entropy), additional, addlen);
	}

	qsc_memutils_secure_erase(entropy, sizeof(entropy));

	return res;
}

static bool hcg_health_test(void)
{
	/* run an internal SHA-512 HMAC_DRBG instantiate/generate known-answer health test */
	static const uint8_t expected[QSC_HCG_KEY_SIZE] =
	{
		0x5AU, 0x94U, 0x7EU, 0x2EU, 0xC8U, 0x11U, 0x34U, 0x4BU,
		0x50U, 0x6FU, 0x32U, 0x1EU, 0x3FU, 0x1FU, 0xBDU, 0xE3U,
		0xFDU, 0xE9U, 0x68U, 0x45U, 0x30U, 0x1AU, 0x7CU, 0x17U,
		0x93U, 0xE7U, 0x2BU, 0x20U, 0x71U, 0xE1U, 0xD9U, 0x84U,
		0x84U, 0x6EU, 0xDAU, 0x8EU, 0xE0U, 0xE9U, 0x73U, 0x01U,
		0xDAU, 0x2EU, 0x6DU, 0x07U, 0xC4U, 0x93U, 0x7BU, 0x7AU,
		0x50U, 0xC7U, 0x29U, 0xA1U, 0xADU, 0x16U, 0xE5U, 0x94U,
		0xABU, 0x3DU, 0xD9U, 0x65U, 0x61U, 0x70U, 0x92U, 0x70U
	};

	uint8_t entropy[QSC_HCG_MIN_ENTROPY_SIZE] = { 0U };
	uint8_t nonce[QSC_HCG_NONCE_SIZE] = { 0U };
	qsc_hcg_state test = { 0U };
	size_t i;
	bool res;

	for (i = 0U; i < sizeof(entropy); ++i)
	{
		entropy[i] = (uint8_t)i;
	}

	for (i = 0U; i < sizeof(nonce); ++i)
	{
		nonce[i] = (uint8_t)(i + sizeof(entropy));
	}

	qsc_memutils_set_value(test.value, QSC_HCG_KEY_SIZE, 0x01U);
	hcg_drbg_update(&test, entropy, sizeof(entropy), nonce, sizeof(nonce), NULL, 0U);
	hcg_hmac_v(&test);
	res = qsc_memutils_are_equal(test.value, expected, sizeof(expected));
	qsc_hcg_dispose(&test);
	qsc_memutils_secure_erase(entropy, sizeof(entropy));
	qsc_memutils_secure_erase(nonce, sizeof(nonce));

	return res;
}

void qsc_hcg_dispose(qsc_hcg_state* ctx)
{
	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx, sizeof(qsc_hcg_state));
	}
}

bool qsc_hcg_instantiate(qsc_hcg_state* ctx, const uint8_t* entropy, size_t entlen, const uint8_t* nonce, size_t noncelen, const uint8_t* personalization, size_t perslen)
{
	bool res;

	res = false;

	if (ctx != NULL)
	{
		qsc_hcg_dispose(ctx);

		if (entropy != NULL && hcg_valid_input(entropy, entlen) == true && hcg_valid_input(nonce, noncelen) == true && hcg_valid_input(personalization, perslen) == true &&
			entlen >= QSC_HCG_MIN_ENTROPY_SIZE && ((noncelen >= QSC_HCG_NONCE_SIZE) || (noncelen == 0U && entlen >= QSC_HCG_MIN_SEED_SIZE)) && hcg_health_test() == true)
		{
			qsc_memutils_set_value(ctx->value, QSC_HCG_KEY_SIZE, 0x01U);
			hcg_drbg_update(ctx, entropy, entlen, nonce, noncelen, personalization, perslen);
			ctx->reseed_counter = 1U;
			ctx->initialized = true;
			res = true;
		}
	}

	return res;
}

bool qsc_hcg_initialize_auto(qsc_hcg_state* ctx, const uint8_t* personalization, size_t perslen, bool prediction_resistance)
{
	uint8_t seed[QSC_HCG_MIN_SEED_SIZE] = { 0U };
	bool res;

	res = false;

	if (ctx != NULL)
	{
		qsc_hcg_dispose(ctx);

		if (hcg_valid_input(personalization, perslen) == true && qsc_acp_generate(seed, sizeof(seed)) == true)
		{
			res = qsc_hcg_instantiate(ctx, seed, QSC_HCG_MIN_ENTROPY_SIZE, seed + QSC_HCG_MIN_ENTROPY_SIZE, QSC_HCG_NONCE_SIZE, personalization, perslen);

			if (res == true)
			{
				ctx->auto_reseed = true;
				ctx->pres = prediction_resistance;
			}
		}
	}

	qsc_memutils_secure_erase(seed, sizeof(seed));

	return res;
}

void qsc_hcg_initialize(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool pres)
{
	bool res;

	res = false;

	if (ctx != NULL)
	{
		qsc_hcg_dispose(ctx);

		if (seed != NULL && seedlen == QSC_HCG_SEED_SIZE)
		{
			res = qsc_hcg_instantiate(ctx, seed, seedlen, NULL, 0U, info, infolen);

			if (res == true && pres == true)
			{
				ctx->auto_reseed = true;
				ctx->pres = true;
				res = hcg_auto_reseed(ctx, NULL, 0U);
			}
		}

		if (res == false)
		{
			qsc_hcg_dispose(ctx);
		}
	}
}

bool qsc_hcg_reseed(qsc_hcg_state* ctx, const uint8_t* entropy, size_t entlen, const uint8_t* additional, size_t addlen)
{
	bool res;

	res = false;

	if (ctx != NULL && ctx->initialized == true && entropy != NULL && entlen >= QSC_HCG_MIN_ENTROPY_SIZE &&
		hcg_valid_input(entropy, entlen) == true && hcg_valid_input(additional, addlen) == true)
	{
		hcg_drbg_update(ctx, entropy, entlen, additional, addlen, NULL, 0U);
		ctx->reseed_counter = 1U;
		ctx->generated_bytes = 0U;
		res = true;
	}

	return res;
}

bool qsc_hcg_generate_ex(qsc_hcg_state* ctx, uint8_t* output, size_t otplen, const uint8_t* additional, size_t addlen)
{
	size_t pos;
	size_t rmd;
	bool res;
	bool pr;

	res = false;
	pr = false;
	pos = 0U;

	if (ctx != NULL && ctx->initialized == true && output != NULL && otplen != 0U && otplen <= QSC_HCG_MAX_REQUEST_SIZE && hcg_valid_input(additional, addlen) == true)
	{
		res = true;

		if (ctx->auto_reseed == true && (ctx->pres == true || ctx->generated_bytes >= QSC_HCG_RESEED_THRESHOLD || ctx->reseed_counter > QSC_HCG_RESEED_INTERVAL))
		{
			pr = ctx->pres;
			res = hcg_auto_reseed(ctx, (pr == true) ? additional : NULL, (pr == true) ? addlen : 0U);

			if (res == false)
			{
				qsc_hcg_dispose(ctx);
			}
		}

		if (res == true && ctx->reseed_counter > QSC_HCG_RESEED_INTERVAL)
		{
			res = false;
		}

		if (res == true)
		{
			if (pr == true)
			{
				additional = NULL;
				addlen = 0U;
			}

			if (addlen != 0U)
			{
				hcg_drbg_update(ctx, additional, addlen, NULL, 0U, NULL, 0U);
			}

			while (pos < otplen)
			{
				hcg_hmac_v(ctx);
				rmd = qsc_intutils_min(QSC_HCG_KEY_SIZE, otplen - pos);
				qsc_memutils_copy(output + pos, ctx->value, rmd);
				pos += rmd;
			}

			hcg_drbg_update(ctx, additional, addlen, NULL, 0U, NULL, 0U);
			ctx->reseed_counter += 1U;
			ctx->generated_bytes += otplen;
		}
	}

	if (res == false && output != NULL && otplen <= QSC_HCG_MAX_REQUEST_SIZE)
	{
		qsc_memutils_clear(output, otplen);
	}


	return res;
}

bool qsc_hcg_generate(qsc_hcg_state* ctx, uint8_t* output, size_t otplen)
{
	bool res;

	res = qsc_hcg_generate_ex(ctx, output, otplen, NULL, 0U);

	return res;
}

void qsc_hcg_update(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen)
{
	if (ctx != NULL && ctx->initialized == true && seed != NULL && seedlen != 0U && seedlen <= QSC_HCG_MAX_INPUT_SIZE)
	{
		hcg_drbg_update(ctx, seed, seedlen, NULL, 0U, NULL, 0U);
	}
}

/* \endcond DOXYGEN_NO_DOCUMENT */
