#include "hcg.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"

/* QSC-HCG-SHA2-512-02 */
static const uint8_t QSC_DEFAULT_INFO[QSC_HCG_INFO_SIZE] = { 
	0x51U, 0x53U, 0x43U, 0x2DU, 0x48U, 0x43U, 0x47U, 0x2DU, 0x53U, 
	0x48U, 0x41U, 0x32U, 0x2DU, 0x35U, 0x31U, 0x32U, 0x2DU, 0x00U, 0x02U };

static void hcg_auto_reseed(qsc_hcg_state* ctx)
{
	if (ctx != NULL)
	{
		/* add a random seed to input seed and info */
		if (ctx->pres == true && ctx->rpos >= QSC_HCG_RESEED_THRESHHOLD)
		{
			qsc_sha512_state sstate = { 0U };
			uint8_t prnd[QSC_HCG_KEY_SIZE];

			qsc_acp_generate(prnd, QSC_HCG_KEY_SIZE);

			qsc_sha512_initialize(&sstate);
			qsc_sha512_update(&sstate, ctx->key, QSC_HCG_KEY_SIZE);
			qsc_sha512_update(&sstate, prnd, QSC_HCG_KEY_SIZE);
			qsc_memutils_secure_erase(prnd, sizeof(prnd));
			/* update the key */
			qsc_sha512_finalize(&sstate, ctx->key);
			ctx->rpos = 0U;
		}
	}
}

static void hcg_fill_buffer(qsc_hcg_state* ctx, uint8_t* buffer)
{
	qsc_hmac512_state hstate = { 0U };

	if (ctx != NULL && buffer != NULL)
	{
		/* increment the nonce counter */
		qsc_intutils_be8increment(ctx->nonce, QSC_HCG_NONCE_SIZE);
		/* initialize HMAC */
		qsc_hmac512_initialize(&hstate, ctx->key, QSC_HCG_KEY_SIZE);
		/* update the MAC with the nonce */
		qsc_hmac512_update(&hstate, ctx->nonce, QSC_HCG_NONCE_SIZE);
		/* update the MAC with the info */
		qsc_hmac512_update(&hstate, ctx->info, ctx->inflen);

		/* if predictive resistance is enabled, add a new seed */
		if (ctx->pres)
		{
			hcg_auto_reseed(ctx);
		}

		/* write the hash to the output buffer */
		qsc_hmac512_finalize(&hstate, buffer);
		/* clear the state */
		qsc_hmac512_dispose(&hstate);
	}
}

void qsc_hcg_dispose(qsc_hcg_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx->info, QSC_HCG_MAX_INFO_SIZE);
		qsc_memutils_secure_erase(ctx->key, QSC_HCG_KEY_SIZE);
		qsc_memutils_secure_erase(ctx->nonce, QSC_HCG_NONCE_SIZE);
		ctx->inflen = 0U;
		ctx->rpos = 0U;
		ctx->pres = false;
	}
}

void qsc_hcg_initialize(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predictive_resistance)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(seed != NULL);
	QSC_ASSERT(seedlen == QSC_HCG_SEED_SIZE);

	if (ctx != NULL && seed != NULL && seedlen == QSC_HCG_SEED_SIZE)
	{
		qsc_hmac512_state hstate = { 0U };

		qsc_memutils_secure_erase(ctx->info, QSC_HCG_MAX_INFO_SIZE);
		qsc_memutils_secure_erase(ctx->key, QSC_HCG_KEY_SIZE);
		qsc_memutils_secure_erase(ctx->nonce, QSC_HCG_NONCE_SIZE);
		ctx->rpos = 0U;
		ctx->pres = predictive_resistance;

		/* initialize the HMAC */
		qsc_hmac512_initialize(&hstate, seed, seedlen);

		/* copy from info string to state */
		if (info != NULL && infolen != 0U)
		{
			ctx->inflen = qsc_intutils_min(QSC_HCG_MAX_INFO_SIZE, infolen);
			qsc_memutils_copy(ctx->info, info, ctx->inflen);
		}
		else
		{
			ctx->inflen = QSC_HCG_INFO_SIZE;
			qsc_memutils_copy(ctx->info, QSC_DEFAULT_INFO, QSC_HCG_INFO_SIZE);
		}

		/* add the info to the MAC */
		qsc_hmac512_update(&hstate, ctx->info, ctx->inflen);

		/* predictive resistance enabled */
		if (ctx->pres)
		{
			uint8_t prnd[QSC_HCG_KEY_SIZE] = { 0U };

			/* add a random seed to hmac message */
			qsc_acp_generate(prnd, QSC_HCG_KEY_SIZE);
			qsc_hmac512_update(&hstate, prnd, QSC_HCG_KEY_SIZE);
			qsc_memutils_secure_erase(prnd, sizeof(prnd));
		}

		/* generate the key */
		qsc_hmac512_finalize(&hstate, ctx->key);
		/* clear internal HMAC state */
        qsc_hmac512_dispose(&hstate);
	}
}

bool qsc_hcg_generate(qsc_hcg_state* ctx, uint8_t* output, size_t otplen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	bool res;

	res = false;

	if (ctx != NULL && output != NULL)
	{
		uint8_t buf[QSC_SHA2_512_HASH_SIZE] = { 0U };
		size_t pos;
		size_t rmd;

		pos = 0U;

		/* loop through the buffer */
		while (otplen != 0U)
		{
			/* fill the buffer */
			hcg_fill_buffer(ctx, buf);

			/* copy to output */
			rmd = qsc_intutils_min(QSC_SHA2_512_HASH_SIZE, otplen);
			qsc_memutils_copy(output + pos, buf, rmd);

			ctx->rpos += rmd;
			otplen -= rmd;
			pos += rmd;
		}

		qsc_memutils_secure_erase(buf, sizeof(buf));
		res = true;
	}

	return res;
}

void qsc_hcg_update(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(seed != NULL);

	if (ctx != NULL && seed != NULL)
	{
		qsc_sha512_state sstate = { 0U };

		qsc_sha512_initialize(&sstate);
		qsc_sha512_update(&sstate, ctx->key, QSC_HCG_KEY_SIZE);
		qsc_sha512_update(&sstate, seed, seedlen);

		/* update the key */
		qsc_sha512_finalize(&sstate, ctx->key);
	}
}

