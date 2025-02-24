#include "hcg.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"

/* QSC-HCG-SHA2-512-02 */
static const uint8_t QSC_DEFAULT_INFO[QSC_HCG_INFO_SIZE] = { 
	0x51, 0x53, 0x43, 0x2D, 0x48, 0x43, 0x47, 0x2D, 0x53, 
	0x48, 0x41, 0x32, 0x2D, 0x35, 0x31, 0x32, 0x2D, 0x00, 0x02 };

static void csg_auto_reseed(qsc_hcg_state* ctx)
{
	/* add a random seed to input seed and info */
	if (ctx->pres == true && ctx->rpos >= QSC_HCG_RESEED_THRESHHOLD)
	{
		qsc_sha512_state sstate = { 0 };
		uint8_t prnd[QSC_HCG_KEY_SIZE];

		qsc_acp_generate(prnd, QSC_HCG_KEY_SIZE);

		qsc_sha512_initialize(&sstate);
		qsc_sha512_update(&sstate, ctx->key, QSC_HCG_KEY_SIZE);
		qsc_sha512_update(&sstate, prnd, QSC_HCG_KEY_SIZE);
		/* update the key */
		qsc_sha512_finalize(&sstate, ctx->key);
		ctx->rpos = 0;
	}
}

static void hcg_fill_buffer(qsc_hcg_state* ctx, uint8_t* buffer)
{
	qsc_hmac512_state hstate = { 0 };

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
		csg_auto_reseed(ctx);
	}

	/* write the hash to the output buffer */
	qsc_hmac512_finalize(&hstate, buffer);
	/* clear the state */
	qsc_hmac512_dispose(&hstate);
}

void qsc_hcg_dispose(qsc_hcg_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->info, QSC_HCG_MAX_INFO_SIZE);
		qsc_memutils_clear(ctx->key, QSC_HCG_KEY_SIZE);
		qsc_memutils_clear(ctx->nonce, QSC_HCG_NONCE_SIZE);
		ctx->inflen = 0;
		ctx->rpos = 0;
		ctx->pres = false;
	}
}

void qsc_hcg_initialize(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predictive_resistance)
{
	assert(ctx != NULL);
	assert(seed != NULL);
	assert(seedlen == QSC_HCG_SEED_SIZE);

	if (ctx != NULL && seed != NULL && seedlen == QSC_HCG_SEED_SIZE)
	{
		qsc_hmac512_state hstate = { 0 };

		qsc_memutils_clear(ctx->info, QSC_HCG_MAX_INFO_SIZE);
		qsc_memutils_clear(ctx->key, QSC_HCG_KEY_SIZE);
		qsc_memutils_clear(ctx->nonce, QSC_HCG_NONCE_SIZE);
		ctx->rpos = 0;
		ctx->pres = predictive_resistance;

		/* initialize the HMAC */
		qsc_hmac512_initialize(&hstate, seed, seedlen);

		/* copy from info string to state */
		if (infolen != 0)
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
			uint8_t prnd[QSC_HCG_KEY_SIZE];

			/* add a random seed to hmac message */
			qsc_acp_generate(prnd, QSC_HCG_KEY_SIZE);
			qsc_hmac512_update(&hstate, prnd, QSC_HCG_KEY_SIZE);
		}

		/* generate the key */
		qsc_hmac512_finalize(&hstate, ctx->key);
	}
}

void qsc_hcg_generate(qsc_hcg_state* ctx, uint8_t* output, size_t otplen)
{
	assert(ctx != NULL);
	assert(output != NULL);

	if (ctx != NULL && output != NULL)
	{
		uint8_t buf[QSC_SHA2_512_HASH_SIZE] = { 0 };
		size_t pos;
		size_t rmd;

		pos = 0;

		/* loop through the buffer */
		while (otplen != 0)
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

		/* reseed check */
		csg_auto_reseed(ctx);
	}
}

void qsc_hcg_update(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen)
{
	assert(ctx != NULL);
	assert(seed != NULL);

	if (ctx != NULL && seed != NULL)
	{
		qsc_sha512_state sstate = { 0 };

		qsc_sha512_initialize(&sstate);
		qsc_sha512_update(&sstate, ctx->key, QSC_HCG_KEY_SIZE);
		qsc_sha512_update(&sstate, seed, seedlen);

		/* update the key */
		qsc_sha512_finalize(&sstate, ctx->key);
	}
}

