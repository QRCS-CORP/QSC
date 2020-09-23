#include "hcg.h"
#include "intutils.h"
#include "memutils.h"
#include "csp.h"

/* QSC-HCG-SHA51201*/
static const uint8_t QSC_DEFAULT_INFO[17] = { 0x51, 0x53, 0x43, 0x2D, 0x48, 0x43, 0x47, 0x2D, 0x53, 0x48, 0x41, 0x32, 0x35, 0x31, 0x32, 0x00, 0x01 };

static void hcg_fill_buffer(qsc_hcg_state* ctx)
{
	/* similar mechanism to hkdf, but with a larger counter and set info size */

	uint8_t hblk[QSC_HMAC_512_RATE] = { 0 };

	/* copy the cache */
	qsc_memutils_copy(hblk, ctx->cache, sizeof(ctx->cache));

	/* increment and copy the counter */
	qsc_intutils_be8increment(ctx->nonce, sizeof(ctx->nonce));
	qsc_memutils_copy(hblk + sizeof(ctx->cache), ctx->nonce, sizeof(ctx->nonce));

	/* copy the info */
	qsc_memutils_copy(hblk + sizeof(ctx->cache) + sizeof(ctx->nonce), ctx->info, sizeof(ctx->info));

	/* finalize and cache the block */
	qsc_hmac512_update(&ctx->hstate, hblk, sizeof(hblk));
	qsc_hmac512_finalize(&ctx->hstate, ctx->cache);

	/* reset cache counters */
	ctx->crmd = QSC_HCG_CACHE_SIZE;
	ctx->cpos = 0;
}

static csg_auto_reseed(qsc_hcg_state* ctx)
{
	if (ctx->pres && ctx->bctr >= QSC_HCG_RESEED_THRESHHOLD)
	{
		/* add a random seed to input seed and info */
		uint8_t prand[QSC_HMAC_512_RATE];
		qsc_csp_generate(prand, sizeof(prand));

		/* update hmac */
		qsc_hmac512_update(&ctx->hstate, prand, sizeof(prand));

		/* re-fill the buffer and reset counter */
		hcg_fill_buffer(ctx);
		ctx->bctr = 0;
	}
}

void qsc_hcg_dispose(qsc_hcg_state* ctx)
{
	memset(ctx->cache, 0x00, sizeof(ctx->cache));
	
	ctx->bctr = 0;
	ctx->cpos = 0;
	ctx->crmd = 0;
	ctx->pres = false;
}

void qsc_hcg_initialize(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predictive_resistance)
{
	assert(ctx != NULL);
	assert(seed != NULL);
	assert(seedlen == QSC_HCG_SEED_SIZE);

	qsc_intutils_clear8(ctx->cache, sizeof(ctx->cache));
	qsc_intutils_clear8(ctx->nonce, sizeof(ctx->nonce));
	ctx->bctr = 0;
	ctx->cpos = 0;
	ctx->pres = predictive_resistance;

	qsc_hmac512_initialize(&ctx->hstate, seed, seedlen);

	/* copy from the info string to state */
	if (infolen != 0)
	{
		const size_t RMDLEN = qsc_intutils_min(sizeof(ctx->info), infolen);
		qsc_memutils_copy(ctx->info, info, RMDLEN);
	}
	else
	{
		qsc_memutils_copy(ctx->info, QSC_DEFAULT_INFO, sizeof(QSC_DEFAULT_INFO));
	}

	if (ctx->pres)
	{
		/* add a random seed to hmac state */
		uint8_t prand[QSC_HMAC_512_RATE];
		qsc_csp_generate(prand, sizeof(prand));
		qsc_hmac512_update(&ctx->hstate, prand, sizeof(prand));
	}

	/* pre-load the state cache */
	qsc_hmac512_finalize(&ctx->hstate, ctx->cache);

	/* cache the first block */
	hcg_fill_buffer(ctx);
}

void qsc_hcg_generate(qsc_hcg_state* ctx, uint8_t* output, size_t outlen)
{
	assert(ctx != NULL);
	assert(output != NULL);

	ctx->bctr += outlen;

	if (ctx->crmd < outlen)
	{
		size_t outpos;

		outpos = 0;

		/* copy remaining bytes from the cache */
		if (ctx->crmd != 0)
		{
			/* empty the state buffer */
			qsc_memutils_copy(output, ctx->cache + ctx->cpos, ctx->crmd);
			outpos += ctx->crmd;
			outlen -= ctx->crmd;
		}

		/* loop through the remainder */
		while (outlen != 0)
		{
			/* fill the buffer */
			hcg_fill_buffer(ctx);

			/* copy to output */
			const size_t RMDLEN = qsc_intutils_min(ctx->crmd, outlen);
			qsc_memutils_copy(output + outpos, ctx->cache, RMDLEN);

			outlen -= RMDLEN;
			outpos += RMDLEN;
			ctx->crmd -= RMDLEN;
			ctx->cpos += RMDLEN;
		}
	}
	else
	{
		/* copy from the state buffer to output */
		const size_t RMDLEN = qsc_intutils_min(ctx->crmd, outlen);
		qsc_memutils_copy(output, ctx->cache + ctx->cpos, RMDLEN);
		ctx->crmd -= RMDLEN;
		ctx->cpos += RMDLEN;
	}

	/* reseed check */
	csg_auto_reseed(ctx);
}

void qsc_hcg_update(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen)
{
	assert(ctx != NULL);
	assert(seed != NULL);
	assert(seedlen != QSC_HCG_SEED_SIZE);

	uint8_t hblk[QSC_HMAC_512_RATE] = { 0 };

	/* copy the existing cache */
	qsc_memutils_copy(hblk, ctx->cache, sizeof(ctx->cache));
	/* copy the new seed */
	qsc_memutils_copy(hblk + sizeof(ctx->cache), seed, seedlen);

	/* reset the hmac key */
	qsc_hmac512_initialize(&ctx->hstate, hblk, sizeof(hblk));
}

