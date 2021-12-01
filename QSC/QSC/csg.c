#include "csg.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"

static void csg_fill_buffer(qsc_csg_state* ctx)
{
	/* cache the block */
	if (ctx->rate == QSC_KECCAK_512_RATE)
	{
		qsc_cshake_squeezeblocks(&ctx->kstate, qsc_keccak_rate_512, ctx->cache, 1);
	}
	else
	{
		qsc_cshake_squeezeblocks(&ctx->kstate, qsc_keccak_rate_256, ctx->cache, 1);
	}

	/* reset cache counters */
	ctx->crmd = ctx->rate;
	ctx->cpos = 0;
}

static void csg_auto_reseed(qsc_csg_state* ctx)
{
	if (ctx->pres && ctx->bctr >= QSC_CSG_RESEED_THRESHHOLD)
	{
		if (ctx->rate == QSC_KECCAK_512_RATE)
		{
			/* add a random seed to input seed and info */
			uint8_t prand[QSC_CSG512_SEED_SIZE];
			qsc_acp_generate(prand, sizeof(prand));

			qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_512, prand, sizeof(prand));
		}
		else
		{
			/* add a random seed to input seed and info */
			uint8_t prand[QSC_CSG256_SEED_SIZE];
			qsc_acp_generate(prand, sizeof(prand));

			qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_256, prand, sizeof(prand));
		}

		/* re-fill the buffer and reset counter */
		csg_fill_buffer(ctx);
		ctx->bctr = 0;
	}
}

void qsc_csg_dispose(qsc_csg_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_keccak_dispose(&ctx->kstate);
		qsc_memutils_clear(ctx->cache, sizeof(ctx->cache));
		ctx->bctr = 0;
		ctx->cpos = 0;
		ctx->crmd = 0;
		ctx->rate = 0;
		ctx->pres = false;
	}
}

void qsc_csg_initialize(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predres)
{
	assert(ctx != NULL);
	assert(seed != NULL);
	assert(seedlen == QSC_CSG256_SEED_SIZE || seedlen == QSC_CSG512_SEED_SIZE);

	if (seedlen == QSC_CSG512_SEED_SIZE)
	{
		ctx->rate = QSC_KECCAK_512_RATE;
	}
	else
	{
		ctx->rate = QSC_KECCAK_256_RATE;
	}

	qsc_intutils_clear8(ctx->cache, sizeof(ctx->cache));
	ctx->bctr = 0;
	ctx->cpos = 0;
	ctx->pres = predres;
	qsc_intutils_clear64(ctx->kstate.state, sizeof(ctx->kstate.state) / sizeof(uint64_t));

	if (ctx->rate == QSC_KECCAK_512_RATE)
	{
		if (ctx->pres)
		{
			/* add a random seed to input seed and info */
			uint8_t prand[QSC_CSG512_SEED_SIZE];
			qsc_acp_generate(prand, sizeof(prand));
			qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_512, seed, seedlen, info, infolen, prand, sizeof(prand));
		}
		else
		{
			/* initialize with the seed and info */
			qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_512, seed, seedlen, info, infolen, NULL, 0);
		}
	}
	else
	{
		if (ctx->pres)
		{
			uint8_t prand[QSC_CSG256_SEED_SIZE];
			qsc_acp_generate(prand, sizeof(prand));
			qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_256, seed, seedlen, info, infolen, prand, sizeof(prand));
		}
		else
		{
			qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_256, seed, seedlen, info, infolen, NULL, 0);
		}
	}

	/* cache the first block */
	csg_fill_buffer(ctx);
}

void qsc_csg_generate(qsc_csg_state* ctx, uint8_t* output, size_t outlen)
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
			csg_fill_buffer(ctx);

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

	/* clear used bytes */
	if (ctx->crmd != 0)
	{
		qsc_memutils_clear(ctx->cache, ctx->cpos);
	}

	/* reseed check */
	csg_auto_reseed(ctx);
}

void qsc_csg_update(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen)
{
	assert(ctx != NULL);
	assert(seed != NULL);

	/* absorb and permute */

	if (ctx->rate == QSC_KECCAK_512_RATE)
	{
		qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_512, seed, seedlen);
	}
	else
	{
		qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_256, seed, seedlen);
	}

	/* re-fill the buffer */
	csg_fill_buffer(ctx);
}
