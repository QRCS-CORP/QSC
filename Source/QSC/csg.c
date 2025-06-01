#include "csg.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"

static void csg_fill_buffer(qsc_csg_state* ctx)
{
	if (ctx != NULL)
	{
		/* cache the block */
		if (ctx->rate == QSC_KECCAK_512_RATE)
		{
			qsc_cshake_squeezeblocks(&ctx->kstate, qsc_keccak_rate_512, ctx->cache, 1U);
		}
		else
		{
			qsc_cshake_squeezeblocks(&ctx->kstate, qsc_keccak_rate_256, ctx->cache, 1U);
		}

		/* reset cache counters */
		ctx->crmd = ctx->rate;
		ctx->cpos = 0U;
	}
}

static void csg_auto_reseed(qsc_csg_state* ctx)
{
	if (ctx != NULL)
	{
		if (ctx->pres && ctx->bctr >= QSC_CSG_RESEED_THRESHHOLD)
		{
			if (ctx->rate == QSC_KECCAK_512_RATE)
			{
				/* add a random seed to input seed and info */
				uint8_t prand[QSC_CSG_512_SEED_SIZE];

				qsc_acp_generate(prand, sizeof(prand));
				qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_512, prand, sizeof(prand));
				qsc_memutils_clear(prand, sizeof(prand));
			}
			else
			{
				/* add a random seed to input seed and info */
				uint8_t prand[QSC_CSG_256_SEED_SIZE];

				qsc_acp_generate(prand, sizeof(prand));
				qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_256, prand, sizeof(prand));
				qsc_memutils_clear(prand, sizeof(prand));
			}

			/* re-fill the buffer and reset counter */
			csg_fill_buffer(ctx);
			ctx->bctr = 0U;
		}
	}
}

void qsc_csg_dispose(qsc_csg_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_keccak_dispose(&ctx->kstate);
		qsc_memutils_clear(ctx->cache, sizeof(ctx->cache));
		ctx->bctr = 0U;
		ctx->cpos = 0U;
		ctx->crmd = 0U;
		ctx->rate = 0U;
		ctx->pres = false;
	}
}

void qsc_csg_initialize(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predres)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(seed != NULL);
	QSC_ASSERT(seedlen == QSC_CSG_256_SEED_SIZE || seedlen == QSC_CSG_512_SEED_SIZE);

	if (ctx != NULL && seed != NULL && (seedlen == QSC_CSG_256_SEED_SIZE || seedlen == QSC_CSG_512_SEED_SIZE))
	{
		if (seedlen == QSC_CSG_512_SEED_SIZE)
		{
			ctx->rate = QSC_KECCAK_512_RATE;
		}
		else if (seedlen == QSC_CSG_256_SEED_SIZE)
		{
			ctx->rate = QSC_KECCAK_256_RATE;
		}

		qsc_intutils_clear8(ctx->cache, sizeof(ctx->cache));
		ctx->bctr = 0U;
		ctx->cpos = 0U;
		ctx->pres = predres;
		qsc_intutils_clear64(ctx->kstate.state, sizeof(ctx->kstate.state) / sizeof(uint64_t));

		if (ctx->rate == QSC_KECCAK_512_RATE)
		{
			if (ctx->pres)
			{
				/* add a random seed to input seed and info */
				uint8_t prand[QSC_CSG_512_SEED_SIZE];
				qsc_acp_generate(prand, sizeof(prand));
				qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_512, seed, seedlen, info, infolen, prand, sizeof(prand));
			}
			else
			{
				/* initialize with the seed and info */
				qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_512, seed, seedlen, info, infolen, NULL, 0U);
			}
		}
		else
		{
			if (ctx->pres)
			{
				uint8_t prand[QSC_CSG_256_SEED_SIZE];
				qsc_acp_generate(prand, sizeof(prand));
				qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_256, seed, seedlen, info, infolen, prand, sizeof(prand));
			}
			else
			{
				qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_256, seed, seedlen, info, infolen, NULL, 0U);
			}
		}

		/* cache the first block */
		csg_fill_buffer(ctx);
	}
}

void qsc_csg_generate(qsc_csg_state* ctx, uint8_t* output, size_t otplen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(otplen != 0U);

	if (ctx != NULL && output != NULL && otplen != 0U)
	{
		size_t outpos;
		size_t rmdlen;

		ctx->bctr += otplen;

		if (ctx->crmd < otplen)
		{
			outpos = 0U;

			/* copy remaining bytes from the cache */
			if (ctx->crmd != 0U)
			{
				/* empty the state buffer */
				qsc_memutils_copy(output, ctx->cache + ctx->cpos, ctx->crmd);
				outpos += ctx->crmd;
				otplen -= ctx->crmd;
			}

			/* loop through the remainder */
			while (otplen != 0U)
			{
				/* fill the buffer */
				csg_fill_buffer(ctx);

				/* copy to output */
				rmdlen = qsc_intutils_min(ctx->crmd, otplen);
				qsc_memutils_copy(output + outpos, ctx->cache, rmdlen);

				otplen -= rmdlen;
				outpos += rmdlen;
				ctx->crmd -= rmdlen;
				ctx->cpos += rmdlen;
			}
		}
		else
		{
			/* copy from the state buffer to output */
			rmdlen = qsc_intutils_min(ctx->crmd, otplen);
			qsc_memutils_copy(output, ctx->cache + ctx->cpos, rmdlen);
			ctx->crmd -= rmdlen;
			ctx->cpos += rmdlen;
		}

		/* clear used bytes */
		if (ctx->crmd != 0U)
		{
			qsc_memutils_clear(ctx->cache, ctx->cpos);
		}

		/* reseed check */
		csg_auto_reseed(ctx);
	}
}

void qsc_csg_update(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(seed != NULL);

	if (ctx != NULL && seed != NULL && seedlen != 0U)
	{
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
}
