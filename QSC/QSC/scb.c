#include "scb.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"
 
#define QSC_SCB_NAME_SIZE 8

static char scb_name[QSC_SCB_NAME_SIZE] = "SCB v1.a";

static void scb_extract(qsc_scb_state* ctx, uint8_t* output, size_t otplen)
{
	if (otplen > 0)
	{
		const size_t BLKCNT = otplen / (size_t)ctx->rate;

		/* extract the bytes from shake */
		qsc_shake_squeezeblocks(&ctx->kstate, ctx->rate, output, BLKCNT);

		if ((size_t)ctx->rate * BLKCNT < otplen)
		{
			uint8_t tmpb[QSC_KECCAK_STATE_BYTE_SIZE] = { 0 };
			const size_t FNLBLK = otplen - ((size_t)ctx->rate * BLKCNT);

			qsc_shake_squeezeblocks(&ctx->kstate, ctx->rate, tmpb, 1);
			qsc_memutils_copy(output + ((size_t)ctx->rate * BLKCNT), tmpb, FNLBLK);
		}
	}
}

static void scb_expand(qsc_scb_state* ctx)
{
	uint8_t* ptmp;

	for (size_t i = 0; i < ctx->cpuc; ++i)
	{
		/* fill the cache */
		scb_extract(ctx, ctx->cache, ctx->clen);

		/* absorb the cache */
		qsc_keccak_absorb(&ctx->kstate, ctx->rate, ctx->cache, ctx->clen, QSC_KECCAK_SHAKE_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);

		/* incrementally increase the cache size up to memory cost */
		if (ctx->clen < ctx->memc * QSC_SCB_CACHE_MULTIPLIER)
		{
			/* calculate the incremental block size */
			const size_t ALCLEN = (ctx->memc * QSC_SCB_CACHE_MULTIPLIER) / ctx->cpuc;

			/* reallocate the array */
			ptmp = (uint8_t*)qsc_memutils_realloc(ctx->cache, ctx->clen + ALCLEN);

			if (ptmp != NULL)
			{
				ctx->cache = ptmp;
				ctx->clen += ALCLEN;
			}
		}
	}
}

void qsc_scb_dispose(qsc_scb_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_keccak_dispose(&ctx->kstate);

		if (ctx->cache != NULL)
		{
			qsc_memutils_clear(ctx->cache, ctx->clen);
			qsc_memutils_alloc_free(ctx->cache);
		}

		ctx->clen = 0;
		ctx->cpuc = 0;
		ctx->memc = 0;
		ctx->rate = qsc_keccak_rate_none;
	}
}

void qsc_scb_initialize(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, size_t cpucost, size_t memcost)
{
	assert(ctx != NULL);
	assert(seed != NULL);
	assert(memcost * QSC_SCB_CACHE_MULTIPLIER <= QSC_SCB_CACHE_MAXIMUM);
	assert(cpucost <= QSC_SCB_CPU_MAXIMUM);

	/* allocate the cache */
	ctx->cache = (uint8_t*)qsc_memutils_malloc(QSC_SCB_CACHE_MINIMUM);

	if (ctx->cache != NULL)
	{
		/* set the state parameters */
		ctx->clen = QSC_SCB_CACHE_MINIMUM;
		qsc_memutils_clear(ctx->cache, ctx->clen);
		ctx->cpuc = cpucost;
		ctx->memc = memcost;

		if (seedlen >= QSC_SCB_512_SEED_SIZE)
		{
			ctx->rate = qsc_keccak_rate_512;
		}
		else
		{
			ctx->rate = qsc_keccak_rate_256;
		}

		/* intialize shake */
		qsc_cshake_initialize(&ctx->kstate, ctx->rate, seed, seedlen, (uint8_t*)scb_name, QSC_SCB_NAME_SIZE, info, infolen);
	}
}

void qsc_scb_generate(qsc_scb_state* ctx, uint8_t* output, size_t otplen)
{
	assert(ctx != NULL);
	assert(output != NULL);

	/* run the cost mechanism */
	scb_expand(ctx);

	/* cost-expand and extract the bytes */
	scb_extract(ctx, output, otplen);
}

void qsc_scb_update(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen)
{
	assert(ctx != NULL);
	assert(seed != NULL);

	/* absorb and permute */
	qsc_cshake_update(&ctx->kstate, ctx->rate, seed, seedlen);
}