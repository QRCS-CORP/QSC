#include "csg.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"

static bool csg_fill_buffer(qsc_csg_state* ctx)
{
	bool res;

	res = false;

	if (ctx != NULL)
	{
		if (ctx->rate == QSC_KECCAK_512_RATE)
		{
			qsc_cshake_squeezeblocks(&ctx->kstate, qsc_keccak_rate_512, ctx->cache, 1U);
			ctx->crmd = ctx->rate;
			ctx->cpos = 0U;
			res = true;
		}
		else if (ctx->rate == QSC_KECCAK_256_RATE)
		{
			qsc_cshake_squeezeblocks(&ctx->kstate, qsc_keccak_rate_256, ctx->cache, 1U);
			ctx->crmd = ctx->rate;
			ctx->cpos = 0U;
			res = true;
		}
	}

	return res;
}

static bool csg_auto_reseed(qsc_csg_state* ctx)
{
	bool res;

	res = true;

	if (ctx != NULL)
	{
		if (ctx->pres == true && ctx->bctr >= QSC_CSG_RESEED_THRESHHOLD)
		{
			res = false;

			if (ctx->rate == QSC_KECCAK_512_RATE)
			{
				uint8_t prand[QSC_CSG_512_SEED_SIZE] = { 0U };

				if (qsc_acp_generate(prand, sizeof(prand)) == true)
				{
					qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_512, prand, sizeof(prand));
					res = csg_fill_buffer(ctx);

					if (res == true)
					{
						ctx->bctr = 0U;
					}
				}

				qsc_memutils_secure_erase(prand, sizeof(prand));
			}
			else if (ctx->rate == QSC_KECCAK_256_RATE)
			{
				uint8_t prand[QSC_CSG_256_SEED_SIZE] = { 0U };

				if (qsc_acp_generate(prand, sizeof(prand)) == true)
				{
					qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_256, prand, sizeof(prand));
					res = csg_fill_buffer(ctx);

					if (res == true)
					{
						ctx->bctr = 0U;
					}
				}

				qsc_memutils_secure_erase(prand, sizeof(prand));
			}
		}
	}

	return res;
}

void qsc_csg_dispose(qsc_csg_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_keccak_dispose(&ctx->kstate);
		qsc_memutils_secure_erase(ctx->cache, sizeof(ctx->cache));
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

	if (ctx != NULL)
	{
		qsc_csg_dispose(ctx);

		if (seed != NULL && (seedlen == QSC_CSG_256_SEED_SIZE || seedlen == QSC_CSG_512_SEED_SIZE))
		{
			bool init;

			init = true;

			if (seedlen == QSC_CSG_512_SEED_SIZE)
			{
				ctx->rate = QSC_KECCAK_512_RATE;
			}
			else
			{
				ctx->rate = QSC_KECCAK_256_RATE;
			}

			ctx->bctr = 0U;
			ctx->cpos = 0U;
			ctx->crmd = 0U;
			ctx->pres = predres;

			if (ctx->rate == QSC_KECCAK_512_RATE)
			{
				if (ctx->pres == true)
				{
					uint8_t prand[QSC_CSG_512_SEED_SIZE] = { 0U };

					if (qsc_acp_generate(prand, sizeof(prand)) == true)
					{
						qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_512, seed, seedlen, info, infolen, prand, sizeof(prand));
					}
					else
					{
						init = false;
					}

					qsc_memutils_secure_erase(prand, sizeof(prand));
				}
				else
				{
					qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_512, seed, seedlen, info, infolen, NULL, 0U);
				}
			}
			else
			{
				if (ctx->pres == true)
				{
					uint8_t prand[QSC_CSG_256_SEED_SIZE] = { 0U };

					if (qsc_acp_generate(prand, sizeof(prand)) == true)
					{
						qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_256, seed, seedlen, info, infolen, prand, sizeof(prand));
					}
					else
					{
						init = false;
					}

					qsc_memutils_secure_erase(prand, sizeof(prand));
				}
				else
				{
					qsc_cshake_initialize(&ctx->kstate, qsc_keccak_rate_256, seed, seedlen, info, infolen, NULL, 0U);
				}
			}

			if (init == true)
			{
				if (csg_fill_buffer(ctx) == false)
				{
					qsc_csg_dispose(ctx);
				}
			}
			else
			{
				qsc_csg_dispose(ctx);
			}
		}
	}
}

bool qsc_csg_generate(qsc_csg_state* ctx, uint8_t* output, size_t otplen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(otplen != 0U);

	bool res;

	res = false;

	if (ctx != NULL && output != NULL && otplen != 0U && (ctx->rate == QSC_KECCAK_256_RATE || ctx->rate == QSC_KECCAK_512_RATE))
	{
		const size_t outlen = otplen;
		size_t outpos;
		size_t rmdlen;

		ctx->bctr += otplen;
		outpos = 0U;

		if (ctx->crmd < otplen)
		{
			if (ctx->crmd != 0U)
			{
				qsc_memutils_copy(output, ctx->cache + ctx->cpos, ctx->crmd);
				outpos += ctx->crmd;
				otplen -= ctx->crmd;
			}

			while (otplen != 0U)
			{
				if (csg_fill_buffer(ctx) == false)
				{
					break;
				}

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
			rmdlen = qsc_intutils_min(ctx->crmd, otplen);
			qsc_memutils_copy(output, ctx->cache + ctx->cpos, rmdlen);
			ctx->crmd -= rmdlen;
			ctx->cpos += rmdlen;
			otplen -= rmdlen;
		}

		if (otplen == 0U)
		{
			if (ctx->crmd != 0U)
			{
				qsc_memutils_secure_erase(ctx->cache, ctx->cpos);
			}

			if (csg_auto_reseed(ctx) == true)
			{
				res = true;
			}
			else
			{
				qsc_memutils_clear(output, outlen);
				qsc_csg_dispose(ctx);
			}
		}
		else
		{
			qsc_memutils_clear(output, outlen);
			qsc_csg_dispose(ctx);
		}
	}
	else if (output != NULL && otplen != 0U)
	{
		qsc_memutils_clear(output, otplen);
	}

	return res;
}

void qsc_csg_update(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(seed != NULL);

	if (ctx != NULL && seed != NULL && seedlen != 0U && (ctx->rate == QSC_KECCAK_256_RATE || ctx->rate == QSC_KECCAK_512_RATE))
	{
		if (ctx->rate == QSC_KECCAK_512_RATE)
		{
			qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_512, seed, seedlen);
		}
		else
		{
			qsc_cshake_update(&ctx->kstate, qsc_keccak_rate_256, seed, seedlen);
		}

		if (csg_fill_buffer(ctx) == false)
		{
			qsc_csg_dispose(ctx);
		}
	}
}
