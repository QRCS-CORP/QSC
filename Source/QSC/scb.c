#include "scb.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"

#define QSC_SCB_NAME_SIZE 8U

static char scb_name[QSC_SCB_NAME_SIZE + 1U] = "SCB v1.d";

static void scb_scatter_index_dynamic(size_t* indice, size_t count)
{
	QSC_ASSERT(indice != NULL);
    QSC_ASSERT(count != 0U);

	/* Calculates an indice that is always l2 cache-size distance between consecutive memory address indices.
	   The number of lanes varies based on memcost, which is a multiple of MiB.
	   A setting of 1 MiB will create 4 lanes, 2 MiB 8 lanes, 10 MiB is 40 lanes, etc. */

	size_t lmul;
	size_t ccnt;

	/* lane multiplier is total buffer size divided by L2 cache-size */
	lmul = (count * QSC_MEMUTILS_CACHE_LINE_SIZE) / QSC_SCB_L2CACHE_DEFAULT_SIZE;
	/* number of cache lines in each lane */
	ccnt = count / lmul;

	for (size_t i = 0U; i < ccnt; ++i)
	{
		for (size_t j = 0U; j < lmul; ++j)
		{
			indice[(lmul * i) + j] = i + (j * ccnt);
		}
	}
}

static void scb_fill_memory(qsc_scb_state* ctx, uint8_t* buffer, size_t buflen, qsc_keccak_state* hstate) 
{
	QSC_ASSERT(ctx != NULL);
    QSC_ASSERT(buffer != NULL);

	qsc_keccak_state kstate = { 0U };
	size_t* indice;
	size_t lcnt;
	size_t oft;

    /* initialize SHAKE with the key */
    qsc_cshake_initialize(&kstate, ctx->rate, ctx->ckey, ctx->klen, NULL, 0U, NULL, 0U);

	/* get the number of cache lines */
	lcnt = buflen / QSC_MEMUTILS_CACHE_LINE_SIZE;

    indice = qsc_memutils_malloc(lcnt * sizeof(size_t));

	if (indice != NULL)
	{
		uint8_t kblk[QSC_KECCAK_256_RATE] = { 0U };
		uint8_t bnum[sizeof(uint64_t)] = { 0U };
		uint64_t lidx;
		uint64_t litr;

		qsc_memutils_clear(indice, lcnt * sizeof(size_t));

		/* create the index based on a scattering pattern */
		scb_scatter_index_dynamic(indice, lcnt);

		/* fill the buffer using the scattering pattern */
		for (size_t i = 0U; i < lcnt; ++i)
		{
			qsc_shake_squeezeblocks(&kstate, ctx->rate, kblk, 1U);
			oft = indice[i] * QSC_MEMUTILS_CACHE_LINE_SIZE;

			QSC_MEMUTILS_MEMORY_FENCE();
			qsc_memutils_copy(buffer + oft, kblk, QSC_MEMUTILS_CACHE_LINE_SIZE);
			QSC_MEMUTILS_MEMORY_FENCE();
			lidx = indice[i];
			litr = i;

			/* add the iteration to the hash */
			qsc_intutils_le64to8(bnum, litr);
			qsc_sha3_update(hstate, ctx->rate, bnum, sizeof(bnum));

			/* add the index to the hash */
			qsc_intutils_le64to8(bnum, lidx);
			qsc_sha3_update(hstate, ctx->rate, bnum, sizeof(bnum));

			if ((i + 1U) % (QSC_SCB_L2CACHE_DEFAULT_SIZE / QSC_MEMUTILS_CACHE_LINE_SIZE) == 0U)
			{
				/* at l2 cache-size intervals, add the entire buffer to the hash */
				qsc_sha3_update(hstate, ctx->rate, buffer, buflen);
			}
		}

		qsc_keccak_dispose(&kstate);
		qsc_memutils_alloc_free(indice);
		indice = NULL;
	}
}

void qsc_scb_dispose(qsc_scb_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->ckey, ctx->klen);
		ctx->cpuc = 0U;
		ctx->klen = 0U;
		ctx->memc = 0U;
		ctx->rate = qsc_keccak_rate_none;
	}
}

void qsc_scb_initialize(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, size_t cpucost, size_t memcost)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(seed != NULL);
	QSC_ASSERT(cpucost <= QSC_SCB_CPU_MAXIMUM);
	QSC_ASSERT(cpucost >= QSC_SCB_CPU_MINIMUM);
	QSC_ASSERT(memcost <= QSC_SCB_MEMORY_MAXIMUM);
	QSC_ASSERT(memcost >= QSC_SCB_MEMORY_MINIMUM);

	if (ctx != NULL && seed != NULL && 
		(seedlen == QSC_SCB_256_SEED_SIZE || seedlen == QSC_SCB_512_SEED_SIZE) &&
		cpucost <= QSC_SCB_CPU_MAXIMUM && cpucost >= QSC_SCB_CPU_MINIMUM &&
		memcost <= QSC_SCB_MEMORY_MAXIMUM && memcost >= QSC_SCB_MEMORY_MINIMUM)
	{
		qsc_keccak_state kstate = { 0U };
		uint8_t kbuf[QSC_KECCAK_256_RATE] = { 0U };

		if (seedlen >= QSC_SCB_512_SEED_SIZE)
		{
			ctx->rate = qsc_keccak_rate_512;
			ctx->klen = QSC_SCB_512_SEED_SIZE;
		}
		else
		{
			ctx->rate = qsc_keccak_rate_256;
			ctx->klen = QSC_SCB_256_SEED_SIZE;
		}

		/* set the state parameters */
		qsc_memutils_clear(ctx->ckey, ctx->klen);
		ctx->cpuc = cpucost;
		ctx->memc = memcost;

		/* intialize shake */
		qsc_cshake_initialize(&kstate, ctx->rate, seed, seedlen, (uint8_t*)scb_name, QSC_SCB_NAME_SIZE, info, infolen);
		qsc_shake_squeezeblocks(&kstate, ctx->rate, kbuf, 1U);
		qsc_keccak_dispose(&kstate);
		qsc_memutils_copy(ctx->ckey, kbuf, ctx->klen);
		qsc_memutils_clear(kbuf, QSC_KECCAK_256_RATE);
	}
}

void qsc_scb_generate(qsc_scb_state* ctx, uint8_t* output, size_t otplen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(otplen != 0U);

	if (ctx != NULL && output != NULL && otplen != 0U)
	{
		qsc_keccak_state hstate = { 0U };
		uint8_t* cbuf;
		size_t clen;

		clen = ctx->memc * QSC_SCB_MEMORY_COST_SIZE;
		cbuf = qsc_memutils_malloc(clen);

		if (cbuf != NULL)
		{
			size_t pos;

			qsc_memutils_clear(cbuf, clen);
			qsc_sha3_initialize(&hstate);

			for (size_t i = 0U; i < ctx->cpuc; ++i)
			{
				/* update the SHA3 hash with the key */
				qsc_sha3_update(&hstate, ctx->rate, ctx->ckey, ctx->klen);
				/* scatter fill the memory with output from SHAKE */
				scb_fill_memory(ctx, cbuf, clen, &hstate);
				/* finalize to the new key */
				qsc_sha3_finalize(&hstate, ctx->rate, ctx->ckey);
			}

			qsc_memutils_clear(cbuf, clen);
			qsc_memutils_alloc_free(cbuf);
			cbuf = NULL;
			pos = 0U;

			/* initialize SHAKE with the derived key */
			qsc_shake_initialize(&hstate, ctx->rate, ctx->ckey, ctx->klen);

			while (pos < otplen)
			{
				uint8_t kblk[QSC_KECCAK_256_RATE] = { 0U };
				const size_t plen = (otplen - pos > ctx->rate) ? ctx->rate : otplen - pos;

				/* copy SHAKE blocks to the output */
				qsc_shake_squeezeblocks(&hstate, ctx->rate, kblk, 1U);
				qsc_memutils_copy(output + pos, kblk, plen);
				pos += plen;
			}

			qsc_keccak_dispose(&hstate);
		}
	}
}

void qsc_scb_update(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(seed != NULL);
	QSC_ASSERT(seedlen != 0);

	if (ctx != NULL && seed != NULL && seedlen != 0)
	{
		qsc_keccak_state kstate = { 0U };

		/* absorb and permute */
		qsc_sha3_initialize(&kstate);
		qsc_sha3_update(&kstate, ctx->rate, ctx->ckey, ctx->klen);
		qsc_sha3_update(&kstate, ctx->rate, seed, seedlen);
		qsc_sha3_finalize(&kstate, ctx->rate, ctx->ckey);
		qsc_keccak_dispose(&kstate);
	}
}
