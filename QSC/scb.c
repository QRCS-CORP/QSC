#include "scb.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"
#include "consoleutils.h"

#define QSC_SCB_NAME_SIZE 8ULL

static char scb_name[QSC_SCB_NAME_SIZE] = "SCB v1.d";

static void scb_scatter_index_dynamic(size_t* indice, size_t count)
{
	/* Calculates an indice that is always l2 cache-size distance between consecutive memory address indices.
	   The number of lanes varies based on memcost, which is a multiple of MiB.
	   A setting of 1 MiB will create 4 lanes, 2 MiB 8 lanes, 10 MiB is 40 lanes, etc. */

	size_t lmul;
	size_t ccnt;

	/* lane multiplier is total buffer size divided by L2 cache-size */
	lmul = (count * QSC_MEMUTILS_CACHE_LINE_SIZE) / QSC_SCB_L2CACHE_DEFAULT_SIZE;
	/* number of cache lines in each lane */
	ccnt = count / lmul;

	for (size_t i = 0; i < ccnt; ++i)
	{
		for (size_t j = 0; j < lmul; ++j)
		{
			indice[(lmul * i) + j] = i + (j * ccnt);
		}
	}
}

static void scb_fill_memory(qsc_scb_state* ctx, uint8_t* buffer, size_t buflen, qsc_keccak_state* hstate) 
{
	qsc_keccak_state kstate = { 0 };
	size_t* indice;
	size_t lcnt;
	size_t oft;

    /* initialize SHAKE with the key */
    qsc_cshake_initialize(&kstate, ctx->rate, ctx->ckey, ctx->klen, NULL, 0, NULL, 0);

	/* get the number of cache lines */
	lcnt = buflen / QSC_MEMUTILS_CACHE_LINE_SIZE;

    indice = qsc_memutils_malloc(lcnt * sizeof(size_t));

	if (indice != NULL)
	{
		uint8_t kblk[QSC_KECCAK_256_RATE] = { 0 };
		uint8_t bnum[sizeof(uint64_t)] = { 0 };
		uint64_t lidx;
		uint64_t litr;

		qsc_memutils_clear(indice, lcnt * sizeof(size_t));

		/* create the index based on a scattering pattern */
		scb_scatter_index_dynamic(indice, lcnt);

		/* fill the buffer using the scattering pattern */
		for (size_t i = 0; i < lcnt; ++i)
		{
			qsc_shake_squeezeblocks(&kstate, ctx->rate, kblk, 1);
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

			if ((i + 1) % (QSC_SCB_L2CACHE_DEFAULT_SIZE / QSC_MEMUTILS_CACHE_LINE_SIZE) == 0)
			{
				/* at l2 cache-size intervals, add the entire buffer to the hash */
				qsc_sha3_update(hstate, ctx->rate, buffer, buflen);
			}
		}

		qsc_keccak_dispose(&kstate);
		qsc_memutils_alloc_free(indice);
	}
}

void qsc_scb_dispose(qsc_scb_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->ckey, ctx->klen);
		ctx->cpuc = 0;
		ctx->klen = 0;
		ctx->memc = 0;
		ctx->rate = qsc_keccak_rate_none;
	}
}

void qsc_scb_initialize(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, size_t cpucost, size_t memcost)
{
	assert(ctx != NULL);
	assert(seed != NULL);
	assert(cpucost <= QSC_SCB_CPU_MAXIMUM);
	assert(cpucost >= QSC_SCB_CPU_MINIMUM);
	assert(memcost <= QSC_SCB_MEMORY_MAXIMUM);
	assert(memcost >= QSC_SCB_MEMORY_MINIMUM);

	if (ctx != NULL && seed != NULL && 
		(seedlen == QSC_SCB_256_SEED_SIZE || seedlen == QSC_SCB_512_SEED_SIZE) &&
		cpucost <= QSC_SCB_CPU_MAXIMUM && cpucost >= QSC_SCB_CPU_MINIMUM &&
		memcost <= QSC_SCB_MEMORY_MAXIMUM && memcost >= QSC_SCB_MEMORY_MINIMUM)
	{
		qsc_keccak_state kstate = { 0 };
		uint8_t kbuf[QSC_KECCAK_256_RATE] = { 0 };

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
		qsc_shake_squeezeblocks(&kstate, ctx->rate, kbuf, 1);
		qsc_keccak_dispose(&kstate);
		qsc_memutils_copy(ctx->ckey, kbuf, ctx->klen);
		qsc_memutils_clear(kbuf, QSC_KECCAK_256_RATE);
	}
}

void qsc_scb_generate(qsc_scb_state* ctx, uint8_t* output, size_t otplen)
{
	assert(ctx != NULL);
	assert(output != NULL);
	assert(otplen != 0);

	if (ctx != NULL && output != NULL && otplen != 0)
	{
		qsc_keccak_state hstate = { 0 };
		uint8_t* cbuf;
		size_t clen;

		clen = ctx->memc * QSC_SCB_MEMORY_COST_SIZE;
		cbuf = qsc_memutils_malloc(clen);

		if (cbuf != NULL)
		{
			size_t pos;

			qsc_memutils_clear(cbuf, clen);
			qsc_sha3_initialize(&hstate);

			for (size_t i = 0; i < ctx->cpuc; ++i)
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
			pos = 0;

			/* initialize SHAKE with the derived key */
			qsc_shake_initialize(&hstate, ctx->rate, ctx->ckey, ctx->klen);

			while (pos < otplen)
			{
				uint8_t kblk[QSC_KECCAK_256_RATE] = { 0 };
				const size_t plen = (otplen - pos > ctx->rate) ? ctx->rate : otplen - pos;

				/* copy SHAKE blocks to the output */
				qsc_shake_squeezeblocks(&hstate, ctx->rate, kblk, 1);
				qsc_memutils_copy(output + pos, kblk, plen);
				pos += plen;
			}

			qsc_keccak_dispose(&hstate);
		}
	}
}

void qsc_scb_update(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen)
{
	assert(ctx != NULL);
	assert(seed != NULL);

	qsc_keccak_state kstate = { 0 };

	/* absorb and permute */
	qsc_sha3_initialize(&kstate);
	qsc_sha3_update(&kstate, ctx->rate, ctx->ckey, ctx->klen);
	qsc_sha3_update(&kstate, ctx->rate, seed, seedlen);
	qsc_sha3_finalize(&kstate, ctx->rate, ctx->ckey);
	qsc_keccak_dispose(&kstate);
}
