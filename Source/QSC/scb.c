/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "scb.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"

/** \brief SCB domain-separation name length in bytes. */
#define QSC_SCB_NAME_SIZE 8U

static const char scb_name[QSC_SCB_NAME_SIZE + 1U] = "SCB v1.d";

/**
 * \brief Build a public, deterministic cache-line traversal schedule.
 * \param indice: Borrowed output buffer containing count size_t entries.
 * \param count: Number of public cache-line entries (nonzero).
 * \note No secret-dependent addressing; caller owns the buffer. Not thread-shared.
 */
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

	if (lmul == 0U) 
	{ 
		lmul = 1U; 
	}

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

/**
 * \brief Fill and hash the memory-cost work buffer.
 * \param ctx: Borrowed, initialized SCB state; not modified by this helper.
 * \param buffer: Borrowed writable buffer of buflen bytes.
 * \param buflen: Public memory-cost allocation size in bytes.
 * \param hstate: Borrowed SHA-3 accumulator updated on success.
 * \return True if all memory work completed; false if index allocation failed.
 * \note Caller manages buffer and state lifetime; not safe for concurrent access to shared state.
 */
static bool scb_fill_memory(qsc_scb_state* ctx, uint8_t* buffer, size_t buflen, qsc_keccak_state* hstate) 
{
	QSC_ASSERT(ctx != NULL);
    QSC_ASSERT(buffer != NULL);

	qsc_keccak_state kstate = { 0U };
	size_t* indice;
	size_t lcnt;
	size_t oft;
	bool res;

	res = false;

	/* get the number of cache lines */
	lcnt = buflen / QSC_MEMUTILS_CACHE_LINE_SIZE;

    indice = qsc_memutils_malloc(lcnt * sizeof(size_t));

	if (indice != NULL)
	{
		uint8_t kblk[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
		uint8_t bnum[sizeof(uint64_t)] = { 0U };
		uint64_t lidx;
		uint64_t litr;

		/* initialize SHAKE with the key */
		qsc_cshake_initialize(&kstate, ctx->rate, ctx->ckey, ctx->klen, NULL, 0U, NULL, 0U);

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

		qsc_memutils_secure_erase(kblk, sizeof(kblk));
		qsc_keccak_dispose(&kstate);
		qsc_memutils_alloc_free(indice);
		indice = NULL;
		res = true;
	}

	return res;
}

void qsc_scb_dispose(qsc_scb_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx->ckey, sizeof(ctx->ckey));
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

	if (ctx != NULL)
	{
		if (seed != NULL && (seedlen == QSC_SCB_256_SEED_SIZE || seedlen == QSC_SCB_512_SEED_SIZE) &&
			(info != NULL || infolen == 0U) && infolen <= (SIZE_MAX / 8U) &&
			cpucost <= QSC_SCB_CPU_MAXIMUM && cpucost >= QSC_SCB_CPU_MINIMUM &&
			memcost <= QSC_SCB_MEMORY_MAXIMUM && memcost >= QSC_SCB_MEMORY_MINIMUM)
		{
			qsc_keccak_state kstate = { 0U };
			uint8_t kbuf[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
			qsc_keccak_rate rate;
			size_t klen;

			if (seedlen == QSC_SCB_512_SEED_SIZE)
			{
				rate = qsc_keccak_rate_512;
				klen = QSC_SCB_512_SEED_SIZE;
			}
			else
			{
				rate = qsc_keccak_rate_256;
				klen = QSC_SCB_256_SEED_SIZE;
			}

			qsc_cshake_initialize(&kstate, rate, seed, seedlen, (const uint8_t*)scb_name, QSC_SCB_NAME_SIZE, info, infolen);
			qsc_shake_squeezeblocks(&kstate, rate, kbuf, 1U);
			qsc_keccak_dispose(&kstate);

			qsc_memutils_secure_erase(ctx->ckey, sizeof(ctx->ckey));
			qsc_memutils_copy(ctx->ckey, kbuf, klen);
			ctx->rate = rate;
			ctx->klen = klen;
			ctx->cpuc = cpucost;
			ctx->memc = memcost;
			qsc_memutils_secure_erase(kbuf, sizeof(kbuf));
		}
		else
		{
			qsc_scb_dispose(ctx);
		}
	}
}

bool qsc_scb_generate(qsc_scb_state* ctx, uint8_t* output, size_t otplen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(otplen != 0U);

	bool res;

	res = false;

	if (ctx != NULL && output != NULL && otplen != 0U &&
		ctx->cpuc >= QSC_SCB_CPU_MINIMUM && ctx->cpuc <= QSC_SCB_CPU_MAXIMUM &&
		ctx->memc >= QSC_SCB_MEMORY_MINIMUM && ctx->memc <= QSC_SCB_MEMORY_MAXIMUM &&
		((ctx->klen == QSC_SCB_256_SEED_SIZE && ctx->rate == qsc_keccak_rate_256) ||
		(ctx->klen == QSC_SCB_512_SEED_SIZE && ctx->rate == qsc_keccak_rate_512)))
	{
		qsc_keccak_state hstate = { 0U };
		uint8_t* cbuf;
		size_t clen;

		clen = ctx->memc * QSC_SCB_MEMORY_COST_SIZE;
		cbuf = qsc_memutils_malloc(clen);

		if (cbuf != NULL)
		{
			uint8_t kblk[QSC_KECCAK_STATE_BYTE_SIZE] = { 0U };
			size_t pos;

			qsc_memutils_clear(cbuf, clen);
			qsc_sha3_initialize(&hstate);
			res = true;

			for (size_t i = 0U; i < ctx->cpuc; ++i)
			{
				/* update the SHA3 hash with the key */
				qsc_sha3_update(&hstate, ctx->rate, ctx->ckey, ctx->klen);
				/* scatter fill the memory with output from SHAKE */
				if (scb_fill_memory(ctx, cbuf, clen, &hstate) == false)
				{
					res = false;
					break;
				}
				/* finalize to the new key */
				qsc_sha3_finalize(&hstate, ctx->rate, ctx->ckey);
			}

			qsc_memutils_secure_erase(cbuf, clen);
			qsc_memutils_alloc_free(cbuf);
			cbuf = NULL;

			if (res == true)
			{
				pos = 0U;
				/* initialize SHAKE with the derived key */
				qsc_shake_initialize(&hstate, ctx->rate, ctx->ckey, ctx->klen);

				while (pos < otplen)
				{
					const size_t plen = (otplen - pos > ctx->rate) ? ctx->rate : otplen - pos;

					/* copy SHAKE blocks to the output */
					qsc_shake_squeezeblocks(&hstate, ctx->rate, kblk, 1U);
					qsc_memutils_copy(output + pos, kblk, plen);
					pos += plen;
				}
			}

			qsc_memutils_secure_erase(kblk, sizeof(kblk));
			qsc_keccak_dispose(&hstate);
		}
	}

	return res;
}

void qsc_scb_update(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(seed != NULL);
	QSC_ASSERT(seedlen != 0);

	if (ctx != NULL && seed != NULL && seedlen != 0U &&
		ctx->cpuc >= QSC_SCB_CPU_MINIMUM && ctx->cpuc <= QSC_SCB_CPU_MAXIMUM &&
		ctx->memc >= QSC_SCB_MEMORY_MINIMUM && ctx->memc <= QSC_SCB_MEMORY_MAXIMUM &&
		((ctx->klen == QSC_SCB_256_SEED_SIZE && ctx->rate == qsc_keccak_rate_256) ||
		(ctx->klen == QSC_SCB_512_SEED_SIZE && ctx->rate == qsc_keccak_rate_512)))
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
