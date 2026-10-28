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

#include "structures_test.h"
#include "async.h"
#include "collection.h"
#include "intutils.h"
#include "memutils.h"
#include "queue.h"
#include "testutils.h"

/*! \brief Runs a collection removal and lookup regression with last-slot handling.
 * \return true when all live and removed entries are consistent.
 */
static bool qsctest_structures_collection_test(void)
{
	qsc_collection_state ctx = { 0 };
	uint8_t item[16U] = { 0U };
	uint8_t output[16U] = { 0U };
	uint8_t key[16U] = { 0U };
	uint32_t i;
	bool res;

	res = true;
	qsc_collection_initialize(&ctx, sizeof(item));
	res = (ctx.opmtx != NULL);

	if (res == true)
	{
		for (i = 0U; i < 256U; ++i)
		{
			qsc_intutils_le32to8(item, i + 1000U);
			qsc_intutils_le32to8(key, i + 1000U);
			qsc_collection_add(&ctx, item, key);
		}

		res = (ctx.count == 256U);

		for (i = 0U; i < 256U && res == true; i += 2U)
		{
			qsc_intutils_le32to8(key, i + 1000U);
			qsc_collection_remove(&ctx, key);
			res = (qsc_collection_item_exists(&ctx, key) == false);
		}

		res = (ctx.count == 128U) && res;

		for (i = 1U; i < 256U && res == true; i += 2U)
		{
			qsc_intutils_le32to8(key, i + 1000U);
			res = qsc_collection_item_exists(&ctx, key);
			res = qsc_collection_find(&ctx, output, key) && res;
			res = (qsc_intutils_le8to32(output) == i + 1000U) && res;
		}

		for (i = 1U; i < 256U && res == true; i += 2U)
		{
			qsc_intutils_le32to8(key, i + 1000U);
			qsc_collection_remove(&ctx, key);
		}

		res = (ctx.count == 0U && ctx.items == NULL && ctx.keys == NULL) && res;
		qsc_collection_dispose(&ctx);
		res = (ctx.opmtx == NULL) && res;
	}

	return res;
}

/*! \brief Tests circular queue wraparound, FIFO ordering and tags.
 * \return true if all tested queue operations are consistent.
 */
static bool qsctest_structures_queue_test(void)
{
	qsc_queue_state ctx = { 0 };
	uint8_t item[16U] = { 0U };
	uint8_t output[16U] = { 0U };
	uint64_t tag;
	uint32_t cycle;
	uint32_t i;
	bool res;

	res = true;
	qsc_queue_initialize(&ctx, 16U, sizeof(item));
	res = (ctx.opmtx != NULL && ctx.depth == 16U);

	if (res == true)
	{
		for (cycle = 0U; cycle < 200U && res == true; ++cycle)
		{
			for (i = 0U; i < 16U; ++i)
			{
				qsc_intutils_le32to8(item, cycle * 16U + i + 1U);
				qsc_queue_push(&ctx, item, sizeof(item), cycle * 16U + i + 1U);
			}

			res = qsc_queue_full(&ctx);
			for (i = 0U; i < 16U && res == true; ++i)
			{
				tag = qsc_queue_pop(&ctx, output, sizeof(output));
				res = (tag == cycle * 16U + i + 1U);
				res = (qsc_intutils_le8to32(output) == tag) && res;
			}

			res = qsc_queue_empty(&ctx) && res;
		}

		qsc_queue_dispose(&ctx);
		res = (ctx.opmtx == NULL) && res;
	}

	return res;
}

/*! \brief Per-thread fixed range for the QSC collection insertion check. */
typedef struct
{
	qsc_collection_state* collection;
	uint32_t start;
} qsctest_structures_worker_state;

/*! \brief Inserts uniquely tagged entries into a shared collection. */
static void qsctest_structures_insert_worker(void* state)
{
	qsctest_structures_worker_state* worker;
	uint8_t item[16U] = { 0U };
	uint8_t key[16U] = { 0U };
	uint32_t i;

	worker = (qsctest_structures_worker_state*)state;

	if (worker != NULL && worker->collection != NULL)
	{
		for (i = 0U; i < 32U; ++i)
		{
			qsc_intutils_le32to8(item, worker->start + i);
			qsc_intutils_le32to8(key, worker->start + i);
			qsc_collection_add(worker->collection, item, key);
		}
	}
}

/*! \brief Tests concurrent producers using QSC's platform threading API.
 * \return true if all inserted entries survive parallel insertion.
 */
static bool qsctest_structures_collection_concurrency_test(void)
{
	qsc_collection_state ctx = { 0 };
	qsctest_structures_worker_state workers[4U];
	qsc_thread threads[4U];
	uint8_t item[16U] = { 0U };
	uint8_t key[16U] = { 0U };
	uint32_t i;
	bool res;

	res = true;
	qsc_collection_initialize(&ctx, sizeof(item));
	res = (ctx.opmtx != NULL);

	if (res == true)
	{
		for (i = 0U; i < 4U; ++i)
		{
			workers[i].collection = &ctx;
			workers[i].start = i * 32U + 1U;
			threads[i] = qsc_async_thread_create(qsctest_structures_insert_worker, &workers[i]);
		}

		/* Each thread is joined explicitly, not dispatched as a test function. */
		qsc_async_thread_wait(threads[0U]);
		qsc_async_thread_wait(threads[1U]);
		qsc_async_thread_wait(threads[2U]);
		qsc_async_thread_wait(threads[3U]);

		res = (ctx.count == 128U);

		for (i = 1U; i <= 128U && res == true; ++i)
		{
			qsc_intutils_le32to8(key, i);
			res = qsc_collection_find(&ctx, item, key);
			res = (qsc_intutils_le8to32(item) == i) && res;
		}

		qsc_collection_dispose(&ctx);
	}

	return res;
}

/*! \brief Invokes each regression directly with explicit PASS/FAIL output. */
void qsctest_structures_run(void)
{
	if (qsctest_structures_collection_test() == true)
	{
		qsctest_print_line("PASS: collection removal and lookup");
	}
	else
	{
		qsctest_print_line("FAIL: collection removal and lookup");
	}

	if (qsctest_structures_queue_test() == true)
	{
		qsctest_print_line("PASS: queue wraparound and tags");
	}
	else
	{
		qsctest_print_line("FAIL: queue wraparound and tags");
	}

	if (qsctest_structures_collection_concurrency_test() == true)
	{
		qsctest_print_line("PASS: collection concurrent insertion");
	}
	else
	{
		qsctest_print_line("FAIL: collection concurrent insertion");
	}
}
