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

#include "queue.h"
#include "memutils.h"
#include <stdint.h>
#if defined(QSC_DEBUG_MODE)
#   include "intutils.h"
#endif

/**
 * \brief Release all memory and synchronization objects owned by an initialized queue.
 * \param ctx Queue state to dispose; no other thread may access it during disposal.
 * \details Clears all allocated item storage and tags before releasing the allocation.
 * \details An uninitialized or already disposed state is ignored.
 */
void qsc_queue_dispose(qsc_queue_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL)
		{
			/* The pointer table and all slots share one aligned allocation. */
			for (size_t i = 0U; i < ctx->depth; ++i)
			{
				qsc_memutils_secure_erase(ctx->queue[i], ctx->width);
			}

			qsc_memutils_aligned_free(ctx->queue);
			ctx->queue = NULL;
		}

		qsc_memutils_secure_erase(ctx->tags, sizeof(ctx->tags));
		ctx->count = 0U;
		ctx->depth = 0U;
		ctx->position = 0U;
		ctx->width = 0U;
		qsc_async_mutex_unlock(ctx->opmtx);
		qsc_async_mutex_destroy(ctx->opmtx);
		ctx->opmtx = NULL;
	}
}

/**
 * \brief Extract all queued items into an output buffer in FIFO order.
 * \param ctx Initialized queue; serialized access is protected by its mutex.
 * \param output Buffer holding at least count times width bytes.
 * \details Output capacity cannot be checked by this legacy API. Use the bounded form for safety.
 */
void qsc_queue_flush(qsc_queue_state* ctx, uint8_t* output)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && output != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL && ctx->depth != 0U)
		{
			size_t idx;

			idx = ctx->position + ctx->depth - ctx->count;
			if (idx >= ctx->depth)
			{
				idx -= ctx->depth;
			}

			for (size_t i = 0U; i < ctx->count; ++i)
			{
				qsc_memutils_copy(output + (i * ctx->width), ctx->queue[idx], ctx->width);
				qsc_memutils_secure_erase(ctx->queue[idx], ctx->width);
				++idx;

				if (idx == ctx->depth)
				{
					idx = 0U;
				}
			}
		}

		ctx->count = 0U;
		ctx->position = 0U;
		qsc_memutils_secure_erase(ctx->tags, sizeof(ctx->tags));
		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

/**
 * \brief Flush a queue only when the provided buffer can hold every queued item.
 * \param ctx Initialized queue; no concurrent disposal is permitted.
 * \param output Destination bytes; required if nonempty.
 * \param outlen Capacity of output in bytes.
 * \return Number of extracted items, or zero if the buffer is too small or input invalid.
 * \details The queue is unchanged on a capacity failure. Thread-safe with other queue operations.
 */
size_t qsc_queue_flush_bounded(qsc_queue_state* ctx, uint8_t* output, size_t outlen)
{
	size_t copied;
	size_t idx;

	copied = 0U;

	if (ctx != NULL && output != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL && ctx->depth != 0U && ctx->count <= outlen / ctx->width)
		{
			copied = ctx->count;
			idx = ctx->position + ctx->depth - ctx->count;

			if (idx >= ctx->depth)
			{
				idx -= ctx->depth;
			}

			for (size_t i = 0U; i < copied; ++i)
			{
				qsc_memutils_copy(output + (i * ctx->width), ctx->queue[idx], ctx->width);
				qsc_memutils_secure_erase(ctx->queue[idx], ctx->width);
				++idx;

				if (idx == ctx->depth)
				{
					idx = 0U;
				}
			}

			ctx->count = 0U;
			ctx->position = 0U;
			qsc_memutils_secure_erase(ctx->tags, sizeof(ctx->tags));
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return copied;
}

/**
 * \brief Initialize fixed-capacity queue storage using one aligned allocation.
 * \param ctx Caller-owned state, not already initialized.
 * \param depth Requested number of slots, clamped to QSC_QUEUE_MAX_DEPTH.
 * \param width Maximum bytes per slot. Must be nonzero and permit safe aligned-size arithmetic.
 * \details Failing initialization leaves ctx with null pointers and zero counters.
 * \details The caller must not initialize or dispose a queue concurrently with operations.
 */
void qsc_queue_initialize(qsc_queue_state* ctx, size_t depth, size_t width)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(depth != 0U);
	QSC_ASSERT(width != 0U);

	size_t head;
	size_t offset;
	size_t stride;
	size_t total;
	uint8_t* block;

	if (ctx != NULL)
	{
		ctx->queue = NULL;
		ctx->opmtx = NULL;
		ctx->count = 0U;
		ctx->depth = 0U;
		ctx->position = 0U;
		ctx->width = 0U;
		qsc_memutils_clear(ctx->tags, sizeof(ctx->tags));

		if (depth != 0U && width != 0U)
		{
			if (depth > QSC_QUEUE_MAX_DEPTH)
			{
				depth = QSC_QUEUE_MAX_DEPTH;
			}

			/* All item addresses retain QSC_QUEUE_ALIGNMENT alignment. */
			if (width <= SIZE_MAX - (QSC_QUEUE_ALIGNMENT - 1U) &&
				depth <= SIZE_MAX / sizeof(uint8_t*))
			{
				stride = (width + QSC_QUEUE_ALIGNMENT - 1U) & ~(QSC_QUEUE_ALIGNMENT - 1U);
				head = depth * sizeof(uint8_t*);

				if (head <= SIZE_MAX - (QSC_QUEUE_ALIGNMENT - 1U))
				{
					offset = (head + QSC_QUEUE_ALIGNMENT - 1U) & ~(QSC_QUEUE_ALIGNMENT - 1U);

					if (stride <= (SIZE_MAX - offset) / depth)
					{
						total = offset + (stride * depth);
						ctx->opmtx = qsc_async_mutex_create();

						if (ctx->opmtx != NULL)
						{
							block = (uint8_t*)qsc_memutils_aligned_alloc((int32_t)QSC_QUEUE_ALIGNMENT, total);

							if (block != NULL)
							{
								qsc_memutils_clear(block, total);
								ctx->queue = (uint8_t**)block;

								for (size_t i = 0U; i < depth; ++i)
								{
									ctx->queue[i] = block + offset + (i * stride);
								}

								ctx->depth = depth;
								ctx->width = width;
							}
							else
							{
								qsc_async_mutex_destroy(ctx->opmtx);
								ctx->opmtx = NULL;
							}
						}
					}
				}
			}
		}
	}
}

/** \brief Return the count of queued items. \param ctx Initialized queue. \return Count, or zero on invalid state. \details Thread-safe except concurrent disposal. */
size_t qsc_queue_items(const qsc_queue_state* ctx)
{
	size_t res;

	QSC_ASSERT(ctx != NULL);
	res = 0U;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = ctx->count;
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

/** \brief Test whether a queue is full. \param ctx Initialized queue. \return True if full; false if empty/invalid. \details Thread-safe except concurrent disposal. */
bool qsc_queue_full(const qsc_queue_state* ctx)
{
	bool res;

	QSC_ASSERT(ctx != NULL);
	res = false;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = (ctx->count == ctx->depth);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

/** \brief Test whether a queue is empty. \param ctx Initialized queue. \return True if empty; false on invalid state. \details Thread-safe except concurrent disposal. */
bool qsc_queue_empty(const qsc_queue_state* ctx)
{
	bool res;

	QSC_ASSERT(ctx != NULL);
	res = false;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = (ctx->count == 0U);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

/**
 * \brief Append an item only if a queue slot is available.
 * \param ctx Initialized queue, exclusive lifetime ownership held by caller.
 * \param input Item bytes, at least inlen bytes.
 * \param inlen Number of item bytes, at most ctx->width.
 * \param tag Caller-defined associated 64-bit tag; zero is valid.
 * \return True if appended; false if full or input invalid.
 * \details Thread-safe against other queue operations, but not against disposal.
 */
bool qsc_queue_try_push(qsc_queue_state* ctx, const uint8_t* input, size_t inlen, uint64_t tag)
{
	bool inserted;

	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	inserted = false;

	if (ctx != NULL && input != NULL && inlen != 0U && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL && ctx->count < ctx->depth && inlen <= ctx->width)
		{
			qsc_memutils_copy(ctx->queue[ctx->position], input, inlen);
			ctx->tags[ctx->position] = tag;
			++ctx->position;

			if (ctx->position == ctx->depth)
			{
				ctx->position = 0U;
			}

			++ctx->count;
			inserted = true;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return inserted;
}

/**
 * \brief Enqueue as many whole items as the queue has available slots.
 * \param ctx Initialized queue.
 * \param input Packed count items, each inlen bytes, owned by caller.
 * \param count Number of candidate items.
 * \param inlen Bytes per item, between one and queue width.
 * \param tags Optional array of count tags; if null, inserted tags are zero.
 * \return Number of items accepted, possibly zero if full or invalid input.
 * \details One lock acquisition per call, FIFO ordering, no allocations.
 */
size_t qsc_queue_push_batch(qsc_queue_state* ctx, const uint8_t* input, size_t count, size_t inlen, const uint64_t* tags)
{
	size_t accepted;
	size_t idx;

	accepted = 0U;

	if (ctx != NULL && input != NULL && inlen != 0U && count <= SIZE_MAX / inlen && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL && inlen <= ctx->width)
		{
			accepted = count;

			if (accepted > ctx->depth - ctx->count)
			{
				accepted = ctx->depth - ctx->count;
			}

			idx = ctx->position;

			for (size_t i = 0U; i < accepted; ++i)
			{
				qsc_memutils_copy(ctx->queue[idx], input + (i * inlen), inlen);
				ctx->tags[idx] = (tags != NULL) ? tags[i] : 0U;
				++idx;

				if (idx == ctx->depth)
				{
					idx = 0U;
				}
			}

			ctx->position = idx;
			ctx->count += accepted;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return accepted;
}

/**
 * \brief Dequeue one item and distinguish an empty queue from tag value zero.
 * \param ctx Initialized queue.
 * \param output Buffer containing at least otplen bytes; unchanged on failure.
 * \param otplen Number of item bytes to copy; must not exceed queue width.
 * \param tag Output tag pointer, may be NULL to ignore tags.
 * \return True on success, false if empty or invalid.
 * \details Popped item memory is securely erased; thread-safe except during disposal.
 */
bool qsc_queue_try_pop(qsc_queue_state* ctx, uint8_t* output, size_t otplen, uint64_t* tag)
{
	size_t idx;
	bool popped;

	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	popped = false;

	if (ctx != NULL && output != NULL && otplen != 0U && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->count != 0U && ctx->queue != NULL && otplen <= ctx->width)
		{
			idx = ctx->position + ctx->depth - ctx->count;

			if (idx >= ctx->depth)
			{
				idx -= ctx->depth;
			}

			qsc_memutils_copy(output, ctx->queue[idx], otplen);

			if (tag != NULL)
			{
				*tag = ctx->tags[idx];
			}

			qsc_memutils_secure_erase(ctx->queue[idx], ctx->width);
			ctx->tags[idx] = 0U;
			--ctx->count;
			popped = true;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return popped;
}

/**
 * \brief Pop multiple items in FIFO order with one mutex acquisition.
 * \param ctx Initialized queue.
 * \param output Buffer holding at least capacity times otplen bytes.
 * \param capacity Maximum number of items to extract.
 * \param otplen Bytes extracted per item, at most queue width.
 * \param tags Optional buffer for capacity tags.
 * \return Number of items returned, or zero if empty or invalid.
 * \details Clears each popped internal slot. Caller must prevent concurrent disposal.
 */
size_t qsc_queue_pop_batch(qsc_queue_state* ctx, uint8_t* output, size_t capacity, size_t otplen, uint64_t* tags)
{
	size_t popped;
	size_t idx;

	popped = 0U;

	if (ctx != NULL && output != NULL && otplen != 0U && capacity <= SIZE_MAX / otplen && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL && otplen <= ctx->width)
		{
			popped = (ctx->count < capacity) ? ctx->count : capacity;
			idx = ctx->position + ctx->depth - ctx->count;

			if (idx >= ctx->depth)
			{
				idx -= ctx->depth;
			}

			for (size_t i = 0U; i < popped; ++i)
			{
				qsc_memutils_copy(output + (i * otplen), ctx->queue[idx], otplen);

				if (tags != NULL)
				{
					tags[i] = ctx->tags[idx];
				}

				qsc_memutils_secure_erase(ctx->queue[idx], ctx->width);
				ctx->tags[idx] = 0U;
				++idx;

				if (idx == ctx->depth)
				{
					idx = 0U;
				}
			}

			ctx->count -= popped;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return popped;
}

/** \brief Legacy dequeue, returning zero if the queue was empty. \param ctx Queue state. \param output Destination. \param otplen Destination bytes. \return Removed tag or zero. \details Clears output on empty, and is safe against other operations but not disposal. */
uint64_t qsc_queue_pop(qsc_queue_state* ctx, uint8_t* output, size_t otplen)
{
	size_t idx;
	uint64_t tag;

	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(otplen != 0U);
	QSC_ASSERT(ctx == NULL || otplen <= ctx->width);
	tag = 0U;

	if (ctx != NULL && output != NULL && otplen != 0U && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL && ctx->count != 0U && otplen <= ctx->width)
		{
			idx = ctx->position + ctx->depth - ctx->count;

			if (idx >= ctx->depth)
			{
				idx -= ctx->depth;
			}

			qsc_memutils_copy(output, ctx->queue[idx], otplen);
			tag = ctx->tags[idx];
			qsc_memutils_secure_erase(ctx->queue[idx], ctx->width);
			ctx->tags[idx] = 0U;
			--ctx->count;
		}
		else
		{
			qsc_memutils_clear(output, otplen);
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return tag;
}

/** \brief Legacy enqueue. \param ctx Initialized queue. \param input Item data. \param inlen Number of bytes. \param tag Item tag. \details Drops an item silently when the queue is full. */
void qsc_queue_push(qsc_queue_state* ctx, const uint8_t* input, size_t inlen, uint64_t tag)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(inlen != 0U);
	QSC_ASSERT(ctx == NULL || inlen <= ctx->width);

	if (ctx != NULL && input != NULL && inlen != 0U && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL && ctx->count < ctx->depth && inlen <= ctx->width)
		{
			qsc_memutils_copy(ctx->queue[ctx->position], input, inlen);
			ctx->tags[ctx->position] = tag;
			++ctx->position;

			if (ctx->position == ctx->depth)
			{
				ctx->position = 0U;
			}

			++ctx->count;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

#if defined(QSC_DEBUG_MODE)
bool qsc_queue_self_test()
{
	uint8_t exp[64U][16U] = { 0U };
	uint8_t otp1[64U * 16U] = { 0U };
	uint8_t otp2[64U][16U] = { 0U };
	qsc_queue_state ctx;
	size_t i;
	bool ret;

	ret = true;
	qsc_queue_initialize(&ctx, 64U, 16U);


	for (i = 0U; i < 64U; ++i)
	{
		for (size_t j = 0U; j < 16U; ++j)
		{
			exp[i][j] = (uint8_t)(i + j);
		}
	}

	for (i = 0U; i < 64U; ++i)
	{
		qsc_queue_push(&ctx, exp[i], 16U, i);
	}

	if (qsc_queue_full(&ctx) == false)
	{
		ret = false;
	}

	for (i = 0U; i < 64U; ++i)
	{
		qsc_queue_pop(&ctx, otp2[i], 16U);
	}

	if (qsc_queue_empty(&ctx) == false)
	{
		ret = false;
	}

	if (qsc_queue_items(&ctx) != 0U)
	{
		ret = false;
	}

	for (i = 0U; i < 64U; ++i)
	{
		if (qsc_memutils_are_equal(exp[i], otp2[i], 16U) == false)
		{
			ret = false;
			break;
		}
	}

	for (i = 0U; i < 64U; ++i)
	{
		qsc_queue_push(&ctx, exp[i], 16U, i);
	}

	if (qsc_queue_items(&ctx) != 64U)
	{
		ret = false;
	}

	qsc_queue_flush(&ctx, otp1);

	for (i = 0U; i < 64U; ++i)
	{
		if (qsc_memutils_are_equal(exp[i], ((uint8_t*)otp1 + i * 16U), 16U) == false)
		{
			ret = false;
			break;
		}
	}

	qsc_queue_dispose(&ctx);

	return ret;
}
#endif
