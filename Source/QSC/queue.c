#include "queue.h"
#include "memutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "intutils.h"
#endif

void qsc_queue_dispose(qsc_queue_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL)
		{
			for (size_t i = 0U; i < ctx->depth; ++i)
			{
				if (ctx->queue[i] != NULL)
				{
					qsc_memutils_secure_erase(ctx->queue[i], ctx->width);
					qsc_memutils_aligned_free(ctx->queue[i]);
				}
			}
		}

		qsc_memutils_aligned_free(ctx->queue);
		ctx->queue = NULL;
		qsc_memutils_secure_erase(ctx->tags, sizeof(ctx->tags));
		ctx->count = 0U;
		ctx->depth = 0U;
		ctx->position = 0U;
		ctx->width = 0U;

		qsc_async_mutex_unlock(ctx->opmtx);

		if (ctx->opmtx)
		{
			qsc_async_mutex_destroy(ctx->opmtx);
		}
	}
}

void qsc_queue_flush(qsc_queue_state* ctx, uint8_t* output)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	if (ctx != NULL && output != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->queue != NULL)
		{
			for (size_t i = 0U; i < ctx->position; ++i)
			{
				if (ctx->queue[i] != NULL)
				{
					qsc_memutils_copy((output + (i * ctx->width)), ctx->queue[i], ctx->width);
					qsc_memutils_secure_erase(ctx->queue[i], ctx->width);
				}
			}
		}

		ctx->count = 0U;
		ctx->position = 0U;
		qsc_memutils_secure_erase(ctx->tags, sizeof(ctx->tags));

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

void qsc_queue_initialize(qsc_queue_state* ctx, size_t depth, size_t width)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(depth != 0U);
	QSC_ASSERT(width != 0U);


	if (ctx != NULL && depth != 0U && width != 0U)
	{
		if (depth > QSC_QUEUE_MAX_DEPTH) 
		{
			depth = QSC_QUEUE_MAX_DEPTH;
		}

		ctx->opmtx = qsc_async_mutex_create();

		ctx->queue = (uint8_t**)qsc_memutils_aligned_alloc(QSC_QUEUE_ALIGNMENT, depth * sizeof(uint8_t*));

		if (ctx->queue != NULL)
		{
			size_t i;
			size_t j;
			bool success;

			success = true;

			for (i = 0U; i < depth; ++i)
			{
				ctx->queue[i] = qsc_memutils_aligned_alloc(QSC_QUEUE_ALIGNMENT, width);

				if (ctx->queue[i] != NULL)
				{
					qsc_memutils_clear(ctx->queue[i], width);
				}
				else
				{
					success = false;
					break;
				}
			}

			if (success == true)
			{
				ctx->count = 0U;
				ctx->depth = depth;
				ctx->position = 0U;
				qsc_memutils_clear(ctx->tags, QSC_QUEUE_MAX_DEPTH);
				ctx->width = width;
			}
			else
			{
				for (j = 0U; j < i; ++j)
				{
					qsc_memutils_aligned_free(ctx->queue[j]);
					ctx->queue[j] = NULL;
				}

				qsc_memutils_aligned_free(ctx->queue);
				ctx->queue = NULL;
			}
		}
	}
}

size_t qsc_queue_items(const qsc_queue_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	size_t res;

	res = 0U;

	if (ctx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = ctx->count;
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

bool qsc_queue_full(const qsc_queue_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	bool res;

	res = false;

	if (ctx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = (ctx->count == ctx->depth);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

bool qsc_queue_empty(const qsc_queue_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	bool res;

	res = false;

	if (ctx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = (ctx->count == 0U);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

uint64_t qsc_queue_pop(qsc_queue_state* ctx, uint8_t* output, size_t otplen)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(otplen != 0U);
	QSC_ASSERT(otplen <= ctx->width);

	uint64_t tag;

	tag = 0U;

	if (ctx != NULL && output != NULL && otplen != 0U)
	{
		if (!qsc_queue_empty(ctx) && otplen <= ctx->width)
		{
			qsc_async_mutex_lock(ctx->opmtx);

			/* copy out oldest entry */
			qsc_memutils_copy(output, ctx->queue[0U], otplen);
			tag = ctx->tags[0U];

			if (ctx->count > 1U)
			{
				for (size_t i = 1U; i < ctx->count; ++i)
				{
					/* shift data buffers */
					qsc_memutils_copy(ctx->queue[i - 1U], ctx->queue[i], ctx->width);
					/* shift tags */
					ctx->tags[i - 1U] = ctx->tags[i];
				}
			}

			/* clear last slot */
			qsc_memutils_secure_erase(ctx->queue[ctx->count - 1U], ctx->width);
			ctx->tags[ctx->count - 1U] = 0U;

			--ctx->count;
			--ctx->position;

			qsc_async_mutex_unlock(ctx->opmtx);
		}
		else
		{
			qsc_memutils_clear(output, otplen);
		}
	}

	return tag;
}

void qsc_queue_push(qsc_queue_state* ctx, const uint8_t* input, size_t inlen, uint64_t tag)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(inlen != 0U);
	QSC_ASSERT(inlen <= ctx->width);

	if (ctx != NULL && input != NULL && inlen != 0U)
	{
		if (!qsc_queue_full(ctx) && inlen <= ctx->width)
		{
			qsc_async_mutex_lock(ctx->opmtx);

			qsc_memutils_copy(ctx->queue[ctx->position], input, inlen);
			ctx->tags[ctx->position] = tag;
			++ctx->position;
			++ctx->count;

			qsc_async_mutex_unlock(ctx->opmtx);
		}
	}
}

#if defined(QSC_DEBUG_MODE)
bool qsc_queue_self_test()
{
	uint8_t exp[64U][16U] = { 0U };
	uint8_t otp1[64U * 16U] = { 0U };
	uint8_t otp2[64U][16U] = { 0U };
	qsc_queue_state ctx;
	int32_t i;
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
