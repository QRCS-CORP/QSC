#include "list.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "secrand.h"

void qsc_list_add(qsc_list_state* ctx, const void* item)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(item != NULL);

	uint8_t* itmp;
	size_t cnt;
	size_t pos;

	if (ctx != NULL && item != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		cnt = ctx->count + 1U;

		if (ctx->items == NULL)
		{
			ctx->items = qsc_memutils_malloc(cnt * ctx->width);

			if (ctx->items  != NULL)
			{
				qsc_memutils_copy(ctx->items, item, ctx->width);
				ctx->count = (uint32_t)cnt;
			}
		}
		else
		{
			itmp = qsc_memutils_realloc(ctx->items, cnt * ctx->width);

			if (itmp != NULL)
			{
				ctx->items = itmp;
				pos = ctx->count * ctx->width;
				qsc_memutils_copy(ctx->items + pos, item, ctx->width);
				ctx->count = (uint32_t)cnt;
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

void qsc_list_copy(const qsc_list_state* ctx, size_t index, void* item)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(ctx->items != NULL);
	QSC_ASSERT(item != NULL);

	if (ctx != NULL && ctx->items != NULL && item != NULL)
	{
		if (index < ctx->count)
		{
			qsc_async_mutex_lock(ctx->opmtx);
			qsc_memutils_copy(item, ctx->items + (index * ctx->width), ctx->width);
			qsc_async_mutex_unlock(ctx->opmtx);
		}
	}
}

size_t qsc_list_count(const qsc_list_state* ctx)
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

void qsc_list_deserialize(qsc_list_state* ctx, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(ctx->items != NULL);
	QSC_ASSERT(input != NULL);

	uint8_t* buf;
	size_t total;
	uint32_t cnt;
	uint32_t wid;

	if (ctx != NULL && ctx->items != NULL && input != NULL)
	{
		cnt = qsc_intutils_le8to32(input);
		wid = qsc_intutils_le8to32(input + sizeof(uint32_t)); 

		if (cnt != 0U && cnt <= QSC_LIST_MAX_DEPTH && wid != 0U && wid <= QSC_LIST_MAX_WIDTH)
		{
			qsc_async_mutex_lock(ctx->opmtx);

			total = (size_t)cnt * (size_t)wid;

			if (wid != 0 && total / wid == cnt)
			{
				buf = qsc_memutils_realloc(ctx->items, total);
				if (buf == NULL) { return; }
				ctx->items = buf;
				ctx->count = cnt;
				ctx->width = wid;
				qsc_memutils_copy(ctx->items, input + 2U * sizeof(uint32_t), total);
			}

			qsc_async_mutex_unlock(ctx->opmtx);
		}
	}
}

void qsc_list_dispose(qsc_list_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL && ctx->items != NULL && ctx->count > 0U)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		qsc_secrand_dispose();

		qsc_memutils_secure_erase(ctx->items, ctx->count * ctx->width);
		qsc_memutils_alloc_free(ctx->items);

		ctx->items = NULL;
		ctx->count = 0U;
		ctx->width = 0U;

		qsc_async_mutex_unlock(ctx->opmtx);

		if (ctx->opmtx)
		{
			qsc_async_mutex_destroy(ctx->opmtx);
		}
	}
}

bool qsc_list_empty(const qsc_list_state* ctx)
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

bool qsc_list_full(const qsc_list_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	bool res;

	res = false;

	if (ctx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = (ctx->count >= QSC_LIST_MAX_DEPTH);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

void qsc_list_initialize(qsc_list_state* ctx, size_t width)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(width > 0U);

	if (ctx != NULL && width > 0U)
	{
		uint8_t seed[32U] = { 0U };

		qsc_csp_generate(seed, sizeof(seed));
		qsc_secrand_initialize(seed, sizeof(seed), NULL, 0U);
		ctx->items = NULL;
		ctx->count = 0U;
		ctx->width = width;
		ctx->opmtx = qsc_async_mutex_create();
	}
}

void qsc_list_item(const qsc_list_state* ctx, uint8_t* item, size_t index)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(ctx->items != NULL);
	QSC_ASSERT(item != NULL);

	if (ctx != NULL && item != NULL && ctx->items != NULL && index < ctx->count)
	{
		const uint8_t* pitm;

		qsc_async_mutex_lock(ctx->opmtx);
		pitm = ctx->items + (index * ctx->width);
		qsc_memutils_copy(item, pitm, ctx->width);
		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

void qsc_list_rshuffle(qsc_list_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	uint32_t idx;
	uint8_t* ditm;
	uint8_t* sitm;

	if (ctx != NULL && ctx->count > 0U && ctx->width > 0U)
	{
		uint8_t* pitm;

		qsc_async_mutex_lock(ctx->opmtx);

		pitm = qsc_memutils_malloc(ctx->width);

		if (pitm != NULL)
		{
			for (size_t i = 0U; i < ctx->count; ++i)
			{
				/* random index in range current index to max index */
				idx = (uint32_t)qsc_secrand_next_int32_maxmin((int32_t)ctx->count - 1U, (int32_t)i);

				sitm = ctx->items + ((size_t)idx * ctx->width);
				ditm = ctx->items + (i * ctx->width);
				
				/* copy the current index item to temp */
				qsc_memutils_copy(pitm, sitm, ctx->width);
				/* copy the rand index item to the index item */
				qsc_memutils_copy(sitm, ditm, ctx->width);
				/* copy the temp item to the random index item */
				qsc_memutils_copy(ditm, pitm, ctx->width);
			}

			qsc_memutils_alloc_free(pitm);
			pitm = NULL;
			
			qsc_async_mutex_unlock(ctx->opmtx);
		}
	}
}

void qsc_list_remove(qsc_list_state* ctx, size_t index)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		if (index < ctx->count && ctx->items != NULL)
		{
			qsc_async_mutex_lock(ctx->opmtx);

			qsc_memutils_secure_erase(ctx->items + (index * ctx->width), ctx->width);

			/* shift last item into slot */
			if (index < ctx->count - 1U)
			{
				uint8_t* itmp;
				size_t ncnt;

				ncnt = ctx->count - 1U;
				qsc_memutils_copy(ctx->items + (index * ctx->width), ctx->items + (ncnt * ctx->width), ctx->width);
				qsc_memutils_secure_erase(ctx->items + (ncnt * ctx->width), ctx->width);

				itmp = qsc_memutils_realloc(ctx->items, ncnt * ctx->width);

				if (itmp != NULL)
				{
					ctx->items = itmp;
					ctx->count = ncnt;
				}
			}
			else if (ctx->count - 1 == 0U)
			{
				/* last item in list */
				qsc_memutils_alloc_free(ctx->items);
				ctx->items = NULL;
				ctx->count = 0U;
			}

			qsc_async_mutex_unlock(ctx->opmtx);
		}
	}
}

size_t qsc_list_serialize(uint8_t* output, const qsc_list_state* ctx)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(ctx != NULL);

	size_t pos;

	pos = 0U;

	if (output != NULL && ctx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		qsc_intutils_le32to8(output, (uint32_t)ctx->count);
		pos = sizeof(uint32_t);
		qsc_intutils_le32to8(output + pos, (uint32_t)ctx->width);
		pos += sizeof(uint32_t);

		qsc_memutils_copy(output + pos, ctx->items, ctx->count * ctx->width);
		pos += ctx->count * ctx->width;

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return pos;
}

size_t qsc_list_size(const qsc_list_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	size_t res;

	res = 0U;

	if (ctx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = sizeof(uint32_t) + sizeof(uint32_t) + (ctx->count * ctx->width);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

void qsc_list_sort(qsc_list_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	uint8_t* pia;
	uint8_t* pib;
	uint8_t* tmp;

	if (ctx != NULL && ctx->items != NULL && ctx->count >= 2U)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		tmp = qsc_memutils_malloc(ctx->width);

		if (tmp != NULL)
		{
			/* sort the list as a little endian array */
			for (size_t i = 0U; i < ctx->count - 1U; ++i)
			{
				for (size_t j = i + 1U; j < ctx->count; ++j)
				{
					pia = ctx->items + (i * ctx->width);
					pib = ctx->items + (j * ctx->width);

					if (qsc_memutils_are_equal(pib, pia, ctx->width) == false)
					{
						qsc_memutils_copy(tmp, pia, ctx->width);
						qsc_memutils_copy(pia, pib, ctx->width);
						qsc_memutils_copy(pib, tmp, ctx->width);
					}
				}
			}

			qsc_memutils_alloc_free(tmp);
			tmp = NULL;

			qsc_async_mutex_unlock(ctx->opmtx);
		}
	}
}

#if defined(QSC_DEBUG_MODE)
bool qsc_list_self_test()
{
	uint8_t exp[64U][16U] = { 0U };
	qsc_list_state ctx = { 0U };
	int32_t i;
	bool ret;

	ret = true;
	qsc_list_initialize(&ctx, 16U);


	for (i = 0U; i < 64; ++i)
	{
		for (size_t j = 0U; j < 16U; ++j)
		{
			exp[i][j] = (uint8_t)(i + j);
		}
	}

	for (i = 0; i < 64; ++i)
	{
		qsc_list_add(&ctx, exp[i]);
	}

	if (qsc_list_full(&ctx) == true)
	{
		ret = false;
	}

	for (i = 63; i >= 0; --i)
	{
		qsc_list_remove(&ctx, i);
	}

	if (qsc_list_empty(&ctx) == false)
	{
		ret = false;
	}

	if (qsc_list_count(&ctx) != 0U)
	{
		ret = false;
	}

	for (i = 0; i < 64; ++i)
	{
		qsc_list_add(&ctx, exp[i]);
	}

	if (ctx.items != NULL)
	{
		for (i = 0; i < 64; ++i)
		{
			const uint8_t* ptmp = ctx.items+ i;

			if (qsc_memutils_are_equal(exp[i], ptmp, 16U) == false)
			{
				ret = false;
				break;
			}
		}
	}

	if (qsc_list_count(&ctx) != 64U)
	{
		ret = false;
	}

	qsc_list_dispose(&ctx);

	return ret;
}
#endif
