#include "list.h"
#include "async.h"
#include "intutils.h"
#include "memutils.h"
#include "secrand.h"

void qsc_list_add(qsc_list_state* ctx, void* item)
{
	assert(ctx != NULL);
	assert(item != NULL);

	uint8_t* itmp;
	size_t cnt;
	size_t pos;

	if (ctx != NULL && item != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();
		cnt = ctx->count + 1;
		itmp = qsc_memutils_realloc(ctx->items, cnt * ctx->width);

		if (itmp != NULL)
		{
			ctx->items = itmp;
			pos = ctx->count * ctx->width;
			qsc_memutils_copy(ctx->items + pos, item, ctx->width);
			ctx->count = (uint32_t)cnt;
		}

		qsc_async_mutex_unlock_ex(mtx);
	}
}

void qsc_list_copy(const qsc_list_state* ctx, size_t index, void* item)
{
	assert(ctx != NULL);
	assert(item != NULL);

	if (ctx != NULL && item != NULL)
	{
		qsc_mutex mtx;

		if (index < ctx->count)
		{
			mtx = qsc_async_mutex_lock_ex();
			qsc_memutils_copy(item, ctx->items + (index * ctx->width), ctx->width);
			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

size_t qsc_list_count(const qsc_list_state* ctx)
{
	assert(ctx != NULL);

	size_t res;

	res = 0;

	if (ctx != NULL)
	{
		res = ctx->count;
	}

	return res;
}

void qsc_list_deserialize(qsc_list_state* ctx, const uint8_t* input)
{
	assert(ctx != NULL);
	assert(input != NULL);

	size_t pos;

	if (ctx != NULL && input != NULL)
	{
		ctx->count = qsc_intutils_le8to32(input);
		pos = sizeof(uint32_t);
		ctx->width = qsc_intutils_le8to32(input + pos);
		pos += sizeof(uint32_t);

		qsc_memutils_copy(ctx->items, input + pos, ctx->count * ctx->width);
	}
}

void qsc_list_dispose(qsc_list_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL && ctx->items != NULL && ctx->count > 0)
	{
		qsc_memutils_clear(ctx->items, ctx->count * ctx->width);
		qsc_memutils_alloc_free(ctx->items);

		ctx->items = NULL;
		ctx->count = 0;
		ctx->width = 0;
	}
}

bool qsc_list_empty(const qsc_list_state* ctx)
{
	assert(ctx != NULL);

	bool res;

	res = false;

	if (ctx != NULL)
	{
		res = (bool)(ctx->count == 0);
	}

	return res;
}

bool qsc_list_full(const qsc_list_state* ctx)
{
	assert(ctx != NULL);

	bool res;

	res = false;

	if (ctx != NULL)
	{
		res = (bool)(ctx->count >= QSC_LIST_MAX_DEPTH);
	}

	return res;
}

void qsc_list_initialize(qsc_list_state* ctx, size_t width)
{
	assert(ctx != NULL);
	assert(width > 0);

	if (ctx != NULL && width > 0)
	{
		ctx->items = (uint8_t*)qsc_memutils_malloc(sizeof(uint8_t));
		ctx->count = 0;
		ctx->width = width;
	}
}

void qsc_list_item(const qsc_list_state* ctx, uint8_t* item, size_t index)
{
	assert(ctx != NULL);
	assert(item != NULL);

	if (ctx != NULL && item != NULL && index < ctx->count)
	{
		qsc_mutex mtx;
		uint8_t* pitm;

		mtx = qsc_async_mutex_lock_ex();
		pitm = ctx->items + (index * ctx->width);
		qsc_memutils_copy(item, pitm, ctx->width);
		qsc_async_mutex_unlock_ex(mtx);
	}
}

void qsc_list_rshuffle(qsc_list_state* ctx)
{
	assert(ctx != NULL);

	uint32_t idx;
	uint8_t* ditm;
	uint8_t* sitm;

	if (ctx != NULL && ctx->count > 0 && ctx->width > 0)
	{
		uint8_t* pitm;

		pitm = qsc_memutils_malloc(ctx->width);

		if (pitm != NULL)
		{
			for (size_t i = 0; i < ctx->count; ++i)
			{
				/* random index in range current index to max index */
				idx = (uint32_t)qsc_secrand_next_int32_maxmin((int32_t)ctx->count - 1, (int32_t)i);

				sitm = ctx->items + ((size_t)idx * ctx->width);
				ditm = ctx->items + (i * ctx->width);
				/* copy the current index item to temp */
				qsc_memutils_copy(pitm, ditm, ctx->width);
				/* copy the rand index item to the index item */
				qsc_memutils_copy(sitm, ditm, ctx->width);
				/* copy the temp item to the random index item */
				qsc_memutils_copy(ditm, pitm, ctx->width);
			}

			qsc_memutils_alloc_free(pitm);
		}
	}
}

void qsc_list_remove(qsc_list_state* ctx, size_t index)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		if (index < ctx->count && ctx->items != NULL)
		{
			qsc_mutex mtx;

			mtx = qsc_async_mutex_lock_ex();

			qsc_memutils_clear(ctx->items + (index * ctx->width), ctx->width);

			/* shift last item into slot */
			if (index < ctx->count - 1)
			{
				uint8_t* itmp;
				size_t ncnt;

				ncnt = ctx->count - 1;
				qsc_memutils_copy(ctx->items + (index * ctx->width), ctx->items + (ncnt * ctx->width), ctx->width);
				qsc_memutils_clear(ctx->items + (ncnt * ctx->width), ctx->width);

				itmp = qsc_memutils_realloc(ctx->items, ncnt * ctx->width);

				if (itmp != NULL)
				{
					ctx->items = itmp;
					ctx->count = ncnt;
				}
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

size_t qsc_list_serialize(uint8_t* output, const qsc_list_state* ctx)
{
	assert(output != NULL);
	assert(ctx != NULL);

	size_t pos;

	pos = 0;

	if (output != NULL && ctx != NULL)
	{
		qsc_intutils_le32to8(output, (uint32_t)ctx->count);
		pos = sizeof(uint32_t);
		qsc_intutils_le32to8(output + pos, (uint32_t)ctx->width);
		pos += sizeof(uint32_t);

		qsc_memutils_copy(output + pos, ctx->items, ctx->count * ctx->width);
		pos += ctx->count * ctx->width;
	}

	return pos;
}

size_t qsc_list_size(const qsc_list_state* ctx)
{
	assert(ctx != NULL);

	size_t res;

	res = 0;

	if (ctx != NULL)
	{
		res = sizeof(uint32_t) + sizeof(uint32_t) + (ctx->count * ctx->width);
	}

	return res;
}

void qsc_list_sort(qsc_list_state* ctx)
{
	assert(ctx != NULL);

	uint8_t* pia;
	uint8_t* pib;
	uint8_t* tmp;

	if (ctx != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();
		tmp = qsc_memutils_malloc(ctx->width);

		if (tmp != NULL)
		{
			/* sort the list as a little endian array */
			for (size_t i = 0; i < ctx->count - 1; ++i)
			{
				for (size_t j = i + 1; j < ctx->count; ++j)
				{
					pia = ctx->items + (i * ctx->width);
					pib = ctx->items + (j * ctx->width);

					if (qsc_memutils_greater_than_le128(pib, pia) == true)
					{
						qsc_memutils_copy(tmp, pia, ctx->width);
						qsc_memutils_copy(pia, pib, ctx->width);
						qsc_memutils_copy(pib, tmp, ctx->width);
					}
				}
			}

			qsc_memutils_alloc_free(tmp);
			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

#if defined(QSC_DEBUG_MODE)
bool qsc_list_self_test()
{
	uint8_t exp[64][16] = { 0 };
	qsc_list_state ctx = { 0 };
	int32_t i;
	bool ret;

	ret = true;
	qsc_list_initialize(&ctx, 16);


	for (i = 0; i < 64; ++i)
	{
		for (size_t j = 0; j < 16; ++j)
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

	if (qsc_list_count(&ctx) != 0)
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

			if (qsc_intutils_are_equal8(exp[i], ptmp, 16) == false)
			{
				ret = false;
				break;
			}
		}
	}

	if (qsc_list_count(&ctx) != 64)
	{
		ret = false;
	}

	qsc_list_dispose(&ctx);

	return ret;
}
#endif
