#include "list.h"
#include "memutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "intutils.h"
#endif

bool qsc_list_add(qsc_list_state* ctx, void* item)
{
	assert(ctx != NULL);
	assert(item != NULL);

	size_t nlen;
	bool res;

	res = false;

	if (!qsc_list_isfull(ctx))
	{
		if (ctx->count == ctx->depth)
		{
			nlen = ctx->count;
			ctx->items = (uint8_t**)qsc_memutils_realloc(ctx->items, nlen + 1 * sizeof(uint8_t*));

			if (ctx->items != NULL)
			{
				ctx->items[nlen] = qsc_memutils_malloc(ctx->width);

				if (ctx->items[nlen] != NULL)
				{
					qsc_memutils_clear(ctx->items[nlen], ctx->width);
					qsc_memutils_copy(ctx->items[nlen], item, ctx->width);
					++ctx->count;
					res = true;
				}
			}
		}
		else
		{
			qsc_memutils_clear(ctx->items[ctx->count], ctx->width);
			qsc_memutils_copy(ctx->items[ctx->count], item, ctx->width);
			++ctx->count;
			res = true;
		}
	}

	return res;
}

void qsc_list_copy(const qsc_list_state* ctx, size_t index, void* item)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		if (index < ctx->count && ctx->items[index] != NULL)
		{
			qsc_memutils_copy(item, ctx->items[index], ctx->width);
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

void qsc_list_destroy(qsc_list_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		for (size_t i = 0; i < ctx->depth; ++i)
		{
			if (ctx->items[i] != NULL)
			{
				qsc_memutils_clear(ctx->items[i], ctx->width);
				qsc_memutils_alloc_free(ctx->items[i]);
			}
		}

		qsc_memutils_alloc_free(ctx->items);
		ctx->items = NULL;
		ctx->count = 0;
		ctx->depth = 0;
		ctx->width = 0;
	}
}

void qsc_list_initialize(qsc_list_state* ctx, size_t depth, size_t width)
{
	assert(ctx != NULL);
	assert(depth != 0 && width != 0);

	ctx->items = (uint8_t**)qsc_memutils_malloc(depth * sizeof(uint8_t*));

	if (ctx->items != NULL)
	{
		for (size_t i = 0; i < depth; ++i)
		{
			ctx->items[i] = (uint8_t*)qsc_memutils_malloc(width);

			if (ctx->items[i] != NULL)
			{
				qsc_memutils_clear(ctx->items[i], width);
			}
		}
	}

	ctx->count = 0;
	ctx->depth = depth;
	ctx->width = width;
}

bool qsc_list_isempty(const qsc_list_state* ctx)
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

bool qsc_list_isfull(const qsc_list_state* ctx)
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

void qsc_list_remove(qsc_list_state* ctx, size_t index)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		if (index < ctx->count && ctx->items[index] != NULL)
		{
			qsc_memutils_clear(ctx->items[index], ctx->width);

			/* shift last item into slot */
			if (index < ctx->count - 1)
			{
				qsc_memutils_copy(ctx->items[index], ctx->items[ctx->count - 1], ctx->width);
				qsc_memutils_clear(ctx->items[ctx->count - 1], ctx->width);
			}

			--ctx->count;
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
	qsc_list_initialize(&ctx, 64, 16);


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

	if (qsc_list_isfull(&ctx) == true)
	{
		ret = false;
	}

	for (i = 63; i >= 0; --i)
	{
		qsc_list_remove(&ctx, i);
	}

	if (qsc_list_isempty(&ctx) == false)
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

	for (i = 0; i < 64; ++i)
	{
		if (qsc_intutils_are_equal8(exp[i], (uint8_t*)ctx.items[i], 16) == false)
		{
			ret = false;
			break;
		}
	}

	if (qsc_list_count(&ctx) != 64)
	{
		ret = false;
	}

	qsc_list_destroy(&ctx);

	return ret;
}
#endif
