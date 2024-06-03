#include "collection.h"
#include "async.h"
#include "intutils.h"
#include "memutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "acp.h"
#endif

void qsc_collection_add(qsc_collection_state* ctx, const uint8_t* item, const uint8_t* key)
{
	assert(ctx != NULL);
	assert(item != NULL);
	assert(key != NULL);

	uint8_t* itmp;
	uint8_t* ktmp;
	size_t ncnt;
	size_t pos;

	if (ctx != NULL && item != NULL && key != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		ncnt = ctx->count + 1;

		if (ctx->items == NULL)
		{
			itmp = qsc_memutils_malloc(ncnt * ctx->width);
			ktmp = qsc_memutils_malloc(ncnt * QSC_COLLECTION_KEY_WIDTH);
		}
		else
		{
			itmp = qsc_memutils_realloc(ctx->items, ncnt * ctx->width);
			ktmp = qsc_memutils_realloc(ctx->keys, ncnt * QSC_COLLECTION_KEY_WIDTH);
		}

		if (itmp != NULL && ktmp != NULL)
		{
			ctx->items = itmp;
			ctx->keys = ktmp;

			pos = ctx->count * ctx->width;
			qsc_memutils_copy(ctx->items + pos, item, ctx->width);
			pos = ctx->count * QSC_COLLECTION_KEY_WIDTH;
			qsc_memutils_copy(ctx->keys + pos, key, QSC_COLLECTION_KEY_WIDTH);
			ctx->count = (uint32_t)ncnt;
		}

		qsc_async_mutex_unlock_ex(mtx);
	}
}

void qsc_collection_deserialize(qsc_collection_state* ctx, const uint8_t* input)
{
	assert(input != NULL);
	assert(ctx != NULL);

	size_t cnt;
	size_t pos;

	if (ctx != NULL && input != NULL)
	{
		cnt = qsc_intutils_le8to32(input);
		pos = sizeof(uint32_t);
		ctx->width = qsc_intutils_le8to32(input + pos);
		pos += sizeof(uint32_t);

		for (size_t i = 0; i < cnt; ++i)
		{
			qsc_collection_add(ctx, input + pos, input + ctx->width + pos);
			pos += ctx->width + QSC_COLLECTION_KEY_WIDTH;
		}
	}
}

void qsc_collection_dispose(qsc_collection_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		if (ctx->items != NULL)
		{
			qsc_memutils_clear(ctx->items, ctx->count * ctx->width);
			qsc_memutils_alloc_free(ctx->items);
			ctx->items = NULL;
		}

		if (ctx->keys != NULL)
		{
			qsc_memutils_clear(ctx->keys, ctx->count * QSC_COLLECTION_KEY_WIDTH);
			qsc_memutils_alloc_free(ctx->keys);
			ctx->keys = NULL;
		}
	}

	ctx->count = 0;
	ctx->width = 0;
}

void qsc_collection_erase(qsc_collection_state* ctx)
{
	size_t width;

	width = ctx->width;
	qsc_collection_dispose(ctx);
	qsc_collection_initialize(ctx, width);
}

bool qsc_collection_find(const qsc_collection_state* ctx, uint8_t* item, const uint8_t* key)
{
	assert(ctx != NULL);
	assert(item != NULL);
	assert(key != NULL);

	bool res;

	res = false;

	if (ctx != NULL && ctx->items != NULL && key != NULL)
	{
		uint8_t* pitm;
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0; i < ctx->count; ++i)
		{
			if (qsc_memutils_are_equal_128(ctx->keys + (i * QSC_COLLECTION_KEY_WIDTH), key) == true)
			{
				pitm = ctx->items + (i * ctx->width);
				qsc_memutils_copy(item, pitm, ctx->width);
				res = true;
				break;
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

bool qsc_collection_item_exists(const qsc_collection_state* ctx, const uint8_t* key)
{
	assert(ctx != NULL);
	assert(key != NULL);

	uint8_t* item;
	bool res;

	res = false;

	if (ctx != NULL && ctx->items != NULL && key != NULL)
	{
		item = (uint8_t*)qsc_memutils_malloc(ctx->width);

		if (item != NULL)
		{
			res = qsc_collection_find(ctx, item, key);
			qsc_memutils_alloc_free(item);
		}
	}

	return res;
}

void qsc_collection_initialize(qsc_collection_state* ctx, size_t width)
{
	assert(ctx != NULL);
	assert(width != 0);

	if (ctx != NULL && width != 0)
	{
		ctx->count = 0;
		ctx->width = (uint32_t)width;

		/* initialize the placeholders */
		ctx->items = qsc_memutils_malloc(sizeof(uint8_t));
		ctx->keys = qsc_memutils_malloc(sizeof(uint8_t));
	}
}

void qsc_collection_item(qsc_collection_state* ctx, uint8_t* item, size_t index)
{
	assert(ctx != NULL);

	if (ctx != NULL && ctx->items != NULL && index < ctx->count)
	{
		qsc_mutex mtx;
		uint8_t* pitm;

		mtx = qsc_async_mutex_lock_ex();
		pitm = ctx->items + (index * ctx->width);
		qsc_memutils_copy(item, pitm, ctx->width);
		qsc_async_mutex_unlock_ex(mtx);
	}
}

void qsc_collection_remove(qsc_collection_state* ctx, const uint8_t* key)
{
	assert(ctx != NULL);
	assert(key != NULL);

	uint8_t *itmp;
	uint8_t *ktmp;
	size_t posi;
	size_t posl;

	if (ctx != NULL && ctx->items != NULL && ctx->keys != NULL && key != NULL)
	{
		qsc_mutex mtx;

		mtx = qsc_async_mutex_lock_ex();

		for (size_t i = 0; i < ctx->count; ++i)
		{
			if (qsc_memutils_are_equal_128(ctx->keys + (i * QSC_COLLECTION_KEY_WIDTH), key) == true)
			{
				if (ctx->count > 1)
				{
					const size_t ITMCNT = ctx->count - 1;

					/* swap the last item with the item being removed */
					posi = i * ctx->width;
					posl = ITMCNT * ctx->width;
					qsc_memutils_copy(ctx->items + posi, ctx->items + posl, ctx->width);
					qsc_memutils_clear(ctx->items + posl, ctx->width);

					/* swap the last key with the key being removed */
					posi = i * QSC_COLLECTION_KEY_WIDTH;
					posl = ITMCNT * QSC_COLLECTION_KEY_WIDTH;
					qsc_memutils_copy(ctx->keys + posi, ctx->keys + posl, QSC_COLLECTION_KEY_WIDTH);
					qsc_memutils_clear(ctx->keys + posl, QSC_COLLECTION_KEY_WIDTH);

				}
				else
				{
					qsc_memutils_clear(ctx->items, ctx->width);
					qsc_memutils_clear(ctx->keys, QSC_COLLECTION_KEY_WIDTH);
				}

				--ctx->count;

				if (ctx->count != 0)
				{
					itmp = qsc_memutils_realloc(ctx->items, ctx->width * ctx->count);

					if (itmp != NULL)
					{
						ctx->items = itmp;
						ktmp = qsc_memutils_realloc(ctx->keys, QSC_COLLECTION_KEY_WIDTH * ctx->count);

						if (ktmp != NULL)
						{
							ctx->keys = ktmp;
						}
					}
				}
				else
				{
					itmp = qsc_memutils_realloc(ctx->items, 1);

					if (itmp != NULL)
					{
						ctx->items = itmp;
						ktmp = qsc_memutils_realloc(ctx->keys, 1);

						if (ktmp != NULL)
						{
							ctx->keys = ktmp;
						}
					}
				}
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}
}

size_t qsc_collection_serialize(uint8_t* output, const qsc_collection_state* ctx)
{
	assert(ctx != NULL);
	assert(output != NULL);

	size_t pos;

	pos = 0;

	if (ctx != NULL && ctx->items != NULL && output != NULL)
	{
		qsc_intutils_le32to8(output, ctx->count);
		pos = sizeof(uint32_t);
		qsc_intutils_le32to8(output + pos, ctx->width);
		pos += sizeof(uint32_t);

		for (size_t i = 0; i < ctx->count; ++i)
		{
			qsc_memutils_copy(output + pos, ctx->items + (i * ctx->width), ctx->width);
			pos += ctx->width;
			qsc_memutils_copy(output + pos, ctx->keys + (i * QSC_COLLECTION_KEY_WIDTH), QSC_COLLECTION_KEY_WIDTH);
			pos += QSC_COLLECTION_KEY_WIDTH;
		}
	}

	return pos;
}

size_t qsc_collection_size(const qsc_collection_state* ctx)
{
	assert(ctx != NULL);

	size_t res;

	res = 0;

	if (ctx != NULL && ctx->items != NULL)
	{
		res = (ctx->count * ctx->width) + (ctx->count * QSC_COLLECTION_KEY_WIDTH) + sizeof(uint32_t) + sizeof(uint32_t);
	}

	return res;
}

#if defined(QSC_DEBUG_MODE)
bool qsc_collection_test()
{
	uint8_t keys[10][16] = { 0 };
	uint8_t items[10][16] = { 0 };
	qsc_collection_state cstate = { 0 };
	uint8_t item[16] = { 0 };
	bool res;

	res = true;
	qsc_collection_initialize(&cstate, 16);

	/* test the add function */
	for (size_t i = 0; i < 10; ++i)
	{
		qsc_acp_generate(keys[i], sizeof(keys[i]));
		qsc_acp_generate(items[i], sizeof(items[i]));
		qsc_collection_add(&cstate, items[i], keys[i]);
	}

	/* test the find function */
	for (size_t i = 0; i < 10; ++i)
	{
		if (qsc_collection_find(&cstate, item, keys[i]) == true)
		{
			if (qsc_memutils_are_equal_128(item, items[i]) == false)
			{
				res = false;
				break;
			}
		}
	}

	if (res == true)
	{
		/* test the remove function */
		for (size_t i = 0; i < 10; ++i)
		{
			qsc_collection_remove(&cstate, keys[i]);

			if (qsc_collection_find(&cstate, item, keys[i]) == true)
			{
				res = false;
				break;
			}
		}
	}

	qsc_collection_dispose(&cstate);

	return res;
}
#endif