#include "collection.h"
#include "intutils.h"
#include "memutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "acp.h"
#endif

void qsc_collection_add(qsc_collection_state* ctx, const uint8_t* item, const uint8_t* key)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(item != NULL);
	QSC_ASSERT(key != NULL);

	uint8_t* itmp;
	uint8_t* ktmp;
	uint8_t* inew;
	uint8_t* knew;
	size_t ncnt;
	size_t pos;
	size_t ilen;
	size_t klen;
	size_t olen;
	size_t okln;

	if (ctx != NULL && item != NULL && key != NULL)
	{
		ncnt = (size_t)ctx->count + 1U;

		if (ctx->width != 0U && ncnt <= (size_t)QSC_COLLECTION_MAX_ENTRIES)
		{
			qsc_async_mutex_lock(ctx->opmtx);

			if (ctx->items == NULL && ctx->keys == NULL)
			{
				itmp = qsc_memutils_malloc(ncnt * (size_t)ctx->width);

				if (itmp != NULL)
				{
					ktmp = qsc_memutils_malloc(ncnt * QSC_COLLECTION_KEY_WIDTH);

					if (ktmp != NULL)
					{
						ctx->items = itmp;
						ctx->keys = ktmp;

						qsc_memutils_clear(ctx->items, ncnt * (size_t)ctx->width);
						qsc_memutils_clear(ctx->keys, ncnt * QSC_COLLECTION_KEY_WIDTH);

						pos = (size_t)ctx->count * (size_t)ctx->width;
						qsc_memutils_copy(ctx->items + pos, item, ctx->width);

						pos = (size_t)ctx->count * QSC_COLLECTION_KEY_WIDTH;
						qsc_memutils_copy(ctx->keys + pos, key, QSC_COLLECTION_KEY_WIDTH);

						ctx->count = (uint32_t)ncnt;
					}
					else
					{
						qsc_memutils_alloc_free(itmp);
						itmp = NULL;
					}
				}
			}
			else if (ctx->items != NULL && ctx->keys != NULL)
			{
				ilen = ncnt * (size_t)ctx->width;
				klen = ncnt * QSC_COLLECTION_KEY_WIDTH;
				olen = (size_t)ctx->count * (size_t)ctx->width;
				okln = (size_t)ctx->count * QSC_COLLECTION_KEY_WIDTH;

				inew = qsc_memutils_malloc(ilen);

				if (inew != NULL)
				{
					knew = qsc_memutils_malloc(klen);

					if (knew != NULL)
					{
						qsc_memutils_clear(inew, ilen);
						qsc_memutils_clear(knew, klen);

						if (olen != 0U)
						{
							qsc_memutils_copy(inew, ctx->items, olen);
						}

						if (okln != 0U)
						{
							qsc_memutils_copy(knew, ctx->keys, okln);
						}

						qsc_memutils_copy(inew + olen, item, ctx->width);
						qsc_memutils_copy(knew + okln, key, QSC_COLLECTION_KEY_WIDTH);

						if (olen != 0U)
						{
							qsc_memutils_secure_erase(ctx->items, olen);
						}

						if (okln != 0U)
						{
							qsc_memutils_secure_erase(ctx->keys, okln);
						}

						qsc_memutils_alloc_free(ctx->items);
						qsc_memutils_alloc_free(ctx->keys);

						ctx->items = inew;
						ctx->keys = knew;
						ctx->count = (uint32_t)ncnt;
					}
					else
					{
						qsc_memutils_alloc_free(inew);
						inew = NULL;
					}
				}
			}

			qsc_async_mutex_unlock(ctx->opmtx);
		}
	}
}

void qsc_collection_deserialize(qsc_collection_state* ctx, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);

	size_t cnt;
	size_t pos;

	if (ctx != NULL && input != NULL)
	{
		cnt = qsc_intutils_le8to32(input);

		if (cnt <= QSC_COLLECTION_MAX_ENTRIES)
		{
			pos = sizeof(uint32_t);
			ctx->width = qsc_intutils_le8to32(input + pos);

			if (ctx->width <= QSC_COLLECTION_MAX_WIDTH)
			{
				pos += sizeof(uint32_t);

				for (size_t i = 0U; i < cnt; ++i)
				{
					qsc_collection_add(ctx, input + pos, input + ctx->width + pos);
					pos += ctx->width + QSC_COLLECTION_KEY_WIDTH;
				}
			}
		}
	}
}

void qsc_collection_dispose(qsc_collection_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->items != NULL)
		{
			if (ctx->count > 0U)
			{
				qsc_memutils_secure_erase(ctx->items, (size_t)ctx->count * ctx->width);
			}

			qsc_memutils_alloc_free(ctx->items);
			ctx->items = NULL;
		}

		if (ctx->keys != NULL)
		{
			if (ctx->count > 0U)
			{
				qsc_memutils_secure_erase(ctx->keys, ctx->count * QSC_COLLECTION_KEY_WIDTH);
			}

			qsc_memutils_alloc_free(ctx->keys);
			ctx->keys = NULL;
		}

		ctx->count = 0U;
		ctx->width = 0U;

		qsc_async_mutex_unlock(ctx->opmtx);

		if (ctx->opmtx)
		{
			qsc_async_mutex_destroy(ctx->opmtx);
		}
	}
}

void qsc_collection_erase(qsc_collection_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	uint32_t width;

	if (ctx != NULL)
	{
		width = ctx->width;
		qsc_collection_dispose(ctx);
		qsc_collection_initialize(ctx, width);
	}
}

bool qsc_collection_find(const qsc_collection_state* ctx, uint8_t* item, const uint8_t* key)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(item != NULL);
	QSC_ASSERT(key != NULL);

	const uint8_t* pitm;
	bool res;

	res = false;

	if (ctx != NULL && ctx->items != NULL && item != NULL && key != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		for (size_t i = 0U; i < (size_t)ctx->count; ++i)
		{
			if (qsc_memutils_are_equal_128(ctx->keys + (i * QSC_COLLECTION_KEY_WIDTH), key) == true)
			{
				pitm = ctx->items + (i * ctx->width);
				qsc_memutils_copy(item, pitm, ctx->width);
				res = true;
				break;
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

bool qsc_collection_item_exists(const qsc_collection_state* ctx, const uint8_t* key)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(key != NULL);

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
			item = NULL;
		}
	}

	return res;
}

void qsc_collection_initialize(qsc_collection_state* ctx, uint32_t width)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(width != 0U);

	if (ctx != NULL && width != 0U)
	{
		ctx->opmtx = qsc_async_mutex_create();
		ctx->count = 0U;
		ctx->width = width;

		ctx->items = NULL;
		ctx->keys = NULL;
	}
}

void qsc_collection_item(qsc_collection_state* ctx, uint8_t* item, size_t index)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(item != NULL);

	if (ctx != NULL && ctx->items != NULL && index < ctx->count)
	{
		const uint8_t* pitm;

		qsc_async_mutex_lock(ctx->opmtx);

		pitm = ctx->items + (index * ctx->width);
		qsc_memutils_copy(item, pitm, ctx->width);

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

void qsc_collection_remove(qsc_collection_state* ctx, const uint8_t* key)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(key != NULL);

	uint8_t* inew;
	uint8_t* knew;
	size_t posi;
	size_t posl;
	size_t ilen;
	size_t klen;

	if (ctx != NULL && ctx->items != NULL && ctx->keys != NULL && key != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		for (size_t i = 0U; i < (size_t)ctx->count; ++i)
		{
			if (qsc_memutils_are_equal_128(ctx->keys + (i * QSC_COLLECTION_KEY_WIDTH), key) == true)
			{
				if (ctx->count > 1U)
				{
					const size_t ITMCNT = (size_t)ctx->count - 1U;

					/* swap the last item with the item being removed */
					posi = i * (size_t)ctx->width;
					posl = ITMCNT * (size_t)ctx->width;
					qsc_memutils_copy(ctx->items + posi, ctx->items + posl, ctx->width);
					qsc_memutils_secure_erase(ctx->items + posl, ctx->width);

					/* swap the last key with the key being removed */
					posi = i * QSC_COLLECTION_KEY_WIDTH;
					posl = ITMCNT * QSC_COLLECTION_KEY_WIDTH;
					qsc_memutils_copy(ctx->keys + posi, ctx->keys + posl, QSC_COLLECTION_KEY_WIDTH);
					qsc_memutils_secure_erase(ctx->keys + posl, QSC_COLLECTION_KEY_WIDTH);

					--ctx->count;

					ilen = (size_t)ctx->width * (size_t)ctx->count;
					klen = QSC_COLLECTION_KEY_WIDTH * (size_t)ctx->count;

					inew = qsc_memutils_malloc(ilen);

					if (inew != NULL)
					{
						knew = qsc_memutils_malloc(klen);

						if (knew != NULL)
						{
							qsc_memutils_copy(inew, ctx->items, ilen);
							qsc_memutils_copy(knew, ctx->keys, klen);

							qsc_memutils_secure_erase(ctx->items, ilen + (size_t)ctx->width);
							qsc_memutils_secure_erase(ctx->keys, klen + QSC_COLLECTION_KEY_WIDTH);

							qsc_memutils_alloc_free(ctx->items);
							qsc_memutils_alloc_free(ctx->keys);

							ctx->items = inew;
							ctx->keys = knew;
						}
						else
						{
							qsc_memutils_alloc_free(inew);
							inew = NULL;
						}
					}
				}
				else
				{
					qsc_memutils_secure_erase(ctx->items, ctx->width);
					qsc_memutils_secure_erase(ctx->keys, QSC_COLLECTION_KEY_WIDTH);

					qsc_memutils_alloc_free(ctx->items);
					qsc_memutils_alloc_free(ctx->keys);

					ctx->items = NULL;
					ctx->keys = NULL;
					ctx->count = 0U;
				}

				break;
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

size_t qsc_collection_serialize(uint8_t* output, const qsc_collection_state* ctx)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	size_t pos;

	pos = 0U;

	if (ctx != NULL && ctx->items != NULL && output != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		qsc_intutils_le32to8(output, ctx->count);
		pos = sizeof(uint32_t);
		qsc_intutils_le32to8(output + pos, ctx->width);
		pos += sizeof(uint32_t);

		for (size_t i = 0U; i < (size_t)ctx->count; ++i)
		{
			qsc_memutils_copy(output + pos, ctx->items + (i * ctx->width), ctx->width);
			pos += ctx->width;
			qsc_memutils_copy(output + pos, ctx->keys + (i * QSC_COLLECTION_KEY_WIDTH), QSC_COLLECTION_KEY_WIDTH);
			pos += QSC_COLLECTION_KEY_WIDTH;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return pos;
}

size_t qsc_collection_size(const qsc_collection_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	size_t res;

	res = 0U;

	if (ctx != NULL && ctx->items != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = (ctx->count * ctx->width) + (ctx->count * QSC_COLLECTION_KEY_WIDTH) + sizeof(uint32_t) + sizeof(uint32_t);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

#if defined(QSC_DEBUG_MODE)
bool qsc_collection_test()
{
	uint8_t keys[10U][16U] = { 0U };
	uint8_t items[10U][16U] = { 0U };
	qsc_collection_state cstate = { 0U };
	uint8_t item[16U] = { 0U };
	bool res;

	res = true;
	qsc_collection_initialize(&cstate, 16U);

	/* test the add function */
	for (size_t i = 0U; i < 10U; ++i)
	{
		qsc_acp_generate(keys[i], sizeof(keys[i]));
		qsc_acp_generate(items[i], sizeof(items[i]));
		qsc_collection_add(&cstate, items[i], keys[i]);
	}

	/* test the find function */
	for (size_t i = 0U; i < 10U; ++i)
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
		for (size_t i = 0U; i < 10U; ++i)
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
