#include "collection.h"
#include "intutils.h"
#include "memutils.h"
#if defined(QSC_DEBUG_MODE)
#	include "acp.h"
#endif

/**
 * \brief Private naturally aligned allocation header for collection item and key buffers.
 * \note Index slots are owned by the key allocation and freed on disposal.
 */
typedef struct
{
	struct
	{
		size_t capacity;    /*!< Reserved entries in this buffer. */
		uint32_t* slots;    /*!< Optional zero-based hash slots plus one; NULL if disabled. */
		size_t slotcount;   /*!< Power-of-two hash slot count or zero. */
	} meta;					/*!< Internal capacity and optional index state. */
	long double alignment;	/*!< Ensures that following item and key buffers are naturally aligned on supported targets. */
} collection_allocation;

static collection_allocation* collection_header(const uint8_t* data)
{
	collection_allocation* res;

	res = NULL;

	if (data != NULL)
	{
		res = ((collection_allocation*)data) - 1;
	}

	return res;
}

static uint8_t* collection_allocate(size_t capacity, size_t width)
{
	collection_allocation* header;
	uint8_t* res;

	res = NULL;

	if (capacity != 0U && width != 0U && capacity <= (SIZE_MAX - sizeof(collection_allocation)) / width)
	{
		header = qsc_memutils_malloc(sizeof(collection_allocation) + (capacity * width));

		if (header != NULL)
		{
			header->meta.capacity = capacity;
			header->meta.slots = NULL;
			header->meta.slotcount = 0U;
			res = (uint8_t*)(header + 1);
		}
	}

	return res;
}

static void collection_release(uint8_t* data)
{
	collection_allocation* header;

	header = collection_header(data);

	if (header != NULL)
	{
		if (header->meta.slots != NULL)
		{
			qsc_memutils_alloc_free(header->meta.slots);
		}

		qsc_memutils_alloc_free(header);
	}
}

static uint64_t collection_hash_key(const uint8_t* key)
{
	uint64_t hash;

	hash = UINT64_C(14695981039346656037);

	for (size_t i = 0U; i < QSC_COLLECTION_KEY_WIDTH; ++i)
	{
		hash = (hash ^ key[i]) * UINT64_C(1099511628211);
	}

	return hash;
}

static size_t collection_find_locked(const qsc_collection_state* ctx, const uint8_t* key)
{
	collection_allocation* hdr;
	size_t slot;
	size_t res;

	res = SIZE_MAX;
	hdr = collection_header(ctx->keys);

	if (hdr != NULL && hdr->meta.slots != NULL && hdr->meta.slotcount != 0U)
	{
		slot = (size_t)collection_hash_key(key) & (hdr->meta.slotcount - 1U);

		for (size_t i = 0U; i < hdr->meta.slotcount; ++i)
		{
			if (hdr->meta.slots[slot] == 0U)
			{
				break;
			}

			res = (size_t)hdr->meta.slots[slot] - 1U;

			if (res < ctx->count && qsc_memutils_are_equal_128(ctx->keys + res * QSC_COLLECTION_KEY_WIDTH, key) == true)
			{
				break;
			}

			res = SIZE_MAX;
			slot = (slot + 1U) & (hdr->meta.slotcount - 1U);
		}
	}
	else
	{
		for (size_t i = 0U; i < ctx->count; ++i)
		{
			if (qsc_memutils_are_equal_128(ctx->keys + i * QSC_COLLECTION_KEY_WIDTH, key) == true)
			{
				res = i;
				break;
			}
		}
	}

	return res;
}

static void collection_index_insert(const qsc_collection_state* ctx, uint32_t* slots, size_t nslots, size_t index)
{
	const uint8_t* key;
	size_t pos;
	size_t prev;
	bool duplicate;

	key = ctx->keys + index * QSC_COLLECTION_KEY_WIDTH;
	pos = (size_t)collection_hash_key(key) & (nslots - 1U);
	duplicate = false;

	while (slots[pos] != 0U)
	{
		prev = (size_t)slots[pos] - 1U;

		if (qsc_memutils_are_equal_128(ctx->keys + prev * QSC_COLLECTION_KEY_WIDTH, key) == true)
		{
			duplicate = true;
			break;
		}

		pos = (pos + 1U) & (nslots - 1U);
	}

	if (duplicate == false)
	{
		slots[pos] = (uint32_t)index + 1U;
	}
}

static bool collection_index_rebuild_locked(qsc_collection_state* ctx, size_t capacity)
{
	collection_allocation* hdr;
	uint32_t* slots;
	size_t nslots;
	bool res;

	res = false;
	hdr = collection_header(ctx->keys);
	nslots = 16U;

	if (hdr != NULL && capacity <= QSC_COLLECTION_MAX_ENTRIES)
	{
		while (nslots < capacity * 2U)
		{
			nslots *= 2U;
		}

		slots = qsc_memutils_malloc(nslots * sizeof(uint32_t));

		if (slots != NULL)
		{
			qsc_memutils_clear(slots, nslots * sizeof(uint32_t));

			for (size_t i = 0U; i < ctx->count; ++i)
			{
				collection_index_insert(ctx, slots, nslots, i);
			}

			if (hdr->meta.slots != NULL)
			{
				qsc_memutils_alloc_free(hdr->meta.slots);
			}

			hdr->meta.slots = slots;
			hdr->meta.slotcount = nslots;
			res = true;
		}
	}

	return res;
}

static bool collection_reserve_locked(qsc_collection_state* ctx, size_t required)
{
	collection_allocation* ihdr;
	collection_allocation* khdr;
	uint8_t* items;
	uint8_t* keys;
	size_t capacity;
	size_t oldcap;
	size_t step;
	bool indexed;
	bool res;

	res = false;

	if (ctx != NULL && ctx->width != 0U && ctx->width <= QSC_COLLECTION_MAX_WIDTH && required <= QSC_COLLECTION_MAX_ENTRIES)
	{
		ihdr = collection_header(ctx->items);
		khdr = collection_header(ctx->keys);
		oldcap = (ihdr != NULL && khdr != NULL) ? ihdr->meta.capacity : 0U;
		indexed = (khdr != NULL && khdr->meta.slots != NULL);

		if (required <= oldcap)
		{
			res = true;
		}
		else if ((ctx->items == NULL && ctx->keys == NULL) || (ctx->items != NULL && ctx->keys != NULL))
		{
			capacity = (oldcap != 0U) ? oldcap : 1U;

			while (capacity < required)
			{
				step = (ctx->width <= (32U * 1024U * 1024U)) ? (32U * 1024U * 1024U) / ctx->width : 1U;

				if (step > capacity)
				{
					step = capacity;
				}

				if (step > QSC_COLLECTION_MAX_ENTRIES - capacity)
				{
					capacity = QSC_COLLECTION_MAX_ENTRIES;
				}
				else
				{
					capacity += step;
				}
			}

			if (capacity <= (SIZE_MAX - sizeof(collection_allocation)) / ctx->width &&
				capacity <= (SIZE_MAX - sizeof(collection_allocation)) / QSC_COLLECTION_KEY_WIDTH)
			{
				items = collection_allocate(capacity, ctx->width);
				keys = collection_allocate(capacity, QSC_COLLECTION_KEY_WIDTH);

				if (items != NULL && keys != NULL)
				{
					if (ctx->count != 0U)
					{
						qsc_memutils_copy(items, ctx->items, (size_t)ctx->count * ctx->width);
						qsc_memutils_copy(keys, ctx->keys, (size_t)ctx->count * QSC_COLLECTION_KEY_WIDTH);
						qsc_memutils_secure_erase(ctx->items, (size_t)ctx->count * ctx->width);
						qsc_memutils_secure_erase(ctx->keys, (size_t)ctx->count * QSC_COLLECTION_KEY_WIDTH);
					}

					collection_release(ctx->items);
					collection_release(ctx->keys);
					ctx->items = items;
					ctx->keys = keys;
					res = true;

					if (indexed == true)
					{
						(void)collection_index_rebuild_locked(ctx, capacity);
					}
				}
				else
				{
					collection_release(items);
					collection_release(keys);
				}
			}
		}
	}

	return res;
}

bool qsc_collection_reserve(qsc_collection_state* ctx, size_t capacity)
{
	bool res;

	res = false;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = collection_reserve_locked(ctx, capacity);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

bool qsc_collection_enable_index(qsc_collection_state* ctx)
{
	bool res;

	res = false;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->count == 0U)
		{
			res = collection_reserve_locked(ctx, 1U);
		}
		else
		{
			res = true;
		}

		if (res == true)
		{
			res = collection_index_rebuild_locked(ctx, collection_header(ctx->keys)->meta.capacity);
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

bool qsc_collection_disable_index(qsc_collection_state* ctx)
{
	collection_allocation* hdr;
	bool res;

	res = false;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		hdr = collection_header(ctx->keys);

		if (hdr != NULL && hdr->meta.slots != NULL)
		{
			qsc_memutils_alloc_free(hdr->meta.slots);
			hdr->meta.slots = NULL;
			hdr->meta.slotcount = 0U;
		}

		res = true;
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

void qsc_collection_add(qsc_collection_state* ctx, const uint8_t* item, const uint8_t* key)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(item != NULL);
	QSC_ASSERT(key != NULL);

	collection_allocation* hdr;
	const uint8_t* srcitem;
	const uint8_t* srckey;
	size_t itemoff;
	size_t keyoff;
	bool itemalias;
	bool keyalias;

	if (ctx != NULL && item != NULL && key != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->width != 0U && ctx->count < QSC_COLLECTION_MAX_ENTRIES)
		{
			itemoff = 0U;
			keyoff = 0U;
			itemalias = false;
			keyalias = false;
			srcitem = item;
			srckey = key;

			if (ctx->items != NULL && (uintptr_t)item >= (uintptr_t)ctx->items &&
				(uintptr_t)item - (uintptr_t)ctx->items <= (size_t)ctx->count * ctx->width &&
				ctx->width <= (size_t)ctx->count * ctx->width - ((uintptr_t)item - (uintptr_t)ctx->items))
			{
				itemoff = (size_t)((uintptr_t)item - (uintptr_t)ctx->items);
				itemalias = true;
			}

			if (ctx->keys != NULL && (uintptr_t)key >= (uintptr_t)ctx->keys &&
				(uintptr_t)key - (uintptr_t)ctx->keys <= (size_t)ctx->count * QSC_COLLECTION_KEY_WIDTH &&
				QSC_COLLECTION_KEY_WIDTH <= (size_t)ctx->count * QSC_COLLECTION_KEY_WIDTH - ((uintptr_t)key - (uintptr_t)ctx->keys))
			{
				keyoff = (size_t)((uintptr_t)key - (uintptr_t)ctx->keys);
				keyalias = true;
			}

			if (collection_reserve_locked(ctx, (size_t)ctx->count + 1U) == true)
			{
				if (itemalias == true)
				{
					srcitem = ctx->items + itemoff;
				}

				if (keyalias == true)
				{
					srckey = ctx->keys + keyoff;
				}

				qsc_memutils_copy(ctx->items + (size_t)ctx->count * ctx->width, srcitem, ctx->width);
				qsc_memutils_copy(ctx->keys + (size_t)ctx->count * QSC_COLLECTION_KEY_WIDTH, srckey, QSC_COLLECTION_KEY_WIDTH);
				++ctx->count;
				hdr = collection_header(ctx->keys);

				if (hdr->meta.slots != NULL)
				{
					if (ctx->count > hdr->meta.slotcount / 2U)
					{
						if (collection_index_rebuild_locked(ctx, hdr->meta.capacity) == false)
						{
							qsc_memutils_alloc_free(hdr->meta.slots);
							hdr->meta.slots = NULL;
							hdr->meta.slotcount = 0U;
						}
					}
					else
					{
						collection_index_insert(ctx, hdr->meta.slots, hdr->meta.slotcount, (size_t)ctx->count - 1U);
					}
				}
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

bool qsc_collection_deserialize_sized(qsc_collection_state* ctx, const uint8_t* input, size_t inputlen)
{
	uint8_t* items;
	uint8_t* keys;
	uint32_t cnt;
	uint32_t width;
	size_t stride;
	size_t pos;
	bool indexed;
	bool res;

	res = false;

	if (ctx != NULL && ctx->opmtx != NULL && input != NULL && inputlen >= 2U * sizeof(uint32_t))
	{
		cnt = qsc_intutils_le8to32(input);
		width = qsc_intutils_le8to32(input + sizeof(uint32_t));
		stride = (size_t)width + QSC_COLLECTION_KEY_WIDTH;

		if (cnt <= QSC_COLLECTION_MAX_ENTRIES && width != 0U && width <= QSC_COLLECTION_MAX_WIDTH &&
			stride <= SIZE_MAX / ((size_t)cnt != 0U ? (size_t)cnt : 1U) &&
			((size_t)cnt * stride) <= inputlen - 2U * sizeof(uint32_t))
		{
			items = NULL;
			keys = NULL;

			if (cnt != 0U)
			{
				items = collection_allocate(cnt, width);
				keys = collection_allocate(cnt, QSC_COLLECTION_KEY_WIDTH);
			}

			if (cnt == 0U || (items != NULL && keys != NULL))
			{
				pos = 2U * sizeof(uint32_t);

				for (size_t i = 0U; i < cnt; ++i)
				{
					qsc_memutils_copy(items + i * width, input + pos, width);
					pos += width;
					qsc_memutils_copy(keys + i * QSC_COLLECTION_KEY_WIDTH, input + pos, QSC_COLLECTION_KEY_WIDTH);
					pos += QSC_COLLECTION_KEY_WIDTH;
				}

				qsc_async_mutex_lock(ctx->opmtx);
				indexed = (ctx->keys != NULL && collection_header(ctx->keys)->meta.slots != NULL);

				if (ctx->items != NULL && ctx->count != 0U)
				{
					qsc_memutils_secure_erase(ctx->items, (size_t)ctx->count * ctx->width);
					qsc_memutils_secure_erase(ctx->keys, (size_t)ctx->count * QSC_COLLECTION_KEY_WIDTH);
				}

				collection_release(ctx->items);
				collection_release(ctx->keys);
				ctx->items = items;
				ctx->keys = keys;
				ctx->width = width;
				ctx->count = cnt;

				if (indexed == true && cnt != 0U)
				{
					(void)collection_index_rebuild_locked(ctx, cnt);
				}

				qsc_async_mutex_unlock(ctx->opmtx);
				res = true;
			}
			else
			{
				collection_release(items);
				collection_release(keys);
			}
		}
	}

	return res;
}

void qsc_collection_deserialize(qsc_collection_state* ctx, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);

	uint32_t cnt;
	uint32_t width;
	size_t pos;

	if (ctx != NULL && ctx->opmtx != NULL && input != NULL)
	{
		cnt = qsc_intutils_le8to32(input);
		width = qsc_intutils_le8to32(input + sizeof(uint32_t));

		if (cnt <= QSC_COLLECTION_MAX_ENTRIES && width != 0U && width <= QSC_COLLECTION_MAX_WIDTH &&
			(ctx->count == 0U || ctx->width == width))
		{
			if (ctx->count == 0U)
			{
				ctx->width = width;
			}

			pos = 2U * sizeof(uint32_t);

			for (size_t i = 0U; i < cnt; ++i)
			{
				qsc_collection_add(ctx, input + pos, input + pos + width);
				pos += (size_t)width + QSC_COLLECTION_KEY_WIDTH;
			}
		}
	}
}

void qsc_collection_dispose(qsc_collection_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->items != NULL)
		{
			if (ctx->count > 0U)
			{
				qsc_memutils_secure_erase(ctx->items, (size_t)ctx->count * ctx->width);
			}

			collection_release(ctx->items);
			ctx->items = NULL;
		}

		if (ctx->keys != NULL)
		{
			if (ctx->count > 0U)
			{
				qsc_memutils_secure_erase(ctx->keys, ctx->count * QSC_COLLECTION_KEY_WIDTH);
			}

			collection_release(ctx->keys);
			ctx->keys = NULL;
		}

		ctx->count = 0U;
		ctx->width = 0U;

		qsc_async_mutex_unlock(ctx->opmtx);

		if (ctx->opmtx)
		{
			qsc_async_mutex_destroy(ctx->opmtx);
			ctx->opmtx = NULL;
		}
	}
}

void qsc_collection_erase(qsc_collection_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	uint32_t width;

	if (ctx != NULL && ctx->opmtx != NULL)
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

	size_t index;
	bool res;

	res = false;

	if (ctx != NULL && item != NULL && key != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->items != NULL && ctx->keys != NULL)
		{
			index = collection_find_locked(ctx, key);

			if (index != SIZE_MAX)
			{
				qsc_memutils_copy(item, ctx->items + index * ctx->width, ctx->width);
				res = true;
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

	bool res;

	res = false;

	if (ctx != NULL && key != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = (ctx->keys != NULL && collection_find_locked(ctx, key) != SIZE_MAX);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

void qsc_collection_initialize(qsc_collection_state* ctx, uint32_t width)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(width != 0U);
	QSC_ASSERT(width <= QSC_COLLECTION_MAX_WIDTH);

	if (ctx != NULL)
	{
		ctx->opmtx = NULL;
		ctx->count = 0U;
		ctx->width = 0U;
		ctx->items = NULL;
		ctx->keys = NULL;

		if (width != 0U && width <= QSC_COLLECTION_MAX_WIDTH)
		{
			ctx->opmtx = qsc_async_mutex_create();

			if (ctx->opmtx != NULL)
			{
				ctx->width = width;
			}
		}
	}
}

void qsc_collection_item(qsc_collection_state* ctx, uint8_t* item, size_t index)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(item != NULL);

	if (ctx != NULL && item != NULL && ctx->opmtx != NULL)
	{
		const uint8_t* pitm;

		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->items != NULL && index < ctx->count)
		{
			pitm = ctx->items + (index * ctx->width);
			qsc_memutils_copy(item, pitm, ctx->width);
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

void qsc_collection_remove(qsc_collection_state* ctx, const uint8_t* key)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(key != NULL);

	collection_allocation* hdr;
	size_t index;
	size_t last;
	bool indexed;

	if (ctx != NULL && key != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->items != NULL && ctx->keys != NULL && ctx->count != 0U)
		{
			index = collection_find_locked(ctx, key);

			if (index != SIZE_MAX)
			{
				last = (size_t)ctx->count - 1U;
				hdr = collection_header(ctx->keys);
				indexed = (hdr->meta.slots != NULL);

				if (index != last)
				{
					qsc_memutils_copy(ctx->items + index * ctx->width, ctx->items + last * ctx->width, ctx->width);
					qsc_memutils_copy(ctx->keys + index * QSC_COLLECTION_KEY_WIDTH, ctx->keys + last * QSC_COLLECTION_KEY_WIDTH, QSC_COLLECTION_KEY_WIDTH);
				}

				qsc_memutils_secure_erase(ctx->items + last * ctx->width, ctx->width);
				qsc_memutils_secure_erase(ctx->keys + last * QSC_COLLECTION_KEY_WIDTH, QSC_COLLECTION_KEY_WIDTH);
				--ctx->count;

				if (ctx->count == 0U)
				{
					collection_release(ctx->items);
					collection_release(ctx->keys);
					ctx->items = NULL;
					ctx->keys = NULL;
				}
				else if (indexed == true && collection_index_rebuild_locked(ctx, hdr->meta.capacity) == false)
				{
					qsc_memutils_alloc_free(hdr->meta.slots);
					hdr->meta.slots = NULL;
					hdr->meta.slotcount = 0U;
				}
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

bool qsc_collection_serialize_sized(uint8_t* output, size_t outputlen, const qsc_collection_state* ctx, size_t* written)
{
	size_t length;
	size_t pos;
	bool res;

	res = false;

	if (ctx != NULL && ctx->opmtx != NULL && output != NULL && written != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		length = 2U * sizeof(uint32_t) + (size_t)ctx->count * ((size_t)ctx->width + QSC_COLLECTION_KEY_WIDTH);

		if (length <= outputlen)
		{
			qsc_intutils_le32to8(output, ctx->count);
			qsc_intutils_le32to8(output + sizeof(uint32_t), ctx->width);
			pos = 2U * sizeof(uint32_t);

			for (size_t i = 0U; i < ctx->count; ++i)
			{
				qsc_memutils_copy(output + pos, ctx->items + i * ctx->width, ctx->width);
				pos += ctx->width;
				qsc_memutils_copy(output + pos, ctx->keys + i * QSC_COLLECTION_KEY_WIDTH, QSC_COLLECTION_KEY_WIDTH);
				pos += QSC_COLLECTION_KEY_WIDTH;
			}

			*written = pos;
			res = true;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

size_t qsc_collection_serialize(uint8_t* output, const qsc_collection_state* ctx)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(output != NULL);

	size_t pos;

	pos = 0U;

	if (ctx != NULL && output != NULL && ctx->opmtx != NULL)
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

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = ((size_t)ctx->count * (size_t)ctx->width) + ((size_t)ctx->count * QSC_COLLECTION_KEY_WIDTH) + sizeof(uint32_t) + sizeof(uint32_t);
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
