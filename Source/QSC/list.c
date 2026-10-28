#include "list.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"

static bool list_random_index(uint32_t minimum, uint32_t maximum, uint32_t* index)
{
	uint32_t limit;
	uint32_t range;
	uint32_t sample;
	bool res;

	res = false;

	if (index != NULL && maximum >= minimum)
	{
		range = maximum - minimum + 1U;
		limit = UINT32_MAX - (UINT32_MAX % range);

		do
		{
			res = qsc_csp_generate((uint8_t*)&sample, sizeof(sample));
		} while (res == true && sample >= limit);

		if (res == true)
		{
			*index = minimum + (sample % range);
		}
	}

	return res;
}

/**
 * \brief Private naturally aligned allocation header for list storage.
 * \note The header is owned by the list and is not part of the public API.
 */
typedef struct
{
	size_t capacity;       /*!< Number of allocated item slots, independent of logical count. */
	long double alignment; /*!< Ensures that the following item buffer is naturally aligned on supported targets. */
} list_allocation;

static list_allocation* list_allocation_from_items(const uint8_t* items)
{
	list_allocation* res;

	res = NULL;

	if (items != NULL)
	{
		res = ((list_allocation*)items) - 1;
	}

	return res;
}

static uint8_t* list_allocate(size_t capacity, size_t width)
{
	list_allocation* base;
	uint8_t* res;

	res = NULL;

	if (capacity != 0U && width != 0U && capacity <= (SIZE_MAX - sizeof(list_allocation)) / width)
	{
		base = qsc_memutils_malloc(sizeof(list_allocation) + (capacity * width));

		if (base != NULL)
		{
			base->capacity = capacity;
			res = (uint8_t*)(base + 1);
		}
	}

	return res;
}

static void list_release(uint8_t* items)
{
	list_allocation* base;

	base = list_allocation_from_items(items);

	if (base != NULL)
	{
		qsc_memutils_alloc_free(base);
	}
}

static bool list_reserve_locked(qsc_list_state* ctx, size_t required)
{
	list_allocation* base;
	uint8_t* tmp;
	size_t capacity;
	size_t current;
	bool res;

	res = false;

	if (ctx != NULL && ctx->width != 0U && ctx->width <= QSC_LIST_MAX_WIDTH && required <= QSC_LIST_MAX_DEPTH)
	{
		base = list_allocation_from_items(ctx->items);
		current = (base != NULL) ? base->capacity : 0U;

		if (required <= current)
		{
			res = true;
		}
		else
		{
			capacity = (current != 0U) ? current : 4U;

			while (capacity < required)
			{
				if (capacity > (size_t)QSC_LIST_MAX_DEPTH / 2U)
				{
					capacity = QSC_LIST_MAX_DEPTH;
				}
				else
				{
					capacity *= 2U;
				}
			}

			if (capacity <= (SIZE_MAX - sizeof(list_allocation)) / ctx->width)
			{
				if (base == NULL)
				{
					tmp = list_allocate(capacity, ctx->width);
				}
				else
				{
					base = qsc_memutils_realloc(base, sizeof(list_allocation) + (capacity * ctx->width));
					tmp = (base != NULL) ? (uint8_t*)(base + 1) : NULL;

					if (base != NULL)
					{
						base->capacity = capacity;
					}
				}

				if (tmp != NULL)
				{
					ctx->items = tmp;
					res = true;
				}
			}
		}
	}

	return res;
}

static int32_t list_compare_le(const uint8_t* a, const uint8_t* b, size_t width)
{
	int32_t res;

	res = 0;

	for (size_t i = width; i != 0U; --i)
	{
		if (a[i - 1U] != b[i - 1U])
		{
			res = (a[i - 1U] > b[i - 1U]) ? 1 : -1;
			break;
		}
	}

	return res;
}

static void list_swap(uint8_t* a, uint8_t* b, uint8_t* scratch, size_t width)
{
	if (a != b)
	{
		qsc_memutils_copy(scratch, a, width);
		qsc_memutils_copy(a, b, width);
		qsc_memutils_copy(b, scratch, width);
	}
}

static void list_sift_down(qsc_list_state* ctx, size_t root, size_t count, uint8_t* scratch)
{
	size_t child;
	size_t largest;

	while (root < count / 2U)
	{
		child = (root * 2U) + 1U;
		largest = root;

		if (list_compare_le(ctx->items + (child * ctx->width), ctx->items + (largest * ctx->width), ctx->width) > 0)
		{
			largest = child;
		}

		if (child + 1U < count && list_compare_le(ctx->items + ((child + 1U) * ctx->width), ctx->items + (largest * ctx->width), ctx->width) > 0)
		{
			largest = child + 1U;
		}

		if (largest == root)
		{
			break;
		}

		list_swap(ctx->items + (root * ctx->width), ctx->items + (largest * ctx->width), scratch, ctx->width);
		root = largest;
	}
}

bool qsc_list_reserve(qsc_list_state* ctx, size_t capacity)
{
	bool res;

	res = false;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = list_reserve_locked(ctx, capacity);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

bool qsc_list_trim(qsc_list_state* ctx)
{
	list_allocation* base;
	uint8_t* tmp;
	bool res;

	res = false;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->count == 0U)
		{
			list_release(ctx->items);
			ctx->items = NULL;
			res = true;
		}
		else if (ctx->items != NULL)
		{
			base = list_allocation_from_items(ctx->items);
			base = qsc_memutils_realloc(base, sizeof(list_allocation) + (ctx->count * ctx->width));

			if (base != NULL)
			{
				base->capacity = ctx->count;
				tmp = (uint8_t*)(base + 1);
				ctx->items = tmp;
				res = true;
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

void qsc_list_add(qsc_list_state* ctx, const void* item)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(item != NULL);

	const uint8_t* src;
	size_t offset;
	bool alias;

	if (ctx != NULL && item != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->count < QSC_LIST_MAX_DEPTH && ctx->width != 0U && ctx->width <= QSC_LIST_MAX_WIDTH)
		{
			src = item;
			offset = 0U;
			alias = false;

			/* An existing list entry may be the source of an append. */
			if (ctx->items != NULL && (uintptr_t)src >= (uintptr_t)ctx->items &&
				(uintptr_t)src - (uintptr_t)ctx->items <= (ctx->count * ctx->width) &&
				ctx->width <= (ctx->count * ctx->width) - ((uintptr_t)src - (uintptr_t)ctx->items))
			{
				offset = (size_t)((uintptr_t)src - (uintptr_t)ctx->items);
				alias = true;
			}

			if (list_reserve_locked(ctx, ctx->count + 1U) == true)
			{
				if (alias == true)
				{
					src = ctx->items + offset;
				}

				qsc_memutils_copy(ctx->items + (ctx->count * ctx->width), src, ctx->width);
				++ctx->count;
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

bool qsc_list_deserialize_sized(qsc_list_state* ctx, const uint8_t* input, size_t inputlen)
{
	uint8_t* buf;
	uint32_t cnt;
	uint32_t wid;
	size_t total;
	bool res;

	res = false;

	if (ctx != NULL && ctx->opmtx != NULL && input != NULL && inputlen >= 2U * sizeof(uint32_t))
	{
		cnt = qsc_intutils_le8to32(input);
		wid = qsc_intutils_le8to32(input + sizeof(uint32_t));

		if (cnt != 0U && cnt <= QSC_LIST_MAX_DEPTH && wid != 0U && wid <= QSC_LIST_MAX_WIDTH)
		{
			total = (size_t)cnt * (size_t)wid;

			if (total <= inputlen - 2U * sizeof(uint32_t))
			{
				buf = list_allocate(cnt, wid);

				if (buf != NULL)
				{
					qsc_memutils_copy(buf, input + 2U * sizeof(uint32_t), total);
					qsc_async_mutex_lock(ctx->opmtx);

					if (ctx->items != NULL && ctx->count != 0U)
					{
						qsc_memutils_secure_erase(ctx->items, ctx->count * ctx->width);
					}

					list_release(ctx->items);
					ctx->items = buf;
					ctx->count = cnt;
					ctx->width = wid;
					qsc_async_mutex_unlock(ctx->opmtx);
					res = true;
				}
			}
		}
	}

	return res;
}

void qsc_list_deserialize(qsc_list_state* ctx, const uint8_t* input)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(input != NULL);

	uint32_t cnt;
	uint32_t wid;

	if (ctx != NULL && input != NULL)
	{
		/* Legacy interface does not carry a buffer size: use sized API for untrusted inputs. */
		cnt = qsc_intutils_le8to32(input);
		wid = qsc_intutils_le8to32(input + sizeof(uint32_t));

		if (cnt != 0U && cnt <= QSC_LIST_MAX_DEPTH && wid != 0U && wid <= QSC_LIST_MAX_WIDTH)
		{
			(void)qsc_list_deserialize_sized(ctx, input, 2U * sizeof(uint32_t) + ((size_t)cnt * wid));
		}
	}
}

void qsc_list_dispose(qsc_list_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->items != NULL)
		{
			qsc_memutils_secure_erase(ctx->items, ctx->count * ctx->width);
			list_release(ctx->items);
			ctx->items = NULL;
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
		ctx->items = NULL;
		ctx->count = 0U;
		ctx->width = (width <= QSC_LIST_MAX_WIDTH) ? width : 0U;
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
				if (list_random_index((uint32_t)i, (uint32_t)ctx->count - 1U, &idx) == false)
				{
					break;
				}

				sitm = ctx->items + ((size_t)idx * ctx->width);
				ditm = ctx->items + (i * ctx->width);
				
				/* copy the current index item to temp */
				qsc_memutils_copy(pitm, sitm, ctx->width);
				/* copy the rand index item to the index item */
				qsc_memutils_copy(sitm, ditm, ctx->width);
				/* copy the temp item to the random index item */
				qsc_memutils_copy(ditm, pitm, ctx->width);
			}

			qsc_memutils_secure_erase(pitm, ctx->width);
			qsc_memutils_alloc_free(pitm);
			pitm = NULL;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

void qsc_list_remove(qsc_list_state* ctx, size_t index)
{
	QSC_ASSERT(ctx != NULL);

	size_t ncnt;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->items != NULL && index < ctx->count)
		{
			ncnt = ctx->count - 1U;

			if (index != ncnt)
			{
				qsc_memutils_copy(ctx->items + (index * ctx->width), ctx->items + (ncnt * ctx->width), ctx->width);
			}

			qsc_memutils_secure_erase(ctx->items + (ncnt * ctx->width), ctx->width);
			ctx->count = ncnt;

			if (ncnt == 0U)
			{
				list_release(ctx->items);
				ctx->items = NULL;
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

bool qsc_list_serialize_sized(uint8_t* output, size_t outputlen, const qsc_list_state* ctx, size_t* written)
{
	size_t length;
	bool res;

	res = false;

	if (ctx != NULL && ctx->opmtx != NULL && output != NULL && written != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->width <= UINT32_MAX && ctx->count <= UINT32_MAX &&
			(ctx->count == 0U || ctx->width <= (SIZE_MAX - 2U * sizeof(uint32_t)) / ctx->count))
		{
			length = 2U * sizeof(uint32_t) + (ctx->count * ctx->width);

			if (length <= outputlen)
			{
				qsc_intutils_le32to8(output, (uint32_t)ctx->count);
				qsc_intutils_le32to8(output + sizeof(uint32_t), (uint32_t)ctx->width);

				if (ctx->count == 0U || ctx->items != NULL)
				{
					if (ctx->count != 0U)
					{
						qsc_memutils_copy(output + 2U * sizeof(uint32_t), ctx->items, ctx->count * ctx->width);
					}

					*written = length;
					res = true;
				}
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
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

		if (ctx->count != 0U && ctx->items != NULL)
		{
			qsc_memutils_copy(output + pos, ctx->items, ctx->count * ctx->width);
			pos += ctx->count * ctx->width;
		}

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

	uint8_t* scratch;
	size_t end;

	if (ctx != NULL && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->items != NULL && ctx->count >= 2U && ctx->width != 0U)
		{
			scratch = qsc_memutils_malloc(ctx->width);

			if (scratch != NULL)
			{
				/* Bottom-up max heap: O(n log n) comparisons, O(width) scratch. */
				for (size_t i = ctx->count / 2U; i != 0U; --i)
				{
					list_sift_down(ctx, i - 1U, ctx->count, scratch);
				}

				for (end = ctx->count; end > 1U; --end)
				{
					list_swap(ctx->items, ctx->items + ((end - 1U) * ctx->width), scratch, ctx->width);
					list_sift_down(ctx, 0U, end - 1U, scratch);
				}

				qsc_memutils_secure_erase(scratch, ctx->width);
				qsc_memutils_alloc_free(scratch);
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
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
			const uint8_t* ptmp = ctx.items + ((size_t)i * ctx.width);

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
