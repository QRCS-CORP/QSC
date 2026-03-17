#include "event.h"
#include "memutils.h"
#include "stringutils.h"

void qsc_event_clear_listener(event_state* ctx, const char name[QSC_EVENT_NAME_SIZE])
{
	QSC_ASSERT(name != NULL);
	QSC_ASSERT(ctx->lcount <= QSC_EVENT_MAX_LISTENERS);

	if (name != NULL && ctx->lcount <= QSC_EVENT_MAX_LISTENERS && ctx->lcount != 0U && ctx->listeners != NULL)
	{
		qsc_event_handler* hndr;

		qsc_async_mutex_lock(ctx->opmtx);

		for (size_t i = 0U; i < ctx->lcount; ++i)
		{
			hndr = &ctx->listeners[i];

			if (hndr != NULL)
			{
				if (qsc_stringutils_compare_strings(name, hndr->name, QSC_EVENT_NAME_SIZE))
				{
					for (size_t j = i; j < ctx->lcount - 1U; ++j)
					{
						ctx->listeners[j] = ctx->listeners[j + 1U];
					}

					qsc_memutils_clear(&ctx->listeners[ctx->lcount - 1U], sizeof(qsc_event_handler));
					--ctx->lcount;

					break;
				}
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

void qsc_event_dispose(event_state* ctx)
{
	if (ctx->listeners != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		qsc_memutils_secure_erase(ctx->listeners, ctx->lcount * sizeof(qsc_event_handler));
		ctx->lcount = 0U;
		qsc_memutils_alloc_free(ctx->listeners);
		ctx->listeners = NULL;

		qsc_async_mutex_unlock(ctx->opmtx);

		if (ctx->opmtx)
		{
			qsc_async_mutex_destroy(ctx->opmtx);
		}
	}
}

qsc_event_callback qsc_event_get_callback(event_state* ctx, const char name[QSC_EVENT_NAME_SIZE])
{
	QSC_ASSERT(name != NULL);
	QSC_ASSERT(ctx->lcount <= QSC_EVENT_MAX_LISTENERS);

	qsc_event_callback hres = NULL;

	if (name != NULL && ctx->lcount <= QSC_EVENT_MAX_LISTENERS &&
		ctx->lcount != 0U && ctx->listeners != NULL)
	{
		qsc_event_handler* hndr;

		qsc_async_mutex_lock(ctx->opmtx);

		for (size_t i = 0U; i < ctx->lcount; ++i)
		{
			hndr = &ctx->listeners[i];

			if (hndr != NULL)
			{
				if (qsc_stringutils_compare_strings(name, hndr->name, QSC_EVENT_NAME_SIZE) == true)
				{
					hres = hndr->callback;
					break;
				}
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return hres;
}

void qsc_event_initialize(event_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		ctx->opmtx = qsc_async_mutex_create();
		ctx->lcount = 0U;
		ctx->listeners = NULL;
		ctx->initialized = true;
	}
}

bool qsc_event_listener_name_exists(const event_state* ctx, const char name[QSC_EVENT_NAME_SIZE])
{
	bool res;

	res = false;

	if (ctx != NULL && ctx->listeners != NULL && ctx->lcount != 0U)
	{
		for (size_t i = 0U; i < ctx->lcount; ++i) 
		{
			if (qsc_stringutils_compare_strings(name, ctx->listeners[i].name, QSC_EVENT_NAME_SIZE))
			{
				res = true;
				break;
			}
		}
	}

	return res;
}

int32_t qsc_event_register(event_state* ctx, const char name[QSC_EVENT_NAME_SIZE], qsc_event_callback callback)
{
	QSC_ASSERT(name != NULL);
    QSC_ASSERT(callback != NULL);

	qsc_event_handler* hndr;
	qsc_event_handler* tevh;
	size_t idx;
	size_t ncnt;
	int32_t res;

	ncnt = 0U;
	res = -1;

	if (name != NULL && callback != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		tevh = NULL;

		if (ctx->lcount < QSC_EVENT_MAX_LISTENERS)
		{
			if (qsc_event_listener_name_exists(ctx, name) == false)
			{
				if (ctx->listeners == NULL)
				{
					tevh = (qsc_event_handler*)qsc_memutils_malloc(sizeof(qsc_event_handler));
				}
				else
				{
					ncnt = ctx->lcount + 1U;
					tevh = (qsc_event_handler*)qsc_memutils_realloc(ctx->listeners, ncnt * sizeof(qsc_event_handler));
				}

				if (tevh != NULL)
				{
					ctx->listeners = tevh;
					idx = ctx->lcount;
					hndr = &ctx->listeners[idx];
					ctx->lcount = ncnt;

					if (ctx->listeners != NULL && hndr != NULL)
					{
						hndr->callback = callback;
						qsc_memutils_copy(hndr->name, name, QSC_EVENT_NAME_SIZE);
						res = 0;
					}
				}
			}
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}
