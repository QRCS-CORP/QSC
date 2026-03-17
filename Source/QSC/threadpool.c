#include "threadpool.h"
#include "memutils.h"

static qsc_mutex qsc_threadpool_mutex = NULL;

bool qsc_threadpool_add_task(qsc_threadpool_state* ctx, void (*func)(void*), void* state)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(func != NULL);

	qsc_thread thd;
	bool res;

	res = false;

	if (ctx != NULL && func != NULL)
	{
		qsc_async_mutex_lock(qsc_threadpool_mutex);

		if (ctx->tcount < QSC_THREADPOOL_THREADS_MAX)
		{
			thd = qsc_async_thread_create(func, state);

			if (thd)
			{
				ctx->tpool[ctx->tcount] = thd;
				++ctx->tcount;
				res = true;
			}
		}

		qsc_async_mutex_unlock(qsc_threadpool_mutex);
	}

	return res;
}

void qsc_threadpool_destroy(qsc_threadpool_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		if (ctx->tcount != 0U)
		{
			for (size_t i = 0U; i < ctx->tcount; ++i)
			{
				qsc_async_thread_terminate(ctx->tpool[i]);
			}
		}

		if (qsc_threadpool_mutex != NULL)
		{
			qsc_async_mutex_destroy(qsc_threadpool_mutex);
		}

		qsc_memutils_clear(ctx->tpool, QSC_THREADPOOL_THREADS_MAX * sizeof(qsc_thread));
		ctx->tcount = 0U;
	}
}

void qsc_threadpool_initialize(qsc_threadpool_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_threadpool_mutex = qsc_async_mutex_create();
		qsc_memutils_clear(ctx->tpool, QSC_THREADPOOL_THREADS_MAX * sizeof(qsc_thread));
		ctx->tcount = 0U;
	}
}

void qsc_threadpool_sort(qsc_threadpool_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	qsc_thread pool[QSC_THREADPOOL_THREADS_MAX] = { 0U };
	int32_t cnt;

	if (ctx != NULL)
	{
		cnt = 0U;

		qsc_async_mutex_lock(qsc_threadpool_mutex);

		for (size_t i = 0U; i < QSC_THREADPOOL_THREADS_MAX; ++i)
		{
			if (ctx->tpool[i])
			{
				pool[cnt] = ctx->tpool[i];
				++cnt;
			}
		}

		if (cnt != 0)
		{
			qsc_memutils_copy(ctx->tpool, pool, sizeof(pool));
		}

		qsc_async_atomic_int32_store(&ctx->tcount, cnt);
		qsc_async_mutex_unlock(qsc_threadpool_mutex);
	}
}

bool qsc_threadpool_thread_active(const qsc_threadpool_state* ctx, size_t index)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(index <= ctx->tcount);

	bool res;

	res = false;

	qsc_async_mutex_lock(qsc_threadpool_mutex);

	if (ctx != NULL && ctx->tcount != 0U && index < ctx->tcount)
	{
		res = (ctx->tpool[index]);
	}

	qsc_async_mutex_unlock(qsc_threadpool_mutex);

	return res;
}

void qsc_threadpool_remove_task(qsc_threadpool_state* ctx, size_t index)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(index < ctx->tcount);

	if (ctx != NULL && ctx->tcount != 0 && index < ctx->tcount && ctx->tpool[index])
	{
		qsc_async_mutex_lock(qsc_threadpool_mutex);

		qsc_async_thread_terminate(ctx->tpool[index]);
		ctx->tpool[index] = ctx->tpool[ctx->tcount - 1U];
		ctx->tpool[ctx->tcount - 1U] = (qsc_thread)0;
		(void)qsc_async_atomic_int32_decrement(&ctx->tcount);

		qsc_async_mutex_unlock(qsc_threadpool_mutex);
	}
}
