#include "threadpool.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
bool qsc_threadpool_add_task(qsc_threadpool_state* ctx, void (*func)(void*), void* state)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(func != NULL);
	QSC_ASSERT(state != NULL);

	qsc_thread thd;
	qsc_mutex mtx;
	size_t idx;
	bool res;

	res = false;

	if (ctx != NULL && func != NULL && state != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();

		if (ctx->tcount < QSC_THREADPOOL_THREADS_MAX)
		{
			thd = qsc_async_thread_create(func, state);

			if (thd != NULL)
			{
				ctx->tpool[ctx->tcount] = thd;
				idx = ctx->tcount;
				++ctx->tcount;
				res = true;
				ctx->tpool[idx] = NULL;
				--ctx->tcount;
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

void qsc_threadpool_clear(qsc_threadpool_state* ctx)
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

		qsc_memutils_clear(ctx->tpool, QSC_THREADPOOL_THREADS_MAX * sizeof(qsc_thread));
		ctx->tcount = 0U;
	}
}

void qsc_threadpool_initialize(qsc_threadpool_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->tpool, QSC_THREADPOOL_THREADS_MAX * sizeof(qsc_thread));
		ctx->tcount = 0U;
	}
}

void qsc_threadpool_sort(qsc_threadpool_state* ctx)
{
	QSC_ASSERT(ctx != NULL);

	qsc_thread pool[QSC_THREADPOOL_THREADS_MAX] = { 0U };
	size_t cnt;

	if (ctx != NULL)
	{
		cnt = 0U;

		for (size_t i = 0U; i < QSC_THREADPOOL_THREADS_MAX; ++i)
		{
			if (ctx->tpool[i] != NULL)
			{
				pool[cnt] = ctx->tpool[i];
				++cnt;
			}
		}

		if (cnt != 0)
		{
			qsc_memutils_copy(ctx->tpool, pool, sizeof(pool));
		}

		ctx->tcount = cnt;
	}
}

bool qsc_threadpool_thread_active(const qsc_threadpool_state* ctx, size_t index)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(index <= ctx->tcount);

	bool res;

	res = false;

	if (ctx != NULL && ctx->tcount != 0U && index < ctx->tcount)
	{
		res = (ctx->tpool[index] != NULL);
	}

	return res;
}

void qsc_threadpool_remove_task(qsc_threadpool_state* ctx, size_t index)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(ctx->tcount != 0U);
	QSC_ASSERT(index < ctx->tcount);

	if (ctx != NULL && ctx->tcount != 0 && index < ctx->tcount && ctx->tpool[index] != 0)
	{
		qsc_async_thread_terminate(ctx->tpool[index]);
		ctx->tpool[index] = NULL;
		--ctx->tcount;
	}
}
#endif
