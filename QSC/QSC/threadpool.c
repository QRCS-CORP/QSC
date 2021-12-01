#include "threadpool.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
bool qsc_threadpool_add_task(qsc_threadpool_state* ctx, void (*func)(void*), void* state)
{
	assert(ctx != NULL && func != NULL && state != NULL);

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

			if (thd != 0)
			{
				ctx->tpool[ctx->tcount] = thd;
				idx = ctx->tcount;
				++ctx->tcount;
				res = true;

				qsc_async_thread_wait(thd);
				ctx->tpool[idx] = 0;
				--ctx->tcount;
			}
		}

		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

void qsc_threadpool_clear(qsc_threadpool_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		if (ctx->tcount != 0)
		{
			for (size_t i = 0; i < ctx->tcount; ++i)
			{
				qsc_async_thread_terminate(ctx->tpool[i]);
			}
		}

		qsc_memutils_clear(ctx->tpool, QSC_THREADPOOL_THREADS_MAX * sizeof(qsc_thread));
		ctx->tcount = 0;
	}
}

void qsc_threadpool_initialize(qsc_threadpool_state* ctx)
{
	assert(ctx != NULL);

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx->tpool, QSC_THREADPOOL_THREADS_MAX * sizeof(int32_t));
		ctx->tcount = 0;

		for (size_t i = 0; i < ctx->tcount; ++i)
		{
			ctx->tpool[i] = 0;
		}
	}
}

void qsc_threadpool_sort(qsc_threadpool_state* ctx)
{
	assert(ctx != NULL);

	qsc_thread pool[QSC_THREADPOOL_THREADS_MAX] = { 0 };
	size_t cnt;

	if (ctx != NULL)
	{
		cnt = 0;

		for (size_t i = 0; i < QSC_THREADPOOL_THREADS_MAX; ++i)
		{
			if (ctx->tpool[i] != 0)
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
	assert(ctx != NULL);
	assert(index <= ctx->tcount);

	bool res;

	res = false;

	if (ctx != NULL && ctx->tcount != 0 && index <= ctx->tcount)
	{
		res = (ctx->tpool[index] != 0);
	}

	return res;
}

void qsc_threadpool_remove_task(qsc_threadpool_state* ctx, size_t index)
{
	assert(ctx != NULL);
	assert(ctx->tcount != 0);
	assert(index < ctx->tcount);

	if (ctx != NULL && ctx->tcount != 0 && index < ctx->tcount && ctx->tpool[index] != 0)
	{
		qsc_async_thread_terminate(ctx->tpool[index]);
		ctx->tpool[index] = 0;
		--ctx->tcount;
	}
}
#endif
