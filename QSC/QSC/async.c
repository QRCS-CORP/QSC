#include "cpuidex.h"
#include "async.h"

void qsc_async_launch_thread(void (*func)(void*), void* state)
{
	assert(func != NULL);

	qsc_mutex mtx;
	qsc_thread thd;

	if (func != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();
		thd = qsc_async_thread_create(func, state);
		qsc_async_thread_wait(thd);
		qsc_async_mutex_unlock_ex(mtx);
	}
}

void qsc_async_launch_parallel_threads(void (*func)(void*), size_t count, ...)
{
	assert(func != NULL);
	assert(count <= QSC_ASYNC_PARALLEL_MAX);

	qsc_mutex mtx;
	qsc_thread thds[QSC_ASYNC_PARALLEL_MAX] = { 0 };
	va_list list;

	if (func != NULL)
	{
		mtx = qsc_async_mutex_lock_ex();
		va_start(list, count);

		for (size_t i = 0; i < count; ++i)
		{
			thds[i] = qsc_async_thread_create(func, va_arg(list, void*));
		}

		qsc_async_thread_wait_all(thds, count);
		va_end(list);
		qsc_async_mutex_unlock_ex(mtx);
	}
}

qsc_mutex qsc_async_mutex_create()
{
	qsc_mutex mtx;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	mtx = CreateMutex(NULL, FALSE, NULL);
#else
	pthread_mutex_init(&mtx, NULL);
#endif

	return mtx;
}

bool qsc_async_mutex_destroy(qsc_mutex mtx)
{
	bool res;

	res = false;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (bool)CloseHandle(mtx);
#else
	res = (pthread_mutex_destroy(&mtx) == 0);
#endif

	return res;
}

void qsc_async_mutex_lock(qsc_mutex mtx)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	WaitForSingleObject(mtx, INFINITE);
#else
	pthread_mutex_lock(&mtx);
#endif
}

qsc_mutex qsc_async_mutex_lock_ex()
{
	qsc_mutex mtx;

	mtx = qsc_async_mutex_create();
	qsc_async_mutex_lock(mtx);

	return mtx;
}

void qsc_async_mutex_unlock(qsc_mutex mtx)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	ReleaseMutex(mtx);
#else
	pthread_mutex_unlock(&mtx);
#endif
}

void qsc_async_mutex_unlock_ex(qsc_mutex mtx)
{
	qsc_async_mutex_unlock(mtx);
	qsc_async_mutex_destroy(mtx);
}

size_t qsc_async_processor_count()
{
	qsc_cpuidex_cpu_features feat = { 0 };
	size_t cpus;

	qsc_cpuidex_features_set(&feat);
	cpus = 1;

	if (feat.cores != 0)
	{
		cpus = feat.cores;
	}

	return cpus;
}

qsc_thread qsc_async_thread_create(void (*func)(void*), void* state)
{
	assert(func != NULL);

	qsc_thread res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    res = NULL;
#else
    res = 0;
#endif

	if (func != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		uint32_t id;
		id = 0;
		res = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, state, 0, &id);
#elif defined(QSC_SYSTEM_OS_POSIX)
		pthread_create(&res, NULL, (void *(*) (void *))func, state);
#endif
	}

	return res;
}

qsc_thread qsc_async_thread_create_ex(void (*func)(void**), void** args)
{
	assert(func != NULL);
	assert(args != NULL);

	qsc_thread res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    res = NULL;
#else
    res = 0;
#endif

	if (func != NULL && args != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		uint32_t id;
		id = 0;
		res = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, args, 0, &id);
#elif defined(QSC_SYSTEM_OS_POSIX)
		pthread_create(&res, NULL, (void *(*) (void *))func, args);
#endif
	}

	return res;
}

int32_t qsc_async_thread_resume(qsc_thread handle)
{
	int32_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (handle != NULL)
	{
		res = ResumeThread(handle);
	}
#else
	pthread_mutex_lock(&tsusp);
	suspended = false;
	pthread_cond_signal(&tcond);
	pthread_mutex_unlock(&tsusp);
	res = 0;
#endif

	return res;
}

void qsc_async_thread_sleep(uint32_t msec)
{
	assert(msec != 0);

	if (msec != 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		HANDLE hthd;
		hthd = GetCurrentThread();
		WaitForSingleObject(hthd, msec);
#elif defined(QSC_SYSTEM_OS_POSIX)
		sleep(msec * 1000);
#endif
	}
}

int32_t qsc_async_thread_suspend(qsc_thread handle)
{
	int32_t res;

	res = -1;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (handle != NULL)
	{
		res = SuspendThread(handle);
	}
#else
	pthread_mutex_lock(&tsusp);

	do
	{
		pthread_cond_wait(&tcond, &tsusp);
	} while (suspended == true);

	pthread_mutex_unlock(&tsusp);
#endif

	return res;
}

bool qsc_async_thread_terminate(qsc_thread handle)
{
	bool res;

	res = false;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (handle != NULL)
	{
		res = CloseHandle(handle);
	}
#elif defined(QSC_SYSTEM_OS_POSIX)
	res = (pthread_cancel(handle) == 0);
#endif

	return res;
}

void qsc_async_thread_wait(qsc_thread handle)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (handle != NULL)
	{
		WaitForSingleObject(handle, INFINITE);
	}
#elif defined(QSC_SYSTEM_OS_POSIX)
	void* stg;
	pthread_join(handle, &stg);
#endif
}

void qsc_async_thread_wait_all(qsc_thread* handles, size_t count)
{
	assert(handles != NULL);

	if (handles != NULL && count != 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		WaitForMultipleObjects((DWORD)count, handles, TRUE, INFINITE);
#elif defined(QSC_SYSTEM_OS_POSIX)
		void* stg;
		size_t i;

		for (i = 0; i < count; ++i)
		{
			pthread_join(handles[i], &stg);
		}
#endif
	}
}
