#include "async.h"

bool qsc_async_mutex_create(qsc_async_mutex* mtx)
{
	assert(mtx != NULL);

	bool res;

	if (mtx != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		mtx = CreateMutex(NULL, FALSE, NULL);
#else
		mtx = PTHREAD_MUTEX_INITIALIZER;
#endif
	}

	res = (mtx != NULL);

	return res;
}

bool qsc_async_mutex_destroy(qsc_async_mutex* mtx)
{
	assert(mtx != NULL);

	bool res;

	res = false;

	if (mtx != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (bool)CloseHandle(mtx);
		mtx = NULL;
#else
		res = (pthread_mutex_destroy(mtx) == 0);
		mtx = NULL;
#endif
	}

	return res;
}

void qsc_async_mutex_lock(qsc_async_mutex* mtx)
{
	assert(mtx != NULL);

	if (mtx != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		WaitForSingleObject(mtx, INFINITE);
#else
		pthread_mutex_lock(mtx);
#endif
	}
}

void qsc_async_mutex_lock_ex(qsc_async_mutex* mtx)
{
	assert(mtx != NULL);

	if (mtx != NULL)
	{
		qsc_async_mutex_create(mtx);
		qsc_async_mutex_lock(mtx);
	}
}

void qsc_async_mutex_unlock(qsc_async_mutex* mtx)
{
	assert(mtx != NULL);

	if (mtx != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		ReleaseMutex(mtx);
#else
		pthread_mutex_unlock(mtx);
#endif
	}
}

void qsc_async_mutex_unlock_ex(qsc_async_mutex* mtx)
{
	assert(mtx != NULL);

	if (mtx != NULL)
	{
		qsc_async_mutex_unlock(mtx);
		qsc_async_mutex_destroy(mtx);
	}
}

qsc_thread qsc_async_thread_initialize(void (*thd_func)(void*), void* state)
{
	assert(thd_func != NULL);
	assert(state != NULL);

	qsc_thread res;

	res = 0;

	if (state != NULL && thd_func != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = _beginthread(thd_func, 0, state);
#elif defined(QSC_SYSTEM_OS_POSIX)
		p_thread_create(&res, NULL, thd_func, state);
#endif
	}

	return res;
}

void qsc_async_thread_terminate(qsc_thread* handle)
{
	assert(handle != NULL);

	if (handle != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		_endthread();
#elif defined(QSC_SYSTEM_OS_POSIX)
		pthread_cancel(handle);
#endif
	}
}

void qsc_async_thread_wait(qsc_thread* handle)
{
	assert(handle != NULL);

	if (handle != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		WaitForSingleObject((HANDLE)handle, INFINITE);
#elif defined(QSC_SYSTEM_OS_POSIX)
		void* stg;

		pthread_join(handle, &stg);

		if (stg != NULL)
		{
			free(stg);
		}
#endif
	}
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

void qsc_async_thread_wait_all(qsc_thread* handles, int count)
{
	assert(handles != NULL);
	assert(count > 0);

	if (handles != NULL && count > 0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		WaitForMultipleObjects(count, (HANDLE*)handles, TRUE, INFINITE);
#elif defined(QSC_SYSTEM_OS_POSIX)
		void* stg;
		size_t i;

		for (i = 0; i < count; ++i)
		{
			pthread_join(handles[i], &stg);

			if (stg != NULL)
			{
				free(stg);
			}
		}
#endif
	}
}