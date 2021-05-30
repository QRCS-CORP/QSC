#include "threads.h"

bool qsc_threads_mutex_create(qsc_threads_mutex* mtx)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	*mtx = CreateMutex(NULL, FALSE, NULL);
#else
	mtx = PTHREAD_MUTEX_INITIALIZER;
#endif

	return (mtx != NULL);
}

bool qsc_threads_mutex_destroy(qsc_threads_mutex* mtx)
{
	bool res;

	res = false;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (mtx != NULL)
	{
		res = (bool)CloseHandle(*mtx);
		mtx = NULL;
	}
#else
	if (mtx != NULL)
	{
		res = (pthread_mutex_destroy(mtx) == 0);
		mtx = NULL;
	}
#endif

	return res;
}

void qsc_threads_mutex_lock(qsc_threads_mutex* mtx)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (mtx != NULL)
	{
		WaitForSingleObject(*mtx, INFINITE);
	}
#else
	if (mtx != NULL)
	{
		pthread_mutex_lock(mtx);
	}
#endif
}

void qsc_threads_mutex_unlock(qsc_threads_mutex* mtx)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (mtx != NULL)
	{
		ReleaseMutex(*mtx);
	}
#else
	if (mtx != NULL)
	{
		pthread_mutex_unlock(mtx);
	}
#endif
}

qsc_thread qsc_threads_initialize(void (*thd_func)(void*), void* state)
{
	qsc_thread res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = _beginthread(thd_func, 0, state);
#elif defined(QSC_SYSTEM_OS_POSIX)
	p_thread_create(&res, NULL, thd_func, state);
#endif

	return res;
}

qsc_thread qsc_threads_initialize_ex(void (*thd_func)(void**), void** args)
{
	qsc_thread res;

	res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = _beginthread(thd_func, 0, args);
#elif defined(QSC_SYSTEM_OS_POSIX)
	p_thread_create(&res, NULL, thd_func, args);
#endif

	return res;
}

void qsc_threads_terminate(qsc_thread* handle)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	_endthread();
#elif defined(QSC_SYSTEM_OS_POSIX)
	pthread_cancel(handle);
#endif
}

void qsc_thread_wait(qsc_thread* handle)
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

void qsc_threads_wait_all(qsc_thread* handles, int count)
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