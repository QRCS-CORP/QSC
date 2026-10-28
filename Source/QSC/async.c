#include "async.h"
#include "memutils.h"
#include "sysutils.h"
#include <stdarg.h>
#include <stdlib.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#   if !defined(VC_EXTRALEAN)
#       define VC_EXTRALEAN
#   endif
#   if !defined(NOMINMAX)
#       define NOMINMAX
#   endif
#   if !defined(_WINSOCKAPI_)
#       define _WINSOCKAPI_
#   endif
#   include <windows.h>
#   include <intrin.h>
#   include <process.h>
#define THREAD_FUNC_RETURN uint32_t __stdcall
#define THREAD_FUNC_CALL __stdcall
#elif defined(QSC_SYSTEM_OS_POSIX)
#   include <time.h>
#   include <unistd.h>
#   define THREAD_FUNC_RETURN void*
#   define THREAD_FUNC_CALL
#endif

/*!
 * \struct async_thread_task_t
 * \brief Contains the parallel-thread task context state.
 */
typedef struct
{
    void (*task)(void* context, size_t index);  /*!< Function to execute */
    void* context;                              /*!< Context to pass to the task */
    size_t index;                               /*!< Index for this thread */
} async_thread_task_t;

/*!
 * \struct async_thread_state_t
 * \brief Contains the single-argument thread task context state.
 */
typedef struct
{
    void (*func)(void*);    /*!< Function to execute */
    void* state;            /*!< Function argument */
} async_thread_state_t;

/*!
 * \struct async_thread_args_t
 * \brief Contains the extended thread task context state.
 */
typedef struct
{
    void (*func)(void**);   /*!< Function to execute */
    void** args;            /*!< Function arguments */
} async_thread_args_t;

/*!
 * \struct async_thread_noargs_t
 * \brief Contains the no-argument thread task context state.
 */
typedef struct
{
    void (*func)(void);     /*!< Function to execute */
} async_thread_noargs_t;

/**
 * \brief Run an indexed parallel task using caller-owned stack state.
 * \param arg: [void*] Owned task context; indexed tasks use caller-owned state.
 * \return [THREAD_FUNC_RETURN] Zero or NULL platform thread exit status.
 * \warning Callback execution occurs outside any internal mutex.
 */
static THREAD_FUNC_RETURN THREAD_FUNC_CALL async_thread_worker(void* arg)
{
	async_thread_task_t* task;

	task = (async_thread_task_t*)arg;

	if (task != NULL && task->task != NULL)
	{
		task->task(task->context, task->index);
	}

#if defined(QSC_SYSTEM_OS_WINDOWS)
	return 0U;
#else
	return NULL;
#endif
}

/**
 * \brief Run a single-argument task and reclaim its heap state on exit or cancellation.
 * \param arg: [void*] Owned task context; indexed tasks use caller-owned state.
 * \return [THREAD_FUNC_RETURN] Zero or NULL platform thread exit status.
 * \warning Callback execution occurs outside any internal mutex.
 */
static THREAD_FUNC_RETURN THREAD_FUNC_CALL async_thread_state_worker(void* arg)
{
	async_thread_state_t* task;

	task = (async_thread_state_t*)arg;

	if (task != NULL)
	{
#if defined(QSC_SYSTEM_OS_POSIX)
		/* Reclaim the task even if the caller cancels the pthread. */
		pthread_cleanup_push(qsc_memutils_alloc_free, task);
#endif
		if (task->func != NULL)
		{
			task->func(task->state);
		}
#if defined(QSC_SYSTEM_OS_POSIX)
		pthread_cleanup_pop(1);
#else
		qsc_memutils_alloc_free(task);
#endif
	}

#if defined(QSC_SYSTEM_OS_WINDOWS)
	return 0U;
#else
	return NULL;
#endif
}

/**
 * \brief Run a multi-argument task and reclaim its heap state on exit or cancellation.
 * \param arg: [void*] Owned task context; indexed tasks use caller-owned state.
 * \return [THREAD_FUNC_RETURN] Zero or NULL platform thread exit status.
 * \warning Callback execution occurs outside any internal mutex.
 */
static THREAD_FUNC_RETURN THREAD_FUNC_CALL async_thread_args_worker(void* arg)
{
	async_thread_args_t* task;

	task = (async_thread_args_t*)arg;

	if (task != NULL)
	{
#if defined(QSC_SYSTEM_OS_POSIX)
		/* Reclaim the task even if the caller cancels the pthread. */
		pthread_cleanup_push(qsc_memutils_alloc_free, task);
#endif
		if (task->func != NULL)
		{
			task->func(task->args);
		}
#if defined(QSC_SYSTEM_OS_POSIX)
		pthread_cleanup_pop(1);
#else
		qsc_memutils_alloc_free(task);
#endif
	}

#if defined(QSC_SYSTEM_OS_WINDOWS)
	return 0U;
#else
	return NULL;
#endif
}

/**
 * \brief Run a parameterless task and reclaim its heap state on exit or cancellation.
 * \param arg: [void*] Owned task context; indexed tasks use caller-owned state.
 * \return [THREAD_FUNC_RETURN] Zero or NULL platform thread exit status.
 * \warning Callback execution occurs outside any internal mutex.
 */
static THREAD_FUNC_RETURN THREAD_FUNC_CALL async_thread_noargs_worker(void* arg)
{
	async_thread_noargs_t* task;

	task = (async_thread_noargs_t*)arg;

	if (task != NULL)
	{
#if defined(QSC_SYSTEM_OS_POSIX)
		/* Reclaim the task even if the caller cancels the pthread. */
		pthread_cleanup_push(qsc_memutils_alloc_free, task);
#endif
		if (task->func != NULL)
		{
			task->func();
		}
#if defined(QSC_SYSTEM_OS_POSIX)
		pthread_cleanup_pop(1);
#else
		qsc_memutils_alloc_free(task);
#endif
	}

#if defined(QSC_SYSTEM_OS_WINDOWS)
	return 0U;
#else
	return NULL;
#endif
}

bool qsc_async_atomic_bool_load(volatile bool* target)
{
    QSC_ASSERT(target != NULL);

    bool res;

    res = false;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        /* OR with 0: reads atomically without modifying the value */
        res = (_InterlockedOr8((volatile char*)target, (char)0) != (char)0);
#else
        res = __atomic_load_n(target, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}

void qsc_async_atomic_bool_store(volatile bool* target, bool value)
{
    QSC_ASSERT(target != NULL);

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        _InterlockedExchange8((volatile char*)target, (char)value);
#else
        __atomic_store_n(target, value, __ATOMIC_SEQ_CST);
#endif
    }
}

bool qsc_async_atomic_bool_exchange(volatile bool* target, bool value)
{
    QSC_ASSERT(target != NULL);

    bool res;

    res = false;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        res = (_InterlockedExchange8((volatile char*)target, (char)value) != (char)0);
#else
        res = __atomic_exchange_n(target, value, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}

bool qsc_async_atomic_bool_compare_exchange(volatile bool* target, bool expected, bool desired)
{
    QSC_ASSERT(target != NULL);

    bool res;

    res = false;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        res = (_InterlockedCompareExchange8((volatile char*)target, (char)desired, (char)expected) == (char)expected);
#else
        /* __atomic_compare_exchange_n writes back to expected on failure; use a copy */
        res = __atomic_compare_exchange_n(target, &expected, desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}
int32_t qsc_async_atomic_int32_load(volatile int32_t* target)
{
    QSC_ASSERT(target != NULL);

    int32_t res;

    res = 0;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        /* OR with 0: reads atomically without modifying the value */
        res = (int32_t)_InterlockedOr((volatile LONG*)target, 0L);
#else
        res = __atomic_load_n(target, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}

void qsc_async_atomic_int32_store(volatile int32_t* target, int32_t value)
{
    QSC_ASSERT(target != NULL);

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        _InterlockedExchange((volatile LONG*)target, (LONG)value);
#else
        __atomic_store_n(target, value, __ATOMIC_SEQ_CST);
#endif
    }
}

int32_t qsc_async_atomic_int32_exchange(volatile int32_t* target, int32_t value)
{
    QSC_ASSERT(target != NULL);

    int32_t res;

    res = 0;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        res = (int32_t)_InterlockedExchange((volatile LONG*)target, (LONG)value);
#else
        res = __atomic_exchange_n(target, value, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}

bool qsc_async_atomic_int32_compare_exchange(volatile int32_t* target, int32_t expected, int32_t desired)
{
    QSC_ASSERT(target != NULL);

    bool res;

    res = false;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        res = (_InterlockedCompareExchange((volatile LONG*)target, (LONG)desired, (LONG)expected) == (LONG)expected);
#else
        res = __atomic_compare_exchange_n(target, &expected, desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}

int32_t qsc_async_atomic_int32_add(volatile int32_t* target, int32_t value)
{
    QSC_ASSERT(target != NULL);

    int32_t res;

    res = 0;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        /* Use unsigned arithmetic to avoid signed-overflow undefined behavior. */
        res = (int32_t)((uint32_t)_InterlockedExchangeAdd((volatile LONG*)target, (LONG)value) + (uint32_t)value);
#else
        res = __atomic_add_fetch(target, value, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}

int32_t qsc_async_atomic_int32_subtract(volatile int32_t* target, int32_t value)
{
    QSC_ASSERT(target != NULL);

    int32_t res;

    res = 0;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        /* Unsigned negation handles INT32_MIN without signed overflow. */
        res = (int32_t)((uint32_t)_InterlockedExchangeAdd((volatile LONG*)target, (LONG)(0U - (uint32_t)value)) - (uint32_t)value);
#else
        res = __atomic_sub_fetch(target, value, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}

int32_t qsc_async_atomic_int32_increment(volatile int32_t* target)
{
    QSC_ASSERT(target != NULL);

    int32_t res;

    res = 0;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        /* _InterlockedIncrement returns the new value directly */
        res = (int32_t)_InterlockedIncrement((volatile LONG*)target);
#else
        res = __atomic_add_fetch(target, 1, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}

int32_t qsc_async_atomic_int32_decrement(volatile int32_t* target)
{
    QSC_ASSERT(target != NULL);

    int32_t res;

    res = 0;

    if (target != NULL)
    {
#if defined(QSC_SYSTEM_COMPILER_MSC)
        /* _InterlockedDecrement returns the new value directly */
        res = (int32_t)_InterlockedDecrement((volatile LONG*)target);
#else
        res = __atomic_sub_fetch(target, 1, __ATOMIC_SEQ_CST);
#endif
    }

    return res;
}

void qsc_async_launch_thread(void (*func)(void*), void* state)
{
	qsc_thread thd;

	QSC_ASSERT(func != NULL);

	if (func != NULL)
	{
		thd = qsc_async_thread_create(func, state);

		if (thd != (qsc_thread)0)
		{
			qsc_async_thread_wait(thd);
		}
		else
		{
			/* Preserve synchronous task completion when thread creation fails. */
			func(state);
		}
	}
}

void qsc_async_launch_parallel_threads(void (*func)(void*), size_t count, ...)
{
	qsc_thread thds[QSC_ASYNC_PARALLEL_MAX] = { 0 };
	va_list args;
	size_t batch;
	size_t i;
	size_t remaining;
	void* state;

	QSC_ASSERT(func != NULL);

	if (func != NULL && count != 0U)
	{
		va_start(args, count);
		remaining = count;

		while (remaining != 0U)
		{
			batch = (remaining < QSC_ASYNC_PARALLEL_MAX) ? remaining : QSC_ASYNC_PARALLEL_MAX;

			for (i = 0U; i < batch; ++i)
			{
				state = va_arg(args, void*);
				thds[i] = qsc_async_thread_create(func, state);

				if (thds[i] == (qsc_thread)0)
				{
					/* The void API cannot signal failure; run the task locally. */
					func(state);
				}
			}

			qsc_async_thread_wait_all(thds, batch);
			remaining -= batch;
		}

		va_end(args);
	}
}

qsc_mutex qsc_async_mutex_create(void)
{
	qsc_mutex mtx;

	mtx = NULL;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	mtx = CreateMutex(NULL, FALSE, NULL);
#else
	mtx = (pthread_mutex_t*)qsc_memutils_malloc(sizeof(pthread_mutex_t));

	if (mtx != NULL)
	{
		if (pthread_mutex_init(mtx, NULL) != 0)
		{
			qsc_memutils_alloc_free(mtx);
			mtx = NULL;
		}
	}
#endif

	return mtx;
}

bool qsc_async_mutex_destroy(qsc_mutex mtx)
{
	bool res;

	res = false;

	if (mtx != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (CloseHandle(mtx) != 0);
#else
		res = (pthread_mutex_destroy(mtx) == 0);

		if (res == true)
		{
			qsc_memutils_alloc_free(mtx);
		}
#endif
	}

	return res;
}

void qsc_async_mutex_lock(qsc_mutex mtx)
{
	QSC_ASSERT(mtx != NULL);

	if (mtx != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		(void)WaitForSingleObject(mtx, INFINITE);
#else
		(void)pthread_mutex_lock(mtx);
#endif
	}
}

qsc_mutex qsc_async_mutex_lock_ex(void)
{
	qsc_mutex mtx;

	mtx = qsc_async_mutex_create();

	if (mtx != NULL)
	{
		qsc_async_mutex_lock(mtx);
	}

	return mtx;
}

void qsc_async_mutex_unlock(qsc_mutex mtx)
{
	QSC_ASSERT(mtx != NULL);

	if (mtx != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		(void)ReleaseMutex(mtx);
#else
		(void)pthread_mutex_unlock(mtx);
#endif
	}
}

void qsc_async_mutex_unlock_ex(qsc_mutex mtx)
{
	if (mtx != NULL)
	{
		qsc_async_mutex_unlock(mtx);
		(void)qsc_async_mutex_destroy(mtx);
	}
}

bool qsc_async_parallel_for(void (*task)(void* context, size_t index), void* context, size_t nthreads)
{
	qsc_thread threads[QSC_ASYNC_PARALLEL_MAX] = { 0 };
	async_thread_task_t tasks[QSC_ASYNC_PARALLEL_MAX];
	size_t batch;
	size_t i;
	size_t launched;
	size_t offset;
	bool res;

	QSC_ASSERT(task != NULL);
	QSC_ASSERT(context != NULL);

	res = false;

	if (task != NULL && context != NULL && nthreads != 0U)
	{
		res = true;
		offset = 0U;

		while (offset < nthreads && res == true)
		{
			batch = ((nthreads - offset) < QSC_ASYNC_PARALLEL_MAX) ? (nthreads - offset) : QSC_ASYNC_PARALLEL_MAX;
			launched = 0U;

			for (i = 0U; i < batch; ++i)
			{
				tasks[i].task = task;
				tasks[i].context = context;
				tasks[i].index = offset + i;

#if defined(QSC_SYSTEM_OS_WINDOWS)
				threads[i] = (qsc_thread)_beginthreadex(NULL, 0, async_thread_worker, &tasks[i], 0, NULL);

				if (threads[i] == NULL)
				{
					res = false;
					break;
				}
#elif defined(QSC_SYSTEM_OS_POSIX)
				if (pthread_create(&threads[i], NULL, async_thread_worker, &tasks[i]) != 0)
				{
					res = false;
					break;
				}
#endif
				++launched;
			}

			qsc_async_thread_wait_all(threads, launched);
			offset += batch;
		}
	}

	return res;
}

size_t qsc_async_processor_count(void)
{
    size_t cpus;

    cpus = qsc_sysutils_cpu_count();

    return cpus;
}

qsc_thread qsc_async_thread_create(void (*func)(void*), void* state)
{
    QSC_ASSERT(func != NULL);

    qsc_thread res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    res = NULL;
#else
    res = 0;
#endif

    if (func != NULL)
    {
        async_thread_state_t* task;

        task = (async_thread_state_t*)qsc_memutils_malloc(sizeof(async_thread_state_t));

        if (task != NULL)
        {
            task->func = func;
            task->state = state;

#if defined(QSC_SYSTEM_OS_WINDOWS)
            uint32_t id;

            id = 0U;
            res = (HANDLE)_beginthreadex(NULL, 0, async_thread_state_worker, task, 0, &id);

            if (res == NULL)
            {
                qsc_memutils_alloc_free(task);
            }
#elif defined(QSC_SYSTEM_OS_POSIX)
            if (pthread_create(&res, NULL, async_thread_state_worker, task) != 0)
            {
                qsc_memutils_alloc_free(task);
                res = 0;
            }
#endif
        }
    }

    return res;
}

bool qsc_async_thread_create_detached(void (*func)(void*), void* state)
{
	qsc_thread handle;
	bool res;

	QSC_ASSERT(func != NULL);

	res = false;

	if (func != NULL)
	{
		handle = qsc_async_thread_create(func, state);

		if (handle != (qsc_thread)0)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			res = (CloseHandle(handle) != 0);
#elif defined(QSC_SYSTEM_OS_POSIX)
			res = (pthread_detach(handle) == 0);

			if (res == false)
			{
				/* The rare detach failure must not leak a joinable thread. */
				(void)pthread_join(handle, NULL);
			}
#endif
		}
	}

	return res;
}

qsc_thread qsc_async_thread_create_ex(void (*func)(void**), void** args)
{
    QSC_ASSERT(func != NULL);

    qsc_thread res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    res = NULL;
#else
    res = 0;
#endif

    if (func != NULL)
    {
        async_thread_args_t* task;

        task = (async_thread_args_t*)qsc_memutils_malloc(sizeof(async_thread_args_t));

        if (task != NULL)
        {
            task->func = func;
            task->args = args;

#if defined(QSC_SYSTEM_OS_WINDOWS)
            uint32_t id;

            id = 0U;
            res = (HANDLE)_beginthreadex(NULL, 0, async_thread_args_worker, task, 0, &id);

            if (res == NULL)
            {
                qsc_memutils_alloc_free(task);
            }
#elif defined(QSC_SYSTEM_OS_POSIX)
            if (pthread_create(&res, NULL, async_thread_args_worker, task) != 0)
            {
                qsc_memutils_alloc_free(task);
                res = 0;
            }
#endif
        }
    }

    return res;
}

qsc_thread qsc_async_thread_create_noargs(void (*func)(void))
{
    QSC_ASSERT(func != NULL);

    qsc_thread res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    res = NULL;
#else
    res = 0;
#endif

    if (func != NULL)
    {
        async_thread_noargs_t* task;

        task = (async_thread_noargs_t*)qsc_memutils_malloc(sizeof(async_thread_noargs_t));

        if (task != NULL)
        {
            task->func = func;

#if defined(QSC_SYSTEM_OS_WINDOWS)
            uint32_t id;

            id = 0U;
            res = (HANDLE)_beginthreadex(NULL, 0, async_thread_noargs_worker, task, 0, &id);

            if (res == NULL)
            {
                qsc_memutils_alloc_free(task);
            }
#elif defined(QSC_SYSTEM_OS_POSIX)
            if (pthread_create(&res, NULL, async_thread_noargs_worker, task) != 0)
            {
                qsc_memutils_alloc_free(task);
                res = 0;
            }
#endif
        }
    }

    return res;
}

int32_t qsc_async_thread_resume(qsc_thread handle)
{
	int32_t res;

	res = -1;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	if (handle != NULL)
	{
		res = (int32_t)ResumeThread(handle);
	}
#elif defined(QSC_SYSTEM_OS_POSIX)
	/* POSIX has no safe, portable mechanism to resume an arbitrary thread. */
	(void)handle;
#endif

	return res;
}

void qsc_async_thread_sleep(uint32_t msec)
{
	if (msec != 0U)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		Sleep(msec);
#elif defined(QSC_SYSTEM_OS_POSIX)
		struct timespec request;
		struct timespec remainder;

		request.tv_sec = (time_t)(msec / 1000U);
		request.tv_nsec = (long)((msec % 1000U) * 1000000UL);

		while (nanosleep(&request, &remainder) != 0 && errno == EINTR)
		{
			request = remainder;
		}
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
		res = (int32_t)SuspendThread(handle);
	}
#elif defined(QSC_SYSTEM_OS_POSIX)
	/* Never block the caller on a process-global suspension condition. */
	(void)handle;
#endif

	return res;
}

bool qsc_async_thread_terminate(qsc_thread handle)
{
	bool res;

	res = false;

	if (handle != (qsc_thread)0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (TerminateThread(handle, 0U) != 0);
		(void)CloseHandle(handle);
#elif defined(QSC_SYSTEM_OS_POSIX)
		/* Cancellation is deferred; detach reclaims the joinable thread state. */
		if (pthread_cancel(handle) == 0)
		{
			res = (pthread_detach(handle) == 0);
		}
#endif
	}

	return res;
}

void qsc_async_thread_wait(qsc_thread handle)
{
	if (handle != (qsc_thread)0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (WaitForSingleObject(handle, INFINITE) == WAIT_OBJECT_0)
		{
			(void)CloseHandle(handle);
		}
#elif defined(QSC_SYSTEM_OS_POSIX)
		(void)pthread_join(handle, NULL);
#endif
	}
}

void qsc_async_thread_wait_time(qsc_thread handle, uint32_t msec)
{
	if (handle != (qsc_thread)0)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		if (WaitForSingleObject(handle, msec) == WAIT_OBJECT_0)
		{
			/* Close only after the worker has exited; timeout keeps the handle valid. */
			(void)CloseHandle(handle);
		}
#elif defined(QSC_SYSTEM_OS_LINUX)
		struct timespec deadline;
		int32_t status;

		if (clock_gettime(CLOCK_REALTIME, &deadline) == 0)
		{
			deadline.tv_sec += (time_t)(msec / 1000U);
			deadline.tv_nsec += (long)((msec % 1000U) * 1000000UL);

			if (deadline.tv_nsec >= 1000000000L)
			{
				++deadline.tv_sec;
				deadline.tv_nsec -= 1000000000L;
			}

			do
			{
				status = pthread_timedjoin_np(handle, NULL, &deadline);
			} while (status == EINTR);
		}
#elif defined(QSC_SYSTEM_OS_POSIX)
		/* Unsupported timed join: do not silently perform an infinite wait. */
		(void)msec;
#endif
	}
}

void qsc_async_thread_wait_all(qsc_thread* handles, size_t count)
{
	size_t i;

	QSC_ASSERT(handles != NULL);

	if (handles != NULL)
	{
		for (i = 0U; i < count; ++i)
		{
			if (handles[i] != (qsc_thread)0)
			{
				qsc_async_thread_wait(handles[i]);
				handles[i] = (qsc_thread)0;
			}
		}
	}
}
