#include "async.h"
#include "cpuidex.h"
#include "memutils.h"
#include <stdlib.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
    /* Windows-specific thread function definitions */
    #define THREAD_FUNC_RETURN uint32_t __stdcall
    #define THREAD_FUNC_CALL __stdcall
#elif defined(QSC_SYSTEM_OS_POSIX)
    #define THREAD_FUNC_RETURN void *
    #define THREAD_FUNC_CALL
    /* Properly initialize the static synchronization objects */
    static pthread_mutex_t tsusp = PTHREAD_MUTEX_INITIALIZER;
    static pthread_cond_t tcond = PTHREAD_COND_INITIALIZER;
    static bool suspended = false;
#endif

/*!
 * \struct async_thread_task_t
 * \brief Contains the thread task context state.
 */
typedef struct 
{
    void (*task)(void *context, size_t index);  /*!< Function to execute */
    void *context;                              /*!< Context to pass to the task */
    size_t index;                               /*!< Index for this thread */
} async_thread_task_t;

THREAD_FUNC_RETURN THREAD_FUNC_CALL async_thread_worker(void *arg) 
{
    async_thread_task_t *task = (async_thread_task_t*)arg;
    task->task(task->context, task->index);
    return 0;
}

bool qsc_async_parallel_for(void (*task)(void *context, size_t index), void* context, size_t nthreads)
{
    assert(task != NULL);

    bool res = false;

    if (task != NULL && nthreads != 0)
    {
        qsc_thread* threads;
        async_thread_task_t* tasks;

        threads = (qsc_thread*)qsc_memutils_malloc(nthreads * sizeof(qsc_thread));
        tasks = (async_thread_task_t*)qsc_memutils_malloc(nthreads * sizeof(async_thread_task_t));

        if (threads != NULL && tasks != NULL)
        {
            qsc_memutils_clear(threads, nthreads * sizeof(qsc_thread));
            qsc_memutils_clear(tasks, nthreads * sizeof(async_thread_task_t));
            res = true;

            /* Process each task on a new thread */
            for (size_t i = 0; i < nthreads; ++i)
            {
                tasks[i].task = task;
                tasks[i].context = context;
                tasks[i].index = i;

#if defined(QSC_SYSTEM_OS_WINDOWS)
                threads[i] = (HANDLE)_beginthreadex(NULL, 0, async_thread_worker, &tasks[i], 0, NULL);

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
            }

            /* Wait for all threads to finish */
            for (size_t i = 0; i < nthreads; ++i)
            {
#if defined(QSC_SYSTEM_OS_WINDOWS)
                if (threads[i] != NULL)
                {
                    WaitForSingleObject(threads[i], INFINITE);
                    CloseHandle(threads[i]);
                }
#elif defined(QSC_SYSTEM_OS_POSIX)
                pthread_join(threads[i], NULL);
#endif
            }

            qsc_memutils_alloc_free(threads);
            qsc_memutils_alloc_free(tasks);
        }
    }

    return res;
}

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

qsc_mutex qsc_async_mutex_create(void)
{
    qsc_mutex mtx;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    mtx = CreateMutex(NULL, FALSE, NULL);
#else
    pthread_mutex_t temp;
    pthread_mutex_init(&temp, NULL);
    mtx = temp;
#endif

    return mtx;
}

bool qsc_async_mutex_destroy(qsc_mutex mtx)
{
    bool res = false;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    res = (bool)CloseHandle(mtx);
#else
    /* Note: mtx is passed by value; this may work if the caller holds the mutex in a variable.
       This implementation calls pthread_mutex_destroy on the address of the local copy. */
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

qsc_mutex qsc_async_mutex_lock_ex(void)
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

size_t qsc_async_processor_count(void)
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
        uint32_t id = 0;
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
        uint32_t id = 0;
        res = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, args, 0, &id);
#elif defined(QSC_SYSTEM_OS_POSIX)
        pthread_create(&res, NULL, (void *(*) (void *))func, args);
#endif
    }

    return res;
}

int32_t qsc_async_thread_resume(qsc_thread handle)
{
    int32_t res = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    if (handle != NULL)
    {
        res = ResumeThread(handle);
    }
#elif defined(QSC_SYSTEM_OS_POSIX)
    pthread_mutex_lock(&tsusp);
    suspended = false;
    pthread_cond_signal(&tcond);
    pthread_mutex_unlock(&tsusp);
#endif

    return res;
}

/* Corrected: Use Sleep for Windows and usleep for POSIX */
void qsc_async_thread_sleep(uint32_t msec)
{
    assert(msec != 0);

    if (msec != 0)
    {
#if defined(QSC_SYSTEM_OS_WINDOWS)
        Sleep(msec);
#elif defined(QSC_SYSTEM_OS_POSIX)
        /* usleep takes microseconds */
        usleep(msec * 1000);
#endif
    }
}

int32_t qsc_async_thread_suspend(qsc_thread handle)
{
    int32_t res = -1;

#if defined(QSC_SYSTEM_OS_WINDOWS)
    if (handle != NULL)
    {
        res = SuspendThread(handle);
    }
#elif defined(QSC_SYSTEM_OS_POSIX)
    pthread_mutex_lock(&tsusp);
    suspended = true;
    while (suspended)
    {
        pthread_cond_wait(&tcond, &tsusp);
    }
    pthread_mutex_unlock(&tsusp);
#endif

    return res;
}

bool qsc_async_thread_terminate(qsc_thread handle)
{
    bool res = false;

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

void qsc_async_thread_wait_time(qsc_thread handle, uint32_t msec)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
    if (handle != NULL)
    {
        WaitForSingleObject(handle, msec);
    }
#elif defined(QSC_SYSTEM_OS_POSIX)
    /* Use usleep for a timed wait */
    usleep(msec * 1000);
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
        for (size_t i = 0; i < count; ++i)
        {
            pthread_join(handles[i], &stg);
        }
#endif
    }
}
