/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL). The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_THREADS_H
#define QSC_THREADS_H

#include "common.h"
#include <stdarg.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
    /* Windows-specific thread and mutex definitions */
    QSC_SYSTEM_CONDITION_IGNORE(5105)
    #include <process.h>
    #include <Windows.h>
    typedef HANDLE qsc_mutex;
    typedef HANDLE qsc_thread;
#elif defined(QSC_SYSTEM_OS_POSIX)
    #include <sys/types.h>
    #include <unistd.h>
    #include <pthread.h>
    typedef pthread_mutex_t qsc_mutex;
    typedef pthread_t qsc_thread;
#else
    #error your operating system is not supported!
#endif

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file async.h
 * \brief Asynchronous Thread and Mutex Management Functions.
 *
 * \details
 * This header defines the public API for asynchronous thread management and mutex operations.
 * It provides functions for launching threads (both individually and in parallel), creating and
 * managing mutexes for thread synchronization, and waiting on thread execution. The API supports
 * both Windows and POSIX threading models.
 *
 * \code
 * // Example: Launch a single thread.
 * qsc_async_launch_thread(sample_task, (void*)arg);
 *
 * // Example: Launch multiple threads in parallel.
 * qsc_async_launch_parallel_threads(sample_task, 4, (void*)arg1, (void*)arg2, (void*)arg3, (void*)arg4);
 *
 * // Example: Create, lock, and unlock a mutex.
 * qsc_mutex mtx = qsc_async_mutex_create();
 * qsc_async_mutex_lock(mtx);
 * // Perform critical operations here.
 * qsc_async_mutex_unlock(mtx);
 * qsc_async_mutex_destroy(mtx);
 * \endcode
 *
 * \section async_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/procthread/">Microsoft Windows Threading</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_create.html">POSIX Threads (pthreads)</a>
 */

/*!
 * \def QSC_ASYNC_PARALLEL_MAX
 * \brief The maximum number of threads that can be launched in parallel for a parallel for loop.
 */
#define QSC_ASYNC_PARALLEL_MAX 128ULL

/* Function Declarations */

/**
 * \brief Launch a function on a new thread.
 *
 * Spawns a new thread to execute the provided function with a single argument.
 *
 * \param func:     [void (*)(void*)] Pointer to the function to execute.
 * \param state:    [void*] Pointer to the argument to pass to the function.
 */
QSC_EXPORT_API void qsc_async_launch_thread(void (*func)(void*), void* state);

/**
 * \brief Launch multiple threads in parallel using variadic arguments.
 *
 * Spawns several threads, each executing the provided function with its respective argument.
 *
 * \param func:     [void (*)(void*)] Pointer to the function to execute.
 * \param count:    [size_t] The number of threads (and corresponding arguments) to launch.
 * \param ...:      [variadic] Variadic arguments representing the state for each thread.
 */
QSC_EXPORT_API void qsc_async_launch_parallel_threads(void (*func)(void*), size_t count, ...);

/**
 * \brief Create a mutex.
 *
 * Creates a new mutex object for synchronizing threads.
 *
 * \return          [qsc_mutex] Returns a handle to the newly created mutex.
 */
QSC_EXPORT_API qsc_mutex qsc_async_mutex_create(void);

/**
 * \brief Destroy a mutex.
 *
 * Destroys the specified mutex object.
 *
 * \param mtx:      [qsc_mutex] The mutex handle to destroy.
 * \return          [bool] Returns true on successful destruction.
 */
QSC_EXPORT_API bool qsc_async_mutex_destroy(qsc_mutex mtx);

/**
 * \brief Lock a mutex.
 *
 * Blocks until the specified mutex is acquired.
 *
 * \param mtx:      [qsc_mutex] The mutex to lock.
 */
QSC_EXPORT_API void qsc_async_mutex_lock(qsc_mutex mtx);

/**
 * \brief Create and lock a mutex.
 *
 * Creates a mutex, locks it immediately, and returns the locked mutex.
 *
 * \return          [qsc_mutex] The locked mutex handle.
 */
QSC_EXPORT_API qsc_mutex qsc_async_mutex_lock_ex(void);

/**
 * \brief Unlock a mutex.
 *
 * Unlocks the specified mutex.
 *
 * \param mtx:      [qsc_mutex] The mutex to unlock.
 */
QSC_EXPORT_API void qsc_async_mutex_unlock(qsc_mutex mtx);

/**
 * \brief Unlock and destroy a mutex.
 *
 * Unlocks the specified mutex and then destroys it.
 *
 * \param mtx:      [qsc_mutex] The mutex to unlock and destroy.
 */
QSC_EXPORT_API void qsc_async_mutex_unlock_ex(qsc_mutex mtx);

/**
 * \brief Get the number of processor cores available.
 *
 * Retrieves the number of CPU cores (including hyper-threads) available on the system.
 *
 * \return          [size_t] The number of processor cores.
 */
QSC_EXPORT_API size_t qsc_async_processor_count(void);

/**
 * \brief Create a thread with one parameter.
 *
 * Creates a new thread that executes the specified function with a single argument.
 *
 * \param func:     [void (*)(void*)] Pointer to the function to execute in the new thread.
 * \param state:    [void*] Pointer to the argument to pass to the thread function.
 * \return          [qsc_thread] Returns a handle to the created thread, or NULL on failure.
 */
QSC_EXPORT_API qsc_thread qsc_async_thread_create(void (*func)(void*), void* state);

/**
 * \brief Create a thread with multiple parameters.
 *
 * Creates a new thread that executes the specified function with multiple arguments.
 *
 * \param func:     [void (*)(void**)] Pointer to the function to execute in the new thread.
 * \param args:     [void**] An array of pointers to the arguments.
 * \return          [qsc_thread] Returns a handle to the created thread, or NULL on failure.
 */
QSC_EXPORT_API qsc_thread qsc_async_thread_create_ex(void (*func)(void**), void** args);

/**
 * \brief Resume a suspended thread.
 *
 * Resumes execution of a thread that has been suspended.
 *
 * \param handle:   [qsc_thread] The thread handle to resume.
 * \return          [int32_t] Returns zero on success.
 */
QSC_EXPORT_API int32_t qsc_async_thread_resume(qsc_thread handle);

/**
 * \brief Suspend the calling thread for a specified number of milliseconds.
 *
 * Suspends execution of the calling thread for the given duration.
 *
 * \param msec:     [uint32_t] The number of milliseconds to sleep.
 */
QSC_EXPORT_API void qsc_async_thread_sleep(uint32_t msec);

/**
 * \brief Suspend a thread.
 *
 * Suspends the execution of the specified thread.
 *
 * \param handle:   [qsc_thread] The thread handle to suspend.
 * \return          [int32_t] Returns a non-negative value on success.
 */
QSC_EXPORT_API int32_t qsc_async_thread_suspend(qsc_thread handle);

/**
 * \brief Terminate a thread.
 *
 * Terminates the specified thread. On Windows, this may terminate the calling thread.
 *
 * \param handle:   [qsc_thread] The thread handle to terminate.
 * \return          [bool] Returns true if termination was successful.
 */
QSC_EXPORT_API bool qsc_async_thread_terminate(qsc_thread handle);

/**
 * \brief Wait for a thread to complete execution.
 *
 * Blocks until the specified thread has finished executing.
 *
 * \param handle:   [qsc_thread] The thread handle to wait on.
 */
QSC_EXPORT_API void qsc_async_thread_wait(qsc_thread handle);

/**
 * \brief Wait for a thread to complete execution with a timeout.
 *
 * Blocks until the specified thread has finished executing or the timeout expires.
 *
 * \param handle:   [qsc_thread] The thread handle to wait on.
 * \param msec:     [uint32_t] The maximum number of milliseconds to wait.
 */
QSC_EXPORT_API void qsc_async_thread_wait_time(qsc_thread handle, uint32_t msec);

/**
 * \brief Wait for an array of threads to complete execution.
 *
 * Blocks until all threads in the provided array have finished executing.
 *
 * \param handles:  [qsc_thread*] An array of thread handles.
 * \param count:    [size_t] The number of threads in the array.
 */
QSC_EXPORT_API void qsc_async_thread_wait_all(qsc_thread* handles, size_t count);

QSC_CPLUSPLUS_ENABLED_END

#endif
