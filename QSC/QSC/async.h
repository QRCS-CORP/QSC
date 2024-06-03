
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSC_THREADS_H
#define QSC_THREADS_H

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

#include "common.h"
#include <stdarg.h>
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <process.h>
#	include <Windows.h>
	typedef HANDLE qsc_mutex;
	typedef HANDLE qsc_thread;
#elif defined(QSC_SYSTEM_OS_POSIX)
#	include <sys/types.h>
#	include <unistd.h>
#	include <pthread.h>
	typedef pthread_mutex_t qsc_mutex;
	typedef pthread_t qsc_thread;
	qsc_mutex tsusp;
	pthread_cond_t tcond;
	bool suspended;
#else
#	error your operating system is not supported!
#endif

/**
* \file async.h
* \brief This file contains thread and mutex functions
* \endcode
*/

/*!
* \def QSC_ASYNC_PARALLEL_MAX
* \brief The parallel for maximum threads
*/
#define QSC_ASYNC_PARALLEL_MAX 128

/**
* \brief Launch a function on a new thread
*
* \param func: The function pointer
* \param state: The function state
*/
QSC_EXPORT_API void qsc_async_launch_thread(void (*func)(void*), void* state);

/**
* \brief Launch a series of threads, using variadic function arguments
*
* \param func: The function pointer
* \param count: The number of arguments
* \param args: The variadic argument list
*/
QSC_EXPORT_API void qsc_async_launch_parallel_threads(void (*func)(void*), size_t count, ...);

/**
* \brief Create a mutex
*
* \return Returns the mutex handle
*/
QSC_EXPORT_API qsc_mutex qsc_async_mutex_create(void);

/**
* \brief Destroy a mutex
*
* \param mtx: The mutex to destroy
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_async_mutex_destroy(qsc_mutex mtx);

/**
* \brief Lock a mutex
*
* \param mtx: The mutex to lock
*/
QSC_EXPORT_API void qsc_async_mutex_lock(qsc_mutex mtx);

/**
* \brief Creates and locks a mutex.
*
* \return Returns the locked mutex
*/
QSC_EXPORT_API qsc_mutex qsc_async_mutex_lock_ex(void);

/**
* \brief Unlock a mutex
*
* \param mtx: The mutex to unlock
*/
QSC_EXPORT_API void qsc_async_mutex_unlock(qsc_mutex mtx);

/**
* \brief Unlocks and destroys a mutex.
* The mutex must be initialized and destroyed.
*
* \param mtx: The mutex to unlock
*/
QSC_EXPORT_API void qsc_async_mutex_unlock_ex(qsc_mutex mtx);

/**
* \brief Returns the number of CPU cores (including hyper-threads) available on the system.
*/
QSC_EXPORT_API size_t qsc_async_processor_count(void);

/**
* \brief Create a thread with one parameter
*
* \param func: The thread function
* \param state: The function state
* \return Returns a thread handle, or NULL on failure
*/
QSC_EXPORT_API qsc_thread qsc_async_thread_create(void (*func)(void*), void* state);

/**
* \brief Create a thread with multiple parameters
*
* \param func: The thread function
* \param args: The function argument list
* \return Returns a thread handle, or NULL on failure
*/
QSC_EXPORT_API qsc_thread qsc_async_thread_create_ex(void (*func)(void**), void** args);

/**
* \brief Resume a thread
*
* \param handle: The thread to resume
*/
QSC_EXPORT_API int32_t qsc_async_thread_resume(qsc_thread handle);

/**
* \brief Pause the thread for a number of milliseconds
*
* \param msec: The number of milliseconds to sleep
*/
QSC_EXPORT_API void qsc_async_thread_sleep(uint32_t msec);

/**
* \brief Suspend a thread
*
* \param handle: The thread to suspend
*/
QSC_EXPORT_API int32_t qsc_async_thread_suspend(qsc_thread handle);

/**
* \brief Terminate a thread
*
* \param handle: The thread to terminate (terminates calling thread on windows)
*/
QSC_EXPORT_API bool qsc_async_thread_terminate(qsc_thread handle);

/**
* \brief Wait for a thread to complete execution
*
* \param handle: The thread handle
*/
QSC_EXPORT_API void qsc_async_thread_wait(qsc_thread handle);

/**
* \brief Wait a number of milliseconds for a thread to complete execution
*
* \param handle: The thread handle
* \param msec: The number of milliseconds to wait
*/
QSC_EXPORT_API void qsc_async_thread_wait_time(qsc_thread handle, uint32_t msec);

/**
* \brief Wait for an array of threads to complete execution
*
* \param handles: The array of threads
* \param count: The number of threads
*/
QSC_EXPORT_API void qsc_async_thread_wait_all(qsc_thread* handles, size_t count);

#endif
