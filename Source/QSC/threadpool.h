/* 2025 Quantum Resistant Cryptographic Solutions Corporation
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
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_THREADPOOL_H
#define QSC_THREADPOOL_H

#include "common.h"
#include "async.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file threadpool.h
 * \brief Asynchronous Thread Pool Management Functions.
 *
 * \details
 * This header defines the public API for managing an asynchronous thread pool.
 * The thread pool enables the scheduling and execution of tasks concurrently
 * by spawning multiple threads. It provides functions to add tasks to the pool,
 * clear all tasks, initialize the pool, sort the threads to prioritize active tasks,
 * check thread activity, and remove individual tasks.
 *
 * \code
 * // Example: Initialize a thread pool, add a task, and check thread activity.
 * qsc_threadpool_state pool;
 * qsc_threadpool_initialize(&pool);
 * 
 * // Define a sample task function.
 * void sample_task(void* arg)
 * {
 *     // Task implementation.
 * }
 * 
 * // Add the task to the thread pool.
 * bool success = qsc_threadpool_add_task(&pool, sample_task, NULL);
 * 
 * // Check if the first thread in the pool is active.
 * bool is_active = qsc_threadpool_thread_active(&pool, 0);
 * 
 * // Remove the task from the pool if needed.
 * qsc_threadpool_remove_task(&pool, 0);
 * 
 * // Clear the thread pool.
 * qsc_threadpool_clear(&pool);
 * \endcode
 *
 * \section threadpool_links Reference Links:
 * - <a href="https://docs.microsoft.com/en-us/windows/win32/procthread/synchronization">Microsoft Threading and Synchronization</a>
 * - <a href="https://pubs.opengroup.org/onlinepubs/9699919799/functions/pthread_create.html">POSIX Threads (pthreads) Documentation</a>
 */

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/*!
* \def QSC_THREADPOOL_THREADS_MAX
* \brief The thread pool maximum threads
*/
#define QSC_THREADPOOL_THREADS_MAX 1024ULL

/*!
* \struct qsc_threadpool_state
* \brief The thread pool state
*/
typedef struct
{
	qsc_thread tpool[QSC_THREADPOOL_THREADS_MAX];	/*!< The thread pool */
	size_t tcount;									/*!< The thread count */
} qsc_threadpool_state;

/**
* \brief Add a task to the thread-pool
*
* \param ctx:	[qsc_threadpool_state*] The thread pool state
* \param func:	[(*func)(void*)] A pointer to the thread function
* \param state:	[void*] The thread state
*/
QSC_EXPORT_API bool qsc_threadpool_add_task(qsc_threadpool_state* ctx, void (*func)(void*), void* state);

/**
* \brief Clear all tasks from the thread-pool
*
* \param ctx:	[qsc_threadpool_state*] The thread pool state
*/
QSC_EXPORT_API void qsc_threadpool_clear(qsc_threadpool_state* ctx);

/**
* \brief Initialize the thread-pool
*
* \param ctx:	[qsc_threadpool_state*] The thread pool state
*/
QSC_EXPORT_API void qsc_threadpool_initialize(qsc_threadpool_state* ctx);

/**
* \brief Sort the threads in the pool, placing active threads at the start of the array
*
* \param ctx:	[qsc_threadpool_state*] The thread pool state
*/
QSC_EXPORT_API void qsc_threadpool_sort(qsc_threadpool_state* ctx);

/**
* \brief Check if a thread is active
*
* \param ctx:	[const qsc_threadpool_state*] The thread pool state
* \param index:	[size_t] The thread index
* 
* \return		[bool] Returns true if the thread is currently used
*/
QSC_EXPORT_API bool qsc_threadpool_thread_active(const qsc_threadpool_state* ctx, size_t index);

/**
* \brief Remove a task from the thread-pool
*
* \param ctx:	[qsc_threadpool_state*] The thread pool state
* \param index:	[size_t] The thread index
*/
QSC_EXPORT_API void qsc_threadpool_remove_task(qsc_threadpool_state* ctx, size_t index);

QSC_CPLUSPLUS_ENABLED_END

#endif
