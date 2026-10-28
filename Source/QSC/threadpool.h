/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_THREADPOOL_H
#define QSC_THREADPOOL_H

#include "qsccommon.h"
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
 * qsc_threadpool_destroy(&pool);
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
	volatile int32_t tcount;						/*!< The thread count */
} qsc_threadpool_state;

/**
* \brief Add a task to the thread-pool
*
* \param ctx: [qsc_threadpool_state*] The thread pool state
* \param func: [(*func)(void*)] A pointer to the thread function
* \param state:	[void*] The thread state
*/
QSC_EXPORT_API bool qsc_threadpool_add_task(qsc_threadpool_state* ctx, void (*func)(void*), void* state);

/**
* \brief Clear all tasks from the thread-pool and dispose of the state
*
* \param ctx: [qsc_threadpool_state*] The thread pool state
*/
QSC_EXPORT_API void qsc_threadpool_destroy(qsc_threadpool_state* ctx);

/**
* \brief Initialize the thread-pool
*
* \param ctx: [qsc_threadpool_state*] The thread pool state
*/
QSC_EXPORT_API void qsc_threadpool_initialize(qsc_threadpool_state* ctx);

/**
* \brief Sort the threads in the pool, placing active threads at the start of the array
*
* \param ctx: [qsc_threadpool_state*] The thread pool state
*/
QSC_EXPORT_API void qsc_threadpool_sort(qsc_threadpool_state* ctx);

/**
* \brief Check if a thread is active
*
* \param ctx: [const qsc_threadpool_state*] The thread pool state
* \param index:	[size_t] The thread index
* 
* \return [bool] Returns true if the thread is currently used
*/
QSC_EXPORT_API bool qsc_threadpool_thread_active(const qsc_threadpool_state* ctx, size_t index);

/**
* \brief Remove a task from the thread-pool
*
* \param ctx: [qsc_threadpool_state*] The thread pool state
* \param index:	[size_t] The thread index
*/
QSC_EXPORT_API void qsc_threadpool_remove_task(qsc_threadpool_state* ctx, size_t index);

/**
 * \brief An opaque, bounded, persistent-worker thread pool.
 * \details Private storage and synchronization; no changes to qsc_threadpool_state.
 * Callers own task arguments and must keep them valid until the task completes.
 * Calls to wait or destroy from a task executing in this pool are not supported.
 * Concurrent submit/wait is supported; callers must synchronize destroy with
 * external submit/wait operations. A callback must not terminate its own thread.
 * \note Thread-safe for task submissions and waiting; non-reentrant destruction.
 */
typedef struct qsc_threadpool_worker_state qsc_threadpool_worker_state;

/**
 * \brief Create a bounded pool of reusable worker threads.
 * \param worker_count: Number of workers, in [1, QSC_THREADPOOL_THREADS_MAX].
 * \param queue_capacity: Maximum number of waiting tasks; must be nonzero.
 * \return An owned pool pointer, or NULL for invalid sizes/allocation/thread failure.
 * \note No task argument ownership is transferred. Destroy the pool to release resources.
 */
QSC_EXPORT_API qsc_threadpool_worker_state* qsc_threadpool_worker_create(size_t worker_count, size_t queue_capacity);

/**
 * \brief Submit a task without blocking when the bounded queue is full.
 * \param pool: Valid initialized pool.
 * \param func: Non-NULL task callback; invoked by a worker outside pool locks.
 * \param state: Caller-owned callback argument; must remain valid through execution.
 * \return True if accepted, false for invalid arguments, full queue, or shutdown.
 * \note Thread-safe across independent and concurrent producers.
 */
QSC_EXPORT_API bool qsc_threadpool_worker_submit(qsc_threadpool_worker_state* pool, void (*func)(void*), void* state);

/**
 * \brief Wait until all previously accepted tasks and currently queued tasks finish.
 * \param pool: Valid pool, or NULL (no operation).
 * \note Concurrent submissions can extend the wait. Do not call from a pool callback.
 */
QSC_EXPORT_API void qsc_threadpool_worker_wait(qsc_threadpool_worker_state* pool);

/**
 * \brief Stop accepting new work, execute all accepted tasks, join workers, and free pool.
 * \param pool: Pool to release, or NULL (no operation). Invalid after return.
 * \note Not safe concurrently with callers using the same pool; not callable from a worker.
 */
QSC_EXPORT_API void qsc_threadpool_worker_destroy(qsc_threadpool_worker_state* pool);

QSC_CPLUSPLUS_ENABLED_END

#endif
