/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
*/

#ifndef QSC_THREADPOOL_H
#define QSC_THREADPOOL_H

#include "common.h"
#include "async.h"

/**
* \file threadpool.h
* \brief An asynchronous thread pool
*/

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

/*!
* \def QSC_THREADPOOL_THREADS_MAX
* \brief The thread pool maximum threads
*/
#define QSC_THREADPOOL_THREADS_MAX 1024

/*!
* \struct qsc_threadpool_state
* \brief The thread pool state
*/
typedef struct qsc_threadpool_state
{
	qsc_thread tpool[QSC_THREADPOOL_THREADS_MAX];	/*!< The thread pool */
	size_t tcount;									/*!< The thread count */
} qsc_threadpool_state;

#if defined(QSC_SYSTEM_OS_WINDOWS)
/**
* \brief Add a task to the thread-pool
*
* \param ctx: The thread pool state
* \param func: A pointer to the thread function
* \param state: The thread state
*/
QSC_EXPORT_API bool qsc_threadpool_add_task(qsc_threadpool_state* ctx, void (*func)(void*), void* state);

/**
* \brief Clear all tasks from the thread-pool
*
* \param ctx: The thread pool state
*/
QSC_EXPORT_API void qsc_threadpool_clear(qsc_threadpool_state* ctx);

/**
* \brief Initialize the thread-pool
*
* \param ctx: The thread pool state
*/
QSC_EXPORT_API void qsc_threadpool_initialize(qsc_threadpool_state* ctx);

/**
* \brief Sort the threads in the pool, placing active threads at the start of the array
*
* \param ctx: The thread pool state
*/
QSC_EXPORT_API void qsc_threadpool_sort(qsc_threadpool_state* ctx);

/**
* \brief Check if a thread is active
*
* \param ctx: The thread pool state
* \param index: The thread index
* \return Returns true if the thread is currently used
*/
QSC_EXPORT_API bool qsc_threadpool_thread_active(const qsc_threadpool_state* ctx, size_t index);

/**
* \brief Remove a task from the thread-pool
*
* \param ctx: The thread pool state
* \param index: The thread index
*/
QSC_EXPORT_API void qsc_threadpool_remove_task(qsc_threadpool_state* ctx, size_t index);

#endif
#endif
