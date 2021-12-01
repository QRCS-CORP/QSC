/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
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
