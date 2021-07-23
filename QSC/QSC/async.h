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
*
*
* Implementation Details:
* A threading base class.
* Written by John G. Underhill
* Updated on December 30, 2020
* Contact: support@vtdev.com */

#ifndef QSC_ASYNC_H
#define QSC_ASYNC_H

#include "common.h"

/* bogus winbase.h error */
QSC_SYSTEM_CONDITION_IGNORE(5105)

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	define WIN32_LEAN_AND_MEAN
#	include <process.h>
#	include <Windows.h>
	typedef HANDLE qsc_async_mutex;
	typedef uintptr_t qsc_thread;
#elif defined(QSC_SYSTEM_OS_POSIX)
#	include <sys/types.h>
#	include <unistd.h>
#	include <pthread>
	typedef pthread_mutex_t qsc_async_mutex;
#	if !defined(pthread_t)
		typedef int32_t pthread_t;
#	endif
	typedef pthread_t qsc_thread;
#else
#	error "The operating system is not supported!"
#endif

/**
* \brief Create a mutex
*
* \param mtx: The mutex to be created
* \return Returns true on success
*/
QSC_EXPORT_API bool qsc_async_mutex_create(qsc_async_mutex* mtx);

/**
* \brief Destroy a mutex
*
* \param mtx: The mutex to destroy
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_async_mutex_destroy(qsc_async_mutex* mtx);

/**
* \brief Lock a mutex.
* The mutex must be initialized and destroyed.
*
* \param mtx: The mutex to lock
*/
QSC_EXPORT_API void qsc_async_mutex_lock(qsc_async_mutex* mtx);

/**
* \brief Initializes and locks a mutex.
*
* \param mtx: The mutex to lock
*/
QSC_EXPORT_API void qsc_async_mutex_lock_ex(qsc_async_mutex* mtx);

/**
* \brief Unlock a mutex.
* The mutex must be initialized and destroyed.
*
* \param mtx: The mutex to unlock
*/
QSC_EXPORT_API void qsc_async_mutex_unlock(qsc_async_mutex* mtx);

/**
* \brief Unlocks and destroys a mutex.
* The mutex must be initialized and destroyed.
*
* \param mtx: The mutex to unlock
*/
QSC_EXPORT_API void qsc_async_mutex_unlock_ex(qsc_async_mutex* mtx);

/**
* \brief Initialize a thread with one parameter
*
* \param thd_func: The thread function
* \param state: The function state
* \return Returns a thread, or zero on failure
*/
QSC_EXPORT_API qsc_thread qsc_async_thread_initialize(void (*thd_func)(void*), void* state);

/**
* \brief Terminate a thread
*
* \param handle: The thread to terminate (terminates calling thread on windows)
*/
QSC_EXPORT_API void qsc_async_thread_terminate(const qsc_thread* handle);

/**
* \brief Wait for a thread to complete execution
*
* \param handle: The thread handle
*/
QSC_EXPORT_API void qsc_async_thread_wait(qsc_thread* handle);

/**
* \brief Pause the thread for a number of milliseconds
*
* \param msec: The number of milliseconds to wait
*/
QSC_EXPORT_API void qsc_async_thread_sleep(uint32_t msec);

/**
* \brief Wait for an array of threads to complete execution
*
* \param handles: The array of threads
* \param count: The number of threads
*/
QSC_EXPORT_API void qsc_async_thread_wait_all(qsc_thread* handles, int32_t count);

#endif
