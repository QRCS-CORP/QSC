/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Implementation Details:
* A threading base class.
* Written by John G. Underhill
* Updated on December 30, 2020
* Contact: develop@vtdev.com */

/* Example

typedef struct test_data
{
	qsc_threads_mutex* mtx;
	char msg[2];
} test_data;

void test_func(test_data* ctx)
{
	qsc_threads_mutex_lock(ctx->mtx);
	qsc_consoleutils_print_line(ctx->msg);
	qsc_threads_mutex_unlock(ctx->mtx);
}

void test_harness()
{
	qsc_threads_mutex mtxs[8];
	qsc_thread thds[8];
	test_data data[8] = { 0 };
	char msg[8][2] = { 0 };
	int i;

	for (i = 0; i < 8; ++i)
	{
		qsc_stringutils_int_to_string(i, data[i].msg);
		data[i].mtx = &mtxs[i];
		qsc_threads_mutex_create(&mtxs[i]);
		thds[i] = qsc_threads_initialize(test_func, &data[i]);
	}

	qsc_threads_wait_all(thds, 8);

	for (i = 0; i < 8; ++i)
	{
		qsc_threads_mutex_destroy(&mtxs[i]);
	}
}
*/

#ifndef QSC_THREADS_H
#define QSC_THREADS_H

#include "common.h"
#include <omp.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <process.h>
#	include <Windows.h>
#	define qsc_threads_mutex HANDLE
#elif defined(QSC_SYSTEM_OS_POSIX)
#	include <sys/types.h>
#	include <unistd.h>
#	include <pthread>
#	define qsc_threads_mutex pthread_mutex_t
#else
#	error your operating system is not supported!
#endif
#if !defined(pthread_t)
#	define pthread_t int
#endif
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	define qsc_thread int
#else
#	define qsc_thread pthread_t
#endif

/**
* \brief Create a mutex
*
* \param mtx: The mutex to be created
* \return Returns true on success
*/
QSC_EXPORT_API bool qsc_threads_mutex_create(qsc_threads_mutex* mtx);

/**
* \brief Destroy a mutex
*
* \param mtx: The mutex to destroy
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_threads_mutex_destroy(qsc_threads_mutex* mtx);

/**
* \brief Lock a mutex
*
* \param mtx: The mutex to lock
*/
QSC_EXPORT_API void qsc_threads_mutex_lock(qsc_threads_mutex* mtx);

/**
* \brief Unlock a mutex
*
* \param mtx: The mutex to unlock
*/
QSC_EXPORT_API void qsc_threads_mutex_unlock(qsc_threads_mutex* mtx);

/**
* \brief Initialize a thread with one parameter
*
* \param thd_func: The thread function
* \param state: The function state
* \return Returns a thread, or zero on failure
*/
QSC_EXPORT_API qsc_thread qsc_threads_initialize(void (*thd_func)(void*), void* state);

/**
* \brief Initialize a thread with two parameters
*
* \param thd_func: The thread function
* \param args: The function argument list
* \return Returns a thread, or zero on failure
*/
QSC_EXPORT_API qsc_thread qsc_threads_initialize_ex(void (*thd_func)(void**), void** args);

/**
* \brief Terminate a thread
*
* \param handle: The thread to terminate (terminates calling thread on windows)
*/
QSC_EXPORT_API void qsc_threads_terminate(qsc_thread* handle);

/**
* \brief Wait for a thread to complete execution
*
* \param handle: The thread handle
*/
QSC_EXPORT_API void qsc_thread_wait(qsc_thread* handle);

/**
* \brief Wait for an array of threads to complete execution
*
* \param handles: The array of threads
* \param count: The number of threads
*/
QSC_EXPORT_API void qsc_threads_wait_all(qsc_thread* handles, int count);

#endif
