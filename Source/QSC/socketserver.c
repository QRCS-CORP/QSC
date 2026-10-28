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

#include "socketserver.h"
#include "async.h"
#include "ipinfo.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#   if !defined(NOMINMAX)
#       define NOMINMAX
#   endif
#   include <windows.h>
#endif


qsc_socket_address_families qsc_socket_server_address_family(const qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_address_families res;

	res = qsc_socket_address_family_none;

	if (sock != NULL)
	{
		res = sock->address_family;
	}

	return res;
}

qsc_socket_protocols qsc_socket_server_socket_protocol(const qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_protocols res;

	res = qsc_socket_protocol_none;

	if (sock != NULL)
	{
		res = sock->socket_protocol;
	}

	return res;
}

qsc_socket_transports qsc_socket_server_socket_transport(const qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_transports res;

	res = qsc_socket_transport_none;

	if (sock != NULL)
	{
		res = sock->socket_transport;
	}

	return res;
}

void qsc_socket_server_close_socket(qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	if (sock != NULL)
	{
		/* Listening sockets must also be closed to interrupt accept(). */
		qsc_socket_server_shut_down(sock);
	}
}

void qsc_socket_server_initialize(qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	if (sock != NULL)
	{
		(void)qsc_socket_start_sockets();
		sock->connection = QSC_UNINITIALIZED_SOCKET;
		qsc_memutils_clear(sock->address, sizeof(sock->address));
		sock->instance = 0U;
		sock->port = 0U;
		sock->address_family = qsc_socket_address_family_none;
		sock->connection_status = qsc_socket_state_none;
		sock->socket_protocol = qsc_socket_protocol_none;
		sock->socket_transport = qsc_socket_transport_none;
	}
}

qsc_socket_exceptions qsc_socket_server_listen(qsc_socket* source, qsc_socket* target, const char* address, uint16_t port, qsc_socket_address_families family)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(target != NULL);
	QSC_ASSERT(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL && address != NULL)
	{
		if (family == qsc_socket_address_family_ipv4)
		{
			qsc_ipinfo_ipv4_address addt;
			addt = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_socket_ipv4_valid_address(address))
			{
				res = qsc_socket_server_listen_ipv4(source, target, &addt, port);
			}
		}
		else if (family == qsc_socket_address_family_ipv6)
		{
			qsc_ipinfo_ipv6_address addt;
			addt = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_socket_ipv6_valid_address(address))
			{
				res = qsc_socket_server_listen_ipv6(source, target, &addt, port);
			}
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_server_listen_ipv4(qsc_socket* source, qsc_socket* target, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(target != NULL);
	QSC_ASSERT(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL && address != NULL)
	{
		res = qsc_socket_create(source, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (res == qsc_socket_exception_success)
		{
			qsc_socket_set_option(source, qsc_socket_protocol_socket, qsc_socket_option_reuse_address, 1);

			res = qsc_socket_bind_ipv4(source, address, port);

			if (res == qsc_socket_exception_success)
			{
				res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (res == qsc_socket_exception_success)
				{
					res = qsc_socket_accept(source, target);
				}
			}
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_server_listen_ipv6(qsc_socket* source, qsc_socket* target, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(target != NULL);
	QSC_ASSERT(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL && address != NULL)
	{
		res = qsc_socket_create(source, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);
		if (res == qsc_socket_exception_success)
		{
#if defined(QSC_SOCKET_DUAL_IPV6_STACK)
			int32_t code;
			code = 0;
			qsc_socket_set_option(source, qsc_socket_protocol_ipv6, qsc_socket_option_ipv6_only, code);
#endif
			qsc_socket_set_option(source, qsc_socket_protocol_socket, qsc_socket_option_reuse_address, 1);

			res = qsc_socket_bind_ipv6(source, address, port);

			if (res == qsc_socket_exception_success)
			{
				res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (res == qsc_socket_exception_success)
				{
					res = qsc_socket_accept(source, target);
				}
			}
		}
	}

	return res;
}

/**
 * \brief Private lifecycle record for an asynchronous listener.
 * \note All registry changes use the global metadata gate. A record stays
 * allocated until the accept worker exits, including self-disposal.
 */
typedef struct qsc_socket_server_listener_record
{
	qsc_socket_server_async_accept_state* state; /*!< Borrowed public state; valid until disposal. */
	qsc_socket* source; /*!< Borrowed listener socket; valid until disposal. */
	qsc_socket accept_source; /*!< Private metadata snapshot prevents concurrent close data races. */
	void (*callback)(qsc_socket_server_accept_result* result); /*!< Accepted-connection callback. */
	void (*error)(qsc_socket* sock, qsc_socket_exceptions exception); /*!< Listener error callback. */
	qsc_thread worker; /*!< Joinable accept worker until disposed. */
	volatile int32_t armed; /*!< Set after the native worker handle is installed. */
	volatile int32_t stopping; /*!< Stop requested; suppress callback dispatch when observed. */
	volatile int32_t disposing; /*!< A different thread is joining the worker. */
	volatile int32_t self_disposed; /*!< Worker must release its record on exit. */
	struct qsc_socket_server_listener_record* next; /*!< Next registered listener. */
} qsc_socket_server_listener_record;

/* Registry access is intentionally limited to lifecycle operations. */
static volatile int32_t qsc_socket_server_registry_gate = 0;
static qsc_socket_server_listener_record* qsc_socket_server_registry_head = NULL;

/** \brief Acquire the short-lived listener registry gate. */
static void qsc_socket_server_registry_lock(void)
{
	while (qsc_async_atomic_int32_compare_exchange(&qsc_socket_server_registry_gate, 0, 1) == false)
	{
		qsc_async_thread_sleep(1U);
	}
}

/** \brief Release the listener registry gate. */
static void qsc_socket_server_registry_unlock(void)
{
	qsc_async_atomic_int32_store(&qsc_socket_server_registry_gate, 0);
}

/**
 * \brief Find a listener record with the registry gate held.
 * \param state: Public listener state address.
 * \return Registered record or NULL. No ownership transferred.
 */
static qsc_socket_server_listener_record* qsc_socket_server_registry_find(const qsc_socket_server_async_accept_state* state)
{
	qsc_socket_server_listener_record* current;
	qsc_socket_server_listener_record* result;

	result = NULL;

	for (current = qsc_socket_server_registry_head; current != NULL; current = current->next)
	{
		if (current->state == state)
		{
			result = current;
			break;
		}
	}

	return result;
}

/**
 * \brief Unregister a lifecycle record; caller holds registry gate.
 * \param entry: Previously registered record, still owned by its disposer.
 */
static void qsc_socket_server_registry_remove(qsc_socket_server_listener_record* entry)
{
	qsc_socket_server_listener_record** link;

	link = &qsc_socket_server_registry_head;

	while (*link != NULL)
	{
		if (*link == entry)
		{
			*link = entry->next;
			break;
		}

		link = &(*link)->next;
	}
}

/**
 * \brief Close an accepted or listening socket, regardless of its state flag.
 * \param sock: Initialized socket, or NULL for no operation.
 * \note This helper must not acquire the registry gate.
 */
static void qsc_socket_server_close_native(qsc_socket* sock)
{
	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
		(void)qsc_socket_shut_down(sock, qsc_socket_shut_down_flag_both);
		(void)qsc_socket_close_socket(sock);
	}
}

/**
 * \brief Determine whether disposal was called on the listener worker.
 * \param entry: Initialized private listener record.
 * \return True when the current thread is the accept worker.
 */
static bool qsc_socket_server_is_worker(const qsc_socket_server_listener_record* entry)
{
	bool res;

	res = false;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (GetCurrentThreadId() == GetThreadId((HANDLE)entry->worker));
#elif defined(QSC_SYSTEM_OS_POSIX)
	res = (pthread_equal(pthread_self(), entry->worker) != 0);
#endif

	return res;
}

/**
 * \brief Accept connections sequentially without holding application locks.
 * \param vstate: Private listener record, valid for the worker lifetime.
 * \note Accepted sockets are owned by callbacks; absent callbacks cause closure.
 */
static void qsc_socket_server_accept_worker(void* vstate)
{
	qsc_socket_server_listener_record* entry;
	qsc_socket_server_accept_result ar;
	qsc_socket_exceptions res;
	bool done;
	struct timeval timeout;

	entry = (qsc_socket_server_listener_record*)vstate;
	done = false;

	while (qsc_async_atomic_int32_load(&entry->armed) == 0)
	{
		qsc_async_thread_sleep(1U);
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = 50000;

	while (done == false && qsc_async_atomic_int32_load(&entry->stopping) == 0)
	{
		if (qsc_socket_receive_ready(&entry->accept_source, &timeout) == false)
		{
			continue;
		}

		if (qsc_async_atomic_int32_load(&entry->stopping) != 0)
		{
			break;
		}

		qsc_memutils_clear(&ar, sizeof(ar));
		ar.target.connection = QSC_UNINITIALIZED_SOCKET;
		res = qsc_socket_accept(&entry->accept_source, &ar.target);

		if (res == qsc_socket_exception_success)
		{
			/* Winsock can propagate the nonblocking listening mode to clients. */
			res = qsc_socket_set_blocking(&ar.target, true);

			if (res != qsc_socket_exception_success)
			{
				qsc_socket_server_close_native(&ar.target);

				if (qsc_async_atomic_int32_load(&entry->stopping) == 0 && entry->error != NULL)
				{
					entry->error(entry->source, res);
				}
			}
			else if (qsc_async_atomic_int32_load(&entry->stopping) == 0)
			{
				if (entry->callback != NULL)
				{
					entry->callback(&ar);
				}
				else
				{
					qsc_socket_server_close_native(&ar.target);
				}
			}
			else
			{
				qsc_socket_server_close_native(&ar.target);
			}
		}
		else if (qsc_async_atomic_int32_load(&entry->stopping) == 0)
		{
			if (res != qsc_socket_exception_blocking_cancelled && res != qsc_socket_exception_would_block)
			{
				if (entry->error != NULL)
				{
					entry->error(entry->source, res);
				}

				done = true;
			}
			else if (res == qsc_socket_exception_would_block)
			{
				/* Prevent a fast retry loop if callers changed the socket mode. */
				qsc_async_thread_sleep(1U);
			}
		}
	}

	qsc_socket_server_registry_lock();

	if (qsc_async_atomic_int32_load(&entry->self_disposed) != 0)
	{
		qsc_socket_server_registry_unlock();
		qsc_memutils_alloc_free(entry);
	}
	else
	{
		/* Disposal retains ownership of public state until the join finishes. */
		qsc_async_atomic_int32_store(&entry->state->tcount, 0);
		qsc_socket_server_registry_unlock();
	}
}

/**
 * \brief Prepare an isolated private record for a newly started listener.
 * \param state: Caller-owned listener state, initialized with source/callbacks.
 * \return New record or NULL when already active or allocation fails.
 * \note Caller must hold the registry gate throughout listener startup.
 */
static qsc_socket_server_listener_record* qsc_socket_server_record_create(qsc_socket_server_async_accept_state* state)
{
	qsc_socket_server_listener_record* entry;

	entry = NULL;

	if (qsc_socket_server_registry_find(state) == NULL)
	{
		entry = (qsc_socket_server_listener_record*)qsc_memutils_malloc(sizeof(qsc_socket_server_listener_record));

		if (entry != NULL)
		{
			qsc_memutils_clear(entry, sizeof(qsc_socket_server_listener_record));
			entry->state = state;
			entry->source = state->source;
			entry->callback = state->callback;
			entry->error = state->error;
			entry->next = qsc_socket_server_registry_head;
			qsc_socket_server_registry_head = entry;
		}
	}

	return entry;
}

/**
 * \brief Start a joinable accept worker for an already listening socket.
 * \param entry: Registered listener record.
 * \return Socket-style success or error status.
 */
static qsc_socket_exceptions qsc_socket_server_worker_start(qsc_socket_server_listener_record* entry)
{
	qsc_socket_exceptions res;

	res = qsc_socket_exception_error;
	entry->worker = qsc_async_thread_create(&qsc_socket_server_accept_worker, entry);

	if (entry->worker != (qsc_thread)0)
	{
		qsc_async_atomic_int32_store(&entry->state->tcount, 1);
		qsc_async_atomic_int32_store(&entry->armed, 1);
		res = qsc_socket_exception_success;
	}

	return res;
}

/**
 * \brief Bind and launch one listener using the requested address family.
 * \param state: Caller-owned asynchronous state.
 * \param address: Typed IPv4 or IPv6 address.
 * \param port: TCP listen port, including zero for an ephemeral port.
 * \param family: Required network address family.
 * \return Socket exception code; failed starts release all resources.
 */
static qsc_socket_exceptions qsc_socket_server_async_start(qsc_socket_server_async_accept_state* state, const void* address, uint16_t port, qsc_socket_address_families family)
{
	qsc_socket_server_listener_record* entry;
	qsc_socket_exceptions res;
	qsc_mutex mtx;

	res = qsc_socket_invalid_input;

	if (state != NULL && state->source != NULL && address != NULL &&
		(family == qsc_socket_address_family_ipv4 || family == qsc_socket_address_family_ipv6))
	{
		/* Keep startup and disposal mutually exclusive until the worker is armed. */
		qsc_socket_server_registry_lock();
		entry = qsc_socket_server_record_create(state);

		if (entry != NULL)
		{
			mtx = qsc_async_mutex_create();

			if (mtx != NULL)
			{
				state->smutex = mtx;
				state->tcount = 0;
				(void)qsc_socket_start_sockets();
				res = qsc_socket_create(state->source, family, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

				if (res == qsc_socket_exception_success)
				{
#if defined(QSC_SOCKET_DUAL_IPV6_STACK)
					if (family == qsc_socket_address_family_ipv6)
					{
						(void)qsc_socket_set_option(state->source, qsc_socket_protocol_ipv6, qsc_socket_option_ipv6_only, 0);
					}
#endif
					(void)qsc_socket_set_option(state->source, qsc_socket_protocol_socket, qsc_socket_option_reuse_address, 1);

					if (family == qsc_socket_address_family_ipv4)
					{
						res = qsc_socket_bind_ipv4(state->source, (const qsc_ipinfo_ipv4_address*)address, port);
					}
					else
					{
						res = qsc_socket_bind_ipv6(state->source, (const qsc_ipinfo_ipv6_address*)address, port);
					}

					if (res == qsc_socket_exception_success)
					{
						res = qsc_socket_listen(state->source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);
					}

					if (res == qsc_socket_exception_success)
					{
						state->source->connection_status = qsc_socket_state_listening;
						res = qsc_socket_set_blocking(state->source, false);

						if (res == qsc_socket_exception_success)
						{
							qsc_memutils_copy(&entry->accept_source, state->source, sizeof(qsc_socket));
							res = qsc_socket_server_worker_start(entry);
						}
					}
				}
			}
			else
			{
				res = qsc_socket_exception_error;
			}

			if (res != qsc_socket_exception_success)
			{
				qsc_socket_server_close_native(state->source);
				qsc_socket_server_registry_remove(entry);
				state->tcount = 0;
				state->smutex = NULL;
				(void)qsc_async_mutex_destroy(mtx);
				qsc_memutils_alloc_free(entry);
			}
		}
		else
		{
			res = qsc_socket_exception_error;
		}

		qsc_socket_server_registry_unlock();
	}

	return res;
}

/**
 * \brief Request that an asynchronous listener stop accepting connections.
 * \param state: Previously started asynchronous listener state.
 * \return True if an active listener was found and shutdown requested.
 * \note Safe from an accept callback. Call dispose to reclaim resources.
 */
bool qsc_socket_server_async_stop(qsc_socket_server_async_accept_state* state)
{
	qsc_socket_server_listener_record* entry;
	bool res;

	res = false;

	if (state != NULL)
	{
		qsc_socket_server_registry_lock();
		entry = qsc_socket_server_registry_find(state);

		if (entry != NULL)
		{
			qsc_async_atomic_int32_store(&entry->stopping, 1);
			qsc_socket_server_close_native(entry->source);
			res = true;
		}

		qsc_socket_server_registry_unlock();
	}

	return res;
}

void qsc_socket_server_async_dispose(qsc_socket_server_async_accept_state* state)
{
	qsc_socket_server_listener_record* entry;
	qsc_mutex mtx;
	bool self;

	if (state != NULL)
	{
		qsc_socket_server_registry_lock();
		entry = qsc_socket_server_registry_find(state);

		if (entry != NULL && qsc_async_atomic_int32_load(&entry->disposing) == 0)
		{
			qsc_async_atomic_int32_store(&entry->disposing, 1);
			qsc_async_atomic_int32_store(&entry->stopping, 1);
			qsc_socket_server_close_native(entry->source);
			self = qsc_socket_server_is_worker(entry);

			if (self == true)
			{
				qsc_async_atomic_int32_store(&entry->self_disposed, 1);
				qsc_socket_server_registry_remove(entry);
				mtx = state->smutex;
				state->smutex = NULL;
				state->tcount = 0;
				state->callback = NULL;
				state->error = NULL;
#if defined(QSC_SYSTEM_OS_WINDOWS)
				(void)CloseHandle((HANDLE)entry->worker);
#else
				(void)pthread_detach(entry->worker);
#endif
				qsc_socket_server_registry_unlock();
				(void)qsc_async_mutex_destroy(mtx);
			}
			else
			{
				qsc_socket_server_registry_unlock();
				qsc_async_thread_wait(entry->worker);
				qsc_socket_server_registry_lock();
				qsc_socket_server_registry_remove(entry);
				mtx = state->smutex;
				state->smutex = NULL;
				state->tcount = 0;
				state->callback = NULL;
				state->error = NULL;
				qsc_socket_server_registry_unlock();
				(void)qsc_async_mutex_destroy(mtx);
				qsc_memutils_alloc_free(entry);
			}
		}
		else
		{
			qsc_socket_server_registry_unlock();
		}
	}
}

qsc_socket_exceptions qsc_socket_server_listen_async(qsc_socket_server_async_accept_state* state, const char* address, uint16_t port, qsc_socket_address_families family)
{
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (state != NULL && address != NULL)
	{
		if (family == qsc_socket_address_family_ipv4)
		{
			qsc_ipinfo_ipv4_address addt;
			addt = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_socket_ipv4_valid_address(address))
			{
				res = qsc_socket_server_listen_async_ipv4(state, &addt, port);
			}
		}
		else if (family == qsc_socket_address_family_ipv6)
		{
			qsc_ipinfo_ipv6_address addt;
			addt = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_socket_ipv6_valid_address(address))
			{
				res = qsc_socket_server_listen_async_ipv6(state, &addt, port);
			}
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_server_listen_async_ipv4(qsc_socket_server_async_accept_state* state, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	return qsc_socket_server_async_start(state, address, port, qsc_socket_address_family_ipv4);
}

qsc_socket_exceptions qsc_socket_server_listen_async_ipv6(qsc_socket_server_async_accept_state* state, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	return qsc_socket_server_async_start(state, address, port, qsc_socket_address_family_ipv6);
}

void qsc_socket_server_set_options(const qsc_socket* sock, qsc_socket_protocols level, qsc_socket_options option, int32_t optval)
{
	QSC_ASSERT(sock != NULL);

	if (sock != NULL)
	{
		qsc_socket_set_option(sock, level, option, optval);
	}
}

void qsc_socket_server_shut_down(qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	if (sock != NULL)
	{
		qsc_socket_server_listener_record* current;

		qsc_socket_server_registry_lock();

		for (current = qsc_socket_server_registry_head; current != NULL; current = current->next)
		{
			if (current->source == sock)
			{
				qsc_async_atomic_int32_store(&current->stopping, 1);
			}
		}

		qsc_socket_server_close_native(sock);
		qsc_socket_server_registry_unlock();
	}
}
