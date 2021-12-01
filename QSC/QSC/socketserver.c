#include "socketserver.h"
#include "async.h"
#include "ipinfo.h"
#include "memutils.h"

qsc_socket_address_families qsc_socket_server_address_family(const qsc_socket* sock)
{
	assert(sock != NULL);

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
	assert(sock != NULL);

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
	assert(sock != NULL);

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
	assert(sock != NULL);

	if (sock != NULL && sock->connection_status == qsc_socket_state_connected)
	{
		qsc_socket_shut_down(sock, qsc_socket_shut_down_flag_both);
	}
}

void qsc_socket_server_initialize(qsc_socket* sock)
{
	qsc_socket_start_sockets();

	sock->connection = QSC_UNINITIALIZED_SOCKET;
	qsc_memutils_clear((char*)sock->address, sizeof(sock->address));
	sock->instance = 0;
	sock->port = 0;
	sock->address_family = qsc_socket_address_family_none;
	sock->connection_status = qsc_socket_state_none;
	sock->socket_protocol = qsc_socket_protocol_none;
	sock->socket_transport = qsc_socket_transport_none;
}

qsc_socket_exceptions qsc_socket_server_listen(qsc_socket* source, qsc_socket* target, const char* address, uint16_t port, qsc_socket_address_families family)
{
	assert(source != NULL);
	assert(target != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL && address != NULL)
	{
		if (family == qsc_socket_address_family_ipv4)
		{
			qsc_ipinfo_ipv4_address addt;
			addt = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_ipinfo_ipv4_address_is_valid(&addt))
			{
				res = qsc_socket_server_listen_ipv4(source, target, &addt, port);
			}
		}
		else
		{
			qsc_ipinfo_ipv6_address addt;
			addt = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_ipinfo_ipv6_address_is_valid(&addt))
			{
				res = qsc_socket_server_listen_ipv6(source, target, &addt, port);
			}
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_server_listen_ipv4(qsc_socket* source, qsc_socket* target, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	assert(source != NULL);
	assert(target != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL && address != NULL)
	{
		res = qsc_socket_create(source, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (res == qsc_socket_exception_success)
		{
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
	assert(source != NULL);
	assert(target != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL && address != NULL)
	{
#if defined(QSC_SOCKET_DUAL_IPV6_STACK)
		res = qsc_socket_create(source, qsc_socket_address_family_none, qsc_socket_transport_stream, qsc_socket_protocol_tcp);
#else
		res = qsc_socket_create(source, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);
#endif
		if (res == qsc_socket_exception_success)
		{
#if defined(QSC_SOCKET_DUAL_IPV6_STACK)
			int32_t code;
			code = 0;
			qsc_socket_set_option(source, qsc_socket_protocol_ipv6, qsc_socket_option_ipv6_only, code);
#endif
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

static void qsc_socket_server_accept_invoke(qsc_socket_server_async_accept_state* state)
{
	assert(state != NULL);
#if defined(QSC_SYSTEM_OS_WINDOWS)
	qsc_mutex mtx;

	mtx = qsc_async_mutex_lock_ex();

	if (state != NULL)
	{
		qsc_socket_server_accept_result ar;
		qsc_socket_exceptions res;

		qsc_memutils_clear((char*)&ar, sizeof(qsc_socket_server_accept_result));

		res = qsc_socket_accept(state->source, &ar.target);

		if (res == qsc_socket_exception_success)
		{
			if (state->callback != NULL)
			{
				state->callback(&ar);
				qsc_async_thread_create((void*)&qsc_socket_server_accept_invoke, state);
			}
		}
		else
		{
			if (state->error != NULL)
			{
				res = qsc_socket_get_last_error();
				state->error(state->source, res);
			}
		}
	}

	qsc_async_mutex_unlock_ex(mtx);
	#endif
}

qsc_socket_exceptions qsc_socket_server_listen_async(qsc_socket_server_async_accept_state* state, const char* address, uint16_t port, qsc_socket_address_families family)
{
	assert(state != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (state != NULL && address != NULL)
	{
		if (family == qsc_socket_address_family_ipv4)
		{
			qsc_ipinfo_ipv4_address addt;
			addt = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_ipinfo_ipv4_address_is_valid(&addt))
			{
				res = qsc_socket_server_listen_async_ipv4(state, &addt, port);
			}
		}
		else
		{
			qsc_ipinfo_ipv6_address addt;
			addt = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_ipinfo_ipv6_address_is_valid(&addt))
			{
				res = qsc_socket_server_listen_async_ipv6(state, &addt, port);
			}
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_server_listen_async_ipv4(qsc_socket_server_async_accept_state* state, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	assert(state != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (state != NULL && address != NULL)
	{
		res = qsc_socket_create(state->source, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_bind_ipv4(state->source, address, port);

			if (res == qsc_socket_exception_success)
			{
				res = qsc_socket_listen(state->source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (res == qsc_socket_exception_success)
				{
					state->source->connection_status = qsc_socket_state_listening;
					qsc_async_thread_create((void*)&qsc_socket_server_accept_invoke, state);
				}
			}
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_server_listen_async_ipv6(qsc_socket_server_async_accept_state* state, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	assert(state != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (state != NULL && address != NULL)
	{
#if defined(QSC_SOCKET_DUAL_IPV6_STACK)
		res = qsc_socket_create(state->source, qsc_socket_address_family_none, qsc_socket_transport_stream, qsc_socket_protocol_tcp);
#else
		res = qsc_socket_create(state->source, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);
#endif
		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_bind_ipv6(state->source, address, port);

#if defined(QSC_SOCKET_DUAL_IPV6_STACK)
			int32_t code;
			code = 0;
			qsc_socket_set_option(state->source, qsc_socket_protocol_ipv6, qsc_socket_option_ipv6_only, code);
#endif

			if (res == qsc_socket_exception_success)
			{
				res = qsc_socket_listen(state->source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (res == qsc_socket_exception_success)
				{
					state->source->connection_status = qsc_socket_state_listening;
					qsc_async_thread_create((void*)&qsc_socket_server_accept_invoke, state);
				}
			}
		}
	}

	return res;
}

void qsc_socket_server_set_options(const qsc_socket* sock, qsc_socket_protocols level, qsc_socket_options option, int32_t optval)
{
	assert(sock != NULL);

	if (sock != NULL)
	{
		qsc_socket_set_option(sock, level, option, optval);
	}
}

void qsc_socket_server_shut_down(qsc_socket* sock)
{
	assert(sock != NULL);

	if (sock != NULL)
	{
		qsc_socket_server_close_socket(sock);
	}
}
