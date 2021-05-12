#include "socketclient.h"
#include "async.h"
#include "memutils.h"
#include "netutils.h"

qsc_socket_address_families qsc_socket_client_address_family(qsc_socket* sock)
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

qsc_socket_protocols qsc_socket_client_socket_protocol(qsc_socket* sock)
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

qsc_socket_transports qsc_socket_client_socket_transport(qsc_socket* sock)
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

qsc_socket_exceptions qsc_socket_client_connect_host(qsc_socket* sock, const char* host, char* service)
{
	assert(sock != NULL);
	assert(host != NULL);
	assert(service != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && host != NULL && service != NULL)
	{
		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			qsc_ipinfo_ipv4_info info = qsc_netutils_get_ipv4_info(host, service);
			res = qsc_socket_client_connect_ipv4(sock, &info.address, info.port);

			if (res == qsc_socket_exception_success)
			{
				sock->connection_status = qsc_socket_state_connected;
			}
		}
		else
		{
			qsc_ipinfo_ipv6_info info = qsc_netutils_get_ipv6_info(host, service);
			res = qsc_socket_client_connect_ipv6(sock, &info.address, info.port);

			if (res == qsc_socket_exception_success)
			{
				sock->connection_status = qsc_socket_state_connected;
			}
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_client_connect_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	assert(sock != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		res = qsc_socket_create(sock, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_connect_ipv4(sock, address, port);
		}

		if (res == qsc_socket_exception_success)
		{
			sock->connection_status = qsc_socket_state_connected;
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_client_connect_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	assert(sock != NULL);
	assert(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		res = qsc_socket_create(sock, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_connect_ipv6(sock, address, port);
		}

		if (res == qsc_socket_exception_success)
		{
			sock->connection_status = qsc_socket_state_connected;
		}
	}

	return res;
}

void qsc_socket_client_initialize(qsc_socket* sock)
{
	assert(sock != NULL);

	if (sock != NULL)
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
}
//
//static void qsc_socket_client_receive_async_invoke(qsc_socket_client_async_receive_state* state)
//{
//	qsc_async_mutex mtx;
//
//	qsc_async_mutex_lock_ex(&mtx);
//
//	if (state != NULL)
//	{
//		while (state->source->connection_status == qsc_socket_state_connected)
//		{
//			int32_t mlen;
//			mlen = 0;
//			mlen = qsc_socket_receive(state->source, state->buffer, state->buflen, qsc_socket_receive_flag_none);
//
//			if (mlen > 0)
//			{
//				state->callback(state->source, state->buffer, (size_t)mlen);
//			}
//			else if (mlen == qsc_socket_exception_error)
//			{
//				qsc_socket_exceptions ex;
//
//				ex = qsc_socket_get_last_error();
//				state->error(state->source, ex);
//			}
//		}
//	}
//
//	qsc_async_mutex_unlock_ex(&mtx);
//}
//
//qsc_socket_exceptions qsc_socket_client_receive_async(qsc_socket_client_async_receive_state* state)
//{
//	assert(state != NULL);
//	assert(state->source != NULL);
//
//	qsc_socket_exceptions res;
//
//	res = qsc_socket_invalid_input;
//
//	if (state != NULL && state->source != NULL)
//	{
//		qsc_async_thread_initialize(qsc_socket_client_receive_async_invoke, state);
//	}
//
//	return res;
//}

size_t qsc_socket_client_receive(qsc_socket* sock, char* output, size_t outlen, qsc_socket_receive_flags flag)
{
	assert(sock != NULL);
	assert(output != NULL);

	size_t res;

	res = 0;

	if (sock != NULL && output != NULL)
	{
		res = qsc_socket_receive(sock, output, outlen, flag);
	}

	return res;
}

size_t qsc_socket_client_receive_from(qsc_socket* sock, const char* address, uint16_t port, char* output, size_t outlen, qsc_socket_receive_flags flag)
{
	assert(sock != NULL);
	assert(address != NULL);
	assert(output != NULL);

	size_t res;

	res = 0;

	if (sock != NULL && output != NULL)
	{
		res = qsc_socket_receive_from(sock, address, port, output, outlen, flag);
	}

	return res;
}

size_t qsc_socket_client_send(qsc_socket* sock, const char* input, size_t inlen, qsc_socket_send_flags flag)
{
	assert(sock != NULL);

	size_t res;

	res = 0;

	if (sock != NULL)
	{
		res = qsc_socket_send(sock, input, inlen, flag);
	}

	return res;
}

size_t qsc_socket_client_send_to(qsc_socket* sock, const char* address, uint16_t port, const char* input, size_t inlen, qsc_socket_send_flags flag)
{
	assert(sock != NULL);
	assert(address != NULL);
	assert(input != NULL);

	size_t res;

	res = 0;

	if (sock != NULL && address != NULL && input != NULL)
	{
		res = qsc_socket_send_to(sock, address, strlen(address), port, input, inlen, flag);
	}

	return res;
}

void qsc_socket_client_shut_down(qsc_socket* sock)
{
	assert(sock != NULL);

	if (sock != NULL)
	{
		if (sock->connection_status == qsc_socket_state_connected)
		{
			qsc_socket_shut_down(sock, qsc_socket_shut_down_flag_both);
		}
	}
}


