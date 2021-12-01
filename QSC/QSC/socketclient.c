#include "socketclient.h"
#include "memutils.h"
#include "async.h"
#include "netutils.h"

qsc_socket_address_families qsc_socket_client_address_family(const qsc_socket* sock)
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

qsc_socket_protocols qsc_socket_client_socket_protocol(const qsc_socket* sock)
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

qsc_socket_transports qsc_socket_client_socket_transport(const qsc_socket* sock)
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

qsc_socket_exceptions qsc_socket_client_connect_host(qsc_socket* sock, const char* host, const char* service)
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

size_t qsc_socket_client_receive(const qsc_socket* sock, char* output, size_t outlen, qsc_socket_receive_flags flag)
{
	assert(sock != NULL);
	assert(output != NULL);

	size_t res;

	res = 0;

	if (sock != NULL && output != NULL)
	{
		res = qsc_socket_receive(sock, (uint8_t*)output, outlen, flag);
	}

	return res;
}

size_t qsc_socket_client_receive_from(qsc_socket* sock, char* address, uint16_t port, char* output, size_t outlen, qsc_socket_receive_flags flag)
{
	assert(sock != NULL);
	assert(address != NULL);
	assert(output != NULL);

	size_t res;

	res = 0;

	if (sock != NULL && output != NULL)
	{
		res = qsc_socket_receive_from(sock, address, port, (uint8_t*)output, outlen, flag);
	}

	return res;
}

size_t qsc_socket_client_send(const qsc_socket* sock, const char* input, size_t inlen, qsc_socket_send_flags flag)
{
	assert(sock != NULL);

	size_t res;

	res = 0;

	if (sock != NULL)
	{
		res = qsc_socket_send(sock, (const uint8_t*)input, inlen, flag);
	}

	return res;
}

size_t qsc_socket_client_send_to(const qsc_socket* sock, const char* address, uint16_t port, const char* input, size_t inlen, qsc_socket_send_flags flag)
{
	assert(sock != NULL);
	assert(address != NULL);
	assert(input != NULL);

	size_t res;

	res = 0;

	if (sock != NULL && address != NULL && input != NULL)
	{
		res = qsc_socket_send_to(sock, address, strlen(address), port, (const uint8_t*)input, inlen, flag);
	}

	return res;
}

void qsc_socket_client_shut_down(qsc_socket* sock)
{
	assert(sock != NULL);

	if (sock != NULL && sock->connection_status == qsc_socket_state_connected)
	{
		qsc_socket_shut_down(sock, qsc_socket_shut_down_flag_both);
	}
}
