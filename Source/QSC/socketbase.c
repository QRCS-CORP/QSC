#include "socketbase.h"
#include "intutils.h"
#include "memutils.h"
#include "async.h"

#if defined(QSC_SYSTEM_OS_POSIX)
#   include <sys/ioctl.h>
#   include <sys/select.h>
#	if !defined(PSTR)
#   	define PSTR char*
#	endif
#endif

static qsc_socket_exceptions qsc_socket_acceptv4(const qsc_socket* source, qsc_socket* target)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(target != NULL);

	struct sockaddr_in sa;
	socklen_t salen;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL)
	{
		salen = sizeof(sa);
		qsc_memutils_clear(&sa, salen);
		target->connection = QSC_UNINITIALIZED_SOCKET;
		target->connection_status = qsc_socket_state_none;
		qsc_memutils_clear(target->address, sizeof(target->address));
		target->address_family = source->address_family;
		target->socket_protocol = source->socket_protocol;
		target->socket_transport = source->socket_transport;

		target->connection = accept(source->connection, (struct sockaddr*)&sa, &salen);

		if (target->connection != QSC_UNINITIALIZED_SOCKET && target->connection != QSC_SOCKET_RET_ERROR)
		{
			target->connection_status = qsc_socket_state_connected;
			inet_ntop(AF_INET, (const void*)&sa.sin_addr, (PSTR)target->address, INET_ADDRSTRLEN);
			qsc_memutils_copy(target->address, target->address, QSC_IPINFO_IPV4_STRNLEN);
			target->port = ntohs(sa.sin_port);
			res = qsc_socket_exception_success;
		}
		else
		{
			res = qsc_socket_get_last_error();
			qsc_socket_close_socket(target);
		}
	}

	return res;
}

static qsc_socket_exceptions qsc_socket_acceptv6(const qsc_socket* source, qsc_socket* target)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(target != NULL);

	socklen_t salen;
	struct sockaddr_in6 sa;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL)
	{
		salen = sizeof(sa);
		qsc_memutils_clear(&sa, salen);
		target->connection = QSC_UNINITIALIZED_SOCKET;
		target->connection_status = qsc_socket_state_none;
		qsc_memutils_clear(target->address, sizeof(target->address));
		target->address_family = source->address_family;
		target->socket_protocol = source->socket_protocol;
		target->socket_transport = source->socket_transport;
		target->connection = accept(source->connection, (struct sockaddr*)&sa, &salen);

		if (target->connection != QSC_UNINITIALIZED_SOCKET && target->connection != QSC_SOCKET_RET_ERROR)
		{
			target->connection_status = qsc_socket_state_connected;
			inet_ntop(AF_INET6, &sa.sin6_addr, (char*)target->address, INET6_ADDRSTRLEN);
			target->port = ntohs(sa.sin6_port);
			res = qsc_socket_exception_success;
		}
		else
		{
			res = qsc_socket_get_last_error();
			qsc_socket_close_socket(target);
		}
	}

	return res;
}

//~~~Accessors~~~//

bool qsc_socket_ipv4_valid_address(const char* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL && strlen(address) >= QSC_IPINFO_IPV4_STRNLEN)
	{
		qsc_ipinfo_ipv4_address add;

		add = qsc_ipinfo_ipv4_address_from_array((const uint8_t*)address);
		res = qsc_ipinfo_ipv4_address_is_valid(&add);
	}

	return res;
}

bool qsc_socket_ipv6_valid_address(const char* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL && strlen(address) >= QSC_IPINFO_IPV6_STRNLEN)
	{
		qsc_ipinfo_ipv6_address add;

		add = qsc_ipinfo_ipv6_address_from_array((const uint8_t*)address);
		res = qsc_ipinfo_ipv6_address_is_valid(&add);
	}

	return res;
}

bool qsc_socket_is_blocking(const qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	int8_t b[1U] = { 0 };
	int32_t res;

	res = false;

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
		res = (recv(sock->connection, (char*)b, 0, 0) == QSC_SOCKET_RET_SUCCESS);
	}

	return res;
}

bool qsc_socket_is_connected(const qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	socklen_t slen;
	int32_t err;
	int32_t res;

	err = 0;
	res = -1;

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
		slen = sizeof(err);
		res = getsockopt(sock->connection, SOL_SOCKET, SO_ERROR, (char*)&err, &slen);
	}

	return (res == 0 && err == 0);
}

qsc_socket_exceptions qsc_socket_accept(const qsc_socket* source, qsc_socket* target)
{
	QSC_ASSERT(source != NULL);
	QSC_ASSERT(target != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (source != NULL && target != NULL)
	{
		if (source->address_family == qsc_socket_address_family_ipv4)
		{
			res = qsc_socket_acceptv4(source, target);
		}
		else
		{
			res = qsc_socket_acceptv6(source, target);
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

void qsc_socket_attach(qsc_socket* source, qsc_socket* target)
{
	QSC_ASSERT(source != NULL);

	if (source != NULL)
	{
		qsc_memutils_copy((uint8_t*)target, (const uint8_t*)source, sizeof(qsc_socket));
	}
}

qsc_socket_exceptions qsc_socket_bind(qsc_socket* sock, const char* address, uint16_t port)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			qsc_ipinfo_ipv4_address addt = qsc_ipinfo_ipv4_address_from_string(address);
			res = qsc_socket_bind_ipv4(sock, &addt, port);
		}
		else
		{
			qsc_ipinfo_ipv6_address addt = qsc_ipinfo_ipv6_address_from_string(address);
			res = qsc_socket_bind_ipv6(sock, &addt, port);
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_bind_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(address != NULL);

	struct sockaddr_in sa;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		uint32_t ip4u;

		qsc_memutils_clear(&sa, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		ip4u = qsc_intutils_le8to32(address->ipv4);
		sa.sin_addr.s_addr = ip4u;
#if defined(QSC_SYSTEM_OS_APPLE)
		sa.sin_len = sizeof(sa);
#endif

		res = (qsc_socket_exceptions)bind(sock->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != qsc_socket_exception_error)
		{
			if (inet_ntop(AF_INET, address->ipv4, (PSTR)sock->address, sizeof(sock->address)) != NULL)
			{
				sock->address_family = qsc_socket_address_family_ipv4;
				sock->port = port;
			}
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_bind_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(address != NULL);

	struct sockaddr_in6 sa;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		qsc_memutils_clear(&sa, sizeof(sa));
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(port);

#if defined(QSC_SYSTEM_OS_WINDOWS)
		qsc_memutils_copy((uint8_t*)sa.sin6_addr.u.Byte, (const uint8_t*)address->ipv6, 16);
#elif defined(QSC_SYSTEM_OS_LINUX)
		qsc_memutils_copy((uint8_t*)sa.sin6_addr.__in6_u.__u6_addr8, (const uint8_t*)address->ipv6, 16);
#elif defined(QSC_SYSTEM_OS_APPLE)
		qsc_memutils_copy((uint8_t*)sa.sin6_addr.__u6_addr.__u6_addr8, (const uint8_t*)address->ipv6, 16);
		sa.sin6_len = sizeof(sa);
#endif

		res = (qsc_socket_exceptions)bind(sock->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != qsc_socket_exception_error)
		{
			inet_ntop(AF_INET6, address->ipv6, (PSTR)sock->address, sizeof(sock->address));
			sock->port = port;
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

void qsc_socket_clear_socket(qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	if (sock != NULL)
	{
		qsc_memutils_clear(sock->address, QSC_SOCKET_ADDRESS_MAX_SIZE);
		sock->address_family = qsc_socket_address_family_none;
		sock->connection = QSC_UNINITIALIZED_SOCKET;
		sock->connection_status = qsc_socket_state_none;
		sock->instance = 0U;
		sock->port = 0U;
		sock->socket_protocol = qsc_socket_protocol_none;
		sock->socket_transport = qsc_socket_transport_none;
	}
}

qsc_socket_exceptions qsc_socket_close_socket(qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET && sock->connection != qsc_socket_exception_error)
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		res = (qsc_socket_exceptions)closesocket(sock->connection);
#else
		res = (qsc_socket_exceptions)close(sock->connection);
#endif

		sock->connection = QSC_UNINITIALIZED_SOCKET;
		sock->connection_status = qsc_socket_state_none;
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_connect(qsc_socket* sock, const char* address, uint16_t port)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			qsc_ipinfo_ipv4_address addt;

			addt = qsc_ipinfo_ipv4_address_from_string(address);
			res = qsc_socket_connect_ipv4(sock, &addt, port);
		}
		else
		{
			qsc_ipinfo_ipv6_address addt;

			addt = qsc_ipinfo_ipv6_address_from_string(address);
			res = qsc_socket_connect_ipv6(sock, &addt, port);
		}
	}

	return res;
}

qsc_socket_exceptions qsc_socket_connect_ipv4(qsc_socket* sock, const qsc_ipinfo_ipv4_address* address, uint16_t port)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(address != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		struct sockaddr_in sa;
		int8_t sadd[QSC_IPINFO_IPV4_STRNLEN] = { 0 };

		qsc_memutils_clear(&sa, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		inet_ntop(AF_INET, address->ipv4, (PSTR)sadd, sizeof(sadd));
		inet_pton(AF_INET, (PSTR)sadd, &(sa.sin_addr));

		res = (qsc_socket_exceptions)connect(sock->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != qsc_socket_exception_error)
		{
			qsc_memutils_copy(sock->address, sadd, QSC_IPINFO_IPV4_STRNLEN);
			sock->connection_status = qsc_socket_state_connected;
			sock->port = port;
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_connect_ipv6(qsc_socket* sock, const qsc_ipinfo_ipv6_address* address, uint16_t port)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(address != NULL);

	struct sockaddr_in6 sa;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && address != NULL)
	{
		int8_t sadd[QSC_IPINFO_IPV6_STRNLEN] = { 0 };

		qsc_memutils_clear(&sa, sizeof(sa));
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(port);
		inet_ntop(AF_INET6, address->ipv6, (PSTR)sadd, sizeof(sadd));
		inet_pton(AF_INET6, (PSTR)sadd, &(sa.sin6_addr));

		res = (qsc_socket_exceptions)connect(sock->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != qsc_socket_exception_error)
		{
			qsc_memutils_copy(sock->address, sadd, QSC_IPINFO_IPV6_STRNLEN);
			sock->connection_status = qsc_socket_state_connected;
			sock->port = port;
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_create(qsc_socket* sock, qsc_socket_address_families family, qsc_socket_transports transport, qsc_socket_protocols protocol)
{
	QSC_ASSERT(sock != NULL);

	int32_t prot;
	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	prot = (int32_t)protocol;
#else
	prot = 0;
#endif

	if (sock != NULL)
	{
		sock->address_family = family;
		sock->socket_transport = transport;
		sock->socket_protocol = protocol;
		sock->connection = socket((int32_t)family, (int32_t)transport, prot);
		res = (sock->connection != QSC_UNINITIALIZED_SOCKET) ? qsc_socket_exception_success : qsc_socket_exception_error;
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

qsc_socket_exceptions qsc_socket_listen(const qsc_socket* sock, int32_t backlog)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL)
	{
		res = (qsc_socket_exceptions)listen(sock->connection, backlog);
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

size_t qsc_socket_max_send_buffer_size(const qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	socklen_t slen;
	int32_t plen;

	plen = 0;

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
		slen = sizeof(plen);
#if defined(QSC_SYSTEM_OS_WINDOWS)
		getsockopt(sock->connection, SOL_SOCKET, SO_MAX_MSG_SIZE, (char*)&plen, &slen);
#else
		getsockopt(sock->connection, SOL_SOCKET, SO_SNDBUF, (char*)&plen, &slen);
#endif
	}

	if (plen == 0)
	{
		plen = SO_SNDBUF;
	}

	return plen;
}

size_t qsc_socket_peek(const qsc_socket* sock, uint8_t* output, size_t otplen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(sock != NULL);

	int32_t res;

	res = 0;

	if (sock != NULL && output != NULL)
	{
		res = recv(sock->connection, (char*)output, (int32_t)otplen, (int32_t)qsc_socket_receive_flag_peek);
		res = (res == qsc_socket_exception_error) ? 0 : res;
	}

	return (size_t)res;
}

size_t qsc_socket_receive(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(output != NULL);

	int32_t res;

	res = 0;

	if (sock != NULL && output != NULL)
	{
		res = recv(sock->connection, (char*)output, (int32_t)otplen, (int32_t)flag);
		res = (res == qsc_socket_exception_error) ? 0 : res;
	}

	return (size_t)res;
}

static void qsc_socket_receive_async_invoke(qsc_socket_receive_async_state* state)
{
	qsc_mutex mtx;

	mtx = qsc_async_mutex_lock_ex();

	if (state != NULL)
	{
		while (state->source->connection_status == qsc_socket_state_connected)
		{
			size_t mlen;

			mlen = qsc_socket_receive(state->source, state->buffer, sizeof(state->buffer), qsc_socket_receive_flag_none);

			if (mlen > 0U)
			{
				state->callback(state->source, state->buffer, &mlen);
			}
		}
	}

	qsc_async_mutex_unlock_ex(mtx);
}

qsc_socket_exceptions qsc_socket_receive_async(qsc_socket_receive_async_state* state)
{
	QSC_ASSERT(state != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (state != NULL && state->source != NULL)
	{
		qsc_async_thread_create((void(*)(void*))&qsc_socket_receive_async_invoke, state);
	}

	return res;
}

uint32_t qsc_socket_receive_poll(const qsc_socket_receive_poll_state* state)
{
	QSC_ASSERT(state != NULL);

	qsc_mutex mtx;
	uint32_t ctr;

	mtx = qsc_async_mutex_lock_ex();

	ctr = 0U;

	if (state != NULL)
	{
		for (size_t i = 0U; i < state->count; ++i)
		{
			if (qsc_socket_is_connected(state->sockarr[i]))
			{
				if (qsc_socket_receive_ready(state->sockarr[i], NULL) == true)
				{
					state->callback(state->sockarr[i], i);
					++ctr;
				}
			}
			else
			{
				state->error(state->sockarr[i], qsc_socket_exception_error);
			}
		}
	}

	qsc_async_mutex_unlock_ex(mtx);

	return ctr;
}

size_t qsc_socket_receive_all(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(output != NULL);

	int32_t pos;
	int32_t res;

	pos = 0;

	if (sock != NULL && output != NULL)
	{
		while (otplen > 0U)
		{
			res = recv(sock->connection, (char*)output, (int32_t)otplen, (int32_t)flag);

			if (res < 1)
			{
				pos = 0;
				break;
			}

			otplen -= res;
			pos += res;
		}
	}

	return (size_t)pos;
}

size_t qsc_socket_receive_from(qsc_socket* sock, char* dest, uint16_t port, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(output != NULL);

	socklen_t len;
	int32_t res;

	res = 0;

	if (sock != NULL && dest != NULL && output != NULL)
	{
		len = 0;

		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			char astr[INET_ADDRSTRLEN] = { 0U };
			struct sockaddr_in d;

			d.sin_family = AF_INET;
			d.sin_port = htons(port);
			d.sin_addr.s_addr = inet_pton(AF_INET, dest, &d.sin_addr);

			res = recvfrom(sock->connection, (char*)output, (int32_t)otplen, (int32_t)flag, (struct sockaddr*)&d, &len);

			if (res != qsc_socket_exception_error)
			{
				inet_ntop(AF_INET, &d.sin_addr, astr, INET_ADDRSTRLEN);
				qsc_memutils_copy(dest, astr, len);
				sock->connection_status = qsc_socket_state_connectionless;
				sock->port = port;
			}
		}
		else
		{
			char astr[INET6_ADDRSTRLEN] = { 0U };
			struct sockaddr_in6 d;

			d.sin6_family = AF_INET6;
			d.sin6_port = htons(port);
			inet_pton(AF_INET6, dest, &d.sin6_addr);

			res = recvfrom(sock->connection, (char*)output, (int32_t)otplen, (int32_t)flag, (struct sockaddr*)&d, &len);

			if (res != qsc_socket_exception_error)
			{
				inet_ntop(AF_INET6, &d.sin6_addr, astr, INET6_ADDRSTRLEN);
				qsc_memutils_copy(dest, astr, len);
				sock->address_family = qsc_socket_address_family_ipv6;
				sock->connection_status = qsc_socket_state_connectionless;
				sock->port = port;
				sock->socket_protocol = qsc_socket_protocol_udp;
				sock->socket_transport = qsc_socket_transport_datagram;
			}
		}
	}

	res = (res == qsc_socket_exception_error) ? 0 : res;

	return (size_t)res;
}

size_t qsc_socket_send(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(input != NULL);

	int32_t res;

	res = 0;

	if (sock != NULL && input != NULL)
	{
		res = send(sock->connection, (const char*)input, (int32_t)inplen, (int32_t)flag);
		res = (res == qsc_socket_exception_error) ? 0 : res;
	}

	return (size_t)res;
}

size_t qsc_socket_send_to(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(input != NULL);

	int32_t res;

	res = 0;

	if (sock != NULL && input != NULL)
	{
		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			struct sockaddr_in d;
			d.sin_family = AF_INET;
			d.sin_port = htons(sock->port);
			inet_pton(AF_INET, (char*)sock->address, &d.sin_addr);

			res = sendto(sock->connection, (const char*)input, (int32_t)inplen, (int32_t)flag, (struct sockaddr*)&d, sizeof(d));
		}
		else
		{
			struct sockaddr_in6 d;
			d.sin6_family = AF_INET6;
			d.sin6_port = htons(sock->port);
			inet_pton(AF_INET6, (char*)sock->address, &d.sin6_addr);

			res = sendto(sock->connection, (const char*)input, (int32_t)inplen, (int32_t)flag, (struct sockaddr*)&d, sizeof(d));
		}
	}

	res = (res == qsc_socket_exception_error) ? 0 : res;

	return (size_t)res;
}

size_t qsc_socket_send_all(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(input != NULL);

	int32_t pos;
	int32_t res;

	pos = 0;

	if (sock != NULL && input != NULL)
	{
		while (inplen > 0)
		{
			res = send(sock->connection, (const char*)input, (int32_t)inplen, (int32_t)flag);

			if (res < 1)
			{
				pos = 0;
				break;
			}

			inplen -= res;
			pos += res;
		}
	}

	return (size_t)pos;
}

qsc_socket_exceptions qsc_socket_shut_down(qsc_socket* sock, qsc_socket_shut_down_flags params)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_exception_error;

	if (sock != NULL)
	{
		if (sock->connection != QSC_UNINITIALIZED_SOCKET && qsc_socket_is_connected(sock) == true)
		{
			res = (qsc_socket_exceptions)shutdown(sock->connection, (int32_t)params);
		}
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

//~~~Helper Functions~~~//

const char* qsc_socket_error_to_string(qsc_socket_exceptions code)
{
	const char* pmsg;

	switch (code)
	{
	case qsc_socket_exception_success:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[0U];
		break;
	}
	case qsc_socket_exception_error:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[1U];
		break;
	}
	case qsc_socket_invalid_input:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[2U];
		break;
	}
	case qsc_socket_exception_address_in_use:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[3U];
		break;
	}
	case qsc_socket_exception_address_required:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[4U];
		break;
	}
	case qsc_socket_exception_address_unsupported:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[5U];
		break;
	}
	case qsc_socket_exception_already_in_use:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[6U];
		break;
	}
	case qsc_socket_exception_blocking_cancelled:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[7U];
		break;
	}
	case qsc_socket_exception_blocking_in_progress:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[8U];
		break;
	}
	case qsc_socket_exception_broadcast_address:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[9U];
		break;
	}
	case qsc_socket_exception_buffer_fault:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[10U];
		break;
	}
	case qsc_socket_exception_circuit_reset:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[11U];
		break;
	}
	case qsc_socket_exception_circuit_terminated:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[12U];
		break;
	}
	case qsc_socket_exception_circuit_timeout:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[13U];
		break;
	}
	case qsc_socket_exception_connection_refused:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[14U];
		break;
	}
	case qsc_socket_exception_descriptor_not_socket:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[15U];
		break;
	}
	case qsc_socket_exception_disk_quota_exceeded:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[16U];
		break;
	}
	case qsc_socket_exception_dropped_connection:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[17U];
		break;
	}
	case qsc_socket_exception_family_unsupported:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[18U];
		break;
	}
	case qsc_socket_exception_host_is_down:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[19U];
		break;
	}
	case qsc_socket_exception_host_unreachable:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[20U];
		break;
	}
	case qsc_socket_exception_in_progress:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[21U];
		break;
	}
	case qsc_socket_exception_invalid_address:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[22U];
		break;
	}
	case qsc_socket_exception_invalid_protocol:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[24U];
		break;
	}
	case qsc_socket_exception_invalid_protocol_option:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[25U];
		break;
	}
	case qsc_socket_exception_item_is_remote:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[27U];
		break;
	}
	case qsc_socket_exception_message_too_long:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[28U];
		break;
	}
	case qsc_socket_exception_name_too_long:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[29U];
		break;
	}
	case qsc_socket_exception_network_failure:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[30U];
		break;
	}
	case qsc_socket_exception_network_unreachable:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[31U];
		break;
	}
	case qsc_socket_exception_no_buffer_space:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[32U];
		break;
	}
	case qsc_socket_exception_no_descriptors:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[33U];
		break;
	}
	case qsc_socket_exception_not_bound:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[35U];
		break;
	}
	case qsc_socket_exception_not_connected:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[36U];
		break;
	}
	case qsc_socket_exception_operation_unsupported:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[38U];
		break;
	}
	case qsc_socket_exception_protocol_unsupported:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[39U];
		break;
	}
	case qsc_socket_exception_shut_down:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[40U];
		break;
	}
	case qsc_socket_exception_socket_unsupported:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[41U];
		break;
	}
	case qsc_socket_exception_system_not_ready:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[42U];
		break;
	}
	case qsc_socket_exception_too_many_users:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[44U];
		break;
	}
	case qsc_socket_exception_translation_failed:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[45U];
		break;
	}
	case qsc_socket_exception_would_block:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[46U];
		break;
	}
	default:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[1U];
	}
	}

	return pmsg;
}

qsc_socket_exceptions qsc_socket_get_last_error()
{
	qsc_socket_exceptions res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (qsc_socket_exceptions)WSAGetLastError();
#else
	res = (qsc_socket_exceptions)errno;
#endif

	return res;
}

qsc_socket_exceptions qsc_socket_ioctl(const qsc_socket* sock, int32_t command, uint32_t* arguments)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(arguments != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && arguments != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (qsc_socket_exceptions)ioctlsocket(sock->connection, command, (u_long*)arguments);
#else
		res = (qsc_socket_exceptions)ioctl(sock->connection, (uint32_t)command, arguments);
#endif
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

bool qsc_socket_receive_ready(const qsc_socket* sock, const struct timeval* timeout)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && timeout != NULL)
	{
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sock->connection, &fds);

		if (timeout == NULL)
		{
			res = (qsc_socket_exceptions)select((int32_t)sock->connection + 1, &fds, NULL, NULL, NULL);
		}
		else
		{
			struct timeval* tcopy = (struct timeval*)timeout;
			res = (qsc_socket_exceptions)select((int32_t)sock->connection + 1, &fds, NULL, NULL, tcopy);
		}
	}

	return (res == qsc_socket_exception_success);
}

bool qsc_socket_send_ready(const qsc_socket* sock, const struct timeval* timeout)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL)
	{
		fd_set fds;
		struct timeval* tcopy;

		FD_ZERO(&fds);
		FD_SET(sock->connection, &fds);

		if (timeout == NULL)
		{
			res = (qsc_socket_exceptions)select((int32_t)sock->connection + 1, NULL, &fds, NULL, NULL);
		}
		else
		{
			tcopy = (struct timeval*)timeout;
			res = (qsc_socket_exceptions)select((int32_t)sock->connection + 1, NULL, &fds, NULL, tcopy);
		}
	}

	return (res == qsc_socket_exception_success);
}

void qsc_socket_set_last_error(qsc_socket_exceptions error)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSASetLastError((int32_t)error);
#else
	errno = (int32_t)error;
#endif
}

qsc_socket_exceptions qsc_socket_shut_down_sockets()
{
	qsc_socket_exceptions res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (qsc_socket_exceptions)WSACleanup();
#else
	res = qsc_socket_exception_success;
#endif

	return res;
}

qsc_socket_exceptions qsc_socket_set_option(const qsc_socket* sock, qsc_socket_protocols level, qsc_socket_options option, int32_t optval)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL)
	{
		res = (qsc_socket_exceptions)setsockopt(sock->connection, (int32_t)level, (int32_t)option, (void*)&optval, sizeof(optval));
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

bool qsc_socket_start_sockets()
{
	qsc_socket_exceptions res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSADATA wsd;

	res = (qsc_socket_exceptions)WSAStartup(0x0202, &wsd);
#else
	res = qsc_socket_exception_success;
#endif

	return (res == qsc_socket_exception_success);
}
