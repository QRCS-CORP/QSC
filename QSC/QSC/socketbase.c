#include "socketbase.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
	const int32_t SOCKET_EINVAL = WSAEINVAL;
	const int32_t SOCKET_EWOULDBLOCK = WSAEWOULDBLOCK;
#else
	const int32_t SD_RECEIVE = 0x00000000L;
	const int32_t SD_SEND = 0x00000001L;
	const int32_t SD_BOTH = 0x00000002L;
	const int32_t SOCKET_EINVAL = EINVAL;
	const int32_t SOCKET_EWOULDBLOCK = EWOULDBLOCK;
#endif

//~~~Private Functions~~~//

static qsc_socket_exceptions qsc_socket_acceptv4(qsc_socket* source, qsc_socket* target)
{
	qsc_socket rskt;
	struct sockaddr_in sa;
	socklen_t salen;
	int8_t astr[INET_ADDRSTRLEN] = { 0 };
	int32_t res;

	salen = sizeof(sa);
	memset(&sa, 0x00, salen);
	rskt = *source;
	rskt.connection = 0;
	rskt.connection_status = socket_state_none;

#if defined(QSC_SYSTEM_OS_POSIX)
	sa.sin_len = sizeof(sa);
#endif

	rskt.connection = accept(source->connection, (struct sockaddr*)&sa, &salen);
	res = (rskt.connection != UNINITIALIZED_SOCKET && rskt.connection != SOCKET_RET_ERROR) ? SOCKET_RET_SUCCESS : SOCKET_RET_ERROR;

	if (res == SOCKET_RET_SUCCESS)
	{
		qsc_socket_attach(target, &rskt);
		target->connection_status = socket_state_connected;
		inet_ntop(AF_INET, &sa.sin_addr, astr, INET_ADDRSTRLEN);
		memcpy(target->address, astr, QSC_IPV4_STRNLEN);
		target->port = (uint16_t)ntohs(sa.sin_port);
	}
	else
	{
		qsc_socket_close_socket(&rskt);
	}

	return (qsc_socket_exceptions)res;
}

static qsc_socket_exceptions qsc_socket_acceptv6(qsc_socket* source, qsc_socket* target)
{
	qsc_socket rskt;
	socklen_t salen;
	struct sockaddr_in6 sa;
	int8_t astr[INET6_ADDRSTRLEN];
	int32_t res;

	salen = sizeof(sa);
	memset(&sa, 0x00, salen);
	rskt = *source;
	rskt.connection = 0;
	rskt.connection_status = socket_state_none;

#if defined(QSC_SYSTEM_OS_POSIX)
	sa.sin6_len = sizeof(sa);
#endif

	rskt.connection = accept(source->connection, (struct sockaddr*)&sa, &salen);
	res = (rskt.connection != INVALID_SOCKET) ? SOCKET_RET_SUCCESS : SOCKET_RET_ERROR;

	if (res == SOCKET_RET_SUCCESS)
	{
		qsc_socket_attach(target, &rskt);
		target->connection_status = socket_state_connected;
		inet_ntop(AF_INET6, &sa.sin6_addr, astr, INET6_ADDRSTRLEN);
		memcpy(target->address, astr, QSC_IPV6_STRNLEN);
		target->port = (uint16_t)ntohs(sa.sin6_port);
	}
	else
	{
		res = qsc_socket_get_last_error();
		qsc_socket_close_socket(&rskt);
	}

	return (qsc_socket_exceptions)res;
}

//~~~Accessors~~~//

bool qsc_socket_is_blocking(qsc_socket* source)
{
	assert(source != NULL);

	int8_t b[1];
	int32_t res;

	res = false;

	if (source != NULL)
	{
		res = (recv(source->connection, b, 0, 0) == SOCKET_RET_SUCCESS);
	}

	return res;
}

bool qsc_socket_is_connected(qsc_socket* source)
{
	assert(source != NULL);

	int32_t err;
	int8_t buf;
	bool res;

	res = true;

	if (source != NULL)
	{
		err = recv(source->connection, &buf, 1, MSG_PEEK);

		if (err == SOCKET_RET_ERROR)
		{
			res = (qsc_socket_get_last_error() != socket_would_block);
		}
	}

	return res;
}

/* ~~~Public Functions~~~ */

qsc_socket_exceptions qsc_socket_accept(qsc_socket* source, qsc_socket* target)
{
	assert(source != NULL);
	assert(target != NULL);

	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL && target != NULL)
	{
		if (source->address_family == address_family_ipv4)
		{
			res = qsc_socket_acceptv4(source, target);
		}
		else
		{
			res = qsc_socket_acceptv6(source, target);
		}
	}

	return (qsc_socket_exceptions)res;
}

void qsc_socket_attach(qsc_socket* source, qsc_socket* target)
{
	assert(source != NULL);

	if (source != NULL)
	{
		source = target;
	}
}

qsc_socket_exceptions qsc_socket_bind(qsc_socket* source, const qsc_ipv4_address* address, uint16_t port)
{
	assert(source != NULL);
	assert(address != NULL);

	struct sockaddr_in sa;
	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL && address != NULL)
	{
		memset(&sa, 0x00, sizeof(sa));

#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin_len = sizeof(sa);
#endif

		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		res = bind(source->connection, (const struct sockaddr*)&sa, sizeof(sa));
		inet_ntop(AF_INET, address->ipv4, source->address, sizeof(source->address));
		source->address_family = address_family_ipv4;
	}

	return (qsc_socket_exceptions)res;
}

qsc_socket_exceptions qsc_socket_bind_ipv6(qsc_socket* source, const qsc_ipv6_address* address, uint16_t port)
{
	assert(source != NULL);
	assert(address != NULL);

	struct sockaddr_in6 sa;
	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL && address != NULL)
	{
		memset(&sa, 0x00, sizeof(sa));

#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin6_len = sizeof(sa);
#endif
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(port);
		res = bind(source->connection, (const struct sockaddr*)&sa, sizeof(sa));
		inet_ntop(AF_INET6, address->ipv6, source->address, sizeof(source->address)); // test this
		source->address_family = address_family_ipv6;
	}

	return (qsc_socket_exceptions)res;
}

qsc_socket_exceptions qsc_socket_close_socket(qsc_socket* source)
{
	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL)
	{
		if (source->connection != UNINITIALIZED_SOCKET && source->connection != SOCKET_RET_ERROR)
		{
#if defined(QSC_SYSTEM_WINDOWS_SOCKETS)
			res = shutdown(source->connection, SD_SEND);

			if (res != SOCKET_RET_ERROR)
			{
				res = closesocket(source->connection);
			}
#else
			res = close(source->connection);
#endif
		}
	}

	return (qsc_socket_exceptions)res;
}

qsc_socket_exceptions qsc_socket_connect(qsc_socket* source, const qsc_ipv4_address* address, uint16_t port)
{
	assert(source != NULL);
	assert(address != NULL);

	struct sockaddr_in sa;
	int8_t sadd[QSC_IPV4_STRNLEN] = { 0 };
	int32_t res;

	sadd[QSC_IPV4_STRNLEN - 1] = '\0';
	res = SOCKET_RET_ERROR;

	if (source != NULL && address != NULL)
	{
		memset(&sa, 0x00, sizeof(sa));

#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin_len = sizeof(sa);
#endif
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		inet_ntop(AF_INET, address->ipv4, sadd, sizeof(sadd));

#if defined(QSC_SYSTEM_OS_WINDOWS)
		inet_pton(AF_INET, sadd, &(sa.sin_addr));
#else
		sa.sin_addr.s_addr = inet_addr(sadd.c_str());
#endif

		res = connect(source->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != SOCKET_RET_ERROR)
		{
			memcpy(source->address, sadd, QSC_IPV4_STRNLEN);
			source->address_family = address_family_ipv4;
			source->connection_status = socket_state_connected;
		}
	}

	return (qsc_socket_exceptions)res;
}

qsc_socket_exceptions qsc_socket_connect_ipv6(qsc_socket* source, const qsc_ipv6_address* address, uint16_t port)
{
	assert(source != NULL);
	assert(address != NULL);

	struct sockaddr_in6 sa;
	int8_t sadd[QSC_IPV6_STRNLEN];
	int32_t res;

	sadd[QSC_IPV6_STRNLEN - 1] = '\0';
	res = SOCKET_RET_ERROR;

	if (source != NULL && address != NULL)
	{
		memset(&sa, 0x00, sizeof(sa));

#if defined(QSC_SYSTEM_OS_POSIX)
		sa.sin6_len = sizeof(sa);
#endif
		sa.sin6_family = AF_INET6;
		sa.sin6_port = htons(port);
		inet_ntop(AF_INET6, address->ipv6, sadd, sizeof(sadd)); // check this

#if defined(QSC_SYSTEM_OS_WINDOWS)
		inet_pton(AF_INET6, sadd, &(sa.sin6_addr));
#else
		sa.sin6_addr.s_addr = inet_addr(sadd.c_str());
#endif

		res = connect(source->connection, (const struct sockaddr*)&sa, sizeof(sa));

		if (res != SOCKET_RET_ERROR)
		{
			memcpy(source->address, sadd, QSC_IPV6_STRNLEN);
			source->address_family = address_family_ipv6;
			source->connection_status = socket_state_connected;
		}
	}

	return (qsc_socket_exceptions)res;
}

bool qsc_socket_create(qsc_socket* source)
{
	assert(source != NULL);

	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL)
	{
		source->connection = socket((int32_t)source->address_family, (int32_t)source->socket_transport, (int32_t)source->socket_protocol);
		res = (source->connection != SOCKET_RET_ERROR);
	}

	return (res != SOCKET_RET_ERROR);
}

qsc_socket_exceptions qsc_socket_listen(qsc_socket* source, int32_t backLog)
{
	assert(source != NULL);

	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL)
	{
		res = listen(source->connection, backLog);
	}

	return (qsc_socket_exceptions)res;
}

size_t qsc_socket_receive(qsc_socket* source, uint8_t* output, size_t length, qsc_socket_receive_flags flag)
{
	assert(source != NULL);
	assert(output != NULL);
	assert(length != 0);

	int32_t res;

	res = 0;

	if (source != NULL)
	{
		res = recv(source->connection, (int8_t*)output, (int32_t)length, (int32_t)flag);
	}

	return (size_t)res;
}

size_t qsc_socket_receive_all(qsc_socket* source, uint8_t* output, size_t length, qsc_socket_receive_flags flag)
{
	assert(source != NULL);
	assert(output != NULL);

	int32_t pos;
	int32_t res;

	res = 0;
	pos = 0;

	if (source != NULL)
	{
		while (length > 0)
		{
			res = recv(source->connection, (int8_t*)output, (int32_t)length, (int32_t)flag);

			if (res < 1)
			{
				break;
			}

			length -= res;
			pos += res;
		}
	}

	return (size_t)pos;
}

size_t qsc_socket_send(qsc_socket* source, const uint8_t* input, size_t length, qsc_socket_send_flags flag)
{
	assert(source != NULL);
	assert(input != NULL);

	int32_t res;

	res = 0;

	if (source != NULL)
	{
		res = send(source->connection, (const int8_t*)input, (int32_t)length + 1, (int32_t)flag);
	}

	return (size_t)res;
}

size_t qsc_socket_send_all(qsc_socket* source, const uint8_t* input, size_t length, qsc_socket_send_flags flag)
{
	assert(source != NULL);
	assert(input != NULL);

	int32_t pos;
	int32_t res;

	res = 0;
	pos = 0;

	if (source != NULL)
	{
		while (length > 0)
		{
			res = send(source->connection, (const int8_t*)input, (int32_t)length, (int32_t)flag);

			if (res < 1)
			{
				break;
			}

			length -= res;
			pos += res;
		}
	}

	return (size_t)pos;
}

qsc_socket_exceptions qsc_socket_shut_down(qsc_socket* source, qsc_socket_shut_down_flags parameters)
{
	assert(source != NULL);

	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL)
	{
		if (source->connection != UNINITIALIZED_SOCKET && qsc_socket_is_connected(source))
		{
			res = shutdown(source->connection, (int32_t)parameters);
		}

#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = closesocket(source->connection);
#else
		res = close(source->connection);
#endif

		source->connection = UNINITIALIZED_SOCKET;
	}

	return (qsc_socket_exceptions)res;
}

//~~~Helper Functions~~~//

qsc_socket_exceptions qsc_socket_get_last_error()
{
	int32_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = (qsc_socket_exceptions)WSAGetLastError();
#else
	res = (qsc_socket_exceptions)errno;
#endif

	return res;
}

qsc_socket_exceptions qsc_socket_ioctl(qsc_socket* source, int32_t command, uint32_t* arguments)
{
	assert(source != NULL);
	assert(arguments != NULL);

	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = ioctlsocket(source->connection, command, arguments);
#else
		res = ioctl((int32_t)source, (int32_t)command, (int8_t*)arguments);
#endif
	}

	return (qsc_socket_exceptions)res;
}

qsc_socket_exceptions qsc_socket_receive_ready(qsc_socket* source, const struct timeval* timeout)
{
	assert(source != NULL);
	assert(timeout != NULL);

	fd_set fds;
	const struct timeval* tcopy;
	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL)
	{
		FD_ZERO(&fds);
		FD_SET(source->connection, &fds);

		if (timeout == NULL)
		{
			res = select((int32_t)source->connection + 1, &fds, NULL, NULL, NULL);
		}
		else
		{
			tcopy = timeout;
			res = select((int32_t)source->connection + 1, &fds, NULL, NULL, tcopy);
		}
	}

	return (qsc_socket_exceptions)res;
}

bool qsc_socket_send_ready(qsc_socket* source, const struct timeval* timeout)
{
	assert(source != NULL);
	assert(timeout != NULL);

	fd_set fds;
	const struct timeval* tcopy;
	int32_t res;

	res = SOCKET_RET_ERROR;

	if (source != NULL)
	{
		FD_ZERO(&fds);
		FD_SET(source->connection, &fds);

		if (timeout == NULL)
		{
			res = select((int32_t)source->connection + 1, NULL, &fds, NULL, NULL);
		}
		else
		{
			tcopy = timeout;
			res = select((int32_t)source->connection + 1, NULL, &fds, NULL, tcopy);
		}
	}

	return (qsc_socket_exceptions)res;
}

void qsc_socket_set_last_error(int32_t errorcode)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSASetLastError(errorcode);
#else
	errno = errorcode;
#endif
}

qsc_socket_exceptions qsc_socket_shut_down_sockets()
{
	int32_t res;

	res = SOCKET_RET_ERROR;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	res = WSACleanup();
#endif

	return (qsc_socket_exceptions)res;
}

qsc_socket_exceptions qsc_socket_option(qsc_socket* source, qsc_socket_protocols protocol, qsc_socket_options tcpopt)
{
	assert(source != NULL);

	int32_t res;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	int8_t code = (int8_t)protocol;
#else
	int32_t code = (int32_t)protocol;
#endif

	res = SOCKET_RET_ERROR;

	if (source != NULL)
	{
		res = setsockopt(source->connection, (int32_t)tcpopt, (int32_t)protocol, &code, sizeof(code));
	}

	return (qsc_socket_exceptions)res;
}

bool qsc_socket_start_sockets()
{
	int32_t res;

	res = SOCKET_RET_SUCCESS;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSADATA wsd;
	res = WSAStartup(0x0202, &wsd);
#endif

	return (res == SOCKET_RET_SUCCESS);
}
