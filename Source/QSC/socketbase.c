#include "socketbase.h"
#include "intutils.h"
#include "memutils.h"
#include "async.h"

#if defined(QSC_SYSTEM_OS_WINDOWS)
#	include <WinSock2.h>
#	include <WS2tcpip.h>
#	include <ws2def.h>
#	include <objbase.h>
#	include <inaddr.h>
#	include <iphlpapi.h>
#   if defined(QSC_SYSTEM_COMPILER_MSC)
#	    pragma comment(lib, "iphlpapi.lib")
#	    pragma comment(lib, "ws2_32.lib")
#   endif
#elif defined(QSC_SYSTEM_OS_POSIX)
#	include <errno.h>
#	include <fcntl.h>
#	include <netdb.h>
#	include <ifaddrs.h>
#	include <netinet/in.h>
#	include <arpa/inet.h>
#	include <sys/socket.h>
#	include <string.h>
#	include <sys/types.h>
#	include <sys/un.h>
#	include <unistd.h>
#	if defined(QSC_SYSTEM_OS_LINUX)
#		include <netpacket/packet.h>
#	elif defined(QSC_SYSTEM_OS_MAC)
#		include <net/if_dl.h>
#		include <netinet/in.h>
#		if !defined(AF_PACKET)
#			define AF_PACKET PF_INET
#		endif
#	endif
#endif

#if defined(QSC_SYSTEM_OS_POSIX)
#   include <sys/ioctl.h>
#   include <sys/select.h>
#	if !defined(PSTR)
#   	define PSTR char*
#	endif
#endif

const char QSC_SOCKET_ERROR_STRINGS[48][128] =
{
	"SUCCESS: The operation completed successfully.",
	"ERROR: The operation has failed.",
	"INVALID: The input parameters are incorrect.",
	"EADDRINUSE: The socket's local address is in use and the socket was not marked to allow address reuse with SO_REUSEADDR.",
	"EDESTADDRREQ: A destination address is required.",
	"EAFNOSUPPORT: The address family is not supported.",
	"EISCONN: The socket is already connected.",
	"EINTR: A blocking sockets call was canceled.",
	"EINPROGRESS: A blocking sockets call is in progress, or the service provider is still processing a callback function.",
	"EACCES: The requested address is a broadcast address, but the appropriate flag was not set.",
	"EFAULT: The buffer parameter is not completely contained in a valid part of the user address space.",
	"ECONNRESET: The virtual circuit was reset by the remote side executing a hard or abortive close.",
	"ECONNABORTED: The virtual circuit was terminated due to a time-out or other failure.",
	"ETIMEDOUT: The connection has been dropped, because of a network failure.",
	"ECONNREFUSED: The connection was refused.",
	"ENOTSOCK: The descriptor is not a socket.",
	"EDQUOT: The disk quota is exceeded.",
	"ENETRESET: The connection has been broken due to the keep-alive activity detecting a failure.",
	"EPFNOSUPPORT: The protocol family is not supported.",
	"EHOSTDOWN: The destination host is down.",
	"EHOSTUNREACH: The remote host cannot be reached from this host at this time.",
	"EALREADY: Operation in progress.",
	"EADDRNOTAVAIL: The address is not available.",
	"INVALID_PARAMETER: One or more parameters are invalid.",
	"EPROTOTYPE: The protocol type is invalid for the socket.",
	"ENOPROTOOPT: The protocol option is invalid.",
	"EINVALIDPROVIDER: The service provider is invalid.",
	"EREMOTE: The item is not available locally.",
	"EMSGSIZE: The message size is too long.",
	"ENAMETOOLONG: The name is too long.",
	"ENETDOWN: The network subsystem has failed.",
	"ENETUNREACH: The network is unreachable.",
	"ENOBUFS: No buffer space is available.",
	"EMFILE: No more socket descriptors are available.",
	"_NOT_ENOUGH_MEMORY: The system does not have enough memory available.",
	"EINVAL: The socket has not been bound with bind, or MSG_OOB was specified for a socket with SO_OOBINLINE enabled.",
	"ENOTCONN: The socket is not connected.",
	"NOTINITIALISED: A successful Startup call must occur before using this function.",
	"EOPNOTSUPP: The socket operation is not supported.",
	"EPROTONOSUPPORT: The protocol is not supported.",
	"ESHUTDOWN: The socket has been shut down.",
	"ESOCKTNOSUPPORT: The socket type is not supported.",
	"SYSNOTREADY: The subsystem is unavailable.",
	"EPROCLIM: The host is using too many processes.",
	"EUSERS: The user quota is exceeded.",
	"ELOOP: Can not translate name.",
	"EWOULDBLOCK: The socket is marked as nonblocking and the requested operation would block.",
	"",
};

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

	if (address != NULL && strlen(address) <= QSC_IPINFO_IPV4_STRNLEN)
	{
		struct in_addr tmp;
		res = (inet_pton(AF_INET, address, &tmp) == 1);
	}

	return res;
}

bool qsc_socket_ipv6_valid_address(const char* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL && strlen(address) <= QSC_IPINFO_IPV6_STRNLEN)
	{
		struct in6_addr tmp;
		res = (inet_pton(AF_INET6, address, &tmp) == 1);
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
#if defined(QSC_SYSTEM_OS_WINDOWS)
		res = (recv(sock->connection, (char*)b, 0, 0) == QSC_SOCKET_RET_SUCCESS);
#else
		int32_t flags = fcntl(sock->connection, F_GETFL, 0);
		return (flags >= 0) && !(flags & O_NONBLOCK);
#endif
	}

	return res;
}

bool qsc_socket_is_connected(const qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	bool res;

	res = false;

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)

		SOCKADDR_STORAGE peer;
		int32_t errlen;
		int32_t peerlen;
		int32_t ret;
		int32_t sockerr;

		qsc_memutils_clear(&peer, sizeof(peer));
		peerlen = (int32_t)sizeof(peer);
		sockerr = 0;
		errlen = (int32_t)sizeof(sockerr);

		/* getpeername succeeds only when the socket has an established
		 * peer; WSAENOTCONN is the expected failure for unconnected sockets. */
		ret = getpeername(sock->connection, (SOCKADDR*)&peer, &peerlen);

		if (ret == 0)
		{
			/* confirm no pending async error on the socket */
			ret = getsockopt(sock->connection, SOL_SOCKET, SO_ERROR, (char*)&sockerr, &errlen);

			if (ret == 0 && sockerr == 0)
			{
				res = true;
			}
		}

#elif defined(QSC_SYSTEM_OS_LINUX) || defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)

		struct sockaddr_storage peer;
		socklen_t peerlen;
		socklen_t errlen;
		int32_t ret;
		int32_t sockerr;

		qsc_memutils_clear(&peer, sizeof(peer));
		peerlen = (socklen_t)sizeof(peer);
		sockerr = 0;
		errlen = (socklen_t)sizeof(sockerr);

		/* getpeername returns 0 only for a connected socket.
		 * ENOTCONN is the expected errno for an unconnected socket;
		 * any other errno indicates a bad descriptor or similar fault. */
		ret = getpeername(sock->connection, (struct sockaddr*)&peer, &peerlen);

		if (ret == 0)
		{
			/* confirm no pending async error (e.g. from a prior failed
			 * non-blocking connect, or an ICMP port-unreachable). */
			ret = getsockopt(sock->connection, SOL_SOCKET, SO_ERROR, (char*)&sockerr, &errlen);

			if (ret == 0 && sockerr == 0)
			{
				res = true;
			}
		}

#endif
	}

	return res;
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
		qsc_memutils_clear(&sa, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		qsc_memutils_copy(&sa.sin_addr.s_addr, address->ipv4, 4U);

#if defined(QSC_SYSTEM_OS_MAC)
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

		qsc_memutils_copy((uint8_t*)sa.sin6_addr.s6_addr, (const uint8_t*)address->ipv6, 16U);
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
		plen = (int32_t)QSC_SOCKET_DEFAULT_SNDBUF_SIZE;
	}

	return plen;
}

size_t qsc_socket_peek(const qsc_socket* sock, uint8_t* output, size_t otplen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(sock != NULL);

	int32_t res;
	int32_t rlen;

	res = 0;

	if (sock != NULL && output != NULL)
	{
		rlen = (otplen > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)otplen;
		res = recv(sock->connection, (char*)output, rlen, (int32_t)qsc_socket_receive_flag_peek);
		res = (res == qsc_socket_exception_error) ? 0 : res;
	}

	return (size_t)res;
}

size_t qsc_socket_receive(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(output != NULL);

	int32_t res;
	int32_t rlen;

	res = 0;

	if (sock != NULL && output != NULL)
	{
		rlen = (otplen > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)otplen;
		res = recv(sock->connection, (char*)output, rlen, (int32_t)flag);
		res = (res == qsc_socket_exception_error) ? 0 : res;
	}

	return (size_t)res;
}

static void qsc_socket_receive_async_invoke(qsc_socket_receive_async_state* state)
{
	size_t mlen;

	if (state != NULL)
	{
		while (state->source->connection_status == qsc_socket_state_connected)
		{
			mlen = qsc_socket_receive(state->source, state->buffer, sizeof(state->buffer), qsc_socket_receive_flag_none);

			if (mlen > 0U)
			{
				state->callback(state->source, state->buffer, &mlen);
			}
		}
	}
}

static void qsc_socket_receive_async_invoke_vp(void* vstate)
{
    qsc_socket_receive_async_state* state = (qsc_socket_receive_async_state*)vstate;
	qsc_socket_receive_async_invoke(state);
}

qsc_socket_exceptions qsc_socket_receive_async(qsc_socket_receive_async_state* state)
{
	QSC_ASSERT(state != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (state != NULL && state->source != NULL)
	{
		if (qsc_async_thread_create(&qsc_socket_receive_async_invoke_vp, state)) 
		{
			res = qsc_socket_exception_success;
		}
	}

	return res;
}

uint32_t qsc_socket_receive_poll(const qsc_socket_receive_poll_state* state)
{
	QSC_ASSERT(state != NULL);

	uint32_t ctr;

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

	return ctr;
}

size_t qsc_socket_receive_all(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(output != NULL);

	size_t pos;
	int32_t chunk;
	int32_t res;

	pos = 0U;

	if (sock != NULL && output != NULL)
	{
		while (otplen > 0U)
		{
			chunk = (otplen > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)otplen;
			res = recv(sock->connection, (char*)(output + pos), chunk, (int32_t)flag);

			if (res < 1)
			{
				pos = 0U;
				break;
			}

			otplen -= (size_t)res;
			pos += (size_t)res;
		}
	}

	return pos;
}

size_t qsc_socket_receive_from(qsc_socket* sock, char* dest, size_t destlen, uint16_t port, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(dest != NULL);
	QSC_ASSERT(output != NULL);

	socklen_t len;
	int32_t res;
	int32_t rlen;

	res = 0;

	if (sock != NULL && dest != NULL && output != NULL)
	{
		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			char astr[INET_ADDRSTRLEN] = { 0U };
			struct sockaddr_in d;

			len = sizeof(d);
			d.sin_family = AF_INET;
			d.sin_port = htons(port);

			if (inet_pton(AF_INET, dest, &d.sin_addr) == 1)
			{
				rlen = (otplen > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)otplen;
				res = recvfrom(sock->connection, (char*)output, rlen, (int32_t)flag, (struct sockaddr*)&d, &len);

				if (res != qsc_socket_exception_error)
				{
					size_t alen;

					inet_ntop(AF_INET, &d.sin_addr, astr, INET_ADDRSTRLEN);
					alen = strnlen(astr, INET_ADDRSTRLEN) + 1U;

					if (alen <= destlen)
					{
						qsc_memutils_copy(dest, astr, alen);
					}

					sock->connection_status = qsc_socket_state_connectionless;
					sock->port = port;
				}
			}
		}
		else
		{
			char astr[INET6_ADDRSTRLEN] = { 0U };
			struct sockaddr_in6 d;

			len = sizeof(d);
			d.sin6_family = AF_INET6;
			d.sin6_port = htons(port);

			if (inet_pton(AF_INET6, dest, &d.sin6_addr) == 1)
			{
				rlen = (otplen > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)otplen;
				res = recvfrom(sock->connection, (char*)output, rlen, (int32_t)flag, (struct sockaddr*)&d, &len);

				if (res != qsc_socket_exception_error)
				{
					size_t alen;

					inet_ntop(AF_INET6, &d.sin6_addr, astr, INET6_ADDRSTRLEN);
					alen = strnlen(astr, INET6_ADDRSTRLEN) + 1U;
					
					if (alen <= destlen)
					{
						qsc_memutils_copy(dest, astr, alen);
					}

					sock->address_family = qsc_socket_address_family_ipv6;
					sock->connection_status = qsc_socket_state_connectionless;
					sock->port = port;
					sock->socket_protocol = qsc_socket_protocol_udp;
					sock->socket_transport = qsc_socket_transport_datagram;
				}
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
	int32_t slen;

	res = 0;

	if (sock != NULL && input != NULL)
	{
		slen = (inplen > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)inplen;
		res = send(sock->connection, (const char*)input, slen, (int32_t)flag);
		res = (res == qsc_socket_exception_error) ? 0 : res;
	}

	return (size_t)res;
}

size_t qsc_socket_send_to(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(input != NULL);

	int32_t res;
	int32_t slen;

	res = 0;

	if (sock != NULL && input != NULL)
	{
		slen = (inplen > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)inplen;

		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			struct sockaddr_in d;
			d.sin_family = AF_INET;
			d.sin_port = htons(sock->port);
			inet_pton(AF_INET, (char*)sock->address, &d.sin_addr);

			res = sendto(sock->connection, (const char*)input, slen, (int32_t)flag, (struct sockaddr*)&d, sizeof(d));
		}
		else
		{
			struct sockaddr_in6 d;
			d.sin6_family = AF_INET6;
			d.sin6_port = htons(sock->port);
			inet_pton(AF_INET6, (char*)sock->address, &d.sin6_addr);

			res = sendto(sock->connection, (const char*)input, slen, (int32_t)flag, (struct sockaddr*)&d, sizeof(d));
		}
	}

	res = (res == qsc_socket_exception_error) ? 0 : res;

	return (size_t)res;
}

size_t qsc_socket_send_all(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(input != NULL);

	size_t pos;
	int32_t chunk;
	int32_t res;

	pos = 0U;

	if (sock != NULL && input != NULL)
	{
		while (inplen > 0U)
		{
			chunk = (inplen > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)inplen;
			res = send(sock->connection, (const char*)(input + pos), (int32_t)chunk, (int32_t)flag);

			if (res < 1)
			{
				pos = 0U;
				break;
			}

			inplen -= (size_t)res;
			pos += (size_t)res;
		}
	}

	return pos;
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
#if defined(QSC_SYSTEM_OS_WINDOWS)
	case qsc_socket_exception_invalid_parameter:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[23U];
		break;
	}
#endif

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
#if defined(QSC_SYSTEM_OS_WINDOWS)
	case qsc_socket_exception_invalid_provider:
	{
		pmsg = QSC_SOCKET_ERROR_STRINGS[26U];
		break;
	}
#endif

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

	int32_t rc;

	rc = 0;

	if (sock != NULL)
	{
		fd_set fds;

		FD_ZERO(&fds);
		FD_SET(sock->connection, &fds);

		if (timeout == NULL)
        {
            rc = select((int32_t)sock->connection + 1, &fds, NULL, NULL, NULL);
        }
        else
        {
            struct timeval tcopy = *timeout;
            rc = select((int32_t)sock->connection + 1, &fds, NULL, NULL, &tcopy);
        }
	}

	return (rc > 0);
}

bool qsc_socket_send_ready(const qsc_socket* sock, const struct timeval* timeout)
{
	QSC_ASSERT(sock != NULL);

	int32_t rc;

	rc = 0;

	if (sock != NULL)
	{
		fd_set fds;

		FD_ZERO(&fds);
		FD_SET(sock->connection, &fds);

		if (timeout == NULL)
		{
			rc = select((int32_t)sock->connection + 1, NULL, &fds, NULL, NULL);
		}
		else
		{
			struct timeval tcopy = *timeout;
			rc =select((int32_t)sock->connection + 1, NULL, &fds, NULL, &tcopy);
		}
	}

	return (rc > 0);
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
