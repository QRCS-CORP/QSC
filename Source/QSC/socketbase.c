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
#	include <poll.h>
#	include <sys/uio.h>
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


/* The event polling API uses the platform's native poll descriptor without changing public socket state. */
#if defined(QSC_SYSTEM_OS_WINDOWS)
/*! \typedef qsc_socket_poll_descriptor
 * \brief Native Windows socket poll descriptor used by the batched readiness helper.
 */
typedef WSAPOLLFD qsc_socket_poll_descriptor;
#else
/*! \typedef qsc_socket_poll_descriptor
 * \brief Native POSIX socket poll descriptor used by the batched readiness helper.
 */
typedef struct pollfd qsc_socket_poll_descriptor;
#endif

/*! \def QSC_SOCKET_POLL_STACK_CAPACITY
 * \brief Number of descriptors kept on the stack before heap allocation is required.
 */
#define QSC_SOCKET_POLL_STACK_CAPACITY 64U

#if defined(QSC_SYSTEM_OS_POSIX)
static int32_t socketbase_send_flags(qsc_socket_send_flags flag)
{
	int32_t res;

	res = (int32_t)flag;

#	if defined(MSG_NOSIGNAL)
	res |= MSG_NOSIGNAL;
#	endif

	return res;
}
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

	bool res;

	res = false;

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		int8_t b[1U] = { 0 };
		res = (recv(sock->connection, (char*)b, 0, 0) == QSC_SOCKET_RET_SUCCESS);
#else
		int32_t flags;

		flags = fcntl(sock->connection, F_GETFL, 0);
		res = (flags >= 0 && (flags & O_NONBLOCK) == 0);
#endif
	}

	return res;
}

qsc_socket_exceptions qsc_socket_set_blocking(const qsc_socket* sock, bool enabled)
{
	QSC_ASSERT(sock != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		uint32_t mode;

		mode = (enabled == true) ? 0U : 1U;
		res = qsc_socket_ioctl(sock, FIONBIO, &mode);
#else
		int32_t flags;

		flags = fcntl(sock->connection, F_GETFL, 0);

		if (flags >= 0)
		{
			if (enabled == true)
			{
				flags &= ~O_NONBLOCK;
			}
			else
			{
				flags |= O_NONBLOCK;
			}

			res = (fcntl(sock->connection, F_SETFL, flags) == 0) ? qsc_socket_exception_success : qsc_socket_exception_error;
		}
		else
		{
			res = qsc_socket_exception_error;
		}
#endif
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
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

#if defined(QSC_SYSTEM_OS_POSIX) && defined(SO_NOSIGPIPE)
		if (res == qsc_socket_exception_success)
		{
			int32_t optval;

			optval = 1;
			(void)setsockopt(sock->connection, SOL_SOCKET, SO_NOSIGPIPE, &optval, sizeof(optval));
		}
#endif
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

qsc_socket_exceptions qsc_socket_receive_progress(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag, size_t* received)
{
	qsc_socket_exceptions res;
	int32_t chunk;
	int32_t nread;
	size_t pos;

	res = qsc_socket_invalid_input;
	pos = 0U;

	if (received != NULL)
	{
		*received = 0U;
	}

	if (sock != NULL && output != NULL && received != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
		res = qsc_socket_exception_success;

		while (pos < otplen)
		{
			chunk = ((otplen - pos) > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)(otplen - pos);
			nread = recv(sock->connection, (char*)(output + pos), chunk, (int32_t)flag);

			if (nread > 0)
			{
				pos += (size_t)nread;
			}
			else if (nread == 0)
			{
				res = qsc_socket_exception_not_connected;
				break;
			}
			else
			{
				res = qsc_socket_get_last_error();

#if defined(QSC_SYSTEM_OS_POSIX)
				if (res == qsc_socket_exception_blocking_cancelled)
				{
					res = qsc_socket_exception_success;
					continue;
				}
#endif
				break;
			}
		}
	}

	if (received != NULL)
	{
		*received = pos;
	}

	return res;
}

size_t qsc_socket_receive_all(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(output != NULL);

	qsc_socket_exceptions res;
	size_t pos;

	pos = 0U;
	res = qsc_socket_receive_progress(sock, output, otplen, flag, &pos);

	/* Preserve the legacy all-or-zero contract for existing callers. */
	if (res != qsc_socket_exception_success)
	{
		pos = 0U;
	}

	return pos;
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

uint32_t qsc_socket_receive_poll(const qsc_socket_receive_poll_state* state)
{
	QSC_ASSERT(state != NULL);

	qsc_socket_poll_descriptor stack[QSC_SOCKET_POLL_STACK_CAPACITY];
	qsc_socket_poll_descriptor* fds;
	uint32_t ctr;
	uint32_t active;
	uint32_t i;
	int32_t ready;
	qsc_socket_exceptions pollerr;
	bool allocated;

	ctr = 0U;
	active = 0U;
	allocated = false;
	fds = stack;

	if (state != NULL && state->sockarr != NULL && state->count != 0U)
	{
		if (state->count > QSC_SOCKET_POLL_STACK_CAPACITY)
		{
			if ((uint64_t)state->count * (uint64_t)sizeof(qsc_socket_poll_descriptor) <= (uint64_t)SIZE_MAX)
			{
				fds = (qsc_socket_poll_descriptor*)qsc_memutils_malloc((size_t)state->count * sizeof(qsc_socket_poll_descriptor));
				allocated = (fds != NULL);
			}
			else
			{
				fds = NULL;
			}
		}

		if (fds != NULL)
		{
			for (i = 0U; i < state->count; ++i)
			{
				fds[i].events = POLLIN;
				fds[i].revents = 0;

				if (state->sockarr[i] != NULL && qsc_socket_is_connected(state->sockarr[i]))
				{
					fds[i].fd = state->sockarr[i]->connection;
					++active;
				}
				else
				{
#if defined(QSC_SYSTEM_OS_WINDOWS)
					fds[i].fd = INVALID_SOCKET;
#else
					fds[i].fd = -1;
#endif
					if (state->error != NULL)
					{
						state->error(state->sockarr[i], qsc_socket_exception_error);
					}
				}
			}

			ready = 0;

			if (active != 0U)
			{
#if defined(QSC_SYSTEM_OS_WINDOWS)
				ready = WSAPoll(fds, (ULONG)state->count, -1);
#else
				ready = poll(fds, (nfds_t)state->count, -1);
#endif
			}

			if (ready > 0)
			{
				for (i = 0U; i < state->count; ++i)
				{
					if ((fds[i].revents & POLLIN) != 0 && state->callback != NULL)
					{
						state->callback(state->sockarr[i], (size_t)i);
						++ctr;
					}
					else if ((fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 && state->error != NULL)
					{
						state->error(state->sockarr[i], qsc_socket_exception_error);
					}
				}
			}
			else if (ready < 0 && state->error != NULL)
			{
				pollerr = qsc_socket_get_last_error();

				for (i = 0U; i < state->count; ++i)
				{
#if defined(QSC_SYSTEM_OS_WINDOWS)
					if (fds[i].fd != INVALID_SOCKET)
#else
					if (fds[i].fd >= 0)
#endif
					{
						state->error(state->sockarr[i], pollerr);
					}
				}
			}
		}

		if (fds == NULL)
		{
			qsc_socket_set_last_error(qsc_socket_exception_no_buffer_space);
		}

		if (allocated == true)
		{
			qsc_memutils_alloc_free(fds);
		}
	}

	return ctr;
}

size_t qsc_socket_receive_timeout(const qsc_socket* sock, uint8_t* output, size_t otplen, qsc_socket_receive_flags flag, int32_t timeout)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(timeout >= 0);

	qsc_socket_exceptions oerr;
	qsc_socket_exceptions rerr;
	qsc_socket_exceptions serr;
	int32_t oldtm;
	size_t mlen;

	mlen = 0U;
	oldtm = 0;

	if (sock != NULL && output != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET && timeout >= 0)
	{
		oerr = qsc_socket_get_option(sock, qsc_socket_protocol_socket, qsc_socket_option_receive_time_out, &oldtm);

		if (oerr == qsc_socket_exception_success)
		{
			serr = qsc_socket_set_option(sock, qsc_socket_protocol_socket, qsc_socket_option_receive_time_out, timeout);

			if (serr == qsc_socket_exception_success)
			{
				/* clear any stale socket error before receiving so that a
				 * zero return can be distinguished from a receive failure. */
				qsc_socket_set_last_error(qsc_socket_exception_success);

				mlen = qsc_socket_receive(sock, output, otplen, flag);
				rerr = qsc_socket_get_last_error();

				/* always restore the receive timeout that was configured before this operation. */
				serr = qsc_socket_set_option(sock, qsc_socket_protocol_socket, qsc_socket_option_receive_time_out, oldtm);

				if (serr == qsc_socket_exception_success)
				{
					/* restoring the option can modify the platform socket error state. Restore the error generated by receive. */
					qsc_socket_set_last_error(rerr);
				}
				else
				{
					qsc_socket_set_last_error(serr);
				}
			}
			else
			{
				qsc_socket_set_last_error(serr);
			}
		}
		else
		{
			qsc_socket_set_last_error(oerr);
		}
	}
	else
	{
		qsc_socket_set_last_error(qsc_socket_invalid_input);
	}

	return mlen;
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
#if defined(QSC_SYSTEM_OS_POSIX)
		res = send(sock->connection, (const char*)input, slen, socketbase_send_flags(flag));
#else
		res = send(sock->connection, (const char*)input, slen, (int32_t)flag);
#endif
		res = (res == qsc_socket_exception_error) ? 0 : res;
	}

	return (size_t)res;
}

size_t qsc_socket_send_to(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(input != NULL);

	struct sockaddr_in d4;
	struct sockaddr_in6 d6;
	int32_t res;
	int32_t slen;
	int32_t parsed;

	res = 0;

	if (sock != NULL && input != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
		slen = (inplen > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)inplen;

		if (sock->address_family == qsc_socket_address_family_ipv4)
		{
			qsc_memutils_clear(&d4, sizeof(d4));
			d4.sin_family = AF_INET;
			d4.sin_port = htons(sock->port);
			parsed = inet_pton(AF_INET, (const char*)sock->address, &d4.sin_addr);

			if (parsed == 1)
			{
#if defined(QSC_SYSTEM_OS_POSIX)
				res = sendto(sock->connection, (const char*)input, slen, socketbase_send_flags(flag), (struct sockaddr*)&d4, (socklen_t)sizeof(d4));
#else
				res = sendto(sock->connection, (const char*)input, slen, (int32_t)flag, (struct sockaddr*)&d4, (socklen_t)sizeof(d4));
#endif
			}
			else
			{
				qsc_socket_set_last_error(qsc_socket_invalid_input);
			}
		}
		else if (sock->address_family == qsc_socket_address_family_ipv6)
		{
			qsc_memutils_clear(&d6, sizeof(d6));
			d6.sin6_family = AF_INET6;
			d6.sin6_port = htons(sock->port);
			parsed = inet_pton(AF_INET6, (const char*)sock->address, &d6.sin6_addr);

			if (parsed == 1)
			{
#if defined(QSC_SYSTEM_OS_POSIX)
				res = sendto(sock->connection, (const char*)input, slen, socketbase_send_flags(flag), (struct sockaddr*)&d6, (socklen_t)sizeof(d6));
#else
				res = sendto(sock->connection, (const char*)input, slen, (int32_t)flag, (struct sockaddr*)&d6, (socklen_t)sizeof(d6));
#endif
			}
			else
			{
				qsc_socket_set_last_error(qsc_socket_invalid_input);
			}
		}
		else
		{
			qsc_socket_set_last_error(qsc_socket_invalid_input);
		}
	}
	else
	{
		qsc_socket_set_last_error(qsc_socket_invalid_input);
	}

	res = (res == qsc_socket_exception_error) ? 0 : res;

	return (size_t)res;
}

size_t qsc_socket_send_vectored(const qsc_socket* sock, const qsc_socket_const_buffer* buffers, size_t count, qsc_socket_send_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(buffers != NULL);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSABUF vec[QSC_SOCKET_IOV_MAX_BUFFERS];
	DWORD transferred;
	int32_t status;
#else
	struct iovec vec[QSC_SOCKET_IOV_MAX_BUFFERS];
	struct msghdr msg;
	ssize_t nsend;
#endif
	size_t res;
	size_t i;
	bool valid;

	res = 0U;
	valid = (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET && buffers != NULL && count > 0U && count <= QSC_SOCKET_IOV_MAX_BUFFERS);

	if (valid == true)
	{
		for (i = 0U; i < count; ++i)
		{
			if (buffers[i].data == NULL || buffers[i].length > (size_t)INT32_MAX)
			{
				valid = false;
				break;
			}
		}
	}

	if (valid == true)
	{
		qsc_socket_set_last_error(qsc_socket_exception_success);
#if defined(QSC_SYSTEM_OS_WINDOWS)
		transferred = 0U;

		for (i = 0U; i < count; ++i)
		{
			vec[i].buf = (CHAR*)buffers[i].data;
			vec[i].len = (ULONG)buffers[i].length;
		}

		status = WSASend(sock->connection, vec, (DWORD)count, &transferred, (DWORD)flag, NULL, NULL);

		if (status == 0)
		{
			res = (size_t)transferred;
		}
#else
		qsc_memutils_clear(&msg, sizeof(msg));

		for (i = 0U; i < count; ++i)
		{
			vec[i].iov_base = (void*)buffers[i].data;
			vec[i].iov_len = buffers[i].length;
		}

		msg.msg_iov = vec;
		msg.msg_iovlen = count;
		nsend = sendmsg(sock->connection, &msg, socketbase_send_flags(flag));

		if (nsend >= 0)
		{
			res = (size_t)nsend;
		}
#endif
	}
	else
	{
		qsc_socket_set_last_error(qsc_socket_invalid_input);
	}

	return res;
}

size_t qsc_socket_receive_vectored(const qsc_socket* sock, const qsc_socket_buffer* buffers, size_t count, qsc_socket_receive_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(buffers != NULL);

#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSABUF vec[QSC_SOCKET_IOV_MAX_BUFFERS];
	DWORD transferred;
	DWORD wflags;
	int32_t status;
#else
	struct iovec vec[QSC_SOCKET_IOV_MAX_BUFFERS];
	struct msghdr msg;
	ssize_t nread;
#endif
	size_t res;
	size_t i;
	bool valid;

	res = 0U;
	valid = (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET && buffers != NULL && count > 0U && count <= QSC_SOCKET_IOV_MAX_BUFFERS);

	if (valid == true)
	{
		for (i = 0U; i < count; ++i)
		{
			if (buffers[i].data == NULL || buffers[i].length > (size_t)INT32_MAX)
			{
				valid = false;
				break;
			}
		}
	}

	if (valid == true)
	{
		qsc_socket_set_last_error(qsc_socket_exception_success);
#if defined(QSC_SYSTEM_OS_WINDOWS)
		transferred = 0U;
		wflags = (DWORD)flag;

		for (i = 0U; i < count; ++i)
		{
			vec[i].buf = (CHAR*)buffers[i].data;
			vec[i].len = (ULONG)buffers[i].length;
		}

		status = WSARecv(sock->connection, vec, (DWORD)count, &transferred, &wflags, NULL, NULL);

		if (status == 0)
		{
			res = (size_t)transferred;
		}
#else
		qsc_memutils_clear(&msg, sizeof(msg));

		for (i = 0U; i < count; ++i)
		{
			vec[i].iov_base = buffers[i].data;
			vec[i].iov_len = buffers[i].length;
		}

		msg.msg_iov = vec;
		msg.msg_iovlen = count;
		nread = recvmsg(sock->connection, &msg, (int32_t)flag);

		if (nread >= 0)
		{
			res = (size_t)nread;
		}
#endif
	}
	else
	{
		qsc_socket_set_last_error(qsc_socket_invalid_input);
	}

	return res;
}

qsc_socket_exceptions qsc_socket_send_progress(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag, size_t* sent)
{
	qsc_socket_exceptions res;
	int32_t chunk;
	int32_t nsent;
	size_t pos;

	res = qsc_socket_invalid_input;
	pos = 0U;

	if (sent != NULL)
	{
		*sent = 0U;
	}

	if (sock != NULL && input != NULL && sent != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
		res = qsc_socket_exception_success;

		while (pos < inplen)
		{
			chunk = ((inplen - pos) > (size_t)INT32_MAX) ? INT32_MAX : (int32_t)(inplen - pos);
#if defined(QSC_SYSTEM_OS_POSIX)
			nsent = send(sock->connection, (const char*)(input + pos), chunk, socketbase_send_flags(flag));
#else
			nsent = send(sock->connection, (const char*)(input + pos), chunk, (int32_t)flag);
#endif
			if (nsent > 0)
			{
				pos += (size_t)nsent;
			}
			else if (nsent == 0)
			{
				res = qsc_socket_exception_not_connected;
				break;
			}
			else
			{
				res = qsc_socket_get_last_error();
#if defined(QSC_SYSTEM_OS_POSIX)
				if (res == qsc_socket_exception_blocking_cancelled)
				{
					res = qsc_socket_exception_success;
					continue;
				}
#endif
				break;
			}
		}
	}

	if (sent != NULL)
	{
		*sent = pos;
	}

	return res;
}

size_t qsc_socket_send_all(const qsc_socket* sock, const uint8_t* input, size_t inplen, qsc_socket_send_flags flag)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(input != NULL);

	qsc_socket_exceptions res;
	size_t pos;

	pos = 0U;
	res = qsc_socket_send_progress(sock, input, inplen, flag, &pos);

	/* Preserve the legacy all-or-zero contract for existing callers. */
	if (res != qsc_socket_exception_success)
	{
		pos = 0U;
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
		if (sock->connection != QSC_UNINITIALIZED_SOCKET && sock->connection != QSC_SOCKET_RET_ERROR)
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

qsc_socket_exceptions qsc_socket_get_option(const qsc_socket* sock, qsc_socket_protocols level, qsc_socket_options option, int32_t* optval)
{
	QSC_ASSERT(sock != NULL);
	QSC_ASSERT(optval != NULL);

	qsc_socket_exceptions res;

	res = qsc_socket_invalid_input;

	if (sock != NULL && optval != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET && level != qsc_socket_protocol_none && option != qsc_socket_option_none)
	{
		*optval = 0;

#if defined(QSC_SYSTEM_OS_POSIX)
		if (option == qsc_socket_option_receive_time_out || option == qsc_socket_option_send_time_out)
		{
			struct timeval tval;
			socklen_t slen;
			uint64_t msec;

			tval.tv_sec = 0;
			tval.tv_usec = 0;
			slen = (socklen_t)sizeof(tval);

			res = (qsc_socket_exceptions)getsockopt(sock->connection, (int32_t)level, (int32_t)option, (char*)&tval, &slen);

			if (res != qsc_socket_exception_error)
			{
				msec = ((uint64_t)tval.tv_sec * 1000ULL) + ((uint64_t)tval.tv_usec / 1000ULL);

				*optval = (msec > (uint64_t)INT32_MAX) ? INT32_MAX : (int32_t)msec;
			}
		}
		else
#endif
			if (option == qsc_socket_option_linger)
			{
				struct linger lval;
				socklen_t slen;

				lval.l_onoff = 0;
				lval.l_linger = 0;
				slen = (socklen_t)sizeof(lval);

				res = (qsc_socket_exceptions)getsockopt(sock->connection, (int32_t)level, (int32_t)option, (char*)&lval, &slen);

				if (res != qsc_socket_exception_error)
				{
					*optval = (lval.l_onoff != 0) ? (int32_t)lval.l_linger : 0;
				}
			}
			else
			{
				int32_t val;
				socklen_t slen;

				val = 0;
				slen = (socklen_t)sizeof(val);

				res = (qsc_socket_exceptions)getsockopt(sock->connection, (int32_t)level, (int32_t)option, (char*)&val, &slen);

				if (res != qsc_socket_exception_error)
				{
					*optval = val;
				}
			}

		if (res == qsc_socket_exception_error)
		{
			res = qsc_socket_get_last_error();
		}
	}

	return res;
}

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

qsc_socket_exceptions qsc_socket_get_last_error(void)
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

/*!
 * \brief Convert a finite timeval to a bounded poll timeout, rounding sub-milliseconds upward.
 * \param timeout Valid non-NULL timeval with non-negative components.
 * \return Rounded milliseconds, saturated to INT32_MAX.
 * \details No allocation or shared state; safe for concurrent callers.
 */
#if defined(QSC_SYSTEM_OS_POSIX)
static int32_t socketbase_poll_timeout(const struct timeval* timeout)
{
	uint64_t msecs;
	int32_t res;

	msecs = (timeout->tv_sec >= ((int64_t)INT32_MAX / 1000LL)) ? (uint64_t)INT32_MAX : (((uint64_t)timeout->tv_sec * 1000ULL) + (((uint64_t)timeout->tv_usec + 999ULL) / 1000ULL));
	res = (msecs > (uint64_t)INT32_MAX) ? INT32_MAX : (int32_t)msecs;

	return res;
}
#endif

bool qsc_socket_receive_ready(const qsc_socket* sock, const struct timeval* timeout)
{
	QSC_ASSERT(sock != NULL);

#if defined(QSC_SYSTEM_OS_POSIX)
	struct pollfd fd;
	int32_t msecs;
	int32_t rc;
#else
	fd_set fds;
	struct timeval tcopy;
	struct timeval* ptimeout;
	int32_t rc;
#endif
	bool res;

	res = false;

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
#if defined(QSC_SYSTEM_OS_POSIX)

		if (timeout == NULL || (timeout->tv_sec >= 0 && timeout->tv_usec >= 0 && timeout->tv_usec < 1000000))
		{
			fd.fd = sock->connection;
			fd.events = POLLIN;
			fd.revents = 0;
			msecs = (timeout == NULL) ? -1 : socketbase_poll_timeout(timeout);
			rc = poll(&fd, 1U, msecs);
			res = (rc > 0 && (fd.revents & POLLIN) != 0);
		}
#else

		FD_ZERO(&fds);
		FD_SET(sock->connection, &fds);
		ptimeout = NULL;

		if (timeout != NULL)
		{
			tcopy = *timeout;
			ptimeout = &tcopy;
		}

		rc = select(0, &fds, NULL, NULL, ptimeout);
		res = (rc > 0);
#endif
	}

	return res;
}

bool qsc_socket_send_ready(const qsc_socket* sock, const struct timeval* timeout)
{
	QSC_ASSERT(sock != NULL);

#if defined(QSC_SYSTEM_OS_POSIX)
	struct pollfd fd;
	int32_t msecs;
	int32_t rc;
#else
	fd_set fds;
	struct timeval tcopy;
	struct timeval* ptimeout;
	int32_t rc;
#endif
	bool res;

	res = false;

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
#if defined(QSC_SYSTEM_OS_POSIX)

		if (timeout == NULL || (timeout->tv_sec >= 0 && timeout->tv_usec >= 0 && timeout->tv_usec < 1000000))
		{
			fd.fd = sock->connection;
			fd.events = POLLOUT;
			fd.revents = 0;
			msecs = (timeout == NULL) ? -1 : socketbase_poll_timeout(timeout);
			rc = poll(&fd, 1U, msecs);
			res = (rc > 0 && (fd.revents & POLLOUT) != 0);
		}
#else

		FD_ZERO(&fds);
		FD_SET(sock->connection, &fds);
		ptimeout = NULL;

		if (timeout != NULL)
		{
			tcopy = *timeout;
			ptimeout = &tcopy;
		}

		rc = select(0, NULL, &fds, NULL, ptimeout);
		res = (rc > 0);
#endif
	}

	return res;
}

void qsc_socket_set_last_error(qsc_socket_exceptions error)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSASetLastError((int32_t)error);
#else
	errno = (int32_t)error;
#endif
}

qsc_socket_exceptions qsc_socket_shut_down_sockets(void)
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

	if (sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
#if defined(QSC_SYSTEM_OS_POSIX)
		if (option == qsc_socket_option_receive_time_out || option == qsc_socket_option_send_time_out)
		{
			struct timeval timeout;

			timeout.tv_sec = optval / 1000;
			timeout.tv_usec = (optval % 1000) * 1000;
			res = (qsc_socket_exceptions)setsockopt(sock->connection, (int32_t)level, (int32_t)option, (void*)&timeout, sizeof(timeout));
		}
		else
		{
			res = (qsc_socket_exceptions)setsockopt(sock->connection, (int32_t)level, (int32_t)option, (void*)&optval, sizeof(optval));
		}
#else
		res = (qsc_socket_exceptions)setsockopt(sock->connection, (int32_t)level, (int32_t)option, (void*)&optval, sizeof(optval));
#endif
	}

	if (res == qsc_socket_exception_error)
	{
		res = qsc_socket_get_last_error();
	}

	return res;
}

bool qsc_socket_start_sockets(void)
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

#if defined(QSC_SYSTEM_OS_POSIX)

#if defined(QSC_SYSTEM_OS_LINUX)
#	include <sys/epoll.h>
#	include <sys/eventfd.h>
#elif defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
#	include <sys/event.h>
#endif

/** \brief Private, per-instance readiness state; socket descriptors are borrowed. */
struct qsc_socket_event_loop
{
#if defined(QSC_SYSTEM_OS_LINUX)
	struct epoll_event* ready;  /*!< Reused kernel event buffer, avoiding allocations during waits. */
	int32_t descriptor;        /*!< Epoll file descriptor. */
	int32_t wake;              /*!< Nonblocking eventfd. */
#elif defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
	struct kevent* ready;      /*!< Reused kernel event buffer. */
	socket_t* registered;      /*!< Registered, caller-owned socket descriptor values. */
	int32_t descriptor;        /*!< Kqueue descriptor. */
#else
	struct pollfd* ready;     /*!< Reused polling descriptors, including wake pipe. */
	socket_t* registered;      /*!< Registered socket descriptors. */
	uint32_t* interests;      /*!< Requested event masks. */
	int32_t wake[2];          /*!< Nonblocking self-pipe descriptors. */
#endif
	size_t capacity;           /*!< Maximum number of registered sockets. */
	size_t count;              /*!< Current number of registered sockets. */
};

#if !defined(QSC_SYSTEM_OS_LINUX)
/** \brief Find a registered descriptor; no simultaneous loop mutation is supported. */
static size_t socket_event_find(const qsc_socket_event_loop* loop, socket_t connection)
{
	size_t i;

	for (i = 0U; i < loop->count; ++i)
	{
		if (loop->registered[i] == connection)
		{
			break;
		}
	}

	return i;
}
#endif

#if defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
/** \brief Set a complete kqueue read/write mask without changing the socket's ownership. */
static bool socket_event_kqueue_set(qsc_socket_event_loop* loop, socket_t connection, uint32_t events)
{
	struct kevent change[2];
	bool res;
	int32_t ret;

	EV_SET(&change[0], (uintptr_t)connection, EVFILT_READ, (uint16_t)(EV_ADD | ((events & qsc_socket_event_read) != 0U ? EV_ENABLE : EV_DISABLE)), 0U, 0, NULL);
	EV_SET(&change[1], (uintptr_t)connection, EVFILT_WRITE, (uint16_t)(EV_ADD | ((events & qsc_socket_event_write) != 0U ? EV_ENABLE : EV_DISABLE)), 0U, 0, NULL);
	ret = kevent(loop->descriptor, change, 2, NULL, 0, NULL);
	res = (ret == 0);

	return res;
}
#endif

qsc_socket_event_loop* qsc_socket_event_loop_create(size_t capacity)
{
	qsc_socket_event_loop* loop;

	loop = NULL;

	if (capacity != 0U && capacity < (size_t)INT32_MAX && capacity <= (SIZE_MAX / sizeof(socket_t)))
	{
		loop = (qsc_socket_event_loop*)qsc_memutils_malloc(sizeof(qsc_socket_event_loop));

		if (loop != NULL)
		{
			qsc_memutils_clear(loop, sizeof(qsc_socket_event_loop));
			loop->capacity = capacity;
#if defined(QSC_SYSTEM_OS_LINUX)
			loop->descriptor = -1;
			loop->wake = -1;

			if (capacity <= ((SIZE_MAX / sizeof(struct epoll_event)) - 1U))
			{
				loop->ready = (struct epoll_event*)qsc_memutils_malloc((capacity + 1U) * sizeof(struct epoll_event));
			}

			if (loop->ready != NULL)
			{
				struct epoll_event ev;

				loop->descriptor = epoll_create1(EPOLL_CLOEXEC);

				if (loop->descriptor >= 0)
				{
					loop->wake = eventfd(0U, EFD_CLOEXEC | EFD_NONBLOCK);
				}

				if (loop->wake >= 0)
				{
					qsc_memutils_clear(&ev, sizeof(ev));
					ev.events = EPOLLIN;
					ev.data.fd = loop->wake;

					if (epoll_ctl(loop->descriptor, EPOLL_CTL_ADD, loop->wake, &ev) != 0)
					{
						close(loop->wake);
						loop->wake = -1;
					}
				}
			}
#elif defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
			loop->descriptor = -1;
			loop->registered = (socket_t*)qsc_memutils_malloc(capacity * sizeof(socket_t));

			if (capacity <= ((SIZE_MAX / sizeof(struct kevent)) - 1U))
			{
				loop->ready = (struct kevent*)qsc_memutils_malloc((capacity + 1U) * sizeof(struct kevent));
			}

			if (loop->registered != NULL && loop->ready != NULL)
			{
				struct kevent change;

				loop->descriptor = kqueue();

				if (loop->descriptor >= 0)
				{
					EV_SET(&change, 1U, EVFILT_USER, EV_ADD | EV_CLEAR, 0U, 0, NULL);

					if (fcntl(loop->descriptor, F_SETFD, FD_CLOEXEC) != 0 ||
						kevent(loop->descriptor, &change, 1, NULL, 0, NULL) != 0)
					{
						close(loop->descriptor);
						loop->descriptor = -1;
					}
				}
			}
#else
			loop->wake[0] = -1;
			loop->wake[1] = -1;
			loop->registered = (socket_t*)qsc_memutils_malloc(capacity * sizeof(socket_t));
			loop->interests = (uint32_t*)qsc_memutils_malloc(capacity * sizeof(uint32_t));

			if (capacity <= ((SIZE_MAX / sizeof(struct pollfd)) - 1U))
			{
				loop->ready = (struct pollfd*)qsc_memutils_malloc((capacity + 1U) * sizeof(struct pollfd));
			}

			if (loop->registered != NULL && loop->interests != NULL && loop->ready != NULL)
			{
				if (pipe(loop->wake) == 0)
				{
					if (fcntl(loop->wake[0], F_SETFD, FD_CLOEXEC) != 0 ||
						fcntl(loop->wake[1], F_SETFD, FD_CLOEXEC) != 0 ||
						fcntl(loop->wake[0], F_SETFL, O_NONBLOCK) != 0 ||
						fcntl(loop->wake[1], F_SETFL, O_NONBLOCK) != 0)
					{
						(void)close(loop->wake[0]);
						(void)close(loop->wake[1]);
						loop->wake[0] = -1;
						loop->wake[1] = -1;
					}
				}
			}
#endif

#if defined(QSC_SYSTEM_OS_LINUX)
			if (loop->descriptor < 0 || loop->wake < 0 || loop->ready == NULL)
#elif defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
			if (loop->descriptor < 0 || loop->registered == NULL || loop->ready == NULL)
#else
			if (loop->wake[0] < 0 || loop->wake[1] < 0 || loop->registered == NULL || loop->interests == NULL || loop->ready == NULL)
#endif
			{
				qsc_socket_event_loop_destroy(loop);
				loop = NULL;
			}
		}
	}

	return loop;
}

bool qsc_socket_event_loop_register(qsc_socket_event_loop* loop, const qsc_socket* sock, uint32_t events)
{
	bool res;

	res = false;

	if (loop != NULL && sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET &&
		(events & (uint32_t)(qsc_socket_event_read | qsc_socket_event_write)) != 0U &&
		(events & (uint32_t)~(qsc_socket_event_read | qsc_socket_event_write)) == 0U && loop->count < loop->capacity)
	{
#if defined(QSC_SYSTEM_OS_LINUX)
		struct epoll_event ev;

		qsc_memutils_clear(&ev, sizeof(ev));
		ev.events = ((events & qsc_socket_event_read) != 0U ? EPOLLIN : 0U) | ((events & qsc_socket_event_write) != 0U ? EPOLLOUT : 0U) | EPOLLRDHUP;
		ev.data.fd = sock->connection;
		res = (epoll_ctl(loop->descriptor, EPOLL_CTL_ADD, sock->connection, &ev) == 0);
#else
		if (socket_event_find(loop, sock->connection) == loop->count)
		{
#if defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
			res = socket_event_kqueue_set(loop, sock->connection, events);
#else
			res = true;
			loop->interests[loop->count] = events;
#endif
			if (res == true)
			{
				loop->registered[loop->count] = sock->connection;
			}
		}
#endif
		if (res == true)
		{
			++loop->count;
		}
	}

	return res;
}

bool qsc_socket_event_loop_modify(qsc_socket_event_loop* loop, const qsc_socket* sock, uint32_t events)
{
	bool res;

	res = false;

	if (loop != NULL && sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET &&
		(events & (uint32_t)(qsc_socket_event_read | qsc_socket_event_write)) != 0U &&
		(events & (uint32_t)~(qsc_socket_event_read | qsc_socket_event_write)) == 0U)
	{
#if defined(QSC_SYSTEM_OS_LINUX)
		struct epoll_event ev;

		qsc_memutils_clear(&ev, sizeof(ev));
		ev.events = ((events & qsc_socket_event_read) != 0U ? EPOLLIN : 0U) | ((events & qsc_socket_event_write) != 0U ? EPOLLOUT : 0U) | EPOLLRDHUP;
		ev.data.fd = sock->connection;
		res = (epoll_ctl(loop->descriptor, EPOLL_CTL_MOD, sock->connection, &ev) == 0);
#else
		size_t pos;

		pos = socket_event_find(loop, sock->connection);

		if (pos < loop->count)
		{
#if defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
			res = socket_event_kqueue_set(loop, sock->connection, events);
#else
			loop->interests[pos] = events;
			res = true;
#endif
		}
#endif
	}

	return res;
}

bool qsc_socket_event_loop_unregister(qsc_socket_event_loop* loop, const qsc_socket* sock)
{
	bool res;

	res = false;

	if (loop != NULL && sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
#if defined(QSC_SYSTEM_OS_LINUX)
		res = (epoll_ctl(loop->descriptor, EPOLL_CTL_DEL, sock->connection, NULL) == 0);
#else
		size_t pos;

		pos = socket_event_find(loop, sock->connection);

		if (pos < loop->count)
		{
#if defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
			struct kevent change[2];

			EV_SET(&change[0], (uintptr_t)sock->connection, EVFILT_READ, EV_DELETE, 0U, 0, NULL);
			EV_SET(&change[1], (uintptr_t)sock->connection, EVFILT_WRITE, EV_DELETE, 0U, 0, NULL);
			res = (kevent(loop->descriptor, change, 2, NULL, 0, NULL) == 0);
#else
			res = true;
			loop->interests[pos] = loop->interests[loop->count - 1U];
#endif
			if (res == true)
			{
				loop->registered[pos] = loop->registered[loop->count - 1U];
			}
		}
#endif
		if (res == true)
		{
			--loop->count;
		}
	}

	return res;
}

int32_t qsc_socket_event_loop_wait(qsc_socket_event_loop* loop, qsc_socket_event* output, size_t capacity, int32_t timeout_ms)
{
	int32_t res;

	res = -1;

	if (loop != NULL && output != NULL && capacity != 0U && capacity < (size_t)INT32_MAX && timeout_ms >= -1)
	{
		int32_t count;
		int32_t limit;
		int32_t i;
		int32_t used;

		limit = (int32_t)((capacity < loop->capacity) ? capacity : loop->capacity);
		++limit;
#if defined(QSC_SYSTEM_OS_LINUX)
		count = epoll_wait(loop->descriptor, loop->ready, limit, timeout_ms);
#elif defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
		struct timespec ts;
		struct timespec* pts;

		pts = NULL;

		if (timeout_ms >= 0)
		{
			ts.tv_sec = (time_t)(timeout_ms / 1000);
			ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
			pts = &ts;
		}

		count = kevent(loop->descriptor, NULL, 0, loop->ready, limit, pts);
#else
		loop->ready[0].fd = loop->wake[0];
		loop->ready[0].events = POLLIN;
		loop->ready[0].revents = 0;

		for (i = 0; i < (int32_t)loop->count; ++i)
		{
			loop->ready[i + 1].fd = loop->registered[i];
			loop->ready[i + 1].events = (short)(((loop->interests[i] & qsc_socket_event_read) != 0U ? POLLIN : 0) |
				((loop->interests[i] & qsc_socket_event_write) != 0U ? POLLOUT : 0));
			loop->ready[i + 1].revents = 0;
		}

		count = poll(loop->ready, (nfds_t)(loop->count + 1U), timeout_ms);
#endif
		used = 0;

		if (count >= 0)
		{
#if !defined(QSC_SYSTEM_OS_LINUX) && !defined(QSC_SYSTEM_OS_MAC) && !defined(QSC_SYSTEM_OS_BSD)
			limit = (int32_t)loop->count + 1;
#else
			limit = count;
#endif
			for (i = 0; i < limit && (size_t)used < capacity; ++i)
			{
				uint32_t events;
				socket_t connection;

				events = 0U;
#if defined(QSC_SYSTEM_OS_LINUX)
				connection = loop->ready[i].data.fd;

				if ((loop->ready[i].events & EPOLLIN) != 0U)
				{
					events |= qsc_socket_event_read;
				}
				if ((loop->ready[i].events & EPOLLOUT) != 0U)
				{
					events |= qsc_socket_event_write;
				}
				if ((loop->ready[i].events & EPOLLERR) != 0U)
				{
					events |= qsc_socket_event_error;
				}
				if ((loop->ready[i].events & (EPOLLRDHUP | EPOLLHUP)) != 0U)
				{
					events |= qsc_socket_event_hangup;
				}
				if (connection == loop->wake)
				{
					uint64_t value;

					(void)read(loop->wake, &value, sizeof(value));
					connection = QSC_UNINITIALIZED_SOCKET;
					events = qsc_socket_event_wakeup;
				}
#elif defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
				connection = (socket_t)loop->ready[i].ident;

				if (loop->ready[i].filter == EVFILT_READ)
				{
					events |= qsc_socket_event_read;
				}
				if (loop->ready[i].filter == EVFILT_WRITE)
				{
					events |= qsc_socket_event_write;
				}
				if ((loop->ready[i].flags & EV_ERROR) != 0U)
				{
					events |= qsc_socket_event_error;
				}
				if ((loop->ready[i].flags & EV_EOF) != 0U)
				{
					events |= qsc_socket_event_hangup;
				}
				if (loop->ready[i].filter == EVFILT_USER)
				{
					connection = QSC_UNINITIALIZED_SOCKET;
					events = qsc_socket_event_wakeup;
				}
#else
				connection = loop->ready[i].fd;

				if ((loop->ready[i].revents & POLLIN) != 0)
				{
					events |= qsc_socket_event_read;
				}
				if ((loop->ready[i].revents & POLLOUT) != 0)
				{
					events |= qsc_socket_event_write;
				}
				if ((loop->ready[i].revents & (POLLERR | POLLNVAL)) != 0)
				{
					events |= qsc_socket_event_error;
				}
				if ((loop->ready[i].revents & POLLHUP) != 0)
				{
					events |= qsc_socket_event_hangup;
				}
				if (connection == loop->wake[0] && events != 0U)
				{
					uint8_t discard[64];

					while (read(loop->wake[0], discard, sizeof(discard)) > 0)
					{
					}

					connection = QSC_UNINITIALIZED_SOCKET;
					events = qsc_socket_event_wakeup;
				}
#endif
				if (events != 0U)
				{
					output[used].connection = connection;
					output[used].events = events;
					++used;
				}
			}

			res = used;
		}
		else if (errno == EINTR)
		{
			res = 0;
		}
	}

	return res;
}

bool qsc_socket_event_loop_wake(qsc_socket_event_loop* loop)
{
	bool res;

	res = false;

	if (loop != NULL)
	{
#if defined(QSC_SYSTEM_OS_LINUX)
		uint64_t value;
		ssize_t written;

		value = 1U;
		written = write(loop->wake, &value, sizeof(value));
		res = (written == (ssize_t)sizeof(value) || (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)));
#elif defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
		struct kevent change;

		EV_SET(&change, 1U, EVFILT_USER, 0U, NOTE_TRIGGER, 0, NULL);
		res = (kevent(loop->descriptor, &change, 1, NULL, 0, NULL) == 0);
#else
		uint8_t value;
		ssize_t written;

		value = 1U;
		written = write(loop->wake[1], &value, sizeof(value));
		res = (written == (ssize_t)sizeof(value) || (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)));
#endif
	}

	return res;
}

void qsc_socket_event_loop_destroy(qsc_socket_event_loop* loop)
{
	if (loop != NULL)
	{
#if defined(QSC_SYSTEM_OS_LINUX)
		if (loop->wake >= 0)
		{
			(void)close(loop->wake);
		}
		if (loop->descriptor >= 0)
		{
			(void)close(loop->descriptor);
		}
		qsc_memutils_alloc_free(loop->ready);
#elif defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)
		if (loop->descriptor >= 0)
		{
			(void)close(loop->descriptor);
		}
		qsc_memutils_alloc_free(loop->registered);
		qsc_memutils_alloc_free(loop->ready);
#else
		if (loop->wake[0] >= 0)
		{
			(void)close(loop->wake[0]);
		}
		if (loop->wake[1] >= 0)
		{
			(void)close(loop->wake[1]);
		}
		qsc_memutils_alloc_free(loop->registered);
		qsc_memutils_alloc_free(loop->interests);
		qsc_memutils_alloc_free(loop->ready);
#endif
		qsc_memutils_alloc_free(loop);
	}
}

#endif

#if defined(QSC_SYSTEM_OS_WINDOWS)

#if !defined(WIN32_LEAN_AND_MEAN)
#	define WIN32_LEAN_AND_MEAN
#endif
#if !defined(NOMINMAX)
#	define NOMINMAX
#endif
#include <windows.h>

/** \brief Private Windows IOCP context; pending is modified atomically. */
struct qsc_socket_iocp
{
	HANDLE descriptor;           /*!< Owned completion port handle. */
	volatile LONG pending;      /*!< Outstanding overlapped requests. */
	LONG limit;                 /*!< Maximum outstanding requests. */
};

/** \brief Owned overlapped request, retained until its completion is dequeued. */
typedef struct
{
	OVERLAPPED overlapped;      /*!< First field: pointer received from GetQueuedCompletionStatus. */
	WSABUF span;                /*!< Original caller-owned buffer span, retained during the operation. */
	socket_t connection;       /*!< Socket descriptor supplied by caller. */
	uint64_t context;          /*!< Caller-defined completion identifier. */
	qsc_socket_iocp_operation operation; /*!< Requested operation type. */
} qsc_socket_iocp_request;

/** \brief Reserve a bounded pending-operation slot before submitting an overlapped I/O request. */
static bool socket_iocp_reserve(qsc_socket_iocp* port)
{
	bool res;
	LONG value;

	res = false;
	value = InterlockedCompareExchange(&port->pending, 0L, 0L);

	while (value < port->limit)
	{
		if (InterlockedCompareExchange(&port->pending, value + 1L, value) == value)
		{
			res = true;
			break;
		}

		value = InterlockedCompareExchange(&port->pending, 0L, 0L);
	}

	return res;
}

/** \brief Submit a bounded overlapped transfer; no completion is produced on immediate failure. */
static bool socket_iocp_submit(qsc_socket_iocp* port, const qsc_socket* sock, const uint8_t* buffer, size_t length, uint64_t context, qsc_socket_iocp_operation operation)
{
	qsc_socket_iocp_request* req;
	DWORD transferred;
	DWORD flags;
	bool res;
	int32_t ret;

	res = false;

	if (port != NULL && sock != NULL && buffer != NULL && length != 0U && length <= (size_t)UINT32_MAX &&
		sock->connection != QSC_UNINITIALIZED_SOCKET && socket_iocp_reserve(port) == true)
	{
		req = (qsc_socket_iocp_request*)qsc_memutils_malloc(sizeof(qsc_socket_iocp_request));

		if (req != NULL)
		{
			qsc_memutils_clear(req, sizeof(qsc_socket_iocp_request));
			req->span.buf = (CHAR*)(void*)buffer;
			req->span.len = (ULONG)length;
			req->connection = sock->connection;
			req->context = context;
			req->operation = operation;
			transferred = 0UL;
			flags = 0UL;

			if (operation == qsc_socket_iocp_receive)
			{
				ret = WSARecv((SOCKET)sock->connection, &req->span, 1UL, &transferred, &flags, (LPWSAOVERLAPPED)&req->overlapped, NULL);
			}
			else
			{
				ret = WSASend((SOCKET)sock->connection, &req->span, 1UL, &transferred, 0UL, (LPWSAOVERLAPPED)&req->overlapped, NULL);
			}

			res = (ret == 0 || WSAGetLastError() == WSA_IO_PENDING);

			if (res == false)
			{
				qsc_memutils_alloc_free(req);
			}
		}

		if (res == false)
		{
			(void)InterlockedDecrement(&port->pending);
		}
	}

	return res;
}

qsc_socket_iocp* qsc_socket_iocp_create(uint32_t max_pending)
{
	qsc_socket_iocp* port;

	port = NULL;

	if (max_pending != 0U && max_pending <= 0x7FFFFFFFU)
	{
		port = (qsc_socket_iocp*)qsc_memutils_malloc(sizeof(qsc_socket_iocp));

		if (port != NULL)
		{
			qsc_memutils_clear(port, sizeof(qsc_socket_iocp));
			port->descriptor = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, (ULONG_PTR)0U, 0UL);
			port->limit = (LONG)max_pending;

			if (port->descriptor == NULL)
			{
				qsc_memutils_alloc_free(port);
				port = NULL;
			}
		}
	}

	return port;
}

bool qsc_socket_iocp_attach(qsc_socket_iocp* port, const qsc_socket* sock)
{
	bool res;

	res = false;

	if (port != NULL && sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
		res = (CreateIoCompletionPort((HANDLE)(uintptr_t)sock->connection, port->descriptor, (ULONG_PTR)1U, 0UL) == port->descriptor);
	}

	return res;
}

bool qsc_socket_iocp_submit_receive(qsc_socket_iocp* port, const qsc_socket* sock, uint8_t* buffer, size_t length, uint64_t context)
{
	return socket_iocp_submit(port, sock, buffer, length, context, qsc_socket_iocp_receive);
}

bool qsc_socket_iocp_submit_send(qsc_socket_iocp* port, const qsc_socket* sock, const uint8_t* buffer, size_t length, uint64_t context)
{
	return socket_iocp_submit(port, sock, buffer, length, context, qsc_socket_iocp_send);
}

int32_t qsc_socket_iocp_wait(qsc_socket_iocp* port, qsc_socket_iocp_result* result, int32_t timeout_ms)
{
	qsc_socket_iocp_request* req;
	OVERLAPPED* overlapped;
	ULONG_PTR key;
	DWORD transferred;
	DWORD error;
	BOOL ok;
	int32_t res;

	res = -1;

	if (port != NULL && result != NULL && timeout_ms >= -1)
	{
		qsc_memutils_clear(result, sizeof(qsc_socket_iocp_result));
		transferred = 0UL;
		key = (ULONG_PTR)0U;
		overlapped = NULL;
		ok = GetQueuedCompletionStatus(port->descriptor, &transferred, &key, &overlapped, (timeout_ms < 0) ? INFINITE : (DWORD)timeout_ms);
		error = (ok == FALSE) ? GetLastError() : ERROR_SUCCESS;

		if (overlapped != NULL)
		{
			req = (qsc_socket_iocp_request*)overlapped;
			result->connection = req->connection;
			result->context = req->context;
			result->transferred = (size_t)transferred;
			result->error = error;
			result->operation = req->operation;
			qsc_memutils_alloc_free(req);
			(void)InterlockedDecrement(&port->pending);
			res = 1;
		}
		else if (ok == TRUE && key == (ULONG_PTR)0U)
		{
			result->connection = QSC_UNINITIALIZED_SOCKET;
			result->operation = qsc_socket_iocp_wakeup;
			res = 1;
		}
		else if (error == WAIT_TIMEOUT)
		{
			res = 0;
		}
	}

	return res;
}

bool qsc_socket_iocp_wake(qsc_socket_iocp* port)
{
	bool res;

	res = false;

	if (port != NULL)
	{
		res = (PostQueuedCompletionStatus(port->descriptor, 0UL, (ULONG_PTR)0U, NULL) != FALSE);
	}

	return res;
}

bool qsc_socket_iocp_cancel(qsc_socket_iocp* port, const qsc_socket* sock)
{
	bool res;

	res = false;

	if (port != NULL && sock != NULL && sock->connection != QSC_UNINITIALIZED_SOCKET)
	{
		res = (CancelIoEx((HANDLE)(uintptr_t)sock->connection, NULL) != FALSE);

		if (res == false)
		{
			res = (GetLastError() == ERROR_NOT_FOUND);
		}
	}

	return res;
}

bool qsc_socket_iocp_destroy(qsc_socket_iocp* port)
{
	bool res;

	res = (port == NULL);

	if (port != NULL && InterlockedCompareExchange(&port->pending, 0L, 0L) == 0L)
	{
		if (CloseHandle(port->descriptor) != FALSE)
		{
			qsc_memutils_alloc_free(port);
			res = true;
		}
	}

	return res;
}

#endif
