#include "netutils.h"
#include <string.h>

qsc_ipv4_address qsc_netutils_get_ipv4_address()
{
	char buf[INET_ADDRSTRLEN] = { 0 };
	socket_t sock;
	struct sockaddr_in loopback;
	socklen_t addlen;
	qsc_ipv4_address add = { 0 };

	memset(&loopback, 0, sizeof(loopback));
	loopback.sin_family = AF_INET;
	loopback.sin_addr.s_addr = INADDR_LOOPBACK;
	loopback.sin_port = htons(9);
	sock = socket(PF_INET, SOCK_DGRAM, 0);

	if (connect(sock, (struct sockaddr*)&loopback, sizeof(loopback)) != SOCKET_RET_ERROR)
	{
		addlen = sizeof(loopback);

		if (getsockname(sock, (struct sockaddr*)&loopback, &addlen) != SOCKET_RET_ERROR)
		{
			if (inet_ntop(AF_INET, &loopback.sin_addr, buf, INET_ADDRSTRLEN) != 0)
			{
				inet_pton(AF_INET, buf, add.ipv4); //check this, is it returning loop or any?
			}
		}
	}

	if (sock != SOCKET_RET_ERROR)
	{
#if defined(QSC_SYSTEM_WINDOWS_SOCKETS)
		closesocket(sock);
#else
		close(sock);
#endif
	}

	return add;
}

qsc_ipv6_address qsc_netutils_get_ipv6_address()
{
	char buf[INET6_ADDRSTRLEN] = { 0 };
	socket_t sock;
	struct sockaddr_in6 loopback;
	socklen_t addlen;
	qsc_ipv6_address add = { 0 };

	memset(&loopback, 0, sizeof(loopback));
	loopback.sin6_family = AF_INET6;
	loopback.sin6_addr = in6addr_linklocalprefix;
	loopback.sin6_port = htons(9);
	sock = socket(PF_INET6, SOCK_DGRAM, 0);

	if (connect(sock, (struct sockaddr*)&loopback, sizeof(loopback)) != SOCKET_RET_ERROR)
	{
		addlen = sizeof(loopback);

		if (getsockname(sock, (struct sockaddr*)&loopback, &addlen) != SOCKET_RET_ERROR)
		{
			if (inet_ntop(AF_INET6, &loopback.sin6_addr, buf, INET6_ADDRSTRLEN) != 0)
			{
				inet_pton(AF_INET6, buf, add.ipv6); //check this
			}
		}
	}

	if (sock != SOCKET_RET_ERROR)
	{
#if defined(QSC_SYSTEM_WINDOWS_SOCKETS)
		closesocket(sock);
#else
		close(sock);
#endif
	}

	return add;
}

qsc_ipv4_info qsc_netutils_get_ipv4_info(const char host[NET_HOSTS_NAME_BUFFER], const char service[NET_SERVICE_NAME_BUFFER])
{
	qsc_ipv4_info info = { 0 };

#if defined(QSC_SYSTEM_OS_WINDOWS)

	struct addrinfo* haddr = NULL;
	struct addrinfo hints;
	char ipstr[INET_ADDRSTRLEN] = { 0 };
	qsc_socket_exceptions ex;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// resolve the server address and port
	ex = (qsc_socket_exceptions)getaddrinfo(host, service, &hints, &haddr); // check this

	if (ex == socket_success)
	{
		inet_ntop(AF_INET, haddr->ai_addr, ipstr, INET_ADDRSTRLEN);
		inet_pton(AF_INET, ipstr, info.address.ipv4);
		info.port = (uint16_t)ntohs(((struct sockaddr_in*)haddr->ai_addr)->sin_port);

		if (haddr != NULL)
		{
			freeaddrinfo(haddr);
		}
	}

#else

	hostent* lphost;
	sockaddr_in sa;
	int32_t res;

	sa.sin_len = sizeof(sa);
	sa.sin_addr.s_addr = inet_addr(host);
	lphost = gethostbyname(host);
	res = lphost != NULL ? 0 : SOCKET_EINVAL;

	if (res == 0)
	{
		sa.sin_addr.s_addr = (struct in_addr*)(lphost->h_addr)->s_addr;
		memcpy(info.address.ipv4, sa.sin_addr, sizeof(info.address.ipv4));
		info.port = (uint16_t)ntohs(sa.sin_port);
	}

#endif

	return info;
}

qsc_ipv6_info qsc_netutils_get_ipv6_info(const char host[NET_HOSTS_NAME_BUFFER], const char service[NET_SERVICE_NAME_BUFFER])
{
	qsc_ipv6_info info = { 0 };
	int32_t res;

#if defined(QSC_SYSTEM_OS_WINDOWS)

	struct addrinfo* haddr = NULL;
	struct addrinfo hints;
	char ipstr[INET_ADDRSTRLEN] = { 0 };

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	// resolve the server address and port
	res = getaddrinfo(host, service, &hints, &haddr); // check this

	if (res == 0)
	{
		inet_ntop(AF_INET6, haddr->ai_addr, ipstr, INET_ADDRSTRLEN);
		inet_pton(AF_INET6, ipstr, info.address.ipv6);
		info.port = (uint16_t)ntohs(((struct sockaddr_in6*)haddr->ai_addr)->sin6_port);

		if (haddr != NULL)
		{
			freeaddrinfo(haddr);
		}
	}

#else

	hostent* lphost;
	sockaddr_in6 sa;

	sa.sin6_len = sizeof(sa);
	sa.sin6_addr.s6_addr = inet_addr(host);
	lphost = gethostbyname(host);
	res = lphost != NULL ? 0 : SOCKET_EINVAL;

	if (res == 0)
	{
		sa.sin6_addr.s6_addr = (struct in6_addr*)(lphost->h_addr)->s6_addr;
		memcpy(info.address.ipv6, sin6_addr.s6_addr, sizeof(info.address.ipv6));
		info.port = (uint16_t)ntohs(sa.sin_port);
	}

#endif

	return info;
}

void qsc_netutils_get_peer_name(char output[NET_HOSTS_NAME_BUFFER], qsc_socket* source)
{
	char name[NET_HOSTS_NAME_BUFFER] = { 0 };
	struct sockaddr psa;
	socklen_t psalen;
	int32_t res;

	psalen = 0;
	res = getpeername(source->connection, &psa, &psalen);

	if (res != SOCKET_RET_ERROR && psalen > 0)
	{
		memcpy(output, psa.sa_data, (size_t)psalen);
	}
}

void qsc_netutils_get_socket_name(char output[NET_PROTOCOL_NAME_BUFFER], qsc_socket* source)
{
	char name[NET_HOSTS_NAME_BUFFER] = { 0 };
	struct sockaddr psa;
	socklen_t psalen;
	int32_t res;

	psalen = 0;

	res = getsockname(source->connection, &psa, &psalen);

	if (res != SOCKET_RET_ERROR && psalen > 0)
	{
		memcpy(output, psa.sa_data, (size_t)psalen);
	}
}

uint16_t qsc_netutils_port_name_to_number(const char portname[NET_HOSTS_NAME_BUFFER], const char protocol[NET_PROTOCOL_NAME_BUFFER])
{
	struct servent* se;
	uint16_t port;

	port = (uint16_t)atoi(portname);

	if (port == 0)
	{
		se = getservbyname(portname, protocol);

		if (se != NULL)
		{
			port = (uint16_t)ntohs(se->s_port);
		}
	}

	return port;
}

bool qsc_netutils_self_test()
{
	qsc_ipv4_address addv4;
	qsc_ipv6_address addv6;
	qsc_ipv4_info infv4;
	qsc_ipv6_info infv6;
	char ipv4lp[] = "127.0.0.1";
	char ipv6lp[] = "::1/128";
	char portc[] = "80";
	bool res;

	addv4 = qsc_netutils_get_ipv4_address();
	infv4 = qsc_netutils_get_ipv4_info(ipv4lp, portc);

	if (qsc_ipv4_is_equal(&addv4, &infv4.address) == false)
	{
		res = false;
	}

	addv6 = qsc_netutils_get_ipv6_address();
	infv6 = qsc_netutils_get_ipv6_info(ipv6lp, portc);

	if (qsc_ipv6_is_equal(&addv6, &infv6.address) == false)
	{
		res = false;
	}
}
