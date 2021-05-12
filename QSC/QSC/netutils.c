#include "netutils.h"
#include "memutils.h"
#include <string.h>

void qsc_netutils_get_adaptor_info(qsc_netutils_adaptor_info* ctx)
{
	assert(ctx != NULL);

#if defined(QSC_SYSTEM_OS_WINDOWS)

	if (ctx != NULL)
	{
		IP_ADAPTER_INFO info;
		DWORD blen;
		DWORD status;

		qsc_memutils_clear((uint8_t*)ctx, sizeof(qsc_netutils_adaptor_info));
		blen = sizeof(info);
		status = GetAdaptersInfo(&info, &blen);

		PIP_ADAPTER_INFO pinfo = &info;

		do
		{
			if (pinfo->Address != NULL)
			{
				if (pinfo->Address[0] != 0)
				{
					qsc_memutils_copy((uint8_t*)ctx->desc, (uint8_t*)pinfo->Description, strlen(pinfo->Description));
					qsc_memutils_copy((uint8_t*)ctx->dhcp, (uint8_t*)pinfo->DhcpServer.IpAddress.String, strlen(pinfo->DhcpServer.IpAddress.String));
					qsc_memutils_copy((uint8_t*)ctx->gateway, (uint8_t*)pinfo->GatewayList.IpAddress.String, strlen(pinfo->GatewayList.IpAddress.String));
					qsc_memutils_copy((uint8_t*)ctx->ip, (uint8_t*)pinfo->IpAddressList.IpAddress.String, strlen(pinfo->IpAddressList.IpAddress.String));
					qsc_memutils_copy((uint8_t*)ctx->name, (uint8_t*)pinfo->AdapterName, strlen(pinfo->AdapterName));
					qsc_memutils_copy((uint8_t*)ctx->mac, (uint8_t*)pinfo->Address, strlen(pinfo->Address));
					qsc_memutils_copy((uint8_t*)ctx->subnet, (uint8_t*)pinfo->IpAddressList.IpMask.String, strlen(pinfo->IpAddressList.IpMask.String));
					break;
				}

				pinfo = pinfo->Next;
			}
		} 
		while (pinfo);
	}

#else

	if (ctx != NULL)
	{
		struct ifaddrs* ifaddr = NULL;
		struct ifaddrs* ifa = NULL;
		size_t i;

		if (getifaddrs(&ifaddr) != -1)
		{
			for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
			{
				if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_PACKET)
				{
					struct sockaddr_ll* s = (struct sockaddr_ll*)ifa->ifa_addr;

					if (s->sll_addr != 0)
					{
						qsc_memutils_copy((uint8_t*)ctx->mac, (uint8_t*)s->sll_addr, sizeof(s->sll_addr));
						break;
					}
				}
			}
		}
	}

#endif
}

void qsc_netutils_get_adaptor_info_array(qsc_netutils_adaptor_info ctx[QSC_NET_MAC_ADAPTOR_INFO_ARRAY])
{
	assert(ctx != NULL);

#if defined(QSC_SYSTEM_OS_WINDOWS)

	if (ctx != NULL)
	{
		IP_ADAPTER_INFO info[16] = { 0 };
		DWORD blen;
		DWORD status;
		size_t ctr;

		qsc_memutils_clear((uint8_t*)ctx, sizeof(qsc_netutils_adaptor_info));
		blen = sizeof(info);
		ctr = 0;
		PIP_ADAPTER_INFO pinfo = NULL;
		status = GetAdaptersInfo(info, &blen);
		pinfo = info;

		do
		{
			if (pinfo->Address != NULL)
			{
				qsc_memutils_copy((uint8_t*)ctx[ctr].desc, (uint8_t*)pinfo->Description, strlen(pinfo->Description));
				qsc_memutils_copy((uint8_t*)ctx[ctr].dhcp, (uint8_t*)pinfo->DhcpServer.IpAddress.String, strlen(pinfo->DhcpServer.IpAddress.String));
				qsc_memutils_copy((uint8_t*)ctx[ctr].gateway, (uint8_t*)pinfo->GatewayList.IpAddress.String, strlen(pinfo->GatewayList.IpAddress.String));
				qsc_memutils_copy((uint8_t*)ctx[ctr].ip, (uint8_t*)pinfo->IpAddressList.IpAddress.String, strlen(pinfo->IpAddressList.IpAddress.String));
				qsc_memutils_copy((uint8_t*)ctx[ctr].name, (uint8_t*)pinfo->AdapterName, strlen(pinfo->AdapterName));
				qsc_memutils_copy((uint8_t*)ctx[ctr].mac, (uint8_t*)pinfo->Address, strlen(pinfo->Address));
				qsc_memutils_copy((uint8_t*)ctx[ctr].subnet, (uint8_t*)pinfo->IpAddressList.IpMask.String, strlen(pinfo->IpAddressList.IpMask.String));
			}

			++ctr;
			pinfo = pinfo->Next;
		} 
		while (pinfo != NULL && ctr < QSC_NET_MAC_ADAPTOR_INFO_ARRAY);
	}

#else

	if (ctx != NULL)
	{
		struct ifaddrs* ifaddr = NULL;
		struct ifaddrs* ifa = NULL;
		size_t ctr;
		size_t i;

		if (getifaddrs(&ifaddr) != -1)
		{
			ctr = 0;

			for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
			{
				if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_PACKET)
				{
					struct sockaddr_ll* s = (struct sockaddr_ll*)ifa->ifa_addr;

					if (s->sll_addr != 0)
					{
						qsc_memutils_copy((uint8_t*)ctx[ctr].mac, (uint8_t*)s->sll_addr, sizeof(s->sll_addr));
						break;
					}
				}

				++ctr;
			}
		}
	}

#endif
}

size_t qsc_netutils_get_domain_name(char output[QSC_NET_HOSTS_NAME_BUFFER])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

	DWORD blen;
	TCHAR dbuf[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };

	blen = MAX_COMPUTERNAME_LENGTH + 1;
	GetComputerNameEx(ComputerNameDnsDomain, dbuf, &blen);

	if (blen != 0)
	{
		qsc_memutils_copy((uint8_t*)output, (uint8_t*)dbuf, blen);
	}
	else
	{
		blen = MAX_COMPUTERNAME_LENGTH + 1;
		GetComputerNameEx(ComputerNameNetBIOS, dbuf, &blen);
		qsc_memutils_copy((uint8_t*)output, (uint8_t*)dbuf, blen);
	}

	return blen;

#else

	char hn[QSC_NET_HOSTS_NAME_BUFFER] = { 0 };
	char* dn;
	struct hostent* hp;
	size_t dlen;

	gethostname(hn, sizeof(hn));
	hp = gethostbyname(hn);
	dn = strchr(hp->h_name, '.');
	dlen = strlen(dn);

	if (dn != NULL && dlen != 0)
	{
		qsc_memutils_copy((uint8_t*)output, (uint8_t*)dn, dlen);
	}

	return dlen;
	
#endif
}

qsc_ipinfo_ipv4_address qsc_netutils_get_ipv4_address()
{
	char buf[INET_ADDRSTRLEN] = { 0 };
	socket_t sock;
	struct sockaddr_in loopback;
	socklen_t addlen;
	qsc_ipinfo_ipv4_address add = { 0 };

#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSADATA wsd;
	WSAStartup(0x0202, &wsd);
#endif

	qsc_memutils_clear((uint8_t*)&loopback, sizeof(loopback));
	loopback.sin_family = AF_INET;
	loopback.sin_addr.s_addr = INADDR_LOOPBACK;
	loopback.sin_port = htons(9);
	sock = socket(PF_INET, SOCK_DGRAM, 0);

	if (connect(sock, (struct sockaddr*)&loopback, sizeof(loopback)) != QSC_SOCKET_RET_ERROR)
	{
		addlen = sizeof(loopback);

		if (getsockname(sock, (struct sockaddr*)&loopback, &addlen) != QSC_SOCKET_RET_ERROR)
		{
			if (inet_ntop(AF_INET, &loopback.sin_addr, buf, INET_ADDRSTRLEN) != 0)
			{
				inet_pton(AF_INET, buf, add.ipv4);
			}
		}
	}

	if (sock != QSC_SOCKET_RET_ERROR)
	{
#if defined(QSC_SYSTEM_WINDOWS_SOCKETS)
		closesocket(sock);
		WSACleanup();
#else
		close(sock);
#endif
	}

	return add;
}

qsc_ipinfo_ipv6_address qsc_netutils_get_ipv6_address()
{
	char buf[INET6_ADDRSTRLEN] = { 0 };
	socket_t sock;
	struct sockaddr_in6 loopback;
	socklen_t addlen;
	qsc_ipinfo_ipv6_address add = { 0 };

#if defined(QSC_SYSTEM_OS_WINDOWS)
	WSADATA wsd;
	WSAStartup(0x0202, &wsd);
#endif

	qsc_memutils_clear((uint8_t*)&loopback, sizeof(loopback));
	loopback.sin6_family = AF_INET6;
	loopback.sin6_addr = in6addr_linklocalprefix;
	loopback.sin6_port = htons(9);
	sock = socket(PF_INET6, SOCK_DGRAM, 0);

	if (connect(sock, (struct sockaddr*)&loopback, sizeof(loopback)) != QSC_SOCKET_RET_ERROR)
	{
		addlen = sizeof(loopback);

		if (getsockname(sock, (struct sockaddr*)&loopback, &addlen) != QSC_SOCKET_RET_ERROR)
		{
			if (inet_ntop(AF_INET6, &loopback.sin6_addr, buf, INET6_ADDRSTRLEN) != 0)
			{
				inet_pton(AF_INET6, buf, add.ipv6);
			}
		}
	}

	if (sock != QSC_SOCKET_RET_ERROR)
	{
#if defined(QSC_SYSTEM_WINDOWS_SOCKETS)
		closesocket(sock);
		WSACleanup();
#else
		close(sock);
#endif
	}

	return add;
}

qsc_ipinfo_ipv4_info qsc_netutils_get_ipv4_info(const char host[QSC_NET_HOSTS_NAME_BUFFER], const char service[QSC_NET_SERVICE_NAME_BUFFER])
{
	qsc_ipinfo_ipv4_info info = { 0 };

#if defined(QSC_SYSTEM_OS_WINDOWS)

	struct addrinfo* haddr = NULL;
	struct addrinfo hints;
	char ipstr[INET_ADDRSTRLEN] = { 0 };
	qsc_socket_exceptions ex;
	WSADATA wsd;

	WSAStartup(0x0202, &wsd);

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// resolve the server address and port
	ex = (qsc_socket_exceptions)getaddrinfo(host, service, &hints, &haddr); // check this

	if (ex == qsc_socket_exception_success)
	{
		inet_ntop(AF_INET, ((CHAR*)haddr->ai_addr->sa_data + 2), ipstr, INET_ADDRSTRLEN);
		inet_pton(AF_INET, ipstr, info.address.ipv4);
		info.port = (uint16_t)ntohs(((struct sockaddr_in*)haddr->ai_addr)->sin_port);

		if (haddr != NULL)
		{
			freeaddrinfo(haddr);
		}

		WSACleanup();
	}

#else

	hostent* lphost;
	sockaddr_in sa;

	sa.sin_len = sizeof(sa);
	sa.sin_addr.s_addr = inet_addr(host);
	lphost = gethostbyname(host);

	if (lphost != NULL)
	{
		sa.sin_addr.s_addr = (struct in_addr*)(lphost->h_addr)->s_addr;
		qsc_memutils_copy((uint8_t*)info.address.ipv4, (uint8_t*)sa.sin_addr, sizeof(info.address.ipv4));
		info.port = (uint16_t)ntohs(sa.sin_port);
	}

#endif

	return info;
}

qsc_ipinfo_ipv6_info qsc_netutils_get_ipv6_info(const char host[QSC_NET_HOSTS_NAME_BUFFER], const char service[QSC_NET_SERVICE_NAME_BUFFER])
{
	qsc_ipinfo_ipv6_info info = { 0 };

#if defined(QSC_SYSTEM_OS_WINDOWS)

	struct addrinfo* haddr = NULL;
	struct addrinfo hints;
	char ipstr[INET6_ADDRSTRLEN] = { 0 };
	int32_t res;
	WSADATA wsd;

	WSAStartup(0x0202, &wsd);
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	// resolve the server address and port
	res = getaddrinfo(host, service, &hints, &haddr); // check this

	if (res == 0)
	{
		inet_ntop(AF_INET6, ((CHAR*)haddr->ai_addr->sa_data + 2), ipstr, INET6_ADDRSTRLEN);
		inet_pton(AF_INET6, ipstr, info.address.ipv6);
		info.port = (uint16_t)ntohs(((struct sockaddr_in6*)haddr->ai_addr)->sin6_port);

		if (haddr != NULL)
		{
			freeaddrinfo(haddr);
		}

		WSACleanup();
	}

#else

	hostent* lphost;
	sockaddr_in6 sa;

	sa.sin6_len = sizeof(sa);
	sa.sin6_addr.s6_addr = inet_addr(host);
	lphost = gethostbyname(host);

	if (lphost != NULL)
	{
		sa.sin6_addr.s6_addr = (struct in6_addr*)(lphost->h_addr)->s6_addr;
		qsc_memutils_copy((uint8_t*)info.address.ipv6, (uint8_t*)sin6_addr.s6_addr, sizeof(info.address.ipv6));
		info.port = (uint16_t)ntohs(sa.sin_port);
	}

#endif

	return info;
}

void qsc_netutils_get_mac_address(uint8_t mac[QSC_NET_MAC_ADDRESS_LENGTH])
{
#if defined(QSC_SYSTEM_OS_WINDOWS)

	IP_ADAPTER_INFO info[16];
	DWORD blen;
	DWORD status;

	blen = sizeof(info);
	status = GetAdaptersInfo(info, &blen);

	PIP_ADAPTER_INFO pinfo = info;

	do
	{
		if (pinfo->Address != NULL)
		{
			if (pinfo->Address[0] != 0)
			{
				qsc_memutils_copy((uint8_t*)mac, (uint8_t*)pinfo->Address, QSC_NET_MAC_ADDRESS_LENGTH);
				break;
			}

			pinfo = pinfo->Next;
		}
	} 
	while (pinfo);

#else

	// TODO: test this
	struct ifaddrs* ifaddr = NULL;
	struct ifaddrs* ifa = NULL;
	size_t i;

	if (getifaddrs(&ifaddr) != -1)
	{
		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_PACKET)
			{
				struct sockaddr_ll* s = (struct sockaddr_ll*)ifa->ifa_addr;

				if (s->sll_addr != 0)
				{
					qsc_memutils_copy((uint8_t*)mac, (uint8_t*)s->sll_addr, sizeof(s->sll_addr));
					break;
				}

				//for (i = 0; i < s->sll_halen; ++i)
				//{
				//	if (s->sll_addr[i] != 0)
				//	{
				//		qsc_memutils_copy((uint8_t*)mac, (uint8_t*)s->sll_addr[i], QSC_NET_MAC_ADDRESS_LENGTH);
				//		break;
				//	}
				//}
			}
		}
	}

#endif
}

void qsc_netutils_get_peer_name(char output[QSC_NET_HOSTS_NAME_BUFFER], qsc_socket* sock)
{
	assert(sock != NULL);

	if (sock != NULL)
	{
		char name[QSC_NET_HOSTS_NAME_BUFFER] = { 0 };
		struct sockaddr psa;
		socklen_t psalen;
		int32_t res;

		psalen = 0;
		res = getpeername(sock->connection, &psa, &psalen);

		if (res != QSC_SOCKET_RET_ERROR && psalen > 0)
		{
			qsc_memutils_copy((uint8_t*)output, (uint8_t*)psa.sa_data, (size_t)psalen);
		}
	}
}

void qsc_netutils_get_socket_name(char output[QSC_NET_PROTOCOL_NAME_BUFFER], qsc_socket* sock)
{
	assert(sock != NULL);

	if (sock != NULL)
	{
		char name[QSC_NET_HOSTS_NAME_BUFFER] = { 0 };
		struct sockaddr psa;
		socklen_t psalen;
		int32_t res;

		psalen = 0;

		res = getsockname(sock->connection, &psa, &psalen);

		if (res != QSC_SOCKET_RET_ERROR && psalen > 0)
		{
			qsc_memutils_copy((uint8_t*)output, (uint8_t*)psa.sa_data, (size_t)psalen);
		}
	}
}

uint16_t qsc_netutils_port_name_to_number(const char portname[QSC_NET_HOSTS_NAME_BUFFER], const char protocol[QSC_NET_PROTOCOL_NAME_BUFFER])
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
	qsc_ipinfo_ipv4_address addv4;
	qsc_ipinfo_ipv6_address addv6;
	qsc_ipinfo_ipv4_info infv4;
	qsc_ipinfo_ipv6_info infv6;
	char ipv4lp[] = "127.0.0.1";
	char ipv6lp[] = "::1/128";
	char portc[] = "80";
	bool res;

	res = false;
	addv4 = qsc_netutils_get_ipv4_address();
	infv4 = qsc_netutils_get_ipv4_info(ipv4lp, portc);

	if (qsc_ipinfo_ipv4_address_is_equal(&addv4, &infv4.address) == false)
	{
		res = false;
	}

	addv6 = qsc_netutils_get_ipv6_address();
	infv6 = qsc_netutils_get_ipv6_info(ipv6lp, portc);

	if (qsc_ipinfo_ipv6_address_is_equal(&addv6, &infv6.address) == false)
	{
		res = false;
	}

	return res;
}
