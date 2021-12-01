#include "netutils.h"
#include "memutils.h"

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
#   include "arrayutils.h"
#   include <ws2ipdef.h>
#else
#   include <ifaddrs.h>
#   include <arpa/inet.h>
#   include <netdb.h>
#   include <netinet/in.h>
#   include <sys/socket.h>
#	include <stdio.h>
#	include <string.h>
#	include <sys/types.h>
#	if !defined(AF_LINK)
#		define AF_LINK AF_PACKET
#	endif
#	if defined(QSC_SYSTEM_OS_APPLE)
#		include <net/if_dl.h>
#		include <netinet/in.h>
#		include <sys/socket.h>
#		if !defined(AF_PACKET)
#			define AF_PACKET PF_INET
#		endif
#	endif
#endif

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
void qsc_netutils_get_adaptor_info(qsc_netutils_adaptor_info* ctx)
{
	assert(ctx != NULL);



	if (ctx != NULL)
	{
		IP_ADAPTER_INFO info;
		DWORD blen;

		qsc_memutils_clear((uint8_t*)ctx, sizeof(qsc_netutils_adaptor_info));
		blen = sizeof(info);
		GetAdaptersInfo(&info, &blen);

		PIP_ADAPTER_INFO pinfo = &info;

		do
		{
			if (pinfo->Address[0] != 0)
			{
				qsc_memutils_copy((uint8_t*)ctx->desc, (uint8_t*)pinfo->Description, strlen(pinfo->Description));
				qsc_memutils_copy((uint8_t*)ctx->dhcp, (uint8_t*)pinfo->DhcpServer.IpAddress.String, strlen(pinfo->DhcpServer.IpAddress.String));
				qsc_memutils_copy((uint8_t*)ctx->gateway, (uint8_t*)pinfo->GatewayList.IpAddress.String, strlen(pinfo->GatewayList.IpAddress.String));
				qsc_memutils_copy((uint8_t*)ctx->ip, (uint8_t*)pinfo->IpAddressList.IpAddress.String, strlen(pinfo->IpAddressList.IpAddress.String));
				qsc_memutils_copy((uint8_t*)ctx->name, (uint8_t*)pinfo->AdapterName, strlen((const char*)pinfo->AdapterName));
				qsc_memutils_copy((uint8_t*)ctx->mac, (uint8_t*)pinfo->Address, strlen((const char*)pinfo->Address));
				qsc_memutils_copy((uint8_t*)ctx->subnet, (uint8_t*)pinfo->IpAddressList.IpMask.String, strlen(pinfo->IpAddressList.IpMask.String));
				break;
			}

			pinfo = pinfo->Next;
		}
		while (pinfo != NULL);
	}
}
#endif

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
void qsc_netutils_get_adaptor_info_array(qsc_netutils_adaptor_info ctx[QSC_NET_MAC_ADAPTOR_INFO_ARRAY])
{
	assert(ctx != NULL);



	if (ctx != NULL)
	{
		IP_ADAPTER_INFO info[16] = { 0 };
		DWORD blen;
		size_t ctr;

		qsc_memutils_clear((uint8_t*)ctx, sizeof(qsc_netutils_adaptor_info));
		blen = sizeof(info);
		ctr = 0;
		PIP_ADAPTER_INFO pinfo = NULL;
		GetAdaptersInfo(info, &blen);
		pinfo = info;

		do
		{
			qsc_memutils_copy((uint8_t*)ctx[ctr].desc, (uint8_t*)pinfo->Description, strlen(pinfo->Description));
			qsc_memutils_copy((uint8_t*)ctx[ctr].dhcp, (uint8_t*)pinfo->DhcpServer.IpAddress.String, strlen(pinfo->DhcpServer.IpAddress.String));
			qsc_memutils_copy((uint8_t*)ctx[ctr].gateway, (uint8_t*)pinfo->GatewayList.IpAddress.String, strlen(pinfo->GatewayList.IpAddress.String));
			qsc_memutils_copy((uint8_t*)ctx[ctr].ip, (uint8_t*)pinfo->IpAddressList.IpAddress.String, strlen(pinfo->IpAddressList.IpAddress.String));
			qsc_memutils_copy((uint8_t*)ctx[ctr].name, (uint8_t*)pinfo->AdapterName, strlen((const char*)pinfo->AdapterName));
			qsc_memutils_copy((uint8_t*)ctx[ctr].mac, (uint8_t*)pinfo->Address, strlen((const char*)pinfo->Address));
			qsc_memutils_copy((uint8_t*)ctx[ctr].subnet, (uint8_t*)pinfo->IpAddressList.IpMask.String, strlen((const char*)pinfo->IpAddressList.IpMask.String));
			++ctr;
			pinfo = pinfo->Next;
		}
		while (pinfo != NULL && ctr < QSC_NET_MAC_ADAPTOR_INFO_ARRAY);
	}
}
#endif

uint32_t qsc_netutils_atoi(const char* source)
{
	assert(source != NULL);

	size_t len;
	uint32_t res;

	res = 0;

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		len = strnlen_s(source, 10);
#else
		len = strlen(source);
#endif

		for (size_t i = 0; i < len; ++i)
		{
			if (source[i] == '\0' || source[i] < 48 || source[i] > 57)
			{
				break;
			}

			res = res * 10 + source[i] - '0';
		}
	}

	return res;
}

size_t qsc_netutils_get_domain_name(char output[QSC_NET_HOSTS_NAME_BUFFER])
{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

	DWORD blen;
	TCHAR dbuf[QSC_SYSTEM_MAX_PATH + 1] = { 0 };

	blen = QSC_SYSTEM_MAX_PATH + 1;
	GetComputerNameEx(ComputerNameDnsDomain, dbuf, &blen);

	if (blen != 0)
	{
		qsc_memutils_copy((uint8_t*)output, (uint8_t*)dbuf, blen);
	}
	else
	{
		blen = QSC_SYSTEM_MAX_PATH + 1;
		GetComputerNameEx(ComputerNameNetBIOS, dbuf, &blen);
		qsc_memutils_copy((uint8_t*)output, (uint8_t*)dbuf, blen);
	}

	return blen;

#else

	char hn[QSC_NET_HOSTS_NAME_BUFFER] = { 0 };
	char* dn;
	struct hostent* hp;
	size_t dlen;

    dlen = 0;
	gethostname(hn, sizeof(hn));
	hp = gethostbyname(hn);

	if (hp != NULL)
    {
        dn = strchr(hp->h_name, '.');

        if (dn != NULL && dlen != 0)
        {
            dlen = strlen(dn);
            qsc_memutils_copy((uint8_t*)output, (uint8_t*)dn, dlen);
        }
    }

	return dlen;

#endif
}

qsc_ipinfo_ipv4_address qsc_netutils_get_ipv4_address()
{
	qsc_ipinfo_ipv4_address add = { 0 };

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

	char hname[INET_ADDRSTRLEN] = { 0 };
	struct addrinfo hints = { 0 };
	struct sockaddr_in insock4 = { 0 };
	WSADATA wsd;
	struct addrinfo* hres = NULL;
	struct addrinfo* ralloc = NULL;
	int32_t res;

	res = WSAStartup(0x0202, &wsd);

	if (res == 0)
	{
		qsc_memutils_clear(&hints, sizeof(hints));
		qsc_memutils_clear(&insock4, sizeof(struct sockaddr_in));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		gethostname(hname, sizeof(hname));
		res = getaddrinfo(hname, NULL, &hints, &hres);

		if (res == 0)
		{
			ralloc = hres;

			while (hres)
			{
				if (hres->ai_family == AF_INET)
				{
					qsc_memutils_copy(&insock4, hres->ai_addr, hres->ai_addrlen);
					insock4.sin_port = htons(9);
					insock4.sin_family = AF_INET;

					if (inet_ntop(AF_INET, &insock4.sin_addr, hname, INET_ADDRSTRLEN) != 0)
					{
						inet_pton(AF_INET, hname, add.ipv4);
					}

					break;
				}

				hres = hres->ai_next;
			}

			freeaddrinfo(ralloc);
		}

		WSACleanup();
	}

#else

	struct ifaddrs* ifas = NULL;
	struct ifaddrs* ifa = NULL;
	void* padd = NULL;

	getifaddrs(&ifas);

	if (ifas != NULL)
	{
        for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (!ifa->ifa_addr)
            {
                continue;
            }

            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                padd = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
                char buf[INET_ADDRSTRLEN];

                if (inet_ntop(AF_INET, padd, buf, INET_ADDRSTRLEN) != 0)
                {
                    inet_pton(AF_INET, buf, add.ipv4);
                }
            }
        }

		freeifaddrs(ifas);
	}

#endif

	return add;
}

qsc_ipinfo_ipv6_address qsc_netutils_get_ipv6_address()
{
	qsc_ipinfo_ipv6_address add = { 0 };

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
	char hname[INET6_ADDRSTRLEN] = { 0 };
	struct addrinfo hints = { 0 };
	struct sockaddr_in6 insock6 = { 0 };
	WSADATA wsd;
	struct addrinfo* haddr = NULL;
	struct addrinfo* ralloc = NULL;
	PADDRINFOA hres;
	int32_t res;

	res = WSAStartup(0x0202, &wsd);

	if (res == 0)
	{
		qsc_memutils_clear(&hints, sizeof(hints));
		qsc_memutils_clear(&insock6, sizeof(struct sockaddr_in6));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		gethostname(hname, sizeof(hname));
		res = getaddrinfo(hname, NULL, &hints, &hres);

		if (res == 0)
		{
			ralloc = haddr;

			while (haddr)
			{
				if (haddr->ai_family == AF_INET6)
				{
					qsc_memutils_copy(&insock6, haddr->ai_addr, haddr->ai_addrlen);
					insock6.sin6_port = htons(9);
					insock6.sin6_family = AF_INET6;

					if (inet_ntop(AF_INET6, &insock6.sin6_addr, hname, INET6_ADDRSTRLEN) != 0)
					{
						inet_pton(AF_INET6, hname, add.ipv6);
					}

					break;
				}

				haddr = haddr->ai_next;
			}

			freeaddrinfo(ralloc);
		}

		WSACleanup();
	}

#else

	struct ifaddrs* ifas = NULL;
	struct ifaddrs* ifa = NULL;
	void* padd = NULL;

	getifaddrs(&ifas);

    if (ifas != NULL)
	{
        for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next)
        {
            if (!ifa->ifa_addr)
            {
                continue;
            }

            if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                padd = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
                char buf[INET6_ADDRSTRLEN];

                if (inet_ntop(AF_INET6, padd, buf, INET6_ADDRSTRLEN) != 0)
                {
                    inet_pton(AF_INET6, buf, add.ipv6);
                }
            }
        }

		freeifaddrs(ifas);
	}

#endif

	return add;
}

qsc_ipinfo_ipv4_info qsc_netutils_get_ipv4_info(const char host[QSC_NET_HOSTS_NAME_BUFFER], const char service[QSC_NET_SERVICE_NAME_BUFFER])
{
	qsc_ipinfo_ipv4_info info = { 0 };
	char ipstr[INET_ADDRSTRLEN] = { 0 };
	struct addrinfo hints;
	struct addrinfo* haddr = NULL;
	qsc_socket_exceptions ex;
	int32_t res;

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
    WSADATA wsd;
    res = WSAStartup(0x0202, &wsd);
#else
    res = 0;
#endif

	if (res == 0)
	{
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		ex = (qsc_socket_exceptions)getaddrinfo(host, service, &hints, &haddr);

		if (ex == qsc_socket_exception_success)
		{
			if (haddr != NULL)
			{
				if (inet_ntop(AF_INET, ((char*)haddr->ai_addr->sa_data + 2), ipstr, INET_ADDRSTRLEN) != 0)
				{
					inet_pton(AF_INET, ipstr, info.address.ipv4);
					info.port = ntohs(((struct sockaddr_in*)haddr->ai_addr)->sin_port);
					info.mask = qsc_ipinfo_ipv4_address_get_cidr_mask(&info.address);
					freeaddrinfo(haddr);
				}
			}
		}

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		WSACleanup();
#endif
	}

	return info;
}

qsc_ipinfo_ipv6_info qsc_netutils_get_ipv6_info(const char host[QSC_NET_HOSTS_NAME_BUFFER], const char service[QSC_NET_SERVICE_NAME_BUFFER])
{
	qsc_ipinfo_ipv6_info info = { 0 };
	char buf[INET6_ADDRSTRLEN] = { 0 };
	struct addrinfo hints;
	struct sockaddr_in6 insock6 = { 0 };
	struct addrinfo* haddr = NULL;
	int32_t res;

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
    WSADATA wsd;
    res = WSAStartup(0x0202, &wsd);
#else
    res = 0;
#endif

	if (res == 0)
	{
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = 0;

		res = getaddrinfo(host, service, &hints, &haddr);

		if (res == 0)
		{
			if (haddr->ai_family == AF_INET6)
			{
				qsc_memutils_copy(&insock6, haddr->ai_addr, haddr->ai_addrlen);
				insock6.sin6_port = htons(9);
				insock6.sin6_family = AF_INET6;

				if (inet_ntop(AF_INET6, &insock6.sin6_addr, buf, INET6_ADDRSTRLEN) != 0)
				{
					inet_pton(AF_INET6, buf, &info.address);
					info.port = ntohs(((struct sockaddr_in6*)haddr->ai_addr)->sin6_port);
					info.mask = qsc_ipinfo_ipv6_address_get_cidr_mask(&info.address);
				}
			}

			freeaddrinfo(haddr);
		}

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		WSACleanup();
#endif
	}

	return info;
}

void qsc_netutils_get_mac_address(char mac[QSC_NET_MAC_ADDRESS_LENGTH])
{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

	IP_ADAPTER_INFO info[16];
	DWORD blen;

	blen = sizeof(info);
	GetAdaptersInfo(info, &blen);
	PIP_ADAPTER_INFO pinfo = info;

	do
	{
		if (pinfo->Address != NULL && pinfo->AddressLength > 0)
		{
			sprintf_s(mac, QSC_NET_MAC_ADDRESS_LENGTH, "%02x:%02x:%02x:%02x:%02x:%02x", (uint32_t)pinfo->Address[0], (uint32_t)pinfo->Address[1], (uint32_t)pinfo->Address[2], (uint32_t)pinfo->Address[3], (uint32_t)pinfo->Address, pinfo->Address[5]);
			break;
		}

		pinfo = pinfo->Next;
	}
	while (pinfo != NULL);

#else

	struct ifaddrs* ifaddr = NULL;
	struct ifaddrs* ifa = NULL;

	if (getifaddrs(&ifaddr) != -1)
	{
#if defined(QSC_SYSTEM_OS_APPLE)
		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_LINK)
			{
				unsigned char* ptr;
				ptr = (unsigned char*)LLADDR((struct sockaddr_dl*)(ifa)->ifa_addr);
				sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", *ptr, *(ptr+1), *(ptr+2), *(ptr+3), *(ptr+4), *(ptr+5));
				break;
			}
		}
#else
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
            if ( (ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET) )
            {
                 struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
                 sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x", s->sll_addr[0], s->sll_addr[1], s->sll_addr[2], s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
                 break;
            }
        }
#endif
        freeifaddrs(ifaddr);
	}

#endif
}

void qsc_netutils_get_peer_name(char output[QSC_NET_HOSTS_NAME_BUFFER], const qsc_socket* sock)
{
	assert(sock != NULL);

	if (sock != NULL)
	{
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

void qsc_netutils_get_socket_name(char output[QSC_NET_PROTOCOL_NAME_BUFFER], const qsc_socket* sock)
{
	assert(sock != NULL);

	if (sock != NULL)
	{
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
	const struct servent* se;
	uint16_t port;

	port = (uint16_t)qsc_netutils_atoi(portname);

	if (port == 0)
	{
		se = getservbyname(portname, protocol);

		if (se != NULL)
		{
			port = ntohs(se->s_port);
		}
	}

	return port;
}
