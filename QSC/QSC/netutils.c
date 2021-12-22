#include "netutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdlib.h>

#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif

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
#	include <unistd.h>
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

void qsc_netutils_get_adaptor_info(qsc_netutils_adaptor_info* ctx, const char* infname)
{
	assert(ctx != NULL);

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

	if (ctx != NULL)
	{
		PIP_ADAPTER_INFO padapt;
		PIP_ADAPTER_INFO pinfo;
		ULONG outlen;
		size_t pctr;
		const size_t PINTMX = 32;

		qsc_memutils_clear((uint8_t*)ctx, sizeof(qsc_netutils_adaptor_info));
		outlen = sizeof(IP_ADAPTER_INFO);
		pinfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));

		if (pinfo != NULL)
		{
			if (GetAdaptersInfo(pinfo, &outlen) == ERROR_BUFFER_OVERFLOW)
			{
				free(pinfo);
				pinfo = (IP_ADAPTER_INFO*)malloc(outlen);
			}

			if (pinfo != NULL)
			{
				if (GetAdaptersInfo(pinfo, &outlen) == NO_ERROR)
				{
					padapt = pinfo;
					pctr = 0;

					while (pinfo != NULL)
					{
						if (qsc_stringutils_string_contains((const char*)pinfo->AdapterName, infname) == true)
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
						++pctr;
						
						if (pctr >= PINTMX)
						{
							break;
						}
					}

					free(padapt);
				}
			}
		}
	}

#else
	// TODO: 
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
				sprintf(ctx->mac, "%02x:%02x:%02x:%02x:%02x:%02x", *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3), *(ptr + 4), *(ptr + 5));
				break;
			}
		}
#else
		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
			if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
				struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;
				sprintf((char*)ctx->mac, "%02x:%02x:%02x:%02x:%02x:%02x", s->sll_addr[0], s->sll_addr[1], s->sll_addr[2], s->sll_addr[3], s->sll_addr[4], s->sll_addr[5]);
				break;
			}
		}
#endif
		freeifaddrs(ifaddr);
	}

#endif
}

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

size_t qsc_netutils_get_domain_name(char output[QSC_NETUTILS_HOSTS_NAME_LENGTH])
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

	char hn[QSC_NETUTILS_HOSTS_NAME_LENGTH] = { 0 };
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

size_t qsc_netutils_get_host_name(char host[QSC_NETUTILS_HOSTS_NAME_LENGTH])
{
	return (size_t)gethostname(host, QSC_NETUTILS_HOSTS_NAME_LENGTH);
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
	size_t pctr;
	qsc_socket_exceptions ex;
	int32_t res;
	const size_t ADRMAX = 32;

	res = WSAStartup(0x0202, &wsd);

	if (res == 0)
	{
		qsc_memutils_clear(&hints, sizeof(hints));
		qsc_memutils_clear(&insock4, sizeof(struct sockaddr_in));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		gethostname(hname, sizeof(hname));
		ex = (qsc_socket_exceptions)getaddrinfo(hname, NULL, &hints, &hres);

		if (ex == qsc_socket_exception_success)
		{
			ralloc = hres;
			pctr = 0;

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
				++pctr;

				if (pctr > ADRMAX)
				{
					break;
				}
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
	struct addrinfo* hres = NULL;
	struct addrinfo* ralloc;
	size_t pctr;
	qsc_socket_exceptions ex;
	int32_t res;
	const size_t ADRMAX = 32;

	res = WSAStartup(0x0202, &wsd);

	if (res == 0)
	{
		qsc_memutils_clear(&hints, sizeof(hints));
		qsc_memutils_clear(&insock6, sizeof(struct sockaddr_in6));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		gethostname(hname, sizeof(hname));
		ex = (qsc_socket_exceptions)getaddrinfo(hname, NULL, &hints, &hres);

		if (ex == qsc_socket_exception_success)
		{
			pctr = 0;
			ralloc = hres;

			while (hres != NULL)
			{
				if (hres->ai_family == AF_INET6)
				{
					qsc_memutils_copy(&insock6, hres->ai_addr, hres->ai_addrlen);
					insock6.sin6_port = htons(9);
					insock6.sin6_family = AF_INET6;

					if (inet_ntop(AF_INET6, &insock6.sin6_addr, hname, INET6_ADDRSTRLEN) != 0)
					{
						inet_pton(AF_INET6, hname, add.ipv6);
					}

					break;
				}

				hres = hres->ai_next;
				++pctr;

				if (pctr > ADRMAX)
				{
					break;
				}
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

qsc_ipinfo_ipv4_info qsc_netutils_get_ipv4_info(const char host[QSC_NETUTILS_HOSTS_NAME_LENGTH], const char service[QSC_NETUTILS_SERVICE_NAME_BUFFER_LENGTH])
{
	char hname[INET_ADDRSTRLEN] = { 0 };
	qsc_ipinfo_ipv4_info info = { 0 };
	struct addrinfo hints;
	struct addrinfo* hres = NULL;
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
		qsc_memutils_clear(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		ex = (qsc_socket_exceptions)getaddrinfo(host, service, &hints, &hres);

		if (ex == qsc_socket_exception_success)
		{
			if (hres != NULL)
			{
				if (inet_ntop(AF_INET, ((char*)hres->ai_addr->sa_data + 2), hname, INET_ADDRSTRLEN) != 0)
				{
					inet_pton(AF_INET, hname, info.address.ipv4);
					info.port = ntohs(((struct sockaddr_in*)hres->ai_addr)->sin_port);
					info.mask = qsc_ipinfo_ipv4_address_get_cidr_mask(&info.address);
					freeaddrinfo(hres);
				}
			}
		}

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		WSACleanup();
#endif
	}

	return info;
}

qsc_ipinfo_ipv6_info qsc_netutils_get_ipv6_info(const char host[QSC_NETUTILS_HOSTS_NAME_LENGTH], const char service[QSC_NETUTILS_SERVICE_NAME_BUFFER_LENGTH])
{
	char buf[INET6_ADDRSTRLEN] = { 0 };
	qsc_ipinfo_ipv6_info info = { 0 };
	struct addrinfo hints;
	struct sockaddr_in6 insock6 = { 0 };
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
		qsc_memutils_clear(&hints, sizeof(hints));
		qsc_memutils_clear(&insock6, sizeof(struct sockaddr_in6));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		ex = (qsc_socket_exceptions)getaddrinfo(host, service, &hints, &haddr);

		if (ex == qsc_socket_exception_success)
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

void qsc_netutils_get_peer_name(char output[QSC_NETUTILS_HOSTS_NAME_LENGTH], const qsc_socket* sock)
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

void qsc_netutils_get_socket_name(char output[QSC_NETUTILS_NAME_BUFFER_LENGTH], const qsc_socket* sock)
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

uint16_t qsc_netutils_port_name_to_number(const char portname[QSC_NETUTILS_HOSTS_NAME_LENGTH], const char protocol[QSC_NETUTILS_NAME_BUFFER_LENGTH])
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

void qsc_netutils_values_print()
{
	char domain[QSC_NETUTILS_HOSTS_NAME_LENGTH] = { 0 };
	char ipv4s[QSC_IPINFO_IPV4_STRNLEN] = { 0 };
	char ipv6s[QSC_IPINFO_IPV6_STRNLEN] = { 0 };
	qsc_ipinfo_ipv4_address ipv4;
	qsc_ipinfo_ipv6_address ipv6;
	qsc_ipinfo_ipv4_info ipv4inf;
	qsc_ipinfo_ipv6_info ipv6inf;
	uint16_t port;
	size_t rlen;

	qsc_consoleutils_print_line("Netutils visual verification test");
	qsc_consoleutils_print_line("Printing network values..");

	qsc_consoleutils_print_safe("Domain name: ");
	rlen = qsc_netutils_get_domain_name(domain);
	if (rlen > 0)
	{
		qsc_consoleutils_print_line(domain);
	}

	qsc_consoleutils_print_safe("IPv4 address: ");
	ipv4 = qsc_netutils_get_ipv4_address();
	qsc_ipinfo_ipv4_address_to_string(ipv4s, &ipv4);
	qsc_consoleutils_print_line(ipv4s);

	qsc_consoleutils_print_safe("IPv6 address: ");
	ipv6 = qsc_netutils_get_ipv6_address();
	qsc_ipinfo_ipv6_address_to_string(ipv6s, &ipv6);
	qsc_consoleutils_print_line(ipv6s);

	qsc_consoleutils_print_line("IPv4 info");
	ipv4inf = qsc_netutils_get_ipv4_info("127.0.0.1", "http");
	qsc_consoleutils_print_safe("IPv4 address: ");
	qsc_ipinfo_ipv4_address_to_string(ipv4s, &ipv4inf.address);
	qsc_consoleutils_print_line(ipv4s);
	qsc_consoleutils_print_safe("CIDR mask: ");
	qsc_consoleutils_print_uint((uint32_t)ipv4inf.mask);
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_safe("Application port: ");
	qsc_consoleutils_print_uint((uint32_t)ipv4inf.port);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_line("IPv6 info:");
	ipv6inf = qsc_netutils_get_ipv6_info("::1", "http");
	qsc_consoleutils_print_safe("IPv6 address: ");
	qsc_ipinfo_ipv6_address_to_string(ipv6s, &ipv6inf.address);
	qsc_consoleutils_print_line(ipv6s);
	qsc_consoleutils_print_safe("CIDR mask: ");
	qsc_consoleutils_print_uint((uint32_t)ipv6inf.mask);
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_safe("Application port: ");
	qsc_consoleutils_print_uint((uint32_t)ipv6inf.port);
	qsc_consoleutils_print_line("");

	qsc_consoleutils_print_safe("Interface info: ");
	qsc_netutils_adaptor_info info = { 0 };
	qsc_netutils_get_adaptor_info(&info, "loop0");
	qsc_consoleutils_print_line(info.desc);

	port = qsc_netutils_port_name_to_number("http", "http");
	qsc_consoleutils_print_uint((uint32_t)port);
	qsc_consoleutils_print_line("");
}
