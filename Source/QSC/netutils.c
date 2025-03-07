#include "netutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdlib.h>

#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
#	define NETUTILS_WSA_STARTUP_SEQUENCE 0x0202
#	define NETUTILS_INET_PTON_SUCCESS 1
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
		ULONG otplen;
		size_t pctr;
		const size_t PINTMX = 32;

		qsc_memutils_clear((uint8_t*)ctx, sizeof(qsc_netutils_adaptor_info));
		otplen = sizeof(IP_ADAPTER_INFO);
		pinfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));

		if (pinfo != NULL)
		{
			if (GetAdaptersInfo(pinfo, &otplen) == ERROR_BUFFER_OVERFLOW)
			{
				free(pinfo);
				pinfo = (IP_ADAPTER_INFO*)malloc(otplen);
			}

			if (pinfo != NULL)
			{
				if (GetAdaptersInfo(pinfo, &otplen) == NO_ERROR)
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

void qsc_netutils_get_mac_address(uint8_t mac[QSC_NETUTILS_MAC_ADDRESS_SIZE])
{
	qsc_netutils_adaptor_info ctx = { 0 };

	qsc_netutils_get_adaptor_info(&ctx, "wlan0");
	qsc_memutils_copy(mac, ctx.mac, QSC_NETUTILS_MAC_ADDRESS_SIZE);
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

size_t qsc_netutils_get_domain_name(char output[QSC_NETUTILS_DOMAIN_NAME_SIZE])
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

	char hn[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };
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

bool qsc_netutils_get_host_name(char host[QSC_NETUTILS_HOSTS_NAME_SIZE])
{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
	WSADATA wsd;
	int32_t slen;

	slen = -1;

	if (WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd) == 0)
	{
		slen = gethostname(host, QSC_NETUTILS_HOSTS_NAME_SIZE);
		WSACleanup();
	}

	return (slen == 0);
#else
    int32_t slen;

    slen = gethostname(host, QSC_NETUTILS_HOSTS_NAME_SIZE);

    if (slen == 0)
    {
        host[QSC_NETUTILS_HOSTS_NAME_SIZE - 1] = '\0';
    }

    return (slen == 0);
#endif
}

void qsc_netutils_get_name_from_ipv4_address(const qsc_ipinfo_ipv4_address* address, char host[QSC_NETUTILS_HOSTS_NAME_SIZE])
{
	assert(address != NULL);

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

	WSADATA wsd;
	int32_t err;
	int32_t slen;

	if (WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd) == 0)
	{
		struct sockaddr_in insock4 = { 0 };

		slen = QSC_IPINFO_IPV4_BYTELEN;
		insock4.sin_family = AF_INET;
		
		err = WSAStringToAddressW((LPWSTR)address->ipv4, AF_INET, NULL, (LPSOCKADDR)&insock4, &slen);
		
		if (err == 0 && slen > 0)
		{
			char aurl[NI_MAXSERV] = { 0 };

			if (getnameinfo((const SOCKADDR*)&insock4, (socklen_t)sizeof(insock4), (PCHAR)aurl, (DWORD)sizeof(aurl), NULL, 0, NI_NAMEREQD) == 0)
			{
				qsc_stringutils_copy_string(host, QSC_NETUTILS_HOSTS_NAME_SIZE, aurl);
			}
		}

		WSACleanup();
	}
	
#else

    struct sockaddr_in insock4;
    socklen_t addrlen;
    char aurl[NI_MAXHOST] = { 0 };
    char sip[QSC_IPINFO_IPV4_STRNLEN] = { 0 };

    // Initialize sockaddr_in struct for IPv4
    qsc_memutils_clear(&insock4, sizeof(insock4));
    insock4.sin_family = AF_INET;

    qsc_ipinfo_ipv4_address_to_string(sip, address);

    //address.ipv4
    inet_pton(AF_INET, sip, &insock4.sin_addr);

    // Set the address length to sizeof(sockaddr_in) for getnameinfo
    addrlen = sizeof(insock4);

    // Call getnameinfo to resolve the hostname
    if (getnameinfo((struct sockaddr*)&insock4, addrlen, aurl, sizeof(aurl), NULL, 0, NI_NAMEREQD) == 0)
    {
        qsc_stringutils_copy_string(host, QSC_NETUTILS_HOSTS_NAME_SIZE, aurl);
    }
#endif
}

bool qsc_netutils_get_ipv4_address(qsc_ipinfo_ipv4_address* padd)
{
	assert(padd != NULL);

	qsc_socket_exceptions serr;

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

	char hname[INET_ADDRSTRLEN] = { 0 };
	struct addrinfo hints = { 0 };
	struct sockaddr_in insock4 = { 0 };
	WSADATA wsd = { 0 };
	struct addrinfo* hres;
	struct addrinfo* ralloc;
	size_t pctr;

	hres = NULL;
	ralloc = NULL;
	serr = (qsc_socket_exceptions)WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd);

	if (serr == qsc_socket_exception_success)
	{
		qsc_memutils_clear(&hints, sizeof(hints));
		qsc_memutils_clear(&insock4, sizeof(struct sockaddr_in));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		serr = (qsc_socket_exceptions)gethostname(hname, sizeof(hname));

		if (serr == qsc_socket_exception_success)
		{
			serr = (qsc_socket_exceptions)getaddrinfo(hname, NULL, &hints, &hres);

			if (serr == qsc_socket_exception_success)
			{
				const size_t ADDMAX = 32;

				ralloc = hres;
				pctr = 0;

				while (hres)
				{
					if (hres->ai_family == AF_INET)
					{
						qsc_memutils_copy(&insock4, hres->ai_addr, hres->ai_addrlen);
						insock4.sin_port = htons(9);
						insock4.sin_family = AF_INET;

						if (inet_ntop(AF_INET, &insock4.sin_addr, hname, INET_ADDRSTRLEN) != NULL)
						{
							if (inet_pton(AF_INET, hname, padd->ipv4) == NETUTILS_INET_PTON_SUCCESS)
							{
								serr = qsc_socket_exception_success;
								break;
							}
							else
							{
								serr = qsc_socket_exception_error;
							}
						}
						else
						{
							serr = qsc_socket_exception_error;
						}
					}

					hres = hres->ai_next;
					++pctr;

					if (pctr > ADDMAX)
					{
						break;
					}
				}

				freeaddrinfo(ralloc);
			}
		}

		WSACleanup();
	}

#else

	struct ifaddrs* ifas;
	struct ifaddrs* ifa;
	void* pva;

	ifas = NULL;
	ifa = NULL;
	pva = NULL;

	serr = qsc_socket_exception_error;

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
                pva = &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
				char buf[INET_ADDRSTRLEN] = { 0 };

                if (inet_ntop(AF_INET, pva, buf, INET_ADDRSTRLEN) != NULL)
                {
					if (inet_pton(AF_INET, buf, padd->ipv4) == 1)
					{
						serr = qsc_socket_exception_success;
						break;
					}
                }
            }
        }

		freeifaddrs(ifas);
	}

#endif

	return (serr == qsc_socket_exception_success);
}

bool qsc_netutils_get_ipv6_address(qsc_ipinfo_ipv6_address* padd)
{
	assert(padd != NULL);

	qsc_socket_exceptions serr;

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
	char hname[INET6_ADDRSTRLEN] = { 0 };
	struct addrinfo hints = { 0 };
	struct sockaddr_in6 insock6 = { 0 };
	WSADATA wsd = { 0 };
	struct addrinfo* hres;
	struct addrinfo* ralloc;
	size_t pctr;
	
	hres = NULL;
	ralloc = NULL;
	serr = (qsc_socket_exceptions)WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd);

	if (serr == qsc_socket_exception_success)
	{
		qsc_memutils_clear(&hints, sizeof(hints));
		qsc_memutils_clear(&insock6, sizeof(struct sockaddr_in6));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = AI_PASSIVE;

		serr = (qsc_socket_exceptions)gethostname(hname, sizeof(hname));

		if (serr == qsc_socket_exception_success)
		{
			serr = (qsc_socket_exceptions)getaddrinfo(hname, NULL, &hints, &hres);

			if (serr == qsc_socket_exception_success)
			{
				const size_t ADDMAX = 32;

				pctr = 0;
				ralloc = hres;

				while (hres != NULL)
				{
					if (hres->ai_family == AF_INET6)
					{
						qsc_memutils_copy(&insock6, hres->ai_addr, hres->ai_addrlen);
						insock6.sin6_port = htons(9);
						insock6.sin6_family = AF_INET6;

						if (inet_ntop(AF_INET6, &insock6.sin6_addr, hname, INET6_ADDRSTRLEN) != NULL)
						{
							if (inet_pton(AF_INET6, hname, padd->ipv6) == NETUTILS_INET_PTON_SUCCESS)
							{
								serr = qsc_socket_exception_success;
								break;
							}
							else
							{
								serr = qsc_socket_exception_error;
							}
						}
						else
						{
							serr = qsc_socket_exception_error;
						}
					}

					hres = hres->ai_next;
					++pctr;

					if (pctr > ADDMAX)
					{
						break;
					}
				}

				freeaddrinfo(ralloc);
			}
		}

		WSACleanup();
	}

#else

	struct ifaddrs* ifas;
	struct ifaddrs* ifa;
	void* pva;

	ifas = NULL;
	ifa = NULL;
	pva = NULL;

	serr = qsc_socket_exception_error;

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
                pva = &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
				char buf[INET6_ADDRSTRLEN] = { 0 };

                if (inet_ntop(AF_INET6, pva, buf, INET6_ADDRSTRLEN) != NULL)
                {
					if (inet_pton(AF_INET6, buf, padd->ipv6) == 1)
					{
						serr = qsc_socket_exception_success;
						break;
					}
                }
            }
        }

		freeifaddrs(ifas);
	}

#endif

	return (serr == qsc_socket_exception_success);
}

void qsc_netutils_get_ipv4_info(qsc_ipinfo_ipv4_info* pinfo, const char* host, const char* service)
{
	assert(pinfo != NULL);
	assert(host != NULL);
	assert(service != NULL);

	char hname[INET_ADDRSTRLEN] = { 0 };
	struct addrinfo hints;
	struct addrinfo* hres = NULL;
	qsc_socket_exceptions ex;
	int32_t res;

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
    WSADATA wsd;
    res = WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd);
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
					inet_pton(AF_INET, hname, pinfo->address.ipv4);
					pinfo->port = ntohs(((struct sockaddr_in*)hres->ai_addr)->sin_port);
					pinfo->mask = qsc_ipinfo_ipv4_address_get_cidr_mask(&pinfo->address);
					freeaddrinfo(hres);
				}
			}
		}

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		WSACleanup();
#endif
	}
}

void qsc_netutils_get_ipv6_info(qsc_ipinfo_ipv6_info* pinfo, const char* host, const char* service)
{
	assert(pinfo != NULL);
	assert(host != NULL);
	assert(service != NULL);

	char buf[INET6_ADDRSTRLEN] = { 0 };
	struct addrinfo hints;
	struct sockaddr_in6 insock6 = { 0 };
	struct addrinfo* haddr = NULL;
	qsc_socket_exceptions ex;
	int32_t res;

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
    WSADATA wsd;
    res = WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd);
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
					inet_pton(AF_INET6, buf, pinfo->address.ipv6);
					pinfo->port = ntohs(((struct sockaddr_in6*)haddr->ai_addr)->sin6_port);
					pinfo->mask = qsc_ipinfo_ipv6_address_get_cidr_mask(&pinfo->address);
				}
			}

			freeaddrinfo(haddr);
		}

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		WSACleanup();
#endif
	}
}

void qsc_netutils_get_peer_name(char output[QSC_NETUTILS_HOSTS_NAME_SIZE], const qsc_socket* sock)
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

void qsc_netutils_get_socket_name(char output[QSC_NETUTILS_NAME_BUFFER_SIZE], const qsc_socket* sock)
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

uint16_t qsc_netutils_port_name_to_number(const char* portname, const char* protocol)
{
	assert(portname != NULL);
	assert(protocol != NULL);

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

#if defined(QSC_DEBUG_MODE)
void qsc_netutils_values_print()
{
	char domain[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };
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
	qsc_netutils_get_ipv4_address(&ipv4);
	qsc_ipinfo_ipv4_address_to_string(ipv4s, &ipv4);
	qsc_consoleutils_print_line(ipv4s);

	qsc_consoleutils_print_safe("IPv6 address: ");
	qsc_netutils_get_ipv6_address(&ipv6);
	qsc_ipinfo_ipv6_address_to_string(ipv6s, &ipv6);
	qsc_consoleutils_print_line(ipv6s);

	qsc_consoleutils_print_line("IPv4 info");
	qsc_netutils_get_ipv4_info(&ipv4inf, "127.0.0.1", "http");
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
	qsc_netutils_get_ipv6_info(&ipv6inf, "::1", "http");
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
#endif
