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
#elif defined(QSC_SYSTEM_OS_MAC)
#	include <unistd.h>
#	include <string.h>
#	include <stdio.h>
#	include <sys/types.h>
#   include <ifaddrs.h>
#   include <arpa/inet.h>
#   include <netdb.h>
#   include <netinet/in.h>
#   include <sys/socket.h>
#	include <net/if_dl.h>
#	include <netinet/in.h>
#	include <sys/socket.h>
#else
#	include <unistd.h>
#	include <string.h>
#	include <stdio.h>
#	include <sys/types.h>
#	include <linux/if_packet.h>
#   include <ifaddrs.h>
#   include <arpa/inet.h>
#   include <netdb.h>
#   include <netinet/in.h>
#   include <sys/socket.h>
#	if !defined(AF_LINK)
#		define AF_LINK AF_PACKET
#	endif
#endif

static void netutils_format_mac(char macout[18U], const uint8_t macin[6U])
{
	QSC_ASSERT(macout != NULL);
	QSC_ASSERT(macin != NULL);

    static const char hex[] = "0123456789abcdef";

    for (size_t i = 0U; i < 6U; ++i)
    {
        macout[i * 3U] = hex[(macin[i] >> 4U) & 0xFU];
        macout[i * 3U + 1U] = hex[ macin[i] & 0xFU];

        if (i < 5U)
        {
            macout[(i * 3U) + 2U] = ':';
        }
    }

    macout[17U] = '\0';
}

void qsc_netutils_get_adaptor_info(qsc_netutils_adaptor_info* ctx, const char* infname)
{
	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(infname != NULL);

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

	if (ctx != NULL && infname != NULL)
	{
		PIP_ADAPTER_INFO padapt;
		PIP_ADAPTER_INFO pinfo;
		ULONG otplen;
		size_t pctr;
		const size_t PINTMX = 32U;

		qsc_memutils_clear(ctx, sizeof(qsc_netutils_adaptor_info));
		otplen = sizeof(IP_ADAPTER_INFO);
		pinfo = (IP_ADAPTER_INFO*)qsc_memutils_malloc(sizeof(IP_ADAPTER_INFO));

		if (pinfo != NULL)
		{
			if (GetAdaptersInfo(pinfo, &otplen) == ERROR_BUFFER_OVERFLOW)
			{
				free(pinfo);
				pinfo = (IP_ADAPTER_INFO*)qsc_memutils_malloc(otplen);
			}

			if (pinfo != NULL)
			{
				if (GetAdaptersInfo(pinfo, &otplen) == NO_ERROR)
				{
					padapt = pinfo;
					pctr = 0U;

					while (pinfo != NULL)
					{
						if (qsc_stringutils_string_contains((const char*)pinfo->AdapterName, infname) == true)
						{
							qsc_stringutils_copy_string(ctx->desc, sizeof(ctx->desc), pinfo->Description);
							qsc_stringutils_copy_string(ctx->dhcp, sizeof(ctx->dhcp), pinfo->DhcpServer.IpAddress.String);
							qsc_stringutils_copy_string(ctx->gateway, sizeof(ctx->gateway), pinfo->GatewayList.IpAddress.String);
							qsc_stringutils_copy_string(ctx->ip, sizeof(ctx->ip), pinfo->IpAddressList.IpAddress.String);
							qsc_stringutils_copy_string(ctx->name, sizeof(ctx->name), pinfo->AdapterName);
							qsc_stringutils_copy_string(ctx->subnet, sizeof(ctx->subnet), pinfo->IpAddressList.IpMask.String);
							qsc_memutils_copy(ctx->mac, pinfo->Address, sizeof(pinfo->Address));
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
#if defined(QSC_SYSTEM_OS_MAC)
    if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK)
    {
        uint8_t *maddr = (uint8_t *)LLADDR((struct sockaddr_dl *)ifa->ifa_addr);

        netutils_format_mac(ctx->mac, maddr);
        break;
    }

#elif defined(QSC_SYSTEM_OS_LINUX)
		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == AF_LINK)
			{
				uint8_t* maddr;

				maddr = (unsigned char*)LLADDR((struct sockaddr_dl*)(ifa)->ifa_addr);
				netutils_format_mac(ctx->mac, maddr);
				break;
			}
		}
#else
		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
			if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
				struct sockaddr_ll *s = (struct sockaddr_ll*)ifa->ifa_addr;

				netutils_format_mac(ctx->mac, s->sll_addr);
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
	QSC_ASSERT(mac != NULL);

	qsc_netutils_adaptor_info ctx = { 0U };

	qsc_netutils_get_adaptor_info(&ctx, "wlan0");
	qsc_memutils_copy(mac, ctx.mac, QSC_NETUTILS_MAC_ADDRESS_SIZE);
}

uint32_t qsc_netutils_atoi(const char* source)
{
	QSC_ASSERT(source != NULL);

	size_t len;
	uint32_t res;

	res = 0;

	if (source != NULL)
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		len = strnlen_s(source, 10U);
#else
		len = strlen(source);
#endif

		for (size_t i = 0U; i < len; ++i)
		{
			if (source[i] == '\0' || source[i] < 48 || source[i] > 57)
			{
				break;
			}

			res = res * 10U + source[i] - '0';
		}
	}

	return res;
}

size_t qsc_netutils_get_domain_name(char output[QSC_NETUTILS_DOMAIN_NAME_SIZE])
{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

	DWORD blen;
	TCHAR dbuf[QSC_SYSTEM_MAX_PATH + 1U] = { 0U };

	blen = QSC_SYSTEM_MAX_PATH + 1U;
	GetComputerNameEx(ComputerNameDnsDomain, dbuf, &blen);

	if (blen != 0U)
	{
		qsc_memutils_copy(output, dbuf, blen);
	}
	else
	{
		blen = QSC_SYSTEM_MAX_PATH + 1U;
		GetComputerNameEx(ComputerNameNetBIOS, dbuf, &blen);
		qsc_memutils_copy(output, dbuf, blen);
	}

	return blen;

#else

	char hn[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0U };
	char* dn;
	struct hostent* hp;
	size_t dlen;

    dlen = 0U;
    gethostname(hn, sizeof(hn));
    hp = gethostbyname(hn);

    if (hp != NULL)
	{
		dn = strchr(hp->h_name, '.');
		if (dn != NULL)
		{
			size_t len = strlen(dn);
			if (len > 0U && len < QSC_NETUTILS_DOMAIN_NAME_SIZE)
			{
				qsc_memutils_copy(output, dn, len);
				dlen = len;
			}
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
        host[QSC_NETUTILS_HOSTS_NAME_SIZE - 1U] = '\0';
    }

    return (slen == 0);
#endif
}

void qsc_netutils_get_name_from_ipv4_address(const qsc_ipinfo_ipv4_address* address, char host[QSC_NETUTILS_HOSTS_NAME_SIZE])
{
	QSC_ASSERT(address != NULL);

	if (address != NULL)
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

		WSADATA  wsd;
		int32_t  err;

		if (WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd) == 0)
		{
			struct sockaddr_in insock4 = { 0U };
			int32_t slen;

			slen = (int32_t)sizeof(insock4);
			insock4.sin_family = AF_INET;

			err = WSAStringToAddressW((LPWSTR)address->ipv4,
				AF_INET,
				NULL,
				(LPSOCKADDR)&insock4,
				&slen);

			if (err == 0)
			{
				char aurl[NI_MAXSERV] = { 0U };

				if (getnameinfo((const SOCKADDR*)&insock4,
					(socklen_t)sizeof(insock4),
					(PCHAR)aurl,
					(DWORD)sizeof(aurl),
					NULL, 0, NI_NAMEREQD) == 0)
				{
					qsc_stringutils_copy_string(host,
						QSC_NETUTILS_HOSTS_NAME_SIZE,
						aurl);
				}
			}
			(void)WSACleanup();
		}

#else

		struct sockaddr_in insock4;
		socklen_t addrlen;
		char aurl[NI_MAXHOST] = { 0U };
		char sip[QSC_IPINFO_IPV4_STRNLEN] = { 0U };

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
}

bool qsc_netutils_get_ipv4_address(qsc_ipinfo_ipv4_address* padd)
{
	QSC_ASSERT(padd != NULL);

	qsc_socket_exceptions serr;

	serr = qsc_socket_exception_error;

	if (padd != NULL)
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

		char hname[INET_ADDRSTRLEN] = { 0U };
		struct addrinfo hints = { 0U };
		struct sockaddr_in insock4 = { 0U };
		WSADATA wsd = { 0U };
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
					const size_t ADDMAX = 32U;

					ralloc = hres;
					pctr = 0;

					while (hres)
					{
						if (hres->ai_family == AF_INET)
						{
							qsc_memutils_copy((uint8_t*)&insock4, (const uint8_t*)hres->ai_addr, hres->ai_addrlen);
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
					char buf[INET_ADDRSTRLEN] = { 0U };

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
	}

	return (serr == qsc_socket_exception_success);
}

bool qsc_netutils_get_ipv6_address(qsc_ipinfo_ipv6_address* padd)
{
	QSC_ASSERT(padd != NULL);

	qsc_socket_exceptions serr;

	serr = qsc_socket_exception_error;

	if (padd != NULL)
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		char hname[INET6_ADDRSTRLEN] = { 0U };
		struct addrinfo hints = { 0U };
		struct sockaddr_in6 insock6 = { 0U };
		WSADATA wsd = { 0U };
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
					const size_t ADDMAX = 32U;

					pctr = 0;
					ralloc = hres;

					while (hres != NULL)
					{
						if (hres->ai_family == AF_INET6)
						{
							qsc_memutils_copy((uint8_t*)&insock6, (const uint8_t*)hres->ai_addr, hres->ai_addrlen);
							insock6.sin6_port = htons(9U);
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
					char buf[INET6_ADDRSTRLEN] = { 0U };

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
	}

	return (serr == qsc_socket_exception_success);
}

void qsc_netutils_get_ipv4_info(qsc_ipinfo_ipv4_info* pinfo, const char* host, const char* service)
{
	QSC_ASSERT(pinfo != NULL);
	QSC_ASSERT(host != NULL);
	QSC_ASSERT(service != NULL);

	if (pinfo != NULL && host != NULL && service != NULL)
	{
		char hname[INET_ADDRSTRLEN] = { 0U };
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
}

void qsc_netutils_get_ipv6_info(qsc_ipinfo_ipv6_info* pinfo, const char* host, const char* service)
{
	QSC_ASSERT(pinfo != NULL);
	QSC_ASSERT(host != NULL);
	QSC_ASSERT(service != NULL);

	if (pinfo != NULL && host != NULL && service != NULL)
	{
		char buf[INET6_ADDRSTRLEN] = { 0U };
		struct addrinfo hints;
		struct sockaddr_in6 insock6 = { 0U };
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
					qsc_memutils_copy((uint8_t*)&insock6, (const uint8_t*)haddr->ai_addr, haddr->ai_addrlen);
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
}

void qsc_netutils_get_peer_name(char output[QSC_NETUTILS_HOSTS_NAME_SIZE], const qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	if (sock != NULL)
	{
		struct sockaddr psa;
		socklen_t psalen;
		int32_t res;

		psalen = 0U;
		res = getpeername(sock->connection, &psa, &psalen);

		if (res != QSC_SOCKET_RET_ERROR && psalen > 0)
		{
			qsc_memutils_copy(output, psa.sa_data, (size_t)psalen);
		}
	}
}

void qsc_netutils_get_socket_name(char output[QSC_NETUTILS_NAME_BUFFER_SIZE], const qsc_socket* sock)
{
	QSC_ASSERT(sock != NULL);

	if (sock != NULL)
	{
		struct sockaddr psa;
		socklen_t psalen;
		int32_t res;

		psalen = 0;

		res = getsockname(sock->connection, &psa, &psalen);

		if (res != QSC_SOCKET_RET_ERROR && psalen > 0)
		{
			qsc_memutils_copy(output, psa.sa_data, (size_t)psalen);
		}
	}
}

uint16_t qsc_netutils_port_name_to_number(const char* portname, const char* protocol)
{
	QSC_ASSERT(portname != NULL);
	QSC_ASSERT(protocol != NULL);

	uint16_t port;

	port = 0;

	if (portname != NULL && protocol != NULL)
	{
		const struct servent* se;

		port = (uint16_t)qsc_netutils_atoi(portname);

		if (port == 0)
		{

			se = getservbyname(portname, protocol);

			if (se != NULL)
			{
				port = ntohs(se->s_port);
			}
		}
	}

	return port;
}

#if defined(QSC_DEBUG_MODE)
void qsc_netutils_values_print()
{
	char domain[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0U };
	char ipv4s[QSC_IPINFO_IPV4_STRNLEN] = { 0U };
	char ipv6s[QSC_IPINFO_IPV6_STRNLEN] = { 0U };
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

	if (rlen > 0U)
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
	qsc_netutils_adaptor_info info = { 0U };
	qsc_netutils_get_adaptor_info(&info, "loop0");
	qsc_consoleutils_print_line(info.desc);

	port = qsc_netutils_port_name_to_number("http", "http");
	qsc_consoleutils_print_uint((uint32_t)port);
	qsc_consoleutils_print_line("");
}
#endif
