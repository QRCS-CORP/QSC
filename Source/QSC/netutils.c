/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "netutils.h"
#include "memutils.h"
#include "stringutils.h"
#include <stdlib.h>

#if defined(QSC_DEBUG_MODE)
#	include "consoleutils.h"
#endif

#include "netutils.h"
#include "memutils.h"
#include "socketbase.h"    /* moved here from netutils.h - qsc_socket_exceptions */
#include "stringutils.h"
#include <stdlib.h>

#if defined(QSC_DEBUG_MODE)
#   include "consoleutils.h"
#endif

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
#   define NETUTILS_WSA_STARTUP_SEQUENCE 0x0202
#   define NETUTILS_INET_PTON_SUCCESS 1
#   include "arrayutils.h"
#   include <winsock2.h>           /* WSAStartup, WSACleanup, WSADATA - must come first */
#   include <ws2tcpip.h>           /* getaddrinfo, freeaddrinfo, getnameinfo, inet_ntop, inet_pton */
#   include <ws2ipdef.h>           /* supplemental ws2 types */
#   include <iphlpapi.h>           /* GetAdaptersInfo, GetAdaptersAddresses, IP_ADAPTER_* */
#   include <sysinfoapi.h>         /* GetComputerNameEx, ComputerNameDnsDomain */
#   if defined(QSC_SYSTEM_COMPILER_MSC)
#       pragma comment(lib, "iphlpapi.lib")
#       pragma comment(lib, "ws2_32.lib")
#   endif
#else
#   include <arpa/inet.h>          /* inet_ntop, inet_pton, htons, ntohs */
#   include <errno.h>              /* errno */
#   include <ifaddrs.h>            /* getifaddrs, freeifaddrs, struct ifaddrs */
#   include <net/if.h>             /* IFF_LOOPBACK, IFF_BROADCAST */
#   include <netdb.h>              /* getaddrinfo, freeaddrinfo, getnameinfo, getservbyname, NI_* */
#   include <netinet/in.h>         /* struct sockaddr_in, sockaddr_in6, IPPROTO_* */
#   include <stdio.h>              /* printf, perror */
#   include <string.h>             /* strchr, strlen */
#   include <sys/socket.h>         /* struct sockaddr, getpeername, getsockname */
#   include <sys/types.h>          /* socklen_t, ssize_t */
#   include <unistd.h>             /* gethostname, close */
#   if defined(QSC_SYSTEM_OS_LINUX)
#       include <netpacket/packet.h>    /* struct sockaddr_ll, AF_PACKET */
#       if !defined(AF_LINK)
#           define AF_LINK AF_PACKET
#       endif
#   elif defined(QSC_SYSTEM_OS_MAC)  || \
         defined(QSC_SYSTEM_OS_BSD)  || \
         defined(QSC_SYSTEM_OS_FREEBSD) || \
         defined(QSC_SYSTEM_OS_OPENBSD) || \
         defined(QSC_SYSTEM_OS_NETBSD)
#       include <net/if_dl.h>          /* struct sockaddr_dl, LLADDR */
#   endif
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

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx, sizeof(qsc_netutils_adaptor_info));
	}

	if (ctx != NULL && infname != NULL && infname[0U] != '\0')
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		PIP_ADAPTER_INFO pinfo;
		PIP_ADAPTER_INFO cur;
		ULONG length;
		DWORD status;

		length = (ULONG)sizeof(IP_ADAPTER_INFO);
		pinfo = (PIP_ADAPTER_INFO)qsc_memutils_malloc((size_t)length);

		if (pinfo != NULL)
		{
			status = GetAdaptersInfo(pinfo, &length);

			if (status == ERROR_BUFFER_OVERFLOW)
			{
				qsc_memutils_alloc_free(pinfo);
				pinfo = (PIP_ADAPTER_INFO)qsc_memutils_malloc((size_t)length);
				status = (pinfo != NULL) ? GetAdaptersInfo(pinfo, &length) : ERROR_NOT_ENOUGH_MEMORY;
			}

			if (status == NO_ERROR)
			{
				for (cur = pinfo; cur != NULL; cur = cur->Next)
				{
					if (qsc_stringutils_string_contains(cur->AdapterName, infname) == true)
					{
						qsc_stringutils_copy_string(ctx->desc, sizeof(ctx->desc), cur->Description);
						qsc_stringutils_copy_string(ctx->dhcp, sizeof(ctx->dhcp), cur->DhcpServer.IpAddress.String);
						qsc_stringutils_copy_string(ctx->gateway, sizeof(ctx->gateway), cur->GatewayList.IpAddress.String);
						qsc_stringutils_copy_string(ctx->ip, sizeof(ctx->ip), cur->IpAddressList.IpAddress.String);
						qsc_stringutils_copy_string(ctx->name, sizeof(ctx->name), cur->AdapterName);
						qsc_stringutils_copy_string(ctx->subnet, sizeof(ctx->subnet), cur->IpAddressList.IpMask.String);

						if (cur->AddressLength == 6U)
						{
							netutils_format_mac(ctx->mac, cur->Address);
						}

						break;
					}
				}
			}

			if (pinfo != NULL)
			{
				qsc_memutils_alloc_free(pinfo);
			}
		}
#else
		struct ifaddrs* first;
		struct ifaddrs* cur;

		first = NULL;

		if (getifaddrs(&first) == 0)
		{
			for (cur = first; cur != NULL; cur = cur->ifa_next)
			{
				if (cur->ifa_addr != NULL && cur->ifa_name != NULL && strcmp(cur->ifa_name, infname) == 0)
				{
					qsc_stringutils_copy_string(ctx->name, sizeof(ctx->name), infname);
					qsc_stringutils_copy_string(ctx->desc, sizeof(ctx->desc), infname);

					if (cur->ifa_addr->sa_family == AF_INET)
					{
						const struct sockaddr_in* addr;

						addr = (const struct sockaddr_in*)cur->ifa_addr;
						(void)inet_ntop(AF_INET, &addr->sin_addr, ctx->ip, (socklen_t)sizeof(ctx->ip));

						if (cur->ifa_netmask != NULL && cur->ifa_netmask->sa_family == AF_INET)
						{
							const struct sockaddr_in* mask;

							mask = (const struct sockaddr_in*)cur->ifa_netmask;
							(void)inet_ntop(AF_INET, &mask->sin_addr, ctx->subnet, (socklen_t)sizeof(ctx->subnet));
						}
					}
#if defined(QSC_SYSTEM_OS_LINUX)
					else if (cur->ifa_addr->sa_family == AF_PACKET)
					{
						const struct sockaddr_ll* link;

						link = (const struct sockaddr_ll*)cur->ifa_addr;

						if (link->sll_halen == 6U)
						{
							netutils_format_mac(ctx->mac, link->sll_addr);
						}
					}
#elif defined(AF_LINK)
					else if (cur->ifa_addr->sa_family == AF_LINK)
					{
						const struct sockaddr_dl* link;

						link = (const struct sockaddr_dl*)cur->ifa_addr;

						if (link->sdl_alen == 6U)
						{
							netutils_format_mac(ctx->mac, (const uint8_t*)LLADDR(link));
						}
					}
#endif
				}
			}

			freeifaddrs(first);
		}
#endif
	}
}

void qsc_netutils_get_mac_address(uint8_t mac[QSC_NETUTILS_MAC_ADDRESS_SIZE])
{
	QSC_ASSERT(mac != NULL);

	bool res;

	res = false;

	if (mac != NULL)
	{
		qsc_memutils_clear(mac, 6U);

#if defined(QSC_SYSTEM_OS_LINUX)

		struct ifaddrs* ifaddr;

		ifaddr = NULL;

		if (getifaddrs(&ifaddr) == 0)
		{
			struct ifaddrs* cur;

			/* pass 1: wired Ethernet (IFF_BROADCAST set, not loopback). */
			cur = ifaddr;

			while (cur != NULL && res == false)
			{
				if (cur->ifa_addr != NULL &&
					cur->ifa_addr->sa_family == AF_PACKET &&
					(cur->ifa_flags & IFF_LOOPBACK) == 0 &&
					(cur->ifa_flags & IFF_BROADCAST) != 0)
				{
					struct sockaddr_ll* sll;

					sll = (struct sockaddr_ll*)cur->ifa_addr;

					if (sll->sll_halen == 6U)
					{
						qsc_memutils_copy(mac, sll->sll_addr, 6U);
						res = true;
					}
				}

				cur = cur->ifa_next;
			}

			/* pass 2: Wi-Fi fallback - any remaining AF_PACKET, non-loopback. */
			if (res == false)
			{
				cur = ifaddr;

				while (cur != NULL && res == false)
				{
					if (cur->ifa_addr != NULL &&
						cur->ifa_addr->sa_family == AF_PACKET &&
						(cur->ifa_flags & IFF_LOOPBACK) == 0)
					{
						struct sockaddr_ll* sll;

						sll = (struct sockaddr_ll*)cur->ifa_addr;

						if (sll->sll_halen == 6U)
						{
							qsc_memutils_copy(mac, sll->sll_addr, 6U);
							res = true;
						}
					}

					cur = cur->ifa_next;
				}
			}

			freeifaddrs(ifaddr);
			ifaddr = NULL;
		}

#elif defined(QSC_SYSTEM_OS_MAC) || defined(QSC_SYSTEM_OS_BSD)

		struct ifaddrs* ifaddr;

		ifaddr = NULL;

		if (getifaddrs(&ifaddr) == 0)
		{
			struct ifaddrs* cur;

			/* pass 1: wired Ethernet - IFF_BROADCAST set, not loopback. */
			cur = ifaddr;

			while (cur != NULL && res == false)
			{
				if (cur->ifa_addr != NULL &&
					cur->ifa_addr->sa_family == AF_LINK &&
					(cur->ifa_flags & IFF_LOOPBACK) == 0 &&
					(cur->ifa_flags & IFF_BROADCAST) != 0)
				{
					struct sockaddr_dl* sdl;

					sdl = (struct sockaddr_dl*)cur->ifa_addr;

					if (sdl->sdl_alen == 6U)
					{
						qsc_memutils_copy(mac,
							(const uint8_t*)sdl->sdl_data + sdl->sdl_nlen, 6U);
						res = true;
					}
				}

				cur = cur->ifa_next;
			}

			/* pass 2: Wi-Fi fallback - any AF_LINK, non-loopback. */
			if (res == false)
			{
				cur = ifaddr;

				while (cur != NULL && res == false)
				{
					if (cur->ifa_addr != NULL &&
						cur->ifa_addr->sa_family == AF_LINK &&
						(cur->ifa_flags & IFF_LOOPBACK) == 0)
					{
						struct sockaddr_dl* sdl;

						sdl = (struct sockaddr_dl*)cur->ifa_addr;

						if (sdl->sdl_alen == 6U)
						{
							qsc_memutils_copy(mac,
								(const uint8_t*)sdl->sdl_data + sdl->sdl_nlen, 6U);
							res = true;
						}
					}

					cur = cur->ifa_next;
				}
			}

			freeifaddrs(ifaddr);
			ifaddr = NULL;
		}

#elif defined(QSC_SYSTEM_OS_WINDOWS)

		IP_ADAPTER_ADDRESSES* adapters;
		ULONG buflen;
		ULONG ret;

		adapters = NULL;
		buflen = 0U;

		ret = GetAdaptersAddresses(
			AF_UNSPEC,
			GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
			GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
			NULL, NULL, &buflen);

		if (ret == ERROR_BUFFER_OVERFLOW && buflen > 0U)
		{
			adapters = (IP_ADAPTER_ADDRESSES*)qsc_memutils_malloc((size_t)buflen);

			if (adapters != NULL)
			{
				ret = GetAdaptersAddresses(
					AF_UNSPEC,
					GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
					GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
					NULL, adapters, &buflen);

				if (ret == NO_ERROR)
				{
					IP_ADAPTER_ADDRESSES* adapter;

					/* pass 1: wired Ethernet. */
					adapter = adapters;

					while (adapter != NULL && res == false)
					{
						if (adapter->IfType == IF_TYPE_ETHERNET_CSMACD &&
							adapter->OperStatus == IfOperStatusUp &&
							adapter->PhysicalAddressLength == 6U)
						{
							qsc_memutils_copy(mac, adapter->PhysicalAddress, 6U);
							res = true;
						}

						adapter = adapter->Next;
					}

					/* pass 2: Wi-Fi fallback. */
					if (res == false)
					{
						adapter = adapters;

						while (adapter != NULL && res == false)
						{
							if (adapter->IfType == IF_TYPE_IEEE80211 &&
								adapter->OperStatus == IfOperStatusUp &&
								adapter->PhysicalAddressLength == 6U)
							{
								qsc_memutils_copy(mac, adapter->PhysicalAddress, 6U);
								res = true;
							}

							adapter = adapter->Next;
						}
					}
				}

				qsc_memutils_alloc_free(adapters);
				adapters = NULL;
			}
		}

#endif
	}
}

uint32_t qsc_netutils_atoi(const char* source)
{
	QSC_ASSERT(source != NULL);

	uint32_t res;
	uint32_t digit;
	size_t i;

	res = 0U;

	if (source != NULL)
	{
		for (i = 0U; source[i] >= '0' && source[i] <= '9'; ++i)
		{
			digit = (uint32_t)(source[i] - '0');

			if (res > ((UINT32_MAX - digit) / 10U))
			{
				res = 0U;
				break;
			}

			res = (res * 10U) + digit;
		}
	}

	return res;
}

size_t qsc_netutils_get_domain_name(char output[QSC_NETUTILS_DOMAIN_NAME_SIZE])
{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)

	DWORD blen;
	TCHAR dbuf[QSC_SYSTEM_MAX_NAME + 1U] = { 0U };

	blen = QSC_SYSTEM_MAX_NAME + 1U;
	GetComputerNameEx(ComputerNameDnsDomain, dbuf, &blen);

	if (blen != 0U)
	{
		qsc_memutils_copy(output, dbuf, blen);
	}
	else
	{
		blen = QSC_SYSTEM_MAX_NAME + 1U;
		GetComputerNameEx(ComputerNameNetBIOS, dbuf, &blen);
		qsc_memutils_copy(output, dbuf, blen);
	}

	return blen;

#else

	char hn[QSC_SYSTEM_MAX_NAME + 1U] = { 0 };
	struct addrinfo hints = { 0 };
	struct addrinfo* res = NULL;
	size_t dlen;

	dlen = 0U;
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_CANONNAME;

	if (gethostname(hn, sizeof(hn)) == 0 &&
		getaddrinfo(hn, NULL, &hints, &res) == 0 && res != NULL)
	{
		if (res->ai_canonname != NULL)
		{
			const char* dot = strchr(res->ai_canonname, '.');

			if (dot != NULL)
			{
				dlen = strlen(dot + 1U);    /* skip the leading '.' */

				if (dlen < QSC_NETUTILS_DOMAIN_NAME_SIZE)
				{
					qsc_memutils_copy(output, dot + 1U, dlen);
				}
				else
				{
					dlen = 0U;
				}
			}
		}

		freeaddrinfo(res);
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
	QSC_ASSERT(host != NULL);

	if (address != NULL && host != NULL)
	{
		struct sockaddr_in addr;
		int32_t result;
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		WSADATA wsd;
#endif

		qsc_memutils_clear(&addr, sizeof(addr));
		qsc_memutils_clear(host, QSC_NETUTILS_HOSTS_NAME_SIZE);
		addr.sin_family = AF_INET;
		qsc_memutils_copy(&addr.sin_addr, address->ipv4, QSC_IPINFO_IPV4_BYTELEN);

#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		result = WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd);

		if (result == 0)
		{
			(void)getnameinfo((const struct sockaddr*)&addr, (socklen_t)sizeof(addr), host, QSC_NETUTILS_HOSTS_NAME_SIZE, NULL, 0, NI_NAMEREQD);
			(void)WSACleanup();
		}
#else
		result = getnameinfo((const struct sockaddr*)&addr, (socklen_t)sizeof(addr), host, QSC_NETUTILS_HOSTS_NAME_SIZE, NULL, 0, NI_NAMEREQD);
		(void)result;
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
		struct ifaddrs* first;
		struct ifaddrs* cur;
		const struct sockaddr_in* addr;
		bool found;

		first = NULL;
		found = false;

		if (getifaddrs(&first) == 0)
		{
			for (cur = first; cur != NULL; cur = cur->ifa_next)
			{
				if (cur->ifa_addr != NULL && cur->ifa_addr->sa_family == AF_INET)
				{
					addr = (const struct sockaddr_in*)cur->ifa_addr;
					qsc_memutils_copy(padd->ipv4, &addr->sin_addr, sizeof(padd->ipv4));
					serr = qsc_socket_exception_success;
					found = true;

					if ((cur->ifa_flags & IFF_LOOPBACK) == 0U)
					{
						break;
					}
				}
			}

			freeifaddrs(first);
		}
		(void)found;
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
		struct ifaddrs* first;
		struct ifaddrs* cur;
		const struct sockaddr_in6* addr;
		bool found;

		first = NULL;
		found = false;

		if (getifaddrs(&first) == 0)
		{
			for (cur = first; cur != NULL; cur = cur->ifa_next)
			{
				if (cur->ifa_addr != NULL && cur->ifa_addr->sa_family == AF_INET6)
				{
					addr = (const struct sockaddr_in6*)cur->ifa_addr;
					qsc_memutils_copy(padd->ipv6, &addr->sin6_addr, sizeof(padd->ipv6));
					serr = qsc_socket_exception_success;
					found = true;

					if ((cur->ifa_flags & IFF_LOOPBACK) == 0U)
					{
						break;
					}
				}
			}

			freeifaddrs(first);
		}
		(void)found;
#endif
	}

	return (serr == qsc_socket_exception_success);
}

void qsc_netutils_get_ipv4_info(qsc_ipinfo_ipv4_info* pinfo, const char* host, const char* service)
{
	QSC_ASSERT(pinfo != NULL);
	QSC_ASSERT(host != NULL);
	QSC_ASSERT(service != NULL);

	if (pinfo != NULL)
	{
		qsc_memutils_clear(pinfo, sizeof(qsc_ipinfo_ipv4_info));
	}

	if (pinfo != NULL && host != NULL && service != NULL)
	{
		struct addrinfo hints;
		struct addrinfo* first;
		struct addrinfo* cur;
		int32_t res;
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		WSADATA wsd;
#endif

		first = NULL;
		qsc_memutils_clear(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_DGRAM;
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		res = WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd);
#else
		res = 0;
#endif
		if (res == 0)
		{
			if (getaddrinfo(host, service, &hints, &first) == 0)
			{
				for (cur = first; cur != NULL; cur = cur->ai_next)
				{
					if (cur->ai_family == AF_INET && cur->ai_addr != NULL && cur->ai_addrlen >= sizeof(struct sockaddr_in))
					{
						const struct sockaddr_in* addr;

						addr = (const struct sockaddr_in*)cur->ai_addr;
						qsc_memutils_copy(pinfo->address.ipv4, &addr->sin_addr, sizeof(pinfo->address.ipv4));
						pinfo->port = ntohs(addr->sin_port);
						pinfo->mask = qsc_ipinfo_ipv4_address_get_cidr_mask(&pinfo->address);
						break;
					}
				}

				freeaddrinfo(first);
			}
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
			(void)WSACleanup();
#endif
		}
	}
}

void qsc_netutils_get_ipv6_info(qsc_ipinfo_ipv6_info* pinfo, const char* host, const char* service)
{
	QSC_ASSERT(pinfo != NULL);
	QSC_ASSERT(host != NULL);
	QSC_ASSERT(service != NULL);

	if (pinfo != NULL)
	{
		qsc_memutils_clear(pinfo, sizeof(qsc_ipinfo_ipv6_info));
	}

	if (pinfo != NULL && host != NULL && service != NULL)
	{
		struct addrinfo hints;
		struct addrinfo* first;
		struct addrinfo* cur;
		int32_t res;
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		WSADATA wsd;
#endif

		first = NULL;
		qsc_memutils_clear(&hints, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_DGRAM;
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		res = WSAStartup(NETUTILS_WSA_STARTUP_SEQUENCE, &wsd);
#else
		res = 0;
#endif
		if (res == 0)
		{
			if (getaddrinfo(host, service, &hints, &first) == 0)
			{
				for (cur = first; cur != NULL; cur = cur->ai_next)
				{
					if (cur->ai_family == AF_INET6 && cur->ai_addr != NULL && cur->ai_addrlen >= sizeof(struct sockaddr_in6))
					{
						const struct sockaddr_in6* addr;

						addr = (const struct sockaddr_in6*)cur->ai_addr;
						qsc_memutils_copy(pinfo->address.ipv6, &addr->sin6_addr, sizeof(pinfo->address.ipv6));
						pinfo->port = ntohs(addr->sin6_port);
						pinfo->mask = qsc_ipinfo_ipv6_address_get_cidr_mask(&pinfo->address);
						break;
					}
				}

				freeaddrinfo(first);
			}
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
			(void)WSACleanup();
#endif
		}
	}
}

void qsc_netutils_get_peer_name(char output[QSC_NETUTILS_HOSTS_NAME_SIZE], const qsc_socket* sock)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(sock != NULL);

	if (output != NULL)
	{
		output[0U] = '\0';
	}

	if (output != NULL && sock != NULL)
	{
		struct sockaddr_storage addr;
		socklen_t length;
		int32_t res;

		qsc_memutils_clear(&addr, sizeof(addr));
		length = (socklen_t)sizeof(addr);
		res = getpeername(sock->connection, (struct sockaddr*)&addr, &length);

		if (res == 0 && length <= (socklen_t)sizeof(addr))
		{
			(void)getnameinfo((const struct sockaddr*)&addr, length, output, QSC_NETUTILS_HOSTS_NAME_SIZE, NULL, 0, NI_NUMERICHOST);
		}
	}
}

void qsc_netutils_get_socket_name(char output[QSC_NETUTILS_NAME_BUFFER_SIZE], const qsc_socket* sock)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(sock != NULL);

	if (output != NULL)
	{
		output[0U] = '\0';
	}

	if (output != NULL && sock != NULL)
	{
		struct sockaddr_storage addr;
		socklen_t length;
		int32_t res;

		qsc_memutils_clear(&addr, sizeof(addr));
		length = (socklen_t)sizeof(addr);
		res = getsockname(sock->connection, (struct sockaddr*)&addr, &length);

		if (res == 0 && length <= (socklen_t)sizeof(addr))
		{
			(void)getnameinfo((const struct sockaddr*)&addr, length, output, QSC_NETUTILS_NAME_BUFFER_SIZE, NULL, 0, NI_NUMERICHOST);
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

		uint32_t numeric;

		numeric = qsc_netutils_atoi(portname);
		port = (numeric <= UINT16_MAX) ? (uint16_t)numeric : 0U;

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
