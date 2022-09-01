#include "netutils_test.h"
#include "../QSC/netutils.h"
#include "../QSC/socketclient.h"
#include "testutils.h"

static bool qsctest_address_info()
{
	qsc_ipinfo_ipv4_address addv4 = { 0 };
	qsc_ipinfo_ipv6_address addv6 = { 0 };
	qsc_ipinfo_ipv4_info infv4;
	qsc_ipinfo_ipv6_info infv6;
	char dom[QSC_NETUTILS_HOSTS_NAME_LENGTH] = { 0 };
	char saddv4[QSC_IPINFO_IPV4_STRNLEN] = { 0 };
	char saddv6[QSC_IPINFO_IPV6_STRNLEN] = { "1"};
	char portc[] = "80";
	char protc[] = "http";
	size_t len;
	uint16_t port;
	bool res;

	res = true;
	addv4 = qsc_netutils_get_ipv4_address();
	qsc_ipinfo_ipv4_address_to_string(saddv4, &addv4);
	infv4 = qsc_netutils_get_ipv4_info(saddv4, portc);

	if (qsc_ipinfo_ipv4_address_is_equal(&addv4, &infv4.address) == false)
	{
		qsctest_print_line("Failure! qsctest_address_info: assigned ipv4 address is not equal! -AI1");
		res = false;
	}
    else
    {
        qsctest_print_safe("IPv4 Address: ");
        qsctest_print_line(saddv4);
    }

	addv6 = qsc_netutils_get_ipv6_address();
	qsc_ipinfo_ipv6_address_to_string(saddv6, &addv6);
	infv6 = qsc_netutils_get_ipv6_info(saddv6, portc);

	if (qsc_ipinfo_ipv6_address_is_equal(&addv6, &infv6.address) == false)
	{
		qsctest_print_line("Failure! qsctest_address_info: assigned ipv6 address is not equal! -AI2");
		res = false;
	}
    else
    {
        qsctest_print_safe("IPv6 Address: ");
        qsctest_print_line(saddv6);
    }

	len = qsc_netutils_get_domain_name(dom);

	if (len == 0)
	{
		qsctest_print_line("The domain name was not detected.");
	}
    else
    {
        qsctest_print_safe("Domain name: ");
        qsctest_print_line(dom);
    }

	port = qsc_netutils_port_name_to_number(portc, protc);

	if (port != 80)
	{
		qsctest_print_line("Failure! qsctest_address_info: invalid port from service name conversion! -AI7");
	}

	return res;
}

void qsctest_netutils_run()
{
	if (qsctest_address_info() == true)
	{
		qsctest_print_line("Success! Passed the netutils address information tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the netutils address information tests.");
	}
}
