#include "netutils.h"

namespace QSCNETCW
{
    using namespace System::Runtime::InteropServices;

    void NetUtils::GetAdaptorInfo(IntPtr infoPtr, String^ ifname)
    {
        if (infoPtr != IntPtr::Zero && String::IsNullOrEmpty(ifname) == false)
        {
            qsc_netutils_adaptor_info* ptr = reinterpret_cast<qsc_netutils_adaptor_info*>(infoPtr.ToPointer());

            IntPtr pifname = Marshal::StringToHGlobalAnsi(ifname);
            qsc_netutils_get_adaptor_info(ptr, static_cast<char*>(pifname.ToPointer()));
            Marshal::FreeHGlobal(pifname);
        }
    }

    bool NetUtils::GetMacAddress(array<Byte>^ mac)
    {
        bool res;

        res = false;

        if (mac != nullptr && mac->LongLength >= QSC_NETUTILS_MAC_ADDRESS_SIZE)
        {
            uint8_t tmp[QSC_NETUTILS_MAC_ADDRESS_SIZE] = { 0 };
            qsc_netutils_get_mac_address(tmp);

            for (int i = 0; i < QSC_NETUTILS_MAC_ADDRESS_SIZE; ++i)
            {
                mac[i] = tmp[i];
            }

            res = true;
        }

        return res;
    }

    UInt32 NetUtils::Atoi(String^ source)
    {
        UInt32 res;

        res = 0;

        if (String::IsNullOrEmpty(source) == false)
        {
            IntPtr psource = Marshal::StringToHGlobalAnsi(source);
            res = static_cast<UInt32>(qsc_netutils_atoi(static_cast<char*>(psource.ToPointer())));
            Marshal::FreeHGlobal(psource);
        }

        return res;
    }

    bool NetUtils::GetDomainName(String^% output)
    {
        char buf[QSC_NETUTILS_DOMAIN_NAME_SIZE] = { 0 };
        size_t len = qsc_netutils_get_domain_name(buf);
        bool res;

        res = false;

        if (len > 0)
        {
            output = gcnew String(buf);
            res = true;
        }

        return res;
    }

    bool NetUtils::GetHostName(String^% host)
    {
        char buf[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };
        bool res;

        res = false;

        if (qsc_netutils_get_host_name(buf) == true)
        {
            host = gcnew String(buf);
            res = true;
        }

        return res;
    }

    void NetUtils::GetNameFromIPv4Address(IntPtr addressPtr, String^% host)
    {
        if (addressPtr != IntPtr::Zero)
        {
            qsc_ipinfo_ipv4_address* addr = reinterpret_cast<qsc_ipinfo_ipv4_address*>(addressPtr.ToPointer());
            char buf[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };

            qsc_netutils_get_name_from_ipv4_address(addr, buf);
            host = gcnew String(buf);
        }
    }

    bool NetUtils::GetIPv4Address(IntPtr addressPtr)
    {
        bool res;

        res = false;

        if (addressPtr != IntPtr::Zero)
        {
            qsc_ipinfo_ipv4_address* ptr = reinterpret_cast<qsc_ipinfo_ipv4_address*>(addressPtr.ToPointer());
            res = qsc_netutils_get_ipv4_address(ptr);
        }

        return res;
    }

    bool NetUtils::GetIPv6Address(IntPtr addressPtr)
    {
        bool res;

        res = false;

        if (addressPtr != IntPtr::Zero)
        {
            qsc_ipinfo_ipv6_address* ptr = reinterpret_cast<qsc_ipinfo_ipv6_address*>(addressPtr.ToPointer());
            res = qsc_netutils_get_ipv6_address(ptr);
        }

        return res;
    }

    void NetUtils::GetIPv4Info(IntPtr infoPtr, String^ host, String^ service)
    {
        if (infoPtr != IntPtr::Zero && String::IsNullOrEmpty(host) == false && String::IsNullOrEmpty(service) == false)
        {
            qsc_ipinfo_ipv4_info* pinfo = reinterpret_cast<qsc_ipinfo_ipv4_info*>(infoPtr.ToPointer());

            IntPtr phost = Marshal::StringToHGlobalAnsi(host);
            IntPtr pserv = Marshal::StringToHGlobalAnsi(service);

            qsc_netutils_get_ipv4_info(pinfo, static_cast<char*>(phost.ToPointer()), static_cast<char*>(pserv.ToPointer()));

            Marshal::FreeHGlobal(phost);
            Marshal::FreeHGlobal(pserv);
        }
    }

    void NetUtils::GetIPv6Info(IntPtr infoPtr, String^ host, String^ service)
    {
        if (infoPtr != IntPtr::Zero && String::IsNullOrEmpty(host) == false && String::IsNullOrEmpty(service) == false)
        {
            qsc_ipinfo_ipv6_info* pinfo = reinterpret_cast<qsc_ipinfo_ipv6_info*>(infoPtr.ToPointer());

            IntPtr phost = Marshal::StringToHGlobalAnsi(host);
            IntPtr pserv = Marshal::StringToHGlobalAnsi(service);

            qsc_netutils_get_ipv6_info(pinfo, static_cast<char*>(phost.ToPointer()), static_cast<char*>(pserv.ToPointer()));

            Marshal::FreeHGlobal(phost);
            Marshal::FreeHGlobal(pserv);
        }
    }

    void NetUtils::GetPeerName(String^% output, IntPtr sockPtr)
    {
        if (sockPtr != IntPtr::Zero)
        {
            qsc_socket* sock = reinterpret_cast<qsc_socket*>(sockPtr.ToPointer());
            char buf[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };

            qsc_netutils_get_peer_name(buf, sock);
            output = gcnew String(buf);
        }
    }

    void NetUtils::GetSocketName(String^% output, IntPtr sockPtr)
    {
        if (sockPtr != IntPtr::Zero)
        {
            qsc_socket* sock = reinterpret_cast<qsc_socket*>(sockPtr.ToPointer());
            char buf[QSC_NETUTILS_NAME_BUFFER_SIZE] = { 0 };

            qsc_netutils_get_socket_name(buf, sock);
            output = gcnew String(buf);
        }
    }

    UInt16 NetUtils::PortNameToNumber(String^ portname, String^ protocol)
    {
        UInt16 res;

        res = 0;

        if (String::IsNullOrEmpty(portname) == false && String::IsNullOrEmpty(protocol) == false)
        {
            IntPtr pport = Marshal::StringToHGlobalAnsi(portname);
            IntPtr pprot = Marshal::StringToHGlobalAnsi(protocol);

            res = qsc_netutils_port_name_to_number(static_cast<char*>(pport.ToPointer()), static_cast<char*>(pprot.ToPointer()));

            Marshal::FreeHGlobal(pport);
            Marshal::FreeHGlobal(pprot);
        }

        return res;
    }
}
