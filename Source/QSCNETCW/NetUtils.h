/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation
 * are proprietary to QRCS and its authorized licensors and are protected under
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software,
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or
 * implied, including but not limited to warranties of merchantability or fitness
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect,
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions
 * Proprietary License (QRCS-PL)**. The complete license terms are included
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSCNETCW_NETUTILS_H
#define QSCNETCW_NETUTILS_H

#include "Common.h"
#include "..\QSC\netutils.h"

namespace QSCNETCW
{
    /// <summary>
    /// Provides a static set of methods for retrieving and manipulating network adapter,
    /// host, and IP information. Wraps the <c>netutils.h</c> C library.
    /// </summary>
    public ref class NetUtils abstract sealed
    {
    public:

        /// <summary>
        /// Retrieves the address information on a named addressable interface.
        /// </summary>
        /// <param name="infoPtr">
        /// A pointer (IntPtr) to an allocated <c>qsc_netutils_adaptor_info</c> structure
        /// that will receive the interface details.
        /// </param>
        /// <param name="ifname">
        /// The adaptor interface name, e.g. "eth0" or "wlan0".
        /// </param>
        static void GetAdaptorInfo(IntPtr infoPtr, String^ ifname);

        /// <summary>
        /// Retrieves the MAC address of the primary interface.
        /// </summary>
        /// <param name="mac">
        /// A managed array to receive the MAC address (at least <c>QSC_NETUTILS_MAC_ADDRESS_SIZE</c> bytes).
        /// </param>
        static bool GetMacAddress(array<Byte>^ mac);

        /// <summary>
        /// Parses a string for a number (like atoi in C).
        /// </summary>
        /// <param name="source">The numeric string to convert.</param>
        /// <returns>The 32-bit number found in the string, or 0 on failure.</returns>
        static System::UInt32 Atoi(String^ source);

        /// <summary>
        /// Retrieves the host's domain name.
        /// </summary>
        /// <param name="output">
        /// A managed string reference to receive the domain name.
        /// </param>
        /// <returns>True on success, otherwise false.</returns>
        static bool GetDomainName(String^% output);

        /// <summary>
        /// Retrieves the host name of the local machine.
        /// </summary>
        /// <param name="host">
        /// A managed string reference to receive the host name.
        /// </param>
        /// <returns>True on success, otherwise false.</returns>
        static bool GetHostName(String^% host);

        /// <summary>
        /// Retrieves the fully qualified host name for a given IPv4 address.
        /// </summary>
        /// <param name="addressPtr">
        /// A pointer (IntPtr) to a <c>qsc_ipinfo_ipv4_address</c> structure containing the IPv4 address.
        /// </param>
        /// <param name="host">
        /// A managed string reference to receive the resolved host name.
        /// </param>
        static void GetNameFromIPv4Address(IntPtr addressPtr, String^% host);

        /// <summary>
        /// Retrieves the local IPv4 address.
        /// </summary>
        /// <param name="addressPtr">
        /// A pointer (IntPtr) to an allocated <c>qsc_ipinfo_ipv4_address</c> that will receive the address.
        /// </param>
        /// <returns>True on success, otherwise false.</returns>
        static bool GetIPv4Address(IntPtr addressPtr);

        /// <summary>
        /// Retrieves the local IPv6 address.
        /// </summary>
        /// <param name="addressPtr">
        /// A pointer (IntPtr) to an allocated <c>qsc_ipinfo_ipv6_address</c> that will receive the address.
        /// </param>
        /// <returns>True on success, otherwise false.</returns>
        static bool GetIPv6Address(IntPtr addressPtr);

        /// <summary>
        /// Retrieves the IPv4 address info for a remote host (host + service).
        /// </summary>
        /// <param name="infoPtr">
        /// A pointer (IntPtr) to a <c>qsc_ipinfo_ipv4_info</c> structure to receive the info.
        /// </param>
        /// <param name="host">
        /// The remote host's qualified name (String).
        /// </param>
        /// <param name="service">
        /// The service name (e.g. "http").
        /// </param>
        static void GetIPv4Info(IntPtr infoPtr, String^ host, String^ service);

        /// <summary>
        /// Retrieves the IPv6 address info for a remote host (host + service).
        /// </summary>
        static void GetIPv6Info(IntPtr infoPtr, String^ host, String^ service);

        /// <summary>
        /// Retrieves the peer (remote) name of a connected socket.
        /// </summary>
        /// <param name="output">A managed string reference to receive the peer name.</param>
        /// <param name="sockPtr">
        /// A pointer (IntPtr) to a <c>qsc_socket</c> describing the connected socket.
        /// </param>
        static void GetPeerName(String^% output, IntPtr sockPtr);

        /// <summary>
        /// Retrieves the socket name of a connected peer.
        /// </summary>
        /// <param name="output">A managed string reference to receive the socket name.</param>
        /// <param name="sockPtr">A pointer to the <c>qsc_socket</c> instance.</param>
        static void GetSocketName(String^% output, IntPtr sockPtr);

        /// <summary>
        /// Gets the port number for the specified port and protocol (like getservbyname).
        /// </summary>
        /// <param name="portname">
        /// The port name string, e.g. "http".
        /// </param>
        /// <param name="protocol">
        /// The protocol name, e.g. "tcp".
        /// </param>
        /// <returns>The numeric port number, or zero on failure.</returns>
        static UInt16 PortNameToNumber(String^ portname, String^ protocol);
    };
}

#endif
