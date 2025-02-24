/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
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

#ifndef QSCTEST_NETUTILS_TEST_H
#define QSCTEST_NETUTILS_TEST_H

#include "../QSC/common.h"

/**
 * \file netutils_test.h
 * \brief Tests for Network Utilities Functions.
 *
 * \details
 * This header defines functions that execute tests for the network utilities provided by the library.
 * The tests verify various network-related functionalities including:
 *
 * - **IPv4 Address Retrieval and Verification**:  
 *   The test retrieves the system's IPv4 address via `qsc_netutils_get_ipv4_address()`, converts it to a
 *   string representation using `qsc_ipinfo_ipv4_address_to_string()`, and then retrieves detailed IPv4
 *   information (such as the address associated with a given port) using `qsc_netutils_get_ipv4_info()`.
 *   The test confirms that the retrieved address matches the address contained in the IPv4 information.
 *
 * - **IPv6 Address Retrieval and Verification**:  
 *   Similarly, the test retrieves the system's IPv6 address with `qsc_netutils_get_ipv6_address()`, converts
 *   it to a string via `qsc_ipinfo_ipv6_address_to_string()`, and obtains corresponding IPv6 information via
 *   `qsc_netutils_get_ipv6_info()`. The test ensures that the addresses match.
 *
 * - **Domain Name Resolution**:  
 *   The test attempts to retrieve the host's domain name using `qsc_netutils_get_domain_name()`, printing
 *   the domain name if available.
 *
 * - **Port Name Conversion**:  
 *   Using a service name (e.g., "http") and its corresponding port string (e.g., "80"), the test converts
 *   these into a numeric port value with `qsc_netutils_port_name_to_number()` and verifies that the conversion
 *   returns the expected port number.
 *
 * The main test function, \c qsctest_netutils_run(), calls an internal helper function that performs these
 * checks and prints the corresponding success or failure messages to the console.
 */

/**
 * \brief Runs the network utilities tests.
 *
 * \details
 * This function executes the following tests:
 * - Retrieves and converts the system's IPv4 and IPv6 addresses, then obtains detailed information for each.
 * - Compares the retrieved addresses with the ones reported in the detailed info to ensure consistency.
 * - Retrieves and prints the host domain name.
 * - Converts a service name ("http") and port string ("80") into a numeric port, verifying that the conversion
 *   yields port 80.
 *
 * The function prints success messages if all tests pass, or failure messages if any test fails.
 */
void qsctest_netutils_run(void);


#endif
