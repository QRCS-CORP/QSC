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

#ifndef QSCTEST_NETUTILS_TEST_H
#define QSCTEST_NETUTILS_TEST_H

#include "qsccommon.h"

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
