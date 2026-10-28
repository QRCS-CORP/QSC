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


#include "tls_test.h"
#include "testutils.h"
#include "TLS/tls_stage1_codec_extension_tests.h"
#include "TLS/tls_stage2_certificate_tests.h"
#include "TLS/tls_stage3_keyupdate_tests.h"
#include "TLS/tls_stage4_enum_equivalence_tests.h"
#include "TLS/tls_stage5_subsystem_tests.h"
#include "TLS/tls_stage6_session_resumption_tests.h"
#include "TLS/tls_stage7_hrr_tests.h"
#include "TLS/tls_stage8_vector_tests.h"
#include "TLS/tls_stage9_tlscert_x509_tests.h"
#include "TLS/tls_stage10_0rtt_tests.h"
#include "TLS/tls_stage11_ecdsa_der_tests.h"
#include "TLS/tls_stage12_ecdsa_signer_tests.h"
#include "TLS/tls_stage13_secp256r1_tests.h"
#include "TLS/tls_stage14_e2e_tests.h"
#include "TLS/tls_stage15_truststore_tests.h"
#include "TLS/tls_stage16_psk_codec_tests.h"
#include "TLS/tls_stage17_multi_suite_tests.h"
#include "TLS/tls_stage18_0rtt_resumption_tests.h"
#include "TLS/tls_stage19_socket_wrapper_tests.h"
#include "TLS/tls_stage20_alpn_tests.h"
#include "TLS/tls_stage21_sni_tests.h"
#include "TLS/tls_stage22_mtls_authorization_tests.h"
#include "TLS/tls_stage23_peer_info_tests.h"
#include "TLS/tls_stage24_ticket_policy_tests.h"
#include "TLS/tls_stage25_framed_message_tests.h"
#include "TLS/tls_stage26_record_fragmentation_tests.h"
#include "TLS/tls_stage27_socket_options_tests.h"
#include "TLS/tls_stage28_concurrent_shutdown_tests.h"
#include "TLS/tls_stage29_negative_x509_tests.h"
#include "TLS/tls_stage30_post_handshake_dispatch_tests.h"
#include "TLS/tls_stage31_mtls_handshake_tests.h"
#include "TLS/tls_stage32_resumption_profile_tests.h"
#include "TLS/tls_stage33_rfc9846_compliance_tests.h"
#include "TLS/tls_stage34_rfc10024_hybrid_tests.h"
#include "TLS/tls_stage35_handshake_deadline_tests.h"
#include "TLS/tls_stage36_pq_standards_tests.h"
#include "TLS/tls_stage37_parameter_variants_tests.h"

bool qsctest_tls_run(void)
{
	bool res;

	res = true;

	qsctest_print_section("06.01", "TLS 01 | CODEC AND EXTENSIONS");
	if (qsctest_tls_stage1_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.02", "TLS 02 | CERTIFICATE MESSAGES");
	if (qsctest_tls_stage2_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.03", "TLS 03 | KEY UPDATE");
	if (qsctest_tls_stage3_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.04", "TLS 04 | ENUMERATION EQUIVALENCE");
	if (qsctest_tls_stage4_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.05", "TLS 05 | TLS SUBSYSTEM");
	if (qsctest_tls_stage5_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.06", "TLS 06 | SESSION RESUMPTION");
	if (qsctest_tls_stage6_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.07", "TLS 07 | HELLO RETRY REQUEST");
	if (qsctest_tls_stage7_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.08", "TLS 08 | RFC 8448 VECTORS");
	if (qsctest_tls_stage8_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.09", "TLS 09 | X.509 AND SPKI MAPPING");
	if (qsctest_tls_stage9_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.10", "TLS 10 | ZERO-RTT VECTORS");
	if (qsctest_tls_stage10_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.11", "TLS 11 | ECDSA DER CODEC");
	if (qsctest_tls_stage11_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.12", "TLS 12 | ECDSA SIGNER INTEROPERABILITY");
	if (qsctest_tls_stage12_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.13", "TLS 13 | SECP256R1 KEY EXCHANGE");
	if (qsctest_tls_stage13_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.14", "TLS 14 | END-TO-END HANDSHAKE");
	if (qsctest_tls_stage14_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.15", "TLS 15 | TRUST STORE INTEGRATION");
	if (qsctest_tls_stage15_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.16", "TLS 16 | PSK CODEC");
	if (qsctest_tls_stage16_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.17", "TLS 17 | MULTI-SUITE HANDSHAKES");
	if (qsctest_tls_stage17_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.18", "TLS 18 | RESUMPTION AND ZERO-RTT");
	if (qsctest_tls_stage18_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.19", "TLS 19 | SOCKET WRAPPER");
	if (qsctest_tls_stage19_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.20", "TLS 20 | ALPN NEGOTIATION");
	if (qsctest_tls_stage20_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.21", "TLS 21 | SNI NEGOTIATION");
	if (qsctest_tls_stage21_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.22", "TLS 22 | MUTUAL TLS AUTHORIZATION");
	if (qsctest_tls_stage22_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.23", "TLS 23 | PEER INFORMATION");
	if (qsctest_tls_stage23_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.24", "TLS 24 | SESSION TICKET POLICY");
	if (qsctest_tls_stage24_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.25", "TLS 25 | FRAMED MESSAGES");
	if (qsctest_tls_stage25_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.26", "TLS 26 | RECORD PROTECTION AND FRAGMENTATION");
	if (qsctest_tls_stage26_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.27", "TLS 27 | SOCKET CONFIGURATION");
	if (qsctest_tls_stage27_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.28", "TLS 28 | CONCURRENT SHUTDOWN");
	if (qsctest_tls_stage28_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.29", "TLS 29 | X.509 NEGATIVE VALIDATION");
	if (qsctest_tls_stage29_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.30", "TLS 30 | POST-HANDSHAKE MESSAGES");
	if (qsctest_tls_stage30_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.31", "TLS 31 | MUTUAL TLS HANDSHAKES");
	if (qsctest_tls_stage31_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.32", "TLS 32 | RESUMPTION PROFILE");
	if (qsctest_tls_stage32_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.33", "TLS 33 | RFC 9846 LIMITS");
	if (qsctest_tls_stage33_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.34", "TLS 34 | HYBRID KEY EXCHANGE");
	if (qsctest_tls_stage34_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.35", "TLS 35 | HANDSHAKE TIMEOUTS");
	if (qsctest_tls_stage35_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.36", "TLS 36 | PQC STANDARDS");
	if (qsctest_tls_stage36_tests() == false)
	{
		res = false;
	}

	qsctest_print_section("06.37", "TLS 37 | PARAMETER AND SIGNATURE VARIANTS");
	if (qsctest_tls_stage37_tests() == false)
	{
		res = false;
	}

	return res;
}
