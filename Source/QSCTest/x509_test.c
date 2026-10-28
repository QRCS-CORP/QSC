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


#include "x509_test.h"
#include "testutils.h"
#include "X509/x509_stage1_tests.h"
#include "X509/x509_stage2a_csr_tests.h"
#include "X509/x509_stage2b_pem_tests.h"
#include "X509/x509_stage2c_crl_tests.h"
#include "X509/x509_stage2d_negative_validation_tests.h"
#include "X509/x509_stage3_positive_interop_tests.h"
#include "X509/x509_stage4a_encoding_tests.h"
#include "X509/x509_stage4b_pqc_tests.h"
#include "X509/x509_stage5_ecdsa_digest_tests.h"

bool qsctest_x509_stage1_run(void)
{
	return qsctest_x509_stage1_tests();
}

bool qsctest_x509_stage2a_run(void)
{
	return qsctest_x509_stage2a_csr_tests();
}

bool qsctest_x509_stage2b_run(void) 
{
	return qsctest_x509_stage2b_pem_tests();
}

bool qsctest_x509_stage2c_run(void)
{
	return qsctest_x509_stage2c_crl_tests();
}

bool qsctest_x509_stage2d_run(void)
{
	return qsctest_x509_stage2d_negative_validation_tests();
}

bool qsctest_x509_stage3_run(void)
{
	return qsctest_x509_stage3_positive_interop_tests();
}

bool qsctest_x509_stage4a_run(void)
{
	return qsctest_x509_stage4a_encoding_tests();
}

bool qsctest_x509_stage4b_run(void)
{
	return qsctest_x509_stage4b_pqc_tests();
}

/** \brief Run ECDSA certificate digest interoperability regressions. \return True if all fixtures pass. */
bool qsctest_x509_stage5_run(void)
{
	return qsctest_x509_stage5_ecdsa_digest_tests();
}

void qsctest_x509_run(void)
{

	qsctest_print_line("Tests chain verification, CRL handling, CSR/PEM processing, and negative/positive validation scenarios.");

	qsctest_print_section("05.01", "CERTIFICATE CHAINS AND REVOCATION");
	if (qsctest_x509_stage1_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 certificate, chain, and revocation validation tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 certificate, chain, and revocation validation tests.");
	}

	qsctest_print_section("05.02", "CERTIFICATE SIGNING REQUESTS");
	if (qsctest_x509_stage2a_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 CSR generation, parsing, encoding, and round-trip tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 CSR generation, parsing, encoding tests.");
	}

	qsctest_print_section("05.03", "PEM AND DER PROCESSING");
	if (qsctest_x509_stage2b_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 PEM decoding, PEM encoding, bundle handling, and DER/PEM round-trip operations tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 PEM decoding, PEM encoding, bundle handling, and DER/PEM tests.");
	}

	qsctest_print_section("05.04", "CERTIFICATE REVOCATION LISTS");
	if (qsctest_x509_stage2c_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 validate CRL encoding, decoding, signature verification, revocation lookup tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 CRL encoding, decoding, signature verification tests.");
	}

	qsctest_print_section("05.05", "NEGATIVE CERTIFICATE VALIDATION");
	if (qsctest_x509_stage2d_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 validate rejection behavior for malformed, expired, invalid certificates tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 rejection behavior tests.");
	}

	qsctest_print_section("05.06", "POSITIVE CERTIFICATE VALIDATION");
	if (qsctest_x509_stage3_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 validate successful processing of correct certificates, chains, and related objects tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 processing of correct certificates tests.");
	}

	qsctest_print_section("05.07", "PQC ENCODING");
	if (qsctest_x509_stage4a_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 PQC ML-DSA/ML-KEM encoding tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 PQC ML-DSA/ML-KEM encoding tests.");
	}

	qsctest_print_section("05.08", "PQC CERTIFICATE COVERAGE");
	if (qsctest_x509_stage4b_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 PQC ML-DSA/ML-KEM coverage tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 PQC ML-DSA/ML-KEM tests.");
	}

	qsctest_print_section("05.09", "ECDSA CERTIFICATE INTEROPERABILITY");
	if (qsctest_x509_stage5_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 ECDSA digest-independent certificate tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 ECDSA certificate digest tests.");
	}

}
