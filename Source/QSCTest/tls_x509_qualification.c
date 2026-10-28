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

#include "qsccommon.h"
#include "selftest.h"
#include "encoding_test.h"
#include "tls_test.h"
#include "x509_test.h"
#include <stdio.h>

/**
 * \file tls_x509_qualification.c
 * \brief Noninteractive deterministic entry point for TLS, X.509 and encoding regressions.
 * \details All test groups are called directly in sequence. The caller must set the
 * current working directory so the existing X509/Vectors fixture paths resolve.
 * This file is built as a standalone application, not alongside qsc_test.c.
 */

/**
 * \brief Run symmetric primitive internal self-checks.
 * \return True if the symmetric self-tests pass.
 * \note QSC owns temporary state; execution is synchronous.
 */
static bool qualification_symmetric(void)
{
	bool res;

	res = qsc_selftest_symmetric_run();
	printf("QUAL_SYMMETRIC=%s\n", res ? "PASS" : "FAIL");
	return res;
}

/**
 * \brief Execute the existing encoding tests sequentially.
 * \return True only if Base64, BER, DER, hexadecimal and PEM tests all pass.
 * \note No shared state; execution is synchronous.
 */
static bool qualification_encoding(void)
{
	bool passed;
	bool res;

	passed = true;
	res = qsctest_encoding_base64();
	printf("QUAL_BASE64=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_encoding_ber();
	printf("QUAL_BER=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_encoding_der();
	printf("QUAL_DER=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_encoding_hex();
	printf("QUAL_HEX=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_encoding_pem();
	printf("QUAL_PEM=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	return passed;
}

/**
 * \brief Execute each established X.509 group directly, without test dispatch tables.
 * \return True only if all nine X.509 groups pass.
 * \note Fixtures remain owned by each test and the runner creates no outputs.
 */
static bool qualification_x509(void)
{
	bool passed;
	bool res;

	passed = true;
	res = qsctest_x509_stage1_run();
	printf("QUAL_X509_1=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_x509_stage2a_run();
	printf("QUAL_X509_2A=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_x509_stage2b_run();
	printf("QUAL_X509_2B=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_x509_stage2c_run();
	printf("QUAL_X509_2C=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_x509_stage2d_run();
	printf("QUAL_X509_2D=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_x509_stage3_run();
	printf("QUAL_X509_3=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_x509_stage4a_run();
	printf("QUAL_X509_4A=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_x509_stage4b_run();
	printf("QUAL_X509_4B=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qsctest_x509_stage5_run();
	printf("QUAL_X509_5=%s\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	return passed;
}

/**
 * \brief Execute the existing 37 TLS stages, each invoked directly by qsctest_tls_run.
 * \return True only when all TLS stages pass.
 * \note TLS integration tests may spawn their own threads internally.
 */
static bool qualification_tls(void)
{
	bool res;

	res = qsctest_tls_run();
	printf("QUAL_TLS_ALL_37=%s\n", res ? "PASS" : "FAIL");
	return res;
}

/**
 * \brief Run full targeted baseline qualification without interactive prompts.
 * \return Zero if all mandatory groups pass; one if any group fails.
 * \note The caller controls log redirection and working directory.
 */
int main(void)
{
	bool passed;
	bool res;

	passed = true;
	res = qualification_symmetric();
	passed = res && passed;
	res = qualification_encoding();
	passed = res && passed;
	res = qualification_x509();
	passed = res && passed;
	res = qualification_tls();
	passed = res && passed;
	printf("QUALIFICATION=%s\n", passed ? "PASS" : "FAIL");
	return passed ? 0 : 1;
}
