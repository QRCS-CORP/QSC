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

#include "hwprovider_test.h"
#include "hwmock_test.h"
#include "p11_test.h"
#include "hwpkcs11tls_test.h"
#include "hwncrypt_test.h"
#include "hwncrypttls_test.h"
#include "hwtpm_test.h"
#include "hwtpmquote_test.h"
#include "hwatecc_test.h"
#include "hwse050_test.h"
#include "hwpsa_test.h"
#include "hwplatform_test.h"
#include "testutils.h"

/**
 * \brief Run the QSC hardware provider regression suites in fixed order.
 * \details Each named suite is called directly without a dispatch loop or registry.
 * The runner does not perform physical hardware qualification or benchmark testing.
 * \return Zero if all suites succeed; otherwise returns nonzero.
 * \note The program has no persistent state and uses QSCTest-provided fixtures.
 */
int main(void)
{
	bool passed;

	passed = true;
	qsctest_print_line("QRCS | QSC HARDWARE INTEGRATION QUALIFICATION");
	qsctest_print_line("Stage 12 | Sequential provider contract and fault tests");

	if (qsctest_hwprovider_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 1 hardware provider contract suite");
	}

	if (qsctest_hwmock_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 2 deterministic mock provider suite");
	}

	if (qsctest_p11_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 3 PKCS11 loader and session suite");
	}

	if (qsctest_hwpkcs11tls_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 5 PKCS11 TLS and X509 suite");
	}

	if (qsctest_hwncrypt_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 7 NCrypt provider contract suite");
	}

	if (qsctest_hwncrypttls_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 7 NCrypt TLS signer suite");
	}

	if (qsctest_hwtpm_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 8 TPM provider contract suite");
	}

	if (qsctest_hwtpmquote_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 8 TPM quote verification suite");
	}

	if (qsctest_hwatecc_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 9 ATECC adapter suite");
	}

	if (qsctest_hwse050_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 9 SE050 PKCS11 profile suite");
	}

	if (qsctest_hwpsa_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 10 Arm PSA contract suite");
	}

	if (qsctest_hwplatform_run() == false)
	{
		passed = false;
		qsctest_print_line("[FAIL] Stage 11 platform keystore contract suite");
	}

	if (passed == true)
	{
		qsctest_print_line("[PASS] Stage 12 combined hardware provider regression");
	}
	else
	{
		qsctest_print_line("[FAIL] Stage 12 combined hardware provider regression");
	}

	return (passed == true) ? 0 : 1;
}
