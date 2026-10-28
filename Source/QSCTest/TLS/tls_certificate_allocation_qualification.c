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

#include "tlscert.h"
#include "x509store.h"
#include "memutils.h"
#include <stdio.h>
#include <time.h>

/**
 * \file tls_certificate_allocation_qualification.c
 * \brief Standalone TLS certificate-chain validation allocation regression.
 * \details Exercises minimum and maximum accepted chain counts with malformed
 * certificate data. No private material is stored; all storage is local.
 */

/**
 * \brief Test invalid DER rejection at an exact bounded certificate count.
 * \param count Number of certificate views; valid values are one through eight.
 * \param iterations Number of deterministic negative validation invocations.
 * \param elapsed_us Receives total CPU microseconds, not wall-clock time.
 * \return True when every malformed certificate is rejected.
 * \note No shared state; not thread-safe if the caller shares the context.
 */
static bool qualification_invalid_chain(size_t count, size_t iterations, double* elapsed_us)
{
	qsc_tls_qsc_x509_context context;
	qsc_tls_certificate_validation_context validation;
	qsc_x509_store store;
	qsc_x509_time now;
	qsc_tls_certificate_view chain[8U];
	uint8_t invalid[5U] = { 0x30U, 0x82U, 0xFFU, 0xFFU, 0x00U };
	clock_t started;
	size_t i;
	size_t j;
	bool passed;

	qsc_memutils_clear(&context, sizeof(context));
	qsc_memutils_clear(&validation, sizeof(validation));
	qsc_memutils_clear(&store, sizeof(store));
	qsc_memutils_clear(&now, sizeof(now));
	qsc_memutils_clear(chain, sizeof(chain));
	passed = true;

	for (i = 0U; i < count; ++i)
	{
		chain[i].data = invalid;
		chain[i].datalen = sizeof(invalid);
	}

	now.year = 2026U;
	now.month = 10U;
	now.day = 27U;
	passed = (qsc_tls_x509_context_initialize(&context, &store, NULL, 0U, &now, NULL, 0U) == qsc_tls_status_success);

	started = clock();

	for (j = 0U; j < iterations && passed == true; ++j)
	{
		passed = (qsc_tls_x509_validate_chain(chain, count, &validation, &context) == false);
		passed = (passed == true && context.lastverifystatus == QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE);
	}

	*elapsed_us = ((double)(clock() - started) * 1000000.0) / (double)CLOCKS_PER_SEC;
	return passed;
}

/**
 * \brief Verify the single-certificate malformed-chain path.
 * \param elapsed_us Receives CPU microseconds for five hundred invocations.
 * \return True if every invocation rejects the invalid certificate.
 * \note Synchronous, deterministic, and does not retain state.
 */
static bool qualification_one_certificate(double* elapsed_us)
{
	bool res;

	res = qualification_invalid_chain(1U, 500U, elapsed_us);
	return res;
}

/**
 * \brief Verify the two-certificate malformed-chain path.
 * \param elapsed_us Receives CPU microseconds for five hundred invocations.
 * \return True if every invocation rejects the invalid certificate.
 * \note Synchronous, deterministic, and does not retain state.
 */
static bool qualification_two_certificates(double* elapsed_us)
{
	bool res;

	res = qualification_invalid_chain(2U, 500U, elapsed_us);
	return res;
}

/**
 * \brief Verify the maximum accepted eight-certificate chain count.
 * \param elapsed_us Receives CPU microseconds for three hundred invocations.
 * \return True if every invocation rejects the invalid certificate.
 * \note Synchronous, deterministic, and does not retain state.
 */
static bool qualification_eight_certificates(double* elapsed_us)
{
	bool res;

	res = qualification_invalid_chain(8U, 300U, elapsed_us);
	return res;
}

/**
 * \brief Run separately named TLS certificate allocation regressions directly.
 * \return Zero if all checks pass, otherwise one.
 * \note Synchronous; no persistent memory allocation or runtime file writes.
 */
int main(void)
{
	double small_us;
	double middle_us;
	double maximum_us;
	bool passed;
	bool res;

	passed = true;
	small_us = 0.0;
	middle_us = 0.0;
	maximum_us = 0.0;

	res = qualification_one_certificate(&small_us);
	printf("%s TLS malformed one-certificate chain: %.3f us/validation\n", res ? "PASS" : "FAIL", small_us / 500.0);
	passed = res && passed;

	res = qualification_two_certificates(&middle_us);
	printf("%s TLS malformed two-certificate chain: %.3f us/validation\n", res ? "PASS" : "FAIL", middle_us / 500.0);
	passed = res && passed;

	res = qualification_eight_certificates(&maximum_us);
	printf("%s TLS malformed eight-certificate chain: %.3f us/validation\n", res ? "PASS" : "FAIL", maximum_us / 300.0);
	passed = res && passed;

	printf("TLS_CERT_ALLOC_QUALIFICATION=%s\n", passed ? "PASS" : "FAIL");
	return passed ? 0 : 1;
}
