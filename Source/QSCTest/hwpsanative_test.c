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

#include "hwpsanative_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PSA_ENABLED) && \
	defined(QSC_HARDWARE_PSA_NATIVE_ENABLED) && defined(QSC_TEST_PSA_KEY_ID) && \
	defined(QSC_TEST_PSA_LOCATION)

#include "hwpsanative.h"
#include "memutils.h"
#include "testutils.h"

/** \struct psa_native_fixture
 * \brief Non-destructive test ownership of an existing PSA identity.
 */
typedef struct psa_native_fixture
{
	qsc_hw_psa_native_service service; /**< Caller-owned native PSA configuration. */
	qsc_hw_psa_context context; /**< QSC PSA provider context. */
	qsc_hw_provider* provider; /**< Open wrapper around existing PSA service. */
	qsc_hw_keyref* key; /**< Open read-only transient handle, never delete key. */
} psa_native_fixture;

/** \brief Initialize one native PSA test fixture from compile-time target policy.
 * \param fixture Zero-initialized caller-owned fixture.
 * \return True only when PSA provider is successfully initialized and opened.
 */
static bool psa_native_test_open_provider(psa_native_fixture* fixture)
{
	qsc_hw_provider_ops operations = { 0U };
	qsc_hw_status status;
	bool valid;

	status = qsc_hw_psa_native_initialize(&fixture->context, &fixture->service,
		(uint32_t)QSC_TEST_PSA_KEY_ID, (uint32_t)QSC_TEST_PSA_LOCATION, false);
	valid = (status == qsc_hw_status_success);

	if (valid == true)
	{
		status = qsc_hw_psa_get_operations(&operations);
		valid = (status == qsc_hw_status_success);
	}

	if (valid == true)
	{
		status = qsc_hw_provider_open(&fixture->provider, &operations, &fixture->context);
		valid = (status == qsc_hw_status_success);
	}

	return valid;
}

/** \brief Open a pre-provisioned P-256 signing identity without modifying it.
 * \param fixture Initialized native PSA provider fixture.
 * \return True when PSA identifies existing non-exportable key and QSC policy allows access.
 */
static bool psa_native_test_open_identity(psa_native_fixture* fixture)
{
	qsc_hw_key_policy policy = { 0U };
	char locator[QSC_HW_PSA_LOCATOR_SIZE] = { 0U };
	qsc_hw_status status;
	size_t size;
	bool valid;

	size = sizeof(locator);
	status = qsc_hw_psa_locator(&fixture->context, locator, &size);
	valid = (status == qsc_hw_status_success);

	if (valid == true)
	{
		policy.size = sizeof(policy);
		policy.version = QSC_HW_ABI_VERSION;
		policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
		policy.usage = qsc_hw_usage_sign;
		policy.allow_software_fallback = true;
		status = qsc_hw_key_open(&fixture->key, fixture->provider, locator, &policy);
		valid = (status == qsc_hw_status_success);
	}

	return valid;
}

/** \brief Release native PSA test references without deleting persistent key ID.
 * \param fixture Open native fixture.
 * \return True if resources were released correctly.
 */
static bool psa_native_test_close(psa_native_fixture* fixture)
{
	bool valid;

	valid = true;

	if (fixture->key != NULL)
	{
		valid = (qsc_hw_key_release(&fixture->key) == qsc_hw_status_success) && valid;
	}

	if (fixture->provider != NULL)
	{
		valid = (qsc_hw_provider_close(&fixture->provider) == qsc_hw_status_success) && valid;
	}

	qsc_memutils_secure_erase(&fixture->service, sizeof(fixture->service));
	return valid;
}

/** \brief Test native PSA provider initialization and capability readout.
 * \return True only if native service loads, advertises signing and closes.
 */
static bool psa_native_test_capabilities(void)
{
	psa_native_fixture fixture = { 0U };
	qsc_hw_capabilities capabilities = { 0U };
	bool valid;

	valid = psa_native_test_open_provider(&fixture);
	capabilities.size = sizeof(capabilities);
	capabilities.version = QSC_HW_ABI_VERSION;

	if (valid == true)
	{
		valid = (qsc_hw_provider_capabilities(fixture.provider, &capabilities) == qsc_hw_status_success);
		valid = ((capabilities.flags & qsc_hw_capability_sign) != 0U) && valid;
	}

	valid = psa_native_test_close(&fixture) && valid;
	qsctest_print_line(valid ? "[PASS] Stage10 native PSA service initialization and signing capabilities" :
		"[FAIL] Stage10 native PSA service initialization and signing capabilities");
	return valid;
}

/** \brief Test existing PSA P-256 identity and SEC1 public-key export.
 * \return True when protected identity can be opened without private export.
 */
static bool psa_native_test_public(void)
{
	psa_native_fixture fixture = { 0U };
	uint8_t publickey[65U] = { 0U };
	size_t length;
	bool valid;

	valid = psa_native_test_open_provider(&fixture);
	valid = (valid == true && psa_native_test_open_identity(&fixture) == true);

	if (valid == true)
	{
		length = sizeof(publickey);
		valid = (qsc_hw_key_public(fixture.key, publickey, &length) == qsc_hw_status_success);
		valid = (length == sizeof(publickey) && publickey[0U] == 0x04U) && valid;
	}

	valid = psa_native_test_close(&fixture) && valid;
	qsctest_print_line(valid ? "[PASS] Stage10 native PSA protected P256 public-key export" :
		"[FAIL] Stage10 native PSA protected P256 public-key export");
	return valid;
}

/** \brief Test native PSA P-256 sign_hash output without altering persistent key.
 * \return True when PSA supplies an exact raw 64-byte signature.
 * \note Independent signature verification against public key is required for G10.
 */
static bool psa_native_test_sign(void)
{
	psa_native_fixture fixture = { 0U };
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	valid = psa_native_test_open_provider(&fixture);
	valid = (valid == true && psa_native_test_open_identity(&fixture) == true);

	if (valid == true)
	{
		digest[0U] = 0x5AU;
		length = sizeof(signature);
		valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_success);
		valid = (length == sizeof(signature)) && valid;
	}

	qsc_memutils_secure_erase(signature, sizeof(signature));
	valid = psa_native_test_close(&fixture) && valid;
	qsctest_print_line(valid ? "[PASS] Stage10 native PSA P256 sign_hash raw output" :
		"[FAIL] Stage10 native PSA P256 sign_hash raw output");
	return valid;
}

bool qsctest_hwpsanative_run(void)
{
	bool valid;

	valid = true;
	valid = psa_native_test_capabilities() && valid;
	valid = psa_native_test_public() && valid;
	valid = psa_native_test_sign() && valid;
	return valid;
}

#endif /* PSA NATIVE DEVICE TEST ENABLED */
