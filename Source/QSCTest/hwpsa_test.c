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

#include "hwpsa_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PSA_ENABLED)

#include "hwpsa.h"
#include "memutils.h"
#include "testutils.h"

/** \struct psa_test_device
 * \brief Deterministic synthetic PSA service; never contains private key bytes.
 */
typedef struct psa_test_device
{
	qsc_hw_psa_key_attributes attributes; /**< Current key metadata. */
	bool exists; /**< A synthetic persistent key is present. */
	bool removed; /**< Simulated PSA service loss. */
	bool fail_sign; /**< Inject failure after writing signature. */
	bool fail_public; /**< Inject failure after writing public point. */
	bool fail_agree; /**< Inject failure after writing derived secret. */
	bool fail_random; /**< Inject failure after writing RNG output. */
	bool invalid_generate; /**< Generate key with exportable policy for rollback test. */
	bool bad_signature_length; /**< Return a too-short successful signature. */
	bool bad_public_point; /**< Return incorrect SEC1 point prefix. */
	bool bad_agreement_length; /**< Return incorrect ECDH secret size. */
	size_t create_count; /**< Number of attempted synthetic generations. */
	size_t rollback_count; /**< Number of requested new-key rollbacks. */
	size_t sign_count; /**< Number of actual PSA-style sign calls. */
	size_t agree_count; /**< Number of actual PSA-style ECDH calls. */
} psa_test_device;

/** \struct psa_test_fixture
 * \brief One caller-owned provider context and independent synthetic service.
 */
typedef struct psa_test_fixture
{
	psa_test_device device; /**< Mock secure service. */
	qsc_hw_psa_context context; /**< PSA backend context. */
	qsc_hw_provider* provider; /**< Owned QSC generic provider wrapper. */
	qsc_hw_keyref* key; /**< Optional owned transient key reference. */
} psa_test_fixture;

/** \brief Return a synthetic key snapshot or explicit missing-device failure.
 * \param service Test-owned synthetic service.
 * \param key_id Key identifier expected by configured service.
 * \param attributes Caller-supplied full PSA metadata output.
 * \return Success or a deterministic typed error.
 */
static qsc_hw_status psa_test_query(void* service, uint32_t key_id, qsc_hw_psa_key_attributes* attributes)
{
	psa_test_device* device;
	qsc_hw_status status;

	device = (psa_test_device*)service;
	status = qsc_hw_status_stale_key;

	if (device == NULL || attributes == NULL || attributes->size != sizeof(qsc_hw_psa_key_attributes))
	{
		status = qsc_hw_status_invalid_parameter;
	}
	else if (device->removed == true)
	{
		status = qsc_hw_status_device_removed;
	}
	else if (device->exists == true && device->attributes.key_id == key_id)
	{
		*attributes = device->attributes;
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Generate a synthetic persistent key unless the ID already exists.
 * \param service Synthetic service state.
 * \param key_id New persistent key ID.
 * \param policy Caller-requested algorithm and usage.
 * \param attributes Generated metadata output.
 * \return Success or typed refusal. No private bytes are generated.
 */
static qsc_hw_status psa_test_create(void* service, uint32_t key_id, const qsc_hw_key_policy* policy,
	qsc_hw_psa_key_attributes* attributes)
{
	psa_test_device* device;
	qsc_hw_status status;

	device = (psa_test_device*)service;
	status = qsc_hw_status_invalid_parameter;

	if (device != NULL && policy != NULL && attributes != NULL)
	{
		++device->create_count;
		status = qsc_hw_status_policy;

		if (device->exists == false)
		{
			device->exists = true;
			device->attributes.key_id = key_id;
			device->attributes.algorithm = policy->algorithm;
			device->attributes.usage = policy->usage;
			device->attributes.persistent = true;
			device->attributes.private_exportable = device->invalid_generate;
			*attributes = device->attributes;
			status = qsc_hw_status_success;
		}
	}

	return status;
}

/** \brief Roll back newly generated synthetic persistent key.
 * \param service Synthetic service state.
 * \param key_id New key identifier.
 * \return Success only for existing matching key.
 */
static qsc_hw_status psa_test_rollback(void* service, uint32_t key_id)
{
	psa_test_device* device;
	qsc_hw_status status;

	device = (psa_test_device*)service;
	status = qsc_hw_status_stale_key;

	if (device != NULL && device->exists == true && device->attributes.key_id == key_id)
	{
		device->exists = false;
		++device->rollback_count;
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Export synthetic public point in SEC1 uncompressed encoding.
 * \param service Synthetic service state.
 * \param key_id Expected key ID.
 * \param output Caller-owned public point destination.
 * \param outputlen In/out byte capacity/actual size.
 * \return Success or injected error after partial output.
 */
static qsc_hw_status psa_test_public(void* service, uint32_t key_id, uint8_t* output, size_t* outputlen)
{
	psa_test_device* device;
	qsc_hw_status status;
	size_t length;
	size_t i;

	device = (psa_test_device*)service;
	status = qsc_hw_status_invalid_parameter;
	length = 65U;

	if (device != NULL && key_id == device->attributes.key_id && output != NULL && outputlen != NULL)
	{
		if (device->attributes.algorithm == qsc_hw_algorithm_ecdsa_p384 || device->attributes.algorithm == qsc_hw_algorithm_ecdh_p384)
		{
			length = 97U;
		}
		else if (device->attributes.algorithm == qsc_hw_algorithm_ecdsa_p521 || device->attributes.algorithm == qsc_hw_algorithm_ecdh_p521)
		{
			length = 133U;
		}

		if (*outputlen >= length)
		{
			for (i = 0U; i < length; ++i)
			{
				output[i] = (uint8_t)(i + 1U);
			}

			output[0U] = device->bad_public_point ? 0x05U : 0x04U;
			*outputlen = length;
			status = device->fail_public ? qsc_hw_status_internal : qsc_hw_status_success;
		}
	}

	return status;
}

/** \brief Produce synthetic raw ECDSA signature or deliberately fail after partial write.
 * \param service Synthetic PSA service state.
 * \param key_id Pinned persistent key ID.
 * \param algorithm ECDSA curve profile.
 * \param digest Precomputed digest; only inspected, no cryptography.
 * \param digestlen Digest length.
 * \param signature Caller output.
 * \param signaturelen In/out output length.
 * \return Deterministic success or injected error.
 */
static qsc_hw_status psa_test_sign(void* service, uint32_t key_id, qsc_hw_algorithm algorithm,
	const uint8_t* digest, size_t digestlen, uint8_t* signature, size_t* signaturelen)
{
	psa_test_device* device;
	qsc_hw_status status;
	size_t length;
	size_t i;

	device = (psa_test_device*)service;
	status = qsc_hw_status_invalid_parameter;
	length = 64U;

	if (device != NULL && key_id == device->attributes.key_id && algorithm == device->attributes.algorithm &&
		digest != NULL && digestlen > 0U && signature != NULL && signaturelen != NULL)
	{
		if (algorithm == qsc_hw_algorithm_ecdsa_p384)
		{
			length = 96U;
		}
		else if (algorithm == qsc_hw_algorithm_ecdsa_p521)
		{
			length = 132U;
		}

		if (*signaturelen >= length)
		{
			++device->sign_count;

			for (i = 0U; i < length; ++i)
			{
				signature[i] = (uint8_t)(digest[0U] + (uint8_t)i);
			}

			*signaturelen = device->bad_signature_length ? length - 1U : length;
			status = device->fail_sign ? qsc_hw_status_internal : qsc_hw_status_success;
		}
	}

	return status;
}

/** \brief Simulate raw ECDH shared-secret export under explicit caller permission.
 * \param service Synthetic PSA service state.
 * \param key_id Key ID.
 * \param algorithm ECDH curve.
 * \param peer SEC1 public point.
 * \param peerlen Public point length.
 * \param secret Caller output.
 * \param secretlen In/out secret byte capacity/actual length.
 * \return Success or injected error after partial output.
 */
static qsc_hw_status psa_test_agree(void* service, uint32_t key_id, qsc_hw_algorithm algorithm,
	const uint8_t* peer, size_t peerlen, uint8_t* secret, size_t* secretlen)
{
	psa_test_device* device;
	qsc_hw_status status;
	size_t length;
	size_t i;

	device = (psa_test_device*)service;
	status = qsc_hw_status_invalid_parameter;
	length = 32U;

	if (device != NULL && key_id == device->attributes.key_id && algorithm == device->attributes.algorithm &&
		peer != NULL && peerlen > 0U && secret != NULL && secretlen != NULL)
	{
		if (algorithm == qsc_hw_algorithm_ecdh_p384)
		{
			length = 48U;
		}
		else if (algorithm == qsc_hw_algorithm_ecdh_p521)
		{
			length = 66U;
		}

		if (*secretlen >= length)
		{
			++device->agree_count;

			for (i = 0U; i < length; ++i)
			{
				secret[i] = (uint8_t)(peer[1U] + (uint8_t)i);
			}

			*secretlen = device->bad_agreement_length ? length - 1U : length;
			status = device->fail_agree ? qsc_hw_status_internal : qsc_hw_status_success;
		}
	}

	return status;
}

/** \brief Return fake RNG bytes or injected failure after partial output.
 * \param service Synthetic PSA service.
 * \param output Caller output buffer.
 * \param length Byte count.
 * \return Success or injected internal failure.
 */
static qsc_hw_status psa_test_random(void* service, uint8_t* output, size_t length)
{
	psa_test_device* device;
	qsc_hw_status status;
	size_t i;

	device = (psa_test_device*)service;
	status = qsc_hw_status_invalid_parameter;

	if (device != NULL && (output != NULL || length == 0U))
	{
		for (i = 0U; i < length; ++i)
		{
			output[i] = (uint8_t)(i ^ 0xA5U);
		}

		status = device->fail_random ? qsc_hw_status_internal : qsc_hw_status_success;
	}

	return status;
}

/** \brief Initialize a complete fake PSA callback interface and key metadata.
 * \param fixture Caller-owned writable fixture.
 * \param callbacks Caller-owned versioned callback table.
 * \param algorithm Desired synthetic algorithm profile.
 * \param existing Whether key id initially exists.
 */
static void psa_test_setup(psa_test_fixture* fixture, qsc_hw_psa_callbacks* callbacks,
	qsc_hw_algorithm algorithm, bool existing)
{
	qsc_memutils_clear(fixture, sizeof(psa_test_fixture));
	qsc_memutils_clear(callbacks, sizeof(qsc_hw_psa_callbacks));
	fixture->device.exists = existing;
	fixture->device.attributes.size = sizeof(qsc_hw_psa_key_attributes);
	fixture->device.attributes.version = QSC_HW_ABI_VERSION;
	fixture->device.attributes.key_id = 0x10000123U;
	fixture->device.attributes.algorithm = algorithm;
	fixture->device.attributes.usage = qsc_hw_usage_sign;
	fixture->device.attributes.persistent = true;
	fixture->device.attributes.private_exportable = false;
	fixture->device.attributes.hardware_protected = true;

	if (algorithm == qsc_hw_algorithm_ecdh_p256 || algorithm == qsc_hw_algorithm_ecdh_p384 ||
		algorithm == qsc_hw_algorithm_ecdh_p521)
	{
		fixture->device.attributes.usage = qsc_hw_usage_agree;
	}

	callbacks->size = sizeof(qsc_hw_psa_callbacks);
	callbacks->version = QSC_HW_ABI_VERSION;
	callbacks->query = psa_test_query;
	callbacks->create = psa_test_create;
	callbacks->rollback = psa_test_rollback;
	callbacks->public_key = psa_test_public;
	callbacks->sign_hash = psa_test_sign;
	callbacks->agree = psa_test_agree;
	callbacks->random = psa_test_random;
}

/** \brief Open a generic provider with the prepared deterministic PSA fixture.
 * \param fixture Prepared test fixture.
 * \param callbacks Versioned PSA callbacks.
 * \param confirmed Whether physical hardware custody has been independently confirmed.
 * \return True when initialized and opened.
 */
static bool psa_test_start(psa_test_fixture* fixture, const qsc_hw_psa_callbacks* callbacks, bool confirmed)
{
	qsc_hw_provider_ops operations = { 0U };
	bool valid;

	valid = (qsc_hw_psa_initialize(&fixture->context, callbacks, &fixture->device, 0x10000123U, confirmed) == qsc_hw_status_success);
	valid = (qsc_hw_psa_get_operations(&operations) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_open(&fixture->provider, &operations, &fixture->context) == qsc_hw_status_success) && valid;
	return valid;
}

/** \brief Construct a versioned policy and open pinned PSA identity.
 * \param fixture Opened provider fixture.
 * \param hardware Require independently confirmed protected hardware.
 * \param allow_fallback Explicitly permit unqualified software custody.
 * \param allow_derive Allow exporting ECDH result into host memory.
 * \return Generic QSC status.
 */
static qsc_hw_status psa_test_open(psa_test_fixture* fixture, bool hardware, bool allow_fallback, bool allow_derive)
{
	qsc_hw_key_policy policy = { 0U };
	char locator[QSC_HW_PSA_LOCATOR_SIZE] = { 0U };
	size_t length;
	qsc_hw_status status;

	length = sizeof(locator);
	status = qsc_hw_psa_locator(&fixture->context, locator, &length);

	if (status == qsc_hw_status_success)
	{
		policy.size = sizeof(policy);
		policy.version = QSC_HW_ABI_VERSION;
		policy.algorithm = fixture->device.attributes.algorithm;
		policy.usage = fixture->device.attributes.usage;
		policy.require_hardware = hardware;
		policy.allow_software_fallback = allow_fallback;
		policy.allow_export = false;
		policy.allow_derived_secret_export = allow_derive;
		status = qsc_hw_key_open(&fixture->key, fixture->provider, locator, &policy);
	}

	return status;
}

/** \brief Release owned QSC keys and provider in correct order.
 * \param fixture Initialized test fixture.
 * \return True only if all live resources close successfully.
 */
static bool psa_test_finish(psa_test_fixture* fixture)
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

	return valid;
}
/** \brief Check that every output byte was erased after an injected failure.
 * \param output Caller-owned readable byte buffer.
 * \param length Buffer byte count.
 * \return True when all bytes are zero.
 */
static bool psa_test_all_zero(const uint8_t* output, size_t length)
{
    size_t i;
    bool valid;

    valid = true;

    for (i = 0U; i < length; ++i)
    {
        if (output[i] != 0U)
        {
            valid = false;
        }
    }

    return valid;
}

/** \brief Test PSA reject ABI, null callbacks and repeated initialization.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_configuration(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = (qsc_hw_psa_initialize(NULL, &callbacks, &fixture.device, 0x10000123U, true) == qsc_hw_status_invalid_parameter);
	callbacks.version = 999U;
	valid = (qsc_hw_psa_initialize(&fixture.context, &callbacks, &fixture.device, 0x10000123U, true) == qsc_hw_status_invalid_parameter) && valid;
	callbacks.version = QSC_HW_ABI_VERSION;
	valid = psa_test_start(&fixture, &callbacks, true) && valid;
	valid = (qsc_hw_psa_initialize(&fixture.context, &callbacks, &fixture.device, 0x10000123U, true) == qsc_hw_status_busy) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA reject ABI, null callbacks and repeated initialization" : "[FAIL] Stage10 PSA reject ABI, null callbacks and repeated initialization");
	return valid;
}

/** \brief Test PSA canonical bounded persistent key locator.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_locator(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	char locator[QSC_HW_PSA_LOCATOR_SIZE] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	length = 0U;
	valid = (qsc_hw_psa_locator(&fixture.context, NULL, &length) == qsc_hw_status_success && length == QSC_HW_PSA_LOCATOR_SIZE) && valid;
	length = QSC_HW_PSA_LOCATOR_SIZE - 1U;
	valid = (qsc_hw_psa_locator(&fixture.context, locator, &length) == qsc_hw_status_buffer_too_small && length == QSC_HW_PSA_LOCATOR_SIZE) && valid;
	length = sizeof(locator);
	valid = (qsc_hw_psa_locator(&fixture.context, locator, &length) == qsc_hw_status_success &&
		qsc_memutils_are_equal((const uint8_t*)locator, (const uint8_t*)"psa://10000123", length) == true) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA canonical bounded persistent key locator" : "[FAIL] Stage10 PSA canonical bounded persistent key locator");
	return valid;
}

/** \brief Test PSA capability flags reflect actual backend callbacks.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_capabilities(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	qsc_hw_capabilities caps = { 0U };
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	callbacks.agree = NULL;
	callbacks.random = NULL;
	valid = psa_test_start(&fixture, &callbacks, true);
	caps.size = sizeof(caps);
	caps.version = QSC_HW_ABI_VERSION;
	valid = (qsc_hw_provider_capabilities(fixture.provider, &caps) == qsc_hw_status_success) && valid;
	valid = ((caps.flags & qsc_hw_capability_agree) == 0U && (caps.flags & qsc_hw_capability_random) == 0U) && valid;
	valid = ((caps.flags & qsc_hw_capability_sign) != 0U && (caps.flags & qsc_hw_capability_attest) == 0U) && valid;
	valid = (caps.requires_serialization == true && caps.thread_safe == false && caps.max_sessions == 1U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA capability flags reflect actual backend callbacks" : "[FAIL] Stage10 PSA capability flags reflect actual backend callbacks");
	return valid;
}

/** \brief Test PSA confirmed physical custody accepted without private export.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_hardware_custody(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	qsc_hw_key_info info = { 0U };
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	info.size = sizeof(info);
	info.version = QSC_HW_ABI_VERSION;
	valid = (qsc_hw_key_get_info(fixture.key, &info) == qsc_hw_status_success) && valid;
	valid = (info.custody == qsc_hw_custody_hardware_nonexportable && info.extractable == false) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA confirmed physical custody accepted without private export" : "[FAIL] Stage10 PSA confirmed physical custody accepted without private export");
	return valid;
}

/** \brief Test PSA unqualified software service cannot claim hardware residency.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_unqualified_custody(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, false);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_policy && fixture.key == NULL) && valid;
	valid = (psa_test_open(&fixture, false, true, false) == qsc_hw_status_success) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA unqualified software service cannot claim hardware residency" : "[FAIL] Stage10 PSA unqualified software service cannot claim hardware residency");
	return valid;
}

/** \brief Test PSA software key location rejected under required-hardware policy.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_location_custody(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	fixture.device.attributes.hardware_protected = false;
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_policy) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA software key location rejected under required-hardware policy" : "[FAIL] Stage10 PSA software key location rejected under required-hardware policy");
	return valid;
}

/** \brief Test PSA exportable private key rejected before any signing.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_export_policy(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	fixture.device.attributes.private_exportable = true;
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_policy && fixture.key == NULL) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA exportable private key rejected before any signing" : "[FAIL] Stage10 PSA exportable private key rejected before any signing");
	return valid;
}

/** \brief Test PSA volatile key rejected from persistent identity scope.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_persistent_policy(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	fixture.device.attributes.persistent = false;
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_policy) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA volatile key rejected from persistent identity scope" : "[FAIL] Stage10 PSA volatile key rejected from persistent identity scope");
	return valid;
}

/** \brief Test PSA mismatched usage and curve policy rejected.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_wrong_usage(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	fixture.device.attributes.usage = qsc_hw_usage_agree;
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_policy) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA mismatched usage and curve policy rejected" : "[FAIL] Stage10 PSA mismatched usage and curve policy rejected");
	return valid;
}

/** \brief Test PSA unknown algorithm rejected with explicit policy error.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_unknown_curve(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ml_dsa_44, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_policy) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA unknown algorithm rejected with explicit policy error" : "[FAIL] Stage10 PSA unknown algorithm rejected with explicit policy error");
	return valid;
}

/** \brief Test PSA P256 SHA256 prehashed signing raw signature contract.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_p256_sign(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	digest[0U] = 0x29U;
	length = 0U;
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), NULL, &length) == qsc_hw_status_success && length == 64U) && valid;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_success) && valid;
	valid = (length == sizeof(signature) && signature[0U] == 0x29U && fixture.device.sign_count == 1U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA P256 SHA256 prehashed signing raw signature contract" : "[FAIL] Stage10 PSA P256 SHA256 prehashed signing raw signature contract");
	return valid;
}

/** \brief Test PSA P384 SHA384 prehashed signature size and digest.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_p384_sign(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t digest[48U] = { 0U };
	uint8_t signature[96U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p384, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_success && length == 96U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA P384 SHA384 prehashed signature size and digest" : "[FAIL] Stage10 PSA P384 SHA384 prehashed signature size and digest");
	return valid;
}

/** \brief Test PSA P521 SHA512 digest 64 and signature 132.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_p521_sign(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t digest[64U] = { 0U };
	uint8_t signature[132U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p521, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_success && length == 132U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA P521 SHA512 digest 64 and signature 132" : "[FAIL] Stage10 PSA P521 SHA512 digest 64 and signature 132");
	return valid;
}

/** \brief Test PSA rejects wrong prehashed digest length and leaves output untouched.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_digest_rejection(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t digest[31U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_invalid_parameter) && valid;
	valid = (fixture.device.sign_count == 0U && signature[0U] == 0U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA rejects wrong prehashed digest length and leaves output untouched" : "[FAIL] Stage10 PSA rejects wrong prehashed digest length and leaves output untouched");
	return valid;
}

/** \brief Test PSA partial signing output securely erased on backend failure.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_sign_failure(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	fixture.device.fail_sign = true;
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_internal) && valid;
	valid = (psa_test_all_zero(signature, sizeof(signature)) == true) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA partial signing output securely erased on backend failure" : "[FAIL] Stage10 PSA partial signing output securely erased on backend failure");
	return valid;
}

/** \brief Test PSA rejects successful callback with truncated raw ECDSA signature.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_signature_format(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	fixture.device.bad_signature_length = true;
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_policy) && valid;
	valid = (psa_test_all_zero(signature, sizeof(signature)) == true) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA rejects successful callback with truncated raw ECDSA signature" : "[FAIL] Stage10 PSA rejects successful callback with truncated raw ECDSA signature");
	return valid;
}

/** \brief Test PSA public SEC1 point retrieval and size query.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_public_point(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t output[65U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	length = 0U;
	valid = (qsc_hw_key_public(fixture.key, NULL, &length) == qsc_hw_status_success && length == 65U) && valid;
	length = 60U;
	valid = (qsc_hw_key_public(fixture.key, output, &length) == qsc_hw_status_buffer_too_small && length == 65U) && valid;
	length = sizeof(output);
	valid = (qsc_hw_key_public(fixture.key, output, &length) == qsc_hw_status_success && output[0U] == 0x04U && length == 65U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA public SEC1 point retrieval and size query" : "[FAIL] Stage10 PSA public SEC1 point retrieval and size query");
	return valid;
}

/** \brief Test PSA public-key failure and malformed point clear partial output.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_public_failure(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t output[65U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	fixture.device.fail_public = true;
	length = sizeof(output);
	valid = (qsc_hw_key_public(fixture.key, output, &length) == qsc_hw_status_internal) && valid;
	valid = (psa_test_all_zero(output, sizeof(output)) == true) && valid;
	fixture.device.fail_public = false;
	fixture.device.bad_public_point = true;
	length = sizeof(output);
	valid = (qsc_hw_key_public(fixture.key, output, &length) == qsc_hw_status_policy) && valid;
	valid = (psa_test_all_zero(output, sizeof(output)) == true) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA public-key failure and malformed point clear partial output" : "[FAIL] Stage10 PSA public-key failure and malformed point clear partial output");
	return valid;
}

/** \brief Test PSA lost secure service reports device removal before signing.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_device_removed(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	fixture.device.removed = true;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_device_removed) && valid;
	valid = (fixture.device.sign_count == 0U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA lost secure service reports device removal before signing" : "[FAIL] Stage10 PSA lost secure service reports device removal before signing");
	return valid;
}

/** \brief Test PSA replaced persistent key changes attribute fingerprint.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_stale_metadata(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	fixture.device.attributes.hardware_protected = false;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_stale_key) && valid;
	valid = (fixture.device.sign_count == 0U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA replaced persistent key changes attribute fingerprint" : "[FAIL] Stage10 PSA replaced persistent key changes attribute fingerprint");
	return valid;
}

/** \brief Test PSA provider reconnect invalidates old transient key generation.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_provider_invalidate(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_invalidate(fixture.provider) == qsc_hw_status_success) && valid;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) == qsc_hw_status_stale_key) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA provider reconnect invalidates old transient key generation" : "[FAIL] Stage10 PSA provider reconnect invalidates old transient key generation");
	return valid;
}

/** \brief Test PSA ECDH refuses raw derived-secret export without explicit policy.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_ecdh_deny(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t peer[65U] = { 0U };
	uint8_t secret[32U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdh_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	peer[0U] = 0x04U;
	length = sizeof(secret);
	valid = (qsc_hw_key_agree(fixture.key, peer, sizeof(peer), secret, &length) == qsc_hw_status_policy) && valid;
	valid = (fixture.device.agree_count == 0U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA ECDH refuses raw derived-secret export without explicit policy" : "[FAIL] Stage10 PSA ECDH refuses raw derived-secret export without explicit policy");
	return valid;
}

/** \brief Test PSA explicit ECDH export produces bounded raw shared secret.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_ecdh_allowed(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t peer[65U] = { 0U };
	uint8_t secret[32U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdh_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, true) == qsc_hw_status_success) && valid;
	peer[0U] = 0x04U;
	peer[1U] = 0x18U;
	length = sizeof(secret);
	valid = (qsc_hw_key_agree(fixture.key, peer, sizeof(peer), secret, &length) == qsc_hw_status_success && length == 32U) && valid;
	valid = (secret[0U] == 0x18U && fixture.device.agree_count == 1U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA explicit ECDH export produces bounded raw shared secret" : "[FAIL] Stage10 PSA explicit ECDH export produces bounded raw shared secret");
	return valid;
}

/** \brief Test PSA failed ECDH must erase host-side partial derived secret.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_ecdh_failure(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t peer[65U] = { 0U };
	uint8_t secret[32U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdh_p256, true);
	fixture.device.fail_agree = true;
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, true) == qsc_hw_status_success) && valid;
	peer[0U] = 0x04U;
	length = sizeof(secret);
	valid = (qsc_hw_key_agree(fixture.key, peer, sizeof(peer), secret, &length) == qsc_hw_status_internal) && valid;
	valid = (psa_test_all_zero(secret, sizeof(secret)) == true) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA failed ECDH must erase host-side partial derived secret" : "[FAIL] Stage10 PSA failed ECDH must erase host-side partial derived secret");
	return valid;
}

/** \brief Test PSA P521 ECDH raw shared secret uses 66 bytes.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_ecdh_p521(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t peer[133U] = { 0U };
	uint8_t secret[66U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdh_p521, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, true) == qsc_hw_status_success) && valid;
	peer[0U] = 0x04U;
	length = sizeof(secret);
	valid = (qsc_hw_key_agree(fixture.key, peer, sizeof(peer), secret, &length) == qsc_hw_status_success && length == 66U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA P521 ECDH raw shared secret uses 66 bytes" : "[FAIL] Stage10 PSA P521 ECDH raw shared secret uses 66 bytes");
	return valid;
}

/** \brief Test PSA ECDH invalid SEC1 peer encoding refused before backend.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_ecdh_peer(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t peer[65U] = { 0U };
	uint8_t secret[32U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdh_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, true) == qsc_hw_status_success) && valid;
	length = sizeof(secret);
	valid = (qsc_hw_key_agree(fixture.key, peer, sizeof(peer), secret, &length) == qsc_hw_status_invalid_parameter) && valid;
	peer[0U] = 0x04U;
	length = sizeof(secret);
	valid = (qsc_hw_key_agree(fixture.key, peer, sizeof(peer) - 1U, secret, &length) == qsc_hw_status_invalid_parameter) && valid;
	valid = (fixture.device.agree_count == 0U) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA ECDH invalid SEC1 peer encoding refused before backend" : "[FAIL] Stage10 PSA ECDH invalid SEC1 peer encoding refused before backend");
	return valid;
}

/** \brief Test PSA ECDH successful callback with bad output length rejected.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_ecdh_wrong_length(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t peer[65U] = { 0U };
	uint8_t secret[32U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdh_p256, true);
	fixture.device.bad_agreement_length = true;
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, true) == qsc_hw_status_success) && valid;
	peer[0U] = 0x04U;
	length = sizeof(secret);
	valid = (qsc_hw_key_agree(fixture.key, peer, sizeof(peer), secret, &length) == qsc_hw_status_policy) && valid;
	valid = (psa_test_all_zero(secret, sizeof(secret)) == true) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA ECDH successful callback with bad output length rejected" : "[FAIL] Stage10 PSA ECDH successful callback with bad output length rejected");
	return valid;
}

/** \brief Test PSA new persistent key generation preserves private custody.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_generation(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	qsc_hw_key_policy policy = { 0U };
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, false);
	valid = psa_test_start(&fixture, &callbacks, true);
	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = true;
	valid = (qsc_hw_key_generate(&fixture.key, fixture.provider, &policy) == qsc_hw_status_success) && valid;
	valid = (fixture.device.exists == true && fixture.device.create_count == 1U && fixture.device.rollback_count == 0U) && valid;
	valid = psa_test_finish(&fixture) && valid;
	valid = (fixture.device.exists == true) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA new persistent key generation preserves private custody" : "[FAIL] Stage10 PSA new persistent key generation preserves private custody");
	return valid;
}

/** \brief Test PSA generated exportable key rejected with immediate rollback.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_generation_reject(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	qsc_hw_key_policy policy = { 0U };
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, false);
	fixture.device.invalid_generate = true;
	valid = psa_test_start(&fixture, &callbacks, true);
	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = true;
	valid = (qsc_hw_key_generate(&fixture.key, fixture.provider, &policy) == qsc_hw_status_policy) && valid;
	valid = (fixture.device.exists == false && fixture.device.rollback_count == 1U && fixture.key == NULL) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA generated exportable key rejected with immediate rollback" : "[FAIL] Stage10 PSA generated exportable key rejected with immediate rollback");
	return valid;
}

/** \brief Test PSA refuses key generation over existing persistent identity.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_generation_no_overwrite(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	qsc_hw_key_policy policy = { 0U };
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = true;
	valid = (qsc_hw_key_generate(&fixture.key, fixture.provider, &policy) == qsc_hw_status_policy) && valid;
	valid = (fixture.device.create_count == 0U && fixture.device.exists == true) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA refuses key generation over existing persistent identity" : "[FAIL] Stage10 PSA refuses key generation over existing persistent identity");
	return valid;
}

/** \brief Test PSA RNG failure securely clears partial output.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_random_failure(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t output[32U] = { 0U };
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (qsc_hw_provider_random(fixture.provider, output, sizeof(output)) == qsc_hw_status_success && output[0U] == 0xA5U) && valid;
	fixture.device.fail_random = true;
	valid = (qsc_hw_provider_random(fixture.provider, output, sizeof(output)) == qsc_hw_status_internal) && valid;
	valid = (psa_test_all_zero(output, sizeof(output)) == true) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA RNG failure securely clears partial output" : "[FAIL] Stage10 PSA RNG failure securely clears partial output");
	return valid;
}

/** \brief Test PSA live key prevents closing provider until released.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_close_busy(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&fixture.provider) == qsc_hw_status_busy) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA live key prevents closing provider until released" : "[FAIL] Stage10 PSA live key prevents closing provider until released");
	return valid;
}

/** \brief Test PSA bridge does not falsely advertise platform attestation.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_no_attestation(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	uint8_t challenge[16U] = { 0U };
	uint8_t evidence[64U] = { 0U };
	size_t length;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	valid = (psa_test_open(&fixture, true, false, false) == qsc_hw_status_success) && valid;
	length = sizeof(evidence);
	valid = (qsc_hw_key_attest(fixture.key, challenge, sizeof(challenge), evidence, &length) == qsc_hw_status_policy) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA bridge does not falsely advertise platform attestation" : "[FAIL] Stage10 PSA bridge does not falsely advertise platform attestation");
	return valid;
}

/** \brief Test PSA rejects key-create callback without rollback contract.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_missing_callback(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	callbacks.rollback = NULL;
	valid = (qsc_hw_psa_initialize(&fixture.context, &callbacks, &fixture.device, 0x10000123U, true) == qsc_hw_status_invalid_parameter);
	valid = (fixture.context.initialized == false) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA rejects key-create callback without rollback contract" : "[FAIL] Stage10 PSA rejects key-create callback without rollback contract");
	return valid;
}

/** \brief Test PSA incorrect persistent locator rejected without selecting key.
 * \return True for exact accepted policy and failure behavior.
 */
static bool psa_test_locator_rejection(void)
{
	psa_test_fixture fixture;
	qsc_hw_psa_callbacks callbacks;
	qsc_hw_key_policy policy = { 0U };
	bool valid;

	psa_test_setup(&fixture, &callbacks, qsc_hw_algorithm_ecdsa_p256, true);
	valid = psa_test_start(&fixture, &callbacks, true);
	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = true;
	valid = (qsc_hw_key_open(&fixture.key, fixture.provider, "psa://10000124", &policy) == qsc_hw_status_stale_key) && valid;
	valid = (fixture.key == NULL) && valid;
	valid = psa_test_finish(&fixture) && valid;

	qsctest_print_line(valid ? "[PASS] Stage10 PSA incorrect persistent locator rejected without selecting key" : "[FAIL] Stage10 PSA incorrect persistent locator rejected without selecting key");
	return valid;
}

bool qsctest_hwpsa_run(void)
{
	bool valid;

	valid = true;
	valid = psa_test_configuration() && valid;
	valid = psa_test_locator() && valid;
	valid = psa_test_capabilities() && valid;
	valid = psa_test_hardware_custody() && valid;
	valid = psa_test_unqualified_custody() && valid;
	valid = psa_test_location_custody() && valid;
	valid = psa_test_export_policy() && valid;
	valid = psa_test_persistent_policy() && valid;
	valid = psa_test_wrong_usage() && valid;
	valid = psa_test_unknown_curve() && valid;
	valid = psa_test_p256_sign() && valid;
	valid = psa_test_p384_sign() && valid;
	valid = psa_test_p521_sign() && valid;
	valid = psa_test_digest_rejection() && valid;
	valid = psa_test_sign_failure() && valid;
	valid = psa_test_signature_format() && valid;
	valid = psa_test_public_point() && valid;
	valid = psa_test_public_failure() && valid;
	valid = psa_test_device_removed() && valid;
	valid = psa_test_stale_metadata() && valid;
	valid = psa_test_provider_invalidate() && valid;
	valid = psa_test_ecdh_deny() && valid;
	valid = psa_test_ecdh_allowed() && valid;
	valid = psa_test_ecdh_failure() && valid;
	valid = psa_test_ecdh_p521() && valid;
	valid = psa_test_ecdh_peer() && valid;
	valid = psa_test_ecdh_wrong_length() && valid;
	valid = psa_test_generation() && valid;
	valid = psa_test_generation_reject() && valid;
	valid = psa_test_generation_no_overwrite() && valid;
	valid = psa_test_random_failure() && valid;
	valid = psa_test_close_busy() && valid;
	valid = psa_test_no_attestation() && valid;
	valid = psa_test_missing_callback() && valid;
	valid = psa_test_locator_rejection() && valid;
	return valid;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PSA_ENABLED */
