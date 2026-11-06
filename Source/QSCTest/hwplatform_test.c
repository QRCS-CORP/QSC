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

#include "hwplatform_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PLATFORM_ENABLED)

#include "hwplatform.h"
#include "memutils.h"
#include "testutils.h"

/** \struct platform_test_device
 * \brief Deterministic OS keystore mock storing nonsecret metadata only.
 */
typedef struct platform_test_device
{
	qsc_hw_platform_key_attributes attributes; /**< Current synthetic key metadata. */
	bool exists; /**< Whether persistent alias is available. */
	bool removed; /**< Whether keystore became unavailable. */
	bool sign_failure; /**< Inject error after writing a partial signature. */
	bool bad_signature_length; /**< Inject a truncated successful signature. */
	bool invalid_generated; /**< Produce an exportable generated key to trigger rollback. */
	bool rollback_failure; /**< Simulate failure to delete newly generated object. */
	uint32_t created; /**< Count of key creation callbacks. */
	uint32_t deleted; /**< Count of rollback callbacks. */
	uint32_t signed_count; /**< Count of signing callbacks. */
} platform_test_device;

/** \struct platform_test_fixture
 * \brief Owned generic provider, platform context, and mock native service.
 */
typedef struct platform_test_fixture
{
	platform_test_device device; /**< Mock backing keystore. */
	qsc_hw_platform_context context; /**< QSC platform provider context. */
	qsc_hw_provider* provider; /**< Owned QSC provider handle. */
	qsc_hw_keyref* key; /**< Owned transient key, may be NULL. */
} platform_test_fixture;

/** \brief Query mock key live attributes without leaking secret material.
 * \param service Mock device.
 * \param alias Unused validated persistent key label.
 * \param attributes Public metadata output.
 * \return Success, stale_key or device_removed.
 */
static qsc_hw_status platform_test_query(void* service, const char* alias,
	qsc_hw_platform_key_attributes* attributes)
{
	platform_test_device* device;
	qsc_hw_status status;

	(void)alias;
	device = (platform_test_device*)service;
	status = qsc_hw_status_stale_key;

	if (device->removed == true)
	{
		status = qsc_hw_status_device_removed;
	}
	else if (device->exists == true)
	{
		*attributes = device->attributes;
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Generate a mock persistent P-256 key only when no identity exists.
 * \param service Mock device.
 * \param alias Validated persistent identity label.
 * \param require_strongbox Whether Android StrongBox mandatory.
 * \param attributes New metadata, including synthetic public key.
 * \return Success or explicit policy refusal.
 */
static qsc_hw_status platform_test_create(void* service, const char* alias,
	bool require_strongbox, qsc_hw_platform_key_attributes* attributes)
{
	platform_test_device* device;
	qsc_hw_status status;

	(void)alias;
	device = (platform_test_device*)service;
	status = qsc_hw_status_policy;

	if (device->exists == false)
	{
		device->exists = true;
		device->created += 1U;
		device->attributes.security = require_strongbox == true ?
			qsc_hw_platform_security_strongbox : qsc_hw_platform_security_enclave;
		device->attributes.private_exportable = device->invalid_generated;
		*attributes = device->attributes;
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Delete only synthetic key created during present generation test.
 * \param service Mock keystore.
 * \param alias Validated persistent alias, intentionally unused.
 * \return Success or simulated failure.
 */
static qsc_hw_status platform_test_rollback(void* service, const char* alias)
{
	platform_test_device* device;
	qsc_hw_status status;

	(void)alias;
	device = (platform_test_device*)service;
	status = qsc_hw_status_policy;

	if (device->rollback_failure == false)
	{
		device->exists = false;
		device->deleted += 1U;
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Produce deterministic raw r||s bytes without real ECDSA private key.
 * \param service Mock keystore.
 * \param alias Persistent alias, intentionally unused.
 * \param digest SHA-256 bytes, not interpreted as a private key.
 * \param digestlen Must equal 32 bytes.
 * \param signature Caller output for 64 bytes.
 * \param signaturelen In/out length.
 * \return Success or injected error after partial write.
 */
static qsc_hw_status platform_test_sign(void* service, const char* alias, const uint8_t* digest,
	size_t digestlen, uint8_t* signature, size_t* signaturelen)
{
	platform_test_device* device;
	qsc_hw_status status;

	(void)alias;
	(void)digest;
	device = (platform_test_device*)service;
	status = qsc_hw_status_invalid_parameter;

	if (digestlen == 32U && *signaturelen >= QSC_HW_PLATFORM_SIGNATURE_SIZE)
	{
		device->signed_count += 1U;
		qsc_memutils_set_value(signature, QSC_HW_PLATFORM_SIGNATURE_SIZE, 0xA5U);
		*signaturelen = device->bad_signature_length == true ? 63U : QSC_HW_PLATFORM_SIGNATURE_SIZE;
		status = device->sign_failure == true ? qsc_hw_status_timeout : qsc_hw_status_success;
	}

	return status;
}

/** \brief Initialize one mock native keystore plus QSC generic provider.
 * \param fixture Zeroed owned test fixture.
 * \param family Apple or Android.
 * \param security Mock actual security level.
 * \param hardware_verified Independent qualification assumption for policy tests.
 * \param require_strongbox Android StrongBox-specific requirement.
 * \param exists Whether key is pre-provisioned.
 * \return True when bridge and generic QSC provider initialized.
 */
static bool platform_test_setup(platform_test_fixture* fixture, qsc_hw_platform_family family,
	qsc_hw_platform_security security, bool hardware_verified, bool require_strongbox, bool exists)
{
	qsc_hw_platform_callbacks callbacks = { 0U };
	qsc_hw_provider_ops operations = { 0U };
	bool valid;
	size_t i;

	qsc_memutils_clear(fixture, sizeof(platform_test_fixture));
	fixture->device.attributes.size = sizeof(qsc_hw_platform_key_attributes);
	fixture->device.attributes.version = QSC_HW_ABI_VERSION;
	fixture->device.attributes.security = security;
	fixture->device.attributes.persistent = true;
	fixture->device.attributes.private_exportable = false;
	fixture->device.attributes.public_key[0U] = 0x04U;

	for (i = 1U; i < QSC_HW_PLATFORM_PUBLIC_SIZE; ++i)
	{
		fixture->device.attributes.public_key[i] = (uint8_t)i;
	}

	fixture->device.exists = exists;
	callbacks.size = sizeof(callbacks);
	callbacks.version = QSC_HW_ABI_VERSION;
	callbacks.query = platform_test_query;
	callbacks.create = platform_test_create;
	callbacks.rollback = platform_test_rollback;
	callbacks.sign_digest = platform_test_sign;
	valid = qsc_hw_platform_initialize(&fixture->context, &callbacks, &fixture->device,
		family, "qsc-test-key", require_strongbox, hardware_verified) == qsc_hw_status_success;

	if (valid == true)
	{
		valid = (qsc_hw_platform_get_operations(&operations) == qsc_hw_status_success);
	}

	if (valid == true)
	{
		valid = (qsc_hw_provider_open(&fixture->provider, &operations, &fixture->context) == qsc_hw_status_success);
	}

	return valid;
}

/** \brief Release one test key and provider in the mandated order.
 * \param fixture Mock fixture; may have NULL handles.
 */
static void platform_test_cleanup(platform_test_fixture* fixture)
{
	if (fixture->key != NULL)
	{
		(void)qsc_hw_key_release(&fixture->key);
	}

	if (fixture->provider != NULL)
	{
		(void)qsc_hw_provider_close(&fixture->provider);
	}

	qsc_hw_platform_dispose(&fixture->context);
}

/** \brief Construct fixed P-256 sign-only policy for one mock identity.
 * \param require_hardware True to reject unqualified platform custody.
 * \return Complete versioned policy without export permissions.
 */
static qsc_hw_key_policy platform_test_policy(bool require_hardware)
{
	qsc_hw_key_policy policy = { 0U };

	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = require_hardware;
	policy.allow_software_fallback = (require_hardware == false);
	policy.allow_export = false;
	policy.allow_derived_secret_export = false;

	return policy;
}

/** \brief Open a platform test identity by canonical locator.
 * \param fixture Active fixture.
 * \param require_hardware Whether nonexportable qualified custody mandatory.
 * \return Typed open status.
 */
static qsc_hw_status platform_test_open(platform_test_fixture* fixture, bool require_hardware)
{
	char locator[QSC_HW_PLATFORM_LOCATOR_MAX] = { 0U };
	qsc_hw_key_policy policy;
	qsc_hw_status status;
	size_t length;

	length = sizeof(locator);
	policy = platform_test_policy(require_hardware);
	status = qsc_hw_platform_locator(&fixture->context, locator, &length);

	if (status == qsc_hw_status_success)
	{
		status = qsc_hw_key_open(&fixture->key, fixture->provider, locator, &policy);
	}

	return status;
}

/** \brief Assert supported Apple Secure Enclave identity and key export restrictions.
 * \return True on mock contract success.
 */
static bool platform_test_apple_open(void)
{
	platform_test_fixture fixture;
	qsc_hw_key_info info = { 0U };
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, true);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		info.size = sizeof(info);
		info.version = QSC_HW_ABI_VERSION;
		valid = qsc_hw_key_get_info(fixture.key, &info) == qsc_hw_status_success &&
			info.custody == qsc_hw_custody_hardware_nonexportable && info.extractable == false;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 Apple Secure Enclave P256 protected key custody" :
		"[FAIL] Stage11 Apple Secure Enclave P256 protected key custody");
	return valid;
}

/** \brief Reject a TEE label substituted for expected Apple Secure Enclave.
 * \return True when wrong hardware family fails closed.
 */
static bool platform_test_apple_reject_tee(void)
{
	platform_test_fixture fixture;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_tee, true, false, true);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_policy;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 Apple rejects non-Enclave security tier" :
		"[FAIL] Stage11 Apple rejects non-Enclave security tier");
	return valid;
}

/** \brief Reject Android TEE identity when StrongBox is mandatory.
 * \return True if no prohibited downgrade happens.
 */
static bool platform_test_strongbox_required(void)
{
	platform_test_fixture fixture;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_tee, true, true, true);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_policy;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 Android StrongBox requirement denies TEE fallback" :
		"[FAIL] Stage11 Android StrongBox requirement denies TEE fallback");
	return valid;
}

/** \brief Accept a reported StrongBox identity when independently qualified.
 * \return True if protected signing key is opened.
 */
static bool platform_test_strongbox_open(void)
{
	platform_test_fixture fixture;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_strongbox, true, true, true);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 Android reported StrongBox P256 opens with hardware policy" :
		"[FAIL] Stage11 Android reported StrongBox P256 opens with hardware policy");
	return valid;
}

/** \brief Allow non-StrongBox TEE only if caller did not require StrongBox.
 * \return True for explicitly allowed Android TEE identity.
 */
static bool platform_test_tee_open(void)
{
	platform_test_fixture fixture;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_tee, true, false, true);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 Android explicitly permitted TEE P256 identity" :
		"[FAIL] Stage11 Android explicitly permitted TEE P256 identity");
	return valid;
}

/** \brief Refuse Android software-backed private key under hardware policy.
 * \return True when software is rejected without replacement.
 */
static bool platform_test_software_reject(void)
{
	platform_test_fixture fixture;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_software, true, false, true);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_policy;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 Android software Keystore key refused by hardware bridge" :
		"[FAIL] Stage11 Android software Keystore key refused by hardware bridge");
	return valid;
}

/** \brief Reject claimed hardware custody if target was not independently qualified.
 * \return True when hardware-required key open fails.
 */
static bool platform_test_unqualified_hardware(void)
{
	platform_test_fixture fixture;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, false, false, true);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_policy;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 unqualified target cannot claim protected hardware custody" :
		"[FAIL] Stage11 unqualified target cannot claim protected hardware custody");
	return valid;
}

/** \brief Permit unqualified interface only with explicit non-hardware key policy.
 * \return True for explicit lower assurance policy.
 */
static bool platform_test_unqualified_allowed(void)
{
	platform_test_fixture fixture;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_tee, false, false, true);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, false) == qsc_hw_status_success;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 unqualified target requires explicit relaxed custody policy" :
		"[FAIL] Stage11 unqualified target requires explicit relaxed custody policy");
	return valid;
}

/** \brief Verify raw P256 prehashed signing and mandatory length.
 * \return True for successful mock signature output.
 */
static bool platform_test_sign_digest(void)
{
	platform_test_fixture fixture;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, true);
	length = sizeof(signature);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		valid = qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) ==
			qsc_hw_status_success && length == 64U && fixture.device.signed_count == 1U &&
			signature[0U] == 0xA5U;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 exact SHA256 prehashed P256 signing raw r-s contract" :
		"[FAIL] Stage11 exact SHA256 prehashed P256 signing raw r-s contract");
	return valid;
}

/** \brief Reject digest lengths other than SHA-256 without invoking native signer.
 * \return True when invalid input cannot reach backend.
 */
static bool platform_test_wrong_digest(void)
{
	platform_test_fixture fixture;
	uint8_t digest[31U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, true);
	length = sizeof(signature);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		valid = qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) ==
			qsc_hw_status_invalid_parameter && fixture.device.signed_count == 0U;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 rejects non-SHA256 digest length before native signing" :
		"[FAIL] Stage11 rejects non-SHA256 digest length before native signing");
	return valid;
}

/** \brief Verify signer failure erases partial signature bytes.
 * \return True when failing native callback cannot leak partial output.
 */
static bool platform_test_sign_failure_erasure(void)
{
	platform_test_fixture fixture;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;
	size_t i;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_strongbox, true, true, true);
	length = sizeof(signature);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		fixture.device.sign_failure = true;
		valid = qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) ==
			qsc_hw_status_timeout;
	}

	for (i = 0U; i < sizeof(signature); ++i)
	{
		if (signature[i] != 0U)
		{
			valid = false;
		}
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 failed StrongBox signing securely erases partial output" :
		"[FAIL] Stage11 failed StrongBox signing securely erases partial output");
	return valid;
}

/** \brief Reject successful callback claiming noncanonical raw signature length.
 * \return True when partial raw signature not accepted.
 */
static bool platform_test_short_signature(void)
{
	platform_test_fixture fixture;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, true);
	length = sizeof(signature);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		fixture.device.bad_signature_length = true;
		valid = qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) ==
			qsc_hw_status_policy && signature[0U] == 0U;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 invalid raw ECDSA signature size rejected and erased" :
		"[FAIL] Stage11 invalid raw ECDSA signature size rejected and erased");
	return valid;
}

/** \brief Verify public SEC1 point output and length query without private export.
 * \return True for exact 65-byte public point.
 */
static bool platform_test_public_point(void)
{
	platform_test_fixture fixture;
	uint8_t public_point[65U] = { 0U };
	size_t length;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, true);
	length = 0U;

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		valid = qsc_hw_key_public(fixture.key, NULL, &length) == qsc_hw_status_success &&
			length == QSC_HW_PLATFORM_PUBLIC_SIZE;
	}

	if (valid == true)
	{
		length = sizeof(public_point);
		valid = qsc_hw_key_public(fixture.key, public_point, &length) == qsc_hw_status_success &&
			length == 65U && public_point[0U] == 0x04U && public_point[64U] == 64U;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 persistent platform public SEC1 point and size query" :
		"[FAIL] Stage11 persistent platform public SEC1 point and size query");
	return valid;
}

/** \brief Detect replaced persistent public identity before allowing a signature.
 * \return True if stale key cannot sign.
 */
static bool platform_test_replaced_key(void)
{
	platform_test_fixture fixture;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_strongbox, true, true, true);
	length = sizeof(signature);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		fixture.device.attributes.public_key[5U] ^= 0x40U;
		valid = qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) ==
			qsc_hw_status_stale_key && fixture.device.signed_count == 0U;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 persistent alias public-key replacement invalidates signer" :
		"[FAIL] Stage11 persistent alias public-key replacement invalidates signer");
	return valid;
}

/** \brief Reject provider downgrade after the key has been opened.
 * \return True for policy rejection before cryptographic operation.
 */
static bool platform_test_security_downgrade(void)
{
	platform_test_fixture fixture;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_strongbox, true, true, true);
	length = sizeof(signature);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		fixture.device.attributes.security = qsc_hw_platform_security_tee;
		valid = qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) ==
			qsc_hw_status_policy && fixture.device.signed_count == 0U;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 StrongBox-to-TEE downgrade detected before signing" :
		"[FAIL] Stage11 StrongBox-to-TEE downgrade detected before signing");
	return valid;
}

/** \brief Map removed platform keystore to explicit device_removed status.
 * \return True if pending private use is denied after removal.
 */
static bool platform_test_removed_device(void)
{
	platform_test_fixture fixture;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, true);
	length = sizeof(signature);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		fixture.device.removed = true;
		valid = qsc_hw_key_sign(fixture.key, digest, sizeof(digest), signature, &length) ==
			qsc_hw_status_device_removed && fixture.device.signed_count == 0U;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 removed platform keystore denies signing" :
		"[FAIL] Stage11 removed platform keystore denies signing");
	return valid;
}

/** \brief Generate a new persistent Secure Enclave key without overwriting existing.
 * \return True if QSC key generation respects policy.
 */
static bool platform_test_generate_new(void)
{
	platform_test_fixture fixture;
	qsc_hw_key_policy policy;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, false);
	policy = platform_test_policy(true);

	if (valid == true)
	{
		valid = qsc_hw_key_generate(&fixture.key, fixture.provider, &policy) ==
			qsc_hw_status_success && fixture.device.created == 1U && fixture.device.exists == true;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 new Secure Enclave identity generation without private export" :
		"[FAIL] Stage11 new Secure Enclave identity generation without private export");
	return valid;
}

/** \brief Refuse generation over an existing app-scoped persistent identity.
 * \return True when generation callback is not called for existing alias.
 */
static bool platform_test_generate_existing(void)
{
	platform_test_fixture fixture;
	qsc_hw_key_policy policy;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_strongbox, true, true, true);
	policy = platform_test_policy(true);

	if (valid == true)
	{
		valid = qsc_hw_key_generate(&fixture.key, fixture.provider, &policy) ==
			qsc_hw_status_policy && fixture.device.created == 0U;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 existing StrongBox alias cannot be overwritten" :
		"[FAIL] Stage11 existing StrongBox alias cannot be overwritten");
	return valid;
}

/** \brief Refuse generated exportable private key and roll back fresh identity.
 * \return True if prohibited key is deleted through rollback callback.
 */
static bool platform_test_generate_rollback(void)
{
	platform_test_fixture fixture;
	qsc_hw_key_policy policy;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, false);
	policy = platform_test_policy(true);
	fixture.device.invalid_generated = true;

	if (valid == true)
	{
		valid = qsc_hw_key_generate(&fixture.key, fixture.provider, &policy) ==
			qsc_hw_status_policy && fixture.device.created == 1U && fixture.device.deleted == 1U &&
			fixture.device.exists == false;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 invalid newly generated protected key immediately rolled back" :
		"[FAIL] Stage11 invalid newly generated protected key immediately rolled back");
	return valid;
}

/** \brief Surface rollback failure rather than silently leaving an unsafe key.
 * \return True when unrecovered object reported internal error.
 */
static bool platform_test_rollback_failure(void)
{
	platform_test_fixture fixture;
	qsc_hw_key_policy policy;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, false);
	policy = platform_test_policy(true);
	fixture.device.invalid_generated = true;
	fixture.device.rollback_failure = true;

	if (valid == true)
	{
		valid = qsc_hw_key_generate(&fixture.key, fixture.provider, &policy) ==
			qsc_hw_status_internal && fixture.device.exists == true;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 failed rollback preserves explicit unrecovered-key diagnostic" :
		"[FAIL] Stage11 failed rollback preserves explicit unrecovered-key diagnostic");
	return valid;
}

/** \brief Reject impossible key alias and unsupported backend family at initialization.
 * \return True if no context enters initialized state.
 */
static bool platform_test_invalid_context(void)
{
	qsc_hw_platform_context context = { 0U };
	platform_test_device device = { 0U };
	qsc_hw_platform_callbacks callbacks = { 0U };
	bool valid;

	callbacks.size = sizeof(callbacks);
	callbacks.version = QSC_HW_ABI_VERSION;
	callbacks.query = platform_test_query;
	valid = qsc_hw_platform_initialize(&context, &callbacks, &device,
		qsc_hw_platform_family_apple, "../bad", false, true) == qsc_hw_status_invalid_parameter;
	valid = valid && qsc_hw_platform_initialize(&context, &callbacks, &device,
		qsc_hw_platform_family_none, "safe", false, true) == qsc_hw_status_invalid_parameter;
	valid = valid && context.initialized == false;
	qsctest_print_line(valid ? "[PASS] Stage11 invalid alias and platform family rejected" :
		"[FAIL] Stage11 invalid alias and platform family rejected");
	return valid;
}

/** \brief Reject malformed callback ABI and incomplete creation rollback contract.
 * \return True for complete contract validation.
 */
static bool platform_test_invalid_callbacks(void)
{
	qsc_hw_platform_context context = { 0U };
	platform_test_device device = { 0U };
	qsc_hw_platform_callbacks callbacks = { 0U };
	bool valid;

	callbacks.size = sizeof(callbacks);
	callbacks.version = QSC_HW_ABI_VERSION + 1U;
	callbacks.query = platform_test_query;
	valid = qsc_hw_platform_initialize(&context, &callbacks, &device,
		qsc_hw_platform_family_apple, "safe", false, true) == qsc_hw_status_invalid_parameter;
	callbacks.version = QSC_HW_ABI_VERSION;
	callbacks.create = platform_test_create;
	valid = valid && qsc_hw_platform_initialize(&context, &callbacks, &device,
		qsc_hw_platform_family_apple, "safe", false, true) == qsc_hw_status_invalid_parameter;
	qsctest_print_line(valid ? "[PASS] Stage11 platform callback version and rollback contract validated" :
		"[FAIL] Stage11 platform callback version and rollback contract validated");
	return valid;
}

/** \brief Verify length and exact identity rules for canonical platform locator.
 * \return True when noncanonical alias cannot resolve same key.
 */
static bool platform_test_wrong_locator(void)
{
	platform_test_fixture fixture;
	qsc_hw_key_policy policy;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, true);
	policy = platform_test_policy(true);

	if (valid == true)
	{
		valid = qsc_hw_key_open(&fixture.key, fixture.provider, "android://qsc-test-key", &policy) ==
			qsc_hw_status_stale_key && fixture.key == NULL;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 incorrect platform key locator rejected" :
		"[FAIL] Stage11 incorrect platform key locator rejected");
	return valid;
}

/** \brief Verify generic provider closes only after key reference released.
 * \return True for ownership and disposal contract.
 */
static bool platform_test_close_busy(void)
{
	platform_test_fixture fixture;
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_android,
		qsc_hw_platform_security_strongbox, true, true, true);

	if (valid == true)
	{
		valid = platform_test_open(&fixture, true) == qsc_hw_status_success;
	}

	if (valid == true)
	{
		valid = qsc_hw_provider_close(&fixture.provider) == qsc_hw_status_busy;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 provider close refused while platform key is live" :
		"[FAIL] Stage11 provider close refused while platform key is live");
	return valid;
}

/** \brief Validate no unsupported ECDH or attestation advertised by bridge.
 * \return True if capabilities contain only actually implemented operations.
 */
static bool platform_test_capabilities(void)
{
	platform_test_fixture fixture;
	qsc_hw_capabilities capabilities = { 0U };
	bool valid;

	valid = platform_test_setup(&fixture, qsc_hw_platform_family_apple,
		qsc_hw_platform_security_enclave, true, false, true);
	capabilities.size = sizeof(capabilities);
	capabilities.version = QSC_HW_ABI_VERSION;

	if (valid == true)
	{
		valid = qsc_hw_provider_capabilities(fixture.provider, &capabilities) ==
			qsc_hw_status_success &&
			(capabilities.flags & qsc_hw_capability_sign) != 0U &&
			(capabilities.flags & (qsc_hw_capability_attest | qsc_hw_capability_agree |
			qsc_hw_capability_random)) == 0U;
	}

	platform_test_cleanup(&fixture);
	qsctest_print_line(valid ? "[PASS] Stage11 platform bridge does not overstate attestation or ECDH" :
		"[FAIL] Stage11 platform bridge does not overstate attestation or ECDH");
	return valid;
}

/** \brief Run every named Stage 11 platform provider test directly in order.
 * \return True if all individually executed tests pass.
 */
bool qsctest_hwplatform_run(void)
{
	bool valid;

	valid = true;

	if (platform_test_apple_open() == false)
	{
		valid = false;
	}
	if (platform_test_apple_reject_tee() == false)
	{
		valid = false;
	}
	if (platform_test_strongbox_required() == false)
	{
		valid = false;
	}
	if (platform_test_strongbox_open() == false)
	{
		valid = false;
	}
	if (platform_test_tee_open() == false)
	{
		valid = false;
	}
	if (platform_test_software_reject() == false)
	{
		valid = false;
	}
	if (platform_test_unqualified_hardware() == false)
	{
		valid = false;
	}
	if (platform_test_unqualified_allowed() == false)
	{
		valid = false;
	}
	if (platform_test_sign_digest() == false)
	{
		valid = false;
	}
	if (platform_test_wrong_digest() == false)
	{
		valid = false;
	}
	if (platform_test_sign_failure_erasure() == false)
	{
		valid = false;
	}
	if (platform_test_short_signature() == false)
	{
		valid = false;
	}
	if (platform_test_public_point() == false)
	{
		valid = false;
	}
	if (platform_test_replaced_key() == false)
	{
		valid = false;
	}
	if (platform_test_security_downgrade() == false)
	{
		valid = false;
	}
	if (platform_test_removed_device() == false)
	{
		valid = false;
	}
	if (platform_test_generate_new() == false)
	{
		valid = false;
	}
	if (platform_test_generate_existing() == false)
	{
		valid = false;
	}
	if (platform_test_generate_rollback() == false)
	{
		valid = false;
	}
	if (platform_test_rollback_failure() == false)
	{
		valid = false;
	}
	if (platform_test_invalid_context() == false)
	{
		valid = false;
	}
	if (platform_test_invalid_callbacks() == false)
	{
		valid = false;
	}
	if (platform_test_wrong_locator() == false)
	{
		valid = false;
	}
	if (platform_test_close_busy() == false)
	{
		valid = false;
	}
	if (platform_test_capabilities() == false)
	{
		valid = false;
	}

	return valid;
}

#else

/** \brief Hardware platform tests disabled in this compile profile.
 * \return True because no platform provider tests are selected.
 */
bool qsctest_hwplatform_run(void)
{
	return true;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PLATFORM_ENABLED */
