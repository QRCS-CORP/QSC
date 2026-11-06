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

#include "hwatecc_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_ATECC_ENABLED)

#include "hwatecc.h"
#include "memutils.h"
#include "stringutils.h"
#include "testutils.h"

/** \struct hwatecc_test_device
 * \brief Deterministic synthetic device and injected fault controls (no cryptography).
 */
typedef struct hwatecc_test_device
{
	uint8_t serial[QSC_HW_ATECC_SERIAL_SIZE]; /**< Public token identity. */
	bool present; /**< Simulated bus availability. */
	bool locked; /**< Simulated secure slot lock status. */
	bool private_slot; /**< Simulated private-key slot config. */
	bool signing; /**< Simulated signing use flag. */
	bool extractable; /**< Simulated dangerous key extraction setting. */
	bool sign_failure; /**< Simulates device returning an error after writing output. */
	bool public_failure; /**< Simulates public-key bus failure. */
	uint32_t sign_count; /**< Number of synthetic sign callback invocations. */
} hwatecc_test_device;

/** \brief Read the synthetic token serial, or a typed bus error.
 * \param device Test-owned device.
 * \param serial Output exactly nine bytes.
 * \return Success or device-removed error.
 */
static qsc_hw_status hwatecc_test_serial(void* device, uint8_t* serial)
{
	hwatecc_test_device* state;
	qsc_hw_status status;

	status = qsc_hw_status_device_removed;
	state = (hwatecc_test_device*)device;

	if (state != NULL && state->present == true)
	{
		qsc_memutils_copy(serial, state->serial, QSC_HW_ATECC_SERIAL_SIZE);
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Report a fixed synthetic ATECC slot policy.
 * \param device Test-owned device.
 * \param slot Selected slot (requires slot 2).
 * \param policy Output configuration without secret data.
 * \return Success or policy error.
 */
static qsc_hw_status hwatecc_test_policy(void* device, uint8_t slot, qsc_hw_atecc_slot_policy* policy)
{
	hwatecc_test_device* state;
	qsc_hw_status status;

	status = qsc_hw_status_policy;
	state = (hwatecc_test_device*)device;

	if (state != NULL && state->present == true && slot == 2U && policy != NULL)
	{
		policy->configuration_locked = state->locked;
		policy->data_locked = state->locked;
		policy->private_key = state->private_slot;
		policy->signing_enabled = state->signing;
		policy->private_exportable = state->extractable;
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Return a deterministic noncryptographic 64-byte public point fixture.
 * \param device Test-owned device.
 * \param slot Selected slot (requires slot 2).
 * \param publickey Writable 64-byte test data.
 * \return Success or injected internal error.
 */
static qsc_hw_status hwatecc_test_public(void* device, uint8_t slot, uint8_t* publickey)
{
	hwatecc_test_device* state;
	qsc_hw_status status;
	size_t i;

	status = qsc_hw_status_internal;
	state = (hwatecc_test_device*)device;

	if (state != NULL && state->public_failure == false && slot == 2U)
	{
		for (i = 0U; i < 64U; ++i)
		{
			publickey[i] = (uint8_t)(i + 1U);
		}

		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Generate a deterministic 64-byte synthetic response to a 32-byte digest.
 * \param device Test-owned device.
 * \param slot Selected slot (requires slot 2).
 * \param digest Noncryptographically inspected 32-byte digest.
 * \param signature Writable fixed response; deliberately partial on injected failure.
 * \return Success or injected internal error.
 */
static qsc_hw_status hwatecc_test_sign(void* device, uint8_t slot, const uint8_t* digest, uint8_t* signature)
{
	hwatecc_test_device* state;
	qsc_hw_status status;
	size_t i;

	status = qsc_hw_status_internal;
	state = (hwatecc_test_device*)device;

	if (state != NULL && slot == 2U && digest != NULL)
	{
		++state->sign_count;

		for (i = 0U; i < 64U; ++i)
		{
			signature[i] = state->sign_failure ? 0xA5U : (uint8_t)(digest[0U] + (uint8_t)i);
		}

		if (state->sign_failure == false)
		{
			status = qsc_hw_status_success;
		}
	}

	return status;
}

/** \brief Create one fully populated local test device and versioned callback table.
 * \param device Writable synthetic device.
 * \param callbacks Writable QSC callback descriptor.
 */
static void hwatecc_test_setup(hwatecc_test_device* device, qsc_hw_atecc_callbacks* callbacks)
{
	size_t i;

	qsc_memutils_clear(device, sizeof(hwatecc_test_device));
	qsc_memutils_clear(callbacks, sizeof(qsc_hw_atecc_callbacks));

	for (i = 0U; i < QSC_HW_ATECC_SERIAL_SIZE; ++i)
	{
		device->serial[i] = (uint8_t)(i + 1U);
	}

	device->present = true;
	device->locked = true;
	device->private_slot = true;
	device->signing = true;
	callbacks->size = sizeof(qsc_hw_atecc_callbacks);
	callbacks->version = QSC_HW_ABI_VERSION;
	callbacks->read_serial = hwatecc_test_serial;
	callbacks->read_slot_policy = hwatecc_test_policy;
	callbacks->read_public = hwatecc_test_public;
	callbacks->sign_digest = hwatecc_test_sign;
}

/** \brief Start a synthetic ATECC provider and optionally open its signing key.
 * \param device Configured synthetic device.
 * \param callbacks Versioned callback descriptor.
 * \param context Zero-initialized context.
 * \param provider Output owned provider.
 * \param key Optional output signing key; NULL means just open provider.
 * \param physical_consent Test-only assertion of device identity; not evidence of real hardware.
 * \return True only when all requested setup calls succeed.
 */
static bool hwatecc_test_open(hwatecc_test_device* device, qsc_hw_atecc_callbacks* callbacks,
	qsc_hw_atecc_context* context, qsc_hw_provider** provider, qsc_hw_keyref** key, bool physical_consent)
{
	qsc_hw_provider_ops ops;
	qsc_hw_key_policy policy;
	qsc_hw_status status;
	char locator[QSC_HW_ATECC_LOCATOR_SIZE] = { 0 };
	size_t length;
	bool valid;

	valid = false;
	qsc_memutils_clear(&ops, sizeof(ops));
	status = qsc_hw_atecc_initialize(context, callbacks, device, 2U, physical_consent);

	if (status == qsc_hw_status_success)
	{
		status = qsc_hw_atecc_get_operations(&ops);
	}

	if (status == qsc_hw_status_success)
	{
		status = qsc_hw_provider_open(provider, &ops, context);
	}

	if (status == qsc_hw_status_success && key != NULL)
	{
		length = sizeof(locator);
		status = qsc_hw_atecc_locator(context, locator, &length);
		qsc_memutils_clear(&policy, sizeof(policy));
		policy.size = sizeof(policy);
		policy.version = QSC_HW_ABI_VERSION;
		policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
		policy.usage = qsc_hw_usage_sign;
		policy.require_hardware = true;
		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_key_open(key, *provider, locator, &policy);
		}
	}

	valid = (status == qsc_hw_status_success);
	return valid;
}

/** \brief Confirm invalid ATECC contexts and callbacks fail closed.
 * \return True if no invalid backend can initialize.
 */
static bool hwatecc_test_reject_bad_config(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = (qsc_hw_atecc_initialize(NULL, &callbacks, &device, 2U, true) == qsc_hw_status_invalid_parameter);
	valid = (qsc_hw_atecc_initialize(&context, &callbacks, &device, 16U, true) == qsc_hw_status_invalid_parameter) && valid;
	callbacks.version += 1U;
	valid = (qsc_hw_atecc_initialize(&context, &callbacks, &device, 2U, true) == qsc_hw_status_invalid_parameter) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC invalid configuration and ABI rejected" : "[FAIL] Stage9 ATECC invalid configuration and ABI rejected");
	return valid;
}

/** \brief Require locked and sign-enabled private slots before initialization.
 * \return True if insecure or non-signing slots fail initialization.
 */
static bool hwatecc_test_reject_unlocked(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	device.locked = false;
	valid = (qsc_hw_atecc_initialize(&context, &callbacks, &device, 2U, true) == qsc_hw_status_policy);
	device.locked = true;
	device.private_slot = false;
	valid = (qsc_hw_atecc_initialize(&context, &callbacks, &device, 2U, true) == qsc_hw_status_policy) && valid;
	device.private_slot = true;
	device.signing = false;
	valid = (qsc_hw_atecc_initialize(&context, &callbacks, &device, 2U, true) == qsc_hw_status_policy) && valid;
	device.signing = true;
	device.extractable = true;
	valid = (qsc_hw_atecc_initialize(&context, &callbacks, &device, 2U, true) == qsc_hw_status_policy) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC unlocked/exportable slot refused" : "[FAIL] Stage9 ATECC unlocked/exportable slot refused");
	return valid;
}

/** \brief Check provider metadata and non-advertisement of destructive features.
 * \return True when only supported bounded operations are advertised.
 */
static bool hwatecc_test_capability_profile(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_capabilities cap = { 0U };
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, NULL, true);
	cap.size = sizeof(cap);
	cap.version = QSC_HW_ABI_VERSION;
	valid = (qsc_hw_provider_capabilities(provider, &cap) == qsc_hw_status_success) && valid;
	valid = (cap.flags == (uint32_t)(qsc_hw_capability_key_open | qsc_hw_capability_public_key | qsc_hw_capability_sign)) && valid;
	valid = (cap.max_sessions == 1U && cap.requires_serialization == true && cap.supports_cancel == false) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC protected P256 capability profile" : "[FAIL] Stage9 ATECC protected P256 capability profile");
	return valid;
}

/** \brief Verify exact device-bound locator length, content and size-query behavior.
 * \return True if output size and serial/slot locator are consistent.
 */
static bool hwatecc_test_locator(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	char locator[QSC_HW_ATECC_LOCATOR_SIZE] = { 0 };
	size_t length;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = (qsc_hw_atecc_initialize(&context, &callbacks, &device, 2U, true) == qsc_hw_status_success);
	length = 1U;
	valid = (qsc_hw_atecc_locator(&context, locator, &length) == qsc_hw_status_buffer_too_small) && valid;
	valid = (length == QSC_HW_ATECC_LOCATOR_SIZE) && valid;
	length = sizeof(locator);
	valid = (qsc_hw_atecc_locator(&context, locator, &length) == qsc_hw_status_success) && valid;
	valid = (qsc_stringutils_compare_strings(locator, "atecc://010203040506070809/02", sizeof(locator)) == true) && valid;
	qsc_hw_atecc_dispose(&context);
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC fixed device/slot locator and sizing" : "[FAIL] Stage9 ATECC fixed device/slot locator and sizing");
	return valid;
}

/** \brief Verify generation and key agreement are unavailable on pre-provisioned signing slots.
 * \return True if unsupported operations do not create or expose private material.
 */
static bool hwatecc_test_no_generate_agree(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	qsc_hw_keyref* generated = NULL;
	qsc_hw_key_policy policy = { 0U };
	uint8_t secret[32U] = { 0U };
	size_t size;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = true;
	valid = (qsc_hw_key_generate(&generated, provider, &policy) == qsc_hw_status_unsupported && generated == NULL) && valid;
	size = sizeof(secret);
	valid = (qsc_hw_key_agree(key, secret, sizeof(secret), secret, &size) == qsc_hw_status_policy) && valid;
	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC no runtime keygen/ECDH or export" : "[FAIL] Stage9 ATECC no runtime keygen/ECDH or export");
	return valid;
}

/** \brief Validate public point size query and exact SEC1 output.
 * \return True when callback emits public key only after hardware policy checks.
 */
static bool hwatecc_test_public_point(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	uint8_t output[QSC_HW_ATECC_PUBLIC_SIZE] = { 0U };
	size_t size;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	size = 0U;
	valid = (qsc_hw_key_public(key, NULL, &size) == qsc_hw_status_success && size == sizeof(output)) && valid;
	size = 1U;
	valid = (qsc_hw_key_public(key, output, &size) == qsc_hw_status_buffer_too_small && size == sizeof(output)) && valid;
	size = sizeof(output);
	valid = (qsc_hw_key_public(key, output, &size) == qsc_hw_status_success) && valid;
	valid = (output[0U] == 0x04U && output[1U] == 1U && output[64U] == 64U) && valid;
	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC SEC1 public point and buffer sizing" : "[FAIL] Stage9 ATECC SEC1 public point and buffer sizing");
	return valid;
}

/** \brief Verify a vendor public-key failure does not disclose partial stale point bytes.
 * \return True if the caller output remains unchanged on callback failure.
 */
static bool hwatecc_test_public_failure(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	uint8_t output[QSC_HW_ATECC_PUBLIC_SIZE] = { 0U };
	size_t size;
	size_t i;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	device.public_failure = true;
	size = sizeof(output);
	valid = (qsc_hw_key_public(key, output, &size) == qsc_hw_status_internal) && valid;

	for (i = 0U; i < sizeof(output); ++i)
	{
		valid = (output[i] == 0U) && valid;
	}

	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC public-key callback failure isolates output" : "[FAIL] Stage9 ATECC public-key callback failure isolates output");
	return valid;
}

/** \brief Verify the signing facade handles prehashed P-256 and buffer-sizing failures.
 * \return True if signing occurs only for valid digest and writable output.
 */
static bool hwatecc_test_sign_digest(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	uint8_t digest[32U] = { 9U };
	uint8_t signature[64U] = { 0U };
	size_t size;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	size = 0U;
	valid = (qsc_hw_key_sign(key, digest, sizeof(digest), NULL, &size) == qsc_hw_status_success && size == 64U) && valid;
	valid = (device.sign_count == 0U) && valid;
	size = 1U;
	valid = (qsc_hw_key_sign(key, digest, sizeof(digest), signature, &size) == qsc_hw_status_buffer_too_small && size == 64U) && valid;
	size = sizeof(signature);
	valid = (qsc_hw_key_sign(key, digest, sizeof(digest), signature, &size) == qsc_hw_status_success) && valid;
	valid = (signature[0U] == 9U && signature[63U] == 72U && device.sign_count == 1U) && valid;
	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC fixed SHA256 digest signature and sizing" : "[FAIL] Stage9 ATECC fixed SHA256 digest signature and sizing");
	return valid;
}

/** \brief Verify signing failures cannot expose a partially written signature.
 * \return True if failed device writes are erased by the adapter and facade.
 */
static bool hwatecc_test_partial_sign_failure(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	uint8_t digest[32U] = { 7U };
	uint8_t signature[64U] = { 0U };
	size_t i;
	size_t size;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	device.sign_failure = true;
	size = sizeof(signature);
	valid = (qsc_hw_key_sign(key, digest, sizeof(digest), signature, &size) == qsc_hw_status_internal) && valid;

	for (i = 0U; i < sizeof(signature); ++i)
	{
		valid = (signature[i] == 0U) && valid;
	}

	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC partial-signature erasure after failure" : "[FAIL] Stage9 ATECC partial-signature erasure after failure");
	return valid;
}

/** \brief Reject a replacement chip after a protected key was opened.
 * \return True if serial replacement invalidates operations without signing.
 */
static bool hwatecc_test_serial_swap(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	uint8_t digest[32U] = { 1U };
	uint8_t signature[64U] = { 0U };
	size_t size;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	device.serial[0U] ^= 0x7FU;
	size = sizeof(signature);
	valid = (qsc_hw_key_sign(key, digest, sizeof(digest), signature, &size) == qsc_hw_status_stale_key) && valid;
	valid = (device.sign_count == 0U) && valid;
	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC replacement serial invalidates old key" : "[FAIL] Stage9 ATECC replacement serial invalidates old key");
	return valid;
}

/** \brief Reject signing after device removal, with no synthetic callback invocation.
 * \return True if missing bus/device fails closed.
 */
static bool hwatecc_test_device_removed(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	uint8_t digest[32U] = { 1U };
	uint8_t signature[64U] = { 0U };
	size_t size;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	device.present = false;
	size = sizeof(signature);
	valid = (qsc_hw_key_sign(key, digest, sizeof(digest), signature, &size) == qsc_hw_status_device_removed) && valid;
	valid = (device.sign_count == 0U) && valid;
	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC missing device aborts signing" : "[FAIL] Stage9 ATECC missing device aborts signing");
	return valid;
}

/** \brief Reject a slot that becomes unlocked or changes signing policy after opening.
 * \return True if late policy change blocks active key use.
 */
static bool hwatecc_test_policy_change(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	uint8_t digest[32U] = { 1U };
	uint8_t signature[64U] = { 0U };
	size_t size;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	device.signing = false;
	size = sizeof(signature);
	valid = (qsc_hw_key_sign(key, digest, sizeof(digest), signature, &size) == qsc_hw_status_policy) && valid;
	valid = (device.sign_count == 0U) && valid;
	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC runtime slot policy change blocks signing" : "[FAIL] Stage9 ATECC runtime slot policy change blocks signing");
	return valid;
}

/** \brief Verify required physical residency cannot be satisfied by a simulated device.
 * \return True if unconfirmed device custody is rejected.
 */
static bool hwatecc_test_unconfirmed_custody(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	qsc_hw_key_policy policy = { 0U };
	char locator[QSC_HW_ATECC_LOCATOR_SIZE] = { 0 };
	size_t length;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, NULL, false);
	length = sizeof(locator);
	valid = (qsc_hw_atecc_locator(&context, locator, &length) == qsc_hw_status_success) && valid;
	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = true;
	valid = (qsc_hw_key_open(&key, provider, locator, &policy) == qsc_hw_status_policy && key == NULL) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC simulator hardware-residency claim rejected" : "[FAIL] Stage9 ATECC simulator hardware-residency claim rejected");
	return valid;
}

/** \brief Ensure open key references prevent premature device-context shutdown.
 * \return True if provider close refuses live protected key references.
 */
static bool hwatecc_test_close_busy(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_busy) && valid;
	valid = (context.initialized == true && key != NULL) && valid;
	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	valid = (context.initialized == false) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC live key blocks provider close" : "[FAIL] Stage9 ATECC live key blocks provider close");
	return valid;
}

/** \brief Reject malicious or mismatched key locators.
 * \return True if a different slot or device serial is not accepted.
 */
static bool hwatecc_test_wrong_locator(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	qsc_hw_key_policy policy = { 0U };
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, NULL, true);
	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = true;
	valid = (qsc_hw_key_open(&key, provider, "atecc://010203040506070809/03", &policy) == qsc_hw_status_stale_key) && valid;
	valid = (qsc_hw_key_open(&key, provider, "atecc://010203040506070809/02XYZ", &policy) == qsc_hw_status_stale_key) && valid;
	valid = (key == NULL) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC wrong slot/ambiguous locator rejected" : "[FAIL] Stage9 ATECC wrong slot/ambiguous locator rejected");
	return valid;
}

/** \brief Test that disallowed digest lengths are rejected without contacting hardware.
 * \return True when SHA-384/short digest cannot enter P-256 signer.
 */
static bool hwatecc_test_digest_length(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	qsc_hw_provider* provider = NULL;
	qsc_hw_keyref* key = NULL;
	uint8_t digest[48U] = { 1U };
	uint8_t signature[64U] = { 0U };
	size_t length;
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = hwatecc_test_open(&device, &callbacks, &context, &provider, &key, true);
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(key, digest, sizeof(digest), signature, &length) == qsc_hw_status_invalid_parameter) && valid;
	length = sizeof(signature);
	valid = (qsc_hw_key_sign(key, digest, 31U, signature, &length) == qsc_hw_status_invalid_parameter) && valid;
	valid = (device.sign_count == 0U) && valid;
	valid = (qsc_hw_key_release(&key) == qsc_hw_status_success) && valid;
	valid = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC SHA256-only digest contract" : "[FAIL] Stage9 ATECC SHA256-only digest contract");
	return valid;
}

/** \brief Verify second initialization is refused without dropping the original context.
 * \return True when live device context cannot be silently overwritten.
 */
static bool hwatecc_test_duplicate_initialization(void)
{
	hwatecc_test_device device;
	qsc_hw_atecc_callbacks callbacks;
	qsc_hw_atecc_context context = { 0U };
	bool valid;

	hwatecc_test_setup(&device, &callbacks);
	valid = (qsc_hw_atecc_initialize(&context, &callbacks, &device, 2U, true) == qsc_hw_status_success);
	valid = (qsc_hw_atecc_initialize(&context, &callbacks, &device, 2U, true) == qsc_hw_status_busy) && valid;
	valid = context.initialized && valid;
	qsc_hw_atecc_dispose(&context);
	qsctest_print_line(valid ? "[PASS] Stage9 ATECC duplicate initialization refused" : "[FAIL] Stage9 ATECC duplicate initialization refused");
	return valid;
}

bool qsctest_hwatecc_run(void)
{
	bool valid;

	valid = true;
	valid = hwatecc_test_reject_bad_config() && valid;
	valid = hwatecc_test_reject_unlocked() && valid;
	valid = hwatecc_test_capability_profile() && valid;
	valid = hwatecc_test_locator() && valid;
	valid = hwatecc_test_no_generate_agree() && valid;
	valid = hwatecc_test_public_point() && valid;
	valid = hwatecc_test_public_failure() && valid;
	valid = hwatecc_test_sign_digest() && valid;
	valid = hwatecc_test_partial_sign_failure() && valid;
	valid = hwatecc_test_serial_swap() && valid;
	valid = hwatecc_test_device_removed() && valid;
	valid = hwatecc_test_policy_change() && valid;
	valid = hwatecc_test_unconfirmed_custody() && valid;
	valid = hwatecc_test_close_busy() && valid;
	valid = hwatecc_test_wrong_locator() && valid;
	valid = hwatecc_test_digest_length() && valid;
	valid = hwatecc_test_duplicate_initialization() && valid;
	return valid;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_ATECC_ENABLED */
