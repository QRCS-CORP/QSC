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

#include "hwmock_test.h"

#if defined(QSC_HARDWARE_ENABLED)

#include "hwmock.h"
#include "hwprovider.h"
#include "memutils.h"
#include "testutils.h"

/** \file hwmock_test.c
 * \brief Isolated provider conformance tests using synthetic, noncryptographic outputs.
 * \details All test functions are invoked by direct statements in source order.
 */

/** \brief Initialize hardware-only test policy without allowing software fallback.
 * \param policy Caller-owned output.
 * \param usage Bitmask of allowed key operations.
 * \param derived_export Explicit raw ECDH secret export permission.
 */
static void hwmock_test_policy(qsc_hw_key_policy* policy, uint32_t usage, bool derived_export)
{
	qsc_memutils_clear(policy, sizeof(qsc_hw_key_policy));
	policy->size = sizeof(qsc_hw_key_policy);
	policy->version = QSC_HW_ABI_VERSION;
	policy->algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy->usage = usage;
	policy->require_hardware = true;
	policy->allow_derived_secret_export = derived_export;
}

/** \brief Open a provider from caller-owned, initialized mock context.
 * \param context Caller-owned backend context.
 * \param provider Output new provider or NULL after failure.
 * \return True only if QSC accepts the versioned callback table.
 */
static bool hwmock_test_provider(qsctest_hwmock_context* context, qsc_hw_provider** provider)
{
	qsc_hw_provider_ops ops;
	bool pass;

	qsctest_hwmock_make_ops(&ops);
	*provider = NULL;
	pass = (qsc_hw_provider_open(provider, &ops, context) == qsc_hw_status_success);

	return pass;
}

/** \brief Authenticate using fixed test-only PIN; no PIN persists in context.
 * \param context Caller-owned mock token.
 * \return True when test PIN authentication succeeds.
 */
static bool hwmock_test_login(qsctest_hwmock_context* context)
{
	static const uint8_t pin[4U] = { 0x31U, 0x32U, 0x33U, 0x34U };
	bool pass;

	pass = (qsctest_hwmock_login(context, pin, sizeof(pin)) == qsc_hw_status_success);

	return pass;
}

/** \brief Release an optional key then close its provider.
 * \param provider Output pointer to provider handle.
 * \param key Output pointer to transient key handle, possibly NULL.
 * \return True if no caller-owned provider/key remains live.
 */
static bool hwmock_test_close(qsc_hw_provider** provider, qsc_hw_keyref** key)
{
	bool pass;

	pass = true;

	if (key != NULL && *key != NULL)
	{
		pass = (qsc_hw_key_release(key) == qsc_hw_status_success) && pass;
	}

	if (provider != NULL && *provider != NULL)
	{
		pass = (qsc_hw_provider_close(provider) == qsc_hw_status_success) && pass;
	}

	return pass;
}

/** \brief Check accurate capabilities and session semantics.
 * \return True when capability flags, limits and threading contract are exact.
 */
static bool qsctest_hwmock_capabilities_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_capabilities caps;
	qsc_hw_provider* provider;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	qsc_memutils_clear(&caps, sizeof(caps));
	caps.size = sizeof(caps);
	caps.version = QSC_HW_ABI_VERSION;
	pass = hwmock_test_provider(&ctx, &provider);

	if (pass == true)
	{
		pass = qsc_hw_provider_capabilities(provider, &caps) == qsc_hw_status_success &&
			caps.max_sessions == QSCTEST_HWMOCK_SESSION_LIMIT && caps.thread_safe == false &&
			caps.requires_serialization == true && caps.operation_can_block == true && caps.supports_cancel == false;
	}

	pass = hwmock_test_close(&provider, NULL) && pass;

	return pass;
}

/** \brief Require authentication for mock private object discovery.
 * \return True when opening without PIN fails with auth_required and no session.
 */
static bool qsctest_hwmock_auth_required_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_auth_required &&
			key == NULL && ctx.sessions == 0U;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Verify authenticated open, nonexportable attributes and lifecycle.
 * \return True when a token key is referenced and disposed exactly once.
 */
static bool qsctest_hwmock_authenticated_open_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_key_info info;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		qsc_memutils_clear(&info, sizeof(info));
		info.size = sizeof(info);
		info.version = QSC_HW_ABI_VERSION;
		pass = qsc_hw_key_get_info(key, &info) == qsc_hw_status_success &&
			info.custody == qsc_hw_custody_hardware_nonexportable && info.extractable == false;
	}

	pass = hwmock_test_close(&provider, &key) && pass;
	pass = pass && ctx.sessions == 0U && ctx.releases == 1U && ctx.closes == 1U;

	return pass;
}

/** \brief Simulate three bad PINs and reject subsequent correct PIN.
 * \return True when lockout cannot be bypassed by another login.
 */
static bool qsctest_hwmock_pin_lockout_test(void)
{
	static const uint8_t bad[4U] = { 0x30U, 0x30U, 0x30U, 0x30U };
	qsctest_hwmock_context ctx;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	pass = qsctest_hwmock_login(&ctx, bad, sizeof(bad)) == qsc_hw_status_auth_failed;
	pass = (qsctest_hwmock_login(&ctx, bad, sizeof(bad)) == qsc_hw_status_auth_failed) && pass;
	pass = (qsctest_hwmock_login(&ctx, bad, sizeof(bad)) == qsc_hw_status_locked) && pass;
	pass = (hwmock_test_login(&ctx) == false && ctx.pin_locked == true && ctx.pin_failures == 3U) && pass;

	return pass;
}

/** \brief Confirm logout prevents new private operations without reauthentication.
 * \return True on auth_required after logout.
 */
static bool qsctest_hwmock_logout_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);
	qsctest_hwmock_logout(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_auth_required;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Simulate disconnection followed by explicit stale-generation invalidation.
 * \return True for device_removed before invalidation and stale_key afterwards.
 */
static bool qsctest_hwmock_removal_stale_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t signature[8U] = { 0U };
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		qsctest_hwmock_remove(&ctx);
		length = sizeof(signature);
		pass = qsc_hw_key_sign(key, NULL, 0U, signature, &length) == qsc_hw_status_device_removed;
		pass = (qsc_hw_provider_invalidate(provider) == qsc_hw_status_success) && pass;
		pass = (qsc_hw_key_sign(key, NULL, 0U, signature, &length) == qsc_hw_status_stale_key) && pass;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Resolve stable key locator after a simulated slot renumbering.
 * \return True for reopening the same persistent key at a different numeric slot.
 */
static bool qsctest_hwmock_slot_renumber_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
		pass = (qsc_hw_key_release(&key) == qsc_hw_status_success) && pass;
		qsctest_hwmock_remove(&ctx);
		qsctest_hwmock_insert(&ctx, false);
		pass = (qsc_hw_provider_invalidate(provider) == qsc_hw_status_success) && pass;
		pass = (ctx.slot == 11U && hwmock_test_login(&ctx)) && pass;
		pass = (qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success) && pass;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Reject prior persistent locator after simulated token replacement.
 * \return True if the replaced token cannot alias the previous identity.
 */
static bool qsctest_hwmock_token_replace_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* oldkey;
	qsc_hw_keyref* newkey;
	uint8_t signature[8U] = { 0U };
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	oldkey = NULL;
	newkey = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&oldkey, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		qsctest_hwmock_remove(&ctx);
		qsctest_hwmock_insert(&ctx, true);
		pass = (qsc_hw_provider_invalidate(provider) == qsc_hw_status_success) && pass;
		pass = hwmock_test_login(&ctx) && pass;
		length = sizeof(signature);
		pass = (qsc_hw_key_sign(oldkey, NULL, 0U, signature, &length) == qsc_hw_status_stale_key) && pass;
		pass = (qsc_hw_key_open(&newkey, provider, "mock:010203:01", &policy) == qsc_hw_status_unsupported) && pass;
	}

	if (newkey != NULL)
	{
		pass = (qsc_hw_key_release(&newkey) == qsc_hw_status_success) && pass;
	}
	if (oldkey != NULL)
	{
		pass = (qsc_hw_key_release(&oldkey) == qsc_hw_status_success) && pass;
	}
	if (provider != NULL)
	{
		pass = (qsc_hw_provider_close(&provider) == qsc_hw_status_success) && pass;
	}

	return pass;
}

/** \brief Exercise two-session limit and provider close-with-live-handle protection.
 * \return True if a third open fails busy and close waits for releases.
 */
static bool qsctest_hwmock_session_limit_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* first;
	qsc_hw_keyref* second;
	qsc_hw_keyref* third;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	first = NULL;
	second = NULL;
	third = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&first, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
		pass = (qsc_hw_key_open(&second, provider, "mock:010203:02", &policy) == qsc_hw_status_success) && pass;
		pass = (qsc_hw_key_open(&third, provider, "mock:010203:01", &policy) == qsc_hw_status_busy && third == NULL) && pass;
		pass = (qsc_hw_provider_close(&provider) == qsc_hw_status_busy && provider != NULL) && pass;
		pass = (qsc_hw_key_release(&first) == qsc_hw_status_success) && pass;
		pass = (qsc_hw_key_open(&third, provider, "mock:010203:01", &policy) == qsc_hw_status_success) && pass;
	}

	if (first != NULL)
	{
		pass = (qsc_hw_key_release(&first) == qsc_hw_status_success) && pass;
	}
	if (second != NULL)
	{
		pass = (qsc_hw_key_release(&second) == qsc_hw_status_success) && pass;
	}
	if (third != NULL)
	{
		pass = (qsc_hw_key_release(&third) == qsc_hw_status_success) && pass;
	}
	pass = hwmock_test_close(&provider, NULL) && pass;
	pass = (ctx.sessions == 0U && ctx.releases == 3U && ctx.closes == 1U) && pass;

	return pass;
}

/** \brief Reject malformed version metadata and release backend handle.
 * \return True if no transient key survives metadata validation failure.
 */
static bool qsctest_hwmock_metadata_fault_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	ctx.bad_metadata = true;
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_policy &&
			key == NULL && ctx.releases == 1U && ctx.sessions == 0U;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Reject software-reported keys when caller demands non-exportable hardware.
 * \return True if no implicit software downgrade occurs.
 */
static bool qsctest_hwmock_software_fallback_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	ctx.software_custody = true;
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_policy && key == NULL;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Reject a backend that reports private key extractability.
 * \return True for explicit policy error without leaked handle.
 */
static bool qsctest_hwmock_exportability_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	ctx.extractable = true;
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_policy && key == NULL;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Detect unknown capability bits rather than trusting invented services.
 * \return True when public API reports internal capability mismatch.
 */
static bool qsctest_hwmock_capabilities_fault_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_capabilities caps;
	qsc_hw_provider* provider;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	ctx.bad_capabilities = true;
	qsc_memutils_clear(&caps, sizeof(caps));
	caps.size = sizeof(caps);
	caps.version = QSC_HW_ABI_VERSION;
	pass = hwmock_test_provider(&ctx, &provider);

	if (pass == true)
	{
		pass = qsc_hw_provider_capabilities(provider, &caps) == qsc_hw_status_internal;
	}

	pass = hwmock_test_close(&provider, NULL) && pass;

	return pass;
}

/** \brief Forward a deterministic module timeout from key lookup.
 * \return True for timeout and zero created transient keys.
 */
static bool qsctest_hwmock_open_timeout_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);
	qsctest_hwmock_set_fault(&ctx, qsctest_hwmock_action_open, qsc_hw_status_timeout, false);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_timeout &&
			ctx.fault_issued == true && key == NULL && ctx.sessions == 0U;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Inject a failed generation before persistent-object creation.
 * \return True if generated key and session counts remain unchanged.
 */
static bool qsctest_hwmock_generate_timeout_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);
	qsctest_hwmock_set_fault(&ctx, qsctest_hwmock_action_generate, qsc_hw_status_timeout, false);

	if (pass == true)
	{
		pass = qsc_hw_key_generate(&key, provider, &policy) == qsc_hw_status_timeout &&
			ctx.fault_issued == true && key == NULL && ctx.generations == 0U && ctx.sessions == 0U;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Generate a protected synthetic identity with enforced metadata.
 * \return True when a new key has nonextractable custody and releases correctly.
 */
static bool qsctest_hwmock_generate_success_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_generate(&key, provider, &policy) == qsc_hw_status_success &&
			ctx.generations == 1U && key != NULL && ctx.keys[2U].exists == true;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Verify repeated deterministic signing, sizing and untouched undersized buffer.
 * \return True when synthetic bytes and required lengths match exactly.
 */
static bool qsctest_hwmock_sign_roundtrip_test(void)
{
	static const uint8_t message[3U] = { 1U, 2U, 3U };
	static const uint8_t expected[8U] = { 1U, 0U, 3U, 2U, 5U, 4U, 7U, 6U };
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t signature[8U];
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		length = 0U;
		pass = qsc_hw_key_sign(key, message, sizeof(message), NULL, &length) == qsc_hw_status_buffer_too_small && length == sizeof(expected);
		qsc_memutils_set_value(signature, sizeof(signature), 0xD3U);
		length = 2U;
		pass = (qsc_hw_key_sign(key, message, sizeof(message), signature, &length) == qsc_hw_status_buffer_too_small) && pass;
		pass = (signature[0U] == 0xD3U && signature[1U] == 0xD3U && length == sizeof(expected)) && pass;
		length = sizeof(signature);
		pass = (qsc_hw_key_sign(key, message, sizeof(message), signature, &length) == qsc_hw_status_success) && pass;
		pass = (length == sizeof(expected) && qsc_memutils_are_equal(signature, expected, sizeof(expected)) == true) && pass;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Inject partial signature mutation then backend timeout.
 * \return True only if QSC removes all untrusted signature output on failure.
 */
static bool qsctest_hwmock_sign_partial_failure_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t signature[8U];
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		qsc_memutils_set_value(signature, sizeof(signature), 0xC7U);
		qsctest_hwmock_set_fault(&ctx, qsctest_hwmock_action_sign, qsc_hw_status_timeout, true);
		length = sizeof(signature);
		pass = qsc_hw_key_sign(key, NULL, 0U, signature, &length) == qsc_hw_status_timeout;
		pass = (qsc_memutils_zeroed(signature, sizeof(signature)) == true && ctx.fault_issued == true) && pass;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Inject a partial RNG output then timeout.
 * \return True when the entire failed output region is erased by QSC.
 */
static bool qsctest_hwmock_random_partial_failure_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_provider* provider;
	uint8_t output[16U];
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	pass = hwmock_test_provider(&ctx, &provider);

	if (pass == true)
	{
		qsc_memutils_set_value(output, sizeof(output), 0xC7U);
		qsctest_hwmock_set_fault(&ctx, qsctest_hwmock_action_random, qsc_hw_status_timeout, true);
		pass = qsc_hw_provider_random(provider, output, sizeof(output)) == qsc_hw_status_timeout &&
			qsc_memutils_zeroed(output, sizeof(output)) == true && ctx.fault_issued == true;
	}

	pass = hwmock_test_close(&provider, NULL) && pass;

	return pass;
}

/** \brief Require explicit authorization to export raw ECDH-derived test bytes.
 * \return True if policy denies agreement before invoking backend.
 */
static bool qsctest_hwmock_agreement_policy_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t peer[2U] = { 0x12U, 0x34U };
	uint8_t secret[8U] = { 0U };
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_agree, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		length = sizeof(secret);
		pass = qsc_hw_key_agree(key, peer, sizeof(peer), secret, &length) == qsc_hw_status_policy;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Exercise explicitly permitted synthetic agreement and sizing.
 * \return True for deterministic 8-byte result and no unexpected export.
 */
static bool qsctest_hwmock_agreement_success_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t peer[2U] = { 0x12U, 0x34U };
	uint8_t secret[8U];
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_agree, true);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		length = 0U;
		pass = qsc_hw_key_agree(key, peer, sizeof(peer), NULL, &length) == qsc_hw_status_buffer_too_small && length == sizeof(secret);
		length = sizeof(secret);
		pass = (qsc_hw_key_agree(key, peer, sizeof(peer), secret, &length) == qsc_hw_status_success) && pass;
		pass = (length == sizeof(secret) && secret[0U] == (uint8_t)(0xC0U ^ 0x12U)) && pass;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Inject a partly written derived secret on backend failure.
 * \return True if QSC securely clears every requested output byte.
 */
static bool qsctest_hwmock_agreement_partial_failure_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t peer[2U] = { 0x12U, 0x34U };
	uint8_t secret[8U];
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_agree, true);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		qsc_memutils_set_value(secret, sizeof(secret), 0xC7U);
		qsctest_hwmock_set_fault(&ctx, qsctest_hwmock_action_agree, qsc_hw_status_timeout, true);
		length = sizeof(secret);
		pass = qsc_hw_key_agree(key, peer, sizeof(peer), secret, &length) == qsc_hw_status_timeout &&
			qsc_memutils_zeroed(secret, sizeof(secret)) == true && ctx.fault_issued == true;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Obtain synthetic attestation bytes only under explicit usage policy.
 * \return True on correct size and deterministic envelope.
 */
static bool qsctest_hwmock_attest_success_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t challenge[2U] = { 0x11U, 0x22U };
	uint8_t evidence[8U];
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_attest, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		length = sizeof(evidence);
		pass = qsc_hw_key_attest(key, challenge, sizeof(challenge), evidence, &length) == qsc_hw_status_success &&
			length == sizeof(evidence) && evidence[0U] == (uint8_t)(0xA0U ^ challenge[0U]);
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Inject partial synthetic attestation then failure.
 * \return True when caller receives no partial unverified evidence bytes.
 */
static bool qsctest_hwmock_attest_partial_failure_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t challenge[2U] = { 0x11U, 0x22U };
	uint8_t evidence[8U];
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_attest, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		qsc_memutils_set_value(evidence, sizeof(evidence), 0xC7U);
		qsctest_hwmock_set_fault(&ctx, qsctest_hwmock_action_attest, qsc_hw_status_timeout, true);
		length = sizeof(evidence);
		pass = qsc_hw_key_attest(key, challenge, sizeof(challenge), evidence, &length) == qsc_hw_status_timeout &&
			qsc_memutils_zeroed(evidence, sizeof(evidence)) == true && ctx.fault_issued == true;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Verify synthetic public key retrieval and exact buffer sizing.
 * \return True when key bytes are readable without an invented private export.
 */
static bool qsctest_hwmock_public_bytes_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t output[4U];
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		length = 0U;
		pass = qsc_hw_key_public(key, NULL, &length) == qsc_hw_status_buffer_too_small && length == sizeof(output);
		length = sizeof(output);
		pass = (qsc_hw_key_public(key, output, &length) == qsc_hw_status_success) && pass;
		pass = (output[0U] == 4U && output[1U] == 1U && length == sizeof(output)) && pass;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Simulate an occupied token operation on an otherwise live signer.
 * \return True when busy is observable and subsequent retry succeeds.
 */
static bool qsctest_hwmock_operation_busy_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t signature[8U];
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		ctx.operation_active = true;
		length = sizeof(signature);
		pass = qsc_hw_key_sign(key, NULL, 0U, signature, &length) == qsc_hw_status_busy;
		ctx.operation_active = false;
		length = sizeof(signature);
		pass = (qsc_hw_key_sign(key, NULL, 0U, signature, &length) == qsc_hw_status_success) && pass;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Reject absent persistent object without inventing an arbitrary identity.
 * \return True for unsupported locator and no handle retention.
 */
static bool qsctest_hwmock_missing_key_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:99", &policy) == qsc_hw_status_unsupported &&
			key == NULL && ctx.sessions == 0U;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Reject absent/invalid inputs with explicit QSC argument errors.
 * \return True when an empty locator and null key result cannot reach the backend.
 */
static bool qsctest_hwmock_invalid_parameter_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "", &policy) == qsc_hw_status_invalid_parameter;
		pass = (qsc_hw_key_open(NULL, provider, "mock:010203:01", &policy) == qsc_hw_status_invalid_parameter) && pass;
		pass = (key == NULL && ctx.opens == 0U) && pass;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Fail securely when an operation loses authentication after key opening.
 * \return True if signing returns auth_required without hidden software fallback.
 */
static bool qsctest_hwmock_auth_loss_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_key_policy policy;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	uint8_t signature[8U];
	size_t length;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	hwmock_test_policy(&policy, qsc_hw_usage_sign, false);
	key = NULL;
	pass = hwmock_test_provider(&ctx, &provider) && hwmock_test_login(&ctx);

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:010203:01", &policy) == qsc_hw_status_success;
	}

	if (pass == true)
	{
		qsctest_hwmock_logout(&ctx);
		length = sizeof(signature);
		pass = qsc_hw_key_sign(key, NULL, 0U, signature, &length) == qsc_hw_status_auth_required && ctx.signatures == 0U;
	}

	pass = hwmock_test_close(&provider, &key) && pass;

	return pass;
}

/** \brief Test provider capability query error propagation and safe closure.
 * \return True when injected timeout is returned without corrupted lifetime.
 */
static bool qsctest_hwmock_capability_timeout_test(void)
{
	qsctest_hwmock_context ctx;
	qsc_hw_capabilities caps;
	qsc_hw_provider* provider;
	bool pass;

	qsctest_hwmock_initialize(&ctx);
	qsc_memutils_clear(&caps, sizeof(caps));
	caps.size = sizeof(caps);
	caps.version = QSC_HW_ABI_VERSION;
	pass = hwmock_test_provider(&ctx, &provider);
	qsctest_hwmock_set_fault(&ctx, qsctest_hwmock_action_capabilities, qsc_hw_status_timeout, false);

	if (pass == true)
	{
		pass = qsc_hw_provider_capabilities(provider, &caps) == qsc_hw_status_timeout && ctx.fault_issued == true;
	}

	pass = hwmock_test_close(&provider, NULL) && pass;

	return pass;
}

/** \brief Execute the mock-token qualification tests in deterministic source order.
 * \return True if all direct named tests pass, false after any failed test.
 */
bool qsctest_hwmock_run(void)
{
	bool passed;

	passed = true;

	if (qsctest_hwmock_capabilities_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 capability snapshot and serialization contract\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 capability snapshot and serialization contract: incorrect flags, limits, or provider cleanup\n");
		passed = false;
	}

	if (qsctest_hwmock_auth_required_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 authentication required before key open\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 authentication required before key open: unauthenticated key accepted\n");
		passed = false;
	}

	if (qsctest_hwmock_authenticated_open_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 nonexportable key open and release\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 nonexportable key open and release: incorrect custody metadata or lifetime\n");
		passed = false;
	}

	if (qsctest_hwmock_pin_lockout_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 PIN retry limit and lockout\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 PIN retry limit and lockout: wrong PIN counting or lockout bypass\n");
		passed = false;
	}

	if (qsctest_hwmock_logout_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 logout removes new-key authorization\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 logout removes new-key authorization: new key opened without session login\n");
		passed = false;
	}

	if (qsctest_hwmock_removal_stale_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 device removal and stale-key generation\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 device removal and stale-key generation: removed or stale key was usable\n");
		passed = false;
	}

	if (qsctest_hwmock_slot_renumber_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 persistent identity survives slot renumbering\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 persistent identity survives slot renumbering: locator bound to transient slot\n");
		passed = false;
	}

	if (qsctest_hwmock_token_replace_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 token replacement rejects prior identity\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 token replacement rejects prior identity: wrong serial allowed reuse\n");
		passed = false;
	}

	if (qsctest_hwmock_session_limit_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 session exhaustion and busy provider close\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 session exhaustion and busy provider close: session overrun or premature provider disposal\n");
		passed = false;
	}

	if (qsctest_hwmock_metadata_fault_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 malformed key metadata rejected and released\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 malformed key metadata rejected and released: invalid metadata accepted or backend handle leaked\n");
		passed = false;
	}

	if (qsctest_hwmock_software_fallback_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 hardware-required policy denies software custody\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 hardware-required policy denies software custody: implicit software downgrade\n");
		passed = false;
	}

	if (qsctest_hwmock_exportability_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 extractable private key rejected\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 extractable private key rejected: private-key policy ignored\n");
		passed = false;
	}

	if (qsctest_hwmock_capabilities_fault_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 unknown capabilities rejected\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 unknown capabilities rejected: unsupported mechanism advertised\n");
		passed = false;
	}

	if (qsctest_hwmock_open_timeout_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 key-open timeout propagation\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 key-open timeout propagation: timeout masked or key retained\n");
		passed = false;
	}

	if (qsctest_hwmock_generate_timeout_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 generation failure atomicity\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 generation failure atomicity: persistent test key generated on error\n");
		passed = false;
	}

	if (qsctest_hwmock_generate_success_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 protected synthetic key generation\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 protected synthetic key generation: new key missing or leaked\n");
		passed = false;
	}

	if (qsctest_hwmock_sign_roundtrip_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 deterministic signing and two-call sizing\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 deterministic signing and two-call sizing: signature, size, or buffer contract incorrect\n");
		passed = false;
	}

	if (qsctest_hwmock_sign_partial_failure_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 partial-signature fault output erasure\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 partial-signature fault output erasure: failed sign returned dirty output\n");
		passed = false;
	}

	if (qsctest_hwmock_random_partial_failure_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 failed RNG output secure erasure\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 failed RNG output secure erasure: partial random bytes left in output\n");
		passed = false;
	}

	if (qsctest_hwmock_agreement_policy_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 forbidden ECDH export denied\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 forbidden ECDH export denied: derived-secret policy ignored\n");
		passed = false;
	}

	if (qsctest_hwmock_agreement_success_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 explicitly permitted synthetic agreement\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 explicitly permitted synthetic agreement: wrong derived-secret length or bytes\n");
		passed = false;
	}

	if (qsctest_hwmock_agreement_partial_failure_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 failed agreement output secure erasure\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 failed agreement output secure erasure: partial derived secret retained\n");
		passed = false;
	}

	if (qsctest_hwmock_attest_success_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 synthetic attestation challenge response\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 synthetic attestation challenge response: wrong evidence bytes or length\n");
		passed = false;
	}

	if (qsctest_hwmock_attest_partial_failure_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 failed attestation output erasure\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 failed attestation output erasure: unverified partial evidence retained\n");
		passed = false;
	}

	if (qsctest_hwmock_public_bytes_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 public-key sizing and retrieval\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 public-key sizing and retrieval: public output bytes or length wrong\n");
		passed = false;
	}

	if (qsctest_hwmock_operation_busy_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 busy token reports error and permits retry\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 busy token reports error and permits retry: busy operation silently completed\n");
		passed = false;
	}

	if (qsctest_hwmock_missing_key_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 missing persistent identity rejected\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 missing persistent identity rejected: unexpected key reference created\n");
		passed = false;
	}

	if (qsctest_hwmock_invalid_parameter_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 invalid argument rejection\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 invalid argument rejection: invalid inputs reached backend\n");
		passed = false;
	}

	if (qsctest_hwmock_auth_loss_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 authentication loss during key lifetime\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 authentication loss during key lifetime: unauthorized signing accepted\n");
		passed = false;
	}

	if (qsctest_hwmock_capability_timeout_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage2 capability timeout and safe disposal\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage2 capability timeout and safe disposal: error hidden or provider leaked\n");
		passed = false;
	}

	return passed;
}

#endif /* QSC_HARDWARE_ENABLED */
