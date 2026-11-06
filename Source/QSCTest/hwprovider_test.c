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

#if defined(QSC_HARDWARE_ENABLED)

#include "hwprovider.h"
#include "memutils.h"
#include "testutils.h"

/** \struct hwtest_context
 * \brief Noncryptographic test-double state; owns no private key bytes.
 */
typedef struct hwtest_context
{
	size_t releases; /**< Number of backend transient releases. */
	size_t signs; /**< Number of backend signing callbacks. */
	size_t closes; /**< Number of backend close notifications. */
	bool software; /**< Simulate a software rather than hardware key. */
	bool extractable; /**< Simulate a backend extractable key. */
	bool invalid_metadata; /**< Force a version mismatch in returned key metadata. */
} hwtest_context;

/** \brief Populate requested key metadata from a deterministic test context.
 * \param ctx Live context owned by test function.
 * \param info Output metadata from provider callback.
 * \note Local deterministic state, no cryptography performed.
 */
static void hwtest_fill_info(const hwtest_context* ctx, qsc_hw_key_info* info)
{
	info->size = sizeof(qsc_hw_key_info);
	info->version = (ctx->invalid_metadata == true) ? 0U : QSC_HW_ABI_VERSION;
	info->algorithm = qsc_hw_algorithm_ecdsa_p256;
	info->usage = qsc_hw_usage_sign;
	info->custody = (ctx->software == true) ? qsc_hw_custody_software : qsc_hw_custody_hardware_nonexportable;
	info->extractable = ctx->extractable;
}

/** \brief Report capabilities of the deterministic mock.
 * \param context Non-NULL hwtest_context pointer.
 * \param capabilities Caller-allocated output with size/version.
 * \return Success; caller validates struct/version before this callback.
 */
static qsc_hw_status hwtest_capabilities(void* context, qsc_hw_capabilities* capabilities)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && capabilities != NULL)
	{
		capabilities->flags = qsc_hw_capability_key_open | qsc_hw_capability_sign | qsc_hw_capability_public_key | qsc_hw_capability_generate;
		capabilities->max_sessions = 1U;
		capabilities->thread_safe = false;
		capabilities->requires_serialization = true;
		capabilities->operation_can_block = false;
		capabilities->supports_cancel = false;
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Noncryptographic open callback; returns the caller-owned context as mock key.
 * \param context Live mock state.
 * \param locator Required nonempty mock locator.
 * \param key Output transient mock identity.
 * \param info Output key metadata.
 * \return Success for a nonempty locator.
 */
static qsc_hw_status hwtest_open_key(void* context, const char* locator, void** key, qsc_hw_key_info* info)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && locator != NULL && locator[0U] != '\0' && key != NULL && info != NULL)
	{
		*key = context;
		hwtest_fill_info((const hwtest_context*)context, info);
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Generate a mock identity without real cryptography or persistent state.
 * \param context Caller-owned mock state.
 * \param policy Requested key policy; validated in public wrapper.
 * \param key Output non-NULL transient test handle.
 * \param info Output actual mock key metadata.
 * \return Success on valid arguments.
 */
static qsc_hw_status hwtest_generate_key(void* context, const qsc_hw_key_policy* policy, void** key, qsc_hw_key_info* info)
{
    qsc_hw_status status;

    status = qsc_hw_status_invalid_parameter;

    if (context != NULL && policy != NULL && key != NULL && info != NULL)
    {
        *key = context;
        hwtest_fill_info((const hwtest_context*)context, info);
        status = qsc_hw_status_success;
    }

    return status;
}

/** \brief Return three deterministic public bytes for size/copy testing.
 * \param context Caller-owned mock state.
 * \param key Key reference equal to context.
 * \param output Output bytes or NULL to query required length.
 * \param outputlen In/out buffer capacity and public data byte count.
 * \return Success or buffer_too_small, without partial output.
 */
static qsc_hw_status hwtest_public_key(void* context, void* key, uint8_t* output, size_t* outputlen)
{
    qsc_hw_status status;

    status = qsc_hw_status_invalid_parameter;

    if (context != NULL && key == context && outputlen != NULL)
    {
        status = qsc_hw_status_buffer_too_small;

        if (output != NULL && *outputlen >= 3U)
        {
            output[0U] = 0x11U;
            output[1U] = 0x22U;
            output[2U] = 0x33U;
            status = qsc_hw_status_success;
        }

        *outputlen = 3U;
    }

    return status;
}

/** \brief Count key releases in test context; does not free caller state.
 * \param context Caller-owned mock state.
 * \param key Expected identity matching context, otherwise ignored.
 */
static void hwtest_release_key(void* context, void* key)
{
	hwtest_context* ctx;

	ctx = (hwtest_context*)context;

	if (ctx != NULL && key == context)
	{
		ctx->releases += 1U;
	}
}

/** \brief Count provider close notifications; does not free caller state.
 * \param context Caller-owned mock state.
 */
static void hwtest_dispose(void* context)
{
	hwtest_context* ctx;

	ctx = (hwtest_context*)context;

	if (ctx != NULL)
	{
		ctx->closes += 1U;
	}
}

/** \brief Produce fixed bytes solely to test callback size/error forwarding.
 * \param context Caller-owned mock state.
 * \param key Mock identity, equal to context.
 * \param algorithm Must equal ECDSA P-256.
 * \param message Caller bytes, ignored in deterministic mock.
 * \param msglen Input byte count.
 * \param signature Output four test bytes, or NULL for size query.
 * \param signaturelen In/out buffer size.
 * \return Success, buffer_too_small or invalid_parameter.
 * \note NOT cryptographic signing and not suitable for actual TLS or HSM use.
 */
static qsc_hw_status hwtest_sign(void* context, void* key, qsc_hw_algorithm algorithm, const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen)
{
	hwtest_context* ctx;
	qsc_hw_status status;

	ctx = (hwtest_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (ctx != NULL && key == context && algorithm == qsc_hw_algorithm_ecdsa_p256 && (message != NULL || msglen == 0U) && signaturelen != NULL)
	{
		ctx->signs += 1U;
		status = qsc_hw_status_buffer_too_small;

		if (signature != NULL && *signaturelen >= 4U)
		{
			signature[0U] = 0x21U;
			signature[1U] = 0x43U;
			signature[2U] = 0x65U;
			signature[3U] = 0x87U;
			status = qsc_hw_status_success;
		}

		*signaturelen = 4U;
	}

	return status;
}

/** \brief Prepare the mock's ABI descriptor and mandatory callback set.
 * \param ops Caller-owned descriptor output, valid throughout provider_open.
 * \note Safe for independent test invocations.
 */
static void hwtest_initialize_ops(qsc_hw_provider_ops* ops)
{
	qsc_memutils_clear(ops, sizeof(qsc_hw_provider_ops));
	ops->size = sizeof(qsc_hw_provider_ops);
	ops->version = QSC_HW_ABI_VERSION;
	ops->get_capabilities = hwtest_capabilities;
	ops->release_key = hwtest_release_key;
	ops->dispose = hwtest_dispose;
	ops->open_key = hwtest_open_key;
	ops->generate_key = hwtest_generate_key;
	ops->public_key = hwtest_public_key;
	ops->sign = hwtest_sign;
}

/** \brief Construct a protected P-256 signing request with no software downgrade.
 * \param policy Caller policy output.
 */
static void hwtest_initialize_policy(qsc_hw_key_policy* policy)
{
	qsc_memutils_clear(policy, sizeof(qsc_hw_key_policy));
	policy->size = sizeof(qsc_hw_key_policy);
	policy->version = QSC_HW_ABI_VERSION;
	policy->algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy->usage = qsc_hw_usage_sign;
	policy->require_hardware = true;
}

/** \brief Reject ABI version mismatch before backend initialization.
 * \return True if version failure returns exact status and NULL provider.
 */
static bool qsctest_hwprovider_version_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_provider* provider;
	bool pass;

	hwtest_initialize_ops(&ops);
	ops.version = 2U;
	provider = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_version && provider == NULL && ctx.closes == 0U;

	return pass;
}

/** \brief Validate roundtrip metadata and backend capability reporting.
 * \return True on successful capability query and disposal.
 */
static bool qsctest_hwprovider_capabilities_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_capabilities caps;
	qsc_hw_provider* provider;
	bool pass;

	hwtest_initialize_ops(&ops);
	qsc_memutils_clear(&caps, sizeof(caps));
	caps.size = sizeof(caps);
	caps.version = QSC_HW_ABI_VERSION;
	provider = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

	if (pass == true)
	{
		pass = qsc_hw_provider_capabilities(provider, &caps) == qsc_hw_status_success &&
			caps.flags == (qsc_hw_capability_key_open | qsc_hw_capability_sign | qsc_hw_capability_public_key | qsc_hw_capability_generate) &&
			caps.requires_serialization == true;
		pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && ctx.closes == 1U && pass;
	}

	return pass;
}

/** \brief Verify hardware-required policy refuses software custody.
 * \return True if policy rejection frees transient backend handle and never creates keyref.
 */
static bool qsctest_hwprovider_custody_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_key_policy policy;
	qsc_hw_keyref* key;
	qsc_hw_provider* provider;
	bool pass;

	ctx.software = true;
	hwtest_initialize_ops(&ops);
	hwtest_initialize_policy(&policy);
	provider = NULL;
	key = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:test", &policy) == qsc_hw_status_policy && key == NULL && ctx.releases == 1U;
		pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
	}

	return pass;
}

/** \brief Verify nonextractable policy rejects backend extractability mismatch.
 * \return True when mismatch is rejected and backend handle released.
 */
static bool qsctest_hwprovider_export_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_key_policy policy;
	qsc_hw_keyref* key;
	qsc_hw_provider* provider;
	bool pass;

	ctx.extractable = true;
	hwtest_initialize_ops(&ops);
	hwtest_initialize_policy(&policy);
	provider = NULL;
	key = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:test", &policy) == qsc_hw_status_policy && key == NULL && ctx.releases == 1U;
		pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
	}

	return pass;
}

/** \brief Check output-length query, buffer rejection and exact mock signature bytes.
 * \return True if all stages satisfy output contracts and close cleanly.
 */
static bool qsctest_hwprovider_sign_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_key_policy policy;
	qsc_hw_key_info info;
	qsc_hw_keyref* key;
	qsc_hw_provider* provider;
	uint8_t msg[2U] = { 0x01U, 0x02U };
	uint8_t sig[5U] = { 0U };
	size_t siglen;
	bool pass;

	hwtest_initialize_ops(&ops);
	hwtest_initialize_policy(&policy);
	provider = NULL;
	key = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:test", &policy) == qsc_hw_status_success;

		if (pass == true)
		{
			qsc_memutils_clear(&info, sizeof(info));
			info.size = sizeof(info);
			info.version = QSC_HW_ABI_VERSION;
			pass = qsc_hw_key_get_info(key, &info) == qsc_hw_status_success && info.extractable == false;
			siglen = 0U;
			pass = qsc_hw_key_sign(key, msg, sizeof(msg), NULL, &siglen) == qsc_hw_status_buffer_too_small && siglen == 4U && pass;
			siglen = 2U;
			pass = qsc_hw_key_sign(key, msg, sizeof(msg), sig, &siglen) == qsc_hw_status_buffer_too_small && siglen == 4U && pass;
			siglen = sizeof(sig);
			pass = qsc_hw_key_sign(key, msg, sizeof(msg), sig, &siglen) == qsc_hw_status_success && siglen == 4U && sig[0U] == 0x21U && sig[3U] == 0x87U && sig[4U] == 0U && pass;
			pass = qsc_hw_key_release(&key) == qsc_hw_status_success && key == NULL && ctx.releases == 1U && pass;
		}

		pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
	}

	return pass;
}

/** \brief Verify provider cannot close while an outstanding keyref exists.
 * \return True if busy status preserves provider until key release.
 */
static bool qsctest_hwprovider_busy_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_key_policy policy;
	qsc_hw_keyref* key;
	qsc_hw_provider* provider;
	bool pass;

	hwtest_initialize_ops(&ops);
	hwtest_initialize_policy(&policy);
	provider = NULL;
	key = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:test", &policy) == qsc_hw_status_success;

		if (pass == true)
		{
			pass = qsc_hw_provider_close(&provider) == qsc_hw_status_busy && provider != NULL && ctx.closes == 0U;
			pass = qsc_hw_key_release(&key) == qsc_hw_status_success && pass;
		}

		pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && provider == NULL && ctx.closes == 1U && pass;
	}

	return pass;
}

/** \brief Invalidate open key references after reconnect without freeing wrong keys.
 * \return True if signing fails stale_key, then transient reference can be released.
 */
static bool qsctest_hwprovider_stale_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_key_policy policy;
	qsc_hw_keyref* key;
	qsc_hw_provider* provider;
	uint8_t sig[4U] = { 0U };
	size_t siglen;
	bool pass;

	hwtest_initialize_ops(&ops);
	hwtest_initialize_policy(&policy);
	provider = NULL;
	key = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:test", &policy) == qsc_hw_status_success;

		if (pass == true)
		{
			pass = qsc_hw_provider_invalidate(provider) == qsc_hw_status_success;
			siglen = sizeof(sig);
			pass = qsc_hw_key_sign(key, sig, sizeof(sig), sig, &siglen) == qsc_hw_status_stale_key && ctx.signs == 0U && pass;
			pass = qsc_hw_key_release(&key) == qsc_hw_status_success && pass;
		}

		pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
	}

	return pass;
}

/** \brief Ensure unsupported RNG/attestation/derive never invoke a different backend operation.
 * \return True for explicit unsupported/policy results without calls to the signer.
 */
static bool qsctest_hwprovider_unsupported_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_key_policy policy;
	qsc_hw_keyref* key;
	qsc_hw_provider* provider;
	uint8_t buffer[8U] = { 0U };
	size_t length;
	bool pass;

	hwtest_initialize_ops(&ops);
	hwtest_initialize_policy(&policy);
	provider = NULL;
	key = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

	if (pass == true)
	{
		pass = qsc_hw_provider_random(provider, buffer, sizeof(buffer)) == qsc_hw_status_unsupported;
		pass = qsc_hw_key_open(&key, provider, "mock:test", &policy) == qsc_hw_status_success && pass;

		if (key != NULL)
		{
			length = sizeof(buffer);
			pass = qsc_hw_key_agree(key, buffer, sizeof(buffer), buffer, &length) == qsc_hw_status_policy && pass;
			length = sizeof(buffer);
			pass = qsc_hw_key_attest(key, buffer, sizeof(buffer), buffer, &length) == qsc_hw_status_policy && pass;
			pass = qsc_hw_key_release(&key) == qsc_hw_status_success && pass;
		}

		pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && ctx.signs == 0U && pass;
	}

	return pass;
}

/** \brief Validate malformed backend metadata cannot bypass policy.
 * \return True when invalid version is rejected with backend handle cleanup.
 */
static bool qsctest_hwprovider_metadata_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_key_policy policy;
	qsc_hw_keyref* key;
	qsc_hw_provider* provider;
	bool pass;

	ctx.invalid_metadata = true;
	hwtest_initialize_ops(&ops);
	hwtest_initialize_policy(&policy);
	provider = NULL;
	key = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

	if (pass == true)
	{
		pass = qsc_hw_key_open(&key, provider, "mock:test", &policy) == qsc_hw_status_policy && ctx.releases == 1U;
		pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
	}

	return pass;
}

/** \brief Test public-key retrieval and two-call sizing with no private bytes.
 * \return True when output sizes and public bytes match deterministic fixture.
 */
static bool qsctest_hwprovider_public_test(void)
{
    hwtest_context ctx = { 0U };
    qsc_hw_provider_ops ops;
    qsc_hw_key_policy policy;
    qsc_hw_keyref* key;
    qsc_hw_provider* provider;
    uint8_t publickey[4U] = { 0U };
    size_t length;
    bool pass;

    hwtest_initialize_ops(&ops);
    hwtest_initialize_policy(&policy);
    provider = NULL;
    key = NULL;
    pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

    if (pass == true)
    {
        pass = qsc_hw_key_open(&key, provider, "mock:test", &policy) == qsc_hw_status_success;

        if (key != NULL)
        {
            length = 0U;
            pass = qsc_hw_key_public(key, NULL, &length) == qsc_hw_status_buffer_too_small && length == 3U && pass;
            length = sizeof(publickey);
            pass = qsc_hw_key_public(key, publickey, &length) == qsc_hw_status_success && length == 3U && publickey[0U] == 0x11U && publickey[2U] == 0x33U && publickey[3U] == 0U && pass;
            pass = qsc_hw_key_release(&key) == qsc_hw_status_success && pass;
        }

        pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
    }

    return pass;
}

/** \brief Test generated key policy and cleanup on software residency mismatch.
 * \return True when hardware generation succeeds and software generation is rejected.
 */
static bool qsctest_hwprovider_generate_test(void)
{
    hwtest_context ctx = { 0U };
    qsc_hw_provider_ops ops;
    qsc_hw_key_policy policy;
    qsc_hw_keyref* key;
    qsc_hw_provider* provider;
    bool pass;

    hwtest_initialize_ops(&ops);
    hwtest_initialize_policy(&policy);
    provider = NULL;
    key = NULL;
    pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

    if (pass == true)
    {
        pass = qsc_hw_key_generate(&key, provider, &policy) == qsc_hw_status_success;

        if (key != NULL)
        {
            pass = qsc_hw_key_release(&key) == qsc_hw_status_success && pass;
        }

        ctx.software = true;
        pass = qsc_hw_key_generate(&key, provider, &policy) == qsc_hw_status_policy && key == NULL && ctx.releases == 2U && pass;
        pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
    }

    return pass;
}

/** \brief Test capability claims are checked against installed callback table.
 * \return True when a lying backend is rejected without dereferencing a NULL callback.
 */
static bool qsctest_hwprovider_capability_mismatch_test(void)
{
    hwtest_context ctx = { 0U };
    qsc_hw_provider_ops ops;
    qsc_hw_capabilities caps;
    qsc_hw_provider* provider;
    bool pass;

    hwtest_initialize_ops(&ops);
    ops.public_key = NULL;
    qsc_memutils_clear(&caps, sizeof(caps));
    caps.size = sizeof(caps);
    caps.version = QSC_HW_ABI_VERSION;
    provider = NULL;
    pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

    if (pass == true)
    {
        pass = qsc_hw_provider_capabilities(provider, &caps) == qsc_hw_status_internal;
        pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
    }

    return pass;
}

/** \brief Verify explicit permitted software custody does not bypass hardware-required policy.
 * \return True when software key is accepted only with caller-authorized fallback.
 */
static bool qsctest_hwprovider_fallback_test(void)
{
    hwtest_context ctx = { 0U };
    qsc_hw_provider_ops ops;
    qsc_hw_key_policy policy;
    qsc_hw_keyref* key;
    qsc_hw_provider* provider;
    bool pass;

    ctx.software = true;
    hwtest_initialize_ops(&ops);
    hwtest_initialize_policy(&policy);
    policy.require_hardware = false;
    policy.allow_software_fallback = true;
    provider = NULL;
    key = NULL;
    pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

    if (pass == true)
    {
        pass = qsc_hw_key_open(&key, provider, "mock:test", &policy) == qsc_hw_status_success;

        if (key != NULL)
        {
            pass = qsc_hw_key_release(&key) == qsc_hw_status_success && pass;
        }

        pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
    }

    return pass;
}

/** \brief Simulate RNG failure after partial output has been written.
 * \param context Caller-owned context, may be NULL for deterministic failure.
 * \param output Caller-owned buffer, at least length bytes if length is nonzero.
 * \param length Requested byte count.
 * \return Simulated device_removed error to exercise fail-closed output clearing.
 */
static qsc_hw_status hwtest_random_failure(void* context, uint8_t* output, size_t length)
{
	qsc_hw_status status;

	(void)context;
	status = qsc_hw_status_device_removed;

	if (output != NULL && length > 0U)
	{
		output[0U] = 0xACU;
	}

	return status;
}

/** \brief Ensure failed backend RNG calls do not expose partial random output.
 * \return True when all output bytes are erased and error is propagated.
 */
static bool qsctest_hwprovider_rng_failure_test(void)
{
	hwtest_context ctx = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_provider* provider;
	uint8_t buffer[4U] = { 0xFFU, 0xFFU, 0xFFU, 0xFFU };
	uint8_t zero[4U] = { 0U };
	bool pass;

	hwtest_initialize_ops(&ops);
	ops.random = hwtest_random_failure;
	provider = NULL;
	pass = qsc_hw_provider_open(&provider, &ops, &ctx) == qsc_hw_status_success;

	if (pass == true)
	{
		pass = qsc_hw_provider_random(provider, buffer, sizeof(buffer)) == qsc_hw_status_device_removed;
		pass = qsc_memutils_are_equal(buffer, zero, sizeof(buffer)) == true && pass;
		pass = qsc_hw_provider_close(&provider) == qsc_hw_status_success && pass;
	}

	return pass;
}

/** \brief Run named Stage 1 checks as direct calls, not a dispatch loop.
 * \return True only when each separately named contract test passes.
 */
bool qsctest_hwprovider_run(void)
{
	bool passed;

	passed = true;

	if (qsctest_hwprovider_version_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 ABI version rejection\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 ABI version rejection: wrong status or leaked wrapper\n");
		passed = false;
	}

	if (qsctest_hwprovider_capabilities_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 capability report\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 capability report: bad flags, state or lifecycle\n");
		passed = false;
	}

	if (qsctest_hwprovider_custody_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 software downgrade prevention\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 software downgrade prevention: rejected key retained or permitted\n");
		passed = false;
	}

	if (qsctest_hwprovider_export_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 private-key export policy\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 private-key export policy: extractable key accepted\n");
		passed = false;
	}

	if (qsctest_hwprovider_sign_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 signed-output contract\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 signed-output contract: incorrect sizes, metadata or bytes\n");
		passed = false;
	}

	if (qsctest_hwprovider_busy_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 provider close while busy\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 provider close while busy: active key invalidated or leaked\n");
		passed = false;
	}

	if (qsctest_hwprovider_stale_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 stale-key generation rejection\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 stale-key generation rejection: stale handle accepted\n");
		passed = false;
	}

	if (qsctest_hwprovider_unsupported_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 unsupported operation isolation\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 unsupported operation isolation: implicit service fallback\n");
		passed = false;
	}

	if (qsctest_hwprovider_metadata_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 backend metadata validation\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 backend metadata validation: mismatched ABI accepted\n");
		passed = false;
	}

    if (qsctest_hwprovider_public_test() == true)
    {
        qsctest_print_safe("[PASS] HW Stage1 public-key retrieval\n");
    }
    else
    {
        qsctest_print_safe("[FAIL] HW Stage1 public-key retrieval: wrong public bytes or lengths\n");
        passed = false;
    }

    if (qsctest_hwprovider_generate_test() == true)
    {
        qsctest_print_safe("[PASS] HW Stage1 provider key generation policy\n");
    }
    else
    {
        qsctest_print_safe("[FAIL] HW Stage1 provider key generation policy: missing enforcement or cleanup\n");
        passed = false;
    }

    if (qsctest_hwprovider_capability_mismatch_test() == true)
    {
        qsctest_print_safe("[PASS] HW Stage1 capability-to-callback consistency\n");
    }
    else
    {
        qsctest_print_safe("[FAIL] HW Stage1 capability-to-callback consistency: unsupported callback advertised\n");
        passed = false;
    }

    if (qsctest_hwprovider_fallback_test() == true)
    {
        qsctest_print_safe("[PASS] HW Stage1 explicitly authorized software custody\n");
    }
    else
    {
        qsctest_print_safe("[FAIL] HW Stage1 explicitly authorized software custody: incorrect custody selection\n");
        passed = false;
    }

	if (qsctest_hwprovider_rng_failure_test() == true)
	{
		qsctest_print_safe("[PASS] HW Stage1 RNG failure output erasure\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] HW Stage1 RNG failure output erasure: leaked output or incorrect error\n");
		passed = false;
	}

	return passed;
}

#endif /* QSC_HARDWARE_ENABLED */
