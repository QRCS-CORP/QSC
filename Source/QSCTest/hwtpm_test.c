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

#include "hwtpm_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_TPM_ENABLED)

#include "hwtpm.h"
#include "memutils.h"
#include "intutils.h"
#include "sha2.h"
#include "ecdsap256.h"
#include "stringutils.h"
#include <stdlib.h>
#include "testutils.h"

/** \brief Confirm TPM2-TSS initialization rejects null/invalid context input.
 * \return true when invalid handles and NULL contexts fail closed.
 */
static bool qsctest_hwtpm_reject_invalid(void)
{
	qsc_hw_tpm_context context = { 0U };
	bool valid;

	valid = (qsc_hw_tpm_initialize(NULL, NULL, UINT32_C(0x81000100), 0U, NULL, false) == qsc_hw_status_invalid_parameter);
	valid = valid && (qsc_hw_tpm_initialize(&context, NULL, 0U, 0U, NULL, false) == qsc_hw_status_invalid_parameter);
	valid = valid && (qsc_hw_tpm_initialize(&context, NULL, UINT32_C(0x01000000), 0U, NULL, false) == qsc_hw_status_invalid_parameter);
	valid = valid && (qsc_hw_tpm_initialize(&context, NULL, UINT32_C(0x81000100), UINT32_C(0x81000100), NULL, false) == qsc_hw_status_invalid_parameter);
	valid = valid && (context.native_state == NULL);
	qsctest_print_line(valid ? "[PASS] Stage8 invalid TPM handle/configuration rejected" : "[FAIL] Stage8 invalid TPM handle/configuration rejected");
	return valid;
}

/** \brief Confirm TPM compilation without vendor SDK does not advertise TPM capabilities.
 * \return true when uncompiled TSS backend fails unsupported without modifying output.
 */
static bool qsctest_hwtpm_disabled_backend(void)
{
	qsc_hw_tpm_context context = { 0U };
	qsc_hw_provider_ops ops;
	qsc_hw_status status;
	bool valid;

	qsc_memutils_clear(&ops, sizeof(ops));
	status = qsc_hw_tpm_get_operations(&ops);
	(void)context;

#if defined(QSC_SYSTEM_OS_LINUX) && defined(QSC_TPM2_TSS_ENABLED)
	valid = (status == qsc_hw_status_success && ops.open_key != NULL &&
		ops.sign != NULL && ops.attest != NULL && ops.get_capabilities != NULL);
#else
	valid = (status == qsc_hw_status_unsupported && ops.open_key == NULL &&
		ops.sign == NULL && ops.attest == NULL);
	valid = valid && (qsc_hw_tpm_initialize(&context, NULL, UINT32_C(0x81000100), 0U, NULL, false) == qsc_hw_status_unsupported);
#endif

	qsctest_print_line(valid ? "[PASS] Stage8 TPM2-TSS platform capability gating" : "[FAIL] Stage8 TPM2-TSS platform capability gating");
	return valid;
}

/** \brief Confirm NULL callback-table arguments cannot initialize a backend.
 * \return true only when NULL operations are rejected.
 */
static bool qsctest_hwtpm_null_operations(void)
{
	bool valid;

	valid = (qsc_hw_tpm_get_operations(NULL) == qsc_hw_status_invalid_parameter);
	qsctest_print_line(valid ? "[PASS] Stage8 null TPM operations rejected" : "[FAIL] Stage8 null TPM operations rejected");
	return valid;
}

/** \brief Confirm native backend attestation identity output requires valid pointers.
 * \return true when no AK identity can leak from NULL context or buffers.
 */
static bool qsctest_hwtpm_ak_output(void)
{
	qsc_hw_tpm_context context = { 0U };
	uint8_t publickey[64U] = { 0U };
	uint8_t name[34U] = { 0U };
	bool valid;

	valid = (qsc_hw_tpm_get_ak_identity(NULL, publickey, name) == qsc_hw_status_invalid_parameter);
	valid = valid && (qsc_hw_tpm_get_ak_identity(&context, NULL, name) == qsc_hw_status_invalid_parameter);
	valid = valid && (qsc_hw_tpm_get_ak_identity(&context, publickey, NULL) == qsc_hw_status_invalid_parameter);
	valid = valid && (qsc_hw_tpm_get_ak_identity(&context, publickey, name) == qsc_hw_status_unsupported);
	qsctest_print_line(valid ? "[PASS] Stage8 unavailable TPM AK identity not disclosed" : "[FAIL] Stage8 unavailable TPM AK identity not disclosed");
	return valid;
}

/** \brief Confirm TPM adapter disposal is safe and idempotent without native state.
 * \return true when no state remains after repeated calls.
 */
static bool qsctest_hwtpm_dispose(void)
{
	qsc_hw_tpm_context context = { 0U };
	bool valid;

	qsc_hw_tpm_dispose(NULL);
	qsc_hw_tpm_dispose(&context);
	qsc_hw_tpm_dispose(&context);
	valid = (context.native_state == NULL);
	qsctest_print_line(valid ? "[PASS] Stage8 empty TPM cleanup idempotent" : "[FAIL] Stage8 empty TPM cleanup idempotent");
	return valid;
}

#if defined(QSC_SYSTEM_OS_LINUX) && defined(QSC_TPM2_TSS_ENABLED)

/** \brief Run a read-only, pre-provisioned physical TPM P-256 identity test.
 * \return true only for a real TPM key that signs a digest verifiable by QSC.
 * \note Requires QSC_TEST_TPM_IDENTITY_HANDLE exactly eight hex digits and
 * QSC_TEST_TPM_PHYSICAL_CONFIRMED=YES after an independent physical TPM check.
 * The environment variable QSC_TEST_TPM_TCTI selects installed TCTI transport.
 * No TPM provisioning, hierarchy ownership changes or persistent deletion occur.
 */
static bool qsctest_hwtpm_native_p256(void)
{
	qsc_hw_tpm_context context = { 0U };
	qsc_hw_provider_ops operations;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	qsc_hw_key_policy policy;
	uint8_t bytes[4U] = { 0U };
	uint8_t publickey[65U] = { 0U };
	uint8_t digest[32U] = { 0U };
	uint8_t signedmsg[96U] = { 0U };
	uint8_t recovered[32U] = { 0U };
	const uint8_t message[] = "QSC Stage 8 TPM physical signing test";
	const char* identity;
	const char* confirmed;
	const char* tcti;
	char locator[14U] = { 0 };
	size_t recoveredlen;
	size_t publiclen;
	size_t siglen;
	uint32_t handle;
	qsc_hw_status status;
	bool valid;

	identity = getenv("QSC_TEST_TPM_IDENTITY_HANDLE");
	confirmed = getenv("QSC_TEST_TPM_PHYSICAL_CONFIRMED");
	tcti = getenv("QSC_TEST_TPM_TCTI");
	handle = 0U;
	provider = NULL;
	key = NULL;
	valid = false;

	if (identity != NULL && confirmed != NULL &&
		qsc_stringutils_string_size(confirmed) == 3U &&
		qsc_stringutils_compare_strings(confirmed, "YES", 3U) == true &&
		qsc_stringutils_string_size(identity) == 8U &&
		qsc_intutils_hex_to_bin_checked(identity, 8U, bytes, sizeof(bytes)) == true)
	{
		handle = qsc_intutils_be8to32(bytes);
		status = qsc_hw_tpm_initialize(&context, tcti, handle, 0U, NULL, true);

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_tpm_get_operations(&operations);
		}

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_provider_open(&provider, &operations, &context);
		}

		if (status == qsc_hw_status_success)
		{
			qsc_memutils_clear(&policy, sizeof(policy));
			policy.size = sizeof(policy);
			policy.version = QSC_HW_ABI_VERSION;
			policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
			policy.usage = qsc_hw_usage_sign;
			policy.require_hardware = true;
			locator[0U] = 't';
			locator[1U] = 'p';
			locator[2U] = 'm';
			locator[3U] = '2';
			locator[4U] = ':';
			qsc_intutils_bin_to_hex(bytes, locator + 5U, sizeof(bytes));
			status = qsc_hw_key_open(&key, provider, locator, &policy);
		}

		if (status == qsc_hw_status_success)
		{
			publiclen = sizeof(publickey);
			status = qsc_hw_key_public(key, publickey, &publiclen);
		}

		if (status == qsc_hw_status_success && publiclen == 65U && publickey[0U] == 0x04U)
		{
			siglen = 64U;
			qsc_sha256_compute(digest, message, sizeof(message) - 1U);
			status = qsc_hw_key_sign(key, digest, sizeof(digest), signedmsg, &siglen);

			if (status == qsc_hw_status_success && siglen == 64U)
			{
				qsc_memutils_copy(signedmsg + 64U, digest, 32U);
				recoveredlen = 0U;
				valid = qsc_ecdsap256_verify_prehashed(recovered, &recoveredlen,
					signedmsg, sizeof(signedmsg), publickey + 1U, digest, sizeof(digest));
				valid = valid && (recoveredlen == 32U) && qsc_memutils_are_equal(recovered, digest, 32U);
			}
		}

		if (key != NULL)
		{
			(void)qsc_hw_key_release(&key);
		}
		if (provider != NULL)
		{
			(void)qsc_hw_provider_close(&provider);
		}
		qsc_hw_tpm_dispose(&context);
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));
	qsc_memutils_secure_erase(signedmsg, sizeof(signedmsg));
	qsctest_print_line(valid ? "[PASS] Stage8 physical TPM ECDSA P-256 signing" :
		"[FAIL] Stage8 physical TPM ECDSA P-256 signing");
	return valid;
}

#endif /* Linux with TPM2-TSS */

bool qsctest_hwtpm_run(void)
{
	bool valid;

	valid = true;
	valid = qsctest_hwtpm_reject_invalid() && valid;
	valid = qsctest_hwtpm_disabled_backend() && valid;
	valid = qsctest_hwtpm_null_operations() && valid;
	valid = qsctest_hwtpm_ak_output() && valid;
	valid = qsctest_hwtpm_dispose() && valid;

#if defined(QSC_SYSTEM_OS_LINUX) && defined(QSC_TPM2_TSS_ENABLED)
	if (getenv("QSC_TEST_TPM_IDENTITY_HANDLE") != NULL)
	{
		valid = qsctest_hwtpm_native_p256() && valid;
	}
	else
	{
		qsctest_print_line("[SKIP] Stage8 physical TPM test requires provisioned TPM and explicit opt-in");
	}
#endif
	return valid;
}

#endif
