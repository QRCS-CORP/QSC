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

#include "hwncrypt_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_NCRYPT_ENABLED)

#include "hwncrypt.h"
#include "memutils.h"
#include "qsctestcommon.h"
#include "testutils.h"
#include "sha2.h"
#include "ecdsap256.h"

#include <stdlib.h>

/** \brief Confirm that NCrypt initialization rejects invalid pointers.
 * \return True only when null arguments are rejected without allocating state.
 */
static bool qsctest_hwncrypt_invalid_arguments(void)
{
	qsc_hw_ncrypt_context context = { 0 };
	bool valid;

	valid = (qsc_hw_ncrypt_initialize(NULL, "stage7", false) == qsc_hw_status_invalid_parameter);
	valid = valid && (qsc_hw_ncrypt_initialize(&context, NULL, false) == qsc_hw_status_invalid_parameter);
	valid = valid && (context.native_state == NULL);
	qsctest_print_line(valid ? "[PASS] Stage7 NCrypt null arguments rejected" : "[FAIL] Stage7 NCrypt null arguments rejected");

	return valid;
}

/** \brief Confirm an empty persistent key name is never accepted.
 * \return True on policy or parameter rejection, with no context initialized.
 */
static bool qsctest_hwncrypt_empty_name(void)
{
	qsc_hw_ncrypt_context context = { 0 };
	qsc_hw_status status;
	bool valid;

	status = qsc_hw_ncrypt_initialize(&context, "", false);
	valid = (status == qsc_hw_status_policy || status == qsc_hw_status_invalid_parameter);
	valid = valid && (context.native_state == NULL);
	qsctest_print_line(valid ? "[PASS] Stage7 NCrypt empty identity name rejected" : "[FAIL] Stage7 NCrypt empty identity name rejected");

	return valid;
}

/** \brief Ensure a missing context never advertises a hardware signing algorithm.
 * \return True if none of the supported named curves is advertised without provider state.
 */
static bool qsctest_hwncrypt_uninitialized_capabilities(void)
{
	qsc_hw_ncrypt_context context = { 0 };
	bool valid;

	valid = (qsc_hw_ncrypt_algorithm_available(&context, qsc_hw_algorithm_ecdsa_p256) == false);
	valid = valid && (qsc_hw_ncrypt_algorithm_available(&context, qsc_hw_algorithm_ecdsa_p384) == false);
	valid = valid && (qsc_hw_ncrypt_algorithm_available(&context, qsc_hw_algorithm_ecdsa_p521) == false);
	valid = valid && (qsc_hw_ncrypt_algorithm_available(NULL, qsc_hw_algorithm_ecdsa_p256) == false);
	qsctest_print_line(valid ? "[PASS] Stage7 NCrypt uninitialized capabilities absent" : "[FAIL] Stage7 NCrypt uninitialized capabilities absent");

	return valid;
}

/** \brief Confirm operation-table pointer validation.
 * \return True only when a NULL descriptor is refused.
 */
static bool qsctest_hwncrypt_null_operations(void)
{
	bool valid;

	valid = (qsc_hw_ncrypt_get_operations(NULL) == qsc_hw_status_invalid_parameter);
	qsctest_print_line(valid ? "[PASS] Stage7 NCrypt NULL operations table rejected" : "[FAIL] Stage7 NCrypt NULL operations table rejected");

	return valid;
}

/** \brief Confirm operations descriptor feature gating by target platform.
 * \return True if Windows exposes valid callback contract and non-Windows has no backend.
 */
static bool qsctest_hwncrypt_operations_gating(void)
{
	qsc_hw_provider_ops operations;
	qsc_hw_status status;
	bool valid;

	qsc_memutils_clear(&operations, sizeof(operations));
	status = qsc_hw_ncrypt_get_operations(&operations);

#if defined(_WIN32)
	valid = (status == qsc_hw_status_success && operations.size == sizeof(operations) &&
		operations.version == QSC_HW_ABI_VERSION && operations.open_key != NULL &&
		operations.generate_key != NULL && operations.sign != NULL && operations.agree == NULL &&
		operations.attest == NULL && operations.random == NULL);
#else
	valid = (status == qsc_hw_status_unsupported && operations.open_key == NULL && operations.sign == NULL);
#endif
	qsctest_print_line(valid ? "[PASS] Stage7 NCrypt platform-gated operations" : "[FAIL] Stage7 NCrypt platform-gated operations");

	return valid;
}

/** \brief Verify backend state disposal is idempotent for an uninitialized context.
 * \return True if repeated calls leave a NULL native-state pointer.
 */
static bool qsctest_hwncrypt_empty_dispose(void)
{
	qsc_hw_ncrypt_context context = { 0 };
	bool valid;

	qsc_hw_ncrypt_dispose(&context);
	qsc_hw_ncrypt_dispose(&context);
	qsc_hw_ncrypt_dispose(NULL);
	valid = (context.native_state == NULL);
	qsctest_print_line(valid ? "[PASS] Stage7 NCrypt empty disposal idempotent" : "[FAIL] Stage7 NCrypt empty disposal idempotent");

	return valid;
}

/** \brief Verify the algorithm selector refuses non-ECDSA schemes.
 * \return True if RSA/EdDSA/PQC are not incorrectly advertised.
 */
static bool qsctest_hwncrypt_unsupported_schemes(void)
{
	qsc_hw_ncrypt_context context = { 0 };
	bool valid;

	valid = (qsc_hw_ncrypt_algorithm_available(&context, qsc_hw_algorithm_ml_dsa_44) == false);
	valid = valid && (qsc_hw_ncrypt_algorithm_available(&context, qsc_hw_algorithm_ecdh_p256) == false);
	valid = valid && (qsc_hw_ncrypt_algorithm_available(&context, qsc_hw_algorithm_eddsa_25519) == false);
	qsctest_print_line(valid ? "[PASS] Stage7 NCrypt unsupported algorithms not advertised" : "[FAIL] Stage7 NCrypt unsupported algorithms not advertised");

	return valid;
}

#if !defined(_WIN32)
/** \brief Verify non-Windows platform fails without vendor dependencies.
 * \return True only for explicit unsupported result without allocating any state.
 */
static bool qsctest_hwncrypt_nonwindows_fail_closed(void)
{
	qsc_hw_ncrypt_context context = { 0 };
	bool valid;

	valid = (qsc_hw_ncrypt_initialize(&context, "qsc-stage7-test", false) == qsc_hw_status_unsupported);
	valid = valid && (context.native_state == NULL);
	qsctest_print_line(valid ? "[PASS] Stage7 NCrypt non-Windows unsupported and fail-closed" : "[FAIL] Stage7 NCrypt non-Windows unsupported and fail-closed");

	return valid;
}
#endif

#if defined(_WIN32)
/** \brief Run a non-destructive reopen-or-create TPM identity signing test on request.
 * \details An opt-in key name is required because generated identities remain persistent.
 * \return True only when a P-256 signature verifies independently through QSC ECDSA.
 * \note Not called without QSC_TEST_NCRYPT_NAME environment variable; never counts as
 * physical qualification when skipped. Caller must use a dedicated test identity name.
 */
static bool qsctest_hwncrypt_native_p256(void)
{
	static const uint8_t message[] = { 'Q', 'S', 'C', '-', 'H', 'S', 'M', '-', 'S', '7' };
	uint8_t digest[32U] = { 0U };
	uint8_t publickey[65U] = { 0U };
	uint8_t signature[sizeof(message) + 64U] = { 0U };
	uint8_t recovered[sizeof(message)] = { 0U };
	qsc_hw_ncrypt_context context = { 0 };
	qsc_hw_provider_ops operations;
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	qsc_hw_key_policy policy;
	qsc_hw_status status;
	size_t publiclen;
	size_t signaturelen;
	size_t recoveredlen;
	const char* name;
	bool valid;
	bool environment_ready;
#if defined(_MSC_VER)
	char* namebuffer;
	size_t namelen;
#endif

	provider = NULL;
	key = NULL;
	valid = false;
#if defined(_MSC_VER)
	namebuffer = NULL;
	namelen = 0U;
	environment_ready = (_dupenv_s(&namebuffer, &namelen, "QSC_TEST_NCRYPT_NAME") == 0);
	name = namebuffer;
#else
	environment_ready = true;
	name = getenv("QSC_TEST_NCRYPT_NAME");
#endif
	qsc_memutils_clear(&operations, sizeof(operations));
	qsc_memutils_clear(&policy, sizeof(policy));
	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = true;

	if (environment_ready == false)
	{
		qsctest_print_line("[FAIL] Stage7 native Windows TPM environment lookup failed");
	}
	else if (name != NULL && name[0U] != '\0')
	{
		status = qsc_hw_ncrypt_initialize(&context, name, false);

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_ncrypt_get_operations(&operations);
		}
		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_provider_open(&provider, &operations, &context);
		}
		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_key_open(&key, provider, name, &policy);

			if (status == qsc_hw_status_stale_key)
			{
				status = qsc_hw_key_generate(&key, provider, &policy);
			}
		}
		if (status == qsc_hw_status_success)
		{
			publiclen = sizeof(publickey);
			status = qsc_hw_key_public(key, publickey, &publiclen);
		}
		if (status == qsc_hw_status_success && publiclen == sizeof(publickey) && publickey[0U] == 0x04U)
		{
			qsc_sha256_compute(digest, message, sizeof(message));
			signaturelen = 64U;
			status = qsc_hw_key_sign(key, digest, sizeof(digest), signature, &signaturelen);
		}
		if (status == qsc_hw_status_success && signaturelen == 64U)
		{
			qsc_memutils_copy(signature + 64U, message, sizeof(message));
			recoveredlen = sizeof(recovered);
			valid = qsc_ecdsap256_verify_prehashed(recovered, &recoveredlen, signature, sizeof(signature), publickey + 1U, digest, sizeof(digest));
			valid = valid && (recoveredlen == sizeof(message));
		}

		if (key != NULL)
		{
			(void)qsc_hw_key_release(&key);
		}
		if (provider != NULL)
		{
			(void)qsc_hw_provider_close(&provider);
		}
		qsc_hw_ncrypt_dispose(&context);
		qsc_memutils_secure_erase(digest, sizeof(digest));
		qsc_memutils_secure_erase(signature, sizeof(signature));
		qsctest_print_line(valid ? "[PASS] Stage7 native Windows TPM P-256 signature verified" : "[FAIL] Stage7 native Windows TPM P-256 signature verified");
	}
	else
	{
		qsctest_print_line("[SKIP] Stage7 native Windows TPM P-256 requires QSC_TEST_NCRYPT_NAME");
		valid = true;
	}

#if defined(_MSC_VER)
	free(namebuffer);
#endif
	return valid;
}
#endif

bool qsctest_hwncrypt_run(void)
{
	bool valid;

	valid = true;
	if (qsctest_hwncrypt_invalid_arguments() == false)
	{
		valid = false;
	}
	if (qsctest_hwncrypt_empty_name() == false)
	{
		valid = false;
	}
	if (qsctest_hwncrypt_uninitialized_capabilities() == false)
	{
		valid = false;
	}
	if (qsctest_hwncrypt_null_operations() == false)
	{
		valid = false;
	}
	if (qsctest_hwncrypt_operations_gating() == false)
	{
		valid = false;
	}
	if (qsctest_hwncrypt_empty_dispose() == false)
	{
		valid = false;
	}
	if (qsctest_hwncrypt_unsupported_schemes() == false)
	{
		valid = false;
	}
#if defined(_WIN32)
	if (qsctest_hwncrypt_native_p256() == false)
	{
		valid = false;
	}
#else
	if (qsctest_hwncrypt_nonwindows_fail_closed() == false)
	{
		valid = false;
	}
#endif

	return valid;
}

#else
/** \brief Keep a harmless entry point when Stage 7 is not selected.
 * \return True; no hardware check is performed or counted as a pass.
 */
bool qsctest_hwncrypt_run(void)
{
	return true;
}
#endif
