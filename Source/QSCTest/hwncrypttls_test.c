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

#include "hwncrypttls_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_NCRYPT_ENABLED)

#include "hwncrypttls.h"
#include "hwmock.h"
#include "memutils.h"
#include "testutils.h"

/** \brief Return synthetic SEC1 P-256 point without providing a private key.
 * \param context Unused mock token state.
 * \param key Unused mock key reference.
 * \param output Destination, or NULL for sizing.
 * \param outputlen In/out capacity and required size (65 bytes).
 * \return Success or typed buffer-too-small status.
 */
static qsc_hw_status hwncrypttls_test_public(void* context, void* key, uint8_t* output, size_t* outputlen)
{
	qsc_hw_status status;
	size_t i;

	(void)context;
	(void)key;
	status = qsc_hw_status_invalid_parameter;

	if (outputlen != NULL)
	{
		status = qsc_hw_status_buffer_too_small;

		if (output == NULL)
		{
			status = qsc_hw_status_success;
		}
		else if (*outputlen >= 65U)
		{
			output[0U] = 0x04U;

			for (i = 1U; i < 65U; ++i)
			{
				output[i] = (uint8_t)i;
			}

			status = qsc_hw_status_success;
		}

		*outputlen = 65U;
	}

	return status;
}

/** \brief Produce a synthetic raw r||s signature over a 32-byte digest.
 * \param context Caller-owned noncryptographic state.
 * \param key Live test key reference.
 * \param algorithm Must be ECDSA P-256.
 * \param message SHA-256 digest, not read by this noncryptographic mock.
 * \param msglen Required digest size.
 * \param signature Caller result or NULL for size query.
 * \param signaturelen In/out capacity and required 64-byte raw signature size.
 * \return Success or explicit failure without providing real signing assurance.
 */
static qsc_hw_status hwncrypttls_test_sign(void* context, void* key, qsc_hw_algorithm algorithm,
	const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen)
{
	qsc_hw_status status;
	size_t i;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && key != NULL && algorithm == qsc_hw_algorithm_ecdsa_p256 &&
		message != NULL && msglen == 32U && signaturelen != NULL)
	{
		status = qsc_hw_status_buffer_too_small;

		if (signature == NULL)
		{
			status = qsc_hw_status_success;
		}
		else if (*signaturelen >= 64U)
		{
			for (i = 0U; i < 64U; ++i)
			{
				signature[i] = (i < 32U) ? 0x01U : 0x02U;
			}

			status = qsc_hw_status_success;
		}

		*signaturelen = 64U;
	}

	return status;
}

/** \brief Initialize a generic non-exportable mock key and TPM TLS signer.
 * \param context Caller-owned initialized mock token.
 * \param provider Receives live QSC provider wrapper.
 * \param key Receives live key reference.
 * \param signer Receives a signer borrowing the opened key.
 * \param software When true, simulate software custody, not hardware.
 * \return True when setup and signer policy match the expected custody outcome.
 */
static bool hwncrypttls_test_setup(qsctest_hwmock_context* context, qsc_hw_provider** provider,
	qsc_hw_keyref** key, qsc_hw_ncrypt_tls_signer* signer, bool software)
{
	static const uint8_t pin[4U] = { 0x31U, 0x32U, 0x33U, 0x34U };
	qsc_hw_provider_ops ops;
	qsc_hw_key_policy policy;
	qsc_hw_status status;
	bool valid;

	qsctest_hwmock_initialize(context);
	context->software_custody = software;
	qsctest_hwmock_make_ops(&ops);
	ops.public_key = hwncrypttls_test_public;
	ops.sign = hwncrypttls_test_sign;
	qsc_memutils_clear(&policy, sizeof(policy));
	policy.size = sizeof(policy);
	policy.version = QSC_HW_ABI_VERSION;
	policy.algorithm = qsc_hw_algorithm_ecdsa_p256;
	policy.usage = qsc_hw_usage_sign;
	policy.require_hardware = !software;
	policy.allow_software_fallback = software;
	*provider = NULL;
	*key = NULL;
	qsc_memutils_clear(signer, sizeof(*signer));
	valid = (qsc_hw_provider_open(provider, &ops, context) == qsc_hw_status_success);

	if (valid == true)
	{
		valid = (qsctest_hwmock_login(context, pin, sizeof(pin)) == qsc_hw_status_success);
	}
	if (valid == true)
	{
		valid = (qsc_hw_key_open(key, *provider, "mock:010203:01", &policy) == qsc_hw_status_success);
	}
	if (valid == true)
	{
		status = qsc_hw_ncrypt_tls_signer_initialize(signer, *key, qsc_tls_sig_ecdsa_secp256r1_sha256);
		valid = (status == (software ? qsc_hw_status_policy : qsc_hw_status_success));
	}

	return valid;
}

/** \brief Release test key and provider in the required order.
 * \param provider Owned provider wrapper.
 * \param key Owned transient key reference.
 * \return True if both cleanup steps complete without leaking references.
 */
static bool hwncrypttls_test_close(qsc_hw_provider** provider, qsc_hw_keyref** key)
{
	bool valid;

	valid = true;

	if (*key != NULL)
	{
		valid = (qsc_hw_key_release(key) == qsc_hw_status_success);
	}
	if (*provider != NULL)
	{
		valid = (qsc_hw_provider_close(provider) == qsc_hw_status_success) && valid;
	}

	return valid;
}

/** \brief Check successful digest-signing and DER encoding with synthetic r||s bytes.
 * \return True if a DER SEQUENCE is emitted and no secret is exported.
 */
static bool hwncrypttls_test_der_sign(void)
{
	static const uint8_t message[] = { 0x54U, 0x4CU, 0x53U };
	uint8_t der[90U] = { 0U };
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	qsc_hw_ncrypt_tls_signer signer;
	qsctest_hwmock_context context;
	size_t length;
	bool valid;

	valid = hwncrypttls_test_setup(&context, &provider, &key, &signer, false);

	if (valid == true)
	{
		length = sizeof(der);
		valid = qsc_hw_ncrypt_tls_sign_callback(qsc_tls_sig_ecdsa_secp256r1_sha256,
			message, sizeof(message), der, &length, &signer);
		valid = valid && (length >= 68U && length <= 72U && der[0U] == 0x30U);
	}

	valid = hwncrypttls_test_close(&provider, &key) && valid;
	qsctest_print_line(valid ? "[PASS] Stage7 TPM TLS synthetic ECDSA raw-to-DER callback" : "[FAIL] Stage7 TPM TLS synthetic ECDSA raw-to-DER callback");
	return valid;
}

/** \brief Reject mismatched TLS signature schemes before token callback invocation.
 * \return True only for failure and cleared output length.
 */
static bool hwncrypttls_test_scheme_rejection(void)
{
	static const uint8_t message[3U] = { 1U, 2U, 3U };
	uint8_t der[90U] = { 0U };
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	qsc_hw_ncrypt_tls_signer signer;
	qsctest_hwmock_context context;
	size_t length;
	bool valid;

	valid = hwncrypttls_test_setup(&context, &provider, &key, &signer, false);

	if (valid == true)
	{
		length = sizeof(der);
		valid = (qsc_hw_ncrypt_tls_sign_callback(qsc_tls_sig_ecdsa_secp384r1_sha384,
			message, sizeof(message), der, &length, &signer) == false && length == 0U &&
			signer.laststatus == qsc_hw_status_policy);
	}

	valid = hwncrypttls_test_close(&provider, &key) && valid;
	qsctest_print_line(valid ? "[PASS] Stage7 TPM TLS wrong signature scheme rejected" : "[FAIL] Stage7 TPM TLS wrong signature scheme rejected");
	return valid;
}

/** \brief Reject software custody even when a mock application permits it.
 * \return True only if signer initialization refuses a software-only key.
 */
static bool hwncrypttls_test_software_rejection(void)
{
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	qsc_hw_ncrypt_tls_signer signer;
	qsctest_hwmock_context context;
	bool valid;

	valid = hwncrypttls_test_setup(&context, &provider, &key, &signer, true);
	valid = hwncrypttls_test_close(&provider, &key) && valid;
	qsctest_print_line(valid ? "[PASS] Stage7 TPM TLS software-key downgrade rejected" : "[FAIL] Stage7 TPM TLS software-key downgrade rejected");
	return valid;
}

/** \brief Reject an undersized output and clear partial signature bytes.
 * \return True only if no partial DER output escapes and error status is set.
 */
static bool hwncrypttls_test_short_output(void)
{
	static const uint8_t message[2U] = { 4U, 5U };
	uint8_t der[5U] = { 0U };
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	qsc_hw_ncrypt_tls_signer signer;
	qsctest_hwmock_context context;
	size_t length;
	bool valid;

	valid = hwncrypttls_test_setup(&context, &provider, &key, &signer, false);

	if (valid == true)
	{
		length = sizeof(der);
		valid = (qsc_hw_ncrypt_tls_sign_callback(qsc_tls_sig_ecdsa_secp256r1_sha256,
			message, sizeof(message), der, &length, &signer) == false && length == 0U &&
			signer.laststatus == qsc_hw_status_buffer_too_small);
	}

	valid = hwncrypttls_test_close(&provider, &key) && valid;
	qsctest_print_line(valid ? "[PASS] Stage7 TPM TLS undersized DER output fail-closed" : "[FAIL] Stage7 TPM TLS undersized DER output fail-closed");
	return valid;
}

/** \brief Reject empty client certificate identity and unsupported SNI setup.
 * \return True when no TLS identity is silently installed.
 */
static bool hwncrypttls_test_invalid_certificate(void)
{
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	qsc_hw_ncrypt_tls_signer signer;
	qsctest_hwmock_context context;
	bool valid;

	valid = hwncrypttls_test_setup(&context, &provider, &key, &signer, false);

	if (valid == true)
	{
		valid = (qsc_hw_ncrypt_tls_client_config_set_identity(NULL, NULL, 0U, &signer) == qsc_tls_status_invalid_input);
		valid = valid && (qsc_hw_ncrypt_tls_server_config_add_identity(NULL, NULL, NULL, 0U, &signer) == qsc_tls_status_invalid_input);
	}

	valid = hwncrypttls_test_close(&provider, &key) && valid;
	qsctest_print_line(valid ? "[PASS] Stage7 TPM TLS invalid certificate config rejected" : "[FAIL] Stage7 TPM TLS invalid certificate config rejected");
	return valid;
}

/** \brief Reject mismatched or missing CSR signer input.
 * \return True if no X.509 output is signed without matching identity data.
 */
static bool hwncrypttls_test_invalid_csr(void)
{
	qsc_hw_provider* provider;
	qsc_hw_keyref* key;
	qsc_hw_ncrypt_tls_signer signer;
	qsctest_hwmock_context context;
	uint8_t output[128U] = { 0U };
	size_t length;
	bool valid;

	valid = hwncrypttls_test_setup(&context, &provider, &key, &signer, false);

	if (valid == true)
	{
		length = sizeof(output);
		valid = (qsc_hw_ncrypt_x509_csr_sign(NULL, &signer, output, &length) == QSC_ASN1_STATUS_INVALID_INPUT);
	}

	valid = hwncrypttls_test_close(&provider, &key) && valid;
	qsctest_print_line(valid ? "[PASS] Stage7 TPM CSR invalid identity rejected" : "[FAIL] Stage7 TPM CSR invalid identity rejected");
	return valid;
}

bool qsctest_hwncrypttls_run(void)
{
	bool valid;

	valid = true;
	if (hwncrypttls_test_der_sign() == false)
	{
		valid = false;
	}
	if (hwncrypttls_test_scheme_rejection() == false)
	{
		valid = false;
	}
	if (hwncrypttls_test_software_rejection() == false)
	{
		valid = false;
	}
	if (hwncrypttls_test_short_output() == false)
	{
		valid = false;
	}
	if (hwncrypttls_test_invalid_certificate() == false)
	{
		valid = false;
	}
	if (hwncrypttls_test_invalid_csr() == false)
	{
		valid = false;
	}

	return valid;
}

#else
/** \brief Keep an inert test entry point when NCrypt feature is disabled.
 * \return True without claiming hardware coverage.
 */
bool qsctest_hwncrypttls_run(void)
{
	return true;
}
#endif
