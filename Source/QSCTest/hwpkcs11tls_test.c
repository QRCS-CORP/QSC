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

#include "hwpkcs11tls_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

#include "hwpkcs11tls.h"
#include "memutils.h"
#include "sha2.h"
#include "tlsecdsader.h"
#include "x509spki.h"
#include "testutils.h"
#include "encoding.h"
#include <stdlib.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#   if !defined(NOMINMAX)
#       define NOMINMAX
#   endif
#   include <windows.h>
#else
#   include <dlfcn.h>
#endif

/** \file hwpkcs11tls_test.c
 * \brief Stage 5 mock-token tests, not real cryptographic HSM verification.
 */

/** \brief Synthetic token ECDSA key object identifier, not a secret. */
static const uint8_t stage5_keyid[1U] = { 0xA1U };

/** \brief DER-encoded test certificate with a synthetic point; its original certificate signature is invalid. */
static const uint8_t stage5_mock_certificate[] = {
	0x30U, 0x82U, 0x01U, 0x2DU, 0x30U, 0x81U, 0xD4U, 0xA0U, 0x03U, 0x02U, 0x01U, 0x02U, 0x02U, 0x04U, 0x01U, 0xDFU,
	0x5EU, 0x76U, 0x30U, 0x0AU, 0x06U, 0x08U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x02U, 0x30U, 0x1FU,
	0x31U, 0x1DU, 0x30U, 0x1BU, 0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x14U, 0x71U, 0x73U, 0x63U, 0x2DU, 0x73U,
	0x74U, 0x61U, 0x67U, 0x65U, 0x35U, 0x2DU, 0x6DU, 0x6FU, 0x63U, 0x6BU, 0x2EU, 0x74U, 0x65U, 0x73U, 0x74U, 0x30U,
	0x1EU, 0x17U, 0x0DU, 0x32U, 0x36U, 0x30U, 0x31U, 0x30U, 0x31U, 0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x5AU,
	0x17U, 0x0DU, 0x32U, 0x37U, 0x30U, 0x31U, 0x30U, 0x31U, 0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x30U, 0x5AU, 0x30U,
	0x1FU, 0x31U, 0x1DU, 0x30U, 0x1BU, 0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x14U, 0x71U, 0x73U, 0x63U, 0x2DU,
	0x73U, 0x74U, 0x61U, 0x67U, 0x65U, 0x35U, 0x2DU, 0x6DU, 0x6FU, 0x63U, 0x6BU, 0x2EU, 0x74U, 0x65U, 0x73U, 0x74U,
	0x30U, 0x59U, 0x30U, 0x13U, 0x06U, 0x07U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x02U, 0x01U, 0x06U, 0x08U, 0x2AU,
	0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U, 0x03U, 0x42U, 0x00U, 0x04U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
	0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
	0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU, 0x20U, 0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U,
	0x28U, 0x29U, 0x2AU, 0x2BU, 0x2CU, 0x2DU, 0x2EU, 0x2FU, 0x30U, 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U,
	0x38U, 0x39U, 0x3AU, 0x3BU, 0x3CU, 0x3DU, 0x3EU, 0x3FU, 0x40U, 0x41U, 0x42U, 0x30U, 0x0AU, 0x06U, 0x08U, 0x2AU,
	0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x02U, 0x03U, 0x48U, 0x00U, 0x30U, 0x45U, 0x02U, 0x21U, 0x00U, 0x99U,
	0x1CU, 0xBBU, 0x19U, 0x99U, 0x8AU, 0x76U, 0x33U, 0xE1U, 0xF2U, 0xA9U, 0x1CU, 0xC1U, 0x8BU, 0x02U, 0x3FU, 0xC5U,
	0x31U, 0xE2U, 0xC8U, 0x40U, 0x74U, 0x8BU, 0x8DU, 0xBDU, 0x5AU, 0x52U, 0xA0U, 0x0BU, 0xB7U, 0x40U, 0x85U, 0x02U,
	0x20U, 0x2DU, 0xB7U, 0x28U, 0x19U, 0x50U, 0xF5U, 0xABU, 0x61U, 0x07U, 0x39U, 0x98U, 0xC7U, 0xCFU, 0xC7U, 0x40U,
	0x97U, 0x36U, 0x0BU, 0xE1U, 0x66U, 0x50U, 0x16U, 0xDCU, 0x5CU, 0x51U, 0xA1U, 0x93U, 0x8AU, 0x8EU, 0xE1U, 0x76U,
	0x24U
};


/** \brief Shared test fixture path valid only during the Stage 5 runner invocation. */
static const char* stage5_fixture_module_path = NULL;

/** \brief Open and authenticate the synthetic PKCS#11 module.
 * \param module Receives opened module.
 * \param session Receives authenticated session.
 * \param key Receives protected mock ECDSA P-256 key.
 * \return True only when all operations succeed.
 */
static bool stage5_setup(qsc_hw_pkcs11_module** module, qsc_hw_pkcs11_session** session,
	qsc_hw_pkcs11_key** key)
{
	const uint8_t pin[4U] = { 0x31U, 0x32U, 0x33U, 0x34U };
	const char* path;
	bool pass;

	*module = NULL;
	*session = NULL;
	*key = NULL;
	path = stage5_fixture_module_path;
	pass = (path != NULL);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_module_open(module, path) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_open(session, *module, 7U, false) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_login(*session, pin, sizeof(pin)) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(key, *session, stage5_keyid, sizeof(stage5_keyid),
			qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success);
	}

	return pass;
}

/** \brief Release all test token handles, leaving persistent token objects untouched.
 * \param module Opened module.
 * \param session Open session.
 * \param key Transient protected key reference.
 * \return True if all resources were released successfully.
 */
static bool stage5_cleanup(qsc_hw_pkcs11_module** module, qsc_hw_pkcs11_session** session,
	qsc_hw_pkcs11_key** key)
{
	bool pass;

	pass = true;

	if (*key != NULL)
	{
		pass = (qsc_hw_pkcs11_key_release(key) == qsc_hw_status_success) && pass;
	}

	if (*session != NULL)
	{
		pass = (qsc_hw_pkcs11_session_close(session) == qsc_hw_status_success) && pass;
	}

	if (*module != NULL)
	{
		pass = (qsc_hw_pkcs11_module_close(module) == qsc_hw_status_success) && pass;
	}

	return pass;
}

/** \brief Initialize the protected signer without private-key export.
 * \param key Protected token key.
 * \param signer Receives initialized signer.
 * \return True on supported scheme and explicit failure for unsupported scheme.
 */
static bool stage5_test_signer_initialization(qsc_hw_pkcs11_key* key, qsc_hw_pkcs11_tls_signer* signer)
{
	bool pass;

	pass = (qsc_hw_pkcs11_tls_signer_initialize(signer, key, qsc_tls_sig_ecdsa_secp256r1_sha256) == qsc_hw_status_success);
	pass = (pass && signer->key == key && signer->scheme == qsc_tls_sig_ecdsa_secp256r1_sha256);

	return pass;
}

/** \brief Refuse incompatible signature scheme during signer initialization.
 * \param key Existing P-256 token key.
 * \return True when P-384 cannot be bound to a P-256 identity.
 */
static bool stage5_test_curve_policy(qsc_hw_pkcs11_key* key)
{
	qsc_hw_pkcs11_tls_signer candidate = { 0 };
	bool pass;

	pass = (qsc_hw_pkcs11_tls_signer_initialize(&candidate, key, qsc_tls_sig_ecdsa_secp384r1_sha384) != qsc_hw_status_success);
	pass = (pass && candidate.key == NULL);

	return pass;
}

/** \brief Verify TLS signing hashes CV bytes and DER-encodes raw CKM_ECDSA output.
 * \param signer Token signer.
 * \return True when decoded raw signature includes SHA-256 digest first byte.
 */
static bool stage5_test_certificate_verify(qsc_hw_pkcs11_tls_signer* signer)
{
	uint8_t input[48U] = { 0U };
	uint8_t signature[144U] = { 0U };
	uint8_t decoded[64U] = { 0U };
	uint8_t digest[32U] = { 0U };
	size_t siglen;
	size_t i;
	bool pass;

	for (i = 0U; i < sizeof(input); ++i)
	{
		input[i] = (uint8_t)(i + 5U);
	}

	siglen = sizeof(signature);
	qsc_sha256_compute(digest, input, sizeof(input));
	pass = qsc_hw_pkcs11_tls_sign_callback(qsc_tls_sig_ecdsa_secp256r1_sha256, input, sizeof(input),
		signature, &siglen, signer);

	if (pass == true)
	{
		pass = (qsc_tls_ecdsa_der_decode(signature, siglen, 32U, decoded, sizeof(decoded)) == qsc_tls_status_success);
		pass = (pass && decoded[0U] == digest[0U] && decoded[1U] == 0x5AU && decoded[63U] == 0x5AU);
	}

	return pass;
}

/** \brief Reject negotiated schemes that do not match protected signer policy.
 * \param signer Token signer.
 * \return True if requested output is erased and no signature is produced.
 */
static bool stage5_test_negotiated_scheme_rejection(qsc_hw_pkcs11_tls_signer* signer)
{
	uint8_t data[16U] = { 1U };
	uint8_t signature[144U];
	size_t siglen;
	size_t i;
	bool pass;

	for (i = 0U; i < sizeof(signature); ++i)
	{
		signature[i] = 0xA5U;
	}

	siglen = sizeof(signature);
	pass = (qsc_hw_pkcs11_tls_sign_callback(qsc_tls_sig_ecdsa_secp384r1_sha384,
		data, sizeof(data), signature, &siglen, signer) == false);
	pass = (pass && siglen == 0U && signer->laststatus == qsc_hw_status_policy);

	for (i = 0U; i < sizeof(signature); ++i)
	{
		pass = (signature[i] == 0U) && pass;
	}

	return pass;
}

/** \brief Refuse undersized DER buffers with no partial signature output.
 * \param signer Token signer.
 * \return True if backend result is buffer-too-small and buffer erased.
 */
static bool stage5_test_short_signature_buffer(qsc_hw_pkcs11_tls_signer* signer)
{
	uint8_t data[16U] = { 1U };
	uint8_t output[32U];
	size_t size;
	size_t i;
	bool pass;

	for (i = 0U; i < sizeof(output); ++i)
	{
		output[i] = 0xA5U;
	}

	size = sizeof(output);
	pass = (qsc_hw_pkcs11_tls_sign_callback(qsc_tls_sig_ecdsa_secp256r1_sha256,
		data, sizeof(data), output, &size, signer) == false);
	pass = (pass && size == 0U && signer->laststatus == qsc_hw_status_buffer_too_small);

	for (i = 0U; i < sizeof(output); ++i)
	{
		pass = (output[i] == 0U) && pass;
	}

	return pass;
}

/** \brief Reject empty CV messages and erase any caller output.
 * \param signer Token signer.
 * \return True on explicit typed error and no output bytes.
 */
static bool stage5_test_empty_cv(qsc_hw_pkcs11_tls_signer* signer)
{
	uint8_t output[80U];
	uint8_t input[1U] = { 0U };
	size_t size;
	bool pass;

	qsc_memutils_set_value(output, sizeof(output), 0xA5U);
	size = sizeof(output);
	pass = (qsc_hw_pkcs11_tls_sign_callback(signer->scheme, input, 0U,
		output, &size, signer) == false);
	pass = (pass && size == 0U && signer->laststatus == qsc_hw_status_invalid_parameter);
	pass = (pass && output[0U] == 0U && output[79U] == 0U);

	return pass;
}

/** \brief Bind a matching token certificate to client TLS without key bytes.
 * \param signer Token signer.
 * \return True when chain and callback are set and private bytes remain empty.
 */
static bool stage5_test_client_config(qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_client_config config = { 0 };
	qsc_tls_certificate_view cert = { 0 };
	bool pass;

	cert.data = stage5_mock_certificate;
	cert.datalen = sizeof(stage5_mock_certificate);
	pass = (qsc_hw_pkcs11_tls_client_config_set_identity(&config, &cert, 1U, signer) == qsc_tls_status_success);
	pass = (pass && config.localcert.signcallback == qsc_hw_pkcs11_tls_sign_callback &&
		config.localcert.signstate == signer && config.localcert.chainlength == 1U &&
		config.localcert.signprivatekeylen == 0U && config.localcert.configured == true);

	return pass;
}

/** \brief Bind a matching token certificate to TLS server without software key.
 * \param signer Token signer.
 * \return True only with no stored private key bytes.
 */
static bool stage5_test_server_config(qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_server_config config = { 0 };
	qsc_tls_certificate_view cert = { 0 };
	bool pass;

	cert.data = stage5_mock_certificate;
	cert.datalen = sizeof(stage5_mock_certificate);
	pass = (qsc_hw_pkcs11_tls_server_config_set_identity(&config, &cert, 1U, signer) == qsc_tls_status_success);
	pass = (pass && config.localcert.signcallback == qsc_hw_pkcs11_tls_sign_callback &&
		config.localcert.signstate == signer && config.localcert.signprivatekeylen == 0U);

	return pass;
}

/** \brief Verify SNI identity copies preserve external token signer lifetime.
 * \param signer Token signer.
 * \return True when hostname mapping retains callback and non-owning signer state.
 */
static bool stage5_test_sni_config(qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_server_config config = { 0 };
	qsc_tls_certificate_view cert = { 0 };
	bool pass;

	cert.data = stage5_mock_certificate;
	cert.datalen = sizeof(stage5_mock_certificate);
	pass = (qsc_hw_pkcs11_tls_server_config_add_identity(&config, "stage5.example.test",
		&cert, 1U, signer) == qsc_tls_status_success);
	pass = (pass && config.identitycount == 1U && config.identities[0U].localcert.signstate == signer &&
		config.identities[0U].localcert.signprivatekeylen == 0U);

	return pass;
}

/** \brief Reject a certificate whose public point differs from protected token key.
 * \param signer Token signer.
 * \return True if config remains unchanged and authentication fails.
 */
static bool stage5_test_cert_mismatch(qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_client_config config = { 0 };
	qsc_tls_certificate_view cert = { 0 };
	uint8_t corrupted[sizeof(stage5_mock_certificate)];
	size_t i;
	bool pass;

	qsc_memutils_copy(corrupted, stage5_mock_certificate, sizeof(corrupted));
	cert.data = corrupted;
	cert.datalen = sizeof(corrupted);
	pass = false;

	for (i = 0U; i + 65U <= sizeof(corrupted); ++i)
	{
		if (corrupted[i] == 0x04U && corrupted[i + 1U] == 0x03U && corrupted[i + 64U] == 0x42U)
		{
			corrupted[i + 2U] ^= 1U;
			pass = true;
			break;
		}
	}

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_tls_client_config_set_identity(&config, &cert, 1U, signer) != qsc_tls_status_success);
		pass = (pass && config.localcert.configured == false);
	}

	return pass;
}

/** \brief Reject an unparseable leaf certificate without modifying configuration.
 * \param signer Token signer.
 * \return True on error and unchanged local certificate config.
 */
static bool stage5_test_malformed_cert(qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_server_config config = { 0 };
	qsc_tls_certificate_view cert = { 0 };
	uint8_t malformed[5U] = { 0x30U, 0x03U, 0x01U, 0x02U, 0x03U };
	bool pass;

	cert.data = malformed;
	cert.datalen = sizeof(malformed);
	pass = (qsc_hw_pkcs11_tls_server_config_set_identity(&config, &cert, 1U, signer) != qsc_tls_status_success);
	pass = (pass && config.localcert.configured == false);

	return pass;
}

/** \brief Verify X.509 callback hashes TBS and returns DER ECDSA format.
 * \param signer Token signer.
 * \return True on typed ASN.1 success and digest-shaped synthetic result.
 */
static bool stage5_test_x509_callback(qsc_hw_pkcs11_tls_signer* signer)
{
	uint8_t der[144U] = { 0U };
	uint8_t decoded[64U] = { 0U };
	uint8_t digest[32U] = { 0U };
	uint8_t tbs[13U] = { 0x30U, 0x0BU, 0x01U };
	size_t size;
	bool pass;

	qsc_sha256_compute(digest, tbs, sizeof(tbs));
	size = sizeof(der);
	pass = (qsc_hw_pkcs11_x509_sign_callback(QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256,
		tbs, sizeof(tbs), der, &size, signer) == QSC_ASN1_STATUS_SUCCESS);

	if (pass == true)
	{
		pass = (qsc_tls_ecdsa_der_decode(der, size, 32U, decoded, sizeof(decoded)) == qsc_tls_status_success);
		pass = (pass && decoded[0U] == digest[0U]);
	}

	return pass;
}

/** \brief Reject X.509 ECDSA hash/scheme mismatch.
 * \param signer Token signer.
 * \return True when wrong algorithm is refused and backend policy error recorded.
 */
static bool stage5_test_x509_scheme_mismatch(qsc_hw_pkcs11_tls_signer* signer)
{
	uint8_t der[144U] = { 0U };
	uint8_t tbs[8U] = { 1U };
	size_t size;
	bool pass;

	size = sizeof(der);
	pass = (qsc_hw_pkcs11_x509_sign_callback(QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384,
		tbs, sizeof(tbs), der, &size, signer) != QSC_ASN1_STATUS_SUCCESS);
	pass = (pass && signer->laststatus == qsc_hw_status_policy);

	return pass;
}

/** \brief Validate CSR public-key identity before passing bytes to signing callback.
 * \param signer Token signer.
 * \return True if deliberately mismatched token public key is rejected.
 */
static bool stage5_test_csr_mismatch(qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_x509_csr csr = { 0 };
	uint8_t der[512U] = { 0U };
	uint8_t point[65U] = { 0U };
	size_t len;
	bool pass;

	point[0U] = 0x04U;
	len = sizeof(der);
	pass = (qsc_x509_spki_initialize_ec(&csr.spki, QSC_X509_NAMED_CURVE_PRIME256V1,
		point, sizeof(point)) == QSC_ASN1_STATUS_SUCCESS);
	csr.signaturealgorithm.signature = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256;

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_x509_csr_sign(&csr, signer, der, &len) == QSC_ASN1_STATUS_INVALID_INPUT);
	}

	return pass;
}

/** \brief Validate full PKCS#10 encoding through the protected mock token callback.
 * \param signer Live mock token signer.
 * \return True when CSR encodes, signs and decodes with token public SPKI.
 */
static bool stage5_test_csr_sign(qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_x509_csr csr = { 0 };
	qsc_x509_csr decoded = { 0 };
	uint8_t der[2048U] = { 0U };
	uint8_t point[65U] = { 0U };
	qsc_x509_name name = { 0 };
	size_t derlen;
	size_t keylen;
	size_t namelen;
	bool pass;

	derlen = sizeof(der);
	keylen = sizeof(point);
	pass = (qsc_hw_pkcs11_key_public(signer->key, point, &keylen) == qsc_hw_status_success);

	if (pass == true)
	{
		pass = (qsc_x509_spki_initialize_ec(&csr.spki, QSC_X509_NAMED_CURVE_PRIME256V1,
			point, keylen) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (pass == true)
	{
		name.count = 1U;
		name.attributes[0U].type = QSC_X509_NAME_ATTRIBUTE_COMMON_NAME;
		name.attributes[0U].string_tag = BER_ASN1_UTF8_STRING;
		name.attributes[0U].rdn_index = 0U;
		namelen = sizeof("stage5-mock.test") - 1U;
		name.attributes[0U].length = namelen;
		qsc_memutils_copy(name.attributes[0U].value, "stage5-mock.test", namelen);
		pass = (qsc_x509_csr_set_subject(&csr, &name) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (pass == true)
	{
		csr.signaturealgorithm.signature = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256;
		pass = (qsc_hw_pkcs11_x509_csr_sign(&csr, signer, der, &derlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (pass == true)
	{
		pass = (qsc_x509_csr_decode_der(&decoded, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
		pass = (pass && decoded.signaturelen > 0U && decoded.spki.publickeylen == sizeof(point));
	}

	qsc_x509_csr_clear(&decoded);

	return pass;
}

/** \brief Verify client TLS state copy retains borrowed token signer pointer.
 * \param signer Protected signer.
 * \return True after normal TLS client initialization.
 */
static bool stage5_test_client_state_copy(qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_client_config config = { 0 };
	qsc_tls_certificate_view cert = { 0 };
	qsc_tls_client_state* state;
	qsc_tls_cipher_suite suite;
	qsc_tls_named_group group;
	qsc_tls_signature_scheme scheme;
	qsc_tls_status status;
	bool pass;

	suite = qsc_tls_cipher_suite_tls_aes_256_gcm_sha384;
	group = qsc_tls_group_secp256r1;
	scheme = qsc_tls_sig_ecdsa_secp256r1_sha256;
	cert.data = stage5_mock_certificate;
	cert.datalen = sizeof(stage5_mock_certificate);
	config.ciphersuites = &suite;
	config.ciphersuitecount = 1U;
	config.groups = &group;
	config.groupcount = 1U;
	config.sigschemes = &scheme;
	config.sigschemecount = 1U;
	pass = (qsc_hw_pkcs11_tls_client_config_set_identity(&config, &cert, 1U, signer) == qsc_tls_status_success);
	state = (qsc_tls_client_state*)qsc_memutils_malloc(sizeof(qsc_tls_client_state));

	if (pass == true && state != NULL)
	{
		status = qsc_tls_client_initialize(state, &config);
		pass = (status == qsc_tls_status_success && state->config.localcert.signstate == signer &&
			state->config.localcert.signprivatekeylen == 0U);
		qsc_tls_client_dispose(state);
	}
	else
	{
		pass = false;
	}

	qsc_memutils_alloc_free(state);

	return pass;
}

/** \brief Verify server TLS state copy retains borrowed token signer pointer.
 * \param signer Protected signer.
 * \return True after normal TLS server initialization.
 */
static bool stage5_test_server_state_copy(qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_server_config config = { 0 };
	qsc_tls_certificate_view cert = { 0 };
	qsc_tls_server_state* state;
	qsc_tls_cipher_suite suite;
	qsc_tls_named_group group;
	qsc_tls_signature_scheme scheme;
	bool pass;

	suite = qsc_tls_cipher_suite_tls_aes_256_gcm_sha384;
	group = qsc_tls_group_secp256r1;
	scheme = qsc_tls_sig_ecdsa_secp256r1_sha256;
	cert.data = stage5_mock_certificate;
	cert.datalen = sizeof(stage5_mock_certificate);
	config.ciphersuitepreference = &suite;
	config.ciphersuitepreferencecount = 1U;
	config.groupspreference = &group;
	config.groupspreferencecount = 1U;
	config.sigschemepreference = &scheme;
	config.sigschemepreferencecount = 1U;
	pass = (qsc_hw_pkcs11_tls_server_config_set_identity(&config, &cert, 1U, signer) == qsc_tls_status_success);
	state = (qsc_tls_server_state*)qsc_memutils_malloc(sizeof(qsc_tls_server_state));

	if (pass == true && state != NULL)
	{
		pass = (qsc_tls_server_initialize(state, &config) == qsc_tls_status_success &&
			state->config.localcert.signstate == signer && state->config.localcert.signprivatekeylen == 0U);
		qsc_tls_server_dispose(state);
	}
	else
	{
		pass = false;
	}

	qsc_memutils_alloc_free(state);

	return pass;
}

/** \typedef stage5_mock_set_fault
 * \brief Test-only synthetic PKCS#11 module fault-controller callback.
 * \param fault Test fixture error mode.
 */
typedef void (*stage5_mock_set_fault)(uint32_t fault);

/** \brief Inject a token signing error after the backend writes partial output.
 * \param signer Protected test signer.
 * \param fault 8=partial-signature error, 1=token removal.
 * \return True if no output escapes the failed operation and no fallback occurs.
 */
static bool stage5_test_backend_failure(qsc_hw_pkcs11_tls_signer* signer, uint32_t fault)
{
	uint8_t input[32U] = { 0x41U };
	uint8_t output[144U];
	const char* path;
	stage5_mock_set_fault set_fault;
	size_t len;
	size_t i;
	bool pass;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	HMODULE library;
#else
	void* library;
#endif

	path = stage5_fixture_module_path;
	pass = false;
	set_fault = NULL;

	if (path != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		library = LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

		if (library != NULL)
		{
			set_fault = (stage5_mock_set_fault)GetProcAddress(library, "qsctest_p11mock_set_fault");
		}
#else
		library = dlopen(path, RTLD_NOW | RTLD_LOCAL);

		if (library != NULL)
		{
			set_fault = (stage5_mock_set_fault)dlsym(library, "qsctest_p11mock_set_fault");
		}
#endif
		if (set_fault != NULL)
		{
			for (i = 0U; i < sizeof(output); ++i)
			{
				output[i] = 0xA5U;
			}

			set_fault(fault);
			len = sizeof(output);
			pass = (qsc_hw_pkcs11_tls_sign_callback(signer->scheme, input, sizeof(input),
				output, &len, signer) == false);
			pass = (pass && len == 0U && signer->laststatus != qsc_hw_status_success);

			for (i = 0U; i < sizeof(output); ++i)
			{
				pass = (output[i] == 0U) && pass;
			}

			set_fault(0U);
		}

		if (library != NULL)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			(void)FreeLibrary(library);
#else
			(void)dlclose(library);
#endif
		}
	}

	return pass;
}

/** \brief Execute each Stage 5 named test by direct sequential invocation.
 * \return True when every executed test passes and the fixture was loaded.
 */
bool qsctest_hwpkcs11tls_run(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	qsc_hw_pkcs11_tls_signer signer = { 0 };
	bool passed;
	bool ready;
	bool environment_ready;
#if defined(_MSC_VER)
	char* modulepath;
	size_t pathlen;
#endif

	passed = true;
#if defined(_MSC_VER)
	modulepath = NULL;
	pathlen = 0U;
	environment_ready = (_dupenv_s(&modulepath, &pathlen, "QSC_TEST_PKCS11_MODULE") == 0);
	stage5_fixture_module_path = modulepath;
#else
	environment_ready = true;
	stage5_fixture_module_path = getenv("QSC_TEST_PKCS11_MODULE");
#endif

	if (environment_ready == false)
	{
		qsctest_print_line("[FAIL] HW-TLS PKCS11 fixture environment lookup failed");
		passed = false;
	}
	else if (stage5_fixture_module_path != NULL)
	{
		ready = stage5_setup(&module, &session, &key);
		passed = ready;

		if (ready == false)
		{
			qsctest_print_line("[FAIL] HW-TLS-001 Mock protected-token setup");
		}
		else
		{
			qsctest_print_line("[PASS] HW-TLS-001 Mock protected-token setup");
		}

		if (ready == true)
		{
			ready = stage5_test_signer_initialization(key, &signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-002 Protected signer initialization" : "[FAIL] HW-TLS-002 Protected signer initialization");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_curve_policy(key);
			qsctest_print_line(ready ? "[PASS] HW-TLS-003 Wrong curve rejected" : "[FAIL] HW-TLS-003 Wrong curve rejected");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_certificate_verify(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-004 CV digest and DER encoding" : "[FAIL] HW-TLS-004 CV digest and DER encoding");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_negotiated_scheme_rejection(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-005 Scheme mismatch fails closed" : "[FAIL] HW-TLS-005 Scheme mismatch fails closed");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_short_signature_buffer(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-006 Short signature buffer cleared" : "[FAIL] HW-TLS-006 Short signature buffer cleared");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_empty_cv(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-007 Empty CV rejected and erased" : "[FAIL] HW-TLS-007 Empty CV rejected and erased");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_client_config(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-008 Client hardware identity configured" : "[FAIL] HW-TLS-008 Client hardware identity configured");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_server_config(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-009 Server hardware identity configured" : "[FAIL] HW-TLS-009 Server hardware identity configured");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_sni_config(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-010 SNI identity retains hardware signer" : "[FAIL] HW-TLS-010 SNI identity retains hardware signer");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_cert_mismatch(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-011 Certificate/token mismatch rejected" : "[FAIL] HW-TLS-011 Certificate/token mismatch rejected");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_malformed_cert(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-012 Malformed certificate rejected" : "[FAIL] HW-TLS-012 Malformed certificate rejected");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_x509_callback(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-013 X509 signing callback" : "[FAIL] HW-TLS-013 X509 signing callback");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_x509_scheme_mismatch(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-014 X509 signature scheme rejected" : "[FAIL] HW-TLS-014 X509 signature scheme rejected");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_csr_mismatch(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-015 CSR public-key mismatch rejected" : "[FAIL] HW-TLS-015 CSR public-key mismatch rejected");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_csr_sign(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-016 Protected-key PKCS10 CSR encoding" : "[FAIL] HW-TLS-016 Protected-key PKCS10 CSR encoding");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_client_state_copy(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-017 Client configuration snapshot" : "[FAIL] HW-TLS-017 Client configuration snapshot");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_server_state_copy(&signer);
			qsctest_print_line(ready ? "[PASS] HW-TLS-018 Server configuration snapshot" : "[FAIL] HW-TLS-018 Server configuration snapshot");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_backend_failure(&signer, 8U);
			qsctest_print_line(ready ? "[PASS] HW-TLS-019 Partial backend signature erased" : "[FAIL] HW-TLS-019 Partial backend signature erased");
			passed = passed && ready;
		}

		if (ready == true)
		{
			ready = stage5_test_backend_failure(&signer, 1U);
			qsctest_print_line(ready ? "[PASS] HW-TLS-020 Removed token cannot sign" : "[FAIL] HW-TLS-020 Removed token cannot sign");
			passed = passed && ready;
		}

		passed = stage5_cleanup(&module, &session, &key) && passed;
		qsctest_print_line(passed ? "[PASS] HW-TLS-021 Mock key/session cleanup" : "[FAIL] HW-TLS-021 Mock key/session cleanup");
	}
	else
	{
		qsctest_print_line("[SKIP] HW-TLS PKCS11 test fixture not configured");
	}

#if defined(_MSC_VER)
	free(modulepath);
#endif
	stage5_fixture_module_path = NULL;

	return passed;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED */
