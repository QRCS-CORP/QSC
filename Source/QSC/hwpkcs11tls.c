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

#include "hwpkcs11tls.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

#include "memutils.h"
#include "sha2.h"
#include "tlsecdsader.h"
#include "x509cert.h"

/** \file hwpkcs11tls.c
 * \brief TLS 1.3 and X.509 ECDSA signing from non-exportable PKCS#11 private keys.
 * \note The backend is synchronous, and the caller owns signer/key lifetime and thread serialization.
 */

/** \brief Resolve an exact TLS ECDSA scheme into digest and key sizes.
 * \param scheme Requested TLS signature scheme.
 * \param digestlen Receives SHA-2 digest size, in bytes.
 * \param pointlen Receives uncompressed SEC1 key size, in bytes.
 * \param curve Receives expected X.509 named curve.
 * \param algorithm Receives X.509 ECDSA signature algorithm.
 * \return True only for three supported classic ECDSA schemes.
 */
static bool hwpkcs11tls_scheme(qsc_tls_signature_scheme scheme, size_t* digestlen, size_t* pointlen,
	qsc_x509_named_curve* curve, qsc_x509_signature_algorithm* algorithm)
{
	bool res;

	res = true;

	switch (scheme)
	{
		case qsc_tls_sig_ecdsa_secp256r1_sha256:
		{
			*digestlen = 32U;
			*pointlen = 65U;
			*curve = QSC_X509_NAMED_CURVE_PRIME256V1;
			*algorithm = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256;
			break;
		}
		case qsc_tls_sig_ecdsa_secp384r1_sha384:
		{
			*digestlen = 48U;
			*pointlen = 97U;
			*curve = QSC_X509_NAMED_CURVE_SECP384R1;
			*algorithm = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384;
			break;
		}
		case qsc_tls_sig_ecdsa_secp521r1_sha512:
		{
			*digestlen = 64U;
			*pointlen = 133U;
			*curve = QSC_X509_NAMED_CURVE_SECP521R1;
			*algorithm = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512;
			break;
		}
		default:
		{
			res = false;
			break;
		}
	}

	return res;
}

/** \brief Test a public SEC1 key against a live token key and expected named curve.
 * \param key Live protected token key.
 * \param curve Expected curve, from TLS signature scheme.
 * \param publickey Expected SEC1 point bytes.
 * \param publiclen Expected public point length in bytes.
 * \return True only when protected-key public attributes match the expected point.
 */
static bool hwpkcs11tls_public_matches(qsc_hw_pkcs11_key* key, qsc_x509_named_curve curve,
	const uint8_t* publickey, size_t publiclen)
{
	uint8_t tokenkey[133U] = { 0U };
	size_t expected;
	bool match;

	expected = sizeof(tokenkey);
	match = false;

	if (key != NULL && publickey != NULL && publiclen <= sizeof(tokenkey) &&
		qsc_hw_pkcs11_key_public(key, tokenkey, &expected) == qsc_hw_status_success &&
		expected == publiclen && publiclen != 0U && tokenkey[0U] == 0x04U)
	{
		if ((curve == QSC_X509_NAMED_CURVE_PRIME256V1 && publiclen == 65U) ||
			(curve == QSC_X509_NAMED_CURVE_SECP384R1 && publiclen == 97U) ||
			(curve == QSC_X509_NAMED_CURVE_SECP521R1 && publiclen == 133U))
		{
			match = qsc_memutils_are_equal(publickey, tokenkey, publiclen);
		}
	}

	qsc_memutils_secure_erase(tokenkey, sizeof(tokenkey));

	return match;
}

/** \brief Check a DER leaf public key and a complete bounded certificate-chain description.
 * \param chain Borrowed leaf-first certificate chain.
 * \param count Number of entries.
 * \param signer Protected key signer to validate.
 * \return Success only when all chain entry bounds and leaf public key agree.
 */
static qsc_tls_status hwpkcs11tls_check_chain(const qsc_tls_certificate_view* chain, size_t count,
	const qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_x509_certificate certificate = { 0 };
	qsc_x509_signature_algorithm signaturealgorithm;
	qsc_x509_named_curve curve;
	size_t digestlen;
	size_t i;
	size_t pointlen;
	qsc_tls_status status;

	status = qsc_tls_status_invalid_input;

	if (chain != NULL && signer != NULL && signer->key != NULL && count != 0U &&
		count <= QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES &&
		hwpkcs11tls_scheme(signer->scheme, &digestlen, &pointlen, &curve, &signaturealgorithm) == true)
	{
		status = qsc_tls_status_success;

		for (i = 0U; i < count; ++i)
		{
			if (chain[i].data == NULL || chain[i].datalen == 0U || chain[i].datalen > QSC_TLS_CERTIFICATE_MAX_SIZE)
			{
				status = qsc_tls_status_invalid_input;
				break;
			}
		}

		if (status == qsc_tls_status_success)
		{
			if (qsc_x509_certificate_decode_der(chain[0U].data, chain[0U].datalen, &certificate) != QSC_ASN1_STATUS_SUCCESS)
			{
				status = qsc_tls_status_invalid_input;
			}
			else if (certificate.subjectpublickeyinfo.algorithm.publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_EC ||
				certificate.subjectpublickeyinfo.algorithm.curve != curve ||
				certificate.subjectpublickeyinfo.unusedbits != 0U ||
				certificate.subjectpublickeyinfo.publickeylen != pointlen ||
				hwpkcs11tls_public_matches(signer->key, curve, certificate.subjectpublickeyinfo.publickey,
					certificate.subjectpublickeyinfo.publickeylen) == false)
			{
				status = qsc_tls_status_authentication_failure;
			}
		}

		qsc_x509_certificate_free(&certificate);
	}

	return status;
}

/** \brief Set a complete local certificate config from a validated token identity.
 * \param localcert Destination configuration owned by TLS caller.
 * \param chain Validated chain.
 * \param count Number of entries.
 * \param signer Live signer which must outlive the configuration's handshakes.
 * \return Success only when chain and token public key match.
 */
static qsc_tls_status hwpkcs11tls_local_config(qsc_tls_local_certificate_config* localcert,
	const qsc_tls_certificate_view* chain, size_t count, qsc_hw_pkcs11_tls_signer* signer)
{
	size_t i;
	qsc_tls_status status;

	status = hwpkcs11tls_check_chain(chain, count, signer);

	if (status == qsc_tls_status_success && localcert != NULL)
	{
		qsc_memutils_clear(localcert, sizeof(*localcert));

		for (i = 0U; i < count; ++i)
		{
			localcert->chain[i] = chain[i];
		}

		localcert->chainlength = count;
		localcert->verifyscheme = signer->scheme;
		localcert->signcallback = qsc_hw_pkcs11_tls_sign_callback;
		localcert->signstate = signer;
		localcert->signprivatekeylen = 0U;
		localcert->staticsignature = false;
		localcert->configured = true;
	}
	else if (status == qsc_tls_status_success)
	{
		status = qsc_tls_status_invalid_input;
	}

	return status;
}

/** \brief Execute SHA-2, protected-token ECDSA and DER conversion as one operation.
 * \param signer Live bound signer.
 * \param input Complete TLS CV or X.509 TBS bytes.
 * \param inputlen Input length in bytes.
 * \param output Caller DER output; erased on failure when capacity is valid.
 * \param outputlen In/out DER buffer capacity and written length.
 * \return Typed PKCS#11 or policy status.
 */
static qsc_hw_status hwpkcs11tls_sign(qsc_hw_pkcs11_tls_signer* signer, const uint8_t* input,
	size_t inputlen, uint8_t* output, size_t* outputlen)
{
	uint8_t digest[64U] = { 0U };
	uint8_t raw[132U] = { 0U };
	qsc_x509_signature_algorithm algorithm;
	qsc_x509_named_curve curve;
	size_t digestlen;
	size_t pointlen;
	size_t rawlen;
	size_t written;
	size_t capacity;
	qsc_hw_status status;

	capacity = 0U;
	status = qsc_hw_status_invalid_parameter;

	if (outputlen != NULL)
	{
		capacity = *outputlen;
		*outputlen = 0U;
	}

	if (signer != NULL && signer->key != NULL && input != NULL && inputlen != 0U && output != NULL &&
		outputlen != NULL && hwpkcs11tls_scheme(signer->scheme, &digestlen, &pointlen, &curve, &algorithm) == true)
	{
		if (digestlen == 32U)
		{
			qsc_sha256_compute(digest, input, inputlen);
		}
		else if (digestlen == 48U)
		{
			qsc_sha384_compute(digest, input, inputlen);
		}
		else
		{
			qsc_sha512_compute(digest, input, inputlen);
		}

		rawlen = sizeof(raw);
		status = qsc_hw_pkcs11_key_sign(signer->key, digest, digestlen, raw, &rawlen);

		if (status == qsc_hw_status_success)
		{
			written = 0U;

			if (rawlen == (pointlen - 1U))
			{
				if (qsc_tls_ecdsa_der_encode(raw, rawlen / 2U, output, capacity, &written) == qsc_tls_status_success)
				{
					*outputlen = written;
				}
				else
				{
					status = qsc_hw_status_buffer_too_small;
				}
			}
			else
			{
				status = qsc_hw_status_policy;
			}
		}
	}

	if (signer != NULL)
	{
		signer->laststatus = status;
	}

	if (status != qsc_hw_status_success && output != NULL && capacity != 0U)
	{
		qsc_memutils_secure_erase(output, capacity);
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));
	qsc_memutils_secure_erase(raw, sizeof(raw));

	return status;
}

qsc_hw_status qsc_hw_pkcs11_tls_signer_initialize(qsc_hw_pkcs11_tls_signer* signer, qsc_hw_pkcs11_key* key,
	qsc_tls_signature_scheme scheme)
{
	qsc_x509_signature_algorithm algorithm;
	qsc_x509_named_curve curve;
	size_t digestlen;
	size_t pointlen;
	uint8_t point[133U] = { 0U };
	size_t size;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (signer != NULL)
	{
		qsc_memutils_clear(signer, sizeof(*signer));

		if (key != NULL && hwpkcs11tls_scheme(scheme, &digestlen, &pointlen, &curve, &algorithm) == true)
		{
			size = sizeof(point);
			status = qsc_hw_pkcs11_key_public(key, point, &size);

			if (status == qsc_hw_status_success)
			{
				if (size == pointlen && point[0U] == 0x04U)
				{
					signer->key = key;
					signer->scheme = scheme;
				}
				else
				{
					status = qsc_hw_status_policy;
				}
			}
		}

		signer->laststatus = status;
	}

	qsc_memutils_secure_erase(point, sizeof(point));

	return status;
}

bool qsc_hw_pkcs11_tls_sign_callback(qsc_tls_signature_scheme scheme, const uint8_t* input,
	size_t inputlen, uint8_t* signature, size_t* signaturelen, void* state)
{
	qsc_hw_pkcs11_tls_signer* signer;
	bool res;

	signer = (qsc_hw_pkcs11_tls_signer*)state;
	res = false;

	if (signer != NULL && signer->key != NULL)
	{
		if (scheme == signer->scheme)
		{
			res = (hwpkcs11tls_sign(signer, input, inputlen, signature, signaturelen) == qsc_hw_status_success);
		}
		else
		{
			signer->laststatus = qsc_hw_status_policy;

			if (signaturelen != NULL)
			{
				if (signature != NULL && *signaturelen != 0U)
				{
					qsc_memutils_secure_erase(signature, *signaturelen);
				}

				*signaturelen = 0U;
			}
		}
	}
	else if (signaturelen != NULL)
	{
		if (signature != NULL && *signaturelen != 0U)
		{
			qsc_memutils_secure_erase(signature, *signaturelen);
		}

		*signaturelen = 0U;
	}

	return res;
}

qsc_tls_status qsc_hw_pkcs11_tls_client_config_set_identity(qsc_tls_client_config* config,
	const qsc_tls_certificate_view* chain, size_t chainlength, qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_status status;

	status = qsc_tls_status_invalid_input;

	if (config != NULL)
	{
		status = hwpkcs11tls_local_config(&config->localcert, chain, chainlength, signer);
	}

	return status;
}

qsc_tls_status qsc_hw_pkcs11_tls_server_config_set_identity(qsc_tls_server_config* config,
	const qsc_tls_certificate_view* chain, size_t chainlength, qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_status status;

	status = qsc_tls_status_invalid_input;

	if (config != NULL)
	{
		status = hwpkcs11tls_local_config(&config->localcert, chain, chainlength, signer);
	}

	return status;
}

qsc_tls_status qsc_hw_pkcs11_tls_server_config_add_identity(qsc_tls_server_config* config,
	const char* hostname, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_hw_pkcs11_tls_signer* signer)
{
	qsc_tls_local_certificate_config localcert = { 0 };
	qsc_tls_status status;

	status = qsc_tls_status_invalid_input;

	if (config != NULL && hostname != NULL)
	{
		status = hwpkcs11tls_local_config(&localcert, chain, chainlength, signer);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_server_config_add_certificate_identity(config, hostname, &localcert);
		}
	}

	return status;
}

qsc_asn1_status qsc_hw_pkcs11_x509_sign_callback(qsc_x509_signature_algorithm algorithm,
	const uint8_t* tbs, size_t tbslen, uint8_t* signature, size_t* signaturelen, void* context)
{
	qsc_hw_pkcs11_tls_signer* signer;
	qsc_x509_signature_algorithm expected;
	qsc_x509_named_curve curve;
	size_t digestlen;
	size_t pointlen;
	qsc_asn1_status status;

	signer = (qsc_hw_pkcs11_tls_signer*)context;
	status = QSC_ASN1_STATUS_INVALID_INPUT;

	if (signer != NULL && signer->key != NULL &&
		hwpkcs11tls_scheme(signer->scheme, &digestlen, &pointlen, &curve, &expected) == true)
	{
		if (algorithm == expected)
		{
			if (hwpkcs11tls_sign(signer, tbs, tbslen, signature, signaturelen) == qsc_hw_status_success)
			{
				status = QSC_ASN1_STATUS_SUCCESS;
			}
			else
			{
				status = QSC_ASN1_STATUS_FAILURE;
			}
		}
		else
		{
			signer->laststatus = qsc_hw_status_policy;

			if (signaturelen != NULL)
			{
				if (signature != NULL && *signaturelen != 0U)
				{
					qsc_memutils_secure_erase(signature, *signaturelen);
				}

				*signaturelen = 0U;
			}
		}
	}

	return status;
}

qsc_asn1_status qsc_hw_pkcs11_x509_csr_sign(const qsc_x509_csr* csr,
	qsc_hw_pkcs11_tls_signer* signer, uint8_t* output, size_t* outputlen)
{
	qsc_x509_signature_algorithm expected;
	qsc_x509_named_curve curve;
	size_t digestlen;
	size_t pointlen;
	qsc_asn1_status status;

	status = QSC_ASN1_STATUS_INVALID_INPUT;

	if (csr != NULL && signer != NULL && signer->key != NULL && output != NULL && outputlen != NULL &&
		hwpkcs11tls_scheme(signer->scheme, &digestlen, &pointlen, &curve, &expected) == true &&
		csr->signaturealgorithm.signature == expected &&
		csr->spki.algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC &&
		csr->spki.algorithm.curve == curve && csr->spki.unusedbits == 0U &&
		csr->spki.publickeylen == pointlen &&
		hwpkcs11tls_public_matches(signer->key, curve, csr->spki.publickey, pointlen) == true)
	{
		status = qsc_x509_csr_sign(csr, qsc_hw_pkcs11_x509_sign_callback, signer, output, outputlen);
	}

	return status;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED */
