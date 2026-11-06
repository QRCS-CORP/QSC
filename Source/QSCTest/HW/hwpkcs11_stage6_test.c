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

#include "hwpkcs11.h"
#include "hwpkcs11tls.h"
#include "memutils.h"
#include "stringutils.h"
#include "tlsecdsader.h"
#include "x509csr.h"
#include "x509spki.h"
#include "x509types.h"
#include "asn1.h"

#include <p11-kit/pkcs11.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

/** \file hwpkcs11_stage6_test.c
 * \brief Standalone NSS Cryptoki software-token verification with independent OpenSSL evidence.
 * \details This test operates ONLY on a disposable NSS software-token database.
 * A separate, explicitly authorized physical-HSM test is needed for Stage 6 gate G6.
 * Builds require hardware PKCS#11 support and externally installed Cryptoki development headers.
 */

/** \def QSC_STAGE6_BUFFER_SIZE
 * \brief Maximum CSR DER or generated test artifact size in bytes.
 */
#define QSC_STAGE6_BUFFER_SIZE 4096U

/** \def QSC_STAGE6_INIT_SIZE
 * \brief Maximum NSS module initialisation parameter bytes including NUL.
 */
#define QSC_STAGE6_INIT_SIZE 2048U

/** \def QSC_STAGE6_KEEP_NSS_MAPPED
 * \brief Sanitizer-only mode to retain mapped vendor code after dlclose for LeakSanitizer root accounting.
 * \note Does not change QSC module loading or runtime operations. Linux RTLD_NODELETE required.
 */

/** \struct qsc_stage6_state
 * \brief Test-only live provider objects, never used in production code.
 * \note Single thread and one process; caller releases all objects before module finalization.
 */
typedef struct qsc_stage6_state
{
	void* library; /**< NSS software module loader handle. */
	CK_FUNCTION_LIST_PTR cryptoki; /**< Direct test-only Cryptoki interface. */
	qsc_hw_pkcs11_module* module; /**< QSC module reference. */
	qsc_hw_pkcs11_session* session; /**< QSC token session. */
	qsc_hw_pkcs11_key* key; /**< QSC nonexportable P-256 key reference. */
	qsc_hw_pkcs11_tls_signer signer; /**< Borrowed signer. */
	CK_SLOT_ID slot; /**< Selected NSS certificate DB slot. */
	uint8_t publickey[65U]; /**< SEC1 P-256 public point. */
	size_t publickeylen; /**< Public point length. */
	const char* artifactdir; /**< Caller-owned absolute output folder. */
} qsc_stage6_state;

/** \brief Fixed test-only persistent object identifier, confined to a fresh disposable NSS database. */
static const uint8_t qsc_stage6_keyid[] = { 0x51U, 0x53U, 0x43U, 0x2DU, 0x53U, 0x36U, 0x01U };

/** \brief Test-only CertificateVerify input; must be verified by an independent OpenSSL implementation. */
static const uint8_t qsc_stage6_message[] = "QRCS QSC PKCS11 Stage6 verified P256 CertificateVerify digest";

/** \brief Write a named public test artifact; never write private key or PIN material.
 * \param dir Existing destination directory.
 * \param name Bounded fixed artifact basename.
 * \param buffer Source bytes.
 * \param length Exact byte count.
 * \return True if all bytes were written and file was closed successfully.
 */
static bool stage6_write_artifact(const char* dir, const char* name, const uint8_t* buffer, size_t length)
{
	char path[QSC_STAGE6_INIT_SIZE] = { 0U };
	FILE* fp;
	size_t written;
	bool success;

	success = false;

	if (dir != NULL && name != NULL && buffer != NULL &&
		snprintf(path, sizeof(path), "%s/%s", dir, name) > 0)
	{
		fp = fopen(path, "wb");

		if (fp != NULL)
		{
			written = fwrite(buffer, 1U, length, fp);
			success = (written == length);

			if (fclose(fp) != 0)
			{
				success = false;
			}
		}
	}

	return success;
}

/** \brief Open a fresh NSS software token using its documented module initialization string.
 * \param state Test state receiving module context.
 * \param modulepath Absolute NSS PKCS#11 shared library path.
 * \param dbdir Fresh disposable initialized NSS database directory.
 * \return True if both the real Cryptoki module and the QSC adapter open successfully.
 * \note No PIN is retained. This is an NSS-specific software test bootstrap only.
 */
static bool stage6_test_nss_initialize(qsc_stage6_state* state, const char* modulepath, const char* dbdir)
{
	CK_C_GetFunctionList getlist;
	CK_C_INITIALIZE_ARGS args;
	CK_RV rv;
	char initargs[QSC_STAGE6_INIT_SIZE] = { 0U };
	int printed;
	qsc_hw_status status;
	bool success;

	success = false;
	printed = snprintf(initargs, sizeof(initargs), "configdir='sql:%s' certPrefix='' keyPrefix='' secmod='secmod.db'", dbdir);

	if (printed > 0 && (size_t)printed < sizeof(initargs))
	{
#if defined(QSC_STAGE6_KEEP_NSS_MAPPED) && defined(RTLD_NODELETE)
		state->library = dlopen(modulepath, RTLD_NOW | RTLD_LOCAL | RTLD_NODELETE);
#else
		state->library = dlopen(modulepath, RTLD_NOW | RTLD_LOCAL);
#endif

		if (state->library != NULL)
		{
			getlist = (CK_C_GetFunctionList)dlsym(state->library, "C_GetFunctionList");

			if (getlist != NULL)
			{
				rv = getlist(&state->cryptoki);

				if (rv == CKR_OK && state->cryptoki != NULL)
				{
					qsc_memutils_clear(&args, sizeof(args));
					args.flags = CKF_OS_LOCKING_OK;
					args.pReserved = initargs;
					rv = state->cryptoki->C_Initialize(&args);

					if (rv == CKR_OK)
					{
						status = qsc_hw_pkcs11_module_open(&state->module, modulepath);
						success = (status == qsc_hw_status_success);

						if (success == false)
						{
							fprintf(stderr, "Stage6 NSS module: QSC status=%u\n", (unsigned int)status);
						}
					}
					else
					{
						fprintf(stderr, "Stage6 NSS bootstrap: CK_RV=0x%lx\n", (unsigned long)rv);
					}
				}
			}
		}
	}

	printf("%s: Stage6 NSS software token initialization\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Discover P-256-capable NSS certificate slot and open authenticated session.
 * \param state Live stage state.
 * \return True when token discovery and empty-PIN login succeed.
 */
static bool stage6_test_token_discovery(qsc_stage6_state* state)
{
	uint64_t slots[8U] = { 0U };
	qsc_hw_pkcs11_token_info info = { 0 };
	qsc_hw_pkcs11_mechanism_info mech = { 0 };
	qsc_hw_status status;
	size_t count;
	size_t i;
	bool success;

	success = false;
	count = sizeof(slots) / sizeof(slots[0U]);
	status = qsc_hw_pkcs11_slot_list(state->module, true, slots, &count);

	if (status == qsc_hw_status_success)
	{
		for (i = 0U; i < count && success == false; ++i)
		{
			status = qsc_hw_pkcs11_token_info_get(state->module, slots[i], &info);

			if (status == qsc_hw_status_success && qsc_stringutils_compare_strings(info.label, "NSS Certificate DB", 18U) == true)
			{
				status = qsc_hw_pkcs11_mechanism_info_get(state->module, slots[i], CKM_EC_KEY_PAIR_GEN, &mech);

				if (status == qsc_hw_status_success && (mech.flags & CKF_GENERATE_KEY_PAIR) != 0U)
				{
					state->slot = (CK_SLOT_ID)slots[i];
					status = qsc_hw_pkcs11_session_open(&state->session, state->module, slots[i], true);

					if (status == qsc_hw_status_success)
					{
						status = qsc_hw_pkcs11_session_login(state->session, NULL, 0U);
						success = (status == qsc_hw_status_success);
					}
				}
			}
		}
	}

	if (success == false)
	{
		fprintf(stderr, "Stage6 NSS slot discovery: status=%u count=%zu\n", (unsigned int)status, count);
	}

	printf("%s: Stage6 real Cryptoki slot and mechanism discovery\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Generate an actual NSS nonextractable P-256 key and retrieve its public point.
 * \param state Authenticated token session.
 * \return True only if protected key generation and public retrieval succeed.
 */
static bool stage6_test_key_generation(qsc_stage6_state* state)
{
	qsc_hw_status status;
	bool success;

	status = qsc_hw_pkcs11_key_generate(&state->key, state->session, qsc_stage6_keyid,
		sizeof(qsc_stage6_keyid), qsc_hw_algorithm_ecdsa_p256);
	success = (status == qsc_hw_status_success);

	if (success == true)
	{
		state->publickeylen = sizeof(state->publickey);
		status = qsc_hw_pkcs11_key_public(state->key, state->publickey, &state->publickeylen);
		success = (status == qsc_hw_status_success && state->publickeylen == sizeof(state->publickey) &&
			state->publickey[0U] == 0x04U);
	}

	if (success == true)
	{
		success = stage6_write_artifact(state->artifactdir, "nss_p256_public.sec1", state->publickey, state->publickeylen);
	}

	if (success == false)
	{
		fprintf(stderr, "Stage6 P-256 key generation: QSC status=%u\n", (unsigned int)status);
	}

	printf("%s: Stage6 protected P-256 keypair generation\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Check Cryptoki attributes and refusal to read the private key's raw value.
 * \param state Authenticated NSS token and known key identifier.
 * \return True only if CKA_TOKEN/PRIVATE/SENSITIVE are true and extraction is denied.
 * \note NSS is a software token; these attributes do not prove physical hardware custody.
 */
static bool stage6_test_private_export_denied(qsc_stage6_state* state)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS klass;
	CK_ATTRIBUTE filter[2U];
	CK_ATTRIBUTE attrs[4U];
	CK_OBJECT_HANDLE handle;
	CK_BBOOL token;
	CK_BBOOL sensitive;
	CK_BBOOL extractable;
	CK_BBOOL privatekey;
	CK_BYTE secret[64U];
	CK_ULONG found;
	CK_RV rv;
	bool success;

	session = CK_INVALID_HANDLE;
	success = false;
	rv = state->cryptoki->C_OpenSession(state->slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &session);

	if (rv == CKR_OK)
	{
		klass = CKO_PRIVATE_KEY;
		filter[0U].type = CKA_CLASS;
		filter[0U].pValue = &klass;
		filter[0U].ulValueLen = sizeof(klass);
		filter[1U].type = CKA_ID;
		filter[1U].pValue = (void*)qsc_stage6_keyid;
		filter[1U].ulValueLen = sizeof(qsc_stage6_keyid);
		rv = state->cryptoki->C_FindObjectsInit(session, filter, 2U);

		if (rv == CKR_OK)
		{
			found = 0U;
			rv = state->cryptoki->C_FindObjects(session, &handle, 1U, &found);
			(void)state->cryptoki->C_FindObjectsFinal(session);

			if (rv == CKR_OK && found == 1U)
			{
				attrs[0U].type = CKA_TOKEN;
				attrs[0U].pValue = &token;
				attrs[0U].ulValueLen = sizeof(token);
				attrs[1U].type = CKA_SENSITIVE;
				attrs[1U].pValue = &sensitive;
				attrs[1U].ulValueLen = sizeof(sensitive);
				attrs[2U].type = CKA_EXTRACTABLE;
				attrs[2U].pValue = &extractable;
				attrs[2U].ulValueLen = sizeof(extractable);
				attrs[3U].type = CKA_PRIVATE;
				attrs[3U].pValue = &privatekey;
				attrs[3U].ulValueLen = sizeof(privatekey);
				rv = state->cryptoki->C_GetAttributeValue(session, handle, attrs, 4U);

				if (rv == CKR_OK && token == CK_TRUE && sensitive == CK_TRUE &&
					extractable == CK_FALSE && privatekey == CK_TRUE)
				{
					qsc_memutils_clear(secret, sizeof(secret));
					attrs[0U].type = CKA_VALUE;
					attrs[0U].pValue = secret;
					attrs[0U].ulValueLen = sizeof(secret);
					rv = state->cryptoki->C_GetAttributeValue(session, handle, attrs, 1U);
					success = (rv == CKR_ATTRIBUTE_SENSITIVE || rv == CKR_ATTRIBUTE_TYPE_INVALID ||
						attrs[0U].ulValueLen == CK_UNAVAILABLE_INFORMATION);
					qsc_memutils_secure_erase(secret, sizeof(secret));
				}
			}
		}

		(void)state->cryptoki->C_CloseSession(session);
	}

	if (success == false)
	{
		fprintf(stderr, "Stage6 private-key export: Cryptoki CK_RV=0x%lx\n", (unsigned long)rv);
	}

	printf("%s: Stage6 token private-key extraction rejected\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Produce an actual ECDSA signature through QSC TLS hardware signer callback.
 * \param state Live test token/key.
 * \return True when signature is DER and output files are written.
 * \note Independent cryptographic verification is executed by the separate OpenSSL test script.
 */
static bool stage6_test_tls_signature(qsc_stage6_state* state)
{
	uint8_t der[160U] = { 0U };
	uint8_t raw[64U] = { 0U };
	qsc_hw_status status;
	size_t derlen;
	bool success;

	status = qsc_hw_pkcs11_tls_signer_initialize(&state->signer, state->key, qsc_tls_sig_ecdsa_secp256r1_sha256);
	success = (status == qsc_hw_status_success);

	if (success == true)
	{
		derlen = sizeof(der);
		success = qsc_hw_pkcs11_tls_sign_callback(state->signer.scheme, qsc_stage6_message,
			sizeof(qsc_stage6_message) - 1U, der, &derlen, &state->signer);
	}

	if (success == true)
	{
		success = (qsc_tls_ecdsa_der_decode(der, derlen, 32U, raw, sizeof(raw)) == qsc_tls_status_success);
	}

	if (success == true)
	{
		success = stage6_write_artifact(state->artifactdir, "nss_tls_message.bin", qsc_stage6_message,
			sizeof(qsc_stage6_message) - 1U);
		success = stage6_write_artifact(state->artifactdir, "nss_tls_signature.der", der, derlen) && success;
	}

	if (success == false)
	{
		fprintf(stderr, "Stage6 TLS ECDSA callback: backend status=%u\n", (unsigned int)state->signer.laststatus);
	}

	qsc_memutils_secure_erase(raw, sizeof(raw));
	printf("%s: Stage6 genuine token TLS ECDSA callback DER signature\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Produce a DER PKCS#10 CSR signed by an actual nonexportable token key.
 * \param state Live signer.
 * \return True when CSR encoding and read-back succeeds.
 * \note OpenSSL independently verifies the CSR signature outside this test.
 */
static bool stage6_test_csr(qsc_stage6_state* state)
{
	qsc_x509_csr csr = { 0 };
	qsc_x509_csr decoded = { 0 };
	qsc_x509_name subject = { 0 };
	uint8_t der[QSC_STAGE6_BUFFER_SIZE] = { 0U };
	const char* common_name = "qsc-stage6-nss.example";
	size_t namelen;
	size_t derlen;
	bool success;

	success = (qsc_x509_spki_initialize_ec(&csr.spki, QSC_X509_NAMED_CURVE_PRIME256V1,
		state->publickey, state->publickeylen) == QSC_ASN1_STATUS_SUCCESS);

	if (success == true)
	{
		subject.count = 1U;
		subject.attributes[0U].type = QSC_X509_NAME_ATTRIBUTE_COMMON_NAME;
		subject.attributes[0U].string_tag = BER_ASN1_UTF8_STRING;
		subject.attributes[0U].rdn_index = 0U;
		namelen = qsc_stringutils_string_size(common_name);
		subject.attributes[0U].length = namelen;
		qsc_memutils_copy(subject.attributes[0U].value, common_name, namelen);
		success = (qsc_x509_csr_set_subject(&csr, &subject) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (success == true)
	{
		csr.signaturealgorithm.signature = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256;
		derlen = sizeof(der);
		success = (qsc_hw_pkcs11_x509_csr_sign(&csr, &state->signer, der, &derlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (success == true)
	{
		success = (qsc_x509_csr_decode_der(&decoded, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
	}

	if (success == true)
	{
		success = stage6_write_artifact(state->artifactdir, "nss_p256_request.der", der, derlen);
	}

	qsc_x509_csr_clear(&decoded);
	printf("%s: Stage6 genuine token-backed PKCS10 CSR encoding\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Check hardware signer policy and buffer erasure after incompatible TLS request.
 * \param state Live signer.
 * \return True when no signature is released for a mismatched curve.
 */
static bool stage6_test_tls_policy(qsc_stage6_state* state)
{
	uint8_t output[160U];
	size_t size;
	bool success;
	size_t i;

	qsc_memutils_set_value(output, sizeof(output), 0xA5U);
	size = sizeof(output);
	success = (qsc_hw_pkcs11_tls_sign_callback(qsc_tls_sig_ecdsa_secp384r1_sha384,
		qsc_stage6_message, sizeof(qsc_stage6_message) - 1U, output, &size,
		&state->signer) == false);
	success = (size == 0U && state->signer.laststatus == qsc_hw_status_policy) && success;

	for (i = 0U; i < sizeof(output); ++i)
	{
		success = (output[i] == 0U) && success;
	}

	printf("%s: Stage6 mismatched TLS signature policy fails closed\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Reopen the software token and resolve the same persistent private key without exporting it.
 * \param state Live session and key references.
 * \return True if the key survives session closure and still signs a digest.
 */
static bool stage6_test_persistent_key(qsc_stage6_state* state)
{
	uint8_t point[65U] = { 0U };
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U] = { 0U };
	qsc_hw_status status;
	size_t pointlen;
	size_t signaturelen;
	bool success;

	status = qsc_hw_pkcs11_key_release(&state->key);
	success = (status == qsc_hw_status_success);

	if (success == true)
	{
		status = qsc_hw_pkcs11_session_close(&state->session);
		success = (status == qsc_hw_status_success);
	}

	if (success == true)
	{
		status = qsc_hw_pkcs11_session_open(&state->session, state->module, (uint64_t)state->slot, true);
		success = (status == qsc_hw_status_success);
	}

	if (success == true)
	{
		status = qsc_hw_pkcs11_session_login(state->session, NULL, 0U);
		success = (status == qsc_hw_status_success);
	}

	if (success == true)
	{
		status = qsc_hw_pkcs11_key_find(&state->key, state->session, qsc_stage6_keyid,
			sizeof(qsc_stage6_keyid), qsc_hw_algorithm_ecdsa_p256);
		success = (status == qsc_hw_status_success);
	}

	if (success == true)
	{
		pointlen = sizeof(point);
		status = qsc_hw_pkcs11_key_public(state->key, point, &pointlen);
		success = (status == qsc_hw_status_success && pointlen == state->publickeylen &&
			qsc_memutils_are_equal(point, state->publickey, pointlen) == true);
	}

	if (success == true)
	{
		signaturelen = sizeof(signature);
		status = qsc_hw_pkcs11_key_sign(state->key, digest, sizeof(digest), signature, &signaturelen);
		success = (status == qsc_hw_status_success && signaturelen == sizeof(signature));
	}

	if (success == false)
	{
		fprintf(stderr, "Stage6 persistent signing: QSC status=%u\n", (unsigned int)status);
	}

	qsc_memutils_secure_erase(signature, sizeof(signature));
	qsc_memutils_secure_erase(digest, sizeof(digest));
	printf("%s: Stage6 token key persistence across session reopen\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Release QSC handles and externally initialized NSS software token.
 * \param state Current test state; accepts partially initialized objects.
 * \return True if owned resources and external NSS runtime are finalized cleanly.
 */
static bool stage6_test_cleanup(qsc_stage6_state* state)
{
	CK_RV rv;
	bool success;

	success = true;
	if (state->key != NULL)
	{
		success = (qsc_hw_pkcs11_key_release(&state->key) == qsc_hw_status_success) && success;
	}
	if (state->session != NULL)
	{
		success = (qsc_hw_pkcs11_session_close(&state->session) == qsc_hw_status_success) && success;
	}
	if (state->module != NULL)
	{
		success = (qsc_hw_pkcs11_module_close(&state->module) == qsc_hw_status_success) && success;
	}
	if (state->cryptoki != NULL)
	{
		rv = state->cryptoki->C_Finalize(NULL_PTR);
		success = (rv == CKR_OK) && success;
	}
	if (state->library != NULL)
	{
		success = (dlclose(state->library) == 0) && success;
	}

	qsc_memutils_secure_erase(state, sizeof(qsc_stage6_state));
	printf("%s: Stage6 NSS token and QSC provider cleanup\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Read public test certificate DER without retaining any private key material.
 * \param path Absolute certificate path.
 * \param output Caller certificate buffer.
 * \param capacity Maximum input bytes.
 * \param length Receives exact byte length.
 * \return True if certificate fits, is nonempty and reads successfully.
 */
static bool stage6_read_certificate(const char* path, uint8_t* output, size_t capacity, size_t* length)
{
	FILE* fp;
	bool success;
	size_t count;

	success = false;
	*length = 0U;
	fp = fopen(path, "rb");

	if (fp != NULL)
	{
		count = fread(output, 1U, capacity, fp);
		success = (count != 0U && count < capacity && ferror(fp) == 0);

		if (success == true)
		{
			*length = count;
		}

		if (fclose(fp) != 0)
		{
			success = false;
		}
	}

	return success;
}

/** \brief Send a generated QSC server flight on a connected local TLS socket.
 * \param fd Connected client socket.
 * \param output Fully serialized TLS response records.
 * \param length Exact response byte count.
 * \return True when all bytes were sent without truncation.
 */
static bool stage6_send_all(int fd, const uint8_t* output, size_t length)
{
	ssize_t sent;
	size_t offset;
	bool success;

	success = true;
	offset = 0U;

	while (offset < length && success == true)
	{
		sent = send(fd, output + offset, length - offset, 0);

		if (sent > 0)
		{
			offset += (size_t)sent;
		}
		else
		{
			success = false;
		}
	}

	return success;
}

/** \brief Serve one loopback-only TLS 1.3 connection with the authentic NSS PKCS#11 signer.
 * \param state Live authenticated token signer.
 * \param certpath Public DER server certificate matching the token key.
 * \param port Explicit localhost port, 1024 through 65535.
 * \return True when OpenSSL completes authenticated TLS handshake.
 * \note Test-only one-connection server, no retry or release-grade socket behavior.
 */
static bool stage6_test_tls_openssl_peer(qsc_stage6_state* state, const char* certpath, unsigned int port)
{
	static const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
	static const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
	static const qsc_tls_signature_scheme schemes[1U] = { qsc_tls_sig_ecdsa_secp256r1_sha256 };
	qsc_tls_server_config config = { 0 };
	qsc_tls_server_state* tls;
	qsc_tls_certificate_view cert = { 0 };
	struct sockaddr_in address = { 0 };
	struct timeval timeout = { 0 };
	uint8_t certificate[QSC_STAGE6_BUFFER_SIZE] = { 0U };
	uint8_t record[20000U] = { 0U };
	uint8_t output[65536U] = { 0U };
	const uint8_t closealert[2U] = { 1U, 0U };
	uint16_t recordlen;
	size_t certlen;
	size_t consumed;
	size_t written;
	ssize_t received;
	qsc_tls_status tlsstatus;
	int server;
	int client;
	int allow;
	bool success;

	success = false;
	server = -1;
	client = -1;
	tls = NULL;

	if (port >= 1024U && port <= 65535U &&
		stage6_read_certificate(certpath, certificate, sizeof(certificate), &certlen) == true)
	{
		cert.data = certificate;
		cert.datalen = certlen;
		config.ciphersuitepreference = suites;
		config.ciphersuitepreferencecount = 1U;
		config.groupspreference = groups;
		config.groupspreferencecount = 1U;
		config.sigschemepreference = schemes;
		config.sigschemepreferencecount = 1U;
		tlsstatus = qsc_hw_pkcs11_tls_server_config_set_identity(&config, &cert, 1U, &state->signer);
		printf("Stage6 server identity status=%u\n", (unsigned int)tlsstatus);

		if (tlsstatus == qsc_tls_status_success)
		{
			tls = (qsc_tls_server_state*)qsc_memutils_malloc(sizeof(qsc_tls_server_state));

			if (tls != NULL)
			{
				tlsstatus = qsc_tls_server_initialize(tls, &config);
				printf("Stage6 server initialize status=%u\n", (unsigned int)tlsstatus);

				if (tlsstatus == qsc_tls_status_success)
				{
					server = socket(AF_INET, SOCK_STREAM, 0);

					if (server >= 0)
					{
						allow = 1;
						(void)setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &allow, sizeof(allow));
						address.sin_family = AF_INET;
						address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
						address.sin_port = htons((uint16_t)port);

						if (bind(server, (const struct sockaddr*)&address, sizeof(address)) == 0 &&
							listen(server, 1) == 0)
						{
							printf("Stage6 loopback TLS server READY port=%u\n", port);
							fflush(stdout);
							client = accept(server, NULL, NULL);

							if (client >= 0)
							{
								timeout.tv_sec = 10;
								(void)setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
								success = true;

								while (success == true && qsc_tls_server_is_handshake_complete(tls) == false)
								{
									received = recv(client, record, 5U, MSG_WAITALL);

									if (received != 5)
									{
										fprintf(stderr, "Stage6 TLS header read=%ld errno=%d\n", (long)received, errno);
										success = false;
									}
									else
									{
										recordlen = (uint16_t)(((uint16_t)record[3U] << 8U) | record[4U]);

										if ((size_t)recordlen + 5U > sizeof(record))
										{
											success = false;
										}
										else
										{
											received = recv(client, record + 5U, recordlen, MSG_WAITALL);

											if (received != (ssize_t)recordlen)
											{
												fprintf(stderr, "Stage6 TLS payload read=%ld expected=%u\n", (long)received, (unsigned int)recordlen);
												success = false;
											}
											else
											{
												consumed = 0U;
												written = 0U;
												tlsstatus = qsc_tls_server_process_record(tls, record,
													(size_t)recordlen + 5U, &consumed, output, sizeof(output), &written);
												printf("Stage6 TLS record type=%u status=%u consumed=%zu out=%zu phase=%u\n",
													(unsigned int)record[0U], (unsigned int)tlsstatus, consumed,
													written, (unsigned int)tls->phase);
												fflush(stdout);
												success = (tlsstatus == qsc_tls_status_success &&
													consumed == (size_t)recordlen + 5U &&
													stage6_send_all(client, output, written) == true);
											}
										}
									}
								}

								success = (qsc_tls_server_is_handshake_complete(tls) == true) && success;

								if (success == true)
								{
									written = 0U;
									tlsstatus = qsc_tls_record_encrypt(&tls->writerecord, output,
										sizeof(output), &written, qsc_tls_record_content_alert,
										closealert, sizeof(closealert));
									success = (tlsstatus == qsc_tls_status_success &&
										stage6_send_all(client, output, written) == true);
								}
							}
						}
					}
				}

				qsc_tls_server_dispose(tls);
				qsc_memutils_alloc_free(tls);
			}
		}
	}

	if (client >= 0)
	{
		(void)close(client);
	}
	if (server >= 0)
	{
		(void)close(server);
	}

	printf("%s: Stage6 QSC PKCS11 TLS 1.3 vs OpenSSL independent peer\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Reopen an already provisioned token test identity without creating or modifying its objects.
 * \param state Live authenticated session.
 * \return True if a persistent token P-256 key and signer can be reopened.
 */
static bool stage6_test_existing_key(qsc_stage6_state* state)
{
	qsc_hw_status status;
	bool success;

	status = qsc_hw_pkcs11_key_find(&state->key, state->session, qsc_stage6_keyid,
		sizeof(qsc_stage6_keyid), qsc_hw_algorithm_ecdsa_p256);
	success = (status == qsc_hw_status_success);

	if (success == true)
	{
		status = qsc_hw_pkcs11_tls_signer_initialize(&state->signer, state->key,
			qsc_tls_sig_ecdsa_secp256r1_sha256);
		success = (status == qsc_hw_status_success);
	}

	printf("%s: Stage6 reopen token identity for independent TLS peer\n", success ? "PASS" : "FAIL");
	return success;
}

/** \brief Execute every named Stage6 software-token qualification test directly in order.
 * \param argc Expected 4 arguments: executable, absolute module path, temporary DB directory, artifact directory.
 * \param argv Process argument strings, caller-owned.
 * \return EXIT_SUCCESS only when all named tests pass; no physical HSM claim is made.
 * \note This executable must run only with a disposable NSS DB prepared by the script.
 */
int main(int argc, char** argv)
{
	qsc_stage6_state state = { 0 };
	bool pass;
	bool next;

	printf("QSC Stage 6: real PKCS11 software-token cryptographic tests (NOT physical HSM qualification)\n");
	pass = (argc == 4 || argc == 6);

	if (pass == true)
	{
		state.artifactdir = argv[3U];
		if (argc == 6)
		{
			unsigned int port;

			port = (unsigned int)strtoul(argv[5U], NULL, 10);
			next = stage6_test_nss_initialize(&state, argv[1U], argv[2U]);
			pass = next && pass;

			if (next == true)
			{
				next = stage6_test_token_discovery(&state);
				pass = next && pass;
			}

			if (next == true)
			{
				next = stage6_test_existing_key(&state);
				pass = next && pass;
			}

			if (next == true)
			{
				next = stage6_test_tls_openssl_peer(&state, argv[4U], port);
				pass = next && pass;
			}
		}
		else
		{
		next = stage6_test_nss_initialize(&state, argv[1U], argv[2U]);
		pass = next && pass;

		if (next == true)
		{
			next = stage6_test_token_discovery(&state);
			pass = next && pass;
		}

		if (next == true)
		{
			next = stage6_test_key_generation(&state);
			pass = next && pass;
		}

		if (next == true)
		{
			next = stage6_test_private_export_denied(&state);
			pass = next && pass;
		}

		if (next == true)
		{
			next = stage6_test_tls_signature(&state);
			pass = next && pass;
		}

		if (next == true)
		{
			next = stage6_test_csr(&state);
			pass = next && pass;
		}

		if (next == true)
		{
			next = stage6_test_tls_policy(&state);
			pass = next && pass;
		}

		if (next == true)
		{
			next = stage6_test_persistent_key(&state);
			pass = next && pass;
		}

		}

		next = stage6_test_cleanup(&state);
		pass = next && pass;
	}
	else
	{
		fprintf(stderr, "Usage: hwpkcs11_stage6_test <absolute NSS module> <disposable NSS DB dir> <output dir> [leaf.der port]\n");
	}

	printf("QSC Stage 6 software-token test summary: %s\n", pass ? "PASS" : "FAIL");
	return pass ? EXIT_SUCCESS : EXIT_FAILURE;
}
