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

#include "tls_stage37_parameter_variants_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "ecdsap256.h"
#include "ecdsap384.h"
#include "ecdsap521.h"
#include "eddsa25519.h"
#include "eddsa448.h"
#include "mldsa.h"
#include "memutils.h"
#include "tlsgroups.h"
#include "tlslimits.h"
#include "tlssigalgs.h"
#include "tlssignerdefault.h"

/**
 * \brief Test a specified named group's two-party shared-secret agreement.
 * \param group Exact TLS 1.3 named group to exercise independently of facade defaults.
 * \return True if both sides derive exactly the expected shared secret; otherwise false.
 * \note All temporary key material is caller-owned and erased before returning.
 */
static bool stage37_group_agreement(qsc_tls_named_group group)
{
	qsc_tls_key_exchange_state client;
	const qsc_tls_group_descriptor* desc;
	uint8_t serverkey[QSC_TLS_MAX_HYBRID_SERVER_KEYSHARE_SIZE] = { 0U };
	uint8_t serversecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
	uint8_t clientsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
	size_t serverkeylen;
	size_t serversecretlen;
	size_t clientsecretlen;
	qsc_tls_status status;
	bool res;

	qsc_memutils_clear(&client, sizeof(client));
	desc = qsc_tls_groups_descriptor_get(group);
	serverkeylen = 0U;
	serversecretlen = 0U;
	clientsecretlen = 0U;
	res = (desc != NULL);

	if (res == true)
	{
		status = qsc_tls_groups_generate_client_keypair(&client, group);
		res = (status == qsc_tls_status_success) && (client.publicsharelen == desc->clientpublicsize);
	}

	if (res == true)
	{
		status = qsc_tls_groups_server_respond(group, client.publicshare, client.publicsharelen, serverkey, sizeof(serverkey), &serverkeylen, serversecret, sizeof(serversecret), &serversecretlen);
		res = (status == qsc_tls_status_success) && (serverkeylen == desc->serverpublicsize) && (serversecretlen == desc->sharedsecretsize);
	}

	if (res == true)
	{
		status = qsc_tls_groups_client_derive_shared_secret(&client, serverkey, serverkeylen, clientsecret, sizeof(clientsecret), &clientsecretlen);
		res = (status == qsc_tls_status_success) && (clientsecretlen == serversecretlen) && qsc_memutils_are_equal(clientsecret, serversecret, clientsecretlen);
	}

	qsc_tls_groups_key_exchange_state_dispose(&client);
	qsc_memutils_secure_erase(serversecret, sizeof(serversecret));
	qsc_memutils_secure_erase(clientsecret, sizeof(clientsecret));

	return res;
}

/**
 * \brief Generate a key and validate the exact signature scheme with tamper rejection.
 * \param scheme Scheme to exercise independent of compile-time facade defaults.
 * \return True if key generation, signing and verification succeed and tampering fails.
 * \note All key and signature buffers are caller-owned and erased before return.
 */
static bool stage37_signature_roundtrip(qsc_tls_signature_scheme scheme)
{
	qsc_tls_signer_default_context signer;
	qsc_tls_certificate_view view;
	uint8_t privatekey[QSC_TLS_MAX_SIGNING_PRIVATE_KEY_SIZE] = { 0U };
	uint8_t publickey[QSC_MLDSA87_PUBLICKEY_SIZE] = { 0U };
	uint8_t signature[QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE] = { 0U };
	uint8_t input[48U] = { 0U };
	uint8_t p256seed[32U] = { 1U };
	uint8_t p384seed[48U] = { 1U };
	uint8_t p521seed[66U] = { 1U };
	size_t signaturelen;
	bool res;

	qsc_memutils_clear(&signer, sizeof(signer));
	qsc_memutils_clear(&view, sizeof(view));
	input[0U] = 0xA5U;
	res = false;

	switch (scheme)
	{
		case qsc_tls_sig_ecdsa_secp256r1_sha256:
		{
			res = (qsc_p256_keypair(publickey, privatekey, p256seed) == 0);
			break;
		}
		case qsc_tls_sig_ecdsa_secp384r1_sha384:
		{
			res = (qsc_p384_keypair(publickey, privatekey, p384seed) == 0);
			break;
		}
		case qsc_tls_sig_ecdsa_secp521r1_sha512:
		{
			res = (qsc_p521_keypair(publickey, privatekey, p521seed) == 0);
			break;
		}
		case qsc_tls_sig_ed25519:
		{
			qsc_ed25519_generate_keypair(publickey, privatekey, qsc_csp_generate);
			res = true;
			break;
		}
		case qsc_tls_sig_ed448:
		{
			qsc_ed448_generate_keypair(publickey, privatekey, qsc_csp_generate);
			res = true;
			break;
		}
		case qsc_tls_sig_mldsa44:
		{
			res = qsc_mldsa44_generate_keypair(publickey, privatekey, qsc_csp_generate);
			break;
		}
		case qsc_tls_sig_mldsa65:
		{
			res = qsc_mldsa65_generate_keypair(publickey, privatekey, qsc_csp_generate);
			break;
		}
		case qsc_tls_sig_mldsa87:
		{
			res = qsc_mldsa87_generate_keypair(publickey, privatekey, qsc_csp_generate);
			break;
		}
		default:
		{
			break;
		}
	}

	if (res == true)
	{
		signer.scheme = scheme;
		signer.privatekey = privatekey;
		signer.privatekeylen = qsc_tls_signature_scheme_private_key_size(scheme);
		view.data = publickey;
		view.datalen = qsc_tls_signature_scheme_public_key_size(scheme);
		signaturelen = sizeof(signature);
		res = qsc_tls_signer_default_sign(scheme, input, sizeof(input), signature, &signaturelen, &signer);
	}

	if (res == true)
	{
		res = qsc_tls_signer_default_verify(scheme, input, sizeof(input), signature, signaturelen, &view, NULL);
	}

	if (res == true)
	{
		signature[0U] ^= 0x01U;
		res = (qsc_tls_signer_default_verify(scheme, input, sizeof(input), signature, signaturelen, &view, NULL) == false);
	}

	qsc_memutils_secure_erase(p256seed, sizeof(p256seed));
	qsc_memutils_secure_erase(p384seed, sizeof(p384seed));
	qsc_memutils_secure_erase(p521seed, sizeof(p521seed));
	qsc_memutils_secure_erase(privatekey, sizeof(privatekey));
	qsc_memutils_secure_erase(signature, sizeof(signature));
	return res;
}

/** \brief Validate X25519 group agreement. \return True if agreement succeeds. */
static bool stage37_group_x25519_test(void)
{
	return stage37_group_agreement(qsc_tls_group_x25519);
}

/** \brief Validate X448 group agreement. \return True if agreement succeeds. */
static bool stage37_group_x448_test(void)
{
	return stage37_group_agreement(qsc_tls_group_x448);
}

/** \brief Validate P-256 group agreement. \return True if agreement succeeds. */
static bool stage37_group_p256_test(void)
{
	return stage37_group_agreement(qsc_tls_group_secp256r1);
}

/** \brief Validate P-384 group agreement. \return True if agreement succeeds. */
static bool stage37_group_p384_test(void)
{
	return stage37_group_agreement(qsc_tls_group_secp384r1);
}

/** \brief Validate P-521 group agreement. \return True if agreement succeeds. */
static bool stage37_group_p521_test(void)
{
	return stage37_group_agreement(qsc_tls_group_secp521r1);
}

/** \brief Validate ML-KEM-512 group agreement. \return True if agreement succeeds. */
static bool stage37_group_mlkem512_test(void)
{
	return stage37_group_agreement(qsc_tls_group_mlkem512);
}

/** \brief Validate ML-KEM-768 group agreement. \return True if agreement succeeds. */
static bool stage37_group_mlkem768_test(void)
{
	return stage37_group_agreement(qsc_tls_group_mlkem768);
}

/** \brief Validate ML-KEM-1024 group agreement. \return True if agreement succeeds. */
static bool stage37_group_mlkem1024_test(void)
{
	return stage37_group_agreement(qsc_tls_group_mlkem1024);
}

/** \brief Validate X25519MLKEM768 group agreement. \return True if agreement succeeds. */
static bool stage37_group_x25519_mlkem768_test(void)
{
	return stage37_group_agreement(qsc_tls_group_x25519_mlkem768);
}

/** \brief Validate SecP256r1MLKEM768 group agreement. \return True if agreement succeeds. */
static bool stage37_group_p256_mlkem768_test(void)
{
	return stage37_group_agreement(qsc_tls_group_secp256r1_mlkem768);
}

/** \brief Validate SecP384r1MLKEM1024 group agreement. \return True if agreement succeeds. */
static bool stage37_group_p384_mlkem1024_test(void)
{
	return stage37_group_agreement(qsc_tls_group_secp384r1_mlkem1024);
}

/** \brief Validate ECDSA P-256 signing and tamper rejection. \return True if checks pass. */
static bool stage37_sign_p256_test(void)
{
	return stage37_signature_roundtrip(qsc_tls_sig_ecdsa_secp256r1_sha256);
}

/** \brief Validate ECDSA P-384 signing and tamper rejection. \return True if checks pass. */
static bool stage37_sign_p384_test(void)
{
	return stage37_signature_roundtrip(qsc_tls_sig_ecdsa_secp384r1_sha384);
}

/** \brief Validate ECDSA P-521 signing and tamper rejection. \return True if checks pass. */
static bool stage37_sign_p521_test(void)
{
	return stage37_signature_roundtrip(qsc_tls_sig_ecdsa_secp521r1_sha512);
}

/** \brief Validate Ed25519 signing and tamper rejection. \return True if checks pass. */
static bool stage37_sign_ed25519_test(void)
{
	return stage37_signature_roundtrip(qsc_tls_sig_ed25519);
}

/** \brief Validate Ed448 signing and tamper rejection. \return True if checks pass. */
static bool stage37_sign_ed448_test(void)
{
	return stage37_signature_roundtrip(qsc_tls_sig_ed448);
}

/** \brief Validate ML-DSA-44 signing and tamper rejection. \return True if checks pass. */
static bool stage37_sign_mldsa44_test(void)
{
	return stage37_signature_roundtrip(qsc_tls_sig_mldsa44);
}

/** \brief Validate ML-DSA-65 signing and tamper rejection. \return True if checks pass. */
static bool stage37_sign_mldsa65_test(void)
{
	return stage37_signature_roundtrip(qsc_tls_sig_mldsa65);
}

/** \brief Validate ML-DSA-87 signing and tamper rejection. \return True if checks pass. */
static bool stage37_sign_mldsa87_test(void)
{
	return stage37_signature_roundtrip(qsc_tls_sig_mldsa87);
}

/** \brief Execute all TLS parameter-variant tests sequentially. \return True if all checks pass. */
bool qsctest_tls_stage37_tests(void)
{
	bool res;

	res = true;

	if (stage37_group_x25519_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group X25519 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group X25519 independent agreement.");
		res = false;
	}

	if (stage37_group_x448_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group X448 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group X448 independent agreement.");
		res = false;
	}

	if (stage37_group_p256_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group P-256 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group P-256 independent agreement.");
		res = false;
	}

	if (stage37_group_p384_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group P-384 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group P-384 independent agreement.");
		res = false;
	}

	if (stage37_group_p521_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group P-521 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group P-521 independent agreement.");
		res = false;
	}

	if (stage37_group_mlkem512_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group ML-KEM-512 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group ML-KEM-512 independent agreement.");
		res = false;
	}

	if (stage37_group_mlkem768_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group ML-KEM-768 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group ML-KEM-768 independent agreement.");
		res = false;
	}

	if (stage37_group_mlkem1024_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group ML-KEM-1024 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group ML-KEM-1024 independent agreement.");
		res = false;
	}

	if (stage37_group_x25519_mlkem768_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group X25519MLKEM768 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group X25519MLKEM768 independent agreement.");
		res = false;
	}

	if (stage37_group_p256_mlkem768_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group SecP256r1MLKEM768 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group SecP256r1MLKEM768 independent agreement.");
		res = false;
	}

	if (stage37_group_p384_mlkem1024_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 group SecP384r1MLKEM1024 independent agreement.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 group SecP384r1MLKEM1024 independent agreement.");
		res = false;
	}

	if (stage37_sign_p256_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 ECDSA P-256 sign, verify and tamper rejection.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 ECDSA P-256 sign, verify and tamper rejection.");
		res = false;
	}

	if (stage37_sign_p384_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 ECDSA P-384 sign, verify and tamper rejection.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 ECDSA P-384 sign, verify and tamper rejection.");
		res = false;
	}

	if (stage37_sign_p521_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 ECDSA P-521 sign, verify and tamper rejection.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 ECDSA P-521 sign, verify and tamper rejection.");
		res = false;
	}

	if (stage37_sign_ed25519_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 Ed25519 sign, verify and tamper rejection.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 Ed25519 sign, verify and tamper rejection.");
		res = false;
	}

	if (stage37_sign_ed448_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 Ed448 sign, verify and tamper rejection.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 Ed448 sign, verify and tamper rejection.");
		res = false;
	}

	if (stage37_sign_mldsa44_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 ML-DSA-44 sign, verify and tamper rejection.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 ML-DSA-44 sign, verify and tamper rejection.");
		res = false;
	}

	if (stage37_sign_mldsa65_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 ML-DSA-65 sign, verify and tamper rejection.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 ML-DSA-65 sign, verify and tamper rejection.");
		res = false;
	}

	if (stage37_sign_mldsa87_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 37 ML-DSA-87 sign, verify and tamper rejection.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 37 ML-DSA-87 sign, verify and tamper rejection.");
		res = false;
	}

	return res;
}
