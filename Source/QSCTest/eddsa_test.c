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

#include "eddsa_test.h"
#include "qsctestcommon.h"
#include "nistrng.h"
#include "testutils.h"
#include "ed25519.h"
#include "eddsa.h"
#include "eddsa25519.h"
#include "eddsa448.h"
#include "intutils.h"
#include "sha2.h"
#include "transpose.h"

bool qsctest_eddsa_kat_test()
{
	uint8_t gpk[QSC_EDDSA_PUBLICKEY_SIZE] = { 0 };
	uint8_t gsk[QSC_EDDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ksd[QSC_EDDSA_SEED_SIZE] = { 0 };
	uint8_t kpk[QSC_EDDSA_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksk[QSC_EDDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kms[1U] = { 0 };
	uint8_t ksg[QSC_EDDSA_SIGNATURE_SIZE + 1U] = { 0 };
	uint8_t msg[1U] = { 0 };
	uint8_t sig[QSC_EDDSA_SIGNATURE_SIZE + 1U] = { 0 };
	size_t mlen;
	size_t slen;
	bool ret;

	mlen = 0U;
	slen = 0U;
	ret = true;

#if defined(QSC_EDDSA_S1EC25519)

	/* RFC 8032 Ed25519, 1-octet message vector */
	qsctest_hex_to_bin("4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB", ksd, sizeof(ksd));

	qsctest_hex_to_bin("3D4017C3E843895A92B70AA74D1B7EBC9C982CCF2EC4968CC0CD55F12AF4660C", kpk, sizeof(kpk));

	/* library private-key format: seed || publickey */
	qsctest_hex_to_bin("4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB"
		"3D4017C3E843895A92B70AA74D1B7EBC9C982CCF2EC4968CC0CD55F12AF4660C", ksk, sizeof(ksk));

	qsctest_hex_to_bin("72", kms, sizeof(kms));

	/* signed message = signature || message */
	qsctest_hex_to_bin("92A009A9F0D4CAB8720E820B5F642540A2B27B5416503F8FB3762223EBDB69DA"
		"085AC1E43E15996E458F3613D0F11D8C387B2EAEB4302AEEB00D291612BB0C0072", ksg, sizeof(ksg));

#elif defined(QSC_EDDSA_S3EC448)

	/* RFC 8032 Ed448, 1-octet message vector */
	qsctest_hex_to_bin("C4EAB05D357007C632F3DBB48489924D552B08FE0C353A0D4A1F00ACDA2C463A"
		"FBEA67C5E8D2877C5E3BC397A659949EF8021E954E0A12274E", ksd, sizeof(ksd));

	qsctest_hex_to_bin("43BA28F430CDFF456AE531545F7ECD0AC834A55D9358C0372BFA0C6C6798C086"
		"6AEA01EB00742802B8438EA4CB82169C235160627B4C3A9480", kpk, sizeof(kpk));

	/* library private-key format: seed || publickey */
	qsctest_hex_to_bin("C4EAB05D357007C632F3DBB48489924D552B08FE0C353A0D4A1F00ACDA2C463A"
		"FBEA67C5E8D2877C5E3BC397A659949EF8021E954E0A12274E43BA28F430CDFF"
		"456AE531545F7ECD0AC834A55D9358C0372BFA0C6C6798C0866AEA01EB007428"
		"02B8438EA4CB82169C235160627B4C3A9480", ksk, sizeof(ksk));

	qsctest_hex_to_bin("03", kms, sizeof(kms));

	/* signed message = signature || message */
	qsctest_hex_to_bin("26B8F91727BD62897AF15E41EB43C377EFB9C610D48F2335CB0BD0087810F435"
		"2541B143C4B981B7E18F62DE8CCDF633FC1BF037AB7CD779805E0DBCC0AAE1CB"
		"CEE1AFB2E027DF36BC04DCECBF154336C19F0AF7E0A6472905E799F1953D2A0F"
		"F3348AB21AA4ADAFD1D234441CF807C03A0003", ksg, sizeof(ksg));

#else
#	error "No parameter set has been selected!"
#endif

	qsc_eddsa_generate_seeded_keypair(gpk, gsk, ksd);

	if (qsc_intutils_are_equal8(kpk, gpk, sizeof(kpk)) != true)
	{
		qsctest_print_safe("Failure! qsctest_eddsa_kat_test: the public key generation does not match -EK1 \n");
		ret = false;
	}

	if (qsc_intutils_are_equal8(ksk, gsk, sizeof(ksk)) != true)
	{
		qsctest_print_safe("Failure! qsctest_eddsa_kat_test: the private key generation does not match -EK2 \n");
		ret = false;
	}

	qsc_eddsa_sign(sig, &slen, kms, sizeof(kms), ksk);

	if (qsc_intutils_are_equal8(ksg, sig, sizeof(ksg)) != true)
	{
		qsctest_print_safe("Failure! qsctest_eddsa_kat_test: the signature does not match -EK3 \n");
		ret = false;
	}

	if (qsc_eddsa_verify(msg, &mlen, ksg, sizeof(ksg), kpk) != true)
	{
		qsctest_print_safe("Failure! qsctest_eddsa_kat_test: signature verification has failed -EK4 \n");
		ret = false;
	}

	if (mlen != sizeof(kms))
	{
		qsctest_print_safe("Failure! qsctest_eddsa_kat_test: recovered message length is incorrect -EK5 \n");
		ret = false;
	}

	if (qsc_intutils_are_equal8(msg, kms, sizeof(kms)) != true)
	{
		qsctest_print_safe("Failure! qsctest_eddsa_kat_test: recovered message does not match -EK6 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_eddsa_privatekey_integrity()
{
	uint8_t msg[QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t mout[QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t sk[QSC_EDDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_EDDSA_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_eddsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip bits in the private key */
	for (size_t i = 0; i < 4; ++i)
	{
		sk[i] ^= 1U;
	}

	/* process message and return signed message */
	qsc_eddsa_sign(sig, &siglen, msg, QSCTEST_EDDSA_MSG0_SIZE, sk);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_eddsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_eddsa_privatekey_integrity: ECDSA message verification passed with altered secret key -ES1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_eddsa_publickey_integrity()
{
	uint8_t msg[QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t mout[QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t sk[QSC_EDDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_EDDSA_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_eddsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip 1 bit in the public key */
	pk[QSC_EDDSA_PUBLICKEY_SIZE - 1] ^= 1U;

	/* process message and return signed message */
	qsc_eddsa_sign(sig, &siglen, msg, QSCTEST_EDDSA_MSG0_SIZE, sk);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_eddsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_eddsa_publickey_integrity: ECDSA message verification passed with altered public key -EP1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_eddsa_signature_integrity()
{
	uint8_t msg[QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t mout[QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t sk[QSC_EDDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_EDDSA_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_eddsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* process message and return signed message */
	qsc_eddsa_sign(sig, &siglen, msg, QSCTEST_EDDSA_MSG0_SIZE, sk);

	/* flip 1 bit in the signed message */
	sig[siglen - 1] ^= 1U;

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_eddsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_eddsa_signature_integrity: ECDSA message verification passed with altered secret key -EI1 \n");
		ret = false;
	}

	/* flip one bit per hash; the signature is entirely hashes */
	for (size_t i = 0; i < 4U; ++i)
	{
		sig[i] ^= 1U;

		if (qsc_eddsa_verify(mout, &msglen, sig, siglen, pk) == true)
		{
			qsctest_print_safe("Failure! qsctest_eddsa_signature_integrity: ECDSA flipping bit did not invalidate signature -EI2 \n");
			sig[i] ^= 1U;
			ret = false;
			break;
		}

		sig[i] ^= 1U;
	}

	return ret;
}

bool qsctest_eddsa_stress_test()
{
	uint8_t msg[QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t mout[QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE] = { 0 };
	uint8_t sk[QSC_EDDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_EDDSA_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = QSCTEST_EDDSA_MSG0_SIZE;
	siglen = QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE; 
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the key-pair */
	qsc_eddsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	for (size_t i = 0; i < QSCTEST_EDDSA_ITERATIONS; i++)
	{
		/* sign the message and return the signed version in sig */
		qsc_eddsa_sign(sig, &siglen, msg, msglen, sk);

		if (siglen != QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_EDDSA_MSG0_SIZE)
		{
			qsctest_print_safe("Failure! qsctest_eddsa_stress_test: ECDSA signature length is incorrect -ES1 \n");
			ret = false;
			break;
		}

		/* verify the signature in sig and copy msg to mout */
		if (qsc_eddsa_verify(mout, &msglen, sig, siglen, pk) != true)
		{
			qsctest_print_safe("Failure! qsctest_eddsa_stress_test: ECDSA message verification has failed -ES2 \n");
			ret = false;
			break;
		}

		if (msglen != QSCTEST_EDDSA_MSG0_SIZE)
		{
			qsctest_print_safe("Failure! qsctest_eddsa_stress_test: ECDSA message length is incorrect -ES3 \n");
			ret = false;
			break;
		}
	}

	return ret;
}

/**
 * \brief Qualify Ed25519 independently of the default EdDSA selection.
 * \return true if the RFC 8032 key, signature, recovery and negative checks all pass.
 * \details Uses local, caller-owned arrays. No external mutable state.
 */
bool qsctest_eddsa25519_kat_test(void)
{
	uint8_t seed[QSC_ED25519_SEED_SIZE] = { 0U };
	uint8_t expectedpk[QSC_ED25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t expectedsig[QSC_ED25519_SIGNATURE_SIZE + 1U] = { 0U };
	uint8_t publickey[QSC_ED25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ED25519_PRIVATEKEY_SIZE] = { 0U };
	uint8_t signedmsg[QSC_ED25519_SIGNATURE_SIZE + 1U] = { 0U };
	uint8_t recovered[1U] = { 0U };
	uint8_t message[1U] = { 0U };
	size_t signedlen;
	size_t recoveredlen;
	bool res;

	res = true;
	signedlen = 0U;
	recoveredlen = 0U;
	qsctest_hex_to_bin("4CCD089B28FF96DA9DB6C346EC114E0F5B8A319F35ABA624DA8CF6ED4FB8A6FB", seed, sizeof(seed));
	qsctest_hex_to_bin("3D4017C3E843895A92B70AA74D1B7EBC9C982CCF2EC4968CC0CD55F12AF4660C", expectedpk, sizeof(expectedpk));
	qsctest_hex_to_bin("92A009A9F0D4CAB8720E820B5F642540A2B27B5416503F8FB3762223EBDB69DA085AC1E43E15996E458F3613D0F11D8C387B2EAEB4302AEEB00D291612BB0C0072", expectedsig, sizeof(expectedsig));
	qsctest_hex_to_bin("72", message, sizeof(message));

	qsc_ed25519_generate_seeded_keypair(publickey, privatekey, seed);

	if (qsc_intutils_are_equal8(publickey, expectedpk, sizeof(publickey)) != true)
	{
		qsctest_print_safe("Failure! Ed25519 independent RFC 8032 public-key vector.\n");
		res = false;
	}

	if (qsc_intutils_are_equal8(privatekey, seed, sizeof(seed)) != true || qsc_intutils_are_equal8(privatekey + sizeof(seed), expectedpk, sizeof(expectedpk)) != true)
	{
		qsctest_print_safe("Failure! Ed25519 independent secret-key layout.\n");
		res = false;
	}

	if (qsc_ed25519_sign(signedmsg, &signedlen, message, sizeof(message), privatekey) != true || signedlen != sizeof(signedmsg))
	{
		qsctest_print_safe("Failure! Ed25519 independent signing operation.\n");
		res = false;
	}

	if (qsc_intutils_are_equal8(signedmsg, expectedsig, sizeof(signedmsg)) != true)
	{
		qsctest_print_safe("Failure! Ed25519 independent RFC 8032 signature vector.\n");
		res = false;
	}

	if (qsc_ed25519_verify(recovered, &recoveredlen, expectedsig, sizeof(expectedsig), expectedpk) != true || recoveredlen != sizeof(recovered) || recovered[0U] != message[0U])
	{
		qsctest_print_safe("Failure! Ed25519 independent signature verification.\n");
		res = false;
	}

	/* Corrupt the signature, not the message, to enforce negative verification. */
	signedmsg[0U] ^= 1U;
	recoveredlen = 0U;

	if (qsc_ed25519_verify(recovered, &recoveredlen, signedmsg, sizeof(signedmsg), expectedpk) == true)
	{
		qsctest_print_safe("Failure! Ed25519 accepted a modified signature.\n");
		res = false;
	}

	return res;
}

/**
 * \brief Qualify Ed448 independently of the default EdDSA selection.
 * \return true if the RFC 8032 key, signature, recovery and negative checks all pass.
 * \details Uses local, caller-owned arrays. No external mutable state.
 */
bool qsctest_eddsa448_kat_test(void)
{
	uint8_t seed[QSC_ED448_SEED_SIZE] = { 0U };
	uint8_t expectedpk[QSC_ED448_PUBLICKEY_SIZE] = { 0U };
	uint8_t expectedsig[QSC_ED448_SIGNATURE_SIZE + 1U] = { 0U };
	uint8_t publickey[QSC_ED448_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ED448_PRIVATEKEY_SIZE] = { 0U };
	uint8_t signedmsg[QSC_ED448_SIGNATURE_SIZE + 1U] = { 0U };
	uint8_t recovered[1U] = { 0U };
	uint8_t message[1U] = { 0U };
	size_t signedlen;
	size_t recoveredlen;
	bool res;

	res = true;
	signedlen = 0U;
	recoveredlen = 0U;
	qsctest_hex_to_bin("C4EAB05D357007C632F3DBB48489924D552B08FE0C353A0D4A1F00ACDA2C463AFBEA67C5E8D2877C5E3BC397A659949EF8021E954E0A12274E", seed, sizeof(seed));
	qsctest_hex_to_bin("43BA28F430CDFF456AE531545F7ECD0AC834A55D9358C0372BFA0C6C6798C0866AEA01EB00742802B8438EA4CB82169C235160627B4C3A9480", expectedpk, sizeof(expectedpk));
	qsctest_hex_to_bin("26B8F91727BD62897AF15E41EB43C377EFB9C610D48F2335CB0BD0087810F4352541B143C4B981B7E18F62DE8CCDF633FC1BF037AB7CD779805E0DBCC0AAE1CBCEE1AFB2E027DF36BC04DCECBF154336C19F0AF7E0A6472905E799F1953D2A0FF3348AB21AA4ADAFD1D234441CF807C03A0003", expectedsig, sizeof(expectedsig));
	qsctest_hex_to_bin("03", message, sizeof(message));

	qsc_ed448_generate_seeded_keypair(publickey, privatekey, seed);

	if (qsc_intutils_are_equal8(publickey, expectedpk, sizeof(publickey)) != true)
	{
		qsctest_print_safe("Failure! Ed448 independent RFC 8032 public-key vector.\n");
		res = false;
	}

	if (qsc_intutils_are_equal8(privatekey, seed, sizeof(seed)) != true || qsc_intutils_are_equal8(privatekey + sizeof(seed), expectedpk, sizeof(expectedpk)) != true)
	{
		qsctest_print_safe("Failure! Ed448 independent secret-key layout.\n");
		res = false;
	}

	if (qsc_ed448_sign(signedmsg, &signedlen, message, sizeof(message), privatekey) != true || signedlen != sizeof(signedmsg))
	{
		qsctest_print_safe("Failure! Ed448 independent signing operation.\n");
		res = false;
	}

	if (qsc_intutils_are_equal8(signedmsg, expectedsig, sizeof(signedmsg)) != true)
	{
		qsctest_print_safe("Failure! Ed448 independent RFC 8032 signature vector.\n");
		res = false;
	}

	if (qsc_ed448_verify(recovered, &recoveredlen, expectedsig, sizeof(expectedsig), expectedpk) != true || recoveredlen != sizeof(recovered) || recovered[0U] != message[0U])
	{
		qsctest_print_safe("Failure! Ed448 independent signature verification.\n");
		res = false;
	}

	/* Corrupt the signature, not the message, to enforce negative verification. */
	signedmsg[0U] ^= 1U;
	recoveredlen = 0U;

	if (qsc_ed448_verify(recovered, &recoveredlen, signedmsg, sizeof(signedmsg), expectedpk) == true)
	{
		qsctest_print_safe("Failure! Ed448 accepted a modified signature.\n");
		res = false;
	}

	return res;
}

/**
 * \brief Verify the RFC 8032 Ed25519 empty-message test vector.
 * \return true on successful key generation, signing and verification, otherwise false.
 * \details Uses independent local buffers; no dynamic ownership or shared state.
 */
bool qsctest_eddsa25519_empty_kat_test(void)
{
	uint8_t seed[QSC_ED25519_SEED_SIZE] = { 0U };
	uint8_t expectedpk[QSC_ED25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t expectedsig[QSC_ED25519_SIGNATURE_SIZE] = { 0U };
	uint8_t publickey[QSC_ED25519_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ED25519_PRIVATEKEY_SIZE] = { 0U };
	uint8_t signedmsg[QSC_ED25519_SIGNATURE_SIZE] = { 0U };
	uint8_t recovered[1U] = { 0U };
	uint8_t empty[1U] = { 0U };
	size_t signedlen;
	size_t recoveredlen;
	bool res;

	res = true;
	signedlen = 0U;
	recoveredlen = 1U;
	qsctest_hex_to_bin("9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60", seed, sizeof(seed));
	qsctest_hex_to_bin("D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A", expectedpk, sizeof(expectedpk));
	qsctest_hex_to_bin("E5564300C360AC729086E2CC806E828A84877F1EB8E5D974D873E065224901555FB8821590A33BACC61E39701CF9B46BD25BF5F0595BBE24655141438E7A100B", expectedsig, sizeof(expectedsig));
	qsc_ed25519_generate_seeded_keypair(publickey, privatekey, seed);

	if (qsc_intutils_are_equal8(publickey, expectedpk, sizeof(publickey)) != true)
	{
		qsctest_print_safe("Failure! Ed25519 empty-message public-key KAT.\n");
		res = false;
	}

	if (qsc_ed25519_sign(signedmsg, &signedlen, empty, 0U, privatekey) != true || signedlen != sizeof(signedmsg))
	{
		qsctest_print_safe("Failure! Ed25519 empty-message signing.\n");
		res = false;
	}

	if (qsc_intutils_are_equal8(signedmsg, expectedsig, sizeof(expectedsig)) != true)
	{
		qsctest_print_safe("Failure! Ed25519 empty-message signature KAT.\n");
		res = false;
	}

	if (qsc_ed25519_verify(recovered, &recoveredlen, expectedsig, sizeof(expectedsig), expectedpk) != true || recoveredlen != 0U)
	{
		qsctest_print_safe("Failure! Ed25519 empty-message verification.\n");
		res = false;
	}

	return res;
}

/**
 * \brief Verify the RFC 8032 Ed448 empty-message test vector.
 * \return true on successful key generation, signing and verification, otherwise false.
 * \details Uses independent local buffers; no dynamic ownership or shared state.
 */
bool qsctest_eddsa448_empty_kat_test(void)
{
	uint8_t seed[QSC_ED448_SEED_SIZE] = { 0U };
	uint8_t expectedpk[QSC_ED448_PUBLICKEY_SIZE] = { 0U };
	uint8_t expectedsig[QSC_ED448_SIGNATURE_SIZE] = { 0U };
	uint8_t publickey[QSC_ED448_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ED448_PRIVATEKEY_SIZE] = { 0U };
	uint8_t signedmsg[QSC_ED448_SIGNATURE_SIZE] = { 0U };
	uint8_t recovered[1U] = { 0U };
	uint8_t empty[1U] = { 0U };
	size_t signedlen;
	size_t recoveredlen;
	bool res;

	res = true;
	signedlen = 0U;
	recoveredlen = 1U;
	qsctest_hex_to_bin("6C82A562CB808D10D632BE89C8513EBF6C929F34DDFA8C9F63C9960EF6E348A3528C8A3FCC2F044E39A3FC5B94492F8F032E7549A20098F95B", seed, sizeof(seed));
	qsctest_hex_to_bin("5FD7449B59B461FD2CE787EC616AD46A1DA1342485A70E1F8A0EA75D80E96778EDF124769B46C7061BD6783DF1E50F6CD1FA1ABEAFE8256180", expectedpk, sizeof(expectedpk));
	qsctest_hex_to_bin("533A37F6BBE457251F023C0D88F976AE2DFB504A843E34D2074FD823D41A591F2B233F034F628281F2FD7A22DDD47D7828C59BD0A21BFD3980FF0D2028D4B18A9DF63E006C5D1C2D345B925D8DC00B4104852DB99AC5C7CDDA8530A113A0F4DBB61149F05A7363268C71D95808FF2E652600", expectedsig, sizeof(expectedsig));
	qsc_ed448_generate_seeded_keypair(publickey, privatekey, seed);

	if (qsc_intutils_are_equal8(publickey, expectedpk, sizeof(publickey)) != true)
	{
		qsctest_print_safe("Failure! Ed448 empty-message public-key KAT.\n");
		res = false;
	}

	if (qsc_ed448_sign(signedmsg, &signedlen, empty, 0U, privatekey) != true || signedlen != sizeof(signedmsg))
	{
		qsctest_print_safe("Failure! Ed448 empty-message signing.\n");
		res = false;
	}

	if (qsc_intutils_are_equal8(signedmsg, expectedsig, sizeof(expectedsig)) != true)
	{
		qsctest_print_safe("Failure! Ed448 empty-message signature KAT.\n");
		res = false;
	}

	if (qsc_ed448_verify(recovered, &recoveredlen, expectedsig, sizeof(expectedsig), expectedpk) != true || recoveredlen != 0U)
	{
		qsctest_print_safe("Failure! Ed448 empty-message verification.\n");
		res = false;
	}

	return res;
}

void qsctest_eddsa_run()
{
	if (qsctest_eddsa25519_empty_kat_test() == true)
	{
		qsctest_print_safe("Success! Ed25519 independent empty-message RFC 8032 KAT passed.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Ed25519 independent empty-message RFC 8032 KAT failed.\n");
	}

	if (qsctest_eddsa448_empty_kat_test() == true)
	{
		qsctest_print_safe("Success! Ed448 independent empty-message RFC 8032 KAT passed.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Ed448 independent empty-message RFC 8032 KAT failed.\n");
	}

	if (qsctest_eddsa25519_kat_test() == true)
	{
		qsctest_print_safe("Success! Ed25519 independent RFC 8032 vectors and tamper test passed.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Ed25519 independent RFC 8032 vectors or tamper test failed.\n");
	}

	if (qsctest_eddsa448_kat_test() == true)
	{
		qsctest_print_safe("Success! Ed448 independent RFC 8032 vectors and tamper test passed.\n");
	}
	else
	{
		qsctest_print_safe("Failure! Ed448 independent RFC 8032 vectors or tamper test failed.\n");
	}

	if (qsctest_eddsa_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed EDDSA known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed EDDSA known answer test. \n");
	}

	if (qsctest_eddsa_stress_test() == true)
	{
		qsctest_print_safe("Success! The EDDSA stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! The EDDSA stress test has failed. \n");
	}

	if (qsctest_eddsa_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! The EDDSA altered public-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! The EDDSA altered public-key test has failed. \n");
	}

	if (qsctest_eddsa_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! The EDDSA altered secret-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! The EDDSA altered secret-key test has failed. \n");
	}

	if (qsctest_eddsa_signature_integrity() == true)
	{
		qsctest_print_safe("Success! The EDDSA altered signature test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! The EDDSA altered signature test has failed. \n");
	}
}
