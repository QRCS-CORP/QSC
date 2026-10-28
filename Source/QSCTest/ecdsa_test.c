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

#include "ecdsa_test.h"
#include "qsctestcommon.h"
#include "nistrng.h"
#include "testutils.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"
#include "ecdsa.h"
#include "ecdsap256.h"
#include "ecdsap384.h"
#include "ecdsap521.h"


/**
 * \brief Qualify independently exported ECDSA P-256 functions against RFC 6979.
 * \return true when both signatures, public-key derivation and deterministic signing match the vectors.
 * \details Stateless test. Exercises a fixed scalar and public key using caller-owned buffers.
 */
bool qsctest_ecdsap256_kat_test(void)
{
	uint8_t msg0[] = { 0x73U, 0x61U, 0x6DU, 0x70U, 0x6CU, 0x65U };
	uint8_t msg1[] = { 0x74U, 0x65U, 0x73U, 0x74U };
	uint8_t recovered[sizeof(msg0)] = { 0U };
	uint8_t pk[QSC_ECDSAP256_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSAP256_SEED_SIZE] = { 0U };
	uint8_t expk[QSC_ECDSAP256_PUBLICKEY_SIZE] = { 0U };
	uint8_t sig0[QSC_ECDSAP256_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	uint8_t sig1[QSC_ECDSAP256_SIGNATURE_SIZE + sizeof(msg1)] = { 0U };
	uint8_t gensig[QSC_ECDSAP256_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	size_t mlen;
	size_t slen;
	bool res;

	mlen = 0U;
	slen = 0U;
	res = true;


/* RFC 6979 A.2.5 private key x */
	qsctest_hex_to_bin("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", sk, 32U);

	/* RFC 6979 A.2.5 public key U = xG */
	qsctest_hex_to_bin("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", expk, 32U);
	qsctest_hex_to_bin("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", expk + 32U, 32U);

	/* RFC 6979 A.2.5 signature for SHA-256, message = "sample" */
	qsctest_hex_to_bin("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", sig0, 32U);
	qsctest_hex_to_bin("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", sig0 + 32U, 32U);
	qsc_memutils_copy(sig0 + QSC_ECDSAP256_SIGNATURE_SIZE, msg0, sizeof(msg0));

	/* RFC 6979 A.2.5 signature for SHA-256, message = "test" */
	qsctest_hex_to_bin("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", sig1, 32U);
	qsctest_hex_to_bin("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083", sig1 + 32U, 32U);
	qsc_memutils_copy(sig1 + QSC_ECDSAP256_SIGNATURE_SIZE, msg1, sizeof(msg1));


	if (qsc_p256_publickey_from_privatekey(pk, sk) != 0 || qsc_intutils_are_equal8(pk, expk, sizeof(expk)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-256 RFC 6979 public key derivation.\n");
		res = false;
	}

	if (qsc_p256_verify(recovered, &mlen, sig0, sizeof(sig0), pk) == false || mlen != sizeof(msg0) || qsc_intutils_are_equal8(recovered, msg0, sizeof(msg0)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-256 RFC 6979 sample signature verification.\n");
		res = false;
	}

	qsc_memutils_clear(recovered, sizeof(recovered));
	mlen = 0U;

	if (qsc_p256_verify(recovered, &mlen, sig1, sizeof(sig1), pk) == false || mlen != sizeof(msg1) || qsc_intutils_are_equal8(recovered, msg1, sizeof(msg1)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-256 RFC 6979 test signature verification.\n");
		res = false;
	}

	if (qsc_p256_sign_scalar(gensig, &slen, msg0, sizeof(msg0), sk) != 0 || slen != sizeof(gensig) || qsc_intutils_are_equal8(gensig, sig0, sizeof(sig0)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-256 RFC 6979 deterministic signing.\n");
		res = false;
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	return res;
}

/**
 * \brief Check direct ECDSA P-256 seeded keypair, round-trip and negative signature paths.
 * \return true when all directly addressed parameter-set operations behave as required.
 * \details Stateless; buffers are caller owned. No implicit default-curve dependency.
 */
bool qsctest_ecdsap256_api_test(void)
{
	uint8_t seed[QSC_ECDSAP256_SEED_SIZE] = { 0U };
	uint8_t publickey[QSC_ECDSAP256_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ECDSAP256_PRIVATEKEY_SIZE] = { 0U };
	uint8_t message[] = { 0x51U, 0x53U, 0x43U, 0x20U, 0x45U, 0x43U, 0x44U, 0x53U, 0x41U };
	uint8_t recovered[sizeof(message)] = { 0U };
	uint8_t signedmsg[QSC_ECDSAP256_SIGNATURE_SIZE + sizeof(message)] = { 0U };
	size_t recoveredlen;
	size_t signedlen;
	bool res;

	res = true;
	recoveredlen = 0U;
	signedlen = 0U;
	seed[sizeof(seed) - 1U] = 1U;

	if (qsc_p256_keypair(publickey, privatekey, seed) != 0)
	{
		qsctest_print_safe("Failure! ECDSA P-256 seeded keypair.\n");
		res = false;
	}
	else if (qsc_intutils_are_equal8(privatekey + QSC_ECDSAP256_SEED_SIZE, publickey, sizeof(publickey)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-256 private-key public-coordinate binding.\n");
		res = false;
	}
	else if (qsc_p256_sign(signedmsg, &signedlen, message, sizeof(message), privatekey) != 0 || signedlen != sizeof(signedmsg))
	{
		qsctest_print_safe("Failure! ECDSA P-256 seeded signing.\n");
		res = false;
	}
	else if (qsc_p256_verify(recovered, &recoveredlen, signedmsg, signedlen, publickey) == false || recoveredlen != sizeof(message) || qsc_intutils_are_equal8(recovered, message, sizeof(message)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-256 sign/verify round trip.\n");
		res = false;
	}
	else
	{
		signedmsg[0U] ^= 1U;
		recoveredlen = 0U;

		if (qsc_p256_verify(recovered, &recoveredlen, signedmsg, signedlen, publickey) == true)
		{
			qsctest_print_safe("Failure! ECDSA P-256 accepted modified signature.\n");
			res = false;
		}
		signedmsg[0U] ^= 1U;
		publickey[0U] ^= 1U;
		recoveredlen = 0U;

		if (qsc_p256_verify(recovered, &recoveredlen, signedmsg, signedlen, publickey) == true)
		{
			qsctest_print_safe("Failure! ECDSA P-256 accepted modified public key.\n");
			res = false;
		}
		publickey[0U] ^= 1U;

	}

	qsc_memutils_secure_erase(privatekey, sizeof(privatekey));
	return res;
}

/**
 * \brief Qualify independently exported ECDSA P-384 functions against RFC 6979.
 * \return true when both signatures, public-key derivation and deterministic signing match the vectors.
 * \details Stateless test. Exercises a fixed scalar and public key using caller-owned buffers.
 */
bool qsctest_ecdsap384_kat_test(void)
{
	uint8_t msg0[] = { 0x73U, 0x61U, 0x6DU, 0x70U, 0x6CU, 0x65U };
	uint8_t msg1[] = { 0x74U, 0x65U, 0x73U, 0x74U };
	uint8_t recovered[sizeof(msg0)] = { 0U };
	uint8_t pk[QSC_ECDSAP384_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSAP384_SEED_SIZE] = { 0U };
	uint8_t expk[QSC_ECDSAP384_PUBLICKEY_SIZE] = { 0U };
	uint8_t sig0[QSC_ECDSAP384_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	uint8_t sig1[QSC_ECDSAP384_SIGNATURE_SIZE + sizeof(msg1)] = { 0U };
	uint8_t gensig[QSC_ECDSAP384_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	size_t mlen;
	size_t slen;
	bool res;

	mlen = 0U;
	slen = 0U;
	res = true;


	/* RFC 6979 A.2.6 private key x */
	qsctest_hex_to_bin("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5", sk, 48U);

	/* RFC 6979 A.2.6 public key U = xG */
	qsctest_hex_to_bin("EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13", expk, 48U);
	qsctest_hex_to_bin("8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720", expk + 48U, 48U);

	/* RFC 6979 A.2.6 signature for SHA-384, message = "sample" */
	qsctest_hex_to_bin("94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46", sig0, 48U);
	qsctest_hex_to_bin("99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8", sig0 + 48U, 48U);
	qsc_memutils_copy(sig0 + QSC_ECDSAP384_SIGNATURE_SIZE, msg0, sizeof(msg0));

	/* RFC 6979 A.2.6 signature for SHA-384, message = "test" */
	qsctest_hex_to_bin("8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB", sig1, 48U);
	qsctest_hex_to_bin("DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5", sig1 + 48U, 48U);
	qsc_memutils_copy(sig1 + QSC_ECDSAP384_SIGNATURE_SIZE, msg1, sizeof(msg1));


	if (qsc_p384_publickey_from_privatekey(pk, sk) != 0 || qsc_intutils_are_equal8(pk, expk, sizeof(expk)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-384 RFC 6979 public key derivation.\n");
		res = false;
	}

	if (qsc_p384_verify(recovered, &mlen, sig0, sizeof(sig0), pk) == false || mlen != sizeof(msg0) || qsc_intutils_are_equal8(recovered, msg0, sizeof(msg0)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-384 RFC 6979 sample signature verification.\n");
		res = false;
	}

	qsc_memutils_clear(recovered, sizeof(recovered));
	mlen = 0U;

	if (qsc_p384_verify(recovered, &mlen, sig1, sizeof(sig1), pk) == false || mlen != sizeof(msg1) || qsc_intutils_are_equal8(recovered, msg1, sizeof(msg1)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-384 RFC 6979 test signature verification.\n");
		res = false;
	}

	if (qsc_p384_sign_scalar(gensig, &slen, msg0, sizeof(msg0), sk) != 0 || slen != sizeof(gensig) || qsc_intutils_are_equal8(gensig, sig0, sizeof(sig0)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-384 RFC 6979 deterministic signing.\n");
		res = false;
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	return res;
}

/**
 * \brief Check direct ECDSA P-384 seeded keypair, round-trip and negative signature paths.
 * \return true when all directly addressed parameter-set operations behave as required.
 * \details Stateless; buffers are caller owned. No implicit default-curve dependency.
 */
bool qsctest_ecdsap384_api_test(void)
{
	uint8_t seed[QSC_ECDSAP384_SEED_SIZE] = { 0U };
	uint8_t publickey[QSC_ECDSAP384_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ECDSAP384_PRIVATEKEY_SIZE] = { 0U };
	uint8_t message[] = { 0x51U, 0x53U, 0x43U, 0x20U, 0x45U, 0x43U, 0x44U, 0x53U, 0x41U };
	uint8_t recovered[sizeof(message)] = { 0U };
	uint8_t signedmsg[QSC_ECDSAP384_SIGNATURE_SIZE + sizeof(message)] = { 0U };
	size_t recoveredlen;
	size_t signedlen;
	bool res;

	res = true;
	recoveredlen = 0U;
	signedlen = 0U;
	seed[sizeof(seed) - 1U] = 1U;

	if (qsc_p384_keypair(publickey, privatekey, seed) != 0)
	{
		qsctest_print_safe("Failure! ECDSA P-384 seeded keypair.\n");
		res = false;
	}
	else if (qsc_intutils_are_equal8(privatekey + QSC_ECDSAP384_SEED_SIZE, publickey, sizeof(publickey)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-384 private-key public-coordinate binding.\n");
		res = false;
	}
	else if (qsc_p384_sign(signedmsg, &signedlen, message, sizeof(message), privatekey) != 0 || signedlen != sizeof(signedmsg))
	{
		qsctest_print_safe("Failure! ECDSA P-384 seeded signing.\n");
		res = false;
	}
	else if (qsc_p384_verify(recovered, &recoveredlen, signedmsg, signedlen, publickey) == false || recoveredlen != sizeof(message) || qsc_intutils_are_equal8(recovered, message, sizeof(message)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-384 sign/verify round trip.\n");
		res = false;
	}
	else
	{
		signedmsg[0U] ^= 1U;
		recoveredlen = 0U;

		if (qsc_p384_verify(recovered, &recoveredlen, signedmsg, signedlen, publickey) == true)
		{
			qsctest_print_safe("Failure! ECDSA P-384 accepted modified signature.\n");
			res = false;
		}
		signedmsg[0U] ^= 1U;
		publickey[0U] ^= 1U;
		recoveredlen = 0U;

		if (qsc_p384_verify(recovered, &recoveredlen, signedmsg, signedlen, publickey) == true)
		{
			qsctest_print_safe("Failure! ECDSA P-384 accepted modified public key.\n");
			res = false;
		}
		publickey[0U] ^= 1U;

	}

	qsc_memutils_secure_erase(privatekey, sizeof(privatekey));
	return res;
}

/**
 * \brief Qualify independently exported ECDSA P-521 functions against RFC 6979.
 * \return true when both signatures, public-key derivation and deterministic signing match the vectors.
 * \details Stateless test. Exercises a fixed scalar and public key using caller-owned buffers.
 */
bool qsctest_ecdsap521_kat_test(void)
{
	uint8_t msg0[] = { 0x73U, 0x61U, 0x6DU, 0x70U, 0x6CU, 0x65U };
	uint8_t msg1[] = { 0x74U, 0x65U, 0x73U, 0x74U };
	uint8_t recovered[sizeof(msg0)] = { 0U };
	uint8_t pk[QSC_ECDSAP521_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSAP521_SEED_SIZE] = { 0U };
	uint8_t expk[QSC_ECDSAP521_PUBLICKEY_SIZE] = { 0U };
	uint8_t sig0[QSC_ECDSAP521_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	uint8_t sig1[QSC_ECDSAP521_SIGNATURE_SIZE + sizeof(msg1)] = { 0U };
	uint8_t gensig[QSC_ECDSAP521_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	size_t mlen;
	size_t slen;
	bool res;

	mlen = 0U;
	slen = 0U;
	res = true;


/* RFC 6979 A.2.7 private key x */
	qsctest_hex_to_bin("00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75"
		"CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538", sk, 66U);

	/* RFC 6979 A.2.7 public key U = xG */
	qsctest_hex_to_bin("01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD"
		"371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4", expk, 66U);
	qsctest_hex_to_bin("00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A"
		"28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5", expk + 66U, 66U);

	/* RFC 6979 A.2.7 signature for SHA-512, message = "sample" */
	qsctest_hex_to_bin("00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F"
		"174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA", sig0, 66U);
	qsctest_hex_to_bin("00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF"
		"282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A", sig0 + 66U, 66U);
	qsc_memutils_copy(sig0 + QSC_ECDSAP521_SIGNATURE_SIZE, msg0, sizeof(msg0));

	/* RFC 6979 A.2.7 signature for SHA-512, message = "test" */
	qsctest_hex_to_bin("013E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F1"
		"0CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D", sig1, 66U);
	qsctest_hex_to_bin("01FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E7"
		"8A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3", sig1 + 66U, 66U);
	qsc_memutils_copy(sig1 + QSC_ECDSAP521_SIGNATURE_SIZE, msg1, sizeof(msg1));


	if (qsc_p521_publickey_from_privatekey(pk, sk) != 0 || qsc_intutils_are_equal8(pk, expk, sizeof(expk)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-521 RFC 6979 public key derivation.\n");
		res = false;
	}

	if (qsc_p521_verify(recovered, &mlen, sig0, sizeof(sig0), pk) == false || mlen != sizeof(msg0) || qsc_intutils_are_equal8(recovered, msg0, sizeof(msg0)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-521 RFC 6979 sample signature verification.\n");
		res = false;
	}

	qsc_memutils_clear(recovered, sizeof(recovered));
	mlen = 0U;

	if (qsc_p521_verify(recovered, &mlen, sig1, sizeof(sig1), pk) == false || mlen != sizeof(msg1) || qsc_intutils_are_equal8(recovered, msg1, sizeof(msg1)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-521 RFC 6979 test signature verification.\n");
		res = false;
	}

	if (qsc_p521_sign_scalar(gensig, &slen, msg0, sizeof(msg0), sk) != 0 || slen != sizeof(gensig) || qsc_intutils_are_equal8(gensig, sig0, sizeof(sig0)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-521 RFC 6979 deterministic signing.\n");
		res = false;
	}

	qsc_memutils_secure_erase(sk, sizeof(sk));
	return res;
}

/**
 * \brief Check direct ECDSA P-521 seeded keypair, round-trip and negative signature paths.
 * \return true when all directly addressed parameter-set operations behave as required.
 * \details Stateless; buffers are caller owned. No implicit default-curve dependency.
 */
bool qsctest_ecdsap521_api_test(void)
{
	uint8_t seed[QSC_ECDSAP521_SEED_SIZE] = { 0U };
	uint8_t publickey[QSC_ECDSAP521_PUBLICKEY_SIZE] = { 0U };
	uint8_t privatekey[QSC_ECDSAP521_PRIVATEKEY_SIZE] = { 0U };
	uint8_t message[] = { 0x51U, 0x53U, 0x43U, 0x20U, 0x45U, 0x43U, 0x44U, 0x53U, 0x41U };
	uint8_t recovered[sizeof(message)] = { 0U };
	uint8_t signedmsg[QSC_ECDSAP521_SIGNATURE_SIZE + sizeof(message)] = { 0U };
	size_t recoveredlen;
	size_t signedlen;
	bool res;

	res = true;
	recoveredlen = 0U;
	signedlen = 0U;
	seed[sizeof(seed) - 1U] = 1U;

	if (qsc_p521_keypair(publickey, privatekey, seed) != 0)
	{
		qsctest_print_safe("Failure! ECDSA P-521 seeded keypair.\n");
		res = false;
	}
	else if (qsc_intutils_are_equal8(privatekey + QSC_ECDSAP521_SEED_SIZE, publickey, sizeof(publickey)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-521 private-key public-coordinate binding.\n");
		res = false;
	}
	else if (qsc_p521_sign(signedmsg, &signedlen, message, sizeof(message), privatekey) != 0 || signedlen != sizeof(signedmsg))
	{
		qsctest_print_safe("Failure! ECDSA P-521 seeded signing.\n");
		res = false;
	}
	else if (qsc_p521_verify(recovered, &recoveredlen, signedmsg, signedlen, publickey) == false || recoveredlen != sizeof(message) || qsc_intutils_are_equal8(recovered, message, sizeof(message)) == false)
	{
		qsctest_print_safe("Failure! ECDSA P-521 sign/verify round trip.\n");
		res = false;
	}
	else
	{
		signedmsg[0U] ^= 1U;
		recoveredlen = 0U;

		if (qsc_p521_verify(recovered, &recoveredlen, signedmsg, signedlen, publickey) == true)
		{
			qsctest_print_safe("Failure! ECDSA P-521 accepted modified signature.\n");
			res = false;
		}
		signedmsg[0U] ^= 1U;
		publickey[0U] ^= 1U;
		recoveredlen = 0U;

		if (qsc_p521_verify(recovered, &recoveredlen, signedmsg, signedlen, publickey) == true)
		{
			qsctest_print_safe("Failure! ECDSA P-521 accepted modified public key.\n");
			res = false;
		}
		publickey[0U] ^= 1U;

	}

	qsc_memutils_secure_erase(privatekey, sizeof(privatekey));
	return res;
}

bool qsctest_ecdsa_kat_test(void)
{
	uint8_t msg0[] = { 0x73U, 0x61U, 0x6DU, 0x70U, 0x6CU, 0x65U };
	uint8_t msg1[] = { 0x74U, 0x65U, 0x73U, 0x74U };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t expk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t sig0[QSC_ECDSA_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	uint8_t sig1[QSC_ECDSA_SIGNATURE_SIZE + sizeof(msg1)] = { 0U };
	uint8_t gensig[QSC_ECDSA_SIGNATURE_SIZE + sizeof(msg0)] = { 0U };
	size_t mlen;
	size_t slen;
	bool res;

	mlen = 0U;
	slen = 0U;
	res = true;

#if defined(QSC_ECDSA_S1P256)

/* RFC 6979 A.2.5 private key x */
	qsctest_hex_to_bin("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", sk, 32U);

	/* RFC 6979 A.2.5 public key U = xG */
	qsctest_hex_to_bin("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", expk, 32U);
	qsctest_hex_to_bin("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", expk + 32U, 32U);

	/* RFC 6979 A.2.5 signature for SHA-256, message = "sample" */
	qsctest_hex_to_bin("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", sig0, 32U);
	qsctest_hex_to_bin("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", sig0 + 32U, 32U);
	qsc_memutils_copy(sig0 + QSC_ECDSA_SIGNATURE_SIZE, msg0, sizeof(msg0));

	/* RFC 6979 A.2.5 signature for SHA-256, message = "test" */
	qsctest_hex_to_bin("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367", sig1, 32U);
	qsctest_hex_to_bin("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083", sig1 + 32U, 32U);
	qsc_memutils_copy(sig1 + QSC_ECDSA_SIGNATURE_SIZE, msg1, sizeof(msg1));

#elif defined(QSC_ECDSA_S3P384)

	/* RFC 6979 A.2.6 private key x */
	qsctest_hex_to_bin("6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5", sk, 48U);

	/* RFC 6979 A.2.6 public key U = xG */
	qsctest_hex_to_bin("EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13", expk, 48U);
	qsctest_hex_to_bin("8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720", expk + 48U, 48U);

	/* RFC 6979 A.2.6 signature for SHA-384, message = "sample" */
	qsctest_hex_to_bin("94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46", sig0, 48U);
	qsctest_hex_to_bin("99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8", sig0 + 48U, 48U);
	qsc_memutils_copy(sig0 + QSC_ECDSA_SIGNATURE_SIZE, msg0, sizeof(msg0));

	/* RFC 6979 A.2.6 signature for SHA-384, message = "test" */
	qsctest_hex_to_bin("8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB", sig1, 48U);
	qsctest_hex_to_bin("DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5", sig1 + 48U, 48U);
	qsc_memutils_copy(sig1 + QSC_ECDSA_SIGNATURE_SIZE, msg1, sizeof(msg1));

#elif defined(QSC_ECDSA_S5P521)

/* RFC 6979 A.2.7 private key x */
	qsctest_hex_to_bin("00FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75"
		"CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538", sk, 66U);

	/* RFC 6979 A.2.7 public key U = xG */
	qsctest_hex_to_bin("01894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD"
		"371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4", expk, 66U);
	qsctest_hex_to_bin("00493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A"
		"28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5", expk + 66U, 66U);

	/* RFC 6979 A.2.7 signature for SHA-512, message = "sample" */
	qsctest_hex_to_bin("00C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F"
		"174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA", sig0, 66U);
	qsctest_hex_to_bin("00617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF"
		"282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A", sig0 + 66U, 66U);
	qsc_memutils_copy(sig0 + QSC_ECDSA_SIGNATURE_SIZE, msg0, sizeof(msg0));

	/* RFC 6979 A.2.7 signature for SHA-512, message = "test" */
	qsctest_hex_to_bin("013E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F1"
		"0CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D", sig1, 66U);
	qsctest_hex_to_bin("01FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E7"
		"8A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3", sig1 + 66U, 66U);
	qsc_memutils_copy(sig1 + QSC_ECDSA_SIGNATURE_SIZE, msg1, sizeof(msg1));

#else
#	error "Unsupported ECDSA parameter set."
#endif

	/* KAT 1: derive public key from fixed private scalar */
	if (qsc_ecdsa_publickey_from_privatekey(pk, sk) != 0)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: public-key derivation failed -EK1 \n");
		res = false;
	}
	else if (qsc_intutils_are_equal8(pk, expk, sizeof(expk)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: derived public key does not match the RFC 6979 vector -EK2 \n");
		res = false;
	}

	/* KAT 2: verify official RFC 6979 signature for message = "sample" */
	if (qsc_ecdsa_verify(mout, &mlen, sig0, sizeof(sig0), pk) == false)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: signature verification failed for sample -EK3 \n");
		res = false;
	}
	else if (mlen != sizeof(msg0) || qsc_intutils_are_equal8(mout, msg0, sizeof(msg0)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: recovered message does not match for sample -EK4 \n");
		res = false;
	}

	/* KAT 3: verify official RFC 6979 signature for message = "test" */
	qsc_memutils_clear(mout, sizeof(mout));
	mlen = 0U;

	if (qsc_ecdsa_verify(mout, &mlen, sig1, sizeof(sig1), pk) == false)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: signature verification failed for test -EK5 \n");
		res = false;
	}
	else if (mlen != sizeof(msg1) || qsc_intutils_are_equal8(mout, msg1, sizeof(msg1)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: recovered message does not match for test -EK6 \n");
		res = false;
	}

	/* KAT 4: deterministic signature generation for message = "sample"
	   Requires qsc_ecdsa_sign_scalar() to use RFC6979 with the raw scalar in sk */
	qsc_ecdsa_sign_scalar(gensig, &slen, msg0, sizeof(msg0), sk);

	if (slen != sizeof(gensig))
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: generated signature length is incorrect -EK7 \n");
		res = false;
	}
	else if (qsc_intutils_are_equal8(gensig, sig0, sizeof(sig0)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: generated signature does not match the RFC6979 vector -EK8 \n");
		res = false;
	}

	return res;
}

bool qsctest_ecdsa_privatekey_integrity(void)
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	size_t msglen;
	size_t siglen;
	bool res;

	res = true;
	msglen = 0U;
	siglen = 0U;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
		"056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));

	qsctest_nistrng_prng_initialize(seed, NULL, 0U);

	/* generate the signature key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip bits in the private key */
	for (size_t i = 0U; i < 4U; ++i)
	{
		sk[i] ^= 1U;
	}

	/* process message and return signed message */
	qsc_ecdsa_sign(sig, &siglen, msg, QSCTEST_ECDSA_MSG0_SIZE, sk);

	/* verify signed message, if successful with altered secret key, fail the test */
	if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_privatekey_integrity: ECDSA message verification passed with altered secret key -ES1 \n");
		res = false;
	}

	return res;
}

bool qsctest_ecdsa_publickey_integrity(void)
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	size_t msglen;
	size_t siglen;
	bool res;

	res = true;
	msglen = 0U;
	siglen = 0U;
	
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
		"056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip 1 bit in the public key */
	pk[QSC_ECDSA_PUBLICKEY_SIZE - 1U] ^= 1U;

	/* process message and return signed message */
	qsc_ecdsa_sign(sig, &siglen, msg, QSCTEST_ECDSA_MSG0_SIZE, sk);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_publickey_integrity: ECDSA message verification passed with altered public key -EP1 \n");
		res = false;
	}

	return res;
}

bool qsctest_ecdsa_signature_integrity(void)
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0U };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	size_t msglen;
	size_t siglen;
	bool res;

	res = true;
	msglen = 0U;
	siglen = 0U;
	
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7"
		"056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));

	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* process message and return signed message */
	qsc_ecdsa_sign(sig, &siglen, msg, QSCTEST_ECDSA_MSG0_SIZE, sk);

	/* flip 1 bit in the signed message */
	sig[siglen - 1U] ^= 1U;

	/* verify signed message, if successful with altered signature, fail the test */
	if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_signature_integrity: ECDSA message verification passed with altered signature -EI1 \n");
		res = false;
	}

	sig[siglen - 1U] ^= 1U;

	/* flip one bit per signature byte */
	for (size_t i = 0U; i < QSCTEST_ECDSA_ITERATIONS; ++i)
	{
		sig[i] ^= 1U;

		if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_signature_integrity: ECDSA flipping bit did not invalidate signature -EI2 \n");
			sig[i] ^= 1U;
			res = false;
			break;
		}

		sig[i] ^= 1U;
	}

	return res;
}

bool qsctest_ecdsa_stress_test(void)
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0U };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t tpk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0U };
	uint8_t tsk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0U };
	size_t msglen;
	size_t siglen;
	bool res;

	res = true;
	msglen = QSCTEST_ECDSA_MSG0_SIZE;
	siglen = QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE;

	/* generate the key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsc_csp_generate);

	for (size_t i = 0U; i < QSCTEST_ECDSA_ITERATIONS && res == true; ++i)
	{
		/* wellness test: seeded key generation must remain deterministic */
		if (qsc_ecdsa_generate_seeded_keypair(tpk, tsk, sk) == false)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: seeded key generation is unavailable -ES2 \n");
			res = false;
			break;
		}

		/* sign the message and return the signed version in sig */
		if (qsc_ecdsa_sign(sig, &siglen, msg, msglen, sk) == false)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA signing has failed -ES3 \n");
			res = false;
			break;
		}

		if (siglen != (QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE))
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA signature length is incorrect -ES4 \n");
			res = false;
			break;
		}

		/* verify the signature in sig and copy msg to mout */
		if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == false)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA message verification has failed -ES5 \n");
			res = false;
			break;
		}

		if (msglen != QSCTEST_ECDSA_MSG0_SIZE)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA message length is incorrect -ES6 \n");
			res = false;
			break;
		}

		if (qsc_intutils_are_equal8(mout, msg, msglen) != true)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA recovered message does not match -ES7 \n");
			res = false;
			break;
		}

		/* wellness test: an altered signature must fail every iteration */
		sig[0U] ^= 1U;

		if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: altered signature verification passed -ES8 \n");
			res = false;
			break;
		}

		sig[0U] ^= 1U;

		/* vary the message between iterations */
		msg[i % QSCTEST_ECDSA_MSG0_SIZE] ^= (uint8_t)(1U + (i & 0x0FU));
		msglen = QSCTEST_ECDSA_MSG0_SIZE;
	}

	return res;
}

void qsctest_ecdsa_run(void)
{

	if (qsctest_ecdsap256_kat_test() == true)
	{
		qsctest_print_safe("Success! ECDSA P-256 independent KAT PASS.\n");
	}
	else
	{
		qsctest_print_safe("Failure! ECDSA P-256 independent KAT FAIL.\n");
	}

	if (qsctest_ecdsap256_api_test() == true)
	{
		qsctest_print_safe("Success! ECDSA P-256 independent API PASS.\n");
	}
	else
	{
		qsctest_print_safe("Failure! ECDSA P-256 independent API FAIL.\n");
	}

	if (qsctest_ecdsap384_kat_test() == true)
	{
		qsctest_print_safe("Success! ECDSA P-384 independent KAT PASS.\n");
	}
	else
	{
		qsctest_print_safe("Failure! ECDSA P-384 independent KAT FAIL.\n");
	}

	if (qsctest_ecdsap384_api_test() == true)
	{
		qsctest_print_safe("Success! ECDSA P-384 independent API PASS.\n");
	}
	else
	{
		qsctest_print_safe("Failure! ECDSA P-384 independent API FAIL.\n");
	}

	if (qsctest_ecdsap521_kat_test() == true)
	{
		qsctest_print_safe("Success! ECDSA P-521 independent KAT PASS.\n");
	}
	else
	{
		qsctest_print_safe("Failure! ECDSA P-521 independent KAT FAIL.\n");
	}

	if (qsctest_ecdsap521_api_test() == true)
	{
		qsctest_print_safe("Success! ECDSA P-521 independent API PASS.\n");
	}
	else
	{
		qsctest_print_safe("Failure! ECDSA P-521 independent API FAIL.\n");
	}

	if (qsctest_ecdsa_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA known answer test. \n");
	}

	if (qsctest_ecdsa_stress_test() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA stress test has failed. \n");
	}

	if (qsctest_ecdsa_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA altered public-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA altered public-key test has failed. \n");
	}

	if (qsctest_ecdsa_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA altered secret-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA altered secret-key test has failed. \n");
	}

	if (qsctest_ecdsa_signature_integrity() == true)
	{
		qsctest_print_safe("Success! Passed the ECDSA altered signature test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ECDSA altered signature test has failed. \n");
	}
}