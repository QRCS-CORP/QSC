#include "ecdsa_test.h"
#include "common.h"
#include "nistrng.h"
#include "testutils.h"
#include "../QSC/ec25519.h"
#include "../QSC/ecdsa.h"
#include "../QSC/intutils.h"
#include "../QSC/sha2.h"
#include "../QSC/transpose.h"

#define QSCTEST_ECDSA_MSG0_SIZE 32
#define QSCTEST_ECDSA_MSG1_SIZE 64
#define QSCTEST_ECDSA_MSG2_SIZE 96
#define QSCTEST_ECDSA_MSG3_SIZE 128

bool qsctest_ecdsa_kat_test()
{
	uint8_t gpk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0 };
	uint8_t gsk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t ksd[QSC_ECDSA_SEED_SIZE] = { 0 };
	uint8_t kpk[5][QSC_ECDSA_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksk[5][QSC_ECDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t kms0[QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t kms1[QSCTEST_ECDSA_MSG1_SIZE] = { 0 };
	uint8_t kms2[QSCTEST_ECDSA_MSG2_SIZE] = { 0 };
	uint8_t kms3[QSCTEST_ECDSA_MSG3_SIZE] = { 0 };
	uint8_t ksg0[QSCTEST_ECDSA_MSG0_SIZE + QSC_ECDSA_SIGNATURE_SIZE] = { 0 };
	uint8_t ksg1[QSCTEST_ECDSA_MSG1_SIZE + QSC_ECDSA_SIGNATURE_SIZE] = { 0 };
	uint8_t ksg2[QSCTEST_ECDSA_MSG2_SIZE + QSC_ECDSA_SIGNATURE_SIZE] = { 0 };
	uint8_t ksg3[QSCTEST_ECDSA_MSG3_SIZE + QSC_ECDSA_SIGNATURE_SIZE] = { 0 };
	uint8_t msg0[QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t msg1[QSCTEST_ECDSA_MSG1_SIZE] = { 0 };
	uint8_t msg2[QSCTEST_ECDSA_MSG2_SIZE] = { 0 };
	uint8_t msg3[QSCTEST_ECDSA_MSG3_SIZE] = { 0 };
	uint8_t sig0[QSCTEST_ECDSA_MSG0_SIZE + QSC_ECDSA_SIGNATURE_SIZE] = { 0 };
	uint8_t sig1[QSCTEST_ECDSA_MSG1_SIZE + QSC_ECDSA_SIGNATURE_SIZE] = { 0 };
	uint8_t sig2[QSCTEST_ECDSA_MSG2_SIZE + QSC_ECDSA_SIGNATURE_SIZE] = { 0 };
	uint8_t sig3[QSCTEST_ECDSA_MSG3_SIZE + QSC_ECDSA_SIGNATURE_SIZE] = { 0 };
	size_t mlen;
	size_t slen;
	bool ret;

	mlen = 0;
	slen = 0;
	ret = true;


	qsctest_hex_to_bin("421151A459FAEADE3D247115F94AEDAE42318124095AFABE4D1451A559FAEDEE", ksd, sizeof(ksd));
	qsctest_hex_to_bin("A750C232933DC14B1184D86D8B4CE72E16D69744BA69818B6AC33B1D823BB2C3", kms0, sizeof(kms0));
	qsctest_hex_to_bin("4BAFDAC9099D4057ED6DD08BCAEE8756E9A40F2CB9598020EB95019528409BBE"
		"A38B384A59F119F57297BFB2FA142FC7BB1D90DBDDDE772BCDE48C5670D5FA13", kms1, sizeof(kms1));
	qsctest_hex_to_bin("FE6C1A31068E332D12AAB37D99406568DEAA36BDB277CEE55304633BD0A267A8"
		"50E203BB3FABE5110BCC1CA4316698AB1CF00F0B0F1D97EF2180887F0EC0991E"
		"8C1111F0C0E1D2B712433AD2B3071BD66E1D81F7FA47BB4BB31AC0F059BB3CB8", kms2, sizeof(kms2));
	qsctest_hex_to_bin("F7E67D982A2FF93ECDA4087152B4864C943B1BA7021F5407043CCB4253D348C2"
		"7B9283ACB26C194FD1CBB79E6AFC32FF686B55B0B3617218DCF39316B4B66B3C"
		"8C0D67267A86DB8ADF3750801BCF9327D4C25441B96197832B4CDE0EAC3FF228"
		"92A2F0BC17C2C213C02377A333E308ED271658049383B7E2E57B6B8B125512E0", kms3, sizeof(kms3));

	qsctest_hex_to_bin("B49F3A78B1C6A7FCA8F3466F33BC0E929F01FBA04306C2A7465F46C3759316D9", kpk[0], sizeof(kpk[0]));
	qsctest_hex_to_bin("F73FA076F84B6DB675A5FDA5AD67E351A41E8E7F29ADD16809CA010387E9C6CC", kpk[1], sizeof(kpk[1]));
	qsctest_hex_to_bin("6FF19B1F18D64851D5C74845C6407F0BF596A52E385E020127E83E54CFF5AC19", kpk[2], sizeof(kpk[2]));
	qsctest_hex_to_bin("98BE21001993A7EB1A1277FF74C15504183D25FDFCC05F0D4DEA892F6E301890", kpk[3], sizeof(kpk[3]));
	qsctest_hex_to_bin("B5076A8474A832DAEE4DD5B4040983B6623B5F344ACA57D4D6EE4BAF3F259E6E", kpk[4], sizeof(kpk[4]));

	qsctest_hex_to_bin("8ED7A797B9CEA8A8370D419136BCDF683B759D2E3C6947F17E13E2485AA9D420"
		"B49F3A78B1C6A7FCA8F3466F33BC0E929F01FBA04306C2A7465F46C3759316D9", ksk[0], sizeof(ksk[0]));
	qsctest_hex_to_bin("BA4D6E67B2CE67A1E44326494044F37A442F3B81725BC1F9341462718B55EE20"
		"F73FA076F84B6DB675A5FDA5AD67E351A41E8E7F29ADD16809CA010387E9C6CC", ksk[1], sizeof(ksk[1]));
	qsctest_hex_to_bin("3ADCE3A3D3FBC977DD4B300A74749F13A3B04A5D73A2CD75A994E3195EFEBDAC"
		"6FF19B1F18D64851D5C74845C6407F0BF596A52E385E020127E83E54CFF5AC19", ksk[2], sizeof(ksk[2]));
	qsctest_hex_to_bin("8400962BB769F63868CAE5A3FEC8DB6A9C8D3F1C846C8DCEEB642B6946EFA8E3"
		"98BE21001993A7EB1A1277FF74C15504183D25FDFCC05F0D4DEA892F6E301890", ksk[3], sizeof(ksk[3]));
	qsctest_hex_to_bin("421151A459FAEADE3D247115F94AEDAE42318124095AFABE4D1451A559FAEDEE"
		"B5076A8474A832DAEE4DD5B4040983B6623B5F344ACA57D4D6EE4BAF3F259E6E", ksk[4], sizeof(ksk[4]));

	qsctest_hex_to_bin("04266C033B91C1322CEB3446C901FFCF3CC40C4034E887C9597CA1893BA7330B"
		"ECBBD8B48142EF35C012C6BA51A66DF9308CB6268AD6B1E4B03E70102495790B"
		"A750C232933DC14B1184D86D8B4CE72E16D69744BA69818B6AC33B1D823BB2C3", ksg0, sizeof(ksg0));
	qsctest_hex_to_bin("57B9D2A711207F837421BAE7DD48EAA18EAB1A9A70A0F1305806FEE17B458F3A"
		"0964B302D1834D3E0AC9E8496F000B77F0083B41F8A957E632FBC7840EEE6A06"
		"4BAFDAC9099D4057ED6DD08BCAEE8756E9A40F2CB9598020EB95019528409BBE"
		"A38B384A59F119F57297BFB2FA142FC7BB1D90DBDDDE772BCDE48C5670D5FA13", ksg1, sizeof(ksg1));
	qsctest_hex_to_bin("7DDA89F85B40539F5AD8C6DE4953F7094A715B63DDA30EC7CF65A785CEAE5FC6"
		"88707EE00BE682CECBE7EE37D8FC39EE6D83C64409681708A0898A183B288A06"
		"FE6C1A31068E332D12AAB37D99406568DEAA36BDB277CEE55304633BD0A267A8"
		"50E203BB3FABE5110BCC1CA4316698AB1CF00F0B0F1D97EF2180887F0EC0991E"
		"8C1111F0C0E1D2B712433AD2B3071BD66E1D81F7FA47BB4BB31AC0F059BB3CB8", ksg2, sizeof(ksg2));
	qsctest_hex_to_bin("0AD71B0025F3D9A50DB338414D6D670E7799B7270A8444F6AE7F12AE7EB71BD0"
		"3FFD3C4F36631F69FDCC4061468FF582EDE495243EF1361A3B3295FA813BA205"
		"F7E67D982A2FF93ECDA4087152B4864C943B1BA7021F5407043CCB4253D348C2"
		"7B9283ACB26C194FD1CBB79E6AFC32FF686B55B0B3617218DCF39316B4B66B3C"
		"8C0D67267A86DB8ADF3750801BCF9327D4C25441B96197832B4CDE0EAC3FF228"
		"92A2F0BC17C2C213C02377A333E308ED271658049383B7E2E57B6B8B125512E0", ksg3, sizeof(ksg3));

	/* test key generation */

	qsc_ecdsa_generate_seeded_keypair(gpk, gsk, ksd);

	if (qsc_intutils_are_equal8(kpk[4], gpk, sizeof(kpk[4])) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: the public key generation does not match -EK1 \n");
		ret = false;
	}

	if (qsc_intutils_are_equal8(ksk[4], gsk, sizeof(ksk[4])) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: the private key generation does not match -EK2 \n");
		ret = false;
	}

	/* test sign and verify */

	/* 32-byte message */
	qsc_ecdsa_sign(sig0, &slen, kms0, sizeof(kms0), ksk[0]);

	if (qsc_intutils_are_equal8(ksg0, sig0, sizeof(ksg0)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: the signature does not match -EK3 \n");
		ret = false;
	}

	if (qsc_ecdsa_verify(msg0, &mlen, ksg0, sizeof(ksg0), kpk[0]) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: signature verification has failed -EK4 \n");
		ret = false;
	}

	/* 64-byte message */
	qsc_ecdsa_sign(sig1, &slen, kms1, sizeof(kms1), ksk[1]);

	if (qsc_intutils_are_equal8(ksg1, sig1, sizeof(ksg1)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: the signature does not match -EK5 \n");
		ret = false;
	}

	if (qsc_ecdsa_verify(msg1, &mlen, ksg1, sizeof(ksg1), kpk[1]) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: signature verification has failed -EK6 \n");
		ret = false;
	}

	/* 96-byte message */
	qsc_ecdsa_sign(sig2, &slen, kms2, sizeof(kms2), ksk[2]);

	if (qsc_intutils_are_equal8(ksg2, sig2, sizeof(ksg2)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: the signature does not match -EK7 \n");
		ret = false;
	}

	if (qsc_ecdsa_verify(msg2, &mlen, ksg2, sizeof(ksg2), kpk[2]) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: signature verification has failed -EK8 \n");
		ret = false;
	}

	/* 128-byte message */
	qsc_ecdsa_sign(sig3, &slen, kms3, sizeof(kms3), ksk[3]);

	if (qsc_intutils_are_equal8(ksg3, sig3, sizeof(ksg3)) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: the signature does not match -EK9 \n");
		ret = false;
	}

	if (qsc_ecdsa_verify(msg3, &mlen, ksg3, sizeof(ksg3), kpk[3]) != true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_kat_test: signature verification has failed -EK10 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_ecdsa_privatekey_integrity()
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip bits in the private key */
	for (size_t i = 0; i < 4; ++i)
	{
		sk[i] ^= 1U;
	}

	/* process message and return signed message */
	qsc_ecdsa_sign(sig, &siglen, msg, QSCTEST_ECDSA_MSG0_SIZE, sk);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_privatekey_integrity: ECDSA message verification passed with altered secret key -ES1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_ecdsa_publickey_integrity()
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* flip 1 bit in the public key */
	pk[QSC_ECDSA_PUBLICKEY_SIZE - 1] ^= 1U;

	/* process message and return signed message */
	qsc_ecdsa_sign(sig, &siglen, msg, QSCTEST_ECDSA_MSG0_SIZE, sk);

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_publickey_integrity: ECDSA message verification passed with altered public key -EP1 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_ecdsa_signature_integrity()
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = 0;
	siglen = 0;
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the signature key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	/* process message and return signed message */
	qsc_ecdsa_sign(sig, &siglen, msg, QSCTEST_ECDSA_MSG0_SIZE, sk);

	/* flip 1 bit in the signed message */
	sig[siglen - 1] ^= 1U;

	/* verify signed message, if successful with altered public key, fail the test */
	if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
	{
		qsctest_print_safe("Failure! qsctest_ecdsa_signature_integrity: ECDSA message verification passed with altered secret key -EI1 \n");
		ret = false;
	}

	/* flip one bit per hash; the signature is entirely hashes */
	for (size_t i = 0; i < (int32_t)(siglen - QSCTEST_ECDSA_MSG0_SIZE); ++i)
	{
		sig[i] ^= 1U;

		if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) == true)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_signature_integrity: ECDSA flipping bit did not invalidate signature -EI2 \n");
			sig[i] ^= 1U;
			ret = false;
			break;
		}

		sig[i] ^= 1U;
	}

	return ret;
}

bool qsctest_ecdsa_stress_test()
{
	uint8_t msg[QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t mout[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t seed[QSCTEST_NIST_RNG_SEED_SIZE] = { 0 };
	uint8_t sig[QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE] = { 0 };
	uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE] = { 0 };
	size_t msglen;
	size_t siglen;
	bool ret;

	ret = true;
	msglen = QSCTEST_ECDSA_MSG0_SIZE;
	siglen = QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE; 
	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0);

	/* generate the key-pair */
	qsc_ecdsa_generate_keypair(pk, sk, qsctest_nistrng_prng_generate);

	for (size_t i = 0; i < QSCTEST_ECDSA_ITERATIONS; i++)
	{
		/* sign the message and return the signed version in sig */
		qsc_ecdsa_sign(sig, &siglen, msg, msglen, sk);

		if (siglen != QSC_ECDSA_SIGNATURE_SIZE + QSCTEST_ECDSA_MSG0_SIZE)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA signature length is incorrect -ES1 \n");
			ret = false;
			break;
		}

		/* verify the signature in sig and copy msg to mout */
		if (qsc_ecdsa_verify(mout, &msglen, sig, siglen, pk) != true)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA message verification has failed -ES2 \n");
			ret = false;
			break;
		}

		if (msglen != QSCTEST_ECDSA_MSG0_SIZE)
		{
			qsctest_print_safe("Failure! qsctest_ecdsa_stress_test: ECDSA message length is incorrect -ES3 \n");
			ret = false;
			break;
		}
	}

	return ret;
}

void qsctest_ecdsa_run()
{
	if (qsctest_ecdsa_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed ECDSA known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed ECDSA known answer test. \n");
	}

	if (qsctest_ecdsa_stress_test() == true)
	{
		qsctest_print_safe("Success! The ECDSA stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! The ECDSA stress test has failed. \n");
	}

	if (qsctest_ecdsa_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! The ECDSA altered public-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! The ECDSA altered public-key test has failed. \n");
	}

	if (qsctest_ecdsa_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! The ECDSA altered secret-key test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! The ECDSA altered secret-key test has failed. \n");
	}

	if (qsctest_ecdsa_signature_integrity() == true)
	{
		qsctest_print_safe("Success! The ECDSA altered signature test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! The ECDSA altered signature test has failed. \n");
	}
}
