#include "ecdh_test.h"
#include "csp.h"
#include "ecdh.h"
#include "memutils.h"
#include "nistrng.h"
#include "testutils.h"

bool qsctest_ecdh_kat_test()
{
	uint8_t kpka[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t kpeer[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t ksec[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t kska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	uint8_t pka[QSC_ECDH_PUBLICKEY_SIZE] = { 0 };
	uint8_t seca[QSC_ECDH_SHAREDSECRET_SIZE] = { 0 };
	uint8_t ska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0 };
	bool ret;

#if defined(QSC_ECDH_S1P256)
	/* official NIST P-256 ECC CDH Primitive KAT */
	qsctest_hex_to_bin("7D7DC5F71EB29DDAF80D6214632EEAE03D9058AF1FB6D22ED80BADB62BC1A534", kska, sizeof(kska));
	qsctest_hex_to_bin("EAD218590119E8876B29146FF89CA61770C4EDBBF97D38CE385ED281D8A6B230"
		"28AF61281FD35E2FA7002523ACC85A429CB06EE6648325389F59EDFCE1405141", kpka, sizeof(kpka));
	qsctest_hex_to_bin("700C48F77F56584C5CC632CA65640DB91B6BACCE3A4DF6B42CE7CC838833D287"
		"DB71E509E3FD9B060DDB20BA5C51DCC5948D46FBF640DFE0441782CAB85FA4AC", kpeer, sizeof(kpeer));
	qsctest_hex_to_bin("46FC62106420FF012E54A434FBDD2D25CCC5852060561E68040DD7778997BD7B", ksec, sizeof(ksec));

#elif defined(QSC_ECDH_S3P384)
	/* official NIST P-384 ECC CDH Primitive KAT, COUNT = 0 */
	qsctest_hex_to_bin("3CC3122A68F0D95027AD38C067916BA0EB8C38894D22E1B15618B6818A661774"
		"AD463B205DA88CF699AB4D43C9CF98A1", kska, sizeof(kska));
	qsctest_hex_to_bin("9803807F2F6D2FD966CDD0290BD410C0190352FBEC7FF6247DE1302DF86F25D3"
		"4FE4A97BEF60CFF548355C015DBB3E5F"
		"BA26CA69EC2F5B5D9DAD20CC9DA711383A9DBE34EA3FA5A2AF75B46502629AD5"
		"4DD8B7D73A8ABB06A3A3BE47D650CC99", kpka, sizeof(kpka));
	qsctest_hex_to_bin("A7C76B970C3B5FE8B05D2838AE04AB47697B9EAF52E764592EFDA27FE7513272"
		"734466B400091ADBF2D68C58E0C50066"
		"AC68F19F2E1CB879AED43A9969B91A0839C4C38A49749B661EFEDF243451915E"
		"D0905A32B060992B468C64766FC8437A", kpeer, sizeof(kpeer));
	qsctest_hex_to_bin("5F9D29DC5E31A163060356213669C8CE132E22F57C9A04F40BA7FCEAD493B457"
		"E5621E766C40A2E3D4D6A04B25E533F1", ksec, sizeof(ksec));

#elif defined(QSC_ECDH_S5P521)
	/* official NIST P-521 ECC CDH Primitive KAT */
	qsctest_hex_to_bin("017EECC07AB4B329068FBA65E56A1F8890AA935E57134AE0FFCCE802735151F4"
		"EAC6564F6EE9974C5E6887A1FEFEE5743AE2241BFEB95D5CE31DDCB6F9EDB4D6FC47",
		kska, sizeof(kska));

	qsctest_hex_to_bin("00685A48E86C79F0F0875F7BC18D25EB5FC8C0B07E5DA4F4370F3A9490340854"
		"334B1E1B87FA395464C60626124A4E70D0F785601D37C09870EBF176666877A2046D"
		"01BA52C56FC8776D9E8F5DB4F0CC27636D0B741BBE05400697942E80B739884A"
		"83BDE99E0F6716939E632BC8986FA18DCCD443A348B6C3E522497955A4F3C302F676",
		kpeer, sizeof(kpeer));

	qsctest_hex_to_bin("00602F9D0CF9E526B29E22381C203C48A886C2B0673033366314F1FFBCBA240B"
		"A42F4EF38A76174635F91E6B4ED34275EB01C8467D05CA80315BF1A7BBD945F550A5"
		"01B7C85F26F5D4B2D7355CF6B02117659943762B6D1DB5AB4F1DBC44CE7B2946"
		"EB6C7DE342962893FD387D1B73D7A8672D1F236961170B7EB3579953EE5CDC88CD2D",
		kpka, sizeof(kpka));

	qsctest_hex_to_bin("005FC70477C3E63BC3954BD0DF3EA0D1F41EE21746ED95FC5E1FDF90930D5E13"
		"6672D72CC770742D1711C3C3A4C334A0AD9759436A4D3C5BF6E74B9578FAC148"
		"C831", ksec, sizeof(ksec));
#else
#	error "No ECDH parameter set has been selected!"
#endif

	ret = true;

	/* use the official NIST private scalar directly */
	qsc_memutils_copy(ska, kska, sizeof(ska));

	/* derive the public key from the private key */
	qsc_ecdh_public_from_private(pka, ska);

	/* test public key generation */
	if (qsc_memutils_are_equal(pka, kpka, sizeof(pka)) != true)
	{
		qsctest_print_safe("Failure! ecdh_kat: public key does not match expected -EK1 \n");
		ret = false;
	}

	/* test private key */
	if (qsc_memutils_are_equal(ska, kska, sizeof(ska)) != true)
	{
		qsctest_print_safe("Failure! ecdh_kat: private key does not match expected -EK2 \n");
		ret = false;
	}

	/* derive the shared secret using the peer public key */
	if (qsc_ecdh_key_exchange(seca, ska, kpeer) != true)
	{
		qsctest_print_safe("Failure! ecdh_kat: key exchange has failed -EK3 \n");
		ret = false;
	}

	/* fail if secret does not match known answer */
	if (qsc_memutils_are_equal(seca, ksec, sizeof(seca)) != true)
	{
		qsctest_print_safe("Failure! ecdh_kat: secret does not match known answer -EK4 \n");
		ret = false;
	}

	return ret;
}

bool qsctest_ecdh_operations_test(void)
{
	uint8_t pka[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };
	uint8_t pkb[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };
	uint8_t seca[QSC_ECDH_SHAREDSECRET_SIZE] = { 0U };
	uint8_t secb[QSC_ECDH_SHAREDSECRET_SIZE] = { 0U };
	uint8_t seed[48U] = { 0U };
	uint8_t ska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skb[QSC_ECDH_PRIVATEKEY_SIZE] = { 0U };
	bool res = true;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0U);

	for (size_t i = 0U; i < QSCTEST_ECDH_ITERATIONS; ++i)
	{
		qsc_ecdh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		qsc_ecdh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		if (qsc_ecdh_key_exchange(seca, ska, pkb) != true)
		{
			qsctest_print_safe("Failure! ecdh_test_operations: key exchange failure -EO1 \n");
			res = false;
			break;
		}

		if (qsc_ecdh_key_exchange(secb, skb, pka) != true)
		{
			qsctest_print_safe("Failure! ecdh_test_operations: key exchange failure -EO2 \n");
			res = false;
			break;
		}

		if (qsc_memutils_are_equal(seca, secb, QSC_ECDH_SHAREDSECRET_SIZE) != true)
		{
			qsctest_print_safe("Failure! ecdh_test_operations: secret keys do not match -EO3 \n");
			res = false;
			break;
		}
	}

	return res;
}

bool qsctest_ecdh_privatekey_integrity(void)
{
	uint8_t seed[48U] = { 0 };
	uint8_t pka[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };
	uint8_t pkb[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };
	uint8_t ska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skb[QSC_ECDH_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seca[QSC_ECDH_SHAREDSECRET_SIZE] = { 0U };
	uint8_t secb[QSC_ECDH_SHAREDSECRET_SIZE] = { 0U };
	bool res = true;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0U);

	for (size_t i = 0U; i < QSCTEST_ECDH_ITERATIONS; ++i)
	{
		qsc_ecdh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		qsc_ecdh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		ska[1] ^= 1U;

		if (qsc_ecdh_key_exchange(seca, ska, pkb) != true)
		{
			continue;
		}

		if (qsc_ecdh_key_exchange(secb, skb, pka) != true)
		{
			qsctest_print_safe("Failure! ecdh_test_privatekey: baseline key exchange failure -ES1 \n");
			res = false;
			break;
		}

		if (qsc_memutils_are_equal(seca, secb, QSC_ECDH_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! ecdh_test_privatekey: altered private key did not change secret -ES2 \n");
			res = false;
			break;
		}
	}

	return res;
}

bool qsctest_ecdh_publickey_integrity(void)
{
	uint8_t seed[48U] = { 0U };
	uint8_t pka[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };
	uint8_t pkb[QSC_ECDH_PUBLICKEY_SIZE] = { 0U };
	uint8_t ska[QSC_ECDH_PRIVATEKEY_SIZE] = { 0U };
	uint8_t skb[QSC_ECDH_PRIVATEKEY_SIZE] = { 0U };
	uint8_t seca[QSC_ECDH_SHAREDSECRET_SIZE] = { 0U };
	uint8_t secb[QSC_ECDH_SHAREDSECRET_SIZE] = { 0U };
	bool res = true;

	qsctest_hex_to_bin("061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1", seed, sizeof(seed));
	qsctest_nistrng_prng_initialize(seed, NULL, 0U);

	for (size_t i = 0U; i < QSCTEST_ECDH_ITERATIONS; ++i)
	{
		qsc_ecdh_generate_keypair(pka, ska, qsctest_nistrng_prng_generate);
		qsc_ecdh_generate_keypair(pkb, skb, qsctest_nistrng_prng_generate);

		pka[0U] ^= 1U;

		if (qsc_ecdh_key_exchange(seca, ska, pkb) != true)
		{
			qsctest_print_safe("Failure! ecdh_test_publickey: baseline key exchange failure -EP1 \n");
			res = false;
			break;
		}

		if (qsc_ecdh_key_exchange(secb, skb, pka) != true)
		{
			continue;
		}

		if (qsc_memutils_are_equal(seca, secb, QSC_ECDH_SHAREDSECRET_SIZE) == true)
		{
			qsctest_print_safe("Failure! ecdh_test_publickey: altered public key did not change secret -EP2 \n");
			res = false;
			break;
		}
	}

	return res;
}

void qsctest_ecdh_run(void)
{
	if (qsctest_ecdh_kat_test() == true)
	{
		qsctest_print_safe("Success! Passed ECDH P-256 known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed ECDH P-256 known answer tests. \n");
	}

	if (qsctest_ecdh_operations_test() == true)
	{
		qsctest_print_safe("Success! Passed ECDH P-256 key generation and key exchange stress test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed ECDH P-256 operations stress tests. \n");
	}

	if (qsctest_ecdh_privatekey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed ECDH P-256 private-key tamper test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed ECDH P-256 private-key tamper test. \n");
	}

	if (qsctest_ecdh_publickey_integrity() == true)
	{
		qsctest_print_safe("Success! Passed ECDH P-256 public-key tamper test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed ECDH P-256 public-key tamper test. \n");
	}
}
