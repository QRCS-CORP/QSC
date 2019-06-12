#include "sphincstest.h"
#include "common.h"
#include "testutils.h"
#include "../SphincsPlus/sign.h"
#include "../SphincsPlus/sysrand.h"
#include <stdio.h>

void sphincs_test()
{
	printf_s("*** The Sphincs+ implementations stress and validity tests *** \n");

	if (sphincs_stress_test() != QCC_STATUS_SUCCESS)
	{
		printf_s("FAIL: The Sphincs+ stress test has failed! \n\n");
	}
	else
	{
		printf_s("PASS: The Sphincs+ stress test has succeeded! \n\n");
	}

	if (sphincs_publickey_integrity() != QCC_STATUS_SUCCESS)
	{
		printf_s("FAIL: The Sphincs+ altered public-key test has failed! \n\n");
	}
	else
	{
		printf_s("PASS: The Sphincs+ altered public-key test has succeeded! \n\n");
	}

	if (sphincs_secretkey_integrity() != QCC_STATUS_SUCCESS)
	{
		printf_s("FAIL: The Sphincs+ altered secret-key test has failed! \n\n");
	}
	else
	{
		printf_s("PASS: The Sphincs+ altered secret-key test has succeeded! \n\n");
	}

	if (test_signature_integrity() != QCC_STATUS_SUCCESS)
	{
		printf_s("FAIL: The Sphincs+ altered signature test has failed! \n\n");
	}
	else
	{
		printf_s("PASS: The Sphincs+ altered signature test has succeeded! \n\n");
	}

	printf_s("Completed! Press any key to close..");
	get_response();

	return 0;
}

/**
* \brief Stress test the key generation, encryption, and decryption functions in a looping test.
* \return Returns one (QCC_STATUS_SUCCESS) for test success
*/
qcc_status sphincs_stress_test()
{
	uint8_t msg[SPHINCS_MSG_SIZE];
	uint8_t mout[SPHINCS_MSG_SIZE];
	uint8_t smsg[SPHINCS_SIGNATURE_SIZE + SPHINCS_MSG_SIZE];
	uint8_t sk[SPHINCS_SECRETKEY_SIZE];
	uint8_t pk[SPHINCS_PUBLICKEY_SIZE];
	uint64_t mlen;
	uint64_t smlen;
	size_t i;

	mlen = SPHINCS_MSG_SIZE;
	smlen = SPHINCS_SIGNATURE_SIZE;

	/* generate a random message */
	if (sysrand_getbytes(msg, SPHINCS_MSG_SIZE) != QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_stress_test: System random generation has failed! \n");
		return QCC_ERROR_RANDFAIL;
	}

	/* generate the key-pair */
	if (sphincs_generate(pk, sk) != QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_stress_test: Sphincs key-pair generation has failed! \n");
		return QCC_ERROR_RANDFAIL;
	}
	else
	{
		printf_s("sphincs_stress_test: Sphincs signature key-pair generation has succeeded. \n");
	}

	for (i = 0; i < SPHINCS_NUM_TESTS; i++)
	{
		/* sign the message and return the signed version in smsg */
		if (sphincs_sign(smsg, &smlen, msg, mlen, sk) != QCC_STATUS_SUCCESS)
		{
			printf_s("sphincs_stress_test: Sphincs signature generation has failed! \n");
			return QCC_STATUS_FAILURE;
		}
		else
		{
			printf_s("sphincs_stress_test: Sphincs signature generation has succeeded. \n");
		}

		if (smlen != SPHINCS_SIGNATURE_SIZE + SPHINCS_MSG_SIZE)
		{
			printf_s("sphincs_stress_test: smlen incorrect [%llu != %u]! \n", smlen, SPHINCS_SIGNATURE_SIZE);
			return QCC_STATUS_FAILURE;
		}
		else
		{
			printf_s("sphincs_stress_test: Sphincs signed message size is correct. \n");
		}

		/* verify the signature in smsg and copy msg to mout */
		if (sphincs_verify(mout, &mlen, smsg, smlen, pk) != QCC_STATUS_SUCCESS)
		{
			printf_s("sphincs_stress_test: Sphincs message verification has failed! \n");
			return QCC_STATUS_FAILURE;
		}
		else
		{
			printf_s("sphincs_stress_test: Sphincs message verification has succeeded. \n");
		}

		if (mlen != SPHINCS_MSG_SIZE)
		{
			printf_s("sphincs_stress_test: mlen incorrect [%llu != %u]! \n", mlen, SPHINCS_MSG_SIZE);
			return QCC_STATUS_FAILURE;
		}
		else
		{
			printf_s("sphincs_stress_test: Sphincs verified message size is correct. \n");
		}
	}

	return QCC_STATUS_SUCCESS;
}

/**
* \brief Test the validity of a mutated public key
* \return Returns one (QCC_STATUS_SUCCESS) for test success
*/
qcc_status sphincs_publickey_integrity()
{
	uint8_t msg[SPHINCS_MSG_SIZE];
	uint8_t mout[SPHINCS_SIGNATURE_SIZE + SPHINCS_MSG_SIZE];
	uint8_t smsg[SPHINCS_SIGNATURE_SIZE + SPHINCS_MSG_SIZE];
	uint8_t sk[SPHINCS_SECRETKEY_SIZE];
	uint8_t pk[SPHINCS_PUBLICKEY_SIZE];
	uint64_t mlen;
	uint64_t smlen;

	mlen = 0;
	smlen = 0;

	/* generate a random message */
	if (sysrand_getbytes(msg, SPHINCS_MSG_SIZE) != QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_publickey_integrity: System random generation has failed! \n");
		return QCC_ERROR_RANDFAIL;
	}

	/* generate the signature key-pair */
	if (sphincs_generate(pk, sk) != QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_publickey_integrity: Sphincs signature key-pair generation has failed! \n");
		return QCC_STATUS_FAILURE;
	}
	else
	{
		printf_s("sphincs_publickey_integrity: Sphincs signature key-pair generation has succeeded. \n");
	}

	/* flip 1 bit in the public key */
	printf_s("sphincs_publickey_integrity: Flipping the 1st bit in the public key. \n");
	pk[SPHINCS_PUBLICKEY_SIZE - 1] ^= 1;

	/* process message and return signed message */
	if (sphincs_sign(smsg, &smlen, msg, SPHINCS_MSG_SIZE, sk) != QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_publickey_integrity: Sphincs signature generation has failed! \n");
		return QCC_STATUS_FAILURE;
	}
	else
	{
		printf_s("sphincs_publickey_integrity: Sphincs signature generation has succeeded. \n");
	}

	/* verify signed message, if successful with altered public key, fail the test */
	if (sphincs_verify(mout, &mlen, smsg, smlen, pk) == QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_publickey_integrity: Sphincs message verification passed with altered public key, test failure! \n");
		return QCC_STATUS_FAILURE;
	}
	else
	{
		printf_s("sphincs_publickey_integrity: Sphincs message verification has failed using altered public key, test success. \n");
	}

	return QCC_STATUS_SUCCESS;
}

/**
* \brief Test the validity of a mutated secret key
* \return Returns one (QCC_STATUS_SUCCESS) for test success
*/
qcc_status sphincs_secretkey_integrity()
{
	uint8_t msg[SPHINCS_MSG_SIZE];
	uint8_t mout[SPHINCS_SIGNATURE_SIZE + SPHINCS_MSG_SIZE];
	uint8_t smsg[SPHINCS_SIGNATURE_SIZE + SPHINCS_MSG_SIZE];
	uint8_t sk[SPHINCS_SECRETKEY_SIZE];
	uint8_t pk[SPHINCS_PUBLICKEY_SIZE];
	uint64_t mlen;
	uint64_t smlen;

	mlen = 0;
	smlen = 0;

	/* generate a random message */
	if (sysrand_getbytes(msg, SPHINCS_MSG_SIZE) != QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_secretkey_integrity: System random generation has failed! \n");
		return QCC_ERROR_RANDFAIL;
	}

	/* generate the signature key-pair */
	if (sphincs_generate(pk, sk) != QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_secretkey_integrity: Sphincs signature key-pair generation has failed! \n");
		return QCC_STATUS_FAILURE;
	}
	else
	{
		printf_s("sphincs_secretkey_integrity: Sphincs signature key-pair generation has succeeded. \n");
	}

	/* flip 1 bit in the public key */
	printf_s("sphincs_secretkey_integrity: Flipping the 1st bit in the secret key. \n");
	sk[SPHINCS_SECRETKEY_SIZE - 1] ^= 1;

	/* process message and return signed message */
	if (sphincs_sign(smsg, &smlen, msg, SPHINCS_MSG_SIZE, sk) != QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_secretkey_integrity: Sphincs signature generation has failed! \n");
		return QCC_STATUS_FAILURE;
	}
	else
	{
		printf_s("sphincs_secretkey_integrity: Sphincs signature generation has succeeded. \n");
	}

	/* verify signed message, if successful with altered public key, fail the test */
	if (sphincs_verify(mout, &mlen, smsg, smlen, pk) == QCC_STATUS_SUCCESS)
	{
		printf_s("sphincs_secretkey_integrity: Sphincs message verification passed with altered secret key, test failure! \n");
		return QCC_STATUS_FAILURE;
	}
	else
	{
		printf_s("sphincs_secretkey_integrity: Sphincs message verification has failed using altered secret key, test success. \n");
	}

	return QCC_STATUS_SUCCESS;
}

/**
* \brief Test the validity of a mutated signature
* \return Returns one (NEWHOPE_STATUS_SUCCESS) for test success
*/
qcc_status test_signature_integrity()
{
	uint8_t msg[SPHINCS_MSG_SIZE];
	uint8_t mout[SPHINCS_SIGNATURE_SIZE + SPHINCS_MSG_SIZE];
	uint8_t smsg[SPHINCS_SIGNATURE_SIZE + SPHINCS_MSG_SIZE];
	uint8_t sk[SPHINCS_SECRETKEY_SIZE];
	uint8_t pk[SPHINCS_PUBLICKEY_SIZE];
	uint64_t mlen;
	uint64_t smlen;
	int32_t i;

	mlen = 0;
	smlen = 0;

	/* generate a random message */
	if (sysrand_getbytes(msg, SPHINCS_MSG_SIZE) != QCC_STATUS_SUCCESS)
	{
		printf_s("test_signature_integrity: System random generation has failed! \n");
		return QCC_ERROR_RANDFAIL;
	}

	/* generate the signature key-pair */
	if (sphincs_generate(pk, sk) != QCC_STATUS_SUCCESS)
	{
		printf_s("test_signature_integrity: Sphincs signature key-pair generation has failed! \n");
		return QCC_STATUS_FAILURE;
	}
	else
	{
		printf_s("test_signature_integrity: Sphincs signature key-pair generation has succeeded. \n");
	}

	/* process message and return signed message */
	if (sphincs_sign(smsg, &smlen, msg, SPHINCS_MSG_SIZE, sk) != QCC_STATUS_SUCCESS)
	{
		printf_s("test_signature_integrity: Sphincs signature generation has failed! \n");
		return QCC_STATUS_FAILURE;
	}
	else
	{
		printf_s("test_signature_integrity: Sphincs signature generation has succeeded. \n");
	}

	/* flip 1 bit in the signed message */
	printf_s("test_signature_integrity: Flipping the 1st bit in the secret key. \n");
	smsg[smlen - 1] ^= 1;

	/* verify signed message, if successful with altered public key, fail the test */
	if (sphincs_verify(mout, &mlen, smsg, smlen, pk) == QCC_STATUS_SUCCESS)
	{
		printf_s("test_signature_integrity: Sphincs message verification passed with altered secret key, test failure! \n");
		return QCC_STATUS_FAILURE;
	}
	else
	{
		printf_s("test_signature_integrity: Sphincs message verification has failed using altered secret key, test success. \n");
	}

	/* flip one bit per hash; the signature is entirely hashes */
	for (i = 0; i < (int32_t)(smlen - SPHINCS_MSG_SIZE); i += SPX_N)
	{
		smsg[i] ^= 1;

		if (!sphincs_verify(mout, &mlen, smsg, smlen, pk))
		{
			printf_s("test_signature_integrity: flipping bit %d DID NOT invalidate sig + m! \n", i);
			smsg[i] ^= 1;
			break;
		}

		smsg[i] ^= 1;
	}

	if (i >= (int32_t)(smlen - SPHINCS_MSG_SIZE))
	{
		printf_s("test_signature_integrity: Changing any signature hash invalidates signature. \n");
	}

	return QCC_STATUS_SUCCESS;
}