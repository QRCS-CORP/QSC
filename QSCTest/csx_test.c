#include "csx_test.h"
#include "../QSC/intutils.h"
#include "../QSC/csx.h"
#include "../QSC/sha3.h"
#include "../QSC/csp.h"
#include "testutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool qsctest_csx512_kat_test()
{
	uint8_t ad[20];
	uint8_t dec[128] = { 0 };
	uint8_t enc1[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t enc2[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t exp1[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t exp2[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t msg[128] = { 0 };
	uint8_t nce[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t ncpy[QSC_CSX_NONCE_SIZE] = { 0 };
	bool status;
	qsc_csx_state state;

	/* vectors from CEX */
	/* csxc512k512 */
	hex_to_bin("F726CF4BECEBDFDE9275C54B5284D0CDEEF158D8E146C027B731B6EF852C008F842B15CD0DCF168F93C9DE6B41DEE964D62777AA999E44C6CFD903E65E0096EF"
		"A271F75C45FE13CE879973C85934D0B43B49BC0ED71AD1E72A9425D2FCDA45FD1A56CE66B25EA602D9F99BDE6909F7D73C68B8A52870577D30F0C0E4D02DE2E5"
		"8871DC1EB42E2ECC89AAFC8F82B9675D3DF18EC031396ED5C51C7F418EFACAB2BBF27CC741CE602E32C7ACC0BA37C3DC129872B915A09307F301E882B745D51E", exp1, sizeof(exp1));
	hex_to_bin("379E86BCE2F0BE6DF0BAA8FEC403C6A7244B21D1D5B9193FCE79510FF2633893F58D57DABBEF0424E1E8D5ED7B485EB7381CC7235350220CA03F1D107A102BD3"
		"5FAB74869AB656D35E0F40950E1564DBDC37ECFD6C50BEE201BFA0F953AEC0A29B063993F5D019CDDE4A8AA02D440C19A4A08AD7A0CD3F2FDFEF61D0383314B5"
		"78DD157DC0173AD4D71840C3078D37829AD9FBFA89969F5C48F5D19BB70B7019454FFE01D4D14D3C677A42DCD7302F3B2486BAF216A125B04043DC10549ED157", exp2, sizeof(exp2));
	hex_to_bin("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12", key, sizeof(key));
	hex_to_bin("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", msg, sizeof(msg));
	hex_to_bin("000102030405060708090A0B0C0D0E0F", nce, sizeof(nce));

	memset(ad, 0x01, sizeof(ad));

	/* copy the nonce */
	memcpy(ncpy, nce, sizeof(nce));

	/* initialize the key parameters struct, info is optional */
	qsc_csx_keyparams kp = { key, QSC_CSX_KEY_SIZE, nce };

	status = true;

	/* initialize the state and create the round-keys */
	qsc_csx_initialize(&state, &kp, true);

	/* set associted data */
	qsc_csx_set_associated(&state, ad, sizeof(ad));

	/* test encryption */
	qsc_csx_transform(&state, enc1, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		status = false;
	}

	/* set associted data */
	qsc_csx_set_associated(&state, NULL, 0);

	/* test encryption and mac chaining */
	qsc_csx_transform(&state, enc2, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		status = false;
	}

	/* reset the nonce */
	kp.nonce = ncpy;

	/* initialize the state */
	qsc_csx_initialize(&state, &kp, false);

	/* set associted data */
	qsc_csx_set_associated(&state, ad, sizeof(ad));

	/* test decryption */
	if (qsc_csx_transform(&state, dec, enc1, sizeof(dec)) == false)
	{
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, msg, sizeof(dec)) == false)
	{
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_csx_dispose(&state);

	return status;
}

bool qsctest_csx512_stress_test()
{
	uint8_t aad[20] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t nonce[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint16_t mlen;
	size_t tctr;
	bool status;
	qsc_csx_state state;

	tctr = 0;
	status = true;

	while (tctr < CSX_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			memcpy(&mlen, pmcnt, sizeof(uint16_t));
		}

		dec = (uint8_t*)malloc(mlen);
		enc = (uint8_t*)malloc(mlen + QSC_CSX_MAC_SIZE);
		msg = (uint8_t*)malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen + QSC_CSX_MAC_SIZE);
			qsc_intutils_clear8(msg, mlen);
			memcpy(nonce, ncopy, QSC_CSX_NONCE_SIZE);

			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			qsc_csx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

			/* encrypt the message */
			qsc_csx_initialize(&state, &kp1, true);
			qsc_csx_set_associated(&state, aad, sizeof(aad));

			if (qsc_csx_transform(&state, enc, msg, mlen) == false)
			{
				status = false;
			}

			/* reset the nonce */
			memcpy(kp1.nonce, ncopy, QSC_CSX_NONCE_SIZE);

			/* decrypt the message */
			qsc_csx_initialize(&state, &kp1, false);
			qsc_csx_set_associated(&state, aad, sizeof(aad));

			if (qsc_csx_transform(&state, dec, enc, mlen) == false)
			{
				status = false;
			}

			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
			}

			free(dec);
			free(enc);
			free(msg);

			++tctr;
		}
		else
		{
			status = false;
			break;
		}
	}

	return status;
}

void qsctest_csx_run()
{
	if (qsctest_csx512_kat_test() == true)
	{
		printf_s("Success! Passed the CSX known answer tests. \n");
	}
	else
	{
		printf_s("Failure! Failed the CSX known answer tests. \n");
	}

	if (qsctest_csx512_stress_test() == true)
	{
		printf_s("Success! Passed the CSX known answer tests. \n");
	}
	else
	{
		printf_s("Failure! Failed the CSX known answer tests. \n");
	}
}