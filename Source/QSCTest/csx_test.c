#include "csx_test.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "csp.h"
#include "testutils.h"

bool qsctest_csx512_kat()
{
#if defined(QSC_CSX_AUTHENTICATED)
	uint8_t ad[20] = { 0 };
	uint8_t enc1[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t enc2[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t exp1[128 + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t exp2[128 + QSC_CSX_MAC_SIZE] = { 0 };
#else
	uint8_t enc1[128] = { 0 };
	uint8_t enc2[128] = { 0 };
	uint8_t exp1[128] = { 0 };
	uint8_t exp2[128] = { 0 };
#endif

	uint8_t dec[128] = { 0 };
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t msg[128] = { 0 };
	uint8_t nce[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t ncpy[QSC_CSX_NONCE_SIZE] = { 0 };
	bool status;
	qsc_csx_state state;


#if defined(QSC_CSX_REDUCED_ROUNDS)
#	if defined(QSC_CSX_AUTHENTICATED)
	/* csxc512p512 */
	qsctest_hex_to_bin("443D22476DB4267FFEF88BF1E49FD46792EEE75CF7EF13B839817882B6F3941D"
		"EF1808E1AF3BDD2726693CE4DBF66CC84BACCAFD288557DBAC2CCA1C5CF5F4B2"
		"CF0F7237A462EDEB45B256AE383FDAEE7170C67CE915FC158F88A196B7BA4919"
		"BE519C1ECCA65FDC7CD391C3AD92A0776A7D0994A6F299C299EA7882A9F3C654"
		"7486CF7AFB1D11FEB57A762B30ED704CEE59810D643D69DA9FC8BE4CDC5551C4"
		"3DFACCAAA2EBD16B062709AE915787777F71610B1E6A512E5D385116FFE477DB", exp1, sizeof(exp1));
	qsctest_hex_to_bin("E72FD8AF9FCE8CACADFE43B8256786FD8E60C98C0C2E8554472BFE875E27DB5B"
		"E2087240AC6CA8409B6078128DF02C49176DA411B9E0CE4D6C42448828F8A12D"
		"B0B88D0583936626FAA156EC6783DC9258980DB450F5B61BB63D07B31450501A"
		"92F5F03F9261AC1F98D3ED48C5CE076B9C73DAF4DB05F3DBE2F0A527BA189731"
		"47512D5577D99AA25816B837F55341CD797285C1B5DC161224BFD2597B79F665"
		"7D642E0F998DBE431252FE855829D601E5AA6E95E6B51108B79054C762A6142F", exp2, sizeof(exp2));
		qsc_memutils_set_value(ad, sizeof(ad), 0x01);
#	else
	qsctest_hex_to_bin("A90D03B57E0F27C6616AA5D5073550ACA3F352A732BDEB7987C5DCE98261318F"
		"7EF0479A903E1BA907B94C5BA351636D5014CC0DFAB83FD9268C5A42B7C64F08"
		"9612AAB864CA44B55377F66841F83BDB3C28FA9FEE9B9E49D62E8378C9897B86"
		"103255D2E37B7EE686EFFD07E0849FDFB77A42D29F5E3F14C8DD3FC1FB23BFA4", exp1, sizeof(exp1));

	qsctest_hex_to_bin("C54D34C9444D4DEC55CD31C999E60AC939C1256A74EF683B581512954B7DE015"
		"4CA42207C94B075EB5B2CEEB916AEA297DF8F594D5B1A7F4B675B6AF8555075E"
		"38BD96CD559F2C983740019B47F6A96268B92A5936700A7808AB983897F3E8B7"
		"61A929B326C05FEA9CA8F4D4A17D9C346E80E87F62048D0E88AE6219C292FF05", exp2, sizeof(exp2));
#	endif
#else
#	if defined(QSC_CSX_AUTHENTICATED)
	/* csxc512p512 */
	qsctest_hex_to_bin("F726CF4BECEBDFDE9275C54B5284D0CDEEF158D8E146C027B731B6EF852C008F"
		"842B15CD0DCF168F93C9DE6B41DEE964D62777AA999E44C6CFD903E65E0096EF"
		"A271F75C45FE13CE879973C85934D0B43B49BC0ED71AD1E72A9425D2FCDA45FD"
		"1A56CE66B25EA602D9F99BDE6909F7D73C68B8A52870577D30F0C0E4D02DE2E5"
		"2EC8B5F4E79AD2F7A86140499FB479E9BD0EEB065E91E4F7F53953E970AA13DC"
		"96172F398E598FF7169C41A8D8E51FAF297004B2B1F242706EE34680CF9A9F9A", exp1, sizeof(exp1));
	qsctest_hex_to_bin("379E86BCE2F0BE6DF0BAA8FEC403C6A7244B21D1D5B9193FCE79510FF2633893"
		"F58D57DABBEF0424E1E8D5ED7B485EB7381CC7235350220CA03F1D107A102BD3"
		"5FAB74869AB656D35E0F40950E1564DBDC37ECFD6C50BEE201BFA0F953AEC0A2"
		"9B063993F5D019CDDE4A8AA02D440C19A4A08AD7A0CD3F2FDFEF61D0383314B5"
		"FCDFC3F96D8A40E41B35A35D4E2AFB81E0C054BA4DBC7FC183DA37E45ADA60F8"
		"F77303C276C7E3A33327EB5E481E4A8886E2E76100434D92384943C7D648C0A5", exp2, sizeof(exp2));
		qsc_memutils_set_value(ad, sizeof(ad), 0x01);
#	else
	qsctest_hex_to_bin("E1E27CD3CF085080363AC3903D31C2AE5E51D4CCF8FB9278FEFB24077A72C2AC"
		"671249C32DED5F96CBC31702CED6B3575F3B562BA9FF9E6467DE7C687AEDA54C"
		"7043FC912BF57B4892FED02E5F4D67C2404DCF99B6021FDBD1B241DBD8673F96"
		"D67A15AC380946EBE5287C61F74C8ECD6A34AF7499D145F1B74BED2A5A7CA631", exp1, sizeof(exp1));

	qsctest_hex_to_bin("026FE8D3D224909030939FF99D7308ACFF9472A3656193CFDA3991C87E955E3F"
		"E2A1C1983FF3E7D7E6B9E646F161765F70D14E2A52312E60C6EC3C774FDC1985"
		"9AE0B3C43F93F0A9900693F451D4B7A342CEB9F0BE047AE7D64C16001843B7A8"
		"0F7EC32CC7A4FF745DBF1700390017B357DF27B1CE2CC44515F2D392AE20E4A8", exp2, sizeof(exp2));
#	endif
#endif

	qsctest_hex_to_bin("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"
		"0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12", key, sizeof(key));
	qsctest_hex_to_bin("0000000000000000000000000000000000000000000000000000000000000000"
		"0000000000000000000000000000000000000000000000000000000000000000"
		"0000000000000000000000000000000000000000000000000000000000000000"
		"0000000000000000000000000000000000000000000000000000000000000000", msg, sizeof(msg));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F", nce, sizeof(nce));

	/* copy the nonce */
	qsc_memutils_copy(ncpy, nce, sizeof(nce));

	/* initialize the key parameters struct, info is optional */
	qsc_csx_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nce};

	status = true;

	/* initialize the state */
	qsc_csx_initialize(&state, &kp, true);

#if defined(QSC_CSX_AUTHENTICATED)
	/* set associated data */
	qsc_csx_set_associated(&state, ad, sizeof(ad));
#endif

	/* test encryption */

	qsc_csx_transform(&state, enc1, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc1, exp1, sizeof(exp1)) == false)
	{
		qsctest_print_safe("Failure! csx512_kat: output does not match the expected answer -CK1 \n");
		status = false;
	}

#if defined(QSC_CSX_AUTHENTICATED)
	/* set associated data */
	qsc_csx_set_associated(&state, ad, sizeof(ad));
#endif

	/* test encryption and chaining */

	qsc_csx_transform(&state, enc2, msg, sizeof(msg));

	if (qsc_intutils_are_equal8(enc2, exp2, sizeof(exp2)) == false)
	{
		qsctest_print_safe("Failure! csx512_kat: output does not match the expected answer -CK2 \n");
		status = false;
	}

	/* reset the nonce */
	kp.nonce = ncpy;

	/* initialize the state */
	qsc_csx_initialize(&state, &kp, false);

#if defined(QSC_CSX_AUTHENTICATED)
	/* set associated data */
	qsc_csx_set_associated(&state, ad, sizeof(ad));
#endif

	/* test decryption */

	if (qsc_csx_transform(&state, dec, enc1, sizeof(dec)) == false)
	{
		qsctest_print_safe("Failure! csx512_kat: output does not match the expected answer -CK3 \n");
		status = false;
	}

	if (qsc_intutils_are_equal8(dec, msg, sizeof(dec)) == false)
	{
		qsctest_print_safe("Failure! csx512_kat: output does not match the expected answer -CK4 \n");
		status = false;
	}

	/* erase the round-key array and reset the state */
	qsc_csx_dispose(&state);

	return status;
}

bool qsctest_csx512_stress()
{
#if defined(QSC_CSX_AUTHENTICATED)
	uint8_t aad[20] = { 0 };
#endif
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t ncopy[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t nonce[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	uint8_t* dec;
	uint8_t* enc;
	uint8_t* msg;
	size_t mlen;
	size_t tctr;
	bool status;
	qsc_csx_state state;

	tctr = 0;
	status = true;

	while (tctr < QSCTEST_CSX_TEST_CYCLES)
	{
		mlen = 0;

		while (mlen == 0)
		{
			/* unlikely but this could return zero */
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			qsc_memutils_copy(&mlen, pmcnt, sizeof(uint16_t));
		}

		dec = (uint8_t*)qsc_memutils_malloc(mlen);
		enc = (uint8_t*)qsc_memutils_malloc(mlen + QSC_CSX_MAC_SIZE);
		msg = (uint8_t*)qsc_memutils_malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
			qsc_intutils_clear8(enc, mlen + QSC_CSX_MAC_SIZE);
			qsc_intutils_clear8(msg, mlen);
			qsc_memutils_copy(nonce, ncopy, QSC_CSX_NONCE_SIZE);

			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			qsc_csx_keyparams kp1 = { .key = key, .keylen = sizeof(key), .nonce = nonce };

			/* encrypt the message */
			qsc_csx_initialize(&state, &kp1, true);

#if defined(QSC_CSX_AUTHENTICATED)
			qsc_csx_set_associated(&state, aad, sizeof(aad));
#endif

			if (qsc_csx_transform(&state, enc, msg, mlen) == false)
			{
				qsctest_print_safe("Failure! csx512_stress: encryption failure -CS1 \n");
				status = false;
			}

			/* reset the nonce */
			qsc_memutils_copy(kp1.nonce, ncopy, QSC_CSX_NONCE_SIZE);

			/* decrypt the message */
			qsc_csx_initialize(&state, &kp1, false);

#if defined(QSC_CSX_AUTHENTICATED)
			qsc_csx_set_associated(&state, aad, sizeof(aad));
#endif

			if (qsc_csx_transform(&state, dec, enc, mlen) == false)
			{
				qsctest_print_safe("Failure! csx512_stress: decryption failure -CS2 \n");
				status = false;
			}

			/* compare decryption output to message */
			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				qsctest_print_safe("Failure! csx512_stress: authentication failure -CS3 \n");
				status = false;
			}

			qsc_memutils_alloc_free(dec);
			qsc_memutils_alloc_free(enc);
			qsc_memutils_alloc_free(msg);

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

#if defined(QSCTEST_CSX_WIDE_BLOCK_TESTS)
bool qsctest_csx_wide_equality()
{
	const size_t SMPMIN = 16 * 128;
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t nonce[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t ncopy[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
	qsc_csx_state ctx1;
	qsc_csx_state ctx2;
	uint8_t* dec;
	uint8_t* enc;
	uint8_t* msg;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	bool status;

	tctr = 0;
	status = true;

	while (tctr < QSCTEST_CSX_TEST_CYCLES)
	{
		mlen = 0;

		do
		{
			qsc_csp_generate(pmcnt, sizeof(pmcnt));
			qsc_memutils_copy(&mlen, pmcnt, sizeof(uint16_t));
		} 
		while (mlen < SMPMIN);

		dec = (uint8_t*)qsc_memutils_malloc(mlen);
#if defined(QSC_CSX_AUTHENTICATED)
		enc = (uint8_t*)qsc_memutils_malloc(mlen + QSC_CSX_MAC_SIZE);
#else
		enc = (uint8_t*)qsc_memutils_malloc(mlen);
#endif
		msg = (uint8_t*)qsc_memutils_malloc(mlen);

		if (dec != NULL && enc != NULL && msg != NULL)
		{
			qsc_intutils_clear8(dec, mlen);
#if defined(QSC_CSX_AUTHENTICATED)
			qsc_intutils_clear8(enc, mlen + QSC_CSX_MAC_SIZE);
#else
			qsc_intutils_clear8(enc, mlen);
#endif
			qsc_intutils_clear8(msg, mlen);

			/* generate the key and nonce */
			qsc_csp_generate(key, sizeof(key));
			qsc_csp_generate(ncopy, sizeof(ncopy));
			/* use a random sized message 1-65535 */
			qsc_csp_generate(msg, mlen);

			/* initialize the key parameters struct */
			qsc_memutils_copy(nonce, ncopy, sizeof(nonce));
			qsc_csx_keyparams kp1 = { .key = key, .keylen = sizeof(key), .nonce = nonce };

			/* initialize the state */
			qsc_csx_initialize(&ctx1, &kp1, true);

			/* encrypt the array */
			qsc_csx_transform(&ctx1, enc, msg, mlen);

			/* erase the internal state */
			qsc_csx_dispose(&ctx1);

			/* reset the nonce */
			qsc_memutils_copy(nonce, ncopy, sizeof(nonce));
			qsc_csx_keyparams kp2 = { .key = key, .keylen = sizeof(key), .nonce = nonce };

			/* initialize the state */
			qsc_csx_initialize(&ctx2, &kp2, false);

			/* encrypt using 16-byte blocks, bypassing AVX512 */

			mctr = mlen;
			moft = 0;

			while (mctr != 0)
			{
				const size_t BLKRMD = qsc_intutils_min(QSC_CSX_BLOCK_SIZE, mctr);
				qsc_csx_transform(&ctx2, (uint8_t*)(dec + moft), (uint8_t*)(enc + moft), BLKRMD);
				mctr -= BLKRMD;
				moft += BLKRMD;
			}

			/* erase the internal state */
			qsc_csx_dispose(&ctx2);

			if (qsc_intutils_are_equal8(dec, msg, mlen) == false)
			{
				status = false;
				break;
			}

			/* reset the state */
			qsc_memutils_alloc_free(dec);
			qsc_memutils_alloc_free(enc);
			qsc_memutils_alloc_free(msg);
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
#endif

void qsctest_csx_run()
{
	if (qsctest_csx512_kat() == true)
	{
		qsctest_print_safe("Success! Passed the CSX known answer tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CSX known answer tests. \n");
	}

	if (qsctest_csx512_stress() == true)
	{
		qsctest_print_safe("Success! Passed the CSX stress tests. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CSX stress tests. \n");
	}

#if defined(QSCTEST_CSX_WIDE_BLOCK_TESTS)
	if (qsctest_csx_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the CSX AVX equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the CSX AVX equality test. \n");
	}
#endif
}
