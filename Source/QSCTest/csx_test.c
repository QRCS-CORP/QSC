#include "csx_test.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/sha3.h"
#include "../QSC/csp.h"
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

	/* vectors from CEX */
#if defined(QSC_CSX_AUTHENTICATED)
#	if defined(QSC_CSX_AUTH_KMACR12)
	/* csxc512p512 */
	qsctest_hex_to_bin("F726CF4BECEBDFDE9275C54B5284D0CDEEF158D8E146C027B731B6EF852C008F"
		"842B15CD0DCF168F93C9DE6B41DEE964D62777AA999E44C6CFD903E65E0096EF"
		"A271F75C45FE13CE879973C85934D0B43B49BC0ED71AD1E72A9425D2FCDA45FD"
		"1A56CE66B25EA602D9F99BDE6909F7D73C68B8A52870577D30F0C0E4D02DE2E5"
		"5FCF2735ADF4D7A22FB2EA72172F0E06173C56991CA24C7927A213F4D548F155"
		"4240A769A599A75A8A2DA332B260FECC1B0F30E74990AF855F0D3DB5041947E9", exp1, sizeof(exp1));
	qsctest_hex_to_bin("379E86BCE2F0BE6DF0BAA8FEC403C6A7244B21D1D5B9193FCE79510FF2633893"
		"F58D57DABBEF0424E1E8D5ED7B485EB7381CC7235350220CA03F1D107A102BD3"
		"5FAB74869AB656D35E0F40950E1564DBDC37ECFD6C50BEE201BFA0F953AEC0A2"
		"9B063993F5D019CDDE4A8AA02D440C19A4A08AD7A0CD3F2FDFEF61D0383314B5"
		"17EE1D270EE97F7443D8334024FA3A656395B240328DFDD87293457F11074ED9"
		"4A9A3D32F48CD88EC4550531B0B6B36413622BBC27570828E054FC2CF15BD998", exp2, sizeof(exp2));
#elif defined(QSC_CSX_AUTH_KMAC24)
	/* csxc512k512 */
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
#	else
	/* csxc512q256 */
	qsctest_hex_to_bin("F726CF4BECEBDFDE9275C54B5284D0CDEEF158D8E146C027B731B6EF852C008F"
		"842B15CD0DCF168F93C9DE6B41DEE964D62777AA999E44C6CFD903E65E0096EF"
		"A271F75C45FE13CE879973C85934D0B43B49BC0ED71AD1E72A9425D2FCDA45FD"
		"1A56CE66B25EA602D9F99BDE6909F7D73C68B8A52870577D30F0C0E4D02DE2E5"
		"13B04B2DD5AC152470E52E7771932258348E918604A42A54F6383D46EFE27226", exp1, sizeof(exp1));
	qsctest_hex_to_bin("379E86BCE2F0BE6DF0BAA8FEC403C6A7244B21D1D5B9193FCE79510FF2633893"
		"F58D57DABBEF0424E1E8D5ED7B485EB7381CC7235350220CA03F1D107A102BD3"
		"5FAB74869AB656D35E0F40950E1564DBDC37ECFD6C50BEE201BFA0F953AEC0A2"
		"9B063993F5D019CDDE4A8AA02D440C19A4A08AD7A0CD3F2FDFEF61D0383314B5"
		"3285521CBCDC258DD1C8621606EA76D846A9E7272E3294BBF02DF3C546A46CD7", exp2, sizeof(exp2));
#	endif
	qsc_memutils_set_value(ad, sizeof(ad), 0x01);
#else
	qsctest_hex_to_bin("E1E27CD3CF085080363AC3903D31C2AE5E51D4CCF8FB9278FEFB24077A72C2AC"
		"671249C32DED5F96CBC31702CED6B3575F3B562BA9FF9E6467DE7C687AEDA54C"
		"7043FC912BF57B4892FED02E5F4D67C2404DCF99B6021FDBD1B241DBD8673F96"
		"D67A15AC380946EBE5287C61F74C8ECD6A34AF7499D145F1B74BED2A5A7CA631", exp1, sizeof(exp1));

	qsctest_hex_to_bin("026FE8D3D224909030939FF99D7308ACFF9472A3656193CFDA3991C87E955E3F"
		"E2A1C1983FF3E7D7E6B9E646F161765F70D14E2A52312E60C6EC3C774FDC1985"
		"9AE0B3C43F93F0A9900693F451D4B7A342CEB9F0BE047AE7D64C16001843B7A8"
		"0F7EC32CC7A4FF745DBF1700390017B357DF27B1CE2CC44515F2D392AE20E4A8", exp2, sizeof(exp2));
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
	qsc_csx_keyparams kp = { key, QSC_CSX_KEY_SIZE, nce };

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
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t ncopy[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t nonce[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
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

			qsc_csx_keyparams kp1 = { key, sizeof(key), nonce, NULL, 0 };

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
	uint8_t* dec;
	uint8_t* enc;
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t* msg;
	uint8_t nonce[QSC_CSX_NONCE_SIZE] = { 0 };
	uint8_t ncopy[QSC_CSX_NONCE_SIZE] = { 0 };
	qsc_csx_state ctx1;
	qsc_csx_state ctx2;
	size_t mctr;
	size_t moft;
	size_t mlen;
	size_t tctr;
	uint8_t pmcnt[sizeof(uint16_t)] = { 0 };
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
			qsc_csx_keyparams kp1 = { key, sizeof(key), nonce };

			/* initialize the state */
			qsc_csx_initialize(&ctx1, &kp1, true);

			/* encrypt the array */
			qsc_csx_transform(&ctx1, enc, msg, mlen);

			/* erase the internal state */
			qsc_csx_dispose(&ctx1);

			/* reset the nonce */
			qsc_memutils_copy(nonce, ncopy, sizeof(nonce));
			qsc_csx_keyparams kp2 = { key, sizeof(key), nonce };

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
