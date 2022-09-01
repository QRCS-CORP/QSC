#include "chacha_test.h"
#include "../QSC/chacha.h"
#include "../QSC/csp.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "testutils.h"
#include <stdio.h>
#include <string.h>

#define CHACHA_TEST_SAMPLE 16 * 64

bool qsctest_chacha128_kat()
{
	QSC_SIMD_ALIGN uint8_t exp[2][64] = { 0 };
	QSC_SIMD_ALIGN uint8_t msg[64] = { 0 };
	QSC_SIMD_ALIGN uint8_t out[64] = { 0 };
	QSC_SIMD_ALIGN uint8_t key[2][QSC_CHACHA_KEY128_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	bool status;

	status = true;
	qsc_intutils_clear8(msg, 64);
	qsc_intutils_clear8(nonce, 8);
	qsc_intutils_clear8(out, 64);

	qsctest_hex_to_bin("FBB87FBB8395E05DAA3B1D683C422046F913985C2AD9B23CFC06C1D8D04FF213D44A7A7CDB84929F915420A8A3DC58BF0F7ECB4B1F167BB1A5E6153FDAF4493D", exp[0], sizeof(exp[0]));
	qsctest_hex_to_bin("A276339F99316A913885A0A4BE870F0691E72B00F1B3F2239F714FE81E88E00CBBE52B4EBBE1EA15894E29658C4CB145E6F89EE4ABB045A78514482CE75AFB7C", exp[1], sizeof(exp[1]));

	qsctest_hex_to_bin("80000000000000000000000000000000", key[0], sizeof(key[0]));
	qsctest_hex_to_bin("00400000000000000000000000000000", key[1], sizeof(key[1]));

	qsc_chacha_state ctx;

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp1 = { key[0], QSC_CHACHA_KEY128_SIZE, nonce };

	qsc_chacha_initialize(&ctx, &kp1);
	qsc_chacha_transform(&ctx, out, msg, 64);

	if (qsc_intutils_are_equal8(out, exp[0], 64) == false)
	{
		qsctest_print_safe("Failure! chacha128_kat: output does not match the expected answer -CK1 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 64);

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp2 = { key[1], QSC_CHACHA_KEY128_SIZE, nonce };

	qsc_chacha_initialize(&ctx, &kp2);
	qsc_chacha_transform(&ctx, out, msg, 64);

	if (qsc_intutils_are_equal8(out, exp[1], 64) == false)
	{
		qsctest_print_safe("Failure! chacha128_kat: output does not match the expected answer -CK2 \n");
		status = false;
	}

	return status;
}

bool qsctest_chacha256_kat()
{
	uint8_t exp[2][64] = { 0 };
	uint8_t msg[64] = { 0 };
	uint8_t out[64] = { 0 };
	uint8_t key[2][QSC_CHACHA_KEY256_SIZE] = { 0 };
	uint8_t nonce[2][QSC_CHACHA_NONCE_SIZE] = { 0 };
	bool status;

	status = true;
	qsc_intutils_clear8(msg, 64);
	qsc_intutils_clear8(out, 64);

	qsctest_hex_to_bin("57459975BC46799394788DE80B928387862985A269B9E8E77801DE9D874B3F51AC4610B9F9BEE8CF8CACD8B5AD0BF17D3DDF23FD7424887EB3F81405BD498CC3", exp[0], sizeof(exp[0]));
	qsctest_hex_to_bin("92A2508E2C4084567195F2A1005E552B4874EC0504A9CD5E4DAF739AB553D2E783D79C5BA11E0653BEBB5C116651302E8D381CB728CA627B0B246E83942A2B99", exp[1], sizeof(exp[1]));

	qsctest_hex_to_bin("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D", key[0], sizeof(key[0]));
	qsctest_hex_to_bin("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12", key[1], sizeof(key[1]));

	qsctest_hex_to_bin("0D74DB42A91077DE", nonce[0], sizeof(nonce[0]));
	qsctest_hex_to_bin("167DE44BB21980E7", nonce[1], sizeof(nonce[1]));

	qsc_chacha_state ctx;

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp1 = { key[0], QSC_CHACHA_KEY256_SIZE, nonce[0] };

	qsc_chacha_initialize(&ctx, &kp1);
	qsc_chacha_transform(&ctx, out, msg, 64);

	if (qsc_intutils_are_equal8(out, exp[0], 64) == false)
	{
		qsctest_print_safe("Failure! chacha256_kat: output does not match the expected answer -CK1 \n");
		status = false;
	}

	qsc_intutils_clear8(out, 64);

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp2 = { key[1], QSC_CHACHA_KEY256_SIZE, nonce[1] };

	qsc_chacha_initialize(&ctx, &kp2);
	qsc_chacha_transform(&ctx, out, msg, 64);

	if (qsc_intutils_are_equal8(out, exp[1], 64) == false)
	{
		qsctest_print_safe("Failure! Failure! chacha256_kat: output does not match the expected answer -CK2 \n");
		status = false;
	}

	return status;
}

#if defined(QSCTEST_CHACHA_WIDE_BLOCK_TESTS)
bool qsctest_chacha128_wide_equality()
{
	QSC_SIMD_ALIGN uint8_t dec[CHACHA_TEST_SAMPLE] = { 0 };
	QSC_SIMD_ALIGN uint8_t enc[CHACHA_TEST_SAMPLE] = { 0 };
	QSC_SIMD_ALIGN uint8_t msg[CHACHA_TEST_SAMPLE] = { 0 };
	QSC_SIMD_ALIGN uint8_t key[QSC_CHACHA_KEY128_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t ncopy[QSC_CHACHA_NONCE_SIZE] = { 0 };
	qsc_chacha_state ctx1;
	qsc_chacha_state ctx2;
	size_t mctr;
	size_t moft;
	bool status;

	status = true;

	for (size_t i = 0; i < QSCTEST_CHACHA_TEST_CYCLES; ++i)
	{
		qsc_intutils_clear8(dec, sizeof(dec));
		qsc_intutils_clear8(enc, sizeof(enc));
		qsc_intutils_clear8(msg, sizeof(msg));

		/* generate the key and nonce */
		qsc_csp_generate(key, sizeof(key));
		qsc_csp_generate(ncopy, sizeof(ncopy));
		qsc_csp_generate(msg, sizeof(msg));

		/* initialize the key parameters struct */
		qsc_memutils_copy(nonce, ncopy, sizeof(nonce));
		qsc_chacha_keyparams kp1 = { key, sizeof(key), nonce };

		/* initialize the state */
		qsc_chacha_initialize(&ctx1, &kp1);

		/* encrypt the array using avx */
		qsc_chacha_transform(&ctx1, enc, msg, sizeof(msg));

		/* erase the internal state */
		qsc_chacha_dispose(&ctx1);

		/* decrypt the cipher-text using 16-byte blocks, bypassing AVX */

		/* reset the nonce */
		qsc_memutils_copy(nonce, ncopy, sizeof(nonce));
		qsc_chacha_keyparams kp2 = { key, sizeof(key), nonce };

		/* initialize the 2nd state */
		qsc_chacha_initialize(&ctx2, &kp2);

		moft = 0;
		mctr = CHACHA_TEST_SAMPLE;

		while (mctr != 0)
		{
			const size_t BLKRMD = qsc_intutils_min(QSC_CHACHA_BLOCK_SIZE, mctr);
			qsc_chacha_transform(&ctx2, (dec + moft), (enc + moft), BLKRMD);
			mctr -= BLKRMD;
			moft += BLKRMD;
		}

		/* erase the internal state */
		qsc_chacha_dispose(&ctx2);

		/* compare the decrypted cipher-text with the message */
		if (qsc_intutils_are_equal8(dec, msg, sizeof(msg)) == false)
		{
			status = false;
			break;
		}
	}

	return status;
}

bool qsctest_chacha256_wide_equality()
{
	QSC_SIMD_ALIGN uint8_t dec[CHACHA_TEST_SAMPLE] = { 0 };
	QSC_SIMD_ALIGN uint8_t enc[CHACHA_TEST_SAMPLE] = { 0 };
	QSC_SIMD_ALIGN uint8_t msg[CHACHA_TEST_SAMPLE] = { 0 };
	QSC_SIMD_ALIGN uint8_t key[QSC_CHACHA_KEY256_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t ncopy[QSC_CHACHA_NONCE_SIZE] = { 0 };
	qsc_chacha_state ctx1;
	qsc_chacha_state ctx2;
	size_t mctr;
	size_t moft;
	bool status;

	status = true;

	for (size_t i = 0; i < QSCTEST_CHACHA_TEST_CYCLES; ++i)
	{
		qsc_intutils_clear8(dec, sizeof(dec));
		qsc_intutils_clear8(enc, sizeof(enc));
		qsc_intutils_clear8(msg, sizeof(msg));

		/* generate the key and nonce */
		qsc_csp_generate(key, sizeof(key));
		qsc_csp_generate(ncopy, sizeof(ncopy));
		qsc_csp_generate(msg, sizeof(msg));

		/* initialize the key parameters struct */
		qsc_memutils_copy(nonce, ncopy, sizeof(nonce));
		qsc_chacha_keyparams kp1 = { key, sizeof(key), nonce };

		/* initialize the state */
		qsc_chacha_initialize(&ctx1, &kp1);

		/* encrypt the array using avx */
		qsc_chacha_transform(&ctx1, enc, msg, sizeof(msg));

		/* erase the internal state */
		qsc_chacha_dispose(&ctx1);

		/* decrypt the cipher-text using 16-byte blocks, bypassing AVX */

		/* reset the nonce */
		qsc_memutils_copy(nonce, ncopy, sizeof(nonce));
		qsc_chacha_keyparams kp2 = { key, sizeof(key), nonce };

		/* initialize the 2nd state */
		qsc_chacha_initialize(&ctx2, &kp2);

		moft = 0;
		mctr = CHACHA_TEST_SAMPLE;

		while (mctr != 0)
		{
			const size_t BLKRMD = qsc_intutils_min(QSC_CHACHA_BLOCK_SIZE, mctr);
			qsc_chacha_transform(&ctx2, (dec + moft), (enc + moft), BLKRMD);
			mctr -= BLKRMD;
			moft += BLKRMD;
		}

		/* erase the internal state */
		qsc_chacha_dispose(&ctx2);

		/* compare the decrypted cipher-text with the message */
		if (qsc_intutils_are_equal8(dec, msg, sizeof(msg)) == false)
		{
			status = false;
			break;
		}
	}

	return status;
}
#endif

void qsctest_chacha_run()
{
	if (qsctest_chacha128_kat() == true)
	{
		qsctest_print_safe("Success! Passed the ChaCha 128-bit key known answer test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ChaCha 128-bit key known answer test. \n");
	}

	if (qsctest_chacha256_kat() == true)
	{
		qsctest_print_safe("Success! Passed the ChaCha 256-bit key known answer test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ChaCha 256-bit key known answer test. \n");
	}

#if defined(QSCTEST_CHACHA_WIDE_BLOCK_TESTS)
	if (qsctest_chacha128_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the ChaCha 128-bit AVX mode equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ChaCha 128-bit AVX mode equality test. \n");
	}

	if (qsctest_chacha256_wide_equality() == true)
	{
		qsctest_print_safe("Success! Passed the ChaCha 256-bit AVX mode equality test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ChaCha 256-bit AVX mode equality test. \n");
	}
#endif
}
