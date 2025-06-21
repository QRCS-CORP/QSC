#include "chacha_test.h"
#include "chacha.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "testutils.h"
#include <stdio.h>
#include <string.h>

#define CHACHA_TEST_SAMPLE 16 * 64

bool qsctest_chacha128_kat()
{
	QSC_SIMD_ALIGN uint8_t ctext[114] = { 0 };
	QSC_SIMD_ALIGN uint8_t cexp[114] = { 0 };
	QSC_SIMD_ALIGN uint8_t input[114] = { 0 };
	QSC_SIMD_ALIGN uint8_t key[QSC_CHACHA_KEY128_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t ptext[114] = { 0 };
	bool status;

	status = true;

	qsctest_hex_to_bin("4C616469657320616E642047656E746C656D656E206F662074686520636C6173"
		"73206F66202739393A204966204920636F756C64206F6666657220796F75206F"
		"6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73"
		"637265656E20776F756C642062652069742E", input, sizeof(input));
	qsctest_hex_to_bin("808182838485868788898A8B8C8D8E8F", key, sizeof(key));
	qsctest_hex_to_bin("070000004041424344454647", nonce, sizeof(nonce));
	qsctest_hex_to_bin("9ECE0069991CE8E91A5F7AA3F723CA6AAF436D210F8021D31FD7B338BB39DC6E"
		"7A488701446A2A542480611145A5597FD46E8004ECB3E2BF9C6337624ABF30D9"
		"677931A2BE0ACAC083BA44A1455843BD89C87048C1345748CA2A155C3242FE81"
		"A4AC18F76B6411AAF5DF0E7CD82AC9F226BC", cexp, sizeof(cexp));

	qsc_chacha_state ctx;

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

	qsc_chacha_initialize(&ctx, &kp);
	qsc_chacha_transform(&ctx, ctext, input, sizeof(input));

	if (qsc_intutils_are_equal8(ctext, cexp, sizeof(ctext)) == false)
	{
		qsctest_print_safe("Failure! chacha256_kat: output does not match the expected answer -CK1 \n");
		status = false;
	}

	/* initialize the key parameters struct */

	qsc_chacha_initialize(&ctx, &kp);
	qsc_chacha_transform(&ctx, ptext, ctext, sizeof(ctext));

	if (qsc_intutils_are_equal8(ptext, input, sizeof(ptext)) == false)
	{
		qsctest_print_safe("Failure! Failure! chacha256_kat: output does not match the expected answer -CK2 \n");
		status = false;
	}

	return status;
}

bool qsctest_chacha256_kat()
{
	/* RFC 7539 Vector, section 2.3.2: https://www.rfc-editor.org/rfc/rfc7539.html */
	QSC_SIMD_ALIGN uint8_t ctext[114] = { 0 };
	QSC_SIMD_ALIGN uint8_t cexp[114] = { 0 };
	QSC_SIMD_ALIGN uint8_t input[114] = { 0 };
	QSC_SIMD_ALIGN uint8_t key[QSC_CHACHA_KEY256_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t ptext[114] = { 0 };
	bool status;

	status = true;

	qsctest_hex_to_bin("4C616469657320616E642047656E746C656D656E206F662074686520636C6173"
		"73206F66202739393A204966204920636F756C64206F6666657220796F75206F"
		"6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73"
		"637265656E20776F756C642062652069742E", input, sizeof(input));
	qsctest_hex_to_bin("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", key, sizeof(key));
	qsctest_hex_to_bin("000000090000004A00000000", nonce, sizeof(nonce));
	qsctest_hex_to_bin("C6BDF594FA87D094756B8D179A7BA25B816398CC26A334E7F7CF2720335074F1"
		"BEB85C505D2D6DEC471CD7FFAF002E85F3D6207BD9865FC130F6E554067F15BB"
		"7E9D9EC4BE553C352466AD3FC54F03E4B3B991E755B51C76764786BAB0A1023D"
		"B1F0012369BFDD6661AEB325BBEE22CBC13C", cexp, sizeof(cexp));

	qsc_chacha_state ctx;

	/* initialize the key parameters struct */
	qsc_chacha_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

	qsc_chacha_initialize(&ctx, &kp);
	qsc_chacha_transform(&ctx, ctext, input, sizeof(input));

	if (qsc_intutils_are_equal8(ctext, cexp, sizeof(ctext)) == false)
	{
		qsctest_print_safe("Failure! chacha256_kat: output does not match the expected answer -CK1 \n");
		status = false;
	}

	/* initialize the key parameters struct */

	qsc_chacha_initialize(&ctx, &kp);
	qsc_chacha_transform(&ctx, ptext, ctext, sizeof(ctext));

	if (qsc_intutils_are_equal8(ptext, input, sizeof(ptext)) == false)
	{
		qsctest_print_safe("Failure! Failure! chacha256_kat: output does not match the expected answer -CK2 \n");
		status = false;
	}

	return status;
}

bool qsctest_chacha256_poly1305_kat()
{
	/* RFC 7539 Vector, section 2.8.2: https://www.rfc-editor.org/rfc/rfc7539.html */
	QSC_SIMD_ALIGN uint8_t aad[12] = { 0 };
	QSC_SIMD_ALIGN uint8_t ctext[130] = { 0 };
	QSC_SIMD_ALIGN uint8_t cexp[130] = { 0 };
	QSC_SIMD_ALIGN uint8_t input[114] = { 0 };
	QSC_SIMD_ALIGN uint8_t key[QSC_CHACHA_KEY256_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	QSC_SIMD_ALIGN uint8_t ptext[114] = { 0 };
	qsc_chacha_poly1305_state state = { 0 };
	bool status;

	qsctest_hex_to_bin("50515253C0C1C2C3C4C5C6C7", aad, sizeof(aad));
	qsctest_hex_to_bin("4C616469657320616E642047656E746C656D656E206F662074686520636C6173"
		"73206F66202739393A204966204920636F756C64206F6666657220796F75206F"
		"6E6C79206F6E652074697020666F7220746865206675747572652C2073756E73"
		"637265656E20776F756C642062652069742E", input, sizeof(input));
	qsctest_hex_to_bin("808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F", key, sizeof(key));
	qsctest_hex_to_bin("070000004041424344454647", nonce, sizeof(nonce));
	qsctest_hex_to_bin("D31A8D34648E60DB7B86AFBC53EF7EC2A4ADED51296E08FEA9E2B5A736EE62D6"
		"3DBEA45E8CA9671282FAFB69DA92728B1A71DE0A9E060B2905D6A5B67ECD3B36"
		"92DDBD7F2D778B8C9803AEE328091B58FAB324E4FAD675945585808B4831D7BC"
		"3FF4DEF08E4B7A9DE576D26586CEC64B61161AE10B594F09E26A7E902ECBD060"
		"0691", cexp, sizeof(cexp));

	qsc_chacha_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

	status = true;

	qsc_chacha_poly1305_initialize(&state, &kp);
	qsc_chacha_poly1305_set_associated(&state, aad, sizeof(aad));
	qsc_chacha_poly1305_encrypt(&state, ctext, input, sizeof(input));

	if (qsc_intutils_are_equal8(ctext, cexp, sizeof(cexp)) == false)
	{
		qsctest_print_safe("Failure! chacha256_poly1305_kat: encryption output does not match the expected answer -CPK1 \n");
		status = false;
	}

	qsc_chacha_poly1305_dispose(&state);
	qsc_chacha_poly1305_initialize(&state, &kp);
	qsc_chacha_poly1305_set_associated(&state, aad, sizeof(aad));

	if (qsc_chacha_poly1305_decrypt(&state, ptext, ctext, sizeof(ctext)) == false)
	{
		qsctest_print_safe("Failure! chacha256_poly1305_kat: decryption failed authentication -CPK2 \n");
		status = false;
	}

	if (qsc_intutils_are_equal8(input, ptext, sizeof(input)) == false)
	{
		qsctest_print_safe("Failure! chacha256_poly1305_kat: decryption output does not match the expected answer -CPK3 \n");
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
		qsc_chacha_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

		/* initialize the state */
		qsc_chacha_initialize(&ctx1, &kp);

		/* encrypt the array using avx */
		qsc_chacha_transform(&ctx1, enc, msg, sizeof(msg));

		/* erase the internal state */
		qsc_chacha_dispose(&ctx1);

		/* decrypt the cipher-text using 16-byte blocks, bypassing AVX */

		/* initialize the 2nd state */
		qsc_chacha_initialize(&ctx2, &kp);

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
		qsc_chacha_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

		/* initialize the state */
		qsc_chacha_initialize(&ctx1, &kp);

		/* encrypt the array using avx */
		qsc_chacha_transform(&ctx1, enc, msg, sizeof(msg));

		/* erase the internal state */
		qsc_chacha_dispose(&ctx1);

		/* decrypt the cipher-text using 16-byte blocks, bypassing AVX */

		/* initialize the 2nd state */
		qsc_chacha_initialize(&ctx2, &kp);

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
	
	if (qsctest_chacha256_poly1305_kat() == true)
	{
		qsctest_print_safe("Success! Passed the ChaCha-Poly1305 known answer test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the ChaCha-Poly1305 known answer test. \n");
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
