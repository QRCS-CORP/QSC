#include "benchmark.h"
#include "rhx.h"
#include "testutils.h"
#include "timer.h"
#include "../QSC/chacha.h"
#include "../QSC/csp.h"
#include "../QSC/csx.h"
#include "../QSC/rcs.h"
#include "../QSC/sha3.h"

/* bs*sc = 1GB */
#define BUFFER_SIZE 1024
#define SAMPLE_COUNT 1000000
#define ONE_GIGABYTE 1024000000

static void aes128_cbc_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t olen;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-128 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, false, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_decrypt(&ctx, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-128 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_rhx_dispose(&ctx);
}

static void aes256_cbc_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t olen;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-256 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, false, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_decrypt(&ctx, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-256 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_rhx_dispose(&ctx);
}

static void rhx256_cbc_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t olen;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, false, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_decrypt(&ctx, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_rhx_dispose(&ctx);
}

static void rhx512_cbc_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t olen;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-512 CBC Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, false, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_cbc_decrypt(&ctx, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-512 CBC Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_rhx_dispose(&ctx);
}

static void aes128_ctrbe_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrbe_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-128 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes128_ctrle_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, AES128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-128 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes256_ctrbe_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrbe_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-256 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes256_ctrle_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, AES256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("AES-256 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx256_ctrbe_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrbe_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx256_ctrle_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, RHX256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx512_ctrbe_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-512 CTR-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx512_ctrle_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_initialize(&ctx, &kp, true, RHX512);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_ctrle_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-512 CTR-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx256_hba_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE + QSC_HBA256_MAC_LENGTH] = { 0 };
	uint8_t key[QSC_RHX256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_hba256_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_hba256_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_hba256_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-256 HBA Encryption processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rhx512_hba_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE + QSC_HBA512_MAC_LENGTH] = { 0 };
	uint8_t key[QSC_RHX512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_RHX_BLOCK_SIZE] = { 0 };
	qsc_rhx_hba512_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rhx_keyparams kp = { key, sizeof(key), iv, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rhx_hba512_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rhx_hba512_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RHX-512 HBA Encryption processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void chacha128_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_CHACHA_KEY128_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	qsc_chacha_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_chacha_keyparams kp = { key, sizeof(key), nonce };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_chacha_initialize(&ctx, &kp);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_chacha_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("CHACHA-128 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void chacha256_speed_test()
{
	uint8_t dec[BUFFER_SIZE] = { 0 };
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_CHACHA_KEY256_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	qsc_chacha_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_chacha_keyparams kp = { key, sizeof(key), nonce };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_chacha_initialize(&ctx, &kp);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_chacha_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("CHACHA-256 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void csx_speed_test()
{
	uint8_t enc[BUFFER_SIZE + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_CSX_NONCE_SIZE] = { 0 };
	qsc_csx_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_csx_keyparams kp = { key, sizeof(key), nonce, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_csx_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_csx_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("CSX-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rcs256_speed_test()
{
	uint8_t enc[BUFFER_SIZE + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t key[QSC_RCS256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0 };
	qsc_rcs_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rcs_keyparams kp = { key, sizeof(key), nonce, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rcs_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rcs_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RCS-256 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rcs512_speed_test()
{
	uint8_t enc[BUFFER_SIZE + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t key[QSC_RCS512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0 };
	qsc_rcs_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rcs_keyparams kp = { key, sizeof(key), nonce, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsctest_timer_start();

	qsc_rcs_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_rcs_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("RCS-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kpa256_benchmark()
{
	const size_t GB1 = 1000000000;
	uint8_t msg[1088] = { 0 };
	uint8_t tag[32] = { 0 };
	uint8_t key[32] = { 0 };
	qsc_kpa_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsctest_timer_start();

	qsc_kpa_initialize(&ctx, key, sizeof(key), NULL, 0);

	while (tctr < GB1 / sizeof(msg))
	{
		qsc_kpa_update(&ctx, msg, sizeof(msg));
		++tctr;
	}

	qsc_kpa_finalize(&ctx, tag, sizeof(tag));

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("HBA-256 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kpa512_benchmark()
{
	const size_t GB1 = 1000000000;
	uint8_t msg[576] = { 0 };
	uint8_t tag[64] = { 0 };
	uint8_t key[64] = { 0 };
	qsc_kpa_state ctx;
	size_t tctr;
	clock_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsctest_timer_start();

	qsc_kpa_initialize(&ctx, key, sizeof(key), NULL, 0);

	while (tctr < GB1 / sizeof(msg))
	{
		qsc_kpa_update(&ctx, msg, sizeof(msg));
		++tctr;
	}

	qsc_kpa_finalize(&ctx, tag, sizeof(tag));

	elapsed = qsctest_timer_elapsed(start);
	qsctest_print_safe("HBA-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

void qsctest_aes_speed_run()
{
	qsctest_print_line("Running the AES-128 performance benchmarks.");
	aes128_cbc_speed_test();
	aes128_ctrbe_speed_test();
	aes128_ctrle_speed_test();

	qsctest_print_line("Running the AES-256 performance benchmarks.");
	aes256_cbc_speed_test();
	aes256_ctrbe_speed_test();
	aes256_ctrle_speed_test();
}

void qsctest_rhx_speed_run()
{
	qsctest_print_line("Running the RHX-256 performance benchmarks.");
	rhx256_cbc_speed_test();
	rhx256_ctrbe_speed_test();
	rhx256_ctrle_speed_test();
	rhx256_hba_speed_test();

	qsctest_print_line("Running the RHX-512 performance benchmarks.");
	rhx512_cbc_speed_test();
	rhx512_ctrbe_speed_test();
	rhx512_ctrle_speed_test();
	rhx512_hba_speed_test();
}

void qsctest_chacha_speed_run()
{
	qsctest_print_line("Running the CHACHA-128 performance benchmarks.");
	chacha128_speed_test();

	qsctest_print_line("Running the CHACHA-256 performance benchmarks.");
	chacha256_speed_test();
}

void qsctest_csx_speed_run()
{
	qsctest_print_line("Running the CSX-512 performance benchmarks.");
	csx_speed_test();
}

void qsctest_kpa_speed_run()
{
	qsctest_print_line("Running the KPA-256 performance benchmarks.");
	kpa256_benchmark();

	qsctest_print_line("Running the KPA-512 performance benchmarks.");
	kpa512_benchmark();
}

void qsctest_rcs_speed_run()
{
	qsctest_print_line("Running the RCS-256 performance benchmarks.");
	rcs256_speed_test();

	qsctest_print_line("Running the RCS-512 performance benchmarks.");
	rcs512_speed_test();
}
