#include "benchmark.h"
#include "testutils.h"
#include "../QSC/aes.h"
#include "../QSC/chacha.h"
#include "../QSC/csp.h"
#include "../QSC/csx.h"
#include "../QSC/qmac.h"
#include "../QSC/rcs.h"
#include "../QSC/sha3.h"
#include "../QSC/timerex.h"

#define BUFFER_SIZE 1024
#define SAMPLE_COUNT 1000000
#define ONE_GIGABYTE 1024000000

static void aes128_cbc_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	qsc_aes_state ctx;
	size_t olen;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_aes_keyparams kp = { key, sizeof(key), iv };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_aes_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("AES-128 qsc_aes_mode_cbc Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_aes_cbc_decrypt(&ctx, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("AES-128 qsc_aes_mode_cbc Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_aes_dispose(&ctx);
}

static void aes256_cbc_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	qsc_aes_state ctx;
	size_t olen;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_aes_keyparams kp = { key, sizeof(key), iv };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_aes_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("AES-256 qsc_aes_mode_cbc Encrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	/* decryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_aes_cbc_decrypt(&ctx, enc, &olen, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("AES-256 qsc_aes_mode_cbc Decrypt processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");

	qsc_aes_dispose(&ctx);
}

static void aes128_ctrbe_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	qsc_aes_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_aes_keyparams kp = { key, sizeof(key), iv };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_aes_ctrbe_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("AES-128 qsc_aes_mode_ctr-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes128_ctrle_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	qsc_aes_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_aes_keyparams kp = { key, sizeof(key), iv };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_aes_ctrle_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("AES-128 qsc_aes_mode_ctr-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes256_ctrbe_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	qsc_aes_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_aes_keyparams kp = { key, sizeof(key), iv };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_aes_ctrbe_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("AES-256 qsc_aes_mode_ctr-BE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void aes256_ctrle_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0 };
	qsc_aes_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and iv */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(iv, sizeof(iv));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_aes_keyparams kp = { key, sizeof(key), iv };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_aes_ctrle_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("AES-256 qsc_aes_mode_ctr-LE processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void chacha128_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_CHACHA_KEY128_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	qsc_chacha_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_chacha_keyparams kp = { key, sizeof(key), nonce };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_chacha_initialize(&ctx, &kp);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_chacha_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("CHACHA-128 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void chacha256_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE] = { 0 };
	uint8_t key[QSC_CHACHA_KEY256_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 };
	qsc_chacha_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_chacha_keyparams kp = { key, sizeof(key), nonce };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_chacha_initialize(&ctx, &kp);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_chacha_transform(&ctx, enc, msg, sizeof(msg));
		++tctr;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("CHACHA-256 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void csx_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE + QSC_CSX_MAC_SIZE] = { 0 };
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_CSX_NONCE_SIZE] = { 0 };
	qsc_csx_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_csx_keyparams kp = { key, sizeof(key), nonce, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_csx_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT - 1)
	{
		qsc_csx_extended_transform(&ctx, enc, msg, sizeof(msg), false);
		++tctr;
	}

	qsc_csx_extended_transform(&ctx, enc, msg, sizeof(msg), true);

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("CSX-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rcs256_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE + QSC_RCS256_MAC_SIZE] = { 0 };
	uint8_t key[QSC_RCS256_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0 };
	qsc_rcs_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rcs_keyparams kp = { key, sizeof(key), nonce, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_rcs_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT - 1)
	{
		qsc_rcs_extended_transform(&ctx, enc, msg, sizeof(msg), false);
		++tctr;
	}

	qsc_rcs_extended_transform(&ctx, enc, msg, sizeof(msg), true);

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("RCS-256 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void rcs512_benchmark_test()
{
	uint8_t enc[BUFFER_SIZE + QSC_RCS512_MAC_SIZE] = { 0 };
	uint8_t key[QSC_RCS512_KEY_SIZE] = { 0 };
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0 };
	qsc_rcs_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	/* generate the message, key and nonce */
	qsc_csp_generate(key, sizeof(key));
	qsc_csp_generate(nonce, sizeof(nonce));
	qsc_csp_generate(msg, sizeof(msg));
	qsc_rcs_keyparams kp = { key, sizeof(key), nonce, NULL, 0 };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_rcs_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT - 1)
	{
		qsc_rcs_extended_transform(&ctx, enc, msg, sizeof(msg), false);
		++tctr;
	}

	qsc_rcs_extended_transform(&ctx, enc, msg, sizeof(msg), true);

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("RCS-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kmac128_benchmark()
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[16] = { 0 };
	uint8_t key[16] = { 0 };
	qsc_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_kmac_initialize(&ctx, QSC_KECCAK_128_RATE, key, sizeof(key), NULL, 0);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_kmac_update(&ctx, QSC_KECCAK_128_RATE, msg, sizeof(msg));
		++tctr;
	}

	qsc_kmac_finalize(&ctx, QSC_KECCAK_128_RATE, tag, sizeof(tag));

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KMAC-128 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kmac256_benchmark()
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[32] = { 0 };
	uint8_t key[32] = { 0 };
	qsc_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_kmac_initialize(&ctx, QSC_KECCAK_256_RATE, key, sizeof(key), NULL, 0);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_kmac_update(&ctx, QSC_KECCAK_256_RATE, msg, sizeof(msg));
		++tctr;
	}

	qsc_kmac_finalize(&ctx, QSC_KECCAK_256_RATE, tag, sizeof(tag));

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KMAC-256 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kmac512_benchmark()
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[64] = { 0 };
	uint8_t key[64] = { 0 };
	qsc_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_kmac_initialize(&ctx, QSC_KECCAK_512_RATE, key, sizeof(key), NULL, 0);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_kmac_update(&ctx, QSC_KECCAK_512_RATE, msg, sizeof(msg));
		++tctr;
	}

	qsc_kmac_finalize(&ctx, QSC_KECCAK_512_RATE, tag, sizeof(tag));

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KMAC-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

#if defined(QSC_SYSTEM_HAS_AVX2)
static void kmac128x4_benchmark()
{
	uint8_t msg[4][BUFFER_SIZE] = { 0 };
	uint8_t tag[4][16] = { 0 };
	uint8_t key[4][16] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_kmac_128x4(tag[0], tag[1], tag[2], tag[3], 16, key[0], key[1], key[2], key[3], 16, 
			NULL, NULL, NULL, NULL, 0, msg[0], msg[1], msg[2], msg[3], BUFFER_SIZE);
		tctr += (4 * BUFFER_SIZE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KMAC-128x4 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kmac256x4_benchmark()
{
	uint8_t msg[4][BUFFER_SIZE] = { 0 };
	uint8_t tag[4][32] = { 0 };
	uint8_t key[4][32] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_kmac_256x4(tag[0], tag[1], tag[2], tag[3], 32, key[0], key[1], key[2], key[3], 32,
			NULL, NULL, NULL, NULL, 0, msg[0], msg[1], msg[2], msg[3], BUFFER_SIZE);
		tctr += (4 * BUFFER_SIZE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KMAC-256x4 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kmac512x4_benchmark()
{
	uint8_t msg[4][BUFFER_SIZE] = { 0 };
	uint8_t tag[4][64] = { 0 };
	uint8_t key[4][64] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_kmac_512x4(tag[0], tag[1], tag[2], tag[3], 64, key[0], key[1], key[2], key[3], 64,
			NULL, NULL, NULL, NULL, 0, msg[0], msg[1], msg[2], msg[3], BUFFER_SIZE);
		tctr += (4 * BUFFER_SIZE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KMAC-512x4 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
static void kmac128x8_benchmark()
{
	uint8_t msg[8][BUFFER_SIZE] = { 0 };
	uint8_t tag[8][16] = { 0 };
	uint8_t key[8][16] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_kmac_128x8(tag[0], tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7], 16, 
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 16,
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, 
			msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], BUFFER_SIZE);
		tctr += (8 * BUFFER_SIZE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KMAC-128x8 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kmac256x8_benchmark()
{
	uint8_t msg[8][BUFFER_SIZE] = { 0 };
	uint8_t tag[8][32] = { 0 };
	uint8_t key[8][32] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_kmac_256x8(tag[0], tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7], 32,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 32,
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0,
			msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], BUFFER_SIZE);
		tctr += (8 * BUFFER_SIZE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KMAC-256x8 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kmac512x8_benchmark()
{
	uint8_t msg[8][BUFFER_SIZE] = { 0 };
	uint8_t tag[8][64] = { 0 };
	uint8_t key[8][64] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_kmac_512x8(tag[0], tag[1], tag[2], tag[3], tag[4], tag[5], tag[6], tag[7], 64,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 64,
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0,
			msg[0], msg[1], msg[2], msg[3], msg[4], msg[5], msg[6], msg[7], BUFFER_SIZE);
		tctr += (8 * BUFFER_SIZE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KMAC-512x8 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}
#endif

static void kpa128_benchmark()
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[16] = { 0 };
	uint8_t key[16] = { 0 };
	qsc_kpa_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_kpa_initialize(&ctx, key, sizeof(key), NULL, 0);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_kpa_update(&ctx, msg, sizeof(msg));
		++tctr;
	}

	qsc_kpa_finalize(&ctx, tag, sizeof(tag));

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KPA-128 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kpa256_benchmark()
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[32] = { 0 };
	uint8_t key[32] = { 0 };
	qsc_kpa_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_kpa_initialize(&ctx, key, sizeof(key), NULL, 0);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_kpa_update(&ctx, msg, sizeof(msg));
		++tctr;
	}

	qsc_kpa_finalize(&ctx, tag, sizeof(tag));

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KPA-256 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void kpa512_benchmark()
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[64] = { 0 };
	uint8_t key[64] = { 0 };
	qsc_kpa_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_kpa_initialize(&ctx, key, sizeof(key), NULL, 0);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_kpa_finalize(&ctx, tag, sizeof(tag));
		++tctr;
	}

	qsc_kpa_update(&ctx, msg, sizeof(msg));

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("KPA-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void shake128_benchmark()
{
	uint8_t key[16] = { 0 };
	uint8_t otp[QSC_KECCAK_128_RATE] = { 0 };
	qsc_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_shake_initialize(&ctx, QSC_KECCAK_128_RATE, key, sizeof(key));

	while (tctr < ONE_GIGABYTE)
	{
		qsc_shake_squeezeblocks(&ctx, QSC_KECCAK_128_RATE, otp, 1);
		tctr += sizeof(otp);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("SHAKE-128 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void shake256_benchmark()
{
	uint8_t key[32] = { 0 };
	uint8_t otp[QSC_KECCAK_256_RATE] = { 0 };
	qsc_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_shake_initialize(&ctx, QSC_KECCAK_256_RATE, key, sizeof(key));

	while (tctr < ONE_GIGABYTE)
	{
		qsc_shake_squeezeblocks(&ctx, QSC_KECCAK_256_RATE, otp, 1);
		tctr += sizeof(otp);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("SHAKE-256 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void shake512_benchmark()
{
	uint8_t key[64] = { 0 };
	uint8_t otp[QSC_KECCAK_512_RATE] = { 0 };
	qsc_keccak_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_shake_initialize(&ctx, QSC_KECCAK_512_RATE, key, sizeof(key));

	while (tctr < ONE_GIGABYTE)
	{
		qsc_shake_squeezeblocks(&ctx, QSC_KECCAK_512_RATE, otp, 1);
		tctr += sizeof(otp);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("SHAKE-512 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

#if defined(QSC_SYSTEM_HAS_AVX2)
static void shake128x4_benchmark()
{
	uint8_t key[4][16] = { 0 };
	uint8_t otp[4][QSC_KECCAK_128_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_shake_128x4(otp[0], otp[1], otp[2], otp[3], QSC_KECCAK_128_RATE, key[0], key[1], key[2], key[3], 16);
		tctr += (4 * QSC_KECCAK_128_RATE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("SHAKE-128x4 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void shake256x4_benchmark()
{
	uint8_t key[4][32] = { 0 };
	uint8_t otp[4][QSC_KECCAK_256_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_shake_256x4(otp[0], otp[1], otp[2], otp[3], QSC_KECCAK_256_RATE, key[0], key[1], key[2], key[3], 32);
		tctr += (4 * QSC_KECCAK_256_RATE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("SHAKE-256x4 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void shake512x4_benchmark()
{
	uint8_t key[4][64] = { 0 };
	uint8_t otp[4][QSC_KECCAK_512_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_shake_512x4(otp[0], otp[1], otp[2], otp[3], QSC_KECCAK_512_RATE, key[0], key[1], key[2], key[3], 64);
		tctr += (4 * QSC_KECCAK_512_RATE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("SHAKE-512x4 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}
#endif

static void qmac_benchmark()
{
	uint8_t key[QSC_QMAC_KEY_SIZE] = { 0x03, 0x05, 0x07, 0x0B };
	uint8_t msg[QSC_QMAC_BLOCK_SIZE] = { 0x0D, 0x11, 0x13, 0x17 };
	uint8_t otp[QSC_QMAC_MAC_SIZE] = { 0 };
	qsc_qmac_state ctx;
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	qsc_qmac_keyparams kp = { key, sizeof(key), NULL, 0, NULL, 0 };
	start = qsc_timerex_stopwatch_start();

	qsc_qmac_initialize(&ctx, &kp);

	while (tctr < ONE_GIGABYTE)
	{
		qsc_qmac_update(&ctx, msg, QSC_QMAC_BLOCK_SIZE);
		tctr += QSC_QMAC_BLOCK_SIZE;
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("QMAC processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

#if defined(QSC_SYSTEM_HAS_AVX512)
static void shake128x8_benchmark()
{
	uint8_t key[8][16] = { 0 };
	uint8_t otp[8][QSC_KECCAK_128_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_shake_128x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], QSC_KECCAK_128_RATE,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 16);
		tctr += (8 * QSC_KECCAK_128_RATE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("SHAKE-128x8 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void shake256x8_benchmark()
{
	uint8_t key[8][32] = { 0 };
	uint8_t otp[8][QSC_KECCAK_256_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_shake_256x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], QSC_KECCAK_256_RATE,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 32);
		tctr += (8 * QSC_KECCAK_256_RATE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("SHAKE-256x8 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}

static void shake512x8_benchmark()
{
	uint8_t key[8][64] = { 0 };
	uint8_t otp[8][QSC_KECCAK_512_RATE] = { 0 };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	while (tctr < ONE_GIGABYTE)
	{
		qsc_shake_512x8(otp[0], otp[1], otp[2], otp[3], otp[4], otp[5], otp[6], otp[7], QSC_KECCAK_512_RATE,
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 64);
		tctr += (8 * QSC_KECCAK_512_RATE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_print_safe("SHAKE-512x8 processed 1GB of data in ");
	qsctest_print_double((double)elapsed / 1000.0);
	qsctest_print_line(" seconds");
}
#endif

void qsctest_benchmark_aes_run()
{
	qsctest_print_line("Running the AES-128 performance benchmarks.");
	aes128_cbc_benchmark_test();
	aes128_ctrbe_benchmark_test();
	aes128_ctrle_benchmark_test();

	qsctest_print_line("Running the AES-256 performance benchmarks.");
	aes256_cbc_benchmark_test();
	aes256_ctrbe_benchmark_test();
	aes256_ctrle_benchmark_test();
}

void qsctest_benchmark_chacha_run()
{
	qsctest_print_line("Running the CHACHA-128 encryption only performance benchmarks.");
	chacha128_benchmark_test();
	qsctest_print_line("Running the CHACHA-256 encryption only performance benchmarks.");
	chacha256_benchmark_test();
}

void qsctest_benchmark_csx_run()
{
	qsctest_print_line("Running the CSX-512 encryption and authentication performance benchmarks.");
	csx_benchmark_test();
}

void qsctest_benchmark_rcs_run()
{
	qsctest_print_line("Running the RCS-256 encryption and authentication performance benchmarks.");
	rcs256_benchmark_test();

	qsctest_print_line("Running the RCS-512 encryption and authentication performance benchmarks.");
	rcs512_benchmark_test();
}

void qsctest_benchmark_kmac_run()
{
	qsctest_print_line("Running the KMAC-128 performance benchmarks.");
	kmac128_benchmark();

	qsctest_print_line("Running the KMAC-256 performance benchmarks.");
	kmac256_benchmark();

	qsctest_print_line("Running the KMAC-512 performance benchmarks.");
	kmac512_benchmark();

#if defined(QSC_SYSTEM_HAS_AVX2)
	qsctest_print_line("Running the AVX2 4X KMAC-128 performance benchmarks.");
	kmac128x4_benchmark();

	qsctest_print_line("Running the AVX2 4X KMAC-256 performance benchmarks.");
	kmac256x4_benchmark();

	qsctest_print_line("Running the AVX2 4X KMAC-512 performance benchmarks.");
	kmac512x4_benchmark();
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
	qsctest_print_line("Running the AVX512 8X KMAC-128 performance benchmarks.");
	kmac128x8_benchmark();

	qsctest_print_line("Running the AVX512 8X KMAC-256 performance benchmarks.");
	kmac256x8_benchmark();

	qsctest_print_line("Running the AVX512 8X KMAC-512 performance benchmarks.");
	kmac512x8_benchmark();
#endif
}

void qsctest_benchmark_kpa_run()
{
	qsctest_print_line("Running the KPA-128 performance benchmarks.");
	kpa128_benchmark();

	qsctest_print_line("Running the KPA-256 performance benchmarks.");
	kpa256_benchmark();

	qsctest_print_line("Running the KPA-512 performance benchmarks.");
	kpa512_benchmark();
}

void qsctest_benchmark_shake_run()
{
	qsctest_print_line("Running the SHAKE-128 performance benchmarks.");
	shake128_benchmark();

	qsctest_print_line("Running the SHAKE-256 performance benchmarks.");
	shake256_benchmark();

	qsctest_print_line("Running the SHAKE-512 performance benchmarks.");
	shake512_benchmark();

#if defined(QSC_SYSTEM_HAS_AVX2)
	qsctest_print_line("Running the AVX2 4X SHAKE-128 performance benchmarks.");
	shake128x4_benchmark();

	qsctest_print_line("Running the AVX2 4X SHAKE-256 performance benchmarks.");
	shake256x4_benchmark();

	qsctest_print_line("Running the AVX2 4X SHAKE-512 performance benchmarks.");
	shake512x4_benchmark();
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
	qsctest_print_line("Running the AVX512 8X SHAKE-128 performance benchmarks.");
	shake128x8_benchmark();

	qsctest_print_line("Running the AVX512 8X SHAKE-256 performance benchmarks.");
	shake256x8_benchmark();

	qsctest_print_line("Running the AVX512 8X SHAKE-512 performance benchmarks.");
	shake512x8_benchmark();
#endif
}

void qsctest_benchmark_qmac_run()
{
	qsctest_print_line("Running the QMAC performance benchmarks.");
	qmac_benchmark();
}