/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */


#include "benchmark.h"
#include "testutils.h"
#include "aes.h"
#include "chacha.h"
#include "csp.h"
#include "csx.h"
#include "qmac.h"
#include "rcs.h"
#include "sha3.h"
#include "timerex.h"
#include "intutils.h"
#include "memutils.h"
#include <stdio.h>

/* All benchmark entry points operate on the same exact byte budget.  For
 * short smoke runs, compile with -DQSCTEST_BENCHMARK_SAMPLE_COUNT=4. */
#define BUFFER_SIZE 1024U
#ifndef QSCTEST_BENCHMARK_SAMPLE_COUNT
#   define QSCTEST_BENCHMARK_SAMPLE_COUNT 1048576U
#endif
#if QSCTEST_BENCHMARK_SAMPLE_COUNT < 1
#error QSCTEST_BENCHMARK_SAMPLE_COUNT must be positive
#endif
#define SAMPLE_COUNT QSCTEST_BENCHMARK_SAMPLE_COUNT
#define ONE_GIGABYTE ((size_t)BUFFER_SIZE * (size_t)SAMPLE_COUNT)

/* Volatile escape prevents the compiler from discarding the output. */
static volatile uint8_t qsctest_benchmark_sink;

/** \brief Report the actual processed byte count and observed throughput. */
static void qsctest_benchmark_report(const char* name, size_t processed, uint64_t elapsed)
{
	char line[160U] = { 0 };
	double seconds;

	seconds = (double)elapsed / 1000.0;
	qsctest_print_line(name);
	(void)snprintf(line, sizeof(line), "  Data processed : %.3f MiB", (double)processed / 1048576.0);
	qsctest_print_line(line);
	(void)snprintf(line, sizeof(line), "  Elapsed        : %.3f s", seconds);
	qsctest_print_line(line);
	if (elapsed != 0U)
	{
		(void)snprintf(line, sizeof(line), "  Throughput     : %.3f MiB/s", ((double)processed / 1048576.0) / seconds);
		qsctest_print_line(line);
	}
	else
	{
		qsctest_print_line("  Throughput     : Unavailable (timer resolution)");
	}
	qsctest_print_line("");
}


static void aes128_cbc_benchmark_test()
{
    uint8_t enc[BUFFER_SIZE] = { 0U };
    uint8_t dec[BUFFER_SIZE] = { 0U };
    uint8_t key[QSC_AES128_KEY_SIZE] = { 0U };
    uint8_t msg[BUFFER_SIZE - 1U] = { 0U };
    uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0U };
    uint8_t initial_iv[QSC_AES_BLOCK_SIZE] = { 0U };
    qsc_aes_state ctx;
    qsc_aes_keyparams kp;
    size_t olen;
    size_t tctr;
    uint64_t start;
    uint64_t elapsed;
    bool passed;

    passed = qsc_csp_generate(key, sizeof(key));
    passed = qsc_csp_generate(iv, sizeof(iv)) && passed;
    passed = qsc_csp_generate(msg, sizeof(msg)) && passed;
    qsc_memutils_copy(initial_iv, iv, sizeof(iv));
    kp.key = key;
    kp.keylen = sizeof(key);
    kp.info = NULL;
    kp.infolen = 0U;
    kp.nonce = iv;
    kp.noncelen = sizeof(iv);

    /* Verify an actual PKCS7-padded encrypt/decrypt record before timing. */
    if (passed)
    {
        qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);
        qsc_aes_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
        qsc_aes_dispose(&ctx);
        qsc_memutils_copy(iv, initial_iv, sizeof(iv));
        qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_128);
        olen = 0U;
        qsc_aes_cbc_decrypt(&ctx, dec, &olen, enc, sizeof(enc));
        passed = olen == sizeof(msg) && qsc_memutils_are_equal(dec, msg, sizeof(msg));
        qsc_aes_dispose(&ctx);
    }
    if (passed == false)
    {
        qsctest_print_line("FAIL: AES-128 CBC benchmark preflight encrypt/decrypt");
        return;
    }

    qsc_memutils_copy(iv, initial_iv, sizeof(iv));
    tctr = 0U;
    start = qsc_timerex_stopwatch_start();

    while (tctr < SAMPLE_COUNT)
    {
        qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);
        qsc_aes_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
        qsc_aes_dispose(&ctx);
        qsc_intutils_be8increment(iv, sizeof(iv));
        ++tctr;
    }

    elapsed = qsc_timerex_stopwatch_elapsed(start);
    qsctest_benchmark_sink ^= enc[0U];
    qsctest_benchmark_report("AES-128 CBC encrypt, independent padded records", tctr * sizeof(msg), elapsed);

    /* Decrypt the preflight ciphertext (not plaintext), with the matching IV. */
    qsc_memutils_copy(iv, initial_iv, sizeof(iv));
    qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);
    qsc_aes_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
    qsc_aes_dispose(&ctx);
    tctr = 0U;
    start = qsc_timerex_stopwatch_start();
    while (tctr < SAMPLE_COUNT)
    {
        qsc_memutils_copy(iv, initial_iv, sizeof(iv));
        qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_128);
        olen = 0U;
        qsc_aes_cbc_decrypt(&ctx, dec, &olen, enc, sizeof(enc));
        qsc_aes_dispose(&ctx);

        if (olen != sizeof(msg) || qsc_memutils_are_equal(dec, msg, sizeof(msg)) == false)
        {
            qsctest_print_line("FAIL: AES-128 CBC decrypt benchmark verification");
            return;
        }

        ++tctr;
    }
    elapsed = qsc_timerex_stopwatch_elapsed(start);
    qsctest_benchmark_sink ^= dec[0U];
    qsctest_benchmark_report("AES-128 CBC decrypt, independent padded records", tctr * sizeof(msg), elapsed);
}

static void aes256_cbc_benchmark_test()
{
    uint8_t enc[BUFFER_SIZE] = { 0U };
    uint8_t dec[BUFFER_SIZE] = { 0U };
    uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
    uint8_t msg[BUFFER_SIZE - 1U] = { 0U };
    uint8_t iv[QSC_AES_BLOCK_SIZE] = { 0U };
    uint8_t initial_iv[QSC_AES_BLOCK_SIZE] = { 0U };
    qsc_aes_state ctx;
    qsc_aes_keyparams kp;
    size_t olen;
    size_t tctr;
    uint64_t start;
    uint64_t elapsed;
    bool passed;

    passed = qsc_csp_generate(key, sizeof(key));
    passed = qsc_csp_generate(iv, sizeof(iv)) && passed;
    passed = qsc_csp_generate(msg, sizeof(msg)) && passed;
    qsc_memutils_copy(initial_iv, iv, sizeof(iv));
    kp.key = key;
    kp.keylen = sizeof(key);
    kp.info = NULL;
    kp.infolen = 0U;
    kp.nonce = iv;
    kp.noncelen = sizeof(iv);

    /* Verify an actual PKCS7-padded encrypt/decrypt record before timing. */
    if (passed)
    {
        qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
        qsc_aes_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
        qsc_aes_dispose(&ctx);
        qsc_memutils_copy(iv, initial_iv, sizeof(iv));
        qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_256);
        olen = 0U;
        qsc_aes_cbc_decrypt(&ctx, dec, &olen, enc, sizeof(enc));
        passed = olen == sizeof(msg) && qsc_memutils_are_equal(dec, msg, sizeof(msg));
        qsc_aes_dispose(&ctx);
    }
    if (passed == false)
    {
        qsctest_print_line("FAIL: AES-256 CBC benchmark preflight encrypt/decrypt");
        return;
    }

    qsc_memutils_copy(iv, initial_iv, sizeof(iv));
    tctr = 0U;
    start = qsc_timerex_stopwatch_start();

    while (tctr < SAMPLE_COUNT)
    {
        qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
        qsc_aes_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
        qsc_aes_dispose(&ctx);
        qsc_intutils_be8increment(iv, sizeof(iv));
        ++tctr;
    }

    elapsed = qsc_timerex_stopwatch_elapsed(start);
    qsctest_benchmark_sink ^= enc[0U];
    qsctest_benchmark_report("AES-256 CBC encrypt, independent padded records", tctr * sizeof(msg), elapsed);

    /* Decrypt the preflight ciphertext (not plaintext), with the matching IV. */
    qsc_memutils_copy(iv, initial_iv, sizeof(iv));
    qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
    qsc_aes_cbc_encrypt(&ctx, enc, msg, sizeof(msg));
    qsc_aes_dispose(&ctx);
    tctr = 0U;
    start = qsc_timerex_stopwatch_start();

    while (tctr < SAMPLE_COUNT)
    {
        qsc_memutils_copy(iv, initial_iv, sizeof(iv));
        qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_256);
        olen = 0U;
        qsc_aes_cbc_decrypt(&ctx, dec, &olen, enc, sizeof(enc));
        qsc_aes_dispose(&ctx);

        if (olen != sizeof(msg) || qsc_memutils_are_equal(dec, msg, sizeof(msg)) == false)
        {
            qsctest_print_line("FAIL: AES-256 CBC decrypt benchmark verification");
            return;
        }

        ++tctr;
    }

    elapsed = qsc_timerex_stopwatch_elapsed(start);
    qsctest_benchmark_sink ^= dec[0U];
    qsctest_benchmark_report("AES-256 CBC decrypt, independent padded records", tctr * sizeof(msg), elapsed);
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
	qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = iv, .noncelen = sizeof(iv) };

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
	qsctest_benchmark_report("AES-128 CTR-BE Mode", tctr * BUFFER_SIZE, elapsed);
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
	qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = iv, .noncelen = sizeof(iv) };

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
	qsctest_benchmark_report("AES-128 CTR-LE", tctr * BUFFER_SIZE, elapsed);
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
	qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = iv, .noncelen = sizeof(iv) };

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
	qsctest_benchmark_report("AES-256 CTR-BE Mode", tctr * BUFFER_SIZE, elapsed);
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
	qsc_aes_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = iv, .noncelen = sizeof(iv) };

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
	qsctest_benchmark_report("AES-256 CTR-LE Mode", tctr * BUFFER_SIZE, elapsed);
}

static void aes256_gmac_benchmark_test()
{
    uint8_t enc[BUFFER_SIZE + QSC_GCM256_MAC_SIZE] = { 0U };
    uint8_t dec[BUFFER_SIZE] = { 0U };
    uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
    uint8_t msg[BUFFER_SIZE] = { 0U };
    uint8_t iv[QSC_GCM_NONCE_SIZE] = { 0U };
    uint8_t original_iv[QSC_GCM_NONCE_SIZE] = { 0U };
    qsc_aes_gcm256_state ctx;
    qsc_aes_keyparams kp;
    size_t tctr;
    uint64_t start;
    uint64_t elapsed;
    bool passed;

    passed = qsc_csp_generate(key, sizeof(key));
    passed = qsc_csp_generate(iv, sizeof(iv)) && passed;
    passed = qsc_csp_generate(msg, sizeof(msg)) && passed;
    qsc_memutils_copy(original_iv, iv, sizeof(iv));
    kp.key = key;
    kp.keylen = sizeof(key);
    kp.info = NULL;
    kp.infolen = 0U;
    kp.nonce = iv;
    kp.noncelen = sizeof(iv);

    if (passed)
    {
        qsc_aes_gcm256_initialize(&ctx, &kp, true);
        qsc_aes_gcm256_encrypt(&ctx, enc, msg, sizeof(msg));
        qsc_aes_gcm256_dispose(&ctx);
        qsc_aes_gcm256_initialize(&ctx, &kp, false);
        passed = qsc_aes_gcm256_decrypt(&ctx, dec, enc, sizeof(enc));
        passed = qsc_memutils_are_equal(dec, msg, sizeof(msg)) && passed;
        qsc_aes_gcm256_dispose(&ctx);
    }

    if (passed)
    {
        enc[sizeof(enc) - 1U] ^= 0x01U;
        qsc_aes_gcm256_initialize(&ctx, &kp, false);
        passed = qsc_aes_gcm256_decrypt(&ctx, dec, enc, sizeof(enc)) == false;
        qsc_aes_gcm256_dispose(&ctx);
    }

    if (passed == false)
    {
        qsctest_print_line("FAIL: AES-256 GCM AEAD roundtrip/tag-rejection preflight");
        return;
    }

    qsctest_print_line("PASS: AES-256 GCM AEAD roundtrip/tag-rejection preflight");
    qsc_memutils_copy(iv, original_iv, sizeof(iv));
    tctr = 0U;
    start = qsc_timerex_stopwatch_start();

    while (tctr < SAMPLE_COUNT)
    {
        qsc_aes_gcm256_initialize(&ctx, &kp, true);
        qsc_aes_gcm256_encrypt(&ctx, enc, msg, sizeof(msg));
        qsc_aes_gcm256_dispose(&ctx);
        qsc_intutils_be8increment(iv, sizeof(iv));
        ++tctr;
    }

    elapsed = qsc_timerex_stopwatch_elapsed(start);
    qsctest_benchmark_sink ^= enc[0U];
    qsctest_benchmark_report("AES-256 GCM authenticated encryption, unique-IV records", tctr * BUFFER_SIZE, elapsed);
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
	qsc_chacha_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

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
	qsctest_benchmark_report("CHACHA-128", tctr * BUFFER_SIZE, elapsed);
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
	qsc_chacha_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

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
	qsctest_benchmark_report("CHACHA-256", tctr * BUFFER_SIZE, elapsed);
}

static void chacha_poly1305_benchmark_test()
{
    uint8_t aad[12U] = { 0U };
    uint8_t enc[BUFFER_SIZE + QSC_POLY1305_MAC_SIZE] = { 0U };
    uint8_t dec[BUFFER_SIZE] = { 0U };
    uint8_t key[QSC_CHACHA_KEY256_SIZE] = { 0U };
    uint8_t msg[BUFFER_SIZE] = { 0U };
    uint8_t iv[QSC_CHACHA_NONCE_SIZE] = { 0U };
    uint8_t saved_iv[QSC_CHACHA_NONCE_SIZE] = { 0U };
    qsc_chacha_poly1305_state ctx;
    qsc_chacha_keyparams kp;
    size_t tctr;
    uint64_t start;
    uint64_t elapsed;
    bool passed;

    qsctest_hex_to_bin("50515253C0C1C2C3C4C5C6C7", aad, sizeof(aad));
    passed = qsc_csp_generate(key, sizeof(key));
    passed = qsc_csp_generate(iv, sizeof(iv)) && passed;
    passed = qsc_csp_generate(msg, sizeof(msg)) && passed;
    qsc_memutils_copy(saved_iv, iv, sizeof(iv));
    kp.key = key;
    kp.keylen = sizeof(key);
    kp.nonce = iv;

    if (passed)
    {
        qsc_chacha_poly1305_initialize(&ctx, &kp);
        qsc_chacha_poly1305_set_associated(&ctx, aad, sizeof(aad));
        qsc_chacha_poly1305_encrypt(&ctx, enc, msg, sizeof(msg));
        qsc_chacha_poly1305_dispose(&ctx);
        qsc_chacha_poly1305_initialize(&ctx, &kp);
        qsc_chacha_poly1305_set_associated(&ctx, aad, sizeof(aad));
        passed = qsc_chacha_poly1305_decrypt(&ctx, dec, enc, sizeof(enc));
        passed = qsc_memutils_are_equal(dec, msg, sizeof(msg)) && passed;
        qsc_chacha_poly1305_dispose(&ctx);
    }

    if (passed == false)
    {
        qsctest_print_line("FAIL: ChaCha20-Poly1305 AEAD roundtrip preflight");
        return;
    }

    qsctest_print_line("PASS: ChaCha20-Poly1305 AEAD roundtrip preflight");
    qsc_memutils_copy(iv, saved_iv, sizeof(iv));
    tctr = 0U;
    start = qsc_timerex_stopwatch_start();

    while (tctr < SAMPLE_COUNT)
    {
        qsc_chacha_poly1305_initialize(&ctx, &kp);
        qsc_chacha_poly1305_set_associated(&ctx, aad, sizeof(aad));
        qsc_chacha_poly1305_encrypt(&ctx, enc, msg, sizeof(msg));
        qsc_chacha_poly1305_dispose(&ctx);
        qsc_intutils_be8increment(iv, sizeof(iv));
        ++tctr;
    }

    elapsed = qsc_timerex_stopwatch_elapsed(start);
    qsctest_benchmark_sink ^= enc[0U];
    qsctest_benchmark_report("ChaCha20-Poly1305 authenticated encryption, unique-IV records", tctr * BUFFER_SIZE, elapsed);
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
	qsc_csx_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_csx_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT - 1)
	{
		if (qsc_csx_extended_transform(&ctx, enc, msg, sizeof(msg), false) == false)
        {
            qsctest_print_line("FAIL: CSX streaming benchmark transform");
            return;
        }

		++tctr;
	}

	if (qsc_csx_extended_transform(&ctx, enc, msg, sizeof(msg), true) == false)
    {
        qsctest_print_line("FAIL: CSX streaming benchmark finalize");
        return;
    }

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_benchmark_report("CSX-512", SAMPLE_COUNT * BUFFER_SIZE, elapsed);
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
	qsc_rcs_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_rcs_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT - 1)
	{
		if (qsc_rcs_extended_transform(&ctx, enc, msg, sizeof(msg), false) == false)
        {
            qsctest_print_line("FAIL: RCS streaming benchmark transform");
            return;
        }

		++tctr;
	}

	if (qsc_rcs_extended_transform(&ctx, enc, msg, sizeof(msg), true) == false)
    {
        qsctest_print_line("FAIL: RCS streaming benchmark finalize");
        return;
    }

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_benchmark_report("RCS-256", SAMPLE_COUNT * BUFFER_SIZE, elapsed);
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
	qsc_rcs_keyparams kp = { .key = key, .keylen = sizeof(key), .nonce = nonce };

	/* encryption */

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_rcs_initialize(&ctx, &kp, true);

	while (tctr < SAMPLE_COUNT - 1)
	{
		if (qsc_rcs_extended_transform(&ctx, enc, msg, sizeof(msg), false) == false)
        {
            qsctest_print_line("FAIL: RCS streaming benchmark transform");
            return;
        }

		++tctr;
	}

	if (qsc_rcs_extended_transform(&ctx, enc, msg, sizeof(msg), true) == false)
    {
        qsctest_print_line("FAIL: RCS streaming benchmark finalize");
        return;
    }

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_benchmark_report("RCS-512", SAMPLE_COUNT * BUFFER_SIZE, elapsed);
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
	qsctest_benchmark_report("KMAC-128", tctr * BUFFER_SIZE, elapsed);
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
	qsctest_benchmark_report("KMAC-256", tctr * BUFFER_SIZE, elapsed);
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
	qsctest_benchmark_report("KMAC-512", tctr * BUFFER_SIZE, elapsed);
}

static void qmac_benchmark()
{
	uint8_t msg[BUFFER_SIZE] = { 0 };
	uint8_t tag[32] = { 0 };
	uint8_t key[32] = { 0 };
	qsc_qmac_state ctx = { 0U };
	size_t tctr;
	uint64_t start;
	uint64_t elapsed;

	tctr = 0;
	start = qsc_timerex_stopwatch_start();

	qsc_qmac_keyparams kp = { .key = key, .keylen = sizeof(key) };
	qsc_qmac_initialize(&ctx, &kp);

	while (tctr < SAMPLE_COUNT)
	{
		qsc_qmac_update(&ctx, msg, sizeof(msg));
		++tctr;
	}

	qsc_qmac_finalize(&ctx, tag);

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_benchmark_report("QMAC-256", tctr * BUFFER_SIZE, elapsed);
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
	qsctest_benchmark_report("KMAC-128x4", tctr, elapsed);
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
	qsctest_benchmark_report("KMAC-256x4", tctr, elapsed);
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
	qsctest_benchmark_report("KMAC-512x4", tctr, elapsed);
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
	qsctest_benchmark_report("KMAC-128x8", tctr, elapsed);
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
	qsctest_benchmark_report("KMAC-256x8", tctr, elapsed);
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
	qsctest_benchmark_report("KMAC-512x8", tctr, elapsed);
}
#endif

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
	qsctest_benchmark_report("SHAKE-128", tctr, elapsed);
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
	qsctest_benchmark_report("SHAKE-256", tctr, elapsed);
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
	qsctest_benchmark_report("SHAKE-512", tctr, elapsed);
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
	qsctest_benchmark_report("SHAKE-128x4", tctr, elapsed);
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
	qsctest_benchmark_report("SHAKE-256x4", tctr, elapsed);
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
		qsc_shake_512x4(otp[0], otp[1], otp[2], otp[3], QSC_KECCAK_512_RATE, key[0], key[1], key[2], key[3], 64U);
		tctr += (4 * QSC_KECCAK_512_RATE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_benchmark_report("SHAKE-512x4", tctr, elapsed);
}
#endif

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
	qsctest_benchmark_report("SHAKE-128x8", tctr, elapsed);
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
	qsctest_benchmark_report("SHAKE-256x8", tctr, elapsed);
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
			key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7], 64U);

		tctr += (8 * QSC_KECCAK_512_RATE);
	}

	elapsed = qsc_timerex_stopwatch_elapsed(start);
	qsctest_benchmark_report("SHAKE-512x8", tctr, elapsed);
}
#endif

void qsctest_benchmark_aes_run()
{
	qsctest_print_line("Benchmark: AES-256 GCM authenticated encryption");
	aes256_gmac_benchmark_test();

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
	qsctest_print_line("Benchmark: AES-128");
	aes128_cbc_benchmark_test();
	aes128_ctrbe_benchmark_test();
	aes128_ctrle_benchmark_test();

	qsctest_print_line("Benchmark: AES-256");
	aes256_cbc_benchmark_test();
	aes256_ctrbe_benchmark_test();
	aes256_ctrle_benchmark_test();
#endif
}

void qsctest_benchmark_chacha_run()
{
	qsctest_print_line("Benchmark: CHACHA-256 Poly1305 encryption and authentication");
	chacha_poly1305_benchmark_test();

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
	qsctest_print_line("Benchmark: CHACHA-128 encryption only");
	chacha128_benchmark_test();
	qsctest_print_line("Benchmark: CHACHA-256 encryption only");
	chacha256_benchmark_test();
#endif
}

void qsctest_benchmark_csx_run()
{
	qsctest_print_line("Benchmark: CSX-512 encryption and authentication");
	csx_benchmark_test();
}

void qsctest_benchmark_rcs_run()
{
	qsctest_print_line("Benchmark: RCS-256 encryption and authentication");
	rcs256_benchmark_test();

	qsctest_print_line("Benchmark: RCS-512 encryption and authentication");
	rcs512_benchmark_test();
}

void qsctest_benchmark_kmac_run()
{
	qsctest_print_line("Benchmark: KMAC-128");
	kmac128_benchmark();

	qsctest_print_line("Benchmark: KMAC-256");
	kmac256_benchmark();

	qsctest_print_line("Benchmark: KMAC-512");
	kmac512_benchmark();

#if defined(QSC_SYSTEM_HAS_AVX2)
	qsctest_print_line("Benchmark: AVX2 4X KMAC-128");
	kmac128x4_benchmark();

	qsctest_print_line("Benchmark: AVX2 4X KMAC-256");
	kmac256x4_benchmark();

	qsctest_print_line("Benchmark: AVX2 4X KMAC-512");
	kmac512x4_benchmark();
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
	qsctest_print_line("Benchmark: AVX512 8X KMAC-128");
	kmac128x8_benchmark();

	qsctest_print_line("Benchmark: AVX512 8X KMAC-256");
	kmac256x8_benchmark();

	qsctest_print_line("Benchmark: AVX512 8X KMAC-512");
	kmac512x8_benchmark();
#endif
}

void qsctest_benchmark_shake_run()
{
	qsctest_print_line("Benchmark: SHAKE-128");
	shake128_benchmark();

	qsctest_print_line("Benchmark: SHAKE-256");
	shake256_benchmark();

	qsctest_print_line("Benchmark: SHAKE-512");
	shake512_benchmark();

#if defined(QSC_SYSTEM_HAS_AVX2)
	qsctest_print_line("Benchmark: AVX2 4X SHAKE-128");
	shake128x4_benchmark();

	qsctest_print_line("Benchmark: AVX2 4X SHAKE-256");
	shake256x4_benchmark();

	qsctest_print_line("Benchmark: AVX2 4X SHAKE-512");
	shake512x4_benchmark();
#endif

#if defined(QSC_SYSTEM_HAS_AVX512)
	qsctest_print_line("Benchmark: AVX512 8X SHAKE-128");
	shake128x8_benchmark();

	qsctest_print_line("Benchmark: AVX512 8X SHAKE-256");
	shake256x8_benchmark();

	qsctest_print_line("Benchmark: AVX512 8X SHAKE-512");
	shake512x8_benchmark();
#endif
}

void qsctest_benchmark_qmac_run()
{
	qsctest_print_line("Benchmark: QMAC");
	qmac_benchmark();
}
