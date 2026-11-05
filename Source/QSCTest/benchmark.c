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
#include "sha2.h"
#include "sha3.h"
#include "timerex.h"
#include "intutils.h"
#include "memutils.h"
#include <stdio.h>

/*! \def QSCTEST_BENCHMARK_SMOKE
 * \brief Optional short-run test build used only for compile/runtime smoke qualification.
 * \details Undefined in normal benchmark builds; never use smoke results for performance comparisons.
 */

/*! \def QSCTEST_BENCHMARK_MAX_RECORD
 * \brief Largest benchmark input record, exactly one mebibyte.
 */
#define QSCTEST_BENCHMARK_MAX_RECORD 1048576U

/*! \def QSCTEST_BENCHMARK_MIN_TIME_MS
 * \brief Minimum sampled time for one profile, to avoid timer quantization.
 */
#if defined(QSCTEST_BENCHMARK_SMOKE)
#define QSCTEST_BENCHMARK_MIN_TIME_MS 1U
#else
#define QSCTEST_BENCHMARK_MIN_TIME_MS 100U
#endif

/*! \def QSCTEST_BENCHMARK_MAX_REPEATS
 * \brief Limit sample repetitions if the timer or host behaves unexpectedly.
 */
#define QSCTEST_BENCHMARK_MAX_REPEATS 1024U

/*! \enum qsctest_benchmark_profile
 * \brief Three fixed record sizes with total data budgets per pass.
 */
typedef enum
{
	qsctest_benchmark_profile_small = 1U, /*!< 1000 records of 1024 bytes (1024000 bytes, not 1 MiB). */
	qsctest_benchmark_profile_medium = 2U, /*!< 6400 records of 16384 bytes (100 MiB). */
	qsctest_benchmark_profile_large = 3U /*!< 1024 records of 1048576 bytes (1 GiB). */
} qsctest_benchmark_profile;

/*! \struct qsctest_benchmark_buffers
 * \typedef qsctest_benchmark_buffers
 * \brief Per-benchmark heap buffers; data remains caller-owned.
 */
typedef struct
{
	uint8_t* input; /*!< One mebibyte of plaintext or hash input. */
	uint8_t* output; /*!< One mebibyte of output plus a maximum 64-byte tag. */
	uint8_t* recovered; /*!< One mebibyte for preflight decryption. */
} qsctest_benchmark_buffers;

/*! \brief Select a requested input/output record length.
 * \param profile: One of the three fixed workload profiles.
 * \return Size of one record in bytes; zero for an invalid profile.
 * \details Pure function; thread safe.
 */
static size_t qsctest_benchmark_record_size(size_t profile)
{
	size_t result;

	result = 0U;

	if (profile == (size_t)qsctest_benchmark_profile_small)
	{
		result = 1024U;
	}
	else if (profile == (size_t)qsctest_benchmark_profile_medium)
	{
		result = 16384U;
	}
	else if (profile == (size_t)qsctest_benchmark_profile_large)
	{
		result = QSCTEST_BENCHMARK_MAX_RECORD;
	}

	return result;
}

/*! \brief Select the number of calls required for a complete profile pass.
 * \param profile: One of the three workload profiles.
 * \param lanes: Number of independent messages processed by each call (1, 4, or 8).
 * \return Calls per pass; zero for unsupported lanes or profiles.
 * \details Total data per pass is identical for scalar and multi-lane functions.
 */
static size_t qsctest_benchmark_record_count(size_t profile, size_t lanes)
{
	size_t count;

	count = 0U;

	if (lanes == 1U || lanes == 4U || lanes == 8U)
	{
		if (profile == (size_t)qsctest_benchmark_profile_small)
		{
			count = 1000U / lanes;
		}
		else if (profile == (size_t)qsctest_benchmark_profile_medium)
		{
			count = 6400U / lanes;
		}
		else if (profile == (size_t)qsctest_benchmark_profile_large)
		{
			count = 1024U / lanes;
		}
	}

#if defined(QSCTEST_BENCHMARK_SMOKE)
	if (count != 0U)
	{
		count = 1U;
	}
#endif

	return count;
}

/*! \brief Allocate fixed-size input, output, and recovered buffers before timing.
 * \param buffers: Receives owned allocations; must be released with qsctest_benchmark_free.
 * \return True if all allocations succeed; false otherwise.
 * \details No shared state. Buffers are reused across all profile passes.
 */
static bool qsctest_benchmark_allocate(qsctest_benchmark_buffers* buffers)
{
	bool result;

	buffers->input = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD);
	buffers->output = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
	buffers->recovered = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD);
	result = buffers->input != NULL && buffers->output != NULL && buffers->recovered != NULL;

	if (result == true)
	{
		qsc_memutils_clear(buffers->input, QSCTEST_BENCHMARK_MAX_RECORD);
		qsc_memutils_clear(buffers->output, QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		qsc_memutils_clear(buffers->recovered, QSCTEST_BENCHMARK_MAX_RECORD);
	}

	return result;
}

/*! \brief Securely clear and free benchmark scratch buffers.
 * \param buffers: Caller-owned allocation descriptor; may contain NULL pointers.
 * \details No shared state; must not race with concurrent users of these buffers.
 */
static void qsctest_benchmark_free(qsctest_benchmark_buffers* buffers)
{
	if (buffers->input != NULL)
	{
		qsc_memutils_secure_erase(buffers->input, QSCTEST_BENCHMARK_MAX_RECORD);
		qsc_memutils_alloc_free(buffers->input);
		buffers->input = NULL;
	}

	if (buffers->output != NULL)
	{
		qsc_memutils_secure_erase(buffers->output, QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		qsc_memutils_alloc_free(buffers->output);
		buffers->output = NULL;
	}

	if (buffers->recovered != NULL)
	{
		qsc_memutils_secure_erase(buffers->recovered, QSCTEST_BENCHMARK_MAX_RECORD);
		qsc_memutils_alloc_free(buffers->recovered);
		buffers->recovered = NULL;
	}
}

/*! \brief Report a cipher or hash benchmark and its operation model.
 * \param name: Algorithm and operation name, borrowed non-NULL constant string.
 * \param operation: Description of exactly what the timed operation includes.
 */
static void qsctest_benchmark_heading(const char* name, const char* operation)
{
	qsctest_print_line(name);
	qsctest_print_line(operation);
	qsctest_print_line("  Profiles: 1 KiB x 1000 (1,024,000 B); 16 KiB x 6400 (100 MiB); 1 MiB x 1024 (1 GiB).");
}

/*! \brief Print one completed profile, including all repeated bytes actually timed.
 * \param profile: Profile number (1 to 3).
 * \param lanes: Independent messages per call.
 * \param repeats: Complete executions of the profile.
 * \param elapsed: Measured milliseconds from qsc_timerex_stopwatch_elapsed.
 * \details Labels small-record, transfer, and bulk profiles, and explains timer repetitions.
 */
static void qsctest_benchmark_report(size_t profile, size_t lanes, size_t repeats, uint64_t elapsed)
{
	char line[192U] = { 0U };
	const char* detail;
	size_t record;
	size_t count;
	double seconds;
	double mebibytes;

	record = qsctest_benchmark_record_size(profile);
	count = qsctest_benchmark_record_count(profile, lanes);
	seconds = (double)elapsed / 1000.0;
	mebibytes = ((double)record * (double)count * (double)lanes * (double)repeats) / 1048576.0;
	detail = "Small records; per-message overhead dominates.";

	if (profile == (size_t)qsctest_benchmark_profile_medium)
	{
		detail = "16 KiB transfer records; balanced setup and processing.";
	}
	else if (profile == (size_t)qsctest_benchmark_profile_large)
	{
		detail = "1 MiB bulk records; sustained single-message throughput.";
	}

	(void)snprintf(line, sizeof(line), "  Profile %zu: %zu-byte messages, %zu message(s)/pass. %s", profile, record, count * lanes, detail);
	qsctest_print_line(line);
	(void)snprintf(line, sizeof(line), "    Timed: %zu pass(es); %.3f MiB; %.3f s", repeats, mebibytes, seconds);
	qsctest_print_line(line);

	if (elapsed > 0U)
	{
		(void)snprintf(line, sizeof(line), "    Throughput: %.3f MiB/s; %.0f message(s)/s", mebibytes / seconds, ((double)count * (double)lanes * (double)repeats) / seconds);
		qsctest_print_line(line);
	}
	else
	{
		qsctest_print_line("    Throughput unavailable: insufficient timer resolution.");
	}
}

/*! \brief Repeat whole fixed-size profile passes to obtain a measurable interval.
 * \param elapsed: Current elapsed time in milliseconds.
 * \param repeats: Number of completed passes.
 * \return True while additional passes are required and allowed.
 */
static bool qsctest_benchmark_repeat(uint64_t elapsed, size_t repeats)
{
	bool result;

	result = elapsed < QSCTEST_BENCHMARK_MIN_TIME_MS && repeats < QSCTEST_BENCHMARK_MAX_REPEATS;

	return result;
}

/*! \brief Preserve a computed output dependency so the optimizer cannot discard work.
 * \param result: First byte of the last output.
 * \details This shared volatile sink is only used by sequential benchmark execution.
 */
static void qsctest_benchmark_consume(uint8_t result)
{
	static volatile uint8_t sink;

	sink ^= result;
}

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-128-CBC encrypt at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void aes128_cbc_encrypt_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	uint8_t iv[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("AES-128-CBC encrypt", "Independent PKCS7-padded records; context setup/disposal included; payload bytes measured.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.info = NULL;
	kp.infolen = 0U;
	kp.nonce = iv;
	kp.noncelen = sizeof(iv);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);
				qsc_aes_cbc_encrypt(&ctx, buffers.output, buffers.input, size);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-128-CBC encrypt setup, decrypt, or integrity check");
	}
	else
	{
		qsctest_print_line("[PASS] aes128_cbc_encrypt: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-128-CBC decrypt at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void aes128_cbc_decrypt_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	uint8_t iv[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t olen;
	bool passed;

	qsctest_benchmark_heading("AES-128-CBC decrypt", "Independent PKCS7-padded records; context setup/disposal included; payload bytes measured.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.info = NULL;
	kp.infolen = 0U;
	kp.nonce = iv;
	kp.noncelen = sizeof(iv);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);
		qsc_aes_cbc_encrypt(&ctx, buffers.output, buffers.input, size);
		qsc_aes_dispose(&ctx);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_128);
		olen = 0U;
		qsc_aes_cbc_decrypt(&ctx, buffers.recovered, &olen, buffers.output, size + QSC_AES_BLOCK_SIZE);
		qsc_aes_dispose(&ctx);
		passed = olen == size && qsc_memutils_are_equal(buffers.recovered, buffers.input, size);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
				qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_128);
				olen = 0U;
				qsc_aes_cbc_decrypt(&ctx, buffers.recovered, &olen, buffers.output, size + QSC_AES_BLOCK_SIZE);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.recovered[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			passed = olen == size && qsc_memutils_are_equal(buffers.recovered, buffers.input, size);
			if (passed == true)
			{
				qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
			}
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-128-CBC decrypt setup, decrypt, or integrity check");
	}
	else
	{
		qsctest_print_line("[PASS] aes128_cbc_decrypt: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-256-CBC encrypt at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void aes256_cbc_encrypt_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	uint8_t iv[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("AES-256-CBC encrypt", "Independent PKCS7-padded records; context setup/disposal included; payload bytes measured.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.info = NULL;
	kp.infolen = 0U;
	kp.nonce = iv;
	kp.noncelen = sizeof(iv);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
				qsc_aes_cbc_encrypt(&ctx, buffers.output, buffers.input, size);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-256-CBC encrypt setup, decrypt, or integrity check");
	}
	else
	{
		qsctest_print_line("[PASS] aes256_cbc_encrypt: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-256-CBC decrypt at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void aes256_cbc_decrypt_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	uint8_t iv[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t olen;
	bool passed;

	qsctest_benchmark_heading("AES-256-CBC decrypt", "Independent PKCS7-padded records; context setup/disposal included; payload bytes measured.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.info = NULL;
	kp.infolen = 0U;
	kp.nonce = iv;
	kp.noncelen = sizeof(iv);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
		qsc_aes_cbc_encrypt(&ctx, buffers.output, buffers.input, size);
		qsc_aes_dispose(&ctx);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_256);
		olen = 0U;
		qsc_aes_cbc_decrypt(&ctx, buffers.recovered, &olen, buffers.output, size + QSC_AES_BLOCK_SIZE);
		qsc_aes_dispose(&ctx);
		passed = olen == size && qsc_memutils_are_equal(buffers.recovered, buffers.input, size);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
				qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_256);
				olen = 0U;
				qsc_aes_cbc_decrypt(&ctx, buffers.recovered, &olen, buffers.output, size + QSC_AES_BLOCK_SIZE);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.recovered[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			passed = olen == size && qsc_memutils_are_equal(buffers.recovered, buffers.input, size);
			if (passed == true)
			{
				qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
			}
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-256-CBC decrypt setup, decrypt, or integrity check");
	}
	else
	{
		qsctest_print_line("[PASS] aes256_cbc_decrypt: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-128-ECB encryption over the three fixed payload profiles.
 * \details ECB is included for primitive performance comparisons only; not secure for general messages.
 * \return No value. Prints independently qualified benchmark and error diagnostics.
 */
static void aes128_ecb_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("AES-128-ECB encrypt", "ECB bulk-block encryption with independent key expansion per message; benchmarking only, no confidentiality security.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = nonce;
	kp.noncelen = sizeof(nonce);
	kp.info = NULL;
	kp.infolen = 0U;

	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);
		qsc_aes_ecb_encrypt_blocks(&ctx, buffers.output, buffers.input, size);
		qsc_aes_dispose(&ctx);
		qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_128);
		qsc_aes_ecb_decrypt_blocks(&ctx, buffers.recovered, buffers.output, size);
		qsc_aes_dispose(&ctx);
		passed = qsc_memutils_are_equal(buffers.recovered, buffers.input, size);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();

		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);
				qsc_aes_ecb_encrypt_blocks(&ctx, buffers.output, buffers.input, size);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
			}

			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));

	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-128-ECB bulk encrypt/decrypt preflight or setup");
	}
	else
	{
		qsctest_print_line("[PASS] aes128_ecb: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-256-ECB encryption over the three fixed payload profiles.
 * \details ECB is included for primitive performance comparisons only; not secure for general messages.
 * \return No value. Prints independently qualified benchmark and error diagnostics.
 */
static void aes256_ecb_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("AES-256-ECB encrypt", "ECB bulk-block encryption with independent key expansion per message; benchmarking only, no confidentiality security.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = nonce;
	kp.noncelen = sizeof(nonce);
	kp.info = NULL;
	kp.infolen = 0U;

	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
		qsc_aes_ecb_encrypt_blocks(&ctx, buffers.output, buffers.input, size);
		qsc_aes_dispose(&ctx);
		qsc_aes_initialize(&ctx, &kp, false, qsc_aes_cipher_256);
		qsc_aes_ecb_decrypt_blocks(&ctx, buffers.recovered, buffers.output, size);
		qsc_aes_dispose(&ctx);
		passed = qsc_memutils_are_equal(buffers.recovered, buffers.input, size);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();

		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
				qsc_aes_ecb_encrypt_blocks(&ctx, buffers.output, buffers.input, size);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
			}

			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));

	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-256-ECB bulk encrypt/decrypt preflight or setup");
	}
	else
	{
		qsctest_print_line("[PASS] aes256_ecb: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-128-CTR-BE encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void aes128_ctrbe_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	uint8_t iv[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("AES-128-CTR-BE", "Independent cipher records, unique counters; context setup included; no authentication.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.info = NULL;
	kp.infolen = 0U;
	kp.nonce = iv;
	kp.noncelen = sizeof(iv);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);
				qsc_aes_ctrbe_transform(&ctx, buffers.output, buffers.input, size);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-128-CTR-BE setup");
	}
	else
	{
		qsctest_print_line("[PASS] aes128_ctrbe: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-128-CTR-LE encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void aes128_ctrle_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES128_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	uint8_t iv[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("AES-128-CTR-LE", "Independent cipher records, unique counters; context setup included; no authentication.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.info = NULL;
	kp.infolen = 0U;
	kp.nonce = iv;
	kp.noncelen = sizeof(iv);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_128);
				qsc_aes_ctrle_transform(&ctx, buffers.output, buffers.input, size);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-128-CTR-LE setup");
	}
	else
	{
		qsctest_print_line("[PASS] aes128_ctrle: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-256-CTR-BE encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void aes256_ctrbe_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	uint8_t iv[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("AES-256-CTR-BE", "Independent cipher records, unique counters; context setup included; no authentication.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.info = NULL;
	kp.infolen = 0U;
	kp.nonce = iv;
	kp.noncelen = sizeof(iv);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
				qsc_aes_ctrbe_transform(&ctx, buffers.output, buffers.input, size);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-256-CTR-BE setup");
	}
	else
	{
		qsctest_print_line("[PASS] aes256_ctrbe: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark AES-256-CTR-LE encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void aes256_ctrle_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_AES_IV_SIZE] = { 0U };
	uint8_t iv[QSC_AES_IV_SIZE] = { 0U };
	qsc_aes_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("AES-256-CTR-LE", "Independent cipher records, unique counters; context setup included; no authentication.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.info = NULL;
	kp.infolen = 0U;
	kp.nonce = iv;
	kp.noncelen = sizeof(iv);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_aes_initialize(&ctx, &kp, true, qsc_aes_cipher_256);
				qsc_aes_ctrle_transform(&ctx, buffers.output, buffers.input, size);
				qsc_aes_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-256-CTR-LE setup");
	}
	else
	{
		qsctest_print_line("[PASS] aes256_ctrle: three benchmark profiles completed");
	}
}
#endif

/*! \brief Benchmark AES-256-GCM authenticated encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void aes256_gmac_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t aad[12U] = { 0U };
	uint8_t key[QSC_AES256_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_GCM_NONCE_SIZE] = { 0U };
	uint8_t iv[QSC_GCM_NONCE_SIZE] = { 0U };
	qsc_aes_gcm256_state ctx;
	qsc_aes_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("AES-256-GCM", "Independent AEAD records; unique IV; key setup and 16-byte tag generation and 12-byte AAD included.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.info = NULL;
	kp.infolen = 0U;
	kp.nonce = iv;
	kp.noncelen = sizeof(iv);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_aes_gcm256_initialize(&ctx, &kp, true);
		qsc_aes_gcm256_set_associated(&ctx, aad, sizeof(aad));
		qsc_aes_gcm256_encrypt(&ctx, buffers.output, buffers.input, size);
		qsc_aes_gcm256_dispose(&ctx);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_aes_gcm256_initialize(&ctx, &kp, false);
		qsc_aes_gcm256_set_associated(&ctx, aad, sizeof(aad));
		passed = qsc_aes_gcm256_decrypt(&ctx, buffers.recovered, buffers.output, size + QSC_GCM256_MAC_SIZE);
		passed = qsc_memutils_are_equal(buffers.recovered, buffers.input, size) && passed;
		qsc_aes_gcm256_dispose(&ctx);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_aes_gcm256_initialize(&ctx, &kp, true);
				qsc_aes_gcm256_set_associated(&ctx, aad, sizeof(aad));
				qsc_aes_gcm256_encrypt(&ctx, buffers.output, buffers.input, size);
				qsc_aes_gcm256_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] AES-256-GCM preflight encryption/decryption or random generation");
	}
	else
	{
		qsctest_print_line("[PASS] aes256_gmac: three benchmark profiles completed");
	}
}

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark ChaCha-128 encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void chacha128_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_CHACHA_KEY128_SIZE] = { 0U };
	uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0U };
	uint8_t iv[QSC_CHACHA_NONCE_SIZE] = { 0U };
	qsc_chacha_state ctx;
	qsc_chacha_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("ChaCha-128", "Independent stream cipher records with unique nonces; setup included; no authentication.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = iv;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_chacha_initialize(&ctx, &kp);
				qsc_chacha_transform(&ctx, buffers.output, buffers.input, size);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] ChaCha-128 setup");
	}
	else
	{
		qsctest_print_line("[PASS] chacha128: three benchmark profiles completed");
	}
}
#endif

#if defined(QSCTEXT_RUNALL_BENCHMARKS)
/*! \brief Benchmark ChaCha-256 encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void chacha256_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[QSC_CHACHA_KEY256_SIZE] = { 0U };
	uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0U };
	uint8_t iv[QSC_CHACHA_NONCE_SIZE] = { 0U };
	qsc_chacha_state ctx;
	qsc_chacha_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("ChaCha-256", "Independent stream cipher records with unique nonces; setup included; no authentication.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = iv;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_chacha_initialize(&ctx, &kp);
				qsc_chacha_transform(&ctx, buffers.output, buffers.input, size);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] ChaCha-256 setup");
	}
	else
	{
		qsctest_print_line("[PASS] chacha256: three benchmark profiles completed");
	}
}
#endif

/*! \brief Benchmark ChaCha20-Poly1305 authenticated encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void chacha_poly1305_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t aad[12U] = { 0U };
	uint8_t key[QSC_CHACHA_KEY256_SIZE] = { 0U };
	uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0U };
	uint8_t iv[QSC_CHACHA_NONCE_SIZE] = { 0U };
	qsc_chacha_poly1305_state ctx;
	qsc_chacha_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("ChaCha20-Poly1305", "Independent AEAD records; unique nonce; context setup, 12-byte AAD, and 16-byte tag included.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = iv;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_chacha_poly1305_initialize(&ctx, &kp);
		qsc_chacha_poly1305_set_associated(&ctx, aad, sizeof(aad));
		qsc_chacha_poly1305_encrypt(&ctx, buffers.output, buffers.input, size);
		qsc_chacha_poly1305_dispose(&ctx);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_chacha_poly1305_initialize(&ctx, &kp);
		qsc_chacha_poly1305_set_associated(&ctx, aad, sizeof(aad));
		passed = qsc_chacha_poly1305_decrypt(&ctx, buffers.recovered, buffers.output, size + QSC_POLY1305_MAC_SIZE);
		passed = qsc_memutils_are_equal(buffers.recovered, buffers.input, size) && passed;
		qsc_chacha_poly1305_dispose(&ctx);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_chacha_poly1305_initialize(&ctx, &kp);
				qsc_chacha_poly1305_set_associated(&ctx, aad, sizeof(aad));
				qsc_chacha_poly1305_encrypt(&ctx, buffers.output, buffers.input, size);
				qsc_chacha_poly1305_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] ChaCha20-Poly1305 preflight or RNG");
	}
	else
	{
		qsctest_print_line("[PASS] chacha_poly1305: three benchmark profiles completed");
	}
}

/*! \brief Benchmark CSX-512 authenticated encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void csx_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t aad[12U] = { 0U };
	uint8_t key[QSC_CSX_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_CSX_NONCE_SIZE] = { 0U };
	uint8_t iv[QSC_CSX_NONCE_SIZE] = { 0U };
	qsc_csx_state ctx;
	qsc_csx_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("CSX-512", "Independent authenticated records; unique counter domain per message; setup, 12-byte AAD, and tag included.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = iv;
	kp.info = NULL;
	kp.infolen = 0U;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_csx_initialize(&ctx, &kp, true);
		qsc_csx_set_associated(&ctx, aad, sizeof(aad));
		passed = qsc_csx_transform(&ctx, buffers.output, buffers.input, size);
		qsc_csx_dispose(&ctx);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_csx_initialize(&ctx, &kp, false);
		qsc_csx_set_associated(&ctx, aad, sizeof(aad));
		passed = qsc_csx_transform(&ctx, buffers.recovered, buffers.output, size) && passed;
		passed = qsc_memutils_are_equal(buffers.recovered, buffers.input, size) && passed;
		qsc_csx_dispose(&ctx);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_csx_initialize(&ctx, &kp, true);
				qsc_csx_set_associated(&ctx, aad, sizeof(aad));
				passed = qsc_csx_transform(&ctx, buffers.output, buffers.input, size);
				qsc_csx_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] CSX-512 independent authenticated record or preflight");
	}
	else
	{
		qsctest_print_line("[PASS] csx: three benchmark profiles completed");
	}
}

/*! \brief Benchmark RCS-256 authenticated encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void rcs256_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t aad[12U] = { 0U };
	uint8_t key[QSC_RCS256_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0U };
	uint8_t iv[QSC_RCS_NONCE_SIZE] = { 0U };
	qsc_rcs_state ctx;
	qsc_rcs_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("RCS-256", "Independent authenticated records; unique counter domain per message; setup, 12-byte AAD, and tag included.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = iv;
	kp.info = NULL;
	kp.infolen = 0U;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_rcs_initialize(&ctx, &kp, true);
		qsc_rcs_set_associated(&ctx, aad, sizeof(aad));
		passed = qsc_rcs_transform(&ctx, buffers.output, buffers.input, size);
		qsc_rcs_dispose(&ctx);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_rcs_initialize(&ctx, &kp, false);
		qsc_rcs_set_associated(&ctx, aad, sizeof(aad));
		passed = qsc_rcs_transform(&ctx, buffers.recovered, buffers.output, size) && passed;
		passed = qsc_memutils_are_equal(buffers.recovered, buffers.input, size) && passed;
		qsc_rcs_dispose(&ctx);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_rcs_initialize(&ctx, &kp, true);
				qsc_rcs_set_associated(&ctx, aad, sizeof(aad));
				passed = qsc_rcs_transform(&ctx, buffers.output, buffers.input, size);
				qsc_rcs_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] RCS-256 independent authenticated record or preflight");
	}
	else
	{
		qsctest_print_line("[PASS] rcs256: three benchmark profiles completed");
	}
}

/*! \brief Benchmark RCS-512 authenticated encryption at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void rcs512_benchmark_test(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t aad[12U] = { 0U };
	uint8_t key[QSC_RCS512_KEY_SIZE] = { 0U };
	uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0U };
	uint8_t iv[QSC_RCS_NONCE_SIZE] = { 0U };
	qsc_rcs_state ctx;
	qsc_rcs_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("RCS-512", "Independent authenticated records; unique counter domain per message; setup, 12-byte AAD, and tag included.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	passed = qsc_csp_generate(nonce, sizeof(nonce)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);
	kp.nonce = iv;
	kp.info = NULL;
	kp.infolen = 0U;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_rcs_initialize(&ctx, &kp, true);
		qsc_rcs_set_associated(&ctx, aad, sizeof(aad));
		passed = qsc_rcs_transform(&ctx, buffers.output, buffers.input, size);
		qsc_rcs_dispose(&ctx);
		qsc_memutils_copy(iv, nonce, sizeof(iv));
		qsc_intutils_be64to8(iv, UINT64_MAX - (uint64_t)profile);
		qsc_rcs_initialize(&ctx, &kp, false);
		qsc_rcs_set_associated(&ctx, aad, sizeof(aad));
		passed = qsc_rcs_transform(&ctx, buffers.recovered, buffers.output, size) && passed;
		passed = qsc_memutils_are_equal(buffers.recovered, buffers.input, size) && passed;
		qsc_rcs_dispose(&ctx);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_memutils_copy(iv, nonce, sizeof(iv));
				qsc_intutils_be64to8(iv, sequence);
				qsc_rcs_initialize(&ctx, &kp, true);
				qsc_rcs_set_associated(&ctx, aad, sizeof(aad));
				passed = qsc_rcs_transform(&ctx, buffers.output, buffers.input, size);
				qsc_rcs_dispose(&ctx);
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] RCS-512 independent authenticated record or preflight");
	}
	else
	{
		qsctest_print_line("[PASS] rcs512: three benchmark profiles completed");
	}
}

/*! \brief Benchmark KMAC-128 independent messages at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void kmac128_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[16U] = { 0U };
	uint8_t mac[16U] = { 0U };
	qsc_keccak_state ctx;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("KMAC-128", "Independent keyed-message authentication; initialize, absorb, and finalize each message.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_kmac_initialize(&ctx, QSC_KECCAK_128_RATE, key, sizeof(key), NULL, 0U);
				qsc_kmac_update(&ctx, QSC_KECCAK_128_RATE, buffers.input, size);
				qsc_kmac_finalize(&ctx, QSC_KECCAK_128_RATE, mac, sizeof(mac));
				qsctest_benchmark_consume(mac[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] KMAC-128 allocation/RNG");
	}
	else
	{
		qsctest_print_line("[PASS] kmac128: three benchmark profiles completed");
	}
}

/*! \brief Benchmark KMAC-256 independent messages at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void kmac256_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[32U] = { 0U };
	uint8_t mac[32U] = { 0U };
	qsc_keccak_state ctx;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("KMAC-256", "Independent keyed-message authentication; initialize, absorb, and finalize each message.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_kmac_initialize(&ctx, QSC_KECCAK_256_RATE, key, sizeof(key), NULL, 0U);
				qsc_kmac_update(&ctx, QSC_KECCAK_256_RATE, buffers.input, size);
				qsc_kmac_finalize(&ctx, QSC_KECCAK_256_RATE, mac, sizeof(mac));
				qsctest_benchmark_consume(mac[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] KMAC-256 allocation/RNG");
	}
	else
	{
		qsctest_print_line("[PASS] kmac256: three benchmark profiles completed");
	}
}

/*! \brief Benchmark KMAC-512 independent messages at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void kmac512_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[64U] = { 0U };
	uint8_t mac[64U] = { 0U };
	qsc_keccak_state ctx;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("KMAC-512", "Independent keyed-message authentication; initialize, absorb, and finalize each message.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_kmac_initialize(&ctx, QSC_KECCAK_512_RATE, key, sizeof(key), NULL, 0U);
				qsc_kmac_update(&ctx, QSC_KECCAK_512_RATE, buffers.input, size);
				qsc_kmac_finalize(&ctx, QSC_KECCAK_512_RATE, mac, sizeof(mac));
				qsctest_benchmark_consume(mac[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] KMAC-512 allocation/RNG");
	}
	else
	{
		qsctest_print_line("[PASS] kmac512: three benchmark profiles completed");
	}
}

/*! \brief Benchmark QMAC-256 independent messages at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void qmac_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[32U] = { 0U };
	uint8_t mac[32U] = { 0U };
	qsc_qmac_state ctx;
	qsc_qmac_keyparams kp;
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("QMAC-256", "Independent keyed messages; initialize, absorb, and finalize each message.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(key, sizeof(key)) && passed;
	kp.key = key;
	kp.keylen = sizeof(key);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_qmac_initialize(&ctx, &kp);
				qsc_qmac_update(&ctx, buffers.input, size);
				qsc_qmac_finalize(&ctx, mac);
				qsc_qmac_dispose(&ctx);
				qsctest_benchmark_consume(mac[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] QMAC-256 allocation/RNG");
	}
	else
	{
		qsctest_print_line("[PASS] qmac: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHA-256 independent message hashing at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void sha256_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t digest[32U] = { 0U };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("SHA-256", "Independent message digest; hash setup, absorption, and finalization included.");
	passed = qsctest_benchmark_allocate(&buffers);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_sha256_compute(digest, buffers.input, size);
				qsctest_benchmark_consume(digest[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHA-256 scratch allocation");
	}
	else
	{
		qsctest_print_line("[PASS] sha256: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHA-384 independent message hashing at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void sha384_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t digest[48U] = { 0U };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("SHA-384", "Independent message digest; hash setup, absorption, and finalization included.");
	passed = qsctest_benchmark_allocate(&buffers);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_sha384_compute(digest, buffers.input, size);
				qsctest_benchmark_consume(digest[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHA-384 scratch allocation");
	}
	else
	{
		qsctest_print_line("[PASS] sha384: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHA-512 independent message hashing at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void sha512_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t digest[64U] = { 0U };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("SHA-512", "Independent message digest; hash setup, absorption, and finalization included.");
	passed = qsctest_benchmark_allocate(&buffers);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_sha512_compute(digest, buffers.input, size);
				qsctest_benchmark_consume(digest[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHA-512 scratch allocation");
	}
	else
	{
		qsctest_print_line("[PASS] sha512: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHA3-256 independent message hashing at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void sha3_256_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t digest[32U] = { 0U };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("SHA3-256", "Independent message digest; hash setup, absorption, and finalization included.");
	passed = qsctest_benchmark_allocate(&buffers);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_sha3_compute256(digest, buffers.input, size);
				qsctest_benchmark_consume(digest[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHA3-256 scratch allocation");
	}
	else
	{
		qsctest_print_line("[PASS] sha3_256: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHA3-512 independent message hashing at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void sha3_512_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t digest[64U] = { 0U };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("SHA3-512", "Independent message digest; hash setup, absorption, and finalization included.");
	passed = qsctest_benchmark_allocate(&buffers);

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_sha3_compute512(digest, buffers.input, size);
				qsctest_benchmark_consume(digest[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHA3-512 scratch allocation");
	}
	else
	{
		qsctest_print_line("[PASS] sha3_512: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHAKE-128 output generation at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void shake128_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t seed[16U] = { 0U };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("SHAKE-128 XOF output", "Independent XOF requests from a fixed seed; throughput counts OUTPUT bytes, not absorbed input.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(seed, sizeof(seed)) && passed;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_shake128_compute(buffers.output, size, seed, sizeof(seed));
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(seed, sizeof(seed));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHAKE-128 allocation/RNG");
	}
	else
	{
		qsctest_print_line("[PASS] shake128: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHAKE-256 output generation at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void shake256_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t seed[32U] = { 0U };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("SHAKE-256 XOF output", "Independent XOF requests from a fixed seed; throughput counts OUTPUT bytes, not absorbed input.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(seed, sizeof(seed)) && passed;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_shake256_compute(buffers.output, size, seed, sizeof(seed));
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(seed, sizeof(seed));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHAKE-256 allocation/RNG");
	}
	else
	{
		qsctest_print_line("[PASS] shake256: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHAKE-512 output generation at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void shake512_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t seed[64U] = { 0U };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	bool passed;

	qsctest_benchmark_heading("SHAKE-512 XOF output", "Independent XOF requests from a fixed seed; throughput counts OUTPUT bytes, not absorbed input.");
	passed = qsctest_benchmark_allocate(&buffers);
	passed = qsc_csp_generate(seed, sizeof(seed)) && passed;

	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 1U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_shake512_compute(buffers.output, size, seed, sizeof(seed));
				qsctest_benchmark_consume(buffers.output[0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 1U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	qsc_memutils_secure_erase(seed, sizeof(seed));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHAKE-512 allocation/RNG");
	}
	else
	{
		qsctest_print_line("[PASS] shake512: three benchmark profiles completed");
	}
}

#if defined(QSC_SYSTEM_HAS_AVX2)

/*! \brief Benchmark KMAC-128x4 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void kmac128x4_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[4U][16U] = { { 0U } };
	uint8_t* out[4U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("KMAC-128x4", "True 4-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 4U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_kmac_128x4(out[0U], out[1U], out[2U], out[3U], 16U, key[0U], key[1U], key[2U], key[3U], 16U, NULL, NULL, NULL, NULL, 0U, buffers.input, buffers.input, buffers.input, buffers.input, size);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 4U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] KMAC-128x4 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] kmac128x4: three benchmark profiles completed");
	}
}

/*! \brief Benchmark KMAC-256x4 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void kmac256x4_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[4U][32U] = { { 0U } };
	uint8_t* out[4U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("KMAC-256x4", "True 4-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 4U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_kmac_256x4(out[0U], out[1U], out[2U], out[3U], 32U, key[0U], key[1U], key[2U], key[3U], 32U, NULL, NULL, NULL, NULL, 0U, buffers.input, buffers.input, buffers.input, buffers.input, size);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 4U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] KMAC-256x4 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] kmac256x4: three benchmark profiles completed");
	}
}

/*! \brief Benchmark KMAC-512x4 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void kmac512x4_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[4U][64U] = { { 0U } };
	uint8_t* out[4U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("KMAC-512x4", "True 4-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 4U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_kmac_512x4(out[0U], out[1U], out[2U], out[3U], 64U, key[0U], key[1U], key[2U], key[3U], 64U, NULL, NULL, NULL, NULL, 0U, buffers.input, buffers.input, buffers.input, buffers.input, size);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 4U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] KMAC-512x4 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] kmac512x4: three benchmark profiles completed");
	}
}

#endif

#if defined(QSC_SYSTEM_HAS_AVX512)

/*! \brief Benchmark KMAC-128x8 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void kmac128x8_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[8U][16U] = { { 0U } };
	uint8_t* out[8U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("KMAC-128x8", "True 8-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	key[4U][0U] = (uint8_t)5U;
	key[5U][0U] = (uint8_t)6U;
	key[6U][0U] = (uint8_t)7U;
	key[7U][0U] = (uint8_t)8U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 8U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_kmac_128x8(out[0U], out[1U], out[2U], out[3U], out[4U], out[5U], out[6U], out[7U], 16U, key[0U], key[1U], key[2U], key[3U], key[4U], key[5U], key[6U], key[7U], 16U, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0U, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, size);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 8U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] KMAC-128x8 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] kmac128x8: three benchmark profiles completed");
	}
}

/*! \brief Benchmark KMAC-256x8 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void kmac256x8_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[8U][32U] = { { 0U } };
	uint8_t* out[8U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("KMAC-256x8", "True 8-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	key[4U][0U] = (uint8_t)5U;
	key[5U][0U] = (uint8_t)6U;
	key[6U][0U] = (uint8_t)7U;
	key[7U][0U] = (uint8_t)8U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 8U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_kmac_256x8(out[0U], out[1U], out[2U], out[3U], out[4U], out[5U], out[6U], out[7U], 32U, key[0U], key[1U], key[2U], key[3U], key[4U], key[5U], key[6U], key[7U], 32U, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0U, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, size);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 8U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] KMAC-256x8 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] kmac256x8: three benchmark profiles completed");
	}
}

/*! \brief Benchmark KMAC-512x8 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void kmac512x8_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[8U][64U] = { { 0U } };
	uint8_t* out[8U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("KMAC-512x8", "True 8-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	key[4U][0U] = (uint8_t)5U;
	key[5U][0U] = (uint8_t)6U;
	key[6U][0U] = (uint8_t)7U;
	key[7U][0U] = (uint8_t)8U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 8U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_kmac_512x8(out[0U], out[1U], out[2U], out[3U], out[4U], out[5U], out[6U], out[7U], 64U, key[0U], key[1U], key[2U], key[3U], key[4U], key[5U], key[6U], key[7U], 64U, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0U, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, buffers.input, size);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 8U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] KMAC-512x8 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] kmac512x8: three benchmark profiles completed");
	}
}

#endif

#if defined(QSC_SYSTEM_HAS_AVX2)

/*! \brief Benchmark SHAKE-128x4 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void shake128x4_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[4U][16U] = { { 0U } };
	uint8_t* out[4U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("SHAKE-128x4", "True 4-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 4U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_shake_128x4(out[0U], out[1U], out[2U], out[3U], size, key[0U], key[1U], key[2U], key[3U], 16U);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 4U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHAKE-128x4 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] shake128x4: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHAKE-256x4 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void shake256x4_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[4U][32U] = { { 0U } };
	uint8_t* out[4U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("SHAKE-256x4", "True 4-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 4U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_shake_256x4(out[0U], out[1U], out[2U], out[3U], size, key[0U], key[1U], key[2U], key[3U], 32U);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 4U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHAKE-256x4 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] shake256x4: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHAKE-512x4 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void shake512x4_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[4U][64U] = { { 0U } };
	uint8_t* out[4U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("SHAKE-512x4", "True 4-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 4U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_shake_512x4(out[0U], out[1U], out[2U], out[3U], size, key[0U], key[1U], key[2U], key[3U], 64U);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 4U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 4U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHAKE-512x4 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] shake512x4: three benchmark profiles completed");
	}
}

#endif

#if defined(QSC_SYSTEM_HAS_AVX512)

/*! \brief Benchmark SHAKE-128x8 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void shake128x8_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[8U][16U] = { { 0U } };
	uint8_t* out[8U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("SHAKE-128x8", "True 8-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	key[4U][0U] = (uint8_t)5U;
	key[5U][0U] = (uint8_t)6U;
	key[6U][0U] = (uint8_t)7U;
	key[7U][0U] = (uint8_t)8U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 8U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_shake_128x8(out[0U], out[1U], out[2U], out[3U], out[4U], out[5U], out[6U], out[7U], size, key[0U], key[1U], key[2U], key[3U], key[4U], key[5U], key[6U], key[7U], 16U);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 8U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHAKE-128x8 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] shake128x8: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHAKE-256x8 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void shake256x8_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[8U][32U] = { { 0U } };
	uint8_t* out[8U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("SHAKE-256x8", "True 8-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	key[4U][0U] = (uint8_t)5U;
	key[5U][0U] = (uint8_t)6U;
	key[6U][0U] = (uint8_t)7U;
	key[7U][0U] = (uint8_t)8U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 8U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_shake_256x8(out[0U], out[1U], out[2U], out[3U], out[4U], out[5U], out[6U], out[7U], size, key[0U], key[1U], key[2U], key[3U], key[4U], key[5U], key[6U], key[7U], 32U);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 8U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHAKE-256x8 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] shake256x8: three benchmark profiles completed");
	}
}

/*! \brief Benchmark SHAKE-512x8 parallel throughput at all three required record sizes.
 * \details Runs independently and sequentially; data is allocated outside the timer.
 * \return No value. Emits a distinct failure diagnostic on setup or operation failure.
 */
static void shake512x8_benchmark(void)
{
	qsctest_benchmark_buffers buffers = { NULL, NULL, NULL };
	uint8_t key[8U][64U] = { { 0U } };
	uint8_t* out[8U] = { NULL };
	size_t profile;
	size_t size;
	size_t count;
	size_t iteration;
	size_t repetitions;
	uint64_t sequence;
	uint64_t start;
	uint64_t elapsed;
	size_t lane;
	bool passed;

	qsctest_benchmark_heading("SHAKE-512x8", "True 8-lane SIMD batch; independent equal-sized messages; aggregate bytes across lanes.");
	passed = qsctest_benchmark_allocate(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		out[lane] = (uint8_t*)qsc_memutils_malloc(QSCTEST_BENCHMARK_MAX_RECORD + 64U);
		passed = out[lane] != NULL && passed;
	}

	key[0U][0U] = (uint8_t)1U;
	key[1U][0U] = (uint8_t)2U;
	key[2U][0U] = (uint8_t)3U;
	key[3U][0U] = (uint8_t)4U;
	key[4U][0U] = (uint8_t)5U;
	key[5U][0U] = (uint8_t)6U;
	key[6U][0U] = (uint8_t)7U;
	key[7U][0U] = (uint8_t)8U;
	sequence = 0U;
	for (profile = (size_t)qsctest_benchmark_profile_small; profile <= (size_t)qsctest_benchmark_profile_large && passed == true; ++profile)
	{
		size = qsctest_benchmark_record_size(profile);
		count = qsctest_benchmark_record_count(profile, 8U);
		repetitions = 0U;
		start = qsc_timerex_stopwatch_start();
		do
		{
			for (iteration = 0U; iteration < count && passed == true; ++iteration)
			{
				qsc_shake_512x8(out[0U], out[1U], out[2U], out[3U], out[4U], out[5U], out[6U], out[7U], size, key[0U], key[1U], key[2U], key[3U], key[4U], key[5U], key[6U], key[7U], 64U);
				qsctest_benchmark_consume(out[0U][0U]);
				++sequence;
			}
			++repetitions;
			elapsed = qsc_timerex_stopwatch_elapsed(start);
		} while (passed == true && qsctest_benchmark_repeat(elapsed, repetitions) == true);

		if (passed == true)
		{
			qsctest_benchmark_report(profile, 8U, repetitions, elapsed);
		}
	}

	qsctest_benchmark_free(&buffers);
	for (lane = 0U; lane < 8U; ++lane)
	{
		if (out[lane] != NULL)
		{
			qsc_memutils_secure_erase(out[lane], QSCTEST_BENCHMARK_MAX_RECORD + 64U);
			qsc_memutils_alloc_free(out[lane]);
		}
	}
	qsc_memutils_secure_erase(key, sizeof(key));
	if (passed == false)
	{
		qsctest_print_line("[FAIL] SHAKE-512x8 buffer allocation");
	}
	else
	{
		qsctest_print_line("[PASS] shake512x8: three benchmark profiles completed");
	}
}

#endif

/*! \brief Execute AES cipher benchmark functions in sequence.
 * \details Default runs GCM; expanded mode runs CBC and CTR for both supported key lengths.
 */
void qsctest_benchmark_aes_run(void)
{
	aes256_gmac_benchmark_test();
#if defined(QSCTEXT_RUNALL_BENCHMARKS)
	aes128_ecb_benchmark_test();
	aes256_ecb_benchmark_test();
	aes128_cbc_encrypt_benchmark_test();
	aes128_cbc_decrypt_benchmark_test();
	aes256_cbc_encrypt_benchmark_test();
	aes256_cbc_decrypt_benchmark_test();
	aes128_ctrbe_benchmark_test();
	aes128_ctrle_benchmark_test();
	aes256_ctrbe_benchmark_test();
	aes256_ctrle_benchmark_test();
#endif
}

/*! \brief Execute ChaCha and ChaCha20-Poly1305 benchmark functions in sequence. */
void qsctest_benchmark_chacha_run(void)
{
	chacha_poly1305_benchmark_test();
#if defined(QSCTEXT_RUNALL_BENCHMARKS)
	chacha128_benchmark_test();
	chacha256_benchmark_test();
#endif
}

/*! \brief Benchmark CSX-512 as independently authenticated messages. */
void qsctest_benchmark_csx_run(void)
{
	csx_benchmark_test();
}

/*! \brief Benchmark both RCS security strengths as independently authenticated messages. */
void qsctest_benchmark_rcs_run(void)
{
	rcs256_benchmark_test();
	rcs512_benchmark_test();
}

/*! \brief Run all KMAC benchmarks by direct invocation. */
void qsctest_benchmark_kmac_run(void)
{
	kmac128_benchmark();
	kmac256_benchmark();
	kmac512_benchmark();
#if defined(QSC_SYSTEM_HAS_AVX2)
	kmac128x4_benchmark();
	kmac256x4_benchmark();
	kmac512x4_benchmark();
#endif
#if defined(QSC_SYSTEM_HAS_AVX512)
	kmac128x8_benchmark();
	kmac256x8_benchmark();
	kmac512x8_benchmark();
#endif
}

/*! \brief Run all SHAKE generation benchmarks by direct invocation. */
void qsctest_benchmark_shake_run(void)
{
	shake128_benchmark();
	shake256_benchmark();
	shake512_benchmark();
#if defined(QSC_SYSTEM_HAS_AVX2)
	shake128x4_benchmark();
	shake256x4_benchmark();
	shake512x4_benchmark();
#endif
#if defined(QSC_SYSTEM_HAS_AVX512)
	shake128x8_benchmark();
	shake256x8_benchmark();
	shake512x8_benchmark();
#endif
}

/*! \brief Benchmark QMAC-256 as independently authenticated messages. */
void qsctest_benchmark_qmac_run(void)
{
	qmac_benchmark();
}

/*! \brief Run SHA-2 and SHA-3 independent-message hash benchmarks directly. */
void qsctest_benchmark_hash_run(void)
{
	sha256_benchmark();
	sha384_benchmark();
	sha512_benchmark();
	sha3_256_benchmark();
	sha3_512_benchmark();
}

