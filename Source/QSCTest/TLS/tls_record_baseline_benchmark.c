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

#include "qsccommon.h"
#include "memutils.h"
#include "timerex.h"
#include "tlsrecord.h"
#include "tlslimits.h"
#include <stdio.h>

/**
 * \file tls_record_baseline_benchmark.c
 * \brief Standalone, cross-platform TLS 1.3 record-layer performance baseline.
 * \details Measures QSC record encryption and decryption in CPU milliseconds.
 * The measured cost includes the public record API, temporary allocations,
 * cryptographic operations, framing, and secure cleanup. Decryption repeatedly
 * processes the same previously generated record with a reset read sequence;
 * no ciphertext is reused for encryption and no production state is affected.
 * All buffers are local, all operations are synchronous, and no files are written.
 */

/**
 * \brief Calculate the median of three timing samples.
 * \param a First elapsed time in milliseconds.
 * \param b Second elapsed time in milliseconds.
 * \param c Third elapsed time in milliseconds.
 * \return Median elapsed time in milliseconds.
 * \note Pure helper; thread-safe and allocation-free.
 */
static uint64_t tlsbench_median(uint64_t a, uint64_t b, uint64_t c)
{
	uint64_t res;

	res = b;

	if ((a >= b && a <= c) || (a >= c && a <= b))
	{
		res = a;
	}
	else if ((c >= b && c <= a) || (c >= a && c <= b))
	{
		res = c;
	}

	return res;
}

/**
 * \brief Benchmark encryption or decryption of one TLS record size.
 * \param name The label identifying the cipher suite.
 * \param suite The TLS 1.3 record cipher suite.
 * \param keylen The cipher-suite key size in bytes.
 * \param length Number of application-data bytes in the record.
 * \param iterations Number of operations per timing sample.
 * \param decrypt Select decryption when true, encryption when false.
 * \return True if record generation, all measured operations, and output validation succeed.
 * \note Uses local state and qsc_timerex CPU clock; no shared state or file output.
 */
static bool tlsbench_measure(const char* name, qsc_tls_cipher_suite suite, size_t keylen, size_t length, size_t iterations, bool decrypt)
{
	qsc_tls_record_state state;
	uint8_t key[32U] = { 0U };
	uint8_t iv[12U] = { 0U };
	uint8_t data[QSC_TLS_MAX_PLAINTEXT_SIZE];
	uint8_t record[QSC_TLS_RECORD_MAX_WIRE_SIZE];
	uint8_t result[QSC_TLS_MAX_PLAINTEXT_SIZE];
	uint64_t samples[3U] = { 0U };
	uint64_t started;
	uint64_t elapsed;
	size_t recordlen;
	size_t outputlen;
	size_t i;
	size_t round;
	qsc_tls_record_content_type inner;
	qsc_tls_status status;
	bool res;

	res = true;
	recordlen = 0U;
	outputlen = 0U;
	inner = qsc_tls_record_content_invalid;

	for (i = 0U; i < length; ++i)
	{
		data[i] = (uint8_t)((i * 3U) ^ 0x5AU);
	}

	qsc_tls_record_state_initialize(&state, suite, key, keylen, iv, sizeof(iv));
	status = qsc_tls_record_encrypt(&state, record, sizeof(record), &recordlen, qsc_tls_record_content_application_data, data, length);
	qsc_tls_record_state_dispose(&state);

	if (status == qsc_tls_status_success)
	{
		for (round = 0U; round < 3U && res == true; ++round)
		{
			qsc_tls_record_state_initialize(&state, suite, key, keylen, iv, sizeof(iv));
			started = qsc_timerex_stopwatch_start();

			for (i = 0U; i < iterations; ++i)
			{
				outputlen = 0U;

				if (decrypt == true)
				{
					state.sequence = 0U;
					status = qsc_tls_record_decrypt(&state, result, sizeof(result), &outputlen, &inner, record, recordlen);
				}
				else
				{
					status = qsc_tls_record_encrypt(&state, record, sizeof(record), &outputlen, qsc_tls_record_content_application_data, data, length);
				}

				if (status != qsc_tls_status_success)
				{
					res = false;
					break;
				}
			}

			elapsed = qsc_timerex_stopwatch_elapsed(started);
			samples[round] = elapsed;
			qsc_tls_record_state_dispose(&state);
		}
	}
	else
	{
		res = false;
	}

	if (res == true)
	{
		if (decrypt == true && (outputlen != length || inner != qsc_tls_record_content_application_data ||
			(length != 0U && qsc_memutils_are_equal(result, data, length) == false)))
		{
			res = false;
		}
	}

	if (res == true)
	{
		uint64_t median;
		double nsperrecord;
		double throughput;

		median = tlsbench_median(samples[0U], samples[1U], samples[2U]);
		nsperrecord = ((double)median * 1000000.0) / (double)iterations;
		throughput = median != 0U ? ((double)length * (double)iterations * 1000.0) / (double)median / 1048576.0 : 0.0;
		printf("TLSBENCH,%s,%s,%zu,%zu,%llu,%.2f,%.2f,%llu,%llu,%llu\n",
			name, decrypt ? "decrypt" : "encrypt", length, iterations, (unsigned long long)median,
			nsperrecord, throughput, (unsigned long long)samples[0U],
			(unsigned long long)samples[1U], (unsigned long long)samples[2U]);
		fflush(stdout);
	}
	else
	{
		printf("[FAIL] TLS record benchmark suite=%s direction=%s length=%zu status=%d\n",
			name, decrypt ? "decrypt" : "encrypt", length, (int)status);
	}

	qsc_memutils_secure_erase(key, sizeof(key));
	qsc_memutils_secure_erase(iv, sizeof(iv));
	qsc_memutils_secure_erase(data, sizeof(data));
	qsc_memutils_secure_erase(record, sizeof(record));
	qsc_memutils_secure_erase(result, sizeof(result));
	return res;
}

/** \brief Benchmark AES-128-GCM records. \return True if all measurements succeed. */
static bool tlsbench_aes128(void)
{
	bool res;

	res = tlsbench_measure("AES128", qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, 16U, 64U, 1200U, false);
	res = tlsbench_measure("AES128", qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, 16U, 64U, 1200U, true) && res;
	res = tlsbench_measure("AES128", qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, 16U, 1024U, 300U, false) && res;
	res = tlsbench_measure("AES128", qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, 16U, 1024U, 300U, true) && res;
	res = tlsbench_measure("AES128", qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, 16U, 16384U, 30U, false) && res;
	res = tlsbench_measure("AES128", qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, 16U, 16384U, 30U, true) && res;
	return res;
}

/** \brief Benchmark AES-256-GCM records. \return True if all measurements succeed. */
static bool tlsbench_aes256(void)
{
	bool res;

	res = tlsbench_measure("AES256", qsc_tls_cipher_suite_tls_aes_256_gcm_sha384, 32U, 64U, 1200U, false);
	res = tlsbench_measure("AES256", qsc_tls_cipher_suite_tls_aes_256_gcm_sha384, 32U, 64U, 1200U, true) && res;
	res = tlsbench_measure("AES256", qsc_tls_cipher_suite_tls_aes_256_gcm_sha384, 32U, 1024U, 300U, false) && res;
	res = tlsbench_measure("AES256", qsc_tls_cipher_suite_tls_aes_256_gcm_sha384, 32U, 1024U, 300U, true) && res;
	res = tlsbench_measure("AES256", qsc_tls_cipher_suite_tls_aes_256_gcm_sha384, 32U, 16384U, 30U, false) && res;
	res = tlsbench_measure("AES256", qsc_tls_cipher_suite_tls_aes_256_gcm_sha384, 32U, 16384U, 30U, true) && res;
	return res;
}

/** \brief Benchmark ChaCha20-Poly1305 records. \return True if all measurements succeed. */
static bool tlsbench_chacha(void)
{
	bool res;

	res = tlsbench_measure("CHACHA20", qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256, 32U, 64U, 8000U, false);
	res = tlsbench_measure("CHACHA20", qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256, 32U, 64U, 8000U, true) && res;
	res = tlsbench_measure("CHACHA20", qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256, 32U, 1024U, 3500U, false) && res;
	res = tlsbench_measure("CHACHA20", qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256, 32U, 1024U, 3500U, true) && res;
	res = tlsbench_measure("CHACHA20", qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256, 32U, 16384U, 450U, false) && res;
	res = tlsbench_measure("CHACHA20", qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256, 32U, 16384U, 450U, true) && res;
	return res;
}

/**
 * \brief Run the standalone TLS record-layer performance baseline.
 * \return Zero if all cases complete correctly; nonzero otherwise.
 * \note Outputs CSV to standard output, writes no runtime artifacts and has no shared state.
 */
int main(void)
{
	bool res;

	printf("TLSBENCH_HEADER,suite,direction,bytes,iterations,median_cpu_ms,ns_per_record,MiB_per_s,sample1_ms,sample2_ms,sample3_ms\n");
	fflush(stdout);
	res = tlsbench_aes128();
	printf("TLSBENCH_AES128=%s\n", res ? "PASS" : "FAIL");
	{
		bool pass;
		pass = tlsbench_aes256();
		printf("TLSBENCH_AES256=%s\n", pass ? "PASS" : "FAIL");
		res = pass && res;
	}
	{
		bool pass;
		pass = tlsbench_chacha();
		printf("TLSBENCH_CHACHA20=%s\n", pass ? "PASS" : "FAIL");
		res = pass && res;
	}
	return res ? 0 : 1;
}
