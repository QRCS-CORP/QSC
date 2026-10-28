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
#include "encoding.h"
#include "fileutils.h"
#include "memutils.h"
#include "timerex.h"
#include "x509cert.h"
#include <stdio.h>

/**
 * \file x509_encoding_baseline_benchmark.c
 * \brief Standalone X.509 and encoding CPU-time baseline for QSC.
 * \details Fixture paths are relative to the QSCTest working directory.
 * No files are written. All allocations and parsing contexts are released locally.
 */

/**
 * \brief Read a known fixture into owned memory.
 * \param path Relative path to the fixture file.
 * \param length Receives the exact number of fixture bytes.
 * \return Allocated buffer on success; NULL on failure. Caller must free with qsc_memutils_alloc_free.
 * \note Non-thread-shared read; no data is modified on disk.
 */
static uint8_t* x509bench_load(const char* path, size_t* length)
{
	uint8_t* res;
	size_t size;

	res = NULL;
	*length = 0U;
	size = qsc_fileutils_get_size(path);

	if (size != 0U)
	{
		res = (uint8_t*)qsc_memutils_malloc(size + 1U);

		if (res != NULL)
		{
			if (qsc_fileutils_copy_file_to_object(path, res, size) == size)
			{
				res[size] = 0U;
				*length = size;
			}
			else
			{
				qsc_memutils_alloc_free(res);
				res = NULL;
			}
		}
	}

	return res;
}

/**
 * \brief Record the repeated DER certificate decoding cost.
 * \return True when parsing and all runs succeed.
 * \note This is a single-certificate parser benchmark, not chain validation.
 */
static bool x509bench_certificate_der(void)
{
	const char* path = "X509/Vectors/Stage3/interop_server.cert.der";
	qsc_x509_certificate cert = { 0 };
	uint8_t* der;
	uint64_t start;
	uint64_t elapsed;
	size_t derlen;
	size_t i;
	qsc_asn1_status status;
	bool res;

	res = true;
	derlen = 0U;
	der = x509bench_load(path, &derlen);

	if (der == NULL)
	{
		res = false;
	}
	else
	{
		start = qsc_timerex_stopwatch_start();

		for (i = 0U; i < 3000U; ++i)
		{
			status = qsc_x509_certificate_decode_der(der, derlen, &cert);

			if (status != QSC_ASN1_STATUS_SUCCESS)
			{
				printf("[FAIL] X509 DER decode iteration=%zu status=%d\n", i, (int)status);
				res = false;
				break;
			}
		}

		elapsed = qsc_timerex_stopwatch_elapsed(start);
		qsc_x509_certificate_clear(&cert);

		if (res == true)
		{
			printf("X509BENCH,DER_CERT_DECODE,%zu,3000,%llu,%.2f\n", derlen,
				(unsigned long long)elapsed, ((double)elapsed * 1000000.0) / 3000.0);
		}
		qsc_memutils_secure_erase(der, derlen);
		qsc_memutils_alloc_free(der);
	}

	return res;
}

/**
 * \brief Record PEM decoding of the matching OpenSSL server certificate fixture.
 * \return True if the expected DER bytes are recovered on every iteration.
 * \note Data buffers remain caller-owned throughout; file reads are not timed.
 */
static bool x509bench_pem_decode(void)
{
	const char* path = "X509/Vectors/Stage3/interop_server.cert.pem";
	const char* derpath = "X509/Vectors/Stage3/interop_server.cert.der";
	uint8_t output[4096U] = { 0U };
	uint8_t* der;
	uint8_t* pem;
	uint64_t start;
	uint64_t elapsed;
	size_t pemlen;
	size_t derlen;
	size_t outputlen;
	size_t i;
	bool res;

	res = true;
	pemlen = 0U;
	derlen = 0U;
	outputlen = 0U;
	pem = x509bench_load(path, &pemlen);
	der = x509bench_load(derpath, &derlen);

	if (pem == NULL || der == NULL)
	{
		res = false;
	}
	else
	{
		start = qsc_timerex_stopwatch_start();

		for (i = 0U; i < 5000U; ++i)
		{
			outputlen = 0U;
			if (qsc_encoding_pem_decode((const char*)pem, pemlen, output, sizeof(output), &outputlen) == false ||
				outputlen != derlen || qsc_memutils_are_equal(output, der, derlen) == false)
			{
				printf("[FAIL] PEM decode iteration=%zu bytes=%zu\n", i, outputlen);
				res = false;
				break;
			}
		}

		elapsed = qsc_timerex_stopwatch_elapsed(start);

		if (res == true)
		{
			printf("X509BENCH,PEM_CERT_DECODE,%zu,5000,%llu,%.2f\n", derlen,
				(unsigned long long)elapsed, ((double)elapsed * 1000000.0) / 5000.0);
		}
	}

	if (der != NULL)
	{
		qsc_memutils_secure_erase(der, derlen);
		qsc_memutils_alloc_free(der);
	}
	if (pem != NULL)
	{
		qsc_memutils_secure_erase(pem, pemlen);
		qsc_memutils_alloc_free(pem);
	}
	qsc_memutils_secure_erase(output, sizeof(output));
	return res;
}

/**
 * \brief Measure 4096-byte Base64 decoding with fixed valid encoded input.
 * \return True if all decoded bytes match their source.
 * \note Does not benchmark Base64 validation rejection paths.
 */
static bool x509bench_base64_decode(void)
{
	uint8_t input[4096U] = { 0U };
	uint8_t output[4096U] = { 0U };
	char encoded[5500U] = { 0 };
	uint64_t start;
	uint64_t elapsed;
	size_t encodedlen;
	size_t i;
	bool res;

	res = true;
	encodedlen = qsc_encoding_base64_encoded_size(sizeof(input));

	for (i = 0U; i < sizeof(input); ++i)
	{
		input[i] = (uint8_t)(i ^ 0x91U);
	}

	if (qsc_encoding_base64_encode(encoded, sizeof(encoded), input, sizeof(input)) == false)
	{
		res = false;
	}
	else
	{
		start = qsc_timerex_stopwatch_start();

		for (i = 0U; i < 5000U; ++i)
		{
			if (qsc_encoding_base64_decode(output, sizeof(output), encoded, encodedlen) == false ||
				qsc_memutils_are_equal(input, output, sizeof(input)) == false)
			{
				printf("[FAIL] Base64 decode iteration=%zu\n", i);
				res = false;
				break;
			}
		}

		elapsed = qsc_timerex_stopwatch_elapsed(start);

		if (res == true)
		{
			printf("X509BENCH,BASE64_DECODE,%zu,5000,%llu,%.2f\n", sizeof(input),
				(unsigned long long)elapsed, ((double)elapsed * 1000000.0) / 5000.0);
		}
	}

	qsc_memutils_secure_erase(input, sizeof(input));
	qsc_memutils_secure_erase(output, sizeof(output));
	qsc_memutils_secure_erase(encoded, sizeof(encoded));
	return res;
}

/**
 * \brief Execute standalone DER, PEM and Base64 benchmarks sequentially.
 * \return Zero if all measurements and validations pass; one on failure.
 */
int main(void)
{
	bool res;
	bool pass;

	printf("X509BENCH_HEADER,operation,bytes,iterations,cpu_ms,ns_per_operation\n");
	res = x509bench_certificate_der();
	printf("X509BENCH_DER=%s\n", res ? "PASS" : "FAIL");
	pass = x509bench_pem_decode();
	printf("X509BENCH_PEM=%s\n", pass ? "PASS" : "FAIL");
	res = pass && res;
	pass = x509bench_base64_decode();
	printf("X509BENCH_BASE64=%s\n", pass ? "PASS" : "FAIL");
	res = pass && res;
	return res ? 0 : 1;
}
