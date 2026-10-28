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

#include "encoding_reference_test.h"
#include "encoding.h"
#include "asn1.h"
#include "memutils.h"
#include "testutils.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/** \brief One independently verified Base64 test vector. */
typedef struct
{
	/** \brief Source byte count. */
	size_t length;
	/** \brief Exact source bytes; only length bytes are used. */
	uint8_t input[6U];
	/** \brief Exact OpenSSL EVP_EncodeBlock result. */
	const char* encoded;
} qsctest_reference_base64_vector;

static const qsctest_reference_base64_vector qsctest_reference_base64_vectors[] =
{
	{ 1U, { 0x66U }, "Zg==" },
	{ 2U, { 0x66U, 0x6FU }, "Zm8=" },
	{ 3U, { 0x66U, 0x6FU, 0x6FU }, "Zm9v" },
	{ 6U, { 0x66U, 0x6FU, 0x6FU, 0x62U, 0x61U, 0x72U }, "Zm9vYmFy" },
	{ 5U, { 0x00U, 0xFFU, 0x80U, 0x01U, 0x02U }, "AP+AAQI=" }
};

static const uint8_t qsctest_reference_rsa_der[] =
{
	0x30U, 0x82U, 0x03U, 0x3DU, 0x30U, 0x82U, 0x02U, 0x25U, 0xA0U, 0x03U, 0x02U, 0x01U, 0x02U, 0x02U, 0x14U, 0x2EU,
	0x82U, 0x2BU, 0xD0U, 0x7CU, 0x9CU, 0x36U, 0x3EU, 0xFDU, 0xF4U, 0xF8U, 0x3AU, 0xABU, 0x69U, 0xFCU, 0x35U, 0x6BU,
	0xD8U, 0x11U, 0x01U, 0x30U, 0x0DU, 0x06U, 0x09U, 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0BU,
	0x05U, 0x00U, 0x30U, 0x2EU, 0x31U, 0x1DU, 0x30U, 0x1BU, 0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x14U, 0x51U,
	0x53U, 0x43U, 0x20U, 0x64U, 0x69U, 0x66U, 0x66U, 0x65U, 0x72U, 0x65U, 0x6EU, 0x74U, 0x69U, 0x61U, 0x6CU, 0x20U,
	0x52U, 0x53U, 0x41U, 0x31U, 0x0DU, 0x30U, 0x0BU, 0x06U, 0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU, 0x04U, 0x51U, 0x52U,
	0x43U, 0x53U, 0x30U, 0x1EU, 0x17U, 0x0DU, 0x32U, 0x36U, 0x31U, 0x30U, 0x32U, 0x38U, 0x30U, 0x31U, 0x35U, 0x38U,
	0x35U, 0x35U, 0x5AU, 0x17U, 0x0DU, 0x32U, 0x36U, 0x31U, 0x30U, 0x32U, 0x39U, 0x30U, 0x31U, 0x35U, 0x38U, 0x35U,
	0x35U, 0x5AU, 0x30U, 0x2EU, 0x31U, 0x1DU, 0x30U, 0x1BU, 0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x14U, 0x51U,
	0x53U, 0x43U, 0x20U, 0x64U, 0x69U, 0x66U, 0x66U, 0x65U, 0x72U, 0x65U, 0x6EU, 0x74U, 0x69U, 0x61U, 0x6CU, 0x20U,
	0x52U, 0x53U, 0x41U, 0x31U, 0x0DU, 0x30U, 0x0BU, 0x06U, 0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU, 0x04U, 0x51U, 0x52U,
	0x43U, 0x53U, 0x30U, 0x82U, 0x01U, 0x22U, 0x30U, 0x0DU, 0x06U, 0x09U, 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU,
	0x01U, 0x01U, 0x01U, 0x05U, 0x00U, 0x03U, 0x82U, 0x01U, 0x0FU, 0x00U, 0x30U, 0x82U, 0x01U, 0x0AU, 0x02U, 0x82U,
	0x01U, 0x01U, 0x00U, 0xBEU, 0x46U, 0xBEU, 0x14U, 0x54U, 0x82U, 0x75U, 0x27U, 0x8CU, 0x51U, 0xCFU, 0xC0U, 0x0FU,
	0x4BU, 0x5EU, 0x95U, 0x67U, 0x09U, 0xB8U, 0x8FU, 0xA7U, 0x09U, 0x03U, 0x79U, 0xFFU, 0xBEU, 0x7DU, 0x6CU, 0x08U,
	0x02U, 0x09U, 0x76U, 0x6DU, 0xD1U, 0xCDU, 0x36U, 0x0FU, 0x54U, 0xE4U, 0xDCU, 0x4FU, 0x7EU, 0x94U, 0x31U, 0x1AU,
	0x50U, 0x35U, 0xF6U, 0x20U, 0x7CU, 0x13U, 0xF8U, 0x29U, 0x5BU, 0x0EU, 0x8DU, 0x46U, 0x02U, 0x75U, 0x8CU, 0xFBU,
	0x86U, 0x78U, 0xBCU, 0xE9U, 0x22U, 0x94U, 0x92U, 0x06U, 0x92U, 0x6BU, 0xF2U, 0xE8U, 0x83U, 0xF4U, 0x46U, 0x2BU,
	0xD0U, 0xFCU, 0x74U, 0x1AU, 0x72U, 0x92U, 0xE4U, 0x47U, 0x4BU, 0x8BU, 0x58U, 0x87U, 0x9DU, 0xD9U, 0x35U, 0x67U,
	0x03U, 0x9BU, 0xDCU, 0xEFU, 0x80U, 0x76U, 0x92U, 0x3EU, 0x74U, 0xC0U, 0xF8U, 0xF7U, 0x17U, 0x81U, 0xD2U, 0xD4U,
	0x32U, 0xEBU, 0xC0U, 0x71U, 0xEEU, 0x80U, 0xF2U, 0xD4U, 0x31U, 0x53U, 0x69U, 0xDDU, 0x6CU, 0xA8U, 0xFBU, 0xA9U,
	0x60U, 0x6EU, 0x89U, 0x48U, 0x54U, 0x7FU, 0xE9U, 0x5BU, 0x98U, 0x2CU, 0xA1U, 0x3DU, 0x3AU, 0x75U, 0xF6U, 0x96U,
	0x13U, 0x76U, 0x58U, 0x12U, 0xA7U, 0x00U, 0x64U, 0xFAU, 0xA5U, 0x26U, 0x69U, 0xE8U, 0x88U, 0x4BU, 0x13U, 0x39U,
	0xBDU, 0xEFU, 0x9CU, 0xE0U, 0xB0U, 0x66U, 0x30U, 0xA9U, 0x6AU, 0x5BU, 0xD4U, 0x7BU, 0xB3U, 0x18U, 0x27U, 0xCBU,
	0xF2U, 0xC8U, 0x16U, 0xF4U, 0xB2U, 0x71U, 0x93U, 0x68U, 0xA8U, 0x79U, 0x0CU, 0xB0U, 0xB9U, 0xDCU, 0x4FU, 0x48U,
	0x77U, 0x06U, 0xB0U, 0xD8U, 0xC9U, 0x75U, 0xAEU, 0x88U, 0xFCU, 0xBBU, 0x74U, 0x13U, 0xAFU, 0x33U, 0x18U, 0xDAU,
	0x8EU, 0x6AU, 0x2EU, 0x4FU, 0x09U, 0x5FU, 0x3CU, 0xC5U, 0xB1U, 0xACU, 0x7EU, 0x15U, 0x22U, 0xFDU, 0x33U, 0xB4U,
	0x6BU, 0x7FU, 0x10U, 0x61U, 0xC5U, 0x07U, 0x9DU, 0x52U, 0x91U, 0xA6U, 0x8CU, 0x34U, 0x1CU, 0x66U, 0x61U, 0x71U,
	0xCAU, 0x01U, 0x36U, 0x43U, 0x05U, 0x64U, 0x30U, 0xB0U, 0x27U, 0x4CU, 0x4AU, 0x60U, 0x6BU, 0x66U, 0xD7U, 0xC1U,
	0x1EU, 0x5EU, 0x63U, 0x02U, 0x03U, 0x01U, 0x00U, 0x01U, 0xA3U, 0x53U, 0x30U, 0x51U, 0x30U, 0x1DU, 0x06U, 0x03U,
	0x55U, 0x1DU, 0x0EU, 0x04U, 0x16U, 0x04U, 0x14U, 0x7BU, 0x92U, 0x09U, 0xDDU, 0x74U, 0x86U, 0xD1U, 0x4CU, 0xD6U,
	0x89U, 0xF6U, 0x08U, 0x10U, 0xD7U, 0xC1U, 0x49U, 0x97U, 0x8EU, 0x4BU, 0x77U, 0x30U, 0x1FU, 0x06U, 0x03U, 0x55U,
	0x1DU, 0x23U, 0x04U, 0x18U, 0x30U, 0x16U, 0x80U, 0x14U, 0x7BU, 0x92U, 0x09U, 0xDDU, 0x74U, 0x86U, 0xD1U, 0x4CU,
	0xD6U, 0x89U, 0xF6U, 0x08U, 0x10U, 0xD7U, 0xC1U, 0x49U, 0x97U, 0x8EU, 0x4BU, 0x77U, 0x30U, 0x0FU, 0x06U, 0x03U,
	0x55U, 0x1DU, 0x13U, 0x01U, 0x01U, 0xFFU, 0x04U, 0x05U, 0x30U, 0x03U, 0x01U, 0x01U, 0xFFU, 0x30U, 0x0DU, 0x06U,
	0x09U, 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0BU, 0x05U, 0x00U, 0x03U, 0x82U, 0x01U, 0x01U,
	0x00U, 0x89U, 0xE8U, 0x01U, 0xF7U, 0xB7U, 0xBFU, 0x9EU, 0x73U, 0x62U, 0xDDU, 0x79U, 0x60U, 0x8AU, 0xA2U, 0x63U,
	0x9BU, 0x1CU, 0x3FU, 0x44U, 0xCDU, 0x6DU, 0x39U, 0x3AU, 0xD7U, 0xD3U, 0x82U, 0xCBU, 0x14U, 0x2DU, 0xFDU, 0x56U,
	0xE6U, 0x4BU, 0xBFU, 0xF3U, 0x88U, 0xF3U, 0x69U, 0x93U, 0xCCU, 0xAFU, 0x5FU, 0x96U, 0xD3U, 0xA0U, 0x68U, 0x66U,
	0xC9U, 0xE6U, 0x55U, 0xEEU, 0x9AU, 0xD9U, 0x60U, 0xDBU, 0x55U, 0x25U, 0x67U, 0x96U, 0x04U, 0xEDU, 0xC2U, 0xE9U,
	0x03U, 0x8FU, 0xAFU, 0xE7U, 0xBCU, 0xF0U, 0xA8U, 0xA6U, 0x62U, 0x26U, 0x06U, 0x98U, 0xE4U, 0x34U, 0x63U, 0x2EU,
	0x36U, 0x78U, 0x2DU, 0x94U, 0x5DU, 0xC5U, 0x30U, 0x97U, 0xB6U, 0x69U, 0x15U, 0x7DU, 0xDBU, 0xBEU, 0x1FU, 0xA3U,
	0x26U, 0x13U, 0x59U, 0xE0U, 0xFCU, 0x4EU, 0xD2U, 0xD2U, 0x4BU, 0x07U, 0x93U, 0x35U, 0xB8U, 0xACU, 0x17U, 0x96U,
	0x48U, 0x47U, 0x7DU, 0xC2U, 0xC7U, 0x0CU, 0xBAU, 0x71U, 0x5EU, 0xCAU, 0xE0U, 0x76U, 0x0FU, 0x92U, 0xD7U, 0xADU,
	0x7DU, 0xB4U, 0xA1U, 0x9AU, 0x6EU, 0x18U, 0x7AU, 0x64U, 0x46U, 0x36U, 0x24U, 0x4FU, 0x69U, 0x75U, 0x7DU, 0xB2U,
	0xFAU, 0xEEU, 0x12U, 0xDEU, 0x56U, 0x83U, 0x4EU, 0x32U, 0x84U, 0x91U, 0xBDU, 0xE3U, 0x65U, 0x42U, 0xD6U, 0x46U,
	0x68U, 0xE1U, 0xDCU, 0x7FU, 0x62U, 0xBFU, 0x9EU, 0x79U, 0xF6U, 0x6FU, 0xD1U, 0x3EU, 0x4EU, 0x14U, 0xF8U, 0x74U,
	0x57U, 0xB4U, 0x0BU, 0xD8U, 0xE9U, 0x82U, 0xC9U, 0x45U, 0x3EU, 0xEAU, 0xCDU, 0xA7U, 0x10U, 0x36U, 0x91U, 0x87U,
	0x1FU, 0x91U, 0x35U, 0x34U, 0x31U, 0x60U, 0xE1U, 0x3CU, 0xF0U, 0x6AU, 0x50U, 0x99U, 0x7CU, 0x6FU, 0x55U, 0x2BU,
	0xA9U, 0x51U, 0xF6U, 0xAAU, 0x53U, 0xFBU, 0x9AU, 0x1CU, 0xB1U, 0x4AU, 0xCBU, 0x16U, 0x00U, 0xDCU, 0x08U, 0xA1U,
	0x0CU, 0xCEU, 0x9CU, 0xF1U, 0x45U, 0xB5U, 0x43U, 0xC0U, 0x08U, 0xF0U, 0x25U, 0xB7U, 0x92U, 0xADU, 0xD0U, 0x01U,
	0xAFU, 0x9FU, 0x90U, 0x9FU, 0xC7U, 0xC1U, 0x9FU, 0xB1U, 0x4DU, 0x1BU, 0x8CU, 0x61U, 0x36U, 0xE5U, 0x1EU, 0x40U,
	0x0BU
};

static const char qsctest_reference_rsa_pem[] =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDPTCCAiWgAwIBAgIULoIr0HycNj799Pg6q2n8NWvYEQEwDQYJKoZIhvcNAQEL\n"
	"BQAwLjEdMBsGA1UEAwwUUVNDIGRpZmZlcmVudGlhbCBSU0ExDTALBgNVBAoMBFFS\n"
	"Q1MwHhcNMjYxMDI4MDE1ODU1WhcNMjYxMDI5MDE1ODU1WjAuMR0wGwYDVQQDDBRR\n"
	"U0MgZGlmZmVyZW50aWFsIFJTQTENMAsGA1UECgwEUVJDUzCCASIwDQYJKoZIhvcN\n"
	"AQEBBQADggEPADCCAQoCggEBAL5GvhRUgnUnjFHPwA9LXpVnCbiPpwkDef++fWwI\n"
	"Agl2bdHNNg9U5NxPfpQxGlA19iB8E/gpWw6NRgJ1jPuGeLzpIpSSBpJr8uiD9EYr\n"
	"0Px0GnKS5EdLi1iHndk1ZwOb3O+AdpI+dMD49xeB0tQy68Bx7oDy1DFTad1sqPup\n"
	"YG6JSFR/6VuYLKE9OnX2lhN2WBKnAGT6pSZp6IhLEzm975zgsGYwqWpb1HuzGCfL\n"
	"8sgW9LJxk2ioeQywudxPSHcGsNjJda6I/Lt0E68zGNqOai5PCV88xbGsfhUi/TO0\n"
	"a38QYcUHnVKRpow0HGZhccoBNkMFZDCwJ0xKYGtm18EeXmMCAwEAAaNTMFEwHQYD\n"
	"VR0OBBYEFHuSCd10htFM1on2CBDXwUmXjkt3MB8GA1UdIwQYMBaAFHuSCd10htFM\n"
	"1on2CBDXwUmXjkt3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB\n"
	"AInoAfe3v55zYt15YIqiY5scP0TNbTk619OCyxQt/VbmS7/ziPNpk8yvX5bToGhm\n"
	"yeZV7prZYNtVJWeWBO3C6QOPr+e88KimYiYGmOQ0Yy42eC2UXcUwl7ZpFX3bvh+j\n"
	"JhNZ4PxO0tJLB5M1uKwXlkhHfcLHDLpxXsrgdg+S1619tKGabhh6ZEY2JE9pdX2y\n"
	"+u4S3laDTjKEkb3jZULWRmjh3H9iv5559m/RPk4U+HRXtAvY6YLJRT7qzacQNpGH\n"
	"H5E1NDFg4TzwalCZfG9VK6lR9qpT+5ocsUrLFgDcCKEMzpzxRbVDwAjwJbeSrdAB\n"
	"r5+Qn8fBn7FNG4xhNuUeQAs=\n"
	"-----END CERTIFICATE-----\n"
;


/** \brief Check a small set of exact Base64 outputs verified with OpenSSL EVP_EncodeBlock.
 * \return True if every known-answer comparison passes; otherwise false.
 * \note Local buffers only; no shared mutable state. */
static bool qsctest_reference_base64_test(void)
{
	char encoded[32U];
	uint8_t decoded[8U];
	size_t i;
	size_t n;
	bool res;

	res = true;

	for (i = 0U; i < sizeof(qsctest_reference_base64_vectors) / sizeof(qsctest_reference_base64_vectors[0U]); ++i)
	{
		const qsctest_reference_base64_vector* v;

		v = &qsctest_reference_base64_vectors[i];
		n = qsc_encoding_base64_encoded_size(v->length);
		qsc_memutils_clear(encoded, sizeof(encoded));
		qsc_memutils_clear(decoded, sizeof(decoded));

		if (n != strlen(v->encoded) ||
			qsc_encoding_base64_encode(encoded, sizeof(encoded), v->input, v->length) == false ||
			strcmp(encoded, v->encoded) != 0 ||
			qsc_encoding_base64_decoded_size(v->encoded, n) != v->length ||
			qsc_encoding_base64_decode(decoded, sizeof(decoded), v->encoded, n) == false ||
			qsc_memutils_are_equal(decoded, v->input, v->length) == false)
		{
			qsctest_print_line("FAIL: reference Base64 bytes, size, or decode differ from OpenSSL vector.");
			res = false;
			break;
		}
	}

	if (res == true)
	{
		qsctest_print_line("PASS: OpenSSL-verified Base64 known-answer and round-trip tests.");
	}

	return res;
}

/** \brief Compare a split streaming Base64 operation to an OpenSSL output.
 * \return True if the encoded and decoded bytes agree.
 * \note State is stack owned; test is thread-safe. */
static bool qsctest_reference_base64_stream_test(void)
{
	const uint8_t source[] = { 0x66U, 0x6FU, 0x6FU, 0x62U, 0x61U, 0x72U };
	const char* reference;
	qsc_encoding_base64_stream_state state;
	char encoded[20U];
	uint8_t decoded[sizeof(source)];
	size_t amount;
	size_t total;
	bool res;

	reference = "Zm9vYmFy";
	total = 0U;
	res = true;
	qsc_memutils_clear(encoded, sizeof(encoded));
	qsc_memutils_clear(decoded, sizeof(decoded));
	qsc_encoding_base64_stream_initialize(&state);

	if (qsc_encoding_base64_stream_encode_update(&state, encoded, sizeof(encoded), source, 1U, &amount) == false)
	{
		res = false;
	}
	else
	{
		total += amount;
	}

	if (res == true)
	{
		if (qsc_encoding_base64_stream_encode_update(&state, encoded + total, sizeof(encoded) - total, source + 1U, 2U, &amount) == false)
		{
			res = false;
		}
		else
		{
			total += amount;
		}
	}

	if (res == true)
	{
		if (qsc_encoding_base64_stream_encode_update(&state, encoded + total, sizeof(encoded) - total, source + 3U, 3U, &amount) == false)
		{
			res = false;
		}
		else
		{
			total += amount;
		}
	}

	if (res == true)
	{
		if (qsc_encoding_base64_stream_encode_final(&state, encoded + total, sizeof(encoded) - total, &amount) == false)
		{
			res = false;
		}
		else
		{
			total += amount;
		}
	}

	if (res == true && (total != strlen(reference) || memcmp(encoded, reference, total) != 0))
	{
		res = false;
	}

	if (res == true)
	{
		total = 0U;
		qsc_encoding_base64_stream_initialize(&state);

		if (qsc_encoding_base64_stream_decode_update(&state, decoded, sizeof(decoded), reference, 2U, &amount) == false)
		{
			res = false;
		}
		else
		{
			total += amount;
		}

		if (res == true)
		{
			if (qsc_encoding_base64_stream_decode_update(&state, decoded + total, sizeof(decoded) - total, reference + 2U, 6U, &amount) == false)
			{
				res = false;
			}
			else
			{
				total += amount;
			}
		}

		if (res == true && (qsc_encoding_base64_stream_decode_final(&state) == false || total != sizeof(source) ||
			qsc_memutils_are_equal(decoded, source, sizeof(source)) == false))
		{
			res = false;
		}
	}

	qsctest_print_line(res ? "PASS: OpenSSL-verified chunked Base64 encoding and decoding." :
		"FAIL: OpenSSL-verified chunked Base64 encoding or decoding.");
	return res;
}

/** \brief Check exact uppercase hexadecimal output and strict invalid-digit rejection.
 * \return True on expected output and rejection.
 * \note Local buffers only. */
static bool qsctest_reference_hex_test(void)
{
	const uint8_t input[] = { 0x00U, 0xFFU, 0x80U, 0x01U, 0x02U };
	const char* expected;
	char encoded[20U];
	uint8_t decoded[sizeof(input)];
	size_t written;
	bool res;

	expected = "00FF800102";
	written = 0U;
	qsc_memutils_clear(encoded, sizeof(encoded));
	qsc_memutils_clear(decoded, sizeof(decoded));
	res = qsc_encoding_hex_encode(input, sizeof(input), encoded, sizeof(encoded));
	res = (res && strcmp(encoded, expected) == 0);
	res = (res && qsc_encoding_hex_decode(expected, strlen(expected), decoded, sizeof(decoded), &written));
	res = (res && written == sizeof(input));
	res = (res && qsc_memutils_are_equal(decoded, input, sizeof(input)));
	res = (res && qsc_encoding_hex_decode("00FG", 4U, decoded, sizeof(decoded), &written) == false);

	qsctest_print_line(res ? "PASS: OpenSSL-verified hexadecimal values and invalid-digit rejection." :
		"FAIL: OpenSSL-verified hexadecimal output or invalid-digit rejection.");
	return res;
}

/** \brief Check DER canonical tag/length handling against OpenSSL-verified TLVs.
 * \return True if valid elements pass and malformed elements fail.
 * \note Local state only. */
static bool qsctest_reference_der_test(void)
{
	const uint8_t integer_ok[] = { 0x02U, 0x01U, 0x7FU };
	const uint8_t null_ok[] = { 0x05U, 0x00U };
	const uint8_t bits_ok[] = { 0x03U, 0x02U, 0x00U, 0xAAU };
	const uint8_t seq_ok[] = { 0x30U, 0x03U, 0x02U, 0x01U, 0x7FU };
	const uint8_t integer_overlong[] = { 0x02U, 0x02U, 0x00U, 0x7FU };
	const uint8_t length_nonminimal[] = { 0x02U, 0x81U, 0x01U, 0x7FU };
	const uint8_t boolean_noncanonical[] = { 0x01U, 0x01U, 0x01U };
	const uint8_t bitstring_unused[] = { 0x03U, 0x02U, 0x03U, 0xAFU };
	size_t consumed;
	bool res;

	consumed = 0U;
	res = qsc_encoding_der_validate(integer_ok, sizeof(integer_ok), &consumed);
	res = (res && consumed == sizeof(integer_ok));
	res = (res && qsc_encoding_der_validate(null_ok, sizeof(null_ok), &consumed));
	res = (res && consumed == sizeof(null_ok));
	res = (res && qsc_encoding_der_validate(bits_ok, sizeof(bits_ok), &consumed));
	res = (res && consumed == sizeof(bits_ok));
	res = (res && qsc_encoding_der_validate(seq_ok, sizeof(seq_ok), &consumed));
	res = (res && consumed == sizeof(seq_ok));
	res = (res && qsc_encoding_der_validate(integer_overlong, sizeof(integer_overlong), &consumed) == false);
	res = (res && qsc_encoding_der_validate(length_nonminimal, sizeof(length_nonminimal), &consumed) == false);
	res = (res && qsc_encoding_der_validate(boolean_noncanonical, sizeof(boolean_noncanonical), &consumed) == false);
	res = (res && qsc_encoding_der_validate(bitstring_unused, sizeof(bitstring_unused), &consumed) == false);

	qsctest_print_line(res ? "PASS: OpenSSL-verified canonical DER and malformed TLV checks." :
		"FAIL: OpenSSL-verified DER validation or malformed TLV rejection.");
	return res;
}

/** \brief Verify one OpenSSL-generated X.509 fixture and exact child offsets and PEM bytes.
 * \return True if every byte, length, and offset matches.
 * \note The certificate fixture is public test material, not a private key. */
static bool qsctest_reference_x509_test(void)
{
	const uint8_t* child;
	char pem[2048U];
	uint8_t decoded[sizeof(qsctest_reference_rsa_der)];
	size_t consumed;
	size_t length;
	size_t written;
	bool res;

	child = NULL;
	consumed = 0U;
	length = 0U;
	written = 0U;
	qsc_memutils_clear(pem, sizeof(pem));
	qsc_memutils_clear(decoded, sizeof(decoded));
	res = qsc_encoding_der_validate(qsctest_reference_rsa_der, sizeof(qsctest_reference_rsa_der), &consumed);
	res = (res && consumed == sizeof(qsctest_reference_rsa_der));
	res = (res && qsc_asn1_der_get_child_region(qsctest_reference_rsa_der, sizeof(qsctest_reference_rsa_der), 0U, &child, &length) == QSC_ASN1_STATUS_SUCCESS);
	res = (res && child == qsctest_reference_rsa_der + 4U && length == 553U);
	res = (res && qsc_asn1_der_get_child_region(qsctest_reference_rsa_der, sizeof(qsctest_reference_rsa_der), 1U, &child, &length) == QSC_ASN1_STATUS_SUCCESS);
	res = (res && child == qsctest_reference_rsa_der + 557U && length == 15U);
	res = (res && qsc_asn1_der_get_child_region(qsctest_reference_rsa_der, sizeof(qsctest_reference_rsa_der), 2U, &child, &length) == QSC_ASN1_STATUS_SUCCESS);
	res = (res && child == qsctest_reference_rsa_der + 572U && length == 261U);
	res = (res && qsc_encoding_pem_encode("CERTIFICATE", pem, sizeof(pem), qsctest_reference_rsa_der, sizeof(qsctest_reference_rsa_der)));
	res = (res && strcmp(pem, qsctest_reference_rsa_pem) == 0);
	res = (res && qsc_encoding_pem_decode(qsctest_reference_rsa_pem, strlen(qsctest_reference_rsa_pem), decoded, sizeof(decoded), &written));
	res = (res && written == sizeof(qsctest_reference_rsa_der));
	res = (res && qsc_memutils_are_equal(decoded, qsctest_reference_rsa_der, written));

	qsctest_print_line(res ? "PASS: OpenSSL-generated RSA X.509 DER child slices and exact PEM output." :
		"FAIL: OpenSSL-generated RSA X.509 DER child offsets, bytes, or PEM output.");
	return res;
}

/** \brief Run named QSC reference tests individually and sequentially.
 * \return True if all tests pass, false otherwise.
 * \note This function is thread-safe; all test state is local. */
bool qsctest_encoding_reference_run(void)
{
	bool valid;

	valid = true;

	if (qsctest_reference_base64_test() == false)
	{
		valid = false;
	}

	if (qsctest_reference_base64_stream_test() == false)
	{
		valid = false;
	}

	if (qsctest_reference_hex_test() == false)
	{
		valid = false;
	}

	if (qsctest_reference_der_test() == false)
	{
		valid = false;
	}

	if (qsctest_reference_x509_test() == false)
	{
		valid = false;
	}

	qsctest_print_line(valid ? "PASS: All self-contained OpenSSL-verified encoding reference tests." :
		"FAIL: One or more OpenSSL-verified encoding reference tests.");
	return valid;
}
