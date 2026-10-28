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
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
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

#include "tls_stage26_record_fragmentation_tests.h"
#include "../testutils.h"
#include "intutils.h"
#include "memutils.h"
#include "tlsdefs.h"
#include "tlslimits.h"
#include "tlsrecord.h"
#include <stdio.h>

static void stage26_fill_sequence(uint8_t* output, size_t outlen, uint8_t seed)
{
    size_t i;

    if (output != NULL)
    {
        for (i = 0U; i < outlen; ++i)
        {
            output[i] = (uint8_t)(seed + (uint8_t)i);
        }
    }
}

static bool stage26_plaintext_fragment_span_test(void)
{
    uint8_t payload[12U] = { 0U };
    uint8_t record[QSC_TLS_RECORD_HEADER_SIZE + sizeof(payload)] = { 0U };
    const uint8_t* span;
    size_t payloadlen;
    size_t recordlen;
    size_t written;
    size_t i;
    qsc_tls_record_content_type type;
    bool complete;
    bool res;

    res = false;
    span = NULL;
    payloadlen = 0U;
    recordlen = 0U;
    written = 0U;
    type = qsc_tls_record_content_invalid;
    complete = true;
    stage26_fill_sequence(payload, sizeof(payload), 0x20U);

    if (qsc_tls_record_encode_plaintext(record, sizeof(record), &written, qsc_tls_record_content_handshake, payload, sizeof(payload)) == qsc_tls_status_success)
    {
        if (written == sizeof(record))
        {
            res = true;

            for (i = 0U; i < written; ++i)
            {
                recordlen = 1U;
                complete = true;

                if (qsc_tls_record_try_get_span_length(record, i, &recordlen, &complete) != qsc_tls_status_success)
                {
                    res = false;
                    break;
                }

                if (i < QSC_TLS_RECORD_HEADER_SIZE)
                {
                    if ((recordlen != 0U) || (complete != false))
                    {
                        res = false;
                        break;
                    }
                }
                else if ((recordlen != written) || (complete != false))
                {
                    res = false;
                    break;
                }
            }

            if (res == true)
            {
                if (qsc_tls_record_try_get_span_length(record, written, &recordlen, &complete) == qsc_tls_status_success)
                {
                    if ((recordlen == written) && (complete == true))
                    {
                        if (qsc_tls_record_decode_plaintext(record, written, &type, &span, &payloadlen) == qsc_tls_status_success)
                        {
                            if ((type == qsc_tls_record_content_handshake) && (payloadlen == sizeof(payload)) &&
                                (qsc_memutils_are_equal(span, payload, sizeof(payload)) == true))
                            {
                                res = true;
                            }
                            else
                            {
                                res = false;
                            }
                        }
                        else
                        {
                            res = false;
                        }
                    }
                    else
                    {
                        res = false;
                    }
                }
                else
                {
                    res = false;
                }
            }
        }
    }

    return res;
}

static bool stage26_plaintext_coalesced_records_test(void)
{
    uint8_t payload1[5U] = { 0x01U, 0x02U, 0x03U, 0x04U, 0x05U };
    uint8_t payload2[2U] = { 0x01U, 0x00U };
    uint8_t record1[QSC_TLS_RECORD_HEADER_SIZE + sizeof(payload1)] = { 0U };
    uint8_t record2[QSC_TLS_RECORD_HEADER_SIZE + sizeof(payload2)] = { 0U };
    uint8_t coalesced[sizeof(record1) + sizeof(record2)] = { 0U };
    const uint8_t* span;
    size_t payloadlen;
    size_t recordlen;
    size_t written1;
    size_t written2;
    size_t offset;
    qsc_tls_record_content_type type;
    bool complete;
    bool res;

    res = false;
    span = NULL;
    payloadlen = 0U;
    recordlen = 0U;
    written1 = 0U;
    written2 = 0U;
    offset = 0U;
    type = qsc_tls_record_content_invalid;
    complete = false;

    if (qsc_tls_record_encode_plaintext(record1, sizeof(record1), &written1, qsc_tls_record_content_application_data, payload1, sizeof(payload1)) == qsc_tls_status_success)
    {
        if (qsc_tls_record_encode_plaintext(record2, sizeof(record2), &written2, qsc_tls_record_content_alert, payload2, sizeof(payload2)) == qsc_tls_status_success)
        {
            qsc_memutils_copy(coalesced, record1, written1);
            qsc_memutils_copy(coalesced + written1, record2, written2);

            if (qsc_tls_record_try_get_span_length(coalesced, sizeof(coalesced), &recordlen, &complete) == qsc_tls_status_success)
            {
                if ((recordlen == written1) && (complete == true))
                {
                    if (qsc_tls_record_decode_plaintext(coalesced, recordlen, &type, &span, &payloadlen) == qsc_tls_status_success)
                    {
                        if ((type == qsc_tls_record_content_application_data) && (payloadlen == sizeof(payload1)) &&
                            (qsc_memutils_are_equal(span, payload1, sizeof(payload1)) == true))
                        {
                            offset = recordlen;
                            recordlen = 0U;
                            complete = false;

                            if (qsc_tls_record_try_get_span_length(coalesced + offset, sizeof(coalesced) - offset, &recordlen, &complete) == qsc_tls_status_success)
                            {
                                if ((recordlen == written2) && (complete == true))
                                {
                                    span = NULL;
                                    payloadlen = 0U;
                                    type = qsc_tls_record_content_invalid;

                                    if (qsc_tls_record_decode_plaintext(coalesced + offset, recordlen, &type, &span, &payloadlen) == qsc_tls_status_success)
                                    {
                                        if ((type == qsc_tls_record_content_alert) && (payloadlen == sizeof(payload2)) &&
                                            (qsc_memutils_are_equal(span, payload2, sizeof(payload2)) == true))
                                        {
                                            res = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return res;
}

static bool stage26_plaintext_boundary_test(void)
{
    static uint8_t payload[QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE + 1U];
    static uint8_t record[QSC_TLS_RECORD_HEADER_SIZE + QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE];
    const uint8_t* span;
    size_t payloadlen;
    size_t written;
    qsc_tls_record_content_type type;
    bool res;

    res = false;
    span = NULL;
    payloadlen = 0U;
    written = 0U;
    type = qsc_tls_record_content_invalid;
    stage26_fill_sequence(payload, sizeof(payload), 0x40U);

    if (qsc_tls_record_encode_plaintext(record, sizeof(record), &written, qsc_tls_record_content_application_data, payload, QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE) == qsc_tls_status_success)
    {
        if (written == sizeof(record))
        {
            if (qsc_tls_record_decode_plaintext(record, written, &type, &span, &payloadlen) == qsc_tls_status_success)
            {
                if ((type == qsc_tls_record_content_application_data) && (payloadlen == QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE) &&
                    (qsc_memutils_are_equal(span, payload, QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE) == true))
                {
                    written = 1U;

                    if (qsc_tls_record_encode_plaintext(record, sizeof(record), &written, qsc_tls_record_content_application_data,
                        payload, QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE + 1U) == qsc_tls_status_invalid_length)
                    {
                        if (written == 0U)
                        {
                            res = true;
                        }
                    }
                }
            }
        }
    }

    return res;
}

static bool stage26_malformed_record_length_test(void)
{
    uint8_t header[QSC_TLS_RECORD_HEADER_SIZE] = { 0U };
    size_t recordlen;
    qsc_tls_record_content_type type;
    const uint8_t* payload;
    size_t payloadlen;
    bool complete;
    bool res;

    res = false;
    recordlen = 0U;
    type = qsc_tls_record_content_invalid;
    payload = NULL;
    payloadlen = 0U;
    complete = false;

    header[0U] = (uint8_t)qsc_tls_record_content_handshake;
    qsc_intutils_be16to8(header + 1U, QSC_TLS_PROTOCOL_VERSION_12);
    qsc_intutils_be16to8(header + 3U, 0xFFFFU);

    if (qsc_tls_record_try_get_span_length(header, sizeof(header), &recordlen, &complete) == qsc_tls_status_record_overflow)
    {
        if ((recordlen == 0U) && (complete == false))
        {
            header[3U] = 0x00U;
            header[4U] = 0x01U;

            if (qsc_tls_record_decode_plaintext(header, sizeof(header), &type, &payload, &payloadlen) == qsc_tls_status_invalid_length)
            {
                if ((type == qsc_tls_record_content_invalid) && (payload == NULL) && (payloadlen == 0U))
                {
                    res = true;
                }
            }
        }
    }

    return res;
}

static bool stage26_protected_record_fragmentation_test(void)
{
    uint8_t key[QSC_TLS_AES128_KEY_SIZE] = { 0U };
    uint8_t iv[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
    uint8_t payload[32U] = { 0U };
    uint8_t record[QSC_TLS_RECORD_HEADER_SIZE + sizeof(payload) + QSC_TLS_INNER_CONTENT_TYPE_SIZE + QSC_TLS_GCM_TAG_SIZE] = { 0U };
    uint8_t output[sizeof(payload)] = { 0U };
    qsc_tls_record_state wstate;
    qsc_tls_record_state rstate;
    qsc_tls_record_content_type inner;
    size_t recordlen;
    size_t written;
    size_t outlen;
    size_t i;
    bool complete;
    bool res;

    res = false;
    recordlen = 0U;
    written = 0U;
    outlen = 0U;
    inner = qsc_tls_record_content_invalid;
    complete = false;
    stage26_fill_sequence(key, sizeof(key), 0x10U);
    stage26_fill_sequence(iv, sizeof(iv), 0x80U);
    stage26_fill_sequence(payload, sizeof(payload), 0xC0U);

    qsc_tls_record_state_initialize(&wstate, qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, key, sizeof(key), iv, sizeof(iv));
    qsc_tls_record_state_initialize(&rstate, qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, key, sizeof(key), iv, sizeof(iv));

    if ((wstate.initialized == true) && (rstate.initialized == true))
    {
        if (qsc_tls_record_encrypt(&wstate, record, sizeof(record), &written, qsc_tls_record_content_application_data, payload, sizeof(payload)) == qsc_tls_status_success)
        {
            res = true;

            for (i = 0U; i < written; ++i)
            {
                recordlen = 1U;
                complete = true;

                if (qsc_tls_record_try_get_span_length(record, i, &recordlen, &complete) != qsc_tls_status_success)
                {
                    res = false;
                    break;
                }

                if (i < QSC_TLS_RECORD_HEADER_SIZE)
                {
                    if ((recordlen != 0U) || (complete != false))
                    {
                        res = false;
                        break;
                    }
                }
                else if ((recordlen != written) || (complete != false))
                {
                    res = false;
                    break;
                }
            }

            if (res == true)
            {
                if (qsc_tls_record_try_get_span_length(record, written, &recordlen, &complete) == qsc_tls_status_success)
                {
                    if ((recordlen == written) && (complete == true))
                    {
                        if (qsc_tls_record_decrypt(&rstate, output, sizeof(output), &outlen, &inner, record, written) == qsc_tls_status_success)
                        {
                            if ((inner == qsc_tls_record_content_application_data) && (outlen == sizeof(payload)) &&
                                (qsc_memutils_are_equal(output, payload, sizeof(payload)) == true) &&
                                (qsc_tls_record_state_get_sequence(&wstate) == 1U) &&
                                (qsc_tls_record_state_get_sequence(&rstate) == 1U))
                            {
                                res = true;
                            }
                            else
                            {
                                res = false;
                            }
                        }
                        else
                        {
                            res = false;
                        }
                    }
                    else
                    {
                        res = false;
                    }
                }
                else
                {
                    res = false;
                }
            }
        }
    }

    qsc_tls_record_state_dispose(&wstate);
    qsc_tls_record_state_dispose(&rstate);

    return res;
}

static bool stage26_protected_coalesced_records_test(void)
{
    uint8_t key[QSC_TLS_AES128_KEY_SIZE] = { 0U };
    uint8_t iv[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
    uint8_t payload1[8U] = { 0U };
    uint8_t payload2[13U] = { 0U };
    uint8_t record1[QSC_TLS_RECORD_HEADER_SIZE + sizeof(payload1) + QSC_TLS_INNER_CONTENT_TYPE_SIZE + QSC_TLS_GCM_TAG_SIZE] = { 0U };
    uint8_t record2[QSC_TLS_RECORD_HEADER_SIZE + sizeof(payload2) + QSC_TLS_INNER_CONTENT_TYPE_SIZE + QSC_TLS_GCM_TAG_SIZE] = { 0U };
    uint8_t coalesced[sizeof(record1) + sizeof(record2)] = { 0U };
    uint8_t output[sizeof(payload2)] = { 0U };
    qsc_tls_record_state wstate;
    qsc_tls_record_state rstate;
    qsc_tls_record_content_type inner;
    size_t recordlen;
    size_t written1;
    size_t written2;
    size_t outlen;
    size_t offset;
    bool complete;
    bool res;

    res = false;
    recordlen = 0U;
    written1 = 0U;
    written2 = 0U;
    outlen = 0U;
    offset = 0U;
    inner = qsc_tls_record_content_invalid;
    complete = false;
    stage26_fill_sequence(key, sizeof(key), 0x30U);
    stage26_fill_sequence(iv, sizeof(iv), 0x60U);
    stage26_fill_sequence(payload1, sizeof(payload1), 0x90U);
    stage26_fill_sequence(payload2, sizeof(payload2), 0xD0U);

    qsc_tls_record_state_initialize(&wstate, qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, key, sizeof(key), iv, sizeof(iv));
    qsc_tls_record_state_initialize(&rstate, qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, key, sizeof(key), iv, sizeof(iv));

    if ((wstate.initialized == true) && (rstate.initialized == true))
    {
        if (qsc_tls_record_encrypt(&wstate, record1, sizeof(record1), &written1, qsc_tls_record_content_application_data, payload1, sizeof(payload1)) == qsc_tls_status_success)
        {
            if (qsc_tls_record_encrypt(&wstate, record2, sizeof(record2), &written2, qsc_tls_record_content_application_data, payload2, sizeof(payload2)) == qsc_tls_status_success)
            {
                qsc_memutils_copy(coalesced, record1, written1);
                qsc_memutils_copy(coalesced + written1, record2, written2);

                if (qsc_tls_record_try_get_span_length(coalesced, sizeof(coalesced), &recordlen, &complete) == qsc_tls_status_success)
                {
                    if ((recordlen == written1) && (complete == true))
                    {
                        if (qsc_tls_record_decrypt(&rstate, output, sizeof(output), &outlen, &inner, coalesced, recordlen) == qsc_tls_status_success)
                        {
                            if ((inner == qsc_tls_record_content_application_data) && (outlen == sizeof(payload1)) &&
                                (qsc_memutils_are_equal(output, payload1, sizeof(payload1)) == true))
                            {
                                offset = recordlen;
                                recordlen = 0U;
                                outlen = 0U;
                                inner = qsc_tls_record_content_invalid;
                                qsc_memutils_clear(output, sizeof(output));

                                if (qsc_tls_record_try_get_span_length(coalesced + offset, sizeof(coalesced) - offset, &recordlen, &complete) == qsc_tls_status_success)
                                {
                                    if ((recordlen == written2) && (complete == true))
                                    {
                                        if (qsc_tls_record_decrypt(&rstate, output, sizeof(output), &outlen, &inner, coalesced + offset, recordlen) == qsc_tls_status_success)
                                        {
                                            if ((inner == qsc_tls_record_content_application_data) && (outlen == sizeof(payload2)) &&
                                                (qsc_memutils_are_equal(output, payload2, sizeof(payload2)) == true) &&
                                                (qsc_tls_record_state_get_sequence(&wstate) == 2U) &&
                                                (qsc_tls_record_state_get_sequence(&rstate) == 2U))
                                            {
                                                res = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    qsc_tls_record_state_dispose(&wstate);
    qsc_tls_record_state_dispose(&rstate);

    return res;
}

/**
 * \brief Verify all record-size boundaries, authentication failure behavior, and sequence handling.
 * \param suite The supported TLS 1.3 AEAD suite under test.
 * \param keylen Key size required by the selected suite, in bytes.
 * \return True when every record size and negative test passes.
 * \note This test runs synchronously and owns all buffers and record states.
 */
static bool stage26_protected_size_matrix(qsc_tls_cipher_suite suite, size_t keylen)
{
	const size_t sizes[] = { 0U, 1U, 15U, 16U, 17U, 63U, 64U, 65U, 255U, 256U, 1024U, 4096U, 16383U, 16384U };
	qsc_tls_record_state rstate;
	qsc_tls_record_state wstate;
	uint8_t decoded[QSC_TLS_MAX_PLAINTEXT_SIZE];
	uint8_t payload[QSC_TLS_MAX_PLAINTEXT_SIZE];
	uint8_t record[QSC_TLS_RECORD_MAX_WIRE_SIZE];
	uint8_t key[32U] = { 0U };
	uint8_t iv[12U] = { 0U };
	qsc_tls_record_content_type inner;
	qsc_tls_status status;
	size_t written;
	size_t received;
	size_t i;
	size_t j;
	bool res;

	res = true;
	written = 0U;
	received = 0U;
	inner = qsc_tls_record_content_invalid;
	qsc_memutils_clear(&rstate, sizeof(rstate));
	qsc_memutils_clear(&wstate, sizeof(wstate));

	for (i = 0U; i < sizeof(payload); ++i)
	{
		payload[i] = (uint8_t)(i ^ 0xA5U);
	}

	for (i = 0U; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
	{
		qsc_tls_record_state_initialize(&wstate, suite, key, keylen, iv, sizeof(iv));
		qsc_tls_record_state_initialize(&rstate, suite, key, keylen, iv, sizeof(iv));
		written = 0U;
		received = 0U;
		status = qsc_tls_record_encrypt(&wstate, record, sizeof(record), &written, qsc_tls_record_content_application_data, payload, sizes[i]);

		if (status == qsc_tls_status_success)
		{
			if (written != QSC_TLS_RECORD_HEADER_SIZE + sizes[i] + QSC_TLS_INNER_CONTENT_TYPE_SIZE + QSC_TLS_GCM_TAG_SIZE)
			{
				status = qsc_tls_status_invalid_length;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_record_decrypt(&rstate, decoded, sizeof(decoded), &received, &inner, record, written);
		}

		if (status != qsc_tls_status_success || received != sizes[i] ||
			inner != qsc_tls_record_content_application_data ||
			(sizes[i] != 0U && qsc_memutils_are_equal(decoded, payload, sizes[i]) == false) ||
			qsc_tls_record_state_get_sequence(&wstate) != 1U ||
			qsc_tls_record_state_get_sequence(&rstate) != 1U)
		{
			printf("[FAIL] TLS record size matrix suite=%u length=%zu status=%d received=%zu type=%u write_seq=%llu read_seq=%llu\n", (unsigned int)suite, sizes[i], (int)status, received, (unsigned int)inner, (unsigned long long)qsc_tls_record_state_get_sequence(&wstate), (unsigned long long)qsc_tls_record_state_get_sequence(&rstate));
			res = false;
		}

		if (res == true)
		{
			qsc_tls_record_state_install_keys(&rstate, suite, key, keylen, iv, sizeof(iv));
			record[written - 1U] ^= 0x01U;
			qsc_memutils_clear(decoded, sizeof(decoded));
			received = 17U;
			inner = qsc_tls_record_content_handshake;
			status = qsc_tls_record_decrypt(&rstate, decoded, sizeof(decoded), &received, &inner, record, written);

			if (status != qsc_tls_status_authentication_failure || received != 0U ||
				inner != qsc_tls_record_content_invalid ||
				qsc_tls_record_state_get_sequence(&rstate) != 0U)
			{
				printf("[FAIL] TLS tampered-tag rejection suite=%u length=%zu status=%d received=%zu\n", (unsigned int)suite, sizes[i], (int)status, received);
				res = false;
			}

			for (j = 0U; j < sizeof(decoded) && res == true; ++j)
			{
				if (decoded[j] != 0U)
				{
					printf("[FAIL] TLS unauthenticated plaintext escaped suite=%u length=%zu index=%zu\n", (unsigned int)suite, sizes[i], j);
					res = false;
				}
			}
		}

		qsc_tls_record_state_dispose(&rstate);
		qsc_tls_record_state_dispose(&wstate);

		if (res == false)
		{
			break;
		}
	}

	qsc_memutils_secure_erase(decoded, sizeof(decoded));
	qsc_memutils_secure_erase(payload, sizeof(payload));
	qsc_memutils_secure_erase(record, sizeof(record));
	qsc_memutils_secure_erase(key, sizeof(key));
	qsc_memutils_secure_erase(iv, sizeof(iv));
	return res;
}

/** \brief Run protected-record boundary tests for AES-128-GCM. \return True on success. */
static bool stage26_protected_aes128_boundaries_test(void)
{
	return stage26_protected_size_matrix(qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, 16U);
}

/** \brief Run protected-record boundary tests for AES-256-GCM. \return True on success. */
static bool stage26_protected_aes256_boundaries_test(void)
{
	return stage26_protected_size_matrix(qsc_tls_cipher_suite_tls_aes_256_gcm_sha384, 32U);
}

/** \brief Run protected-record boundary tests for ChaCha20-Poly1305. \return True on success. */
static bool stage26_protected_chacha_boundaries_test(void)
{
	return stage26_protected_size_matrix(qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256, 32U);
}

bool qsctest_tls_stage26_tests(void)
{
    bool res;

    res = true;

	if (stage26_protected_aes128_boundaries_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 26 AES-128-GCM record boundary, tag-rejection and plaintext-isolation tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 26 AES-128-GCM record boundary, tag-rejection and plaintext-isolation tests.");
		res = false;
	}

	if (stage26_protected_aes256_boundaries_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 26 AES-256-GCM record boundary, tag-rejection and plaintext-isolation tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 26 AES-256-GCM record boundary, tag-rejection and plaintext-isolation tests.");
		res = false;
	}

	if (stage26_protected_chacha_boundaries_test() == true)
	{
		qsctest_print_line("[PASS] TLS Stage 26 ChaCha20-Poly1305 record boundary, tag-rejection and plaintext-isolation tests.");
	}
	else
	{
		qsctest_print_line("[FAIL] TLS Stage 26 ChaCha20-Poly1305 record boundary, tag-rejection and plaintext-isolation tests.");
		res = false;
	}

    if (stage26_plaintext_fragment_span_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 26 plaintext record fragmentation span test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 26 plaintext record fragmentation span test.");
        res = false;
    }

    if (stage26_plaintext_coalesced_records_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 26 plaintext record coalescing test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 26 plaintext record coalescing test.");
        res = false;
    }

    if (stage26_plaintext_boundary_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 26 plaintext record boundary test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 26 plaintext record boundary test.");
        res = false;
    }

    if (stage26_malformed_record_length_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 26 malformed record length rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 26 malformed record length rejection test.");
        res = false;
    }

    if (stage26_protected_record_fragmentation_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 26 protected record fragmentation test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 26 protected record fragmentation test.");
        res = false;
    }

    if (stage26_protected_coalesced_records_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 26 protected record coalescing test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 26 protected record coalescing test.");
        res = false;
    }

    return res;
}
