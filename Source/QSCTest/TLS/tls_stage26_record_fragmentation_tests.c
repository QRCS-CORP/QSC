#include "tls_stage26_record_fragmentation_tests.h"
#include "../testutils.h"
#include "intutils.h"
#include "memutils.h"
#include "tlsdefs.h"
#include "tlslimits.h"
#include "tlsrecord.h"

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
    uint8_t payload2[7U] = { 0xA0U, 0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U, 0xA6U };
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

    if (qsc_tls_record_try_get_span_length(header, sizeof(header), &recordlen, &complete) == qsc_tls_status_invalid_length)
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

bool qsctest_tls_stage26_tests(void)
{
    bool res;

    res = true;

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
