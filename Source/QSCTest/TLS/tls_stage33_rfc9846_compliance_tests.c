#include "tls_stage33_rfc9846_compliance_tests.h"
#include "../testutils.h"
#include "aes.h"
#include "memutils.h"
#include "tlsalert.h"
#include "tlsdefs.h"
#include "tlserrors.h"
#include "tlsgroups.h"
#include "tlslimits.h"
#include "tlsrecord.h"
#include <string.h>

static size_t stage33_build_gcm_record(uint8_t* record, size_t recordcap, const uint8_t* key, const uint8_t* iv, const uint8_t* content, 
    size_t contentlen, qsc_tls_record_content_type innertype, size_t paddinglen)
{
    qsc_aes_keyparams kp;
    qsc_aes_gcm128_state gcm;
    uint8_t nonce[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
    uint8_t* inner;
    size_t innerlen;
    size_t payloadlen;
    size_t res;

    inner = NULL;
    innerlen = contentlen + QSC_TLS_INNER_CONTENT_TYPE_SIZE + paddinglen;
    payloadlen = innerlen + QSC_TLS_GCM_TAG_SIZE;
    res = 0U;
    qsc_memutils_clear(&kp, sizeof(kp));
    qsc_memutils_clear(&gcm, sizeof(gcm));

    if (record != NULL && key != NULL && iv != NULL && content != NULL && payloadlen <= QSC_TLS_RECORD_MAX_CIPHERTEXT_SIZE && recordcap >= QSC_TLS_RECORD_HEADER_SIZE + payloadlen)
    {
        inner = (uint8_t*)qsc_memutils_malloc(innerlen);

        if (inner != NULL)
        {
            qsc_memutils_clear(inner, innerlen);
            qsc_memutils_copy(inner, content, contentlen);
            inner[contentlen] = (uint8_t)innertype;
            qsc_memutils_copy(nonce, iv, sizeof(nonce));
            record[0U] = (uint8_t)qsc_tls_record_content_application_data;
            record[1U] = 0x03U;
            record[2U] = 0x03U;
            record[3U] = (uint8_t)(payloadlen >> 8U);
            record[4U] = (uint8_t)payloadlen;
            kp.key = key;
            kp.keylen = QSC_TLS_AES128_KEY_SIZE;
            kp.nonce = nonce;
            kp.noncelen = sizeof(nonce);
            qsc_aes_gcm128_initialize(&gcm, &kp, true);
            qsc_aes_gcm128_set_associated(&gcm, record, QSC_TLS_RECORD_HEADER_SIZE);
            qsc_aes_gcm128_encrypt(&gcm, record + QSC_TLS_RECORD_HEADER_SIZE, inner, innerlen);
            qsc_aes_gcm128_dispose(&gcm);
            res = QSC_TLS_RECORD_HEADER_SIZE + payloadlen;
            qsc_memutils_alloc_free(inner);
        }
    }

    return res;
}

static bool stage33_record_wire_limits_test(void)
{
    uint8_t* record;
    size_t recordlen;
    qsc_tls_status status;
    bool complete;
    bool res;

    record = (uint8_t*)qsc_memutils_malloc(QSC_TLS_RECORD_MAX_WIRE_SIZE + 8U);
    recordlen = 0U;
    complete = false;
    res = (record != NULL);

    if (res == true)
    {
        qsc_memutils_clear(record, QSC_TLS_RECORD_MAX_WIRE_SIZE + 8U);
        record[0U] = (uint8_t)qsc_tls_record_content_application_data;
        record[1U] = 0x03U;
        record[2U] = 0x03U;
        record[3U] = (uint8_t)(QSC_TLS_RECORD_MAX_CIPHERTEXT_SIZE >> 8U);
        record[4U] = (uint8_t)QSC_TLS_RECORD_MAX_CIPHERTEXT_SIZE;
        status = qsc_tls_record_try_get_span_length(record, QSC_TLS_RECORD_HEADER_SIZE, &recordlen, &complete);
        res = (status == qsc_tls_status_success && complete == false && recordlen == QSC_TLS_RECORD_MAX_WIRE_SIZE);
    }

    if (res == true)
    {
        record[3U] = (uint8_t)((QSC_TLS_RECORD_MAX_CIPHERTEXT_SIZE + 1U) >> 8U);
        record[4U] = (uint8_t)(QSC_TLS_RECORD_MAX_CIPHERTEXT_SIZE + 1U);
        status = qsc_tls_record_try_get_span_length(record, QSC_TLS_RECORD_HEADER_SIZE, &recordlen, &complete);
        res = (status == qsc_tls_status_record_overflow);
    }

    if (record != NULL)
    {
        qsc_memutils_alloc_free(record);
    }

    return res;
}

static bool stage33_plaintext_constraints_test(void)
{
    uint8_t alert[QSC_TLS_ALERT_SIZE] = { (uint8_t)qsc_tls_alert_level_warning, (uint8_t)qsc_tls_alert_close_notify };
    uint8_t badccs[1U] = { 0x02U };
    uint8_t ccs[1U] = { 0x01U };
    uint8_t small[64U] = { 0U };
    uint8_t* plain;
    uint8_t* record;
    const uint8_t* payload;
    size_t payloadlen;
    size_t written;
    qsc_tls_record_content_type type;
    qsc_tls_status status;
    bool res;

    plain = (uint8_t*)qsc_memutils_malloc(QSC_TLS_MAX_PLAINTEXT_SIZE + 1U);
    record = (uint8_t*)qsc_memutils_malloc(QSC_TLS_RECORD_MAX_WIRE_SIZE + 8U);
    payload = NULL;
    payloadlen = 0U;
    written = 0U;
    type = qsc_tls_record_content_invalid;
    res = (plain != NULL && record != NULL);

    if (res == true)
    {
        qsc_memutils_set_value(plain, QSC_TLS_MAX_PLAINTEXT_SIZE + 1U, 0xA5U);
        status = qsc_tls_record_encode_plaintext(record, QSC_TLS_RECORD_MAX_WIRE_SIZE, &written, qsc_tls_record_content_handshake, plain, QSC_TLS_MAX_PLAINTEXT_SIZE);
        res = (status == qsc_tls_status_success && written == QSC_TLS_RECORD_HEADER_SIZE + QSC_TLS_MAX_PLAINTEXT_SIZE);
    }

    if (res == true)
    {
        record[0U] = (uint8_t)qsc_tls_record_content_handshake;
        record[1U] = 0x03U;
        record[2U] = 0x03U;
        record[3U] = (uint8_t)((QSC_TLS_MAX_PLAINTEXT_SIZE + 1U) >> 8U);
        record[4U] = (uint8_t)(QSC_TLS_MAX_PLAINTEXT_SIZE + 1U);
        qsc_memutils_set_value(record + QSC_TLS_RECORD_HEADER_SIZE, QSC_TLS_MAX_PLAINTEXT_SIZE + 1U, 0x11U);
        status = qsc_tls_record_decode_plaintext(record, QSC_TLS_RECORD_HEADER_SIZE + QSC_TLS_MAX_PLAINTEXT_SIZE + 1U, &type, &payload, &payloadlen);
        res = (status == qsc_tls_status_record_overflow);
    }

    if (res == true)
    {
        status = qsc_tls_record_encode_plaintext(small, sizeof(small), &written, qsc_tls_record_content_handshake, NULL, 0U);
        res = (status == qsc_tls_status_invalid_length);
    }

    if (res == true)
    {
        status = qsc_tls_record_encode_plaintext(small, sizeof(small), &written, qsc_tls_record_content_alert, alert, 1U);
        res = (status == qsc_tls_status_invalid_length);
    }

    if (res == true)
    {
        status = qsc_tls_record_encode_plaintext(small, sizeof(small), &written, qsc_tls_record_content_alert, alert, sizeof(alert));
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        status = qsc_tls_record_encode_plaintext(small, sizeof(small), &written, qsc_tls_record_content_change_cipher_spec, badccs, sizeof(badccs));
        res = (status == qsc_tls_status_invalid_message);
    }

    if (res == true)
    {
        status = qsc_tls_record_encode_plaintext(small, sizeof(small), &written, qsc_tls_record_content_change_cipher_spec, ccs, sizeof(ccs));
        res = (status == qsc_tls_status_success);
    }

    if (plain != NULL)
    {
        qsc_memutils_alloc_free(plain);
    }

    if (record != NULL)
    {
        qsc_memutils_alloc_free(record);
    }

    return res;
}

static bool stage33_inner_plaintext_limits_test(void)
{
    qsc_tls_record_state state;
    uint8_t iv[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
    uint8_t key[QSC_TLS_AES128_KEY_SIZE] = { 0U };
    uint8_t* output;
    uint8_t* plain;
    uint8_t* record;
    size_t i;
    size_t recordlen;
    size_t written;
    qsc_tls_record_content_type type;
    qsc_tls_status status;
    bool res;

    output = (uint8_t*)qsc_memutils_malloc(QSC_TLS_RECORD_MAX_INNER_SIZE);
    plain = (uint8_t*)qsc_memutils_malloc(QSC_TLS_MAX_PLAINTEXT_SIZE + 1U);
    record = (uint8_t*)qsc_memutils_malloc(QSC_TLS_RECORD_MAX_WIRE_SIZE + 8U);
    recordlen = 0U;
    written = 0U;
    type = qsc_tls_record_content_invalid;
    qsc_memutils_clear(&state, sizeof(state));
    res = (output != NULL && plain != NULL && record != NULL);

    if (res == true)
    {
        for (i = 0U; i < sizeof(key); ++i)
        {
            key[i] = (uint8_t)(0x10U + i);
        }

        for (i = 0U; i < sizeof(iv); ++i)
        {
            iv[i] = (uint8_t)(0x80U + i);
        }

        for (i = 0U; i < 32U; ++i)
        {
            plain[i] = (uint8_t)i;
        }

        recordlen = stage33_build_gcm_record(record, QSC_TLS_RECORD_MAX_WIRE_SIZE, key, iv, plain, 32U, qsc_tls_record_content_application_data, 220U);
        qsc_tls_record_state_initialize(&state, qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, key, sizeof(key), iv, sizeof(iv));
        status = qsc_tls_record_decrypt(&state, output, QSC_TLS_RECORD_MAX_INNER_SIZE, &written, &type, record, recordlen);
        res = (status == qsc_tls_status_success && written == 32U && type == qsc_tls_record_content_application_data && qsc_memutils_are_equal(output, plain, 32U) == true);
        qsc_tls_record_state_dispose(&state);
    }

    if (res == true)
    {
        qsc_memutils_set_value(plain, QSC_TLS_MAX_PLAINTEXT_SIZE + 1U, 0x5AU);
        recordlen = stage33_build_gcm_record(record, QSC_TLS_RECORD_MAX_WIRE_SIZE, key, iv, plain, QSC_TLS_MAX_PLAINTEXT_SIZE + 1U, qsc_tls_record_content_application_data, 0U);
        qsc_tls_record_state_initialize(&state, qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, key, sizeof(key), iv, sizeof(iv));
        status = qsc_tls_record_decrypt(&state, output, QSC_TLS_RECORD_MAX_INNER_SIZE, &written, &type, record, recordlen);
        res = (status == qsc_tls_status_record_overflow);
        qsc_tls_record_state_dispose(&state);
    }

    if (output != NULL)
    {
        qsc_memutils_alloc_free(output);
    }

    if (plain != NULL)
    {
        qsc_memutils_alloc_free(plain);
    }

    if (record != NULL)
    {
        qsc_memutils_alloc_free(record);
    }

    return res;
}

static bool stage33_error_mapping_test(void)
{
    bool res;

    res = (qsc_tls_alert_from_status(qsc_tls_status_record_overflow) == qsc_tls_alert_record_overflow);
    res = (res == true && strcmp(qsc_tls_error_to_string(qsc_tls_status_record_overflow), "Unknown TLS status code.") != 0);
    res = (res == true && strcmp(qsc_tls_alert_to_string(qsc_tls_alert_user_canceled), "user_canceled") == 0);
    res = (res == true && strcmp(qsc_tls_alert_to_string(qsc_tls_alert_bad_certificate_status_response), "bad_certificate_status_response") == 0);
    res = (res == true && strcmp(qsc_tls_alert_to_string(qsc_tls_alert_insufficient_security), "insufficient_security") == 0);

    return res;
}

static bool stage33_ephemeral_keyshare_test(void)
{
    qsc_tls_key_exchange_state first;
    qsc_tls_key_exchange_state second;
    qsc_tls_status status;
    bool firstinitialized;
    bool res;
    bool secondinitialized;

    firstinitialized = false;
    qsc_memutils_clear(&first, sizeof(first));
    qsc_memutils_clear(&second, sizeof(second));
    res = false;
    secondinitialized = false;
    status = qsc_tls_groups_generate_client_keypair(&first, qsc_tls_group_x25519);

    if (status == qsc_tls_status_success)
    {
        firstinitialized = true;
        status = qsc_tls_groups_generate_client_keypair(&second, qsc_tls_group_x25519);
    }

    if (status == qsc_tls_status_success)
    {
        secondinitialized = true;
        res = (first.publicsharelen != 0U && first.publicsharelen == second.publicsharelen &&
            qsc_memutils_are_equal(first.publicshare, second.publicshare, first.publicsharelen) == false);
    }

    if (firstinitialized == true)
    {
        qsc_tls_groups_key_exchange_state_dispose(&first);
    }

    if (secondinitialized == true)
    {
        qsc_tls_groups_key_exchange_state_dispose(&second);
    }

    return res;
}

bool qsctest_tls_stage33_tests(void)
{
    bool res;

    res = true;

    if (stage33_record_wire_limits_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 33 RFC 9846 record wire-limit test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 33 RFC 9846 record wire-limit test.");
        res = false;
    }

    if (stage33_plaintext_constraints_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 33 RFC 9846 plaintext record-constraint test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 33 RFC 9846 plaintext record-constraint test.");
        res = false;
    }

    if (stage33_inner_plaintext_limits_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 33 RFC 9846 TLSInnerPlaintext limit test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 33 RFC 9846 TLSInnerPlaintext limit test.");
        res = false;
    }

    if (stage33_error_mapping_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 33 RFC 9846 record-overflow and alert mapping test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 33 RFC 9846 record-overflow and alert mapping test.");
        res = false;
    }

    if (stage33_ephemeral_keyshare_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 33 fresh ephemeral KeyShare test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 33 fresh ephemeral KeyShare test.");
        res = false;
    }

    return res;
}
