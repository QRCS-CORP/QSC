#include "tls_stage23_peer_info_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "tlssocket.h"

static bool stage23_string_equals(const char* text, const char* expected)
{
    size_t explen;
    bool res;

    res = false;

    if ((text != NULL) && (expected != NULL))
    {
        explen = qsc_stringutils_string_size(expected);

        if (qsc_stringutils_string_size(text) == explen)
        {
            res = qsc_memutils_are_equal((const uint8_t*)text, (const uint8_t*)expected, explen);
        }
    }

    return res;
}

static void stage23_copy_text(char* output, size_t outputlen, const char* input)
{
    if ((output != NULL) && (outputlen != 0U))
    {
        output[0U] = '\0';

        if (input != NULL)
        {
            (void)qsc_stringutils_copy_string(output, outputlen, input);
        }
    }
}

static void stage23_make_result(qsc_tls_socket_result* result, qsc_tls_socket_status status, qsc_tls_status tlsstatus, qsc_x509w_status x509status, 
    qsc_x509_verify_status verifystatus, qsc_tls_alert_description alert)
{
    if (result != NULL)
    {
        result->status = status;
        result->tlsstatus = tlsstatus;
        result->socketstatus = (qsc_socket_exceptions)QSC_SOCKET_RET_SUCCESS;
        result->x509status = x509status;
        result->verifystatus = verifystatus;
        result->alert = alert;
    }
}

static bool stage23_negotiated_accessors_initial_state_test(void)
{
    qsc_tls_socket_connection* connection;
    qsc_tls_socket_peer_info peer;
    bool res;

    res = false;
    connection = (qsc_tls_socket_connection*)qsc_memutils_malloc(sizeof(qsc_tls_socket_connection));

    if (connection == NULL)
    {
        return false;
    }

    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));

    if ((qsc_tls_socket_negotiated_cipher_suite(connection) == qsc_tls_cipher_suite_none) &&
        (qsc_tls_socket_negotiated_group(connection) == qsc_tls_group_none) &&
        (qsc_tls_socket_negotiated_signature_scheme(connection) == qsc_tls_sig_none))
    {
        if (qsc_tls_socket_get_peer_info(connection, &peer) == qsc_tls_socket_status_success)
        {
            if ((peer.authenticated == false) && (peer.chain_valid == false) && (peer.hostname_checked == false) &&
                (peer.hostname_matched == false) && (peer.psk_accepted == false) && (peer.early_data_accepted == false) &&
                (peer.alpn_selected == false) && (peer.verify_status == QSC_X509_VERIFY_STATUS_SUCCESS) &&
                (peer.x509_status == QSC_X509W_STATUS_SUCCESS))
            {
                res = true;
            }
        }
    }


    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    qsc_memutils_alloc_free(connection);

    return res;
}

static bool stage23_client_negotiated_parameter_test(void)
{
    qsc_tls_socket_connection* connection;
    bool res;

    res = false;
    connection = (qsc_tls_socket_connection*)qsc_memutils_malloc(sizeof(qsc_tls_socket_connection));

    if (connection == NULL)
    {
        return false;
    }

    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    connection->role = qsc_tls_role_client;
    connection->handshaked = true;
    connection->engine.state.client.negotiatedsuite = qsc_tls_cipher_suite_tls_aes_256_gcm_sha384;
    connection->engine.state.client.negotiatedgroup = qsc_tls_group_x25519_mlkem768;
    connection->engine.state.client.negotiatedsigscheme = qsc_tls_sig_ecdsa_secp256r1_sha256;

    if ((qsc_tls_socket_negotiated_cipher_suite(connection) == qsc_tls_cipher_suite_tls_aes_256_gcm_sha384) &&
        (qsc_tls_socket_negotiated_group(connection) == qsc_tls_group_x25519_mlkem768) &&
        (qsc_tls_socket_negotiated_signature_scheme(connection) == qsc_tls_sig_ecdsa_secp256r1_sha256))
    {
        res = true;
    }


    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    qsc_memutils_alloc_free(connection);

    return res;
}

static bool stage23_server_negotiated_parameter_test(void)
{
    qsc_tls_socket_connection* connection;
    bool res;

    res = false;
    connection = (qsc_tls_socket_connection*)qsc_memutils_malloc(sizeof(qsc_tls_socket_connection));

    if (connection == NULL)
    {
        return false;
    }

    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    connection->role = qsc_tls_role_server;
    connection->handshaked = true;
    connection->engine.state.server.negotiatedsuite = qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256;
    connection->engine.state.server.negotiatedgroup = qsc_tls_group_secp256r1_mlkem768;
    connection->engine.state.server.negotiatedsigscheme = qsc_tls_sig_mldsa65;

    if ((qsc_tls_socket_negotiated_cipher_suite(connection) == qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256) &&
        (qsc_tls_socket_negotiated_group(connection) == qsc_tls_group_secp256r1_mlkem768) &&
        (qsc_tls_socket_negotiated_signature_scheme(connection) == qsc_tls_sig_mldsa65))
    {
        res = true;
    }


    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    qsc_memutils_alloc_free(connection);

    return res;
}

static bool stage23_peer_info_copy_test(void)
{
    qsc_tls_socket_connection* connection;
    qsc_tls_socket_peer_info peer;
    bool res;

    res = false;
    connection = (qsc_tls_socket_connection*)qsc_memutils_malloc(sizeof(qsc_tls_socket_connection));

    if (connection == NULL)
    {
        return false;
    }

    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    connection->peerinfo.authenticated = true;
    connection->peerinfo.chain_valid = true;
    connection->peerinfo.hostname_checked = true;
    connection->peerinfo.hostname_matched = true;
    connection->peerinfo.psk_accepted = false;
    connection->peerinfo.early_data_accepted = false;
    connection->peerinfo.alpn_selected = true;
    connection->peerinfo.cipher_suite = qsc_tls_cipher_suite_tls_aes_128_gcm_sha256;
    connection->peerinfo.named_group = qsc_tls_group_secp384r1_mlkem1024;
    connection->peerinfo.signature_scheme = qsc_tls_sig_ecdsa_secp384r1_sha384;
    connection->peerinfo.x509_status = QSC_X509W_STATUS_SUCCESS;
    connection->peerinfo.verify_status = QSC_X509_VERIFY_STATUS_SUCCESS;
    stage23_make_result(&connection->peerinfo.result, qsc_tls_socket_status_success, qsc_tls_status_success,
        QSC_X509W_STATUS_SUCCESS, QSC_X509_VERIFY_STATUS_SUCCESS, qsc_tls_alert_close_notify);
    stage23_copy_text(connection->peerinfo.subject, sizeof(connection->peerinfo.subject), "CN=alpha.example.test");
    stage23_copy_text(connection->peerinfo.issuer, sizeof(connection->peerinfo.issuer), "CN=QSC Test Root");
    stage23_copy_text(connection->peerinfo.common_name, sizeof(connection->peerinfo.common_name), "alpha.example.test");
    stage23_copy_text(connection->peerinfo.dns_name, sizeof(connection->peerinfo.dns_name), "alpha.example.test");
    stage23_copy_text(connection->peerinfo.selected_alpn, sizeof(connection->peerinfo.selected_alpn), "http/1.1");

    if (qsc_tls_socket_get_peer_info(connection, &peer) == qsc_tls_socket_status_success)
    {
        if ((peer.authenticated == true) && (peer.chain_valid == true) && (peer.hostname_checked == true) &&
            (peer.hostname_matched == true) && (peer.alpn_selected == true) &&
            (peer.cipher_suite == qsc_tls_cipher_suite_tls_aes_128_gcm_sha256) &&
            (peer.named_group == qsc_tls_group_secp384r1_mlkem1024) &&
            (peer.signature_scheme == qsc_tls_sig_ecdsa_secp384r1_sha384) &&
            (peer.result.status == qsc_tls_socket_status_success) && (peer.result.tlsstatus == qsc_tls_status_success) &&
            (peer.x509_status == QSC_X509W_STATUS_SUCCESS) && (peer.verify_status == QSC_X509_VERIFY_STATUS_SUCCESS) &&
            (stage23_string_equals(peer.subject, "CN=alpha.example.test") == true) &&
            (stage23_string_equals(peer.issuer, "CN=QSC Test Root") == true) &&
            (stage23_string_equals(peer.common_name, "alpha.example.test") == true) &&
            (stage23_string_equals(peer.dns_name, "alpha.example.test") == true) &&
            (stage23_string_equals(peer.selected_alpn, "http/1.1") == true))
        {
            res = true;
        }
    }


    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    qsc_memutils_alloc_free(connection);

    return res;
}

static bool stage23_verification_failure_result_test(void)
{
    qsc_tls_socket_connection* connection;
    qsc_tls_socket_peer_info peer;
    bool res;

    res = false;
    connection = (qsc_tls_socket_connection*)qsc_memutils_malloc(sizeof(qsc_tls_socket_connection));

    if (connection == NULL)
    {
        return false;
    }

    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    connection->peerinfo.authenticated = false;
    connection->peerinfo.chain_valid = false;
    connection->peerinfo.hostname_checked = true;
    connection->peerinfo.hostname_matched = false;
    connection->peerinfo.x509_status = QSC_X509W_STATUS_HOSTNAME_MISMATCH;
    connection->peerinfo.verify_status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
    stage23_make_result(&connection->peerinfo.result, qsc_tls_socket_status_certificate_verify_failed,
        qsc_tls_status_authentication_failure, QSC_X509W_STATUS_HOSTNAME_MISMATCH,
        QSC_X509_VERIFY_STATUS_NAME_MISMATCH, qsc_tls_alert_bad_certificate);
    stage23_copy_text(connection->peerinfo.subject, sizeof(connection->peerinfo.subject), "CN=wrong.example.test");
    stage23_copy_text(connection->peerinfo.dns_name, sizeof(connection->peerinfo.dns_name), "wrong.example.test");

    if (qsc_tls_socket_get_peer_info(connection, &peer) == qsc_tls_socket_status_success)
    {
        if ((peer.authenticated == false) && (peer.chain_valid == false) && (peer.hostname_checked == true) &&
            (peer.hostname_matched == false) && (peer.x509_status == QSC_X509W_STATUS_HOSTNAME_MISMATCH) &&
            (peer.verify_status == QSC_X509_VERIFY_STATUS_NAME_MISMATCH) &&
            (peer.result.status == qsc_tls_socket_status_certificate_verify_failed) &&
            (peer.result.tlsstatus == qsc_tls_status_authentication_failure) &&
            (peer.result.x509status == QSC_X509W_STATUS_HOSTNAME_MISMATCH) &&
            (peer.result.verifystatus == QSC_X509_VERIFY_STATUS_NAME_MISMATCH) &&
            (peer.result.alert == qsc_tls_alert_bad_certificate) &&
            (stage23_string_equals(peer.subject, "CN=wrong.example.test") == true) &&
            (stage23_string_equals(peer.dns_name, "wrong.example.test") == true))
        {
            res = true;
        }
    }


    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    qsc_memutils_alloc_free(connection);

    return res;
}

static bool stage23_selected_alpn_inspection_test(void)
{
    qsc_tls_socket_connection* connection;
    char protocol[QSC_TLS_SOCKET_ALPN_SIZE_MAX + 1U];
    size_t protocollen;
    bool res;

    res = false;
    protocollen = 0U;
    connection = (qsc_tls_socket_connection*)qsc_memutils_malloc(sizeof(qsc_tls_socket_connection));

    if (connection == NULL)
    {
        return false;
    }

    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));

    if (qsc_tls_socket_get_selected_alpn(connection, protocol, sizeof(protocol), &protocollen) == qsc_tls_socket_status_not_initialized)
    {
        connection->peerinfo.alpn_selected = true;
        stage23_copy_text(connection->peerinfo.selected_alpn, sizeof(connection->peerinfo.selected_alpn), "qsc-test/1");

        if (qsc_tls_socket_get_selected_alpn(connection, protocol, sizeof(protocol), &protocollen) == qsc_tls_socket_status_success)
        {
            if ((protocollen == qsc_stringutils_string_size("qsc-test/1")) &&
                (stage23_string_equals(protocol, "qsc-test/1") == true))
            {
                if (qsc_tls_socket_get_selected_alpn(connection, protocol, 2U, &protocollen) == qsc_tls_socket_status_invalid_input)
                {
                    res = true;
                }
            }
        }
    }


    qsc_memutils_clear(connection, sizeof(qsc_tls_socket_connection));
    qsc_memutils_alloc_free(connection);

    return res;
}

bool qsctest_tls_stage23_tests(void)
{
    bool res;

    res = true;

    if (stage23_negotiated_accessors_initial_state_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 23 negotiated accessors initial-state test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 23 negotiated accessors initial-state test.");
        res = false;
    }

    if (stage23_client_negotiated_parameter_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 23 client negotiated-parameter inspection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 23 client negotiated-parameter inspection test.");
        res = false;
    }

    if (stage23_server_negotiated_parameter_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 23 server negotiated-parameter inspection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 23 server negotiated-parameter inspection test.");
        res = false;
    }

    if (stage23_peer_info_copy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 23 peer-info copy inspection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 23 peer-info copy inspection test.");
        res = false;
    }

    if (stage23_verification_failure_result_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 23 verification failure-result inspection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 23 verification failure-result inspection test.");
        res = false;
    }

    if (stage23_selected_alpn_inspection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 23 selected ALPN inspection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 23 selected ALPN inspection test.");
        res = false;
    }

    return res;
}
