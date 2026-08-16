#include "tls_stage31_mtls_handshake_tests.h"
#include "../testutils.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlsrecord.h"
#include "tlshandshake.h"
#include "tlscert.h"
#include "tlsextensions.h"
#include "memutils.h"
#include <stdio.h>
#include <string.h>

typedef struct test_verify_state
{
    uint8_t expected;
    bool accept_chain;
    bool accept_signature;
    size_t authorization_calls;
    bool authorize;
} test_verify_state;

typedef struct test_sign_state
{
    uint8_t value;
} test_sign_state;

static bool test_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* context, void* state)
{
    test_verify_state* st;

    (void)context;
    st = (test_verify_state*)state;

    return (st != NULL && st->accept_chain == true && chain != NULL && chainlength != 0U && chain[0U].data != NULL && chain[0U].datalen != 0U);
}

static bool test_verify_signature(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, 
    size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    test_verify_state* st;
    size_t i;
    bool res;

    st = (test_verify_state*)state;
    res = (st != NULL && st->accept_signature == true && scheme == qsc_tls_sig_ecdsa_secp256r1_sha256 &&
        input != NULL && inputlen != 0U && signature != NULL && signaturelen == 64U && signer != NULL && signer->datalen != 0U);

    for (i = 0U; i < signaturelen && res == true; ++i)
    {
        if (signature[i] != st->expected)
        {
            res = false;
        }
    }

    return res;
}

static bool test_sign(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, void* state)
{
    test_sign_state* st;
    bool res;

    st = (test_sign_state*)state;
    res = false;

    if (scheme == qsc_tls_sig_ecdsa_secp256r1_sha256 && input != NULL && inputlen != 0U && signature != NULL &&
        signaturelen != NULL && *signaturelen >= 64U && st != NULL)
    {
        memset(signature, st->value, 64U);
        *signaturelen = 64U;
        res = true;
    }

    return res;
}

static bool test_authorize(const qsc_tls_client_authorization_info* info, void* state)
{
    test_verify_state* st;

    st = (test_verify_state*)state;

    if (st != NULL)
    {
        ++st->authorization_calls;
    }

    return (st != NULL && st->authorize == true && info != NULL && info->chainvalid == true);
}

static void configure_local_certificate(qsc_tls_local_certificate_config* localcert, const uint8_t* cert, size_t certlen, test_sign_state* signstate)
{
    memset(localcert, 0, sizeof(*localcert));
    localcert->chain[0U].data = cert;
    localcert->chain[0U].datalen = certlen;
    localcert->chainlength = 1U;
    localcert->verifyscheme = qsc_tls_sig_ecdsa_secp256r1_sha256;
    localcert->signcallback = test_sign;
    localcert->signstate = signstate;
    localcert->configured = true;
}

static bool feed_client(qsc_tls_client_state* client, const uint8_t* input, size_t inputlen, uint8_t* output, size_t outcap, size_t* outlen)
{
    size_t consumed;
    size_t off;
    size_t written;
    qsc_tls_status status;

    off = 0U;
    *outlen = 0U;
    status = qsc_tls_status_success;

    while (off < inputlen && status == qsc_tls_status_success)
    {
        consumed = 0U;
        written = 0U;
        status = qsc_tls_client_process_record(client, input + off, inputlen - off, &consumed,
            output + *outlen, outcap - *outlen, &written);

        if (status == qsc_tls_status_success && consumed == 0U)
        {
            status = qsc_tls_status_failure;
        }

        off += consumed;
        *outlen += written;
    }

    return (status == qsc_tls_status_success && off == inputlen);
}

static qsc_tls_status feed_server(qsc_tls_server_state* server, const uint8_t* input, size_t inputlen)
{
    uint8_t output[4096U] = { 0U };
    size_t consumed;
    size_t off;
    size_t written;
    qsc_tls_status status;

    off = 0U;
    status = qsc_tls_status_success;

    while (off < inputlen && status == qsc_tls_status_success)
    {
        consumed = 0U;
        written = 0U;
        status = qsc_tls_server_process_record(server, input + off, inputlen - off, &consumed, output, sizeof(output), &written);
        off += consumed;

        if (status == qsc_tls_status_success && consumed == 0U)
        {
            status = qsc_tls_status_failure;
        }
    }

    return status;
}

static bool run_handshake(bool requestauth, bool requireauth, bool clientcert, uint8_t clientsig, bool requireauthorization, bool authorize, 
    qsc_tls_alert_description* serveralert, bool* serverauthenticated, bool* clientsentcert, size_t* authorizationcalls)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    static const qsc_tls_named_group groups[] = { qsc_tls_group_x25519 };
    static const qsc_tls_signature_scheme schemes[] = { qsc_tls_sig_ecdsa_secp256r1_sha256 };
    static const uint8_t servercert[] = { 0x30U, 0x03U, 0x02U, 0x01U, 0x01U };
    static const uint8_t clientcertbytes[] = { 0x30U, 0x03U, 0x02U, 0x01U, 0x02U };
    uint8_t* clientflight;
    uint8_t clienthello[32768U] = { 0U };
    uint8_t* serverflight;
    qsc_tls_certificate_interface clientiface;
    qsc_tls_certificate_interface serveriface;
    qsc_tls_client_config clientconfig = { 0 };
    qsc_tls_server_config serverconfig;
    qsc_tls_client_state* client;
    qsc_tls_server_state* server;
    test_verify_state clientverify = { 0 };
    test_verify_state serververify = { 0 };
    test_sign_state clientsigner;
    test_sign_state serversigner;
    size_t clientflightlen;
    size_t clienthellolen;
    size_t consumed;
    size_t serverflightlen;
    qsc_tls_status status;
    bool clientinitialized;
    bool result;
    bool serverinitialized;

    clientflight = (uint8_t*)qsc_memutils_malloc(131072U);
    serverflight = (uint8_t*)qsc_memutils_malloc(131072U);
    client = (qsc_tls_client_state*)qsc_memutils_malloc(sizeof(qsc_tls_client_state));
    server = (qsc_tls_server_state*)qsc_memutils_malloc(sizeof(qsc_tls_server_state));
    clientinitialized = false;
    result = (client != NULL && server != NULL && clientflight != NULL && serverflight != NULL);
    serverinitialized = false;
    memset(&serverconfig, 0, sizeof(serverconfig));

    if (result == true)
    {
        qsc_memutils_clear(client, sizeof(qsc_tls_client_state));
        qsc_memutils_clear(clientflight, 131072U);
        qsc_memutils_clear(serverflight, 131072U);
        qsc_memutils_clear(server, sizeof(qsc_tls_server_state));
        clientverify.expected = 0xA5U;
        clientverify.accept_chain = true;
        clientverify.accept_signature = true;
        clientverify.authorize = true;
        serververify.expected = 0xA5U;
        serververify.accept_chain = true;
        serververify.accept_signature = true;
        serververify.authorize = authorize;
        clientsigner.value = clientsig;
        serversigner.value = 0xA5U;
        qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &clientverify);
        qsc_tls_certificate_interface_initialize(&serveriface, test_validate_chain, test_verify_signature, &serververify);

        clientconfig.ciphersuites = suites;
        clientconfig.ciphersuitecount = 1U;
        clientconfig.groups = groups;
        clientconfig.groupcount = 1U;
        clientconfig.sigschemes = schemes;
        clientconfig.sigschemecount = 1U;
        clientconfig.certinterface = clientiface;

        if (clientcert == true)
        {
            configure_local_certificate(&clientconfig.localcert, clientcertbytes, sizeof(clientcertbytes), &clientsigner);
        }

        serverconfig.ciphersuitepreference = suites;
        serverconfig.ciphersuitepreferencecount = 1U;
        serverconfig.groupspreference = groups;
        serverconfig.groupspreferencecount = 1U;
        serverconfig.sigschemepreference = schemes;
        serverconfig.sigschemepreferencecount = 1U;
        configure_local_certificate(&serverconfig.localcert, servercert, sizeof(servercert), &serversigner);
        serverconfig.clientcertinterface = serveriface;
        serverconfig.requestclientauth = requestauth;
        serverconfig.requireclientauth = requireauth;
        serverconfig.requireclientauthorization = requireauthorization;
        serverconfig.clientauthcallback = requireauthorization ? test_authorize : NULL;
        serverconfig.clientauthstate = &serververify;

        status = qsc_tls_client_initialize(client, &clientconfig);
        result = (status == qsc_tls_status_success);
        clientinitialized = result;
    }

    if (result == true)
    {
        status = qsc_tls_server_initialize(server, &serverconfig);
        result = (status == qsc_tls_status_success);
        serverinitialized = result;
    }

    clienthellolen = 0U;

    if (result == true)
    {
        status = qsc_tls_client_send_hello(client, clienthello, sizeof(clienthello), &clienthellolen);
        result = (status == qsc_tls_status_success && clienthellolen != 0U);
    }

    consumed = 0U;
    serverflightlen = 0U;

    if (result == true)
    {
        status = qsc_tls_server_process_record(server, clienthello, clienthellolen, &consumed,
            serverflight, 131072U, &serverflightlen);
        result = (status == qsc_tls_status_success && consumed == clienthellolen && serverflightlen != 0U);
    }

    clientflightlen = 0U;

    if (result == true)
    {
        result = feed_client(client, serverflight, serverflightlen, clientflight, 131072U, &clientflightlen);
    }

    if (result == true)
    {
        status = feed_server(server, clientflight, clientflightlen);
        result = (status == qsc_tls_status_success);
    }

    if (serveralert != NULL)
    {
        *serveralert = (server != NULL) ? server->lastalert : qsc_tls_alert_internal_error;
    }

    if (serverauthenticated != NULL)
    {
        *serverauthenticated = (server != NULL) ? server->clientauthenticated : false;
    }

    if (clientsentcert != NULL)
    {
        *clientsentcert = (client != NULL) ? client->clientcertificatesent : false;
    }

    if (authorizationcalls != NULL)
    {
        *authorizationcalls = serververify.authorization_calls;
    }

    if (result == true)
    {
        result = (client->phase == qsc_tls_client_phase_established && server->phase == qsc_tls_server_phase_established);
    }

    if (clientinitialized == true)
    {
        qsc_tls_client_dispose(client);
    }

    if (serverinitialized == true)
    {
        qsc_tls_server_dispose(server);
    }

    if (client != NULL)
    {
        qsc_memutils_secure_erase(client, sizeof(qsc_tls_client_state));
        qsc_memutils_alloc_free(client);
    }

    if (server != NULL)
    {
        qsc_memutils_secure_erase(server, sizeof(qsc_tls_server_state));
        qsc_memutils_alloc_free(server);
    }

    if (clientflight != NULL)
    {
        qsc_memutils_clear(clientflight, 131072U);
        qsc_memutils_alloc_free(clientflight);
    }

    if (serverflight != NULL)
    {
        qsc_memutils_clear(serverflight, 131072U);
        qsc_memutils_alloc_free(serverflight);
    }

    return result;
}

static bool process_certificate_request_message(const uint8_t* body, size_t bodylen, qsc_tls_alert_description* alert)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    static const qsc_tls_named_group groups[] = { qsc_tls_group_x25519 };
    static const qsc_tls_signature_scheme schemes[] = { qsc_tls_sig_ecdsa_secp256r1_sha256 };
    uint8_t hs[512U] = { 0U };
    uint8_t record[1024U] = { 0U };
    uint8_t output[1024U] = { 0U };
    qsc_tls_client_config config = { 0 };
    qsc_tls_client_state client;
    size_t consumed;
    size_t hsoff;
    size_t recordlen;
    size_t written;
    qsc_tls_status status;
    bool ok;

    memset(&client, 0, sizeof(client));
    config.ciphersuites = suites;
    config.ciphersuitecount = 1U;
    config.groups = groups;
    config.groupcount = 1U;
    config.sigschemes = schemes;
    config.sigschemecount = 1U;
    status = qsc_tls_client_initialize(&client, &config);
    ok = (status == qsc_tls_status_success);

    if (ok == true)
    {
        client.phase = qsc_tls_client_phase_waiting_certificate;
        status = qsc_tls_transcript_initialize(&client.transcript, qsc_tls_hash_sha256);
        ok = (status == qsc_tls_status_success);
    }

    hsoff = 0U;

    if (ok == true)
    {
        status = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_certificate_request, bodylen);
        ok = (status == qsc_tls_status_success && hsoff + bodylen <= sizeof(hs));
    }

    if (ok == true)
    {
        memcpy(hs + hsoff, body, bodylen);
        hsoff += bodylen;
        recordlen = 0U;
        status = qsc_tls_record_encode_plaintext(record, sizeof(record), &recordlen, qsc_tls_record_content_handshake, hs, hsoff);
        ok = (status == qsc_tls_status_success);
    }

    consumed = 0U;
    written = 0U;

    if (ok == true)
    {
        status = qsc_tls_client_process_record(&client, record, recordlen, &consumed, output, sizeof(output), &written);
        ok = (status == qsc_tls_status_success);
    }

    if (alert != NULL)
    {
        *alert = client.lastalert;
    }

    qsc_tls_client_dispose(&client);

    return ok;
}

static bool test_certificate_request_missing_signature_algorithms(void)
{
    uint8_t body[] = { 0x00U, 0x00U, 0x04U, 0xAAU, 0xAAU, 0x00U, 0x00U };
    qsc_tls_alert_description alert;
    bool ok;

    alert = qsc_tls_alert_close_notify;
    ok = process_certificate_request_message(body, sizeof(body), &alert);

    return (ok == false && alert == qsc_tls_alert_missing_extension);
}

static bool test_certificate_request_nonzero_context(void)
{
    uint8_t body[128U] = { 0U };
    uint8_t extensions[64U] = { 0U };
    static const qsc_tls_signature_scheme schemes[] = { qsc_tls_sig_ecdsa_secp256r1_sha256 };
    const uint8_t context[] = { 0x01U };
    size_t bodyoff;
    size_t extoff;
    qsc_tls_alert_description alert;
    qsc_tls_status status;
    bool ok;

    bodyoff = 0U;
    extoff = 0U;
    status = qsc_tls_extensions_encode_signature_algorithms(extensions, sizeof(extensions), &extoff, schemes, 1U);
    ok = (status == qsc_tls_status_success);

    if (ok == true)
    {
        status = qsc_tls_certificate_request_encode(context, sizeof(context), extensions, extoff, body, sizeof(body), &bodyoff);
        ok = (status == qsc_tls_status_success);
    }

    alert = qsc_tls_alert_close_notify;

    if (ok == true)
    {
        ok = process_certificate_request_message(body, bodyoff, &alert);
        ok = (ok == false && alert == qsc_tls_alert_illegal_parameter);
    }

    return ok;
}

static bool test_required_empty_certificate(void)
{
    qsc_tls_alert_description alert;
    size_t calls;
    bool authenticated;
    bool sent;
    bool ok;

    calls = 0U;
    authenticated = true;
    sent = true;
    ok = run_handshake(false, true, false, 0xA5U, false, true, &alert, &authenticated, &sent, &calls);

    return (ok == false && alert == qsc_tls_alert_certificate_required && authenticated == false && sent == false && calls == 0U);
}

static bool test_required_mtls(void)
{
    qsc_tls_alert_description alert;
    size_t calls;
    bool authenticated;
    bool sent;
    bool ok;

    calls = 0U;
    authenticated = false;
    sent = false;
    ok = run_handshake(true, true, true, 0xA5U, true, true, &alert, &authenticated, &sent, &calls);

    return (ok == true && authenticated == true && sent == true && calls == 1U);
}

static bool test_non_mtls_finished_not_identity_auth(void)
{
    qsc_tls_alert_description alert;
    size_t calls;
    bool authenticated;
    bool sent;
    bool ok;

    calls = 0U;
    authenticated = true;
    sent = true;
    ok = run_handshake(false, false, false, 0xA5U, false, true, &alert, &authenticated, &sent, &calls);

    return (ok == true && authenticated == false && sent == false && calls == 0U);
}

static bool test_optional_empty_certificate(void)
{
    qsc_tls_alert_description alert;
    size_t calls;
    bool authenticated;
    bool sent;
    bool ok;

    calls = 0U;
    authenticated = true;
    sent = true;
    ok = run_handshake(true, false, false, 0xA5U, false, true, &alert, &authenticated, &sent, &calls);

    return (ok == true && authenticated == false && sent == false && calls == 0U);
}

static bool test_bad_client_certificate_verify(void)
{
    qsc_tls_alert_description alert;
    size_t calls;
    bool authenticated;
    bool sent;
    bool ok;

    calls = 0U;
    authenticated = true;
    sent = false;
    ok = run_handshake(true, true, true, 0x5AU, true, true, &alert, &authenticated, &sent, &calls);

    return (ok == false && alert == qsc_tls_alert_decrypt_error && authenticated == false && calls == 0U);
}

static bool test_authorization_rejection(void)
{
    qsc_tls_alert_description alert;
    size_t calls;
    bool authenticated;
    bool sent;
    bool ok;

    calls = 0U;
    authenticated = true;
    sent = false;
    ok = run_handshake(true, true, true, 0xA5U, true, false, &alert, &authenticated, &sent, &calls);

    return (ok == false && alert == qsc_tls_alert_access_denied && authenticated == false && calls == 1U);
}

bool qsctest_tls_stage31_tests(void)
{
    bool res;

    res = true;

#define STAGE31_RUN(fn, label) do { if ((fn)() == true) { qsctest_print_line("[PASS] TLS Stage 31 " label "."); } else { qsctest_print_line("[FAIL] TLS Stage 31 " label "."); res = false; } } while (0)
    STAGE31_RUN(test_certificate_request_missing_signature_algorithms, "CertificateRequest signature_algorithms requirement test");
    STAGE31_RUN(test_certificate_request_nonzero_context, "CertificateRequest request-context rejection test");
    STAGE31_RUN(test_required_empty_certificate, "required empty client Certificate rejection test");
    STAGE31_RUN(test_required_mtls, "required mutual-TLS handshake test");
    STAGE31_RUN(test_non_mtls_finished_not_identity_auth, "Finished-not-client-identity-authentication test");
    STAGE31_RUN(test_optional_empty_certificate, "optional empty client Certificate test");
    STAGE31_RUN(test_bad_client_certificate_verify, "bad client CertificateVerify rejection test");
    STAGE31_RUN(test_authorization_rejection, "client authorization rejection test");
#undef STAGE31_RUN

    return res;
}
