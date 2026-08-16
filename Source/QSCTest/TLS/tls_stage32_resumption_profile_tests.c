#include "tls_stage32_resumption_profile_tests.h"
#include "../testutils.h"
#include "tlsclient.h"
#include "tlsengine.h"
#include "tlsserver.h"
#include "tlssession.h"
#include "tlssocket.h"
#include "tlshandshake.h"
#include "tlsrecord.h"
#include "memutils.h"
#include "timestamp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct test_ticket_store
{
    qsc_tls_session_ticket ticket;
    size_t lookups;
} test_ticket_store;

typedef struct test_verify_state
{
    uint8_t expected;
} test_verify_state;

typedef struct test_sign_state
{
    uint8_t value;
} test_sign_state;

typedef struct
{
    qsc_tls_connection client;
    qsc_tls_connection server;
} stage32_connection_pair;

static stage32_connection_pair* stage32_connection_pair_allocate(void)
{
    stage32_connection_pair* pair;

    pair = (stage32_connection_pair*)qsc_memutils_malloc(sizeof(stage32_connection_pair));

    if (pair != NULL)
    {
        qsc_memutils_clear(pair, sizeof(stage32_connection_pair));
    }

    return pair;
}

static void stage32_connection_pair_free(stage32_connection_pair* pair)
{
    if (pair != NULL)
    {
        qsc_memutils_alloc_free(pair);
    }
}

static qsc_tls_connection* stage32_connection_allocate(void)
{
    qsc_tls_connection* connection;

    connection = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));

    if (connection != NULL)
    {
        qsc_memutils_clear(connection, sizeof(qsc_tls_connection));
    }

    return connection;
}

static bool test_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* context, void* state)
{
    (void)context;
    (void)state;

    return (chain != NULL && chainlength != 0U && chain[0U].data != NULL && chain[0U].datalen != 0U);
}

static bool test_verify_signature(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    test_verify_state* st;
    size_t i;
    bool res;

    st = (test_verify_state*)state;

    res = (st != NULL && scheme == qsc_tls_sig_ecdsa_secp256r1_sha256 && input != NULL && inputlen != 0U &&
        signature != NULL && signaturelen == 64U && signer != NULL && signer->datalen != 0U);

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

    if (st != NULL && scheme == qsc_tls_sig_ecdsa_secp256r1_sha256 && input != NULL && inputlen != 0U && signature != NULL && signaturelen != NULL && *signaturelen >= 64U)
    {
        memset(signature, st->value, 64U);
        *signaturelen = 64U;
        res = true;
    }

    return res;
}

static bool test_ticket_lookup(const uint8_t* identity, size_t identitylen, qsc_tls_session_ticket* ticketout, void* state)
{
    test_ticket_store* store;
    bool res;

    store = (test_ticket_store*)state;
    res = false;

    if (store != NULL)
    {
        ++store->lookups;

        if (ticketout != NULL && identity != NULL && identitylen == store->ticket.ticketlen && identitylen != 0U && qsc_memutils_are_equal(identity, store->ticket.ticket, identitylen) == true)
        {
            *ticketout = store->ticket;
            res = true;
        }
    }

    return res;
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

static void configure_handshake(qsc_tls_client_config* clientconfig, qsc_tls_server_config* serverconfig, const qsc_tls_cipher_suite* clientsuites, 
    size_t clientsuitecount, const qsc_tls_cipher_suite* serversuites, size_t serversuitecount, const qsc_tls_session_ticket* offeredticket, 
    const char* hostname, test_ticket_store* store, qsc_tls_certificate_interface* clientiface, test_sign_state* serversigner)
{
    static const qsc_tls_named_group groups[] = { qsc_tls_group_x25519 };
    static const qsc_tls_signature_scheme schemes[] = { qsc_tls_sig_ecdsa_secp256r1_sha256 };
    static const uint8_t servercert[] = { 0x30U, 0x03U, 0x02U, 0x01U, 0x01U };

    memset(clientconfig, 0, sizeof(*clientconfig));
    memset(serverconfig, 0, sizeof(*serverconfig));
    clientconfig->ciphersuites = clientsuites;
    clientconfig->ciphersuitecount = clientsuitecount;
    clientconfig->groups = groups;
    clientconfig->groupcount = 1U;
    clientconfig->sigschemes = schemes;
    clientconfig->sigschemecount = 1U;
    clientconfig->hostname = hostname;
    clientconfig->certinterface = *clientiface;
    clientconfig->offeredticket = offeredticket;
    clientconfig->enableresumption = true;

    serverconfig->ciphersuitepreference = serversuites;
    serverconfig->ciphersuitepreferencecount = serversuitecount;
    serverconfig->groupspreference = groups;
    serverconfig->groupspreferencecount = 1U;
    serverconfig->sigschemepreference = schemes;
    serverconfig->sigschemepreferencecount = 1U;
    serverconfig->psklookup = test_ticket_lookup;
    serverconfig->psklookupstate = store;
    configure_local_certificate(&serverconfig->localcert, servercert, sizeof(servercert), serversigner);
}

static qsc_tls_status feed_engine(qsc_tls_connection* connection, const uint8_t* input, size_t inputlen, uint8_t* output, size_t outputcap, size_t* outputlen)
{
    size_t consumed;
    size_t off;
    size_t written;
    qsc_tls_status status;

    off = 0U;
    *outputlen = 0U;
    status = qsc_tls_status_success;

    while (off < inputlen && status == qsc_tls_status_success)
    {
        consumed = 0U;
        written = 0U;
        status = qsc_tls_engine_handshake(connection, input + off, inputlen - off, &consumed,
            output + *outputlen, outputcap - *outputlen, &written);

        if (status == qsc_tls_status_success && consumed == 0U)
        {
            status = qsc_tls_status_failure;
        }

        off += consumed;
        *outputlen += written;
    }

    return status;
}

static bool run_engine_handshake(qsc_tls_client_config* clientconfig, qsc_tls_server_config* serverconfig, qsc_tls_connection* client, qsc_tls_connection* server)
{
    uint8_t* clientflight;
    uint8_t* serverflight;
    size_t clientflightlen;
    size_t consumed;
    size_t serverflightlen;
    qsc_tls_status status;
    bool res;

    clientflight = (uint8_t*)qsc_memutils_malloc(131072U);
    serverflight = (uint8_t*)qsc_memutils_malloc(131072U);
    clientflightlen = 0U;
    consumed = 0U;
    serverflightlen = 0U;
    status = qsc_tls_status_failure;
    res = (clientflight != NULL && serverflight != NULL);

    if (res == true)
    {
        qsc_memutils_clear(clientflight, 131072U);
        qsc_memutils_clear(serverflight, 131072U);
        status = qsc_tls_engine_initialize_client(client, clientconfig);
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        status = qsc_tls_engine_initialize_server(server, serverconfig);
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        status = qsc_tls_engine_handshake(client, NULL, 0U, &consumed, clientflight, 131072U, &clientflightlen);
        res = (status == qsc_tls_status_success && clientflightlen != 0U);
    }

    if (res == true)
    {
        status = feed_engine(server, clientflight, clientflightlen, serverflight, 131072U, &serverflightlen);
        res = (status == qsc_tls_status_success && serverflightlen != 0U);
    }

    if (res == true)
    {
        status = feed_engine(client, serverflight, serverflightlen, clientflight, 131072U, &clientflightlen);
        res = (status == qsc_tls_status_success && clientflightlen != 0U);
    }

    if (res == true)
    {
        status = feed_engine(server, clientflight, clientflightlen, serverflight, 131072U, &serverflightlen);
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        res = (qsc_tls_engine_is_handshake_complete(client) == true && qsc_tls_engine_is_handshake_complete(server) == true);
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

    return res;
}

static bool issue_ticket_pair(qsc_tls_connection* client, qsc_tls_connection* server, uint32_t lifetime, qsc_tls_session_ticket* clientticket, qsc_tls_session_ticket* serverticket)
{
    uint8_t record[4096U] = { 0U };
    size_t consumed;
    size_t written;
    qsc_tls_status status;
    bool res;

    consumed = 0U;
    written = 0U;
    status = qsc_tls_engine_emit_session_ticket(server, lifetime, record, sizeof(record), &written, serverticket);
    res = (status == qsc_tls_status_success && written != 0U);

    if (res == true)
    {
        status = qsc_tls_engine_consume_session_ticket(client, record, written, &consumed, clientticket);
        res = (status == qsc_tls_status_success && consumed == written);
    }

    return res;
}

static bool make_ticket_pair(qsc_tls_session_ticket* clientticket, qsc_tls_session_ticket* serverticket)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    stage32_connection_pair* pair;
    test_ticket_store store;
    test_verify_state verifier;
    test_sign_state signer;
    bool res;

    pair = stage32_connection_pair_allocate();

    if (pair == NULL)
    {
        return false;
    }

    memset(&store, 0, sizeof(store));
    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    res = run_engine_handshake(&clientconfig, &serverconfig, &pair->client, &pair->server);

    if (res == true)
    {
        res = issue_ticket_pair(&pair->client, &pair->server, 3600U, clientticket, serverticket);
    }

    if (res == true)
    {
        res = (clientticket->protocolversion == QSC_TLS_PROTOCOL_VERSION_13 &&
            serverticket->protocolversion == QSC_TLS_PROTOCOL_VERSION_13 &&
            clientticket->receipttimems != 0ULL && serverticket->issuetimems != 0ULL &&
            clientticket->ticketlen == serverticket->ticketlen &&
            qsc_memutils_are_equal(clientticket->ticket, serverticket->ticket, clientticket->ticketlen) == true &&
            clientticket->resumptionsecretlen == serverticket->resumptionsecretlen &&
            qsc_memutils_are_equal(clientticket->resumptionsecret, serverticket->resumptionsecret, clientticket->resumptionsecretlen) == true &&
            clientticket->servernamelen == strlen("example.com") && serverticket->servernamelen == strlen("example.com"));
    }

    qsc_tls_engine_dispose(&pair->client);
    qsc_tls_engine_dispose(&pair->server);
    stage32_connection_pair_free(pair);

    return res;
}

static bool run_resumption(const qsc_tls_session_ticket* clientticket, const qsc_tls_session_ticket* serverticket, const char* hostname, 
    const qsc_tls_cipher_suite* clientsuites, size_t clientsuitecount, const qsc_tls_cipher_suite* serversuites, size_t serversuitecount, 
    bool* clientaccepted, bool* serveraccepted, bool* agevalid, size_t* lookups)
{
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    stage32_connection_pair* pair;
    test_ticket_store store;
    test_verify_state verifier;
    test_sign_state signer;
    bool res;

    pair = stage32_connection_pair_allocate();

    if (pair == NULL)
    {
        return false;
    }

    memset(&store, 0, sizeof(store));
    store.ticket = *serverticket;
    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);

    configure_handshake(&clientconfig, &serverconfig, clientsuites, clientsuitecount, serversuites, serversuitecount, clientticket, hostname, &store, &clientiface, &signer);
    res = run_engine_handshake(&clientconfig, &serverconfig, &pair->client, &pair->server);

    if (clientaccepted != NULL)
    {
        *clientaccepted = pair->client.state.client.pskaccepted;
    }

    if (serveraccepted != NULL)
    {
        *serveraccepted = pair->server.state.server.pskaccepted;
    }

    if (agevalid != NULL)
    {
        *agevalid = pair->server.state.server.pskticketagevalid;
    }

    if (lookups != NULL)
    {
        *lookups = store.lookups;
    }

    qsc_tls_engine_dispose(&pair->client);
    qsc_tls_engine_dispose(&pair->server);
    stage32_connection_pair_free(pair);

    return res;
}

static bool test_resumption_success(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    qsc_tls_session_ticket clientticket = { 0 };
    qsc_tls_session_ticket serverticket = { 0 };
    size_t lookups;
    bool cage;
    bool caccept;
    bool saccept;
    bool res;

    lookups = 0U;
    cage = false;
    caccept = false;
    saccept = false;
    res = make_ticket_pair(&clientticket, &serverticket);

    if (res == true)
    {
        res = run_resumption(&clientticket, &serverticket, "example.com", suites, 1U, suites, 1U,
            &caccept, &saccept, &cage, &lookups);
    }

    return (res == true && caccept == true && saccept == true && cage == true && lookups == 1U);
}

static bool test_same_hash_different_suite(void)
{
    static const qsc_tls_cipher_suite clientsuites[] =
    {
        qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256,
        qsc_tls_cipher_suite_tls_aes_128_gcm_sha256
    };
    static const qsc_tls_cipher_suite serversuites[] =
    {
        qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256,
        qsc_tls_cipher_suite_tls_aes_128_gcm_sha256
    };
    qsc_tls_session_ticket clientticket = { 0 };
    qsc_tls_session_ticket serverticket = { 0 };
    bool caccept;
    bool saccept;
    bool res;

    caccept = false;
    saccept = false;
    res = make_ticket_pair(&clientticket, &serverticket);

    if (res == true)
    {
        res = run_resumption(&clientticket, &serverticket, "example.com", clientsuites, 2U, serversuites, 2U, &caccept, &saccept, NULL, NULL);
    }

    return (res == true && caccept == true && saccept == true);
}

static bool test_expired_ticket_falls_back(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    qsc_tls_session_ticket clientticket = { 0 };
    qsc_tls_session_ticket serverticket = { 0 };
    uint64_t now;
    size_t lookups;
    bool caccept;
    bool saccept;
    bool res;

    caccept = true;
    saccept = true;
    lookups = 0U;
    res = make_ticket_pair(&clientticket, &serverticket);
    now = qsc_timestamp_epochtime_milliseconds();

    if (res == true && now > ((uint64_t)clientticket.lifetime * 1000ULL + 1ULL))
    {
        clientticket.receipttimems = now - ((uint64_t)clientticket.lifetime * 1000ULL + 1ULL);
        res = run_resumption(&clientticket, &serverticket, "example.com", suites, 1U, suites, 1U, &caccept, &saccept, NULL, &lookups);
    }

    return (res == true && caccept == false && saccept == false && lookups == 0U);
}

static bool test_sni_mismatch_falls_back(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    qsc_tls_session_ticket clientticket = { 0 };
    qsc_tls_session_ticket serverticket = { 0 };
    size_t lookups;
    bool caccept;
    bool saccept;
    bool res;

    caccept = true;
    saccept = true;
    lookups = 0U;
    res = make_ticket_pair(&clientticket, &serverticket);

    if (res == true)
    {
        res = run_resumption(&clientticket, &serverticket, "other.example.com", suites, 1U, suites, 1U,
            &caccept, &saccept, NULL, &lookups);
    }

    return (res == true && caccept == false && saccept == false && lookups == 0U);
}

static bool test_obfuscated_ticket_age_tracks_elapsed_time(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    qsc_tls_session_ticket clientticket;
    qsc_tls_session_ticket serverticket;
    uint64_t now;
    bool agevalid;
    bool caccept;
    bool saccept;
    bool res;

    memset(&clientticket, 0, sizeof(clientticket));
    memset(&serverticket, 0, sizeof(serverticket));
    agevalid = false;
    caccept = false;
    saccept = false;
    res = make_ticket_pair(&clientticket, &serverticket);
    now = qsc_timestamp_epochtime_milliseconds();

    if (res == true && now > 30000ULL)
    {
        serverticket.issuetimems = now - 30000ULL;
        clientticket.receipttimems = now - 30000ULL;
        res = run_resumption(&clientticket, &serverticket, "example.com", suites, 1U, suites, 1U, &caccept, &saccept, &agevalid, NULL);
    }

    return (res == true && caccept == true && saccept == true && agevalid == true);
}

static bool test_ticket_age_skew_accepts_psk_not_freshness(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    qsc_tls_session_ticket clientticket;
    qsc_tls_session_ticket serverticket;
    uint64_t now;
    bool agevalid;
    bool caccept;
    bool saccept;
    bool res;

    memset(&clientticket, 0, sizeof(clientticket));
    memset(&serverticket, 0, sizeof(serverticket));
    agevalid = true;
    caccept = false;
    saccept = false;
    res = make_ticket_pair(&clientticket, &serverticket);
    now = qsc_timestamp_epochtime_milliseconds();

    if (res == true && now > 60000ULL)
    {
        serverticket.issuetimems = now - 60000ULL;
        clientticket.receipttimems = now;
        res = run_resumption(&clientticket, &serverticket, "example.com", suites, 1U, suites, 1U, &caccept, &saccept, &agevalid, NULL);
    }

    return (res == true && caccept == true && saccept == true && agevalid == false);
}

static bool test_bad_binder_is_fatal(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    uint8_t clienthello[32768U] = { 0U };
    uint8_t serverflight[131072U] = { 0U };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    qsc_tls_connection* client;
    qsc_tls_connection* server;
    qsc_tls_session_ticket clientticket = { 0 };
    qsc_tls_session_ticket serverticket = { 0 };
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer = { 0 };
    size_t consumed;
    size_t written;
    qsc_tls_status status;
    bool clientinitialized;
    bool res;
    bool serverinitialized;

    client = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));
    server = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));
    clientinitialized = false;
    serverinitialized = false;
    res = (client != NULL && server != NULL);

    if (res == true)
    {
        qsc_memutils_clear(client, sizeof(qsc_tls_connection));
        qsc_memutils_clear(server, sizeof(qsc_tls_connection));
        res = make_ticket_pair(&clientticket, &serverticket);
    }

    if (res == true)
    {
        clientticket.resumptionsecret[0U] ^= 0x01U;
        store.ticket = serverticket;
        verifier.expected = 0xA5U;
        signer.value = 0xA5U;
        qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
        configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, &clientticket, "example.com", &store, &clientiface, &signer);
        status = qsc_tls_engine_initialize_client(client, &clientconfig);
        res = (status == qsc_tls_status_success);
        clientinitialized = res;
    }

    if (res == true)
    {
        status = qsc_tls_engine_initialize_server(server, &serverconfig);
        res = (status == qsc_tls_status_success);
        serverinitialized = res;
    }

    consumed = 0U;
    written = 0U;

    if (res == true)
    {
        status = qsc_tls_engine_handshake(client, NULL, 0U, &consumed, clienthello, sizeof(clienthello), &written);
        res = (status == qsc_tls_status_success && written != 0U);
    }

    consumed = 0U;

    if (res == true)
    {
        status = qsc_tls_engine_handshake(server, clienthello, written, &consumed, serverflight, sizeof(serverflight), &written);
        res = (status == qsc_tls_status_authentication_failure && server->state.server.lastalert == qsc_tls_alert_decrypt_error &&
            server->state.server.pskaccepted == false && store.lookups == 1U);
    }

    if (clientinitialized == true)
    {
        qsc_tls_engine_dispose(client);
    }

    if (serverinitialized == true)
    {
        qsc_tls_engine_dispose(server);
    }

    if (client != NULL)
    {
        qsc_memutils_secure_erase(client, sizeof(qsc_tls_connection));
        qsc_memutils_alloc_free(client);
    }

    if (server != NULL)
    {
        qsc_memutils_secure_erase(server, sizeof(qsc_tls_connection));
        qsc_memutils_alloc_free(server);
    }

    return res;
}

static bool test_unique_ticket_nonce(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    uint8_t record[4096U] = { 0U };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    stage32_connection_pair* pair;
    qsc_tls_session_ticket first = { 0 };
    qsc_tls_session_ticket second = { 0 };
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer;
    size_t written;
    qsc_tls_status status;
    bool res;

    pair = stage32_connection_pair_allocate();

    if (pair == NULL)
    {
        return false;
    }

    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    res = run_engine_handshake(&clientconfig, &serverconfig, &pair->client, &pair->server);
    written = 0U;

    if (res == true)
    {
        status = qsc_tls_engine_emit_session_ticket(&pair->server, 3600U, record, sizeof(record), &written, &first);
        res = (status == qsc_tls_status_success && written != 0U);
    }

    written = 0U;

    if (res == true)
    {
        status = qsc_tls_engine_emit_session_ticket(&pair->server, 3600U, record, sizeof(record), &written, &second);

        res = (status == qsc_tls_status_success && written != 0U && first.noncelen == second.noncelen &&
            qsc_memutils_are_equal(first.nonce, second.nonce, first.noncelen) == false);
    }

    qsc_tls_engine_dispose(&pair->client);
    qsc_tls_engine_dispose(&pair->server);
    stage32_connection_pair_free(pair);

    return res;
}

static bool test_ticket_codec_early_data_extension(void)
{
    uint8_t encoded[2048U] = { 0U };
    qsc_tls_session_ticket decoded = { 0 };
    qsc_tls_session_ticket ticket = { 0 };
    size_t written;
    qsc_tls_status status;
    bool res;

    ticket.lifetime = 60U;
    ticket.ageadd = 7U;
    ticket.nonce[0U] = 1U;
    ticket.noncelen = 1U;
    ticket.ticket[0U] = 2U;
    ticket.ticketlen = 1U;
    ticket.maxearlydatasize = 4096U;
    written = 0U;
    status = qsc_tls_session_ticket_encode(&ticket, encoded, sizeof(encoded), &written);
    res = (status == qsc_tls_status_success && written != 0U);

    if (res == true)
    {
        status = qsc_tls_session_ticket_decode(encoded, written, &decoded);
        res = (status == qsc_tls_status_success && decoded.maxearlydatasize == 4096U && decoded.lifetime == 60U && decoded.ageadd == 7U);
    }

    return res;
}

static bool test_ticket_codec_duplicate_extension(void)
{
    uint8_t duplicate[2048U] = { 0U };
    uint8_t encoded[2048U] = { 0U };
    qsc_tls_session_ticket decoded = { 0 };
    qsc_tls_session_ticket ticket = { 0 };
    size_t extlen;
    size_t written;
    qsc_tls_status status;
    bool res;

    ticket.lifetime = 60U;
    ticket.nonce[0U] = 1U;
    ticket.noncelen = 1U;
    ticket.ticket[0U] = 2U;
    ticket.ticketlen = 1U;
    ticket.maxearlydatasize = 1024U;
    written = 0U;
    status = qsc_tls_session_ticket_encode(&ticket, encoded, sizeof(encoded), &written);
    res = (status == qsc_tls_status_success && written > 15U);

    if (res == true)
    {
        extlen = ((size_t)encoded[13U] << 8U) | (size_t)encoded[14U];
        res = (extlen != 0U && written + extlen <= sizeof(duplicate));
    }

    if (res == true)
    {
        memcpy(duplicate, encoded, written);
        duplicate[13U] = (uint8_t)(((extlen * 2U) >> 8U) & 0xFFU);
        duplicate[14U] = (uint8_t)((extlen * 2U) & 0xFFU);
        memcpy(duplicate + written, encoded + 15U, extlen);
        status = qsc_tls_session_ticket_decode(duplicate, written + extlen, &decoded);
        res = (status == qsc_tls_status_invalid_message);
    }

    return res;
}

static bool test_zero_lifetime_ticket_is_discarded(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    uint8_t record[4096U] = { 0U };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    stage32_connection_pair* pair;
    qsc_tls_session_ticket clientticket = { 0 };
    qsc_tls_session_ticket serverticket = { 0 };
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer;
    size_t consumed;
    size_t written;
    qsc_tls_status status;
    bool res;

    pair = stage32_connection_pair_allocate();

    if (pair == NULL)
    {
        return false;
    }

    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    res = run_engine_handshake(&clientconfig, &serverconfig, &pair->client, &pair->server);
    written = 0U;

    if (res == true)
    {
        status = qsc_tls_engine_emit_session_ticket(&pair->server, 0U, record, sizeof(record), &written, &serverticket);
        res = (status == qsc_tls_status_success && written != 0U);
    }

    consumed = 0U;

    if (res == true)
    {
        status = qsc_tls_engine_consume_session_ticket(&pair->client, record, written, &consumed, &clientticket);
        res = (status == qsc_tls_status_success && consumed == written && pair->client.hasreceivedticket == false &&
            clientticket.ticketlen == 0U && clientticket.resumptionsecretlen == 0U);
    }

    qsc_tls_engine_dispose(&pair->client);
    qsc_tls_engine_dispose(&pair->server);
    stage32_connection_pair_free(pair);

    return res;
}

static bool test_excessive_ticket_lifetime_rejected(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    uint8_t record[4096U] = { 0U };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    stage32_connection_pair* pair;
    qsc_tls_session_ticket ticket = { 0 };
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer;
    size_t written;
    qsc_tls_status status;
    bool res;

    pair = stage32_connection_pair_allocate();

    if (pair == NULL)
    {
        return false;
    }

    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    res = run_engine_handshake(&clientconfig, &serverconfig, &pair->client, &pair->server);
    written = 0U;

    if (res == true)
    {
        status = qsc_tls_engine_emit_session_ticket(&pair->server, QSC_TLS_SESSION_TICKET_LIFETIME_MAX + 1U, record, sizeof(record), &written, &ticket);
        res = (status == qsc_tls_status_invalid_length && written == 0U);
    }

    qsc_tls_engine_dispose(&pair->client);
    qsc_tls_engine_dispose(&pair->server);
    stage32_connection_pair_free(pair);

    return res;
}

static bool test_socket_ticket_validation(void)
{
    qsc_tls_session_ticket clientticket = { 0 };
    qsc_tls_session_ticket serverticket = { 0 };
    static qsc_tls_socket_context context;
    qsc_tls_socket_ticket_policy policy = { 0 };
    qsc_tls_socket_status status;
    test_ticket_store store = { 0 };
    bool res;

    res = make_ticket_pair(&clientticket, &serverticket);

    if (res == true)
    {
        res = qsc_tls_socket_session_ticket_is_valid(&clientticket);
    }

    qsc_tls_socket_context_initialize(&context);
    qsc_tls_socket_ticket_policy_initialize_default(&policy);
    policy.enabled = true;
    status = qsc_tls_socket_context_set_session_ticket_policy(&context, &policy);
    res = (res == true && status == qsc_tls_socket_status_success);

    if (res == true)
    {
        status = qsc_tls_socket_context_set_psk_lookup_callback(&context, test_ticket_lookup, &store);
        res = (status == qsc_tls_socket_status_success && context.psklookup == test_ticket_lookup && context.psklookupstate == &store);
    }

    if (res == true)
    {
        status = qsc_tls_socket_context_set_session_ticket(&context, &clientticket);
        res = (status == qsc_tls_socket_status_success && context.hassessionticket == true);
    }

    if (res == true)
    {
        clientticket.protocolversion = QSC_TLS_PROTOCOL_VERSION_12;
        res = (qsc_tls_socket_session_ticket_is_valid(&clientticket) == false);
    }

    qsc_tls_socket_context_dispose(&context);

    return res;
}

static bool test_client_0rtt_configuration_rejected(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    qsc_tls_connection* client;
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer;
    qsc_tls_status status;

    client = stage32_connection_allocate();

    if (client == NULL)
    {
        return false;
    }

    qsc_memutils_clear(client, sizeof(qsc_tls_connection));
    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    clientconfig.enableearlydata = true;
    status = qsc_tls_engine_initialize_client(client, &clientconfig);
    qsc_tls_engine_dispose(client);
    qsc_memutils_alloc_free(client);

    return (status == qsc_tls_status_not_supported);
}

static bool test_server_0rtt_configuration_rejected(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    qsc_tls_connection* server;
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer;
    qsc_tls_status status;

    server = stage32_connection_allocate();

    if (server == NULL)
    {
        return false;
    }

    qsc_memutils_clear(server, sizeof(qsc_tls_connection));
    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    serverconfig.acceptearlydata = true;
    status = qsc_tls_engine_initialize_server(server, &serverconfig);
    qsc_tls_engine_dispose(server);
    qsc_memutils_alloc_free(server);

    return (status == qsc_tls_status_not_supported);
}

static bool test_pre_handshake_application_write_rejected(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    uint8_t output[256U] = { 0U };
    static const uint8_t message[] = { 0x01U, 0x02U, 0x03U };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    qsc_tls_connection* client;
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer;
    size_t written;
    qsc_tls_status status;
    bool res;

    client = stage32_connection_allocate();

    if (client == NULL)
    {
        return false;
    }

    qsc_memutils_clear(client, sizeof(qsc_tls_connection));
    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    written = 0U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    status = qsc_tls_engine_initialize_client(client, &clientconfig);
    res = (status == qsc_tls_status_success);

    if (res == true)
    {
        client->state.client.earlydataoffered = true;
        client->state.client.writerecord.initialized = true;
        status = qsc_tls_engine_write_application_data(client, message, sizeof(message), output, sizeof(output), &written);
        res = (status == qsc_tls_status_invalid_state && written == 0U);
    }

    qsc_tls_engine_dispose(client);
    qsc_memutils_alloc_free(client);

    return res;
}

static bool test_engine_managed_ticket_strips_early_data(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    uint8_t body[1024U] = { 0U };
    uint8_t handshake[1100U] = { 0U };
    uint8_t record[1400U] = { 0U };
    uint8_t application[64U] = { 0U };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    stage32_connection_pair* pair;
    qsc_tls_session_ticket received = { 0 };
    qsc_tls_session_ticket wireticket = { 0 };
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer;
    size_t applicationwritten;
    size_t bodylen;
    size_t consumed;
    size_t hsoff;
    size_t recordlen;
    qsc_tls_status status;
    bool res;

    pair = stage32_connection_pair_allocate();

    if (pair == NULL)
    {
        return false;
    }

    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    res = run_engine_handshake(&clientconfig, &serverconfig, &pair->client, &pair->server);
    applicationwritten = 0U;
    bodylen = 0U;
    consumed = 0U;
    hsoff = 0U;
    recordlen = 0U;

    if (res == true)
    {
        wireticket.lifetime = 60U;
        wireticket.ageadd = 0x01020304U;
        wireticket.nonce[0U] = 0xA1U;
        wireticket.noncelen = 1U;
        wireticket.ticket[0U] = 0x11U;
        wireticket.ticket[1U] = 0x22U;
        wireticket.ticket[2U] = 0x33U;
        wireticket.ticketlen = 3U;
        wireticket.maxearlydatasize = 4096U;
        status = qsc_tls_session_ticket_encode(&wireticket, body, sizeof(body), &bodylen);
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        status = qsc_tls_handshake_write_header(handshake, sizeof(handshake), &hsoff, qsc_tls_handshake_type_new_session_ticket, bodylen);
        res = (status == qsc_tls_status_success && hsoff + bodylen <= sizeof(handshake));
    }

    if (res == true)
    {
        qsc_memutils_copy(handshake + hsoff, body, bodylen);
        hsoff += bodylen;
        status = qsc_tls_record_encrypt(&pair->server.state.server.writerecord, record, sizeof(record), &recordlen, qsc_tls_record_content_handshake, handshake, hsoff);
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        status = qsc_tls_engine_read_application_data(&pair->client, record, recordlen, &consumed, application, sizeof(application), &applicationwritten);
        res = (status == qsc_tls_status_success && consumed == recordlen && applicationwritten == 0U);
    }

    if (res == true)
    {
        status = qsc_tls_engine_take_session_ticket(&pair->client, &received);
        res = (status == qsc_tls_status_success && received.maxearlydatasize == 0U && received.ticketlen == wireticket.ticketlen);
    }

    qsc_tls_session_ticket_dispose(&received);
    qsc_tls_engine_dispose(&pair->client);
    qsc_tls_engine_dispose(&pair->server);
    stage32_connection_pair_free(pair);

    return res;
}

static bool test_socket_0rtt_policy_rejected(void)
{
    qsc_tls_socket_connection* connection;
    qsc_tls_socket_context* context;
    qsc_tls_socket_ticket_policy policy;
    qsc_tls_socket_status status;
    bool res;

    connection = (qsc_tls_socket_connection*)malloc(sizeof(qsc_tls_socket_connection));
    context = (qsc_tls_socket_context*)malloc(sizeof(qsc_tls_socket_context));
    res = (connection != NULL && context != NULL);

    if (res == true)
    {
        qsc_tls_socket_context_initialize(context);
        qsc_tls_socket_ticket_policy_initialize_default(&policy);
        policy.enabled = true;
        policy.allow_early_data = true;
        status = qsc_tls_socket_context_set_session_ticket_policy(context, &policy);
        res = (status == qsc_tls_socket_status_policy_rejected);

        memset(connection, 0, sizeof(qsc_tls_socket_connection));
        status = qsc_tls_socket_client_connect_host_ex(connection, context, "localhost", "9", NULL, true);
        res = (res == true && status == qsc_tls_socket_status_policy_rejected && connection->connected == false);
        qsc_tls_socket_context_dispose(context);
    }

    free(connection);
    free(context);

    return res;
}

static bool test_reserved_server_early_state_cannot_enable_read(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    const uint8_t ccs[1U] = { 0x01U };
    uint8_t input[32U] = { 0U };
    uint8_t output[32U] = { 0U };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    qsc_tls_connection* server;
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer;
    size_t consumed;
    size_t inputlen;
    size_t written;
    qsc_tls_status status;
    bool res;

    server = stage32_connection_allocate();

    if (server == NULL)
    {
        return false;
    }

    qsc_memutils_clear(server, sizeof(qsc_tls_connection));
    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    consumed = 0U;
    inputlen = 0U;
    written = 0U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    status = qsc_tls_engine_initialize_server(server, &serverconfig);
    res = (status == qsc_tls_status_success);

    if (res == true)
    {
        status = qsc_tls_record_encode_plaintext(input, sizeof(input), &inputlen, qsc_tls_record_content_change_cipher_spec, ccs, sizeof(ccs));
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        server->state.server.earlydataaccepted = true;
        server->state.server.phase = qsc_tls_server_phase_waiting_end_of_early_data;
        server->state.server.readrecord.initialized = true;
        status = qsc_tls_engine_read_application_data(server, input, inputlen, &consumed, output, sizeof(output), &written);
        res = (status == qsc_tls_status_invalid_state && consumed == 0U && written == 0U);
    }

    qsc_tls_engine_dispose(server);
    qsc_memutils_alloc_free(server);

    return res;
}

static bool test_emitted_ticket_has_no_early_data(void)
{
    static const qsc_tls_cipher_suite suites[] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    uint8_t record[4096U] = { 0U };
    qsc_tls_certificate_interface clientiface;
    qsc_tls_client_config clientconfig;
    qsc_tls_server_config serverconfig;
    stage32_connection_pair* pair;
    qsc_tls_session_ticket ticket = { 0 };
    test_ticket_store store = { 0 };
    test_verify_state verifier;
    test_sign_state signer;
    size_t written;
    qsc_tls_status status;
    bool res;

    pair = stage32_connection_pair_allocate();

    if (pair == NULL)
    {
        return false;
    }

    verifier.expected = 0xA5U;
    signer.value = 0xA5U;
    qsc_tls_certificate_interface_initialize(&clientiface, test_validate_chain, test_verify_signature, &verifier);
    configure_handshake(&clientconfig, &serverconfig, suites, 1U, suites, 1U, NULL, "example.com", &store, &clientiface, &signer);
    res = run_engine_handshake(&clientconfig, &serverconfig, &pair->client, &pair->server);
    written = 0U;

    if (res == true)
    {
        status = qsc_tls_engine_emit_session_ticket(&pair->server, 60U, record, sizeof(record), &written, &ticket);
        res = (status == qsc_tls_status_success && written != 0U && ticket.maxearlydatasize == 0U);
    }

    qsc_tls_session_ticket_dispose(&ticket);
    qsc_tls_engine_dispose(&pair->client);
    qsc_tls_engine_dispose(&pair->server);
    stage32_connection_pair_free(pair);

    return res;
}

bool qsctest_tls_stage32_tests(void)
{
    bool res;

    res = true;

#define STAGE32_RUN(fn, label) do { if ((fn)() == true) { qsctest_print_line("[PASS] TLS Stage 32 " label "."); } else { qsctest_print_line("[FAIL] TLS Stage 32 " label "."); res = false; } } while (0)
    STAGE32_RUN(test_resumption_success, "PSK-DHE resumption test");
    STAGE32_RUN(test_same_hash_different_suite, "same-KDF different-cipher-suite resumption test");
    STAGE32_RUN(test_expired_ticket_falls_back, "expired-ticket full-handshake fallback test");
    STAGE32_RUN(test_sni_mismatch_falls_back, "SNI-bound ticket fallback test");
    STAGE32_RUN(test_obfuscated_ticket_age_tracks_elapsed_time, "obfuscated ticket-age encoding test");
    STAGE32_RUN(test_ticket_age_skew_accepts_psk_not_freshness, "ticket-age skew freshness test");
    STAGE32_RUN(test_bad_binder_is_fatal, "bad selected-PSK binder fatality test");
    STAGE32_RUN(test_unique_ticket_nonce, "unique ticket nonce test");
    STAGE32_RUN(test_ticket_codec_early_data_extension, "NewSessionTicket early-data extension codec test");
    STAGE32_RUN(test_ticket_codec_duplicate_extension, "duplicate NewSessionTicket extension rejection test");
    STAGE32_RUN(test_zero_lifetime_ticket_is_discarded, "zero-lifetime ticket discard test");
    STAGE32_RUN(test_excessive_ticket_lifetime_rejected, "excessive ticket lifetime rejection test");
    STAGE32_RUN(test_socket_ticket_validation, "socket ticket metadata validation test");
    STAGE32_RUN(test_client_0rtt_configuration_rejected, "client 0-RTT configuration rejection test");
    STAGE32_RUN(test_server_0rtt_configuration_rejected, "server 0-RTT configuration rejection test");
    STAGE32_RUN(test_pre_handshake_application_write_rejected, "pre-handshake application-write rejection test");
    STAGE32_RUN(test_reserved_server_early_state_cannot_enable_read, "reserved server early-state isolation test");
    STAGE32_RUN(test_engine_managed_ticket_strips_early_data, "engine-managed ticket early-data normalization test");
    STAGE32_RUN(test_socket_0rtt_policy_rejected, "socket 0-RTT policy rejection test");
    STAGE32_RUN(test_emitted_ticket_has_no_early_data, "emitted-ticket no-early-data test");
#undef STAGE32_RUN

    return res;
}
