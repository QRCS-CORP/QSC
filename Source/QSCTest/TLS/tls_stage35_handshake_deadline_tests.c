#include "tls_stage35_handshake_deadline_tests.h"
#include "../testutils.h"
#include "async.h"
#include "csp.h"
#include "eddsa.h"
#include "memutils.h"
#include "socketbase.h"
#include "sysutils.h"
#include "tlsclient.h"
#include "tlsengine.h"
#include "tlsio.h"
#include "tlsserver.h"
#include "tlssignerdefault.h"

#define STAGE35_HANDSHAKE_TIMEOUT_MS 2000U
#define STAGE35_TRICKLE_TIMEOUT_MS 120U
#define STAGE35_TRICKLE_INTERVAL_MS 45U
#define STAGE35_TRICKLE_BYTES 4U

static uint8_t stage35_server_public_key[QSC_EDDSA_PUBLICKEY_SIZE];
static uint8_t stage35_server_private_key[QSC_EDDSA_PRIVATEKEY_SIZE];
static uint8_t stage35_server_certificate[QSC_EDDSA_PUBLICKEY_SIZE];
static bool stage35_material_initialized = false;

typedef struct stage35_server_state
{
    qsc_socket* listener;
    qsc_tls_server_config config;
    qsc_tls_status tlsstatus;
    qsc_socket_exceptions socketstatus;
} stage35_server_state;

typedef struct stage35_trickle_state
{
    qsc_socket* listener;
    qsc_socket_exceptions socketstatus;
} stage35_trickle_state;

static bool stage35_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength,
    const qsc_tls_certificate_validation_context* context, void* state)
{
    (void)context;
    (void)state;

    return (chain != NULL && chainlength == 1U && chain[0U].data != NULL && chain[0U].datalen == sizeof(stage35_server_certificate));
}

static bool stage35_verify_certificate_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen,
    const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    qsc_tls_certificate_view view;

    (void)signer;
    (void)state;
    view.data = stage35_server_public_key;
    view.datalen = sizeof(stage35_server_public_key);

    return qsc_tls_signer_default_verify(scheme, input, inputlen, signature, signaturelen, &view, NULL);
}

static void stage35_initialize_material(void)
{
    if (stage35_material_initialized == false)
    {
        qsc_eddsa_generate_keypair(stage35_server_public_key, stage35_server_private_key, qsc_csp_generate);
        qsc_memutils_copy(stage35_server_certificate, stage35_server_public_key, sizeof(stage35_server_certificate));
        stage35_material_initialized = true;
    }
}

static void stage35_initialize_client_config(qsc_tls_client_config* config)
{
    static const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    static const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
    static const qsc_tls_signature_scheme schemes[1U] = { qsc_tls_sig_ed25519 };

    if (config != NULL)
    {
        qsc_memutils_clear(config, sizeof(*config));
        config->ciphersuites = suites;
        config->ciphersuitecount = 1U;
        config->groups = groups;
        config->groupcount = 1U;
        config->sigschemes = schemes;
        config->sigschemecount = 1U;
        config->hostname = "example.com";
        config->certinterface.validatechain = stage35_validate_chain;
        config->certinterface.verifycertificateverify = stage35_verify_certificate_verify;
    }
}

static void stage35_initialize_server_config(qsc_tls_server_config* config, qsc_tls_signer_default_context* signer)
{
    static const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    static const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
    static const qsc_tls_signature_scheme schemes[1U] = { qsc_tls_sig_ed25519 };

    if (config != NULL && signer != NULL)
    {
        qsc_memutils_clear(config, sizeof(*config));
        qsc_memutils_clear(signer, sizeof(*signer));
        config->ciphersuitepreference = suites;
        config->ciphersuitepreferencecount = 1U;
        config->groupspreference = groups;
        config->groupspreferencecount = 1U;
        config->sigschemepreference = schemes;
        config->sigschemepreferencecount = 1U;
        config->localcert.chain[0U].data = stage35_server_certificate;
        config->localcert.chain[0U].datalen = sizeof(stage35_server_certificate);
        config->localcert.chainlength = 1U;
        config->localcert.verifyscheme = qsc_tls_sig_ed25519;
        config->localcert.configured = true;
        signer->scheme = qsc_tls_sig_ed25519;
        signer->privatekey = stage35_server_private_key;
        signer->privatekeylen = sizeof(stage35_server_private_key);
        config->localcert.signcallback = qsc_tls_signer_default_sign;
        config->localcert.signstate = signer;
    }
}

static bool stage35_create_listener(qsc_socket* listener, uint16_t* port)
{
    qsc_socket_exceptions status;
    uint16_t candidate;
    bool res;

    res = false;

    if (listener != NULL && port != NULL)
    {
        *port = 0U;

        for (candidate = 45780U; candidate < 45790U && res == false; ++candidate)
        {
            qsc_memutils_clear(listener, sizeof(*listener));
            listener->connection = QSC_UNINITIALIZED_SOCKET;
            status = qsc_socket_create(listener, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

            if (status == qsc_socket_exception_success)
            {
                status = qsc_socket_bind(listener, "127.0.0.1", candidate);
            }

            if (status == qsc_socket_exception_success)
            {
                status = qsc_socket_listen(listener, 1);
            }

            if (status == qsc_socket_exception_success)
            {
                *port = candidate;
                res = true;
            }
            else
            {
                (void)qsc_socket_close_socket(listener);
            }
        }
    }

    return res;
}

static bool stage35_connect_client(qsc_socket* socket, uint16_t port)
{
    qsc_socket_exceptions status;
    bool res;

    res = false;

    if (socket != NULL && port != 0U)
    {
        qsc_memutils_clear(socket, sizeof(*socket));
        socket->connection = QSC_UNINITIALIZED_SOCKET;
        status = qsc_socket_create(socket, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

        if (status == qsc_socket_exception_success)
        {
            status = qsc_socket_connect(socket, "127.0.0.1", port);
            res = (status == qsc_socket_exception_success);
        }

        if (res == false)
        {
            (void)qsc_socket_close_socket(socket);
        }
    }

    return res;
}

static void stage35_server_worker(void* state)
{
    stage35_server_state* context;

    context = (stage35_server_state*)state;

    if (context != NULL && context->listener != NULL)
    {
        qsc_socket accepted;
        qsc_tls_connection* engine;
        qsc_tls_io_connection io;

        qsc_memutils_clear(&accepted, sizeof(accepted));
        engine = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));

        if (engine != NULL)
        {
            qsc_memutils_clear(engine, sizeof(qsc_tls_connection));
        }
        qsc_memutils_clear(&io, sizeof(io));
        accepted.connection = QSC_UNINITIALIZED_SOCKET;
        context->socketstatus = qsc_socket_accept(context->listener, &accepted);
        context->tlsstatus = qsc_tls_status_failure;

        if (context->socketstatus == qsc_socket_exception_success && engine != NULL)
        {
            context->tlsstatus = qsc_tls_engine_initialize_server(engine, &context->config);

            if (context->tlsstatus == qsc_tls_status_success)
            {
                context->tlsstatus = qsc_tls_io_attach(&io, engine, &accepted);
            }

            if (context->tlsstatus == qsc_tls_status_success)
            {
                context->tlsstatus = qsc_tls_io_handshake_ex(&io, STAGE35_HANDSHAKE_TIMEOUT_MS);
            }

            qsc_tls_engine_dispose(engine);
        }

        if (context->socketstatus == qsc_socket_exception_success)
        {
            (void)qsc_socket_close_socket(&accepted);
        }

        if (engine != NULL)
        {
            qsc_memutils_alloc_free(engine);
        }
    }
}

static void stage35_trickle_worker(void* state)
{
    stage35_trickle_state* context;

    context = (stage35_trickle_state*)state;

    if (context != NULL && context->listener != NULL)
    {
        static const uint8_t partialrecord[STAGE35_TRICKLE_BYTES] = { 0x16U, 0x03U, 0x03U, 0x00U };
        qsc_socket accepted;

        qsc_memutils_clear(&accepted, sizeof(accepted));
        accepted.connection = QSC_UNINITIALIZED_SOCKET;
        context->socketstatus = qsc_socket_accept(context->listener, &accepted);

        if (context->socketstatus == qsc_socket_exception_success)
        {
            size_t i;

            for (i = 0U; i < sizeof(partialrecord); ++i)
            {
                qsc_async_thread_sleep(STAGE35_TRICKLE_INTERVAL_MS);
                (void)qsc_socket_send(&accepted, partialrecord + i, 1U, qsc_socket_send_flag_none);
            }

            (void)qsc_socket_close_socket(&accepted);
        }
    }
}

static bool stage35_status_contract_test(void)
{
    const char* message;
    bool res;

    message = qsc_tls_error_to_string(qsc_tls_status_timeout);
    res = (QSC_TLS_IO_HANDSHAKE_TIMEOUT_DEFAULT == 30000U && qsc_tls_status_timeout == -10 && message != NULL);

    if (res == true)
    {
        res = (qsc_memutils_are_equal((const uint8_t*)message, (const uint8_t*)"The TLS status code is unknown.", 31U) == false);
    }

    return res;
}

static bool stage35_successful_handshake_test(void)
{
    qsc_tls_client_config clientconfig;
    qsc_tls_connection* clientengine;
    qsc_tls_io_connection clientio;
    qsc_tls_signer_default_context signer;
    qsc_socket clientsocket = { 0 };
    qsc_socket listener = { 0 };
    qsc_thread thread;
    stage35_server_state serverstate;
    uint16_t port;
    bool res;

    clientengine = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));

    if (clientengine == NULL)
    {
        return false;
    }

    qsc_memutils_clear(clientengine, sizeof(qsc_tls_connection));
    qsc_memutils_clear(&clientio, sizeof(clientio));
    qsc_memutils_clear(&serverstate, sizeof(serverstate));
    clientsocket.connection = QSC_UNINITIALIZED_SOCKET;
    listener.connection = QSC_UNINITIALIZED_SOCKET;
    port = 0U;
    res = false;
    stage35_initialize_material();
    stage35_initialize_client_config(&clientconfig);
    stage35_initialize_server_config(&serverstate.config, &signer);

    if (stage35_create_listener(&listener, &port) == true)
    {
        serverstate.listener = &listener;
        serverstate.socketstatus = qsc_socket_exception_error;
        serverstate.tlsstatus = qsc_tls_status_failure;
        thread = qsc_async_thread_create(stage35_server_worker, &serverstate);

        if (thread != (qsc_thread)0 && stage35_connect_client(&clientsocket, port) == true)
        {
            qsc_tls_status status;

            status = qsc_tls_engine_initialize_client(clientengine, &clientconfig);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_io_attach(&clientio, clientengine, &clientsocket);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_io_handshake_ex(&clientio, STAGE35_HANDSHAKE_TIMEOUT_MS);
            }

            qsc_async_thread_wait(thread);

            res = (status == qsc_tls_status_success && serverstate.socketstatus == qsc_socket_exception_success &&
                serverstate.tlsstatus == qsc_tls_status_success && qsc_tls_engine_is_handshake_complete(clientengine) == true);
        }
        else if (thread != (qsc_thread)0)
        {
            qsc_async_thread_wait(thread);
        }
    }

    qsc_tls_engine_dispose(clientengine);
    qsc_memutils_alloc_free(clientengine);
    (void)qsc_socket_close_socket(&clientsocket);
    (void)qsc_socket_close_socket(&listener);

    return res;
}

static bool stage35_trickle_deadline_test(void)
{
    qsc_tls_client_config clientconfig;
    qsc_tls_connection* clientengine;
    qsc_tls_io_connection clientio;
    qsc_socket clientsocket = { 0 };
    qsc_socket listener = { 0 };
    qsc_thread thread = { 0 };
    stage35_trickle_state tricklestate = { 0 };
    qsc_tls_status status;
    uint64_t elapsed;
    uint64_t startms;
    uint16_t port;
    bool res;

    clientengine = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));

    if (clientengine == NULL)
    {
        return false;
    }

    qsc_memutils_clear(clientengine, sizeof(qsc_tls_connection));
    qsc_memutils_clear(&clientio, sizeof(clientio));
    clientsocket.connection = QSC_UNINITIALIZED_SOCKET;
    listener.connection = QSC_UNINITIALIZED_SOCKET;
    elapsed = 0U;
    port = 0U;
    status = qsc_tls_status_failure;
    res = false;
    stage35_initialize_client_config(&clientconfig);

    if (stage35_create_listener(&listener, &port) == true)
    {
        tricklestate.listener = &listener;
        tricklestate.socketstatus = qsc_socket_exception_error;
        thread = qsc_async_thread_create(stage35_trickle_worker, &tricklestate);

        if (thread != (qsc_thread)0 && stage35_connect_client(&clientsocket, port) == true)
        {
            (void)qsc_socket_set_option(&clientsocket, qsc_socket_protocol_socket, qsc_socket_option_receive_time_out, 1000);
            (void)qsc_socket_set_option(&clientsocket, qsc_socket_protocol_socket, qsc_socket_option_send_time_out, 1000);
            status = qsc_tls_engine_initialize_client(clientengine, &clientconfig);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_io_attach(&clientio, clientengine, &clientsocket);
            }

            if (status == qsc_tls_status_success)
            {
                startms = qsc_sysutils_system_uptime();
                status = qsc_tls_io_handshake_ex(&clientio, STAGE35_TRICKLE_TIMEOUT_MS);
                elapsed = qsc_sysutils_system_uptime() - startms;
            }

            qsc_async_thread_wait(thread);

            res = (status == qsc_tls_status_timeout && tricklestate.socketstatus == qsc_socket_exception_success &&
                elapsed >= (uint64_t)(STAGE35_TRICKLE_TIMEOUT_MS - 20U) && elapsed < 1000U);
        }
        else if (thread != (qsc_thread)0)
        {
            qsc_async_thread_wait(thread);
        }
    }

    qsc_tls_engine_dispose(clientengine);
    qsc_memutils_alloc_free(clientengine);
    (void)qsc_socket_close_socket(&clientsocket);
    (void)qsc_socket_close_socket(&listener);

    return res;
}

bool qsctest_tls_stage35_tests(void)
{
    bool socketsstarted;
    bool res;

    res = true;
    socketsstarted = qsc_socket_start_sockets();

    if (stage35_status_contract_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 35 cumulative handshake timeout status contract test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 35 cumulative handshake timeout status contract test.");
        res = false;
    }

    if (socketsstarted == true && stage35_successful_handshake_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 35 timed blocking I/O handshake completion test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 35 timed blocking I/O handshake completion test.");
        res = false;
    }

    if (socketsstarted == true && stage35_trickle_deadline_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 35 slow-trickle cumulative handshake deadline test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 35 slow-trickle cumulative handshake deadline test.");
        res = false;
    }

    if (socketsstarted == true)
    {
        (void)qsc_socket_shut_down_sockets();
    }

    return res;
}
