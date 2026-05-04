#include "tls_stage19_socket_wrapper_tests.h"
#include "../testutils.h"
#include "intutils.h"
#include "memutils.h"
#include "tlssocket.h"

typedef struct stage19_log_state
{
    size_t calls;
    qsc_tls_socket_log_level lastlevel;
    qsc_tls_socket_event lastevent;
    qsc_tls_socket_status laststatus;
} stage19_log_state;

static void stage19_log_callback(qsc_tls_socket_log_level level, qsc_tls_socket_event event, const qsc_tls_socket_result* result, const char* message, void* state)
{
    stage19_log_state* ctx;

    (void)message;
    ctx = (stage19_log_state*)state;

    if (ctx != NULL)
    {
        ctx->calls += 1U;
        ctx->lastlevel = level;
        ctx->lastevent = event;

        if (result != NULL)
        {
            ctx->laststatus = result->status;
        }
    }
}

static void stage19_on_connect(qsc_tls_socket_connection* connection, void* state)
{
    size_t* counter;

    (void)connection;
    counter = (size_t*)state;

    if (counter != NULL)
    {
        *counter += 1U;
    }
}

static void stage19_on_receive(qsc_tls_socket_connection* connection, const uint8_t* message, size_t msglen, void* state)
{
    size_t* counter;

    (void)connection;
    (void)message;
    (void)msglen;
    counter = (size_t*)state;

    if (counter != NULL)
    {
        *counter += 1U;
    }
}

static void stage19_on_disconnect(qsc_tls_socket_connection* connection, void* state)
{
    size_t* counter;

    (void)connection;
    counter = (size_t*)state;

    if (counter != NULL)
    {
        *counter += 1U;
    }
}

static void stage19_on_error(qsc_tls_socket_connection* connection, qsc_tls_socket_status status, void* state)
{
    size_t* counter;

    (void)connection;
    (void)status;
    counter = (size_t*)state;

    if (counter != NULL)
    {
        *counter += 1U;
    }
}

static bool stage19_context_policy_test(void)
{
    qsc_tls_socket_context ctx;
    qsc_tls_cipher_suite suites[1U];
    qsc_tls_named_group groups[1U];
    qsc_tls_signature_scheme sigs[1U];
    bool res;

    res = false;
    qsc_tls_socket_context_initialize(&ctx);

    if (ctx.initialized == true)
    {
        if (qsc_tls_socket_context_set_default_client_policy(&ctx) == qsc_tls_socket_status_success)
        {
            if ((ctx.ciphersuitecount == 3U) && (ctx.groupcount == 2U) && (ctx.sigschemecount == 3U))
            {
                if ((ctx.ciphersuites[0U] == qsc_tls_cipher_suite_tls_aes_256_gcm_sha384) && (ctx.groups[0U] == qsc_tls_group_x25519) &&
                    (ctx.sigschemes[0U] == qsc_tls_sig_ecdsa_secp256r1_sha256))
                {
                    if (qsc_tls_socket_context_set_mlkem_hybrid_policy(&ctx) == qsc_tls_socket_status_success)
                    {
                        if ((ctx.groupcount == 3U) && (ctx.groups[0U] == qsc_tls_group_x25519_mlkem768) && (ctx.groups[1U] == qsc_tls_group_x25519))
                        {
                            if ((qsc_tls_socket_context_set_experimental_pqc_policy(&ctx) == qsc_tls_socket_status_success))
                            {
                                if ((ctx.groupcount == 4U) && (ctx.groups[1U] == qsc_tls_group_mlkem768) && (ctx.sigschemecount == 6U) && (ctx.sigschemes[0U] == qsc_tls_sig_mldsa65))
                                {
                                    suites[0U] = qsc_tls_cipher_suite_tls_aes_128_gcm_sha256;
                                    groups[0U] = qsc_tls_group_secp256r1;
                                    sigs[0U] = qsc_tls_sig_ecdsa_secp256r1_sha256;

                                    if (qsc_tls_socket_context_set_cipher_suites(&ctx, suites, 1U) == qsc_tls_socket_status_success)
                                    {
                                        if ((ctx.ciphersuitecount == 1U) && (ctx.ciphersuites[0U] == suites[0U]))
                                        {
                                            if (qsc_tls_socket_context_set_named_groups(&ctx, groups, 1U) == qsc_tls_socket_status_success)
                                            {
                                                if ((ctx.groupcount == 1U) && (ctx.groups[0U] == groups[0U]))
                                                {
                                                    if (qsc_tls_socket_context_set_signature_schemes(&ctx, sigs, 1U) == qsc_tls_socket_status_success)
                                                    {
                                                        if ((ctx.sigschemecount == 1U) && (ctx.sigschemes[0U] == sigs[0U]))
                                                        {
                                                            if (qsc_tls_socket_context_set_cipher_suites(&ctx, suites, 0U) == qsc_tls_socket_status_invalid_input)
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
                }
            }
        }
    }

    qsc_tls_socket_context_dispose(&ctx);

    return res;
}

static bool stage19_options_ticket_log_test(void)
{
    qsc_tls_socket_context ctx;
    qsc_tls_socket_connection conn;
    qsc_tls_socket_options options;
    qsc_tls_socket_ticket_policy policy;
    qsc_tls_session_ticket ticket;
    stage19_log_state logs;
    bool res;

    res = false;
    qsc_memutils_clear(&logs, sizeof(logs));
    qsc_memutils_clear(&ticket, sizeof(ticket));
    qsc_tls_socket_context_initialize(&ctx);
    qsc_tls_socket_connection_initialize(&conn);

    qsc_tls_socket_options_initialize_default(&options);

    if ((options.receive_timeout_ms == 30000U) && (options.send_timeout_ms == 30000U) && (options.handshake_timeout_ms == 30000U) &&
        (options.reuse_address == true) && (options.no_delay == true) && (options.blocking == true))
    {
        if ((qsc_tls_socket_context_set_log_callback(&ctx, stage19_log_callback, &logs) == qsc_tls_socket_status_success))
        {
            options.receive_timeout_ms = 1111U;
            options.send_timeout_ms = 2222U;
            options.handshake_timeout_ms = 3333U;
            options.keep_alive = true;

            if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_success)
            {
                if ((ctx.socketoptions.receive_timeout_ms == 1111U) && (ctx.socketoptions.send_timeout_ms == 2222U) &&
                    (ctx.socketoptions.handshake_timeout_ms == 3333U) && (ctx.socketoptions.keep_alive == true))
                {
                    if ((logs.calls != 0U) && (logs.lastevent == qsc_tls_socket_event_socket_options))
                    {
                        qsc_tls_socket_ticket_policy_initialize_default(&policy);

                        if ((policy.enabled == false) && (policy.allow_early_data == false) && (policy.auto_send_server_ticket == false) && (policy.lifetime_seconds == 86400U))
                        {
                            policy.enabled = true;
                            policy.allow_early_data = true;
                            policy.auto_send_server_ticket = true;
                            policy.lifetime_seconds = 7200U;
                            policy.renewal_interval_seconds = 3600U;

                            if (qsc_tls_socket_context_set_session_ticket_policy(&ctx, &policy) == qsc_tls_socket_status_success)
                            {
                                if ((ctx.ticketpolicy.enabled == true) && (ctx.ticketpolicy.allow_early_data == true) &&
                                    (ctx.ticketpolicy.auto_send_server_ticket == true) && (ctx.ticketpolicy.lifetime_seconds == 7200U))
                                {
                                    ticket.ticketlen = 4U;
                                    ticket.ticket[0U] = 1U;
                                    ticket.ticket[1U] = 2U;
                                    ticket.ticket[2U] = 3U;
                                    ticket.ticket[3U] = 4U;
                                    ticket.resumptionsecretlen = 32U;
                                    ticket.resumptionsecret[0U] = 0xA5U;
                                    ticket.suite = qsc_tls_cipher_suite_tls_aes_128_gcm_sha256;

                                    if (qsc_tls_socket_context_set_session_ticket(&ctx, &ticket) == qsc_tls_socket_status_success)
                                    {
                                        if ((ctx.hassessionticket == true) && (ctx.ticketpolicy.enabled == true) && (ctx.sessionticket.ticketlen == 4U) && (ctx.sessionticket.ticket[3U] == 4U))
                                        {
                                            qsc_tls_socket_context_clear_session_ticket(&ctx);

                                            if (ctx.hassessionticket == false)
                                            {
                                                if (qsc_tls_socket_connection_set_socket_options(&conn, &options) == qsc_tls_socket_status_success)
                                                {
                                                    if (conn.socketoptions.receive_timeout_ms == 1111U)
                                                    {
                                                        if (qsc_tls_socket_connection_set_log_callback(&conn, stage19_log_callback, &logs) == qsc_tls_socket_status_success)
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
            }
        }
    }

    qsc_tls_socket_connection_dispose(&conn);
    qsc_tls_socket_context_dispose(&ctx);

    return res;
}

static bool stage19_peer_server_control_test(void)
{
    qsc_tls_socket_connection conn;
    qsc_tls_socket_peer_info peer;
    qsc_tls_socket_server server;
    qsc_tls_socket_status st;
    size_t cbcount;
    bool res;

    res = true;
    cbcount = 0U;
    qsc_tls_socket_connection_initialize(&conn);

    st = qsc_tls_socket_get_peer_info(&conn, &peer);

    if ((st == qsc_tls_socket_status_success) && (peer.authenticated == false) && (peer.chain_valid == false) &&
        (peer.psk_accepted == false) && (peer.verify_status == QSC_X509_VERIFY_STATUS_SUCCESS))
    {
        if (qsc_tls_socket_connection_get_session_ticket(&conn, &conn.lastticket) == qsc_tls_socket_status_not_initialized)
        {
            qsc_tls_socket_server_initialize(&server);

            if ((server.initialized == true) && (server.maxclients == QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX))
            {
                if (qsc_tls_socket_server_set_callbacks(&server, stage19_on_connect, stage19_on_receive, stage19_on_disconnect, stage19_on_error, &cbcount) == qsc_tls_socket_status_success)
                {
                    if ((server.onconnect != NULL) && (server.onreceive != NULL) && (server.ondisconnect != NULL) && (server.onerror != NULL) && (server.callbackstate == &cbcount))
                    {
                        if (qsc_tls_socket_server_set_max_clients(&server, 2U) == qsc_tls_socket_status_success)
                        {
                            if (server.maxclients == 2U)
                            {
                                if (qsc_tls_socket_server_set_max_clients(&server, 0U) == qsc_tls_socket_status_invalid_input)
                                {
                                    if (qsc_tls_socket_server_start(&server) == qsc_tls_socket_status_not_initialized)
                                    {
                                        if (qsc_tls_socket_server_start_concurrent(&server) == qsc_tls_socket_status_not_initialized)
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

            qsc_tls_socket_server_stop(&server);
            qsc_tls_socket_server_dispose(&server);
        }
    }


    qsc_tls_socket_connection_dispose(&conn);

    return res;
}

bool qsctest_tls_stage19_tests(void)
{
    bool res;

    res = true;

    if (stage19_context_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 19 socket wrapper context policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 19 socket wrapper context policy test.");
        res = false;
    }

    if (stage19_options_ticket_log_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 19 socket wrapper options, ticket, and logging test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 19 socket wrapper options, ticket, and logging test.");
        res = false;
    }

    if (stage19_peer_server_control_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 19 socket wrapper peer and server-control test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 19 socket wrapper peer and server-control test.");
        res = false;
    }

    return res;
}
