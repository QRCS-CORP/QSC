#include "tls_stage27_socket_options_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlssocket.h"

#define STAGE27_SOCKET_OPTION_INT32_MAX 2147483647UL
#define STAGE27_SOCKET_OPTION_INT32_OVERFLOW 2147483648UL

typedef struct stage27_log_state
{
    size_t calls;
    qsc_tls_socket_log_level lastlevel;
    qsc_tls_socket_event lastevent;
    qsc_tls_socket_status laststatus;
} stage27_log_state;

static void stage27_log_callback(qsc_tls_socket_log_level level, qsc_tls_socket_event event, const qsc_tls_socket_result* result, const char* message, void* state)
{
    stage27_log_state* ctx;

    (void)message;
    ctx = (stage27_log_state*)state;

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

static bool stage27_default_options_test(void)
{
    qsc_tls_socket_options options;
    bool res;

    res = false;
    qsc_tls_socket_options_initialize_default(&options);

    if ((options.connect_timeout_ms == 0U) && (options.handshake_timeout_ms == 30000U) &&
        (options.receive_timeout_ms == 30000U) && (options.send_timeout_ms == 30000U) &&
        (options.idle_timeout_ms == 0U))
    {
        if ((options.receive_buffer_size == QSC_TLS_SOCKET_SERVER_BUFFER_SIZE) &&
            (options.send_buffer_size == QSC_TLS_SOCKET_SERVER_BUFFER_SIZE))
        {
            if ((options.reuse_address == true) && (options.no_delay == true) &&
                (options.keep_alive == false) && (options.dual_stack == true) &&
                (options.blocking == true))
            {
                res = true;
            }
        }
    }

    return res;
}

static bool stage27_context_option_policy_test(void)
{
    static qsc_tls_socket_context ctx;
    qsc_tls_socket_options options;
    stage27_log_state logs;
    bool res;

    res = false;
    qsc_memutils_clear(&logs, sizeof(logs));
    qsc_tls_socket_context_initialize(&ctx);
    qsc_tls_socket_options_initialize_default(&options);

    if (qsc_tls_socket_context_set_log_callback(&ctx, stage27_log_callback, &logs) == qsc_tls_socket_status_success)
    {
        options.connect_timeout_ms = 1001U;
        options.handshake_timeout_ms = 2002U;
        options.receive_timeout_ms = 3003U;
        options.send_timeout_ms = 4004U;
        options.idle_timeout_ms = 5005U;
        options.receive_buffer_size = 6006U;
        options.send_buffer_size = 7007U;
        options.reuse_address = false;
        options.no_delay = false;
        options.keep_alive = true;
        options.dual_stack = false;
        options.blocking = false;

        if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_success)
        {
            if ((ctx.socketoptions.connect_timeout_ms == 1001U) && (ctx.socketoptions.handshake_timeout_ms == 2002U) &&
                (ctx.socketoptions.receive_timeout_ms == 3003U) && (ctx.socketoptions.send_timeout_ms == 4004U) &&
                (ctx.socketoptions.idle_timeout_ms == 5005U) && (ctx.socketoptions.receive_buffer_size == 6006U) &&
                (ctx.socketoptions.send_buffer_size == 7007U))
            {
                if ((ctx.socketoptions.reuse_address == false) && (ctx.socketoptions.no_delay == false) &&
                    (ctx.socketoptions.keep_alive == true) && (ctx.socketoptions.dual_stack == false) &&
                    (ctx.socketoptions.blocking == false))
                {
                    if ((logs.calls == 1U) && (logs.lastlevel == qsc_tls_socket_log_level_info) &&
                        (logs.lastevent == qsc_tls_socket_event_socket_options))
                    {
                        res = true;
                    }
                }
            }
        }
    }

    qsc_tls_socket_context_dispose(&ctx);

    return res;
}

static bool stage27_timeout_boundary_policy_test(void)
{
    static qsc_tls_socket_context ctx;
    qsc_tls_socket_options options;
    bool res;

    res = false;
    qsc_tls_socket_context_initialize(&ctx);
    qsc_tls_socket_options_initialize_default(&options);

    options.connect_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_MAX;
    options.handshake_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_MAX;
    options.receive_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_MAX;
    options.send_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_MAX;
    options.idle_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_MAX;

    if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_success)
    {
        options.connect_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_OVERFLOW;

        if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_invalid_input)
        {
            qsc_tls_socket_options_initialize_default(&options);
            options.handshake_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_OVERFLOW;

            if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_invalid_input)
            {
                qsc_tls_socket_options_initialize_default(&options);
                options.receive_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_OVERFLOW;

                if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_invalid_input)
                {
                    qsc_tls_socket_options_initialize_default(&options);
                    options.send_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_OVERFLOW;

                    if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_invalid_input)
                    {
                        qsc_tls_socket_options_initialize_default(&options);
                        options.idle_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_OVERFLOW;

                        if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_invalid_input)
                        {
                            qsc_tls_socket_options_initialize_default(&options);
                            options.connect_timeout_ms = 0U;
                            options.handshake_timeout_ms = 0U;
                            options.receive_timeout_ms = 0U;
                            options.send_timeout_ms = 0U;
                            options.idle_timeout_ms = 0U;

                            if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_success)
                            {
                                res = true;
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

static bool stage27_buffer_boundary_policy_test(void)
{
    static qsc_tls_socket_context ctx;
    qsc_tls_socket_options options;
    bool res;

    res = false;
    qsc_tls_socket_context_initialize(&ctx);
    qsc_tls_socket_options_initialize_default(&options);

    options.receive_buffer_size = (size_t)STAGE27_SOCKET_OPTION_INT32_MAX;
    options.send_buffer_size = (size_t)STAGE27_SOCKET_OPTION_INT32_MAX;

    if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_success)
    {
        options.receive_buffer_size = (size_t)STAGE27_SOCKET_OPTION_INT32_MAX + 1U;

        if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_invalid_input)
        {
            qsc_tls_socket_options_initialize_default(&options);
            options.send_buffer_size = (size_t)STAGE27_SOCKET_OPTION_INT32_MAX + 1U;

            if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_invalid_input)
            {
                qsc_tls_socket_options_initialize_default(&options);
                options.receive_buffer_size = 0U;
                options.send_buffer_size = 0U;

                if (qsc_tls_socket_context_set_socket_options(&ctx, &options) == qsc_tls_socket_status_success)
                {
                    res = true;
                }
            }
        }
    }

    qsc_tls_socket_context_dispose(&ctx);

    return res;
}

static bool stage27_connection_option_policy_test(void)
{
    static qsc_tls_socket_connection conn;
    qsc_tls_socket_options options;
    bool res;

    res = false;
    qsc_tls_socket_connection_initialize(&conn);
    qsc_tls_socket_options_initialize_default(&options);

    options.receive_timeout_ms = 111U;
    options.send_timeout_ms = 222U;
    options.handshake_timeout_ms = 333U;
    options.keep_alive = true;
    options.blocking = false;

    if (qsc_tls_socket_connection_set_socket_options(&conn, &options) == qsc_tls_socket_status_success)
    {
        if ((conn.socketoptions.receive_timeout_ms == 111U) && (conn.socketoptions.send_timeout_ms == 222U) &&
            (conn.socketoptions.handshake_timeout_ms == 333U) && (conn.socketoptions.keep_alive == true) &&
            (conn.socketoptions.blocking == false))
        {
            options.receive_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_OVERFLOW;

            if (qsc_tls_socket_connection_set_socket_options(&conn, &options) == qsc_tls_socket_status_invalid_input)
            {
                if (conn.socketoptions.receive_timeout_ms == 111U)
                {
                    res = true;
                }
            }
        }
    }

    qsc_tls_socket_connection_dispose(&conn);

    return res;
}

static bool stage27_listener_option_policy_test(void)
{
    static qsc_tls_socket_listener listener;
    qsc_tls_socket_options options;
    bool res;

    res = false;
    qsc_tls_socket_listener_initialize(&listener);
    qsc_tls_socket_options_initialize_default(&options);

    if (qsc_tls_socket_listener_set_options(&listener, false, false, 1234U, 5678U) == qsc_tls_socket_status_success)
    {
        if ((listener.socketoptions.reuse_address == false) && (listener.socketoptions.no_delay == false) &&
            (listener.socketoptions.receive_timeout_ms == 1234U) && (listener.socketoptions.send_timeout_ms == 5678U))
        {
            options.reuse_address = true;
            options.no_delay = true;
            options.keep_alive = true;
            options.receive_timeout_ms = 4321U;
            options.send_timeout_ms = 8765U;

            if (qsc_tls_socket_listener_set_socket_options(&listener, &options) == qsc_tls_socket_status_success)
            {
                if ((listener.socketoptions.reuse_address == true) && (listener.socketoptions.no_delay == true) &&
                    (listener.socketoptions.keep_alive == true) && (listener.socketoptions.receive_timeout_ms == 4321U) &&
                    (listener.socketoptions.send_timeout_ms == 8765U))
                {
                    options.send_timeout_ms = (uint32_t)STAGE27_SOCKET_OPTION_INT32_OVERFLOW;

                    if (qsc_tls_socket_listener_set_socket_options(&listener, &options) == qsc_tls_socket_status_invalid_input)
                    {
                        if (listener.socketoptions.send_timeout_ms == 8765U)
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

bool qsctest_tls_stage27_tests(void)
{
    bool res;

    res = true;

    if (stage27_default_options_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 27 socket option default policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 27 socket option default policy test.");
        res = false;
    }

    if (stage27_context_option_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 27 socket context option policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 27 socket context option policy test.");
        res = false;
    }

    if (stage27_timeout_boundary_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 27 timeout boundary policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 27 timeout boundary policy test.");
        res = false;
    }

    if (stage27_buffer_boundary_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 27 socket buffer boundary policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 27 socket buffer boundary policy test.");
        res = false;
    }

    if (stage27_connection_option_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 27 socket connection option policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 27 socket connection option policy test.");
        res = false;
    }

    if (stage27_listener_option_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 27 socket listener option policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 27 socket listener option policy test.");
        res = false;
    }

    return res;
}
