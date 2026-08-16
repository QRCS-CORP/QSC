#include "tls_stage28_concurrent_shutdown_tests.h"
#include "../testutils.h"
#include "async.h"
#include "memutils.h"
#include "tlssocket.h"

typedef struct
{
    qsc_tls_socket_server* server;
    qsc_tls_socket_status status;
} stage28_server_thread_state;

static void stage28_server_thread(void* state)
{
    stage28_server_thread_state* tstate;

    tstate = (stage28_server_thread_state*)state;

    if (tstate != NULL && tstate->server != NULL)
    {
        tstate->status = qsc_tls_socket_server_start_concurrent(tstate->server);
    }
}

static void stage28_stop_thread(void* state)
{
    qsc_tls_socket_server* server;

    server = (qsc_tls_socket_server*)state;

    if (server != NULL)
    {
        qsc_tls_socket_server_stop(server);
    }
}

static bool stage28_server_initialization_cleanup_test(void)
{
    static qsc_tls_socket_server server;
    bool res;

    res = false;
    qsc_tls_socket_server_initialize(&server);

    if ((server.initialized == true) && (server.listener.initialized == true) &&
        (server.maxclients == QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX) &&
        (qsc_async_atomic_bool_load(&server.running) == false) && (server.concurrent == false))
    {
        size_t i;
        bool clean;

        clean = true;

        for (i = 0U; i < QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX; ++i)
        {
            if ((qsc_async_atomic_bool_load(&server.active[i]) != false) || (qsc_async_atomic_bool_load(&server.accepted[i]) != false) ||
                (qsc_async_atomic_bool_load(&server.started[i]) != false) || (server.workerstates[i].server != NULL) || (server.workerstates[i].index != 0U))
            {
                clean = false;
                break;
            }
        }

        if (clean == true)
        {
            res = true;
        }
    }

    qsc_tls_socket_server_dispose(&server);

    return res;
}

static bool stage28_server_max_client_active_rejection_test(void)
{
    static qsc_tls_socket_server server;
    bool res;

    res = false;
    qsc_tls_socket_server_initialize(&server);

    if (qsc_tls_socket_server_set_max_clients(&server, 2U) == qsc_tls_socket_status_success)
    {
        qsc_async_atomic_bool_store(&server.active[0U], true);

        if (qsc_tls_socket_server_set_max_clients(&server, 1U) == qsc_tls_socket_status_policy_rejected)
        {
            qsc_async_atomic_bool_store(&server.active[0U], false);

            if ((qsc_tls_socket_server_set_max_clients(&server, 1U) == qsc_tls_socket_status_success) && (server.maxclients == 1U))
            {
                res = true;
            }
        }
    }

    qsc_tls_socket_server_dispose(&server);

    return res;
}

static bool stage28_server_stop_cancellation_handoff_test(void)
{
    static qsc_tls_socket_server server;
    bool res;

    res = false;
    qsc_tls_socket_server_initialize(&server);

    if (qsc_tls_socket_server_set_max_clients(&server, 2U) == qsc_tls_socket_status_success)
    {
        qsc_tls_socket_connection_initialize(&server.connections[0U]);
        qsc_async_atomic_bool_store(&server.listener.listening, true);
        qsc_async_atomic_bool_store(&server.active[0U], true);
        qsc_async_atomic_bool_store(&server.accepted[0U], true);
        server.connections[0U].connected = true;
        server.connections[0U].handshaked = true;
        server.connections[0U].owns_socket = false;
        server.workerstates[0U].server = &server;
        server.workerstates[0U].index = 0U;

        qsc_tls_socket_server_stop(&server);

        if ((qsc_async_atomic_bool_load(&server.listener.listening) == false) &&
            (qsc_async_atomic_bool_load(&server.connections[0U].cancelrequested) == true) &&
            (qsc_async_atomic_bool_load(&server.active[0U]) == true) &&
            (qsc_async_atomic_bool_load(&server.accepted[0U]) == true) &&
            (server.connections[0U].connected == true))
        {
            res = true;
        }

        qsc_tls_socket_connection_dispose(&server.connections[0U]);
        server.workerstates[0U].server = NULL;
        server.workerstates[0U].index = 0U;
        qsc_async_atomic_bool_store(&server.accepted[0U], false);
        qsc_async_atomic_bool_store(&server.active[0U], false);
    }

    qsc_tls_socket_server_dispose(&server);

    return res;
}

static bool stage28_server_stop_started_marker_cleanup_test(void)
{
    static qsc_tls_socket_server server;
    bool res;

    res = false;
    qsc_tls_socket_server_initialize(&server);

    if (qsc_tls_socket_server_set_max_clients(&server, 2U) == qsc_tls_socket_status_success)
    {
        qsc_async_atomic_bool_store(&server.listener.listening, true);
        qsc_async_atomic_bool_store(&server.started[0U], true);
        qsc_async_atomic_bool_store(&server.active[0U], false);
        server.workerstates[0U].server = &server;
        server.workerstates[0U].index = 0U;

        qsc_tls_socket_server_stop(&server);

        if ((qsc_async_atomic_bool_load(&server.started[0U]) == false) &&
            (qsc_async_atomic_bool_load(&server.active[0U]) == false) &&
            (server.workerthreads[0U] == (qsc_thread)0) &&
            (qsc_async_atomic_bool_load(&server.listener.listening) == false))
        {
            res = true;
        }
    }

    qsc_tls_socket_server_dispose(&server);

    return res;
}

static bool stage28_listener_close_idempotent_test(void)
{
    qsc_tls_socket_listener listener;
    bool res;

    res = false;
    qsc_tls_socket_listener_initialize(&listener);
    qsc_async_atomic_bool_store(&listener.listening, true);

    qsc_tls_socket_listener_close(&listener);

    if (qsc_async_atomic_bool_load(&listener.listening) == false)
    {
        qsc_tls_socket_listener_close(&listener);

        if (qsc_async_atomic_bool_load(&listener.listening) == false)
        {
            res = true;
        }
    }

    return res;
}

static bool stage28_repeated_stop_policy_test(void)
{
    static qsc_tls_socket_server server;
    bool res;

    res = false;
    qsc_tls_socket_server_initialize(&server);
    qsc_async_atomic_bool_store(&server.listener.listening, true);

    qsc_tls_socket_server_stop(&server);
    qsc_tls_socket_server_stop(&server);

    if ((qsc_async_atomic_bool_load(&server.running) == false) && (qsc_async_atomic_bool_load(&server.listener.listening) == false) &&
        (qsc_async_atomic_bool_load(&server.active[0U]) == false) && (qsc_async_atomic_bool_load(&server.started[0U]) == false))
    {
        res = true;
    }

    qsc_tls_socket_server_dispose(&server);

    return res;
}

static bool stage28_concurrent_accept_stop_test(void)
{
    static qsc_tls_socket_context context;
    static qsc_tls_socket_server server;
    stage28_server_thread_state state;
    qsc_thread thread;
    bool res;
    size_t i;

    res = false;
    qsc_tls_socket_context_initialize(&context);
    qsc_tls_socket_server_initialize(&server);
    state.server = &server;
    state.status = qsc_tls_socket_status_invalid_input;

    if (qsc_tls_socket_server_configure(&server, &context, "127.0.0.1", 46328U, qsc_socket_address_family_ipv4) == qsc_tls_socket_status_success)
    {
        thread = qsc_async_thread_create(stage28_server_thread, &state);

        if (thread != (qsc_thread)0)
        {
            for (i = 0U; i < 200U; ++i)
            {
                if (qsc_async_atomic_bool_load(&server.running) == true)
                {
                    break;
                }

                qsc_async_thread_sleep(1U);
            }

            if (qsc_async_atomic_bool_load(&server.running) == true)
            {
                qsc_tls_socket_server_stop(&server);
                qsc_async_thread_wait(thread);

                if ((qsc_async_atomic_bool_load(&server.running) == false) &&
                    (qsc_async_atomic_bool_load(&server.listener.listening) == false) &&
                    (qsc_async_atomic_bool_load(&server.active[0U]) == false))
                {
                    res = true;
                }
            }
            else
            {
                qsc_tls_socket_server_stop(&server);
                qsc_async_thread_wait(thread);
            }
        }
    }

    qsc_tls_socket_server_dispose(&server);
    qsc_tls_socket_context_dispose(&context);

    return res;
}

static bool stage28_concurrent_repeated_stop_test(void)
{
    static qsc_tls_socket_context context;
    static qsc_tls_socket_server server;
    stage28_server_thread_state state;
    qsc_thread serverthread;
    qsc_thread stopthread1;
    qsc_thread stopthread2;
    bool res;
    size_t i;

    res = false;
    qsc_tls_socket_context_initialize(&context);
    qsc_tls_socket_server_initialize(&server);
    state.server = &server;
    state.status = qsc_tls_socket_status_invalid_input;

    if (qsc_tls_socket_server_configure(&server, &context, "127.0.0.1", 46330U, qsc_socket_address_family_ipv4) == qsc_tls_socket_status_success)
    {
        serverthread = qsc_async_thread_create(stage28_server_thread, &state);

        if (serverthread != (qsc_thread)0)
        {
            for (i = 0U; i < 200U; ++i)
            {
                if (qsc_async_atomic_bool_load(&server.running) == true)
                {
                    break;
                }

                qsc_async_thread_sleep(1U);
            }

            if (qsc_async_atomic_bool_load(&server.running) == true)
            {
                stopthread1 = qsc_async_thread_create(stage28_stop_thread, &server);
                stopthread2 = qsc_async_thread_create(stage28_stop_thread, &server);

                if (stopthread1 != (qsc_thread)0 && stopthread2 != (qsc_thread)0)
                {
                    qsc_async_thread_wait(stopthread1);
                    qsc_async_thread_wait(stopthread2);
                    qsc_async_thread_wait(serverthread);

                    if ((qsc_async_atomic_bool_load(&server.running) == false) &&
                        (qsc_async_atomic_bool_load(&server.listener.listening) == false) &&
                        (qsc_async_atomic_bool_load(&server.active[0U]) == false))
                    {
                        res = true;
                    }
                }
                else
                {
                    qsc_tls_socket_server_stop(&server);
                    qsc_async_thread_wait(serverthread);
                }
            }
            else
            {
                qsc_tls_socket_server_stop(&server);
                qsc_async_thread_wait(serverthread);
            }
        }
    }

    qsc_tls_socket_server_dispose(&server);
    qsc_tls_socket_context_dispose(&context);

    return res;
}

bool qsctest_tls_stage28_tests(void)
{
    bool res;

    res = true;

    if (stage28_server_initialization_cleanup_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 28 server initialization cleanup test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 28 server initialization cleanup test.");
        res = false;
    }

    if (stage28_server_max_client_active_rejection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 28 server max-client active rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 28 server max-client active rejection test.");
        res = false;
    }

    if (stage28_server_stop_cancellation_handoff_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 28 server stop cancellation handoff test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 28 server stop cancellation handoff test.");
        res = false;
    }

    if (stage28_server_stop_started_marker_cleanup_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 28 server stop started-marker cleanup test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 28 server stop started-marker cleanup test.");
        res = false;
    }

    if (stage28_listener_close_idempotent_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 28 listener close idempotent test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 28 listener close idempotent test.");
        res = false;
    }

    if (stage28_repeated_stop_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 28 repeated stop policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 28 repeated stop policy test.");
        res = false;
    }

    if (stage28_concurrent_accept_stop_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 28 concurrent accept-stop synchronization test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 28 concurrent accept-stop synchronization test.");
        res = false;
    }

    if (stage28_concurrent_repeated_stop_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 28 concurrent repeated-stop synchronization test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 28 concurrent repeated-stop synchronization test.");
        res = false;
    }

    return res;
}
