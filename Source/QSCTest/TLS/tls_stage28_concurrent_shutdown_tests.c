#include "tls_stage28_concurrent_shutdown_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlssocket.h"

static bool stage28_server_initialization_cleanup_test(void)
{
    static qsc_tls_socket_server server;
    bool res;

    res = false;
    qsc_tls_socket_server_initialize(&server);

    if ((server.initialized == true) && (server.listener.initialized == true) &&
        (server.maxclients == QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX) &&
        (server.running == false) && (server.concurrent == false))
    {
        size_t i;
        bool clean;

        clean = true;

        for (i = 0U; i < QSC_TLS_SOCKET_SERVER_CONNECTIONS_MAX; ++i)
        {
            if ((server.active[i] != false) || (server.started[i] != false) ||
                (server.workerstates[i].server != NULL) || (server.workerstates[i].index != 0U))
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
        server.active[0U] = true;

        if (qsc_tls_socket_server_set_max_clients(&server, 1U) == qsc_tls_socket_status_policy_rejected)
        {
            server.maxclients = 2U;
            qsc_tls_socket_server_stop(&server);

            if ((server.active[0U] == false) &&
                (qsc_tls_socket_server_set_max_clients(&server, 1U) == qsc_tls_socket_status_success) &&
                (server.maxclients == 1U))
            {
                res = true;
            }
        }
    }

    qsc_tls_socket_server_dispose(&server);

    return res;
}

static bool stage28_server_stop_active_slot_cleanup_test(void)
{
    static qsc_tls_socket_server server;
    bool res;

    res = false;
    qsc_tls_socket_server_initialize(&server);

    if (qsc_tls_socket_server_set_max_clients(&server, 3U) == qsc_tls_socket_status_success)
    {
        qsc_tls_socket_connection_initialize(&server.connections[0U]);
        qsc_tls_socket_connection_initialize(&server.connections[1U]);
        server.listener.listening = true;
        server.running = true;
        server.concurrent = true;
        server.active[0U] = true;
        server.active[1U] = true;
        server.connections[0U].connected = true;
        server.connections[1U].connected = true;
        server.connections[0U].handshaked = true;
        server.connections[1U].handshaked = true;
        server.connections[0U].owns_socket = false;
        server.connections[1U].owns_socket = false;
        server.workerstates[0U].server = &server;
        server.workerstates[1U].server = &server;
        server.workerstates[0U].index = 0U;
        server.workerstates[1U].index = 1U;

        qsc_tls_socket_server_stop(&server);

        if ((server.running == false) && (server.listener.listening == false) &&
            (server.active[0U] == false) && (server.active[1U] == false) &&
            (server.workerstates[0U].server == NULL) && (server.workerstates[1U].server == NULL) &&
            (server.workerstates[0U].index == 0U) && (server.workerstates[1U].index == 0U))
        {
            res = true;
        }
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
        server.listener.listening = true;
        server.running = true;
        server.concurrent = true;
        server.started[0U] = true;
        server.active[0U] = false;
        server.workerstates[0U].server = &server;
        server.workerstates[0U].index = 0U;

        qsc_tls_socket_server_stop(&server);

        if ((server.running == false) && (server.started[0U] == false) &&
            (server.active[0U] == false) && (server.workerthreads[0U] == (qsc_thread)0) &&
            (server.listener.listening == false))
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
    listener.listening = true;

    qsc_tls_socket_listener_close(&listener);

    if (listener.listening == false)
    {
        qsc_tls_socket_listener_close(&listener);

        if (listener.listening == false)
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
    server.listener.listening = true;
    server.running = true;
    server.concurrent = true;

    qsc_tls_socket_server_stop(&server);
    qsc_tls_socket_server_stop(&server);

    if ((server.running == false) && (server.listener.listening == false) &&
        (server.active[0U] == false) && (server.started[0U] == false))
    {
        res = true;
    }

    qsc_tls_socket_server_dispose(&server);

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

    if (stage28_server_stop_active_slot_cleanup_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 28 server stop active-slot cleanup test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 28 server stop active-slot cleanup test.");
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

    return res;
}
