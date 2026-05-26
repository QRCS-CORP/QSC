#include "tls_stage25_framed_message_tests.h"
#include "../testutils.h"
#include "intutils.h"
#include "memutils.h"
#include "tlssocket.h"

typedef struct stage25_log_state
{
    size_t calls;
    qsc_tls_socket_log_level lastlevel;
    qsc_tls_socket_event lastevent;
    qsc_tls_socket_status laststatus;
} stage25_log_state;

static void stage25_log_callback(qsc_tls_socket_log_level level, qsc_tls_socket_event event, const qsc_tls_socket_result* result, const char* message, void* state)
{
    stage25_log_state* ctx;

    (void)message;
    ctx = (stage25_log_state*)state;

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

static bool stage25_frame_constants_and_header_test(void)
{
    uint8_t hdr[QSC_TLS_SOCKET_FRAME_HEADER_SIZE] = { 0U };
    bool res;

    res = false;

    if ((QSC_TLS_SOCKET_FRAME_HEADER_SIZE == 4U) && (QSC_TLS_SOCKET_FRAME_SIZE_MAX == 16777216U))
    {
        qsc_intutils_be32to8(hdr, 0x00010203UL);

        if ((hdr[0U] == 0x00U) && (hdr[1U] == 0x01U) && (hdr[2U] == 0x02U) && (hdr[3U] == 0x03U))
        {
            if (qsc_intutils_be8to32(hdr) == 0x00010203UL)
            {
                qsc_intutils_be32to8(hdr, (uint32_t)QSC_TLS_SOCKET_FRAME_SIZE_MAX);

                if (qsc_intutils_be8to32(hdr) == (uint32_t)QSC_TLS_SOCKET_FRAME_SIZE_MAX)
                {
                    res = true;
                }
            }
        }
    }

    return res;
}

static bool stage25_frame_send_input_policy_test(void)
{
    static qsc_tls_socket_connection conn;
    uint8_t payload[1U] = { 0xA5U };
    qsc_tls_socket_status st;
    bool res;

    res = false;
    qsc_tls_socket_connection_initialize(&conn);

    if (qsc_tls_socket_send_frame(&conn, payload, QSC_TLS_SOCKET_FRAME_SIZE_MAX + 1U) == qsc_tls_socket_status_invalid_input)
    {
        st = qsc_tls_socket_send_frame(&conn, NULL, 0U);

        if (st == qsc_tls_socket_status_not_initialized)
        {
            res = true;
        }
    }

    qsc_tls_socket_connection_dispose(&conn);

    return res;
}

static bool stage25_frame_receive_input_policy_test(void)
{
    static qsc_tls_socket_connection conn;
    uint8_t output[1U] = { 0U };
    size_t read;
    qsc_tls_socket_status st;
    bool res;

    res = false;
    read = 1U;
    qsc_tls_socket_connection_initialize(&conn);

    read = 1U;
    st = qsc_tls_socket_receive_frame(&conn, NULL, 0U, &read);

    if ((st == qsc_tls_socket_status_not_initialized) && (read == 0U))
    {
        read = 1U;

        if (qsc_tls_socket_receive_frame(&conn, output, sizeof(output), &read) == qsc_tls_socket_status_not_initialized)
        {
            if (read == 0U)
            {
                res = true;
            }
        }
    }

    qsc_tls_socket_connection_dispose(&conn);

    return res;
}

static bool stage25_unestablished_connection_rejection_test(void)
{
    static qsc_tls_socket_connection conn;
    uint8_t payload[4U] = { 1U, 2U, 3U, 4U };
    uint8_t output[4U] = { 0U };
    size_t read;
    bool res;

    res = false;
    read = 4U;
    qsc_tls_socket_connection_initialize(&conn);

    if (qsc_tls_socket_send_frame(&conn, payload, sizeof(payload)) == qsc_tls_socket_status_not_initialized)
    {
        if (qsc_tls_socket_receive_frame(&conn, output, sizeof(output), &read) == qsc_tls_socket_status_not_initialized)
        {
            if (read == 0U)
            {
                res = true;
            }
        }
    }

    qsc_tls_socket_connection_dispose(&conn);

    return res;
}

static bool stage25_frame_event_logging_test(void)
{
    static qsc_tls_socket_connection conn;
    stage25_log_state logs;
    uint8_t payload[2U] = { 0xC0U, 0xDEU };
    uint8_t output[2U] = { 0U };
    size_t read;
    bool res;

    res = false;
    read = 0U;
    qsc_memutils_clear(&logs, sizeof(logs));
    qsc_tls_socket_connection_initialize(&conn);

    if (qsc_tls_socket_connection_set_log_callback(&conn, stage25_log_callback, &logs) == qsc_tls_socket_status_success)
    {
        if (qsc_tls_socket_send_frame(&conn, payload, sizeof(payload)) == qsc_tls_socket_status_not_initialized)
        {
            if ((logs.calls == 1U) && (logs.lastlevel == qsc_tls_socket_log_level_error) &&
                (logs.lastevent == qsc_tls_socket_event_frame_send) && (logs.laststatus == qsc_tls_socket_status_not_initialized))
            {
                if (qsc_tls_socket_receive_frame(&conn, output, sizeof(output), &read) == qsc_tls_socket_status_not_initialized)
                {
                    if ((logs.calls == 2U) && (logs.lastlevel == qsc_tls_socket_log_level_error) &&
                        (logs.lastevent == qsc_tls_socket_event_frame_receive) && (logs.laststatus == qsc_tls_socket_status_not_initialized) &&
                        (read == 0U))
                    {
                        res = true;
                    }
                }
            }
        }
    }

    qsc_tls_socket_connection_dispose(&conn);

    return res;
}

bool qsctest_tls_stage25_tests(void)
{
    bool res;

    res = true;

    if (stage25_frame_constants_and_header_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 25 framed-message constants and header test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 25 framed-message constants and header test.");
        res = false;
    }

    if (stage25_frame_send_input_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 25 framed-message send input policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 25 framed-message send input policy test.");
        res = false;
    }

    if (stage25_frame_receive_input_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 25 framed-message receive input policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 25 framed-message receive input policy test.");
        res = false;
    }

    if (stage25_unestablished_connection_rejection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 25 framed-message unestablished connection rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 25 framed-message unestablished connection rejection test.");
        res = false;
    }

    if (stage25_frame_event_logging_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 25 framed-message event logging test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 25 framed-message event logging test.");
        res = false;
    }

    return res;
}
