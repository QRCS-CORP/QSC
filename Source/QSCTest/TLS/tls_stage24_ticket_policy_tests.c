#include "tls_stage24_ticket_policy_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlssession.h"
#include "tlssocket.h"

static void stage24_make_ticket(qsc_tls_session_ticket* ticket)
{
    size_t i;

    if (ticket != NULL)
    {
        qsc_memutils_clear(ticket, sizeof(*ticket));
        ticket->lifetime = 3600U;
        ticket->ageadd = 0x01020304UL;
        ticket->noncelen = 8U;
        ticket->ticketlen = 32U;
        ticket->resumptionsecretlen = 32U;
        ticket->suite = qsc_tls_cipher_suite_tls_aes_256_gcm_sha384;

        for (i = 0U; i < ticket->noncelen; ++i)
        {
            ticket->nonce[i] = (uint8_t)(0xA0U + i);
        }

        for (i = 0U; i < ticket->ticketlen; ++i)
        {
            ticket->ticket[i] = (uint8_t)(0xB0U + i);
        }

        for (i = 0U; i < ticket->resumptionsecretlen; ++i)
        {
            ticket->resumptionsecret[i] = (uint8_t)(0xC0U + i);
        }
    }
}

static bool stage24_ticket_equals(const qsc_tls_session_ticket* left, const qsc_tls_session_ticket* right)
{
    bool res;

    res = false;

    if ((left != NULL) && (right != NULL))
    {
        if ((left->lifetime == right->lifetime) &&
            (left->ageadd == right->ageadd) &&
            (left->noncelen == right->noncelen) &&
            (left->ticketlen == right->ticketlen) &&
            (left->resumptionsecretlen == right->resumptionsecretlen) &&
            (left->suite == right->suite) &&
            (qsc_memutils_are_equal(left->nonce, right->nonce, left->noncelen) == true) &&
            (qsc_memutils_are_equal(left->ticket, right->ticket, left->ticketlen) == true) &&
            (qsc_memutils_are_equal(left->resumptionsecret, right->resumptionsecret, left->resumptionsecretlen) == true))
        {
            res = true;
        }
    }

    return res;
}

static bool stage24_default_policy_test(void)
{
    qsc_tls_socket_ticket_policy policy;
    bool res;

    res = false;
    qsc_memutils_clear(&policy, sizeof(policy));
    qsc_tls_socket_ticket_policy_initialize_default(&policy);

    if ((policy.enabled == false) &&
        (policy.allow_early_data == false) &&
        (policy.auto_send_server_ticket == false) &&
        (policy.lifetime_seconds == 86400U) &&
        (policy.renewal_interval_seconds == 0U))
    {
        res = true;
    }

    return res;
}

static bool stage24_context_policy_setter_test(void)
{
    static qsc_tls_socket_context context;
    qsc_tls_socket_ticket_policy policy;
    bool res;

    res = false;
    qsc_memutils_clear(&context, sizeof(context));
    qsc_tls_socket_ticket_policy_initialize_default(&context.ticketpolicy);
    qsc_tls_socket_ticket_policy_initialize_default(&policy);
    policy.enabled = true;
    policy.allow_early_data = true;
    policy.auto_send_server_ticket = true;
    policy.lifetime_seconds = 7200U;
    policy.renewal_interval_seconds = 1800U;

    if (qsc_tls_socket_context_set_session_ticket_policy(&context, &policy) == qsc_tls_socket_status_success)
    {
        if ((context.ticketpolicy.enabled == true) &&
            (context.ticketpolicy.allow_early_data == true) &&
            (context.ticketpolicy.auto_send_server_ticket == true) &&
            (context.ticketpolicy.lifetime_seconds == 7200U) &&
            (context.ticketpolicy.renewal_interval_seconds == 1800U))
        {
            policy.lifetime_seconds = 0U;

            if (qsc_tls_socket_context_set_session_ticket_policy(&context, &policy) == qsc_tls_socket_status_policy_rejected)
            {
                policy.lifetime_seconds = 7200U;
                policy.renewal_interval_seconds = 7200U;

                if (qsc_tls_socket_context_set_session_ticket_policy(&context, &policy) == qsc_tls_socket_status_policy_rejected)
                {
                    policy.renewal_interval_seconds = 7201U;

                    if (qsc_tls_socket_context_set_session_ticket_policy(&context, &policy) == qsc_tls_socket_status_policy_rejected)
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

static bool stage24_context_ticket_store_test(void)
{
    static qsc_tls_socket_context context;
    qsc_tls_socket_ticket_policy policy;
    qsc_tls_session_ticket ticket;
    bool res;

    res = false;
    qsc_memutils_clear(&context, sizeof(context));
    qsc_tls_socket_ticket_policy_initialize_default(&context.ticketpolicy);
    qsc_tls_socket_ticket_policy_initialize_default(&policy);
    stage24_make_ticket(&ticket);

    if (qsc_tls_socket_context_set_session_ticket(&context, &ticket) == qsc_tls_socket_status_policy_rejected)
    {
        if (context.hassessionticket == false)
        {
            policy.enabled = true;

            if (qsc_tls_socket_context_set_session_ticket_policy(&context, &policy) == qsc_tls_socket_status_success)
            {
                if (qsc_tls_socket_context_set_session_ticket(&context, &ticket) == qsc_tls_socket_status_success)
                {
                    if ((context.hassessionticket == true) && (stage24_ticket_equals(&context.sessionticket, &ticket) == true))
                    {
                        qsc_tls_socket_context_clear_session_ticket(&context);

                        if (context.hassessionticket == false)
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

static bool stage24_context_ticket_default_lifetime_test(void)
{
    static qsc_tls_socket_context context;
    qsc_tls_socket_ticket_policy policy;
    qsc_tls_session_ticket ticket;
    bool res;

    res = false;
    qsc_memutils_clear(&context, sizeof(context));
    qsc_tls_socket_ticket_policy_initialize_default(&context.ticketpolicy);
    qsc_tls_socket_ticket_policy_initialize_default(&policy);
    policy.enabled = true;
    policy.lifetime_seconds = 1800U;
    stage24_make_ticket(&ticket);
    ticket.lifetime = 0U;

    if (qsc_tls_socket_context_set_session_ticket_policy(&context, &policy) == qsc_tls_socket_status_success)
    {
        if (qsc_tls_socket_context_set_session_ticket(&context, &ticket) == qsc_tls_socket_status_success)
        {
            if ((context.hassessionticket == true) && (context.sessionticket.lifetime == 1800U))
            {
                res = true;
            }
        }
    }

    return res;
}

static bool stage24_ticket_structural_validation_test(void)
{
    qsc_tls_session_ticket ticket;
    bool res;

    res = false;
    stage24_make_ticket(&ticket);

    if (qsc_tls_socket_session_ticket_is_valid(&ticket) == true)
    {
        ticket.ticketlen = 0U;

        if (qsc_tls_socket_session_ticket_is_valid(&ticket) == false)
        {
            stage24_make_ticket(&ticket);
            ticket.resumptionsecretlen = 0U;

            if (qsc_tls_socket_session_ticket_is_valid(&ticket) == false)
            {
                stage24_make_ticket(&ticket);
                ticket.suite = qsc_tls_cipher_suite_none;

                if (qsc_tls_socket_session_ticket_is_valid(&ticket) == false)
                {
                    stage24_make_ticket(&ticket);
                    ticket.lifetime = QSC_TLS_SOCKET_TICKET_LIFETIME_MAX + 1U;

                    if (qsc_tls_socket_session_ticket_is_valid(&ticket) == false)
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

static bool stage24_connection_ticket_accessor_test(void)
{
    static qsc_tls_socket_connection connection;
    qsc_tls_session_ticket ticket;
    qsc_tls_session_ticket output;
    bool res;

    res = false;
    qsc_memutils_clear(&connection, sizeof(connection));
    qsc_tls_socket_ticket_policy_initialize_default(&connection.ticketpolicy);
    stage24_make_ticket(&ticket);

    if (qsc_tls_socket_connection_get_session_ticket(&connection, &output) == qsc_tls_socket_status_not_initialized)
    {
        connection.ticketpolicy.enabled = true;
        connection.lastticket = ticket;
        connection.haslastticket = true;

        if (qsc_tls_socket_connection_get_session_ticket(&connection, &output) == qsc_tls_socket_status_success)
        {
            if (stage24_ticket_equals(&output, &ticket) == true)
            {
                qsc_tls_socket_connection_clear_session_ticket(&connection);

                if ((connection.haslastticket == false) &&
                    (qsc_tls_socket_connection_get_session_ticket(&connection, &output) == qsc_tls_socket_status_not_initialized))
                {
                    res = true;
                }
            }
        }
    }

    return res;
}

static bool stage24_session_ticket_codec_policy_test(void)
{
    qsc_tls_session_ticket ticket;
    qsc_tls_session_ticket decoded;
    uint8_t encoded[1400U] = { 0U };
    size_t written;
    bool res;

    res = false;
    written = 0U;
    stage24_make_ticket(&ticket);

    if (qsc_tls_session_ticket_encode(&ticket, encoded, sizeof(encoded), &written) == qsc_tls_status_success)
    {
        if (written != 0U)
        {
            if (qsc_tls_session_ticket_decode(encoded, written, &decoded) == qsc_tls_status_success)
            {
                decoded.resumptionsecretlen = ticket.resumptionsecretlen;
                qsc_memutils_copy(decoded.resumptionsecret, ticket.resumptionsecret, ticket.resumptionsecretlen);
                decoded.suite = ticket.suite;

                if ((decoded.lifetime == ticket.lifetime) &&
                    (decoded.ageadd == ticket.ageadd) &&
                    (decoded.noncelen == ticket.noncelen) &&
                    (decoded.ticketlen == ticket.ticketlen) &&
                    (qsc_memutils_are_equal(decoded.nonce, ticket.nonce, ticket.noncelen) == true) &&
                    (qsc_memutils_are_equal(decoded.ticket, ticket.ticket, ticket.ticketlen) == true))
                {
                    if (qsc_tls_session_ticket_decode(encoded, written - 1U, &decoded) != qsc_tls_status_success)
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

bool qsctest_tls_stage24_tests(void)
{
    bool res;

    res = true;

    if (stage24_default_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 24 session ticket default policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 24 session ticket default policy test.");
        res = false;
    }

    if (stage24_context_policy_setter_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 24 session ticket context policy setter test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 24 session ticket context policy setter test.");
        res = false;
    }

    if (stage24_context_ticket_store_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 24 session ticket context store and clear test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 24 session ticket context store and clear test.");
        res = false;
    }

    if (stage24_context_ticket_default_lifetime_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 24 session ticket default lifetime test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 24 session ticket default lifetime test.");
        res = false;
    }

    if (stage24_ticket_structural_validation_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 24 session ticket structural validation test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 24 session ticket structural validation test.");
        res = false;
    }

    if (stage24_connection_ticket_accessor_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 24 session ticket connection accessor test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 24 session ticket connection accessor test.");
        res = false;
    }

    if (stage24_session_ticket_codec_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 24 session ticket codec policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 24 session ticket codec policy test.");
        res = false;
    }

    return res;
}
