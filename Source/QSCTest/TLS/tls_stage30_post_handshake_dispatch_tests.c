#include "tls_stage30_post_handshake_dispatch_tests.h"
#include "../testutils.h"
#include <string.h>
#include "tlsengine.h"
#include "tlsrecord.h"
#include "tlskeyschedule.h"
#include "tlshandshake.h"
#include "tlssession.h"
#include "memutils.h"

#define TEST_RECORD_BUFFER 20000U

typedef struct
{
    qsc_tls_connection client;
    qsc_tls_connection server;
} stage30_connection_pair;

static stage30_connection_pair* stage30_connection_pair_allocate(void)
{
    stage30_connection_pair* pair;

    pair = (stage30_connection_pair*)qsc_memutils_malloc(sizeof(stage30_connection_pair));

    if (pair != NULL)
    {
        qsc_memutils_clear(pair, sizeof(stage30_connection_pair));
    }

    return pair;
}

static bool stage30_connection_pair_result(stage30_connection_pair* pair, bool result)
{
    if (pair != NULL)
    {
        qsc_tls_engine_dispose(&pair->client);
        qsc_tls_engine_dispose(&pair->server);
        qsc_memutils_alloc_free(pair);
    }

    return result;
}

static bool set_direction(qsc_tls_record_state* write_state, qsc_tls_record_state* read_state, const uint8_t* secret, size_t secretlen)
{
    uint8_t key[32U] = { 0U };
    uint8_t iv[12U] = { 0U };
    size_t keylen;
    size_t ivlen;
    qsc_tls_status status;

    keylen = 0U;
    ivlen = 0U;
    status = qsc_tls_keyschedule_suite_record_sizes(qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, &keylen, &ivlen);

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_keyschedule_derive_traffic_keys(qsc_tls_hash_sha256, secret, secretlen, keylen, ivlen, key, iv);
    }

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_record_state_install_keys(write_state, qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, key, keylen, iv, ivlen);
    }

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_record_state_install_keys(read_state, qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, key, keylen, iv, ivlen);
    }

    qsc_memutils_secure_erase(key, sizeof(key));
    qsc_memutils_secure_erase(iv, sizeof(iv));

    return (status == qsc_tls_status_success);
}

static bool setup_pair(qsc_tls_connection* client, qsc_tls_connection* server, bool enable_resumption)
{
    uint8_t clientsecret[32U] = { 0U };
    uint8_t serversecret[32U] = { 0U };
    size_t i;
    bool res;

    qsc_memutils_clear(client, sizeof(*client));
    qsc_memutils_clear(server, sizeof(*server));
    client->role = qsc_tls_role_client;
    server->role = qsc_tls_role_server;
    client->state.client.phase = qsc_tls_client_phase_established;
    server->state.server.phase = qsc_tls_server_phase_established;
    client->state.client.negotiatedsuite = qsc_tls_cipher_suite_tls_aes_128_gcm_sha256;
    server->state.server.negotiatedsuite = qsc_tls_cipher_suite_tls_aes_128_gcm_sha256;
    client->state.client.negotiatedhash = qsc_tls_hash_sha256;
    server->state.server.negotiatedhash = qsc_tls_hash_sha256;
    client->state.client.config.enableresumption = enable_resumption;
    server->state.server.clientpskdhemodeoffered = true;

    res = (qsc_tls_keyschedule_state_initialize(&client->state.client.keyschedule, qsc_tls_hash_sha256) == qsc_tls_status_success);
    res = res && (qsc_tls_keyschedule_state_initialize(&server->state.server.keyschedule, qsc_tls_hash_sha256) == qsc_tls_status_success);

    for (i = 0U; i < sizeof(clientsecret); ++i)
    {
        clientsecret[i] = (uint8_t)(0x21U + i);
        serversecret[i] = (uint8_t)(0x61U + i);
        client->state.client.keyschedule.resumptionmastersecret[i] = (uint8_t)(0xA0U + i);
        server->state.server.keyschedule.resumptionmastersecret[i] = (uint8_t)(0xA0U + i);
    }

    client->state.client.keyschedule.masterdone = true;
    server->state.server.keyschedule.masterdone = true;
    qsc_memutils_copy(client->state.client.keyschedule.clientapplicationtrafficsecret, clientsecret, sizeof(clientsecret));
    qsc_memutils_copy(server->state.server.keyschedule.clientapplicationtrafficsecret, clientsecret, sizeof(clientsecret));
    qsc_memutils_copy(client->state.client.keyschedule.serverapplicationtrafficsecret, serversecret, sizeof(serversecret));
    qsc_memutils_copy(server->state.server.keyschedule.serverapplicationtrafficsecret, serversecret, sizeof(serversecret));

    res = res && set_direction(&client->state.client.writerecord, &server->state.server.readrecord, clientsecret, sizeof(clientsecret));
    res = res && set_direction(&server->state.server.writerecord, &client->state.client.readrecord, serversecret, sizeof(serversecret));
    qsc_memutils_secure_erase(clientsecret, sizeof(clientsecret));
    qsc_memutils_secure_erase(serversecret, sizeof(serversecret));

    return res;
}

static bool encode_ticket_handshake(uint8_t* output, size_t outlen, size_t* written, uint32_t lifetime)
{
    qsc_tls_session_ticket ticket = { 0U };
    uint8_t body[256U] = { 0U };
    size_t bodylen;
    size_t offset;
    size_t i;
    qsc_tls_status status;

    bodylen = 0U;
    offset = 0U;
    ticket.lifetime = lifetime;
    ticket.ageadd = 0x12345678U;
    ticket.noncelen = 4U;
    ticket.ticketlen = 16U;

    for (i = 0U; i < ticket.noncelen; ++i)
    {
        ticket.nonce[i] = (uint8_t)(0x10U + i);
    }

    for (i = 0U; i < ticket.ticketlen; ++i)
    {
        ticket.ticket[i] = (uint8_t)(0x40U + i);
    }

    status = qsc_tls_session_ticket_encode(&ticket, body, sizeof(body), &bodylen);

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_handshake_write_header(output, outlen, &offset, qsc_tls_handshake_type_new_session_ticket, bodylen);
    }

    if (status == qsc_tls_status_success && bodylen <= (outlen - offset))
    {
        qsc_memutils_copy(output + offset, body, bodylen);
        offset += bodylen;
        *written = offset;
    }
    else if (status == qsc_tls_status_success)
    {
        status = qsc_tls_status_buffer_too_small;
    }

    qsc_tls_session_ticket_dispose(&ticket);
    qsc_memutils_secure_erase(body, sizeof(body));

    return (status == qsc_tls_status_success);
}

static bool read_one(qsc_tls_connection* receiver, const uint8_t* record, size_t recordlen, uint8_t* appout, size_t appcap, size_t* appwritten)
{
    size_t consumed;
    qsc_tls_status status;

    consumed = 0U;
    *appwritten = 0U;
    status = qsc_tls_engine_read_application_data_ex(receiver, record, recordlen, &consumed, appout, appcap, appwritten, NULL, 0U, NULL);

    return (status == qsc_tls_status_success && consumed == recordlen);
}

static bool test_key_update_unfragmented(void)
{
    stage30_connection_pair* pair;
    uint8_t record[TEST_RECORD_BUFFER] = { 0U };
    uint8_t appout[32U] = { 0U };
    size_t recordlen;
    size_t appwritten;
    qsc_tls_status status;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    recordlen = 0U;
    appwritten = 0U;

    if (setup_pair(&pair->client, &pair->server, true) == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    status = qsc_tls_engine_request_key_update(&pair->server, false, record, sizeof(record), &recordlen);

    return stage30_connection_pair_result(pair, (status == qsc_tls_status_success && read_one(&pair->client, record, recordlen, appout, sizeof(appout), &appwritten) == true
        && appwritten == 0U && pair->client.state.client.phase == qsc_tls_client_phase_established));
}

static bool test_key_update_fragmented(void)
{
    stage30_connection_pair* pair;
    qsc_tls_record_state sender;
    uint8_t hs[5U] = { (uint8_t)qsc_tls_handshake_type_key_update, 0U, 0U, 1U, 0U };
    uint8_t record1[TEST_RECORD_BUFFER] = { 0U };
    uint8_t record2[TEST_RECORD_BUFFER] = { 0U };
    uint8_t appout[1U] = { 0U };
    size_t len1;
    size_t len2;
    size_t appwritten;
    qsc_tls_status status;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    len1 = 0U;
    len2 = 0U;
    appwritten = 0U;

    if (setup_pair(&pair->client, &pair->server, true) == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    sender = pair->server.state.server.writerecord;
    status = qsc_tls_record_encrypt(&sender, record1, sizeof(record1), &len1, qsc_tls_record_content_handshake, hs, 2U);
    status = (status == qsc_tls_status_success)
        ? qsc_tls_record_encrypt(&sender, record2, sizeof(record2), &len2, qsc_tls_record_content_handshake, hs + 2U, 3U)
        : status;

    if (status != qsc_tls_status_success || read_one(&pair->client, record1, len1, appout, sizeof(appout), &appwritten) == false
        || pair->client.state.client.handshakebufferlen != 2U)
    {
        return stage30_connection_pair_result(pair, false);
    }

    return stage30_connection_pair_result(pair, (read_one(&pair->client, record2, len2, appout, sizeof(appout), &appwritten) == true
        && pair->client.state.client.handshakebufferlen == 0U && pair->client.state.client.phase == qsc_tls_client_phase_established));
}

static bool test_ticket_unfragmented(void)
{
    stage30_connection_pair* pair;
    qsc_tls_session_ticket issued = { 0U };
    qsc_tls_session_ticket received = { 0U };
    uint8_t record[TEST_RECORD_BUFFER] = { 0U };
    uint8_t appout[1U] = { 0U };
    size_t recordlen;
    size_t appwritten;
    qsc_tls_status status;
    bool res;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    recordlen = 0U;
    appwritten = 0U;
    res = setup_pair(&pair->client, &pair->server, true);

    if (res == true)
    {
        status = qsc_tls_engine_emit_session_ticket(&pair->server, 3600U, record, sizeof(record), &recordlen, &issued);
        res = (status == qsc_tls_status_success);
    }

    if (res == true)
    {
        res = read_one(&pair->client, record, recordlen, appout, sizeof(appout), &appwritten);
    }

    if (res == true)
    {
        res = (appwritten == 0U && qsc_tls_engine_take_session_ticket(&pair->client, &received) == qsc_tls_status_success
            && received.ticketlen != 0U && received.lifetime == 3600U);
    }

    qsc_tls_session_ticket_dispose(&issued);
    qsc_tls_session_ticket_dispose(&received);

    return stage30_connection_pair_result(pair, res);
}

static bool test_ticket_fragmented(void)
{
    stage30_connection_pair* pair;
    qsc_tls_record_state sender;
    qsc_tls_session_ticket received = { 0U };
    uint8_t hs[512U] = { 0U };
    uint8_t record1[TEST_RECORD_BUFFER] = { 0U };
    uint8_t record2[TEST_RECORD_BUFFER] = { 0U };
    uint8_t appout[1U] = { 0U };
    size_t hslen;
    size_t len1;
    size_t len2;
    size_t appwritten;
    size_t split;
    qsc_tls_status status;
    bool res;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    hslen = 0U;
    len1 = 0U;
    len2 = 0U;
    appwritten = 0U;
    split = 7U;
    res = setup_pair(&pair->client, &pair->server, true) && encode_ticket_handshake(hs, sizeof(hs), &hslen, 7200U);

    if (res == false || hslen <= split)
    {
        return stage30_connection_pair_result(pair, false);
    }

    sender = pair->server.state.server.writerecord;
    status = qsc_tls_record_encrypt(&sender, record1, sizeof(record1), &len1, qsc_tls_record_content_handshake, hs, split);
    status = (status == qsc_tls_status_success)
        ? qsc_tls_record_encrypt(&sender, record2, sizeof(record2), &len2, qsc_tls_record_content_handshake, hs + split, hslen - split)
        : status;

    if (status != qsc_tls_status_success || read_one(&pair->client, record1, len1, appout, sizeof(appout), &appwritten) == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    res = (pair->client.hasreceivedticket == false && pair->client.state.client.handshakebufferlen == split
        && read_one(&pair->client, record2, len2, appout, sizeof(appout), &appwritten) == true
        && qsc_tls_engine_take_session_ticket(&pair->client, &received) == qsc_tls_status_success
        && received.lifetime == 7200U && pair->client.state.client.handshakebufferlen == 0U);

    qsc_tls_session_ticket_dispose(&received);

    return stage30_connection_pair_result(pair, res);
}

static bool test_ticket_ignored_when_disabled(void)
{
    stage30_connection_pair* pair;
    qsc_tls_record_state sender;
    uint8_t hs[512U] = { 0U };
    uint8_t record[TEST_RECORD_BUFFER] = { 0U };
    uint8_t appout[1U] = { 0U };
    size_t hslen;
    size_t recordlen;
    size_t appwritten;
    qsc_tls_status status;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    hslen = 0U;
    recordlen = 0U;
    appwritten = 0U;

    if (setup_pair(&pair->client, &pair->server, false) == false || encode_ticket_handshake(hs, sizeof(hs), &hslen, 3600U) == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    sender = pair->server.state.server.writerecord;
    status = qsc_tls_record_encrypt(&sender, record, sizeof(record), &recordlen, qsc_tls_record_content_handshake, hs, hslen);

    return stage30_connection_pair_result(pair, (status == qsc_tls_status_success && read_one(&pair->client, record, recordlen, appout, sizeof(appout), &appwritten) == true
        && pair->client.hasreceivedticket == false && pair->client.state.client.phase == qsc_tls_client_phase_established));
}

static bool test_unexpected_handshake(void)
{
    stage30_connection_pair* pair;
    qsc_tls_record_state sender;
    uint8_t hs[4U] = { (uint8_t)qsc_tls_handshake_type_finished, 0U, 0U, 0U };
    uint8_t record[TEST_RECORD_BUFFER] = { 0U };
    uint8_t appout[1U] = { 0U };
    size_t recordlen;
    size_t consumed;
    size_t appwritten;
    qsc_tls_status status;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    recordlen = 0U;
    consumed = 0U;
    appwritten = 0U;

    if (setup_pair(&pair->client, &pair->server, true) == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    sender = pair->server.state.server.writerecord;
    status = qsc_tls_record_encrypt(&sender, record, sizeof(record), &recordlen, qsc_tls_record_content_handshake, hs, sizeof(hs));

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_engine_read_application_data_ex(&pair->client, record, recordlen, &consumed, appout, sizeof(appout), &appwritten, NULL, 0U, NULL);
    }

    return stage30_connection_pair_result(pair, (status == qsc_tls_status_invalid_message && consumed == recordlen
        && pair->client.state.client.lastalert == qsc_tls_alert_unexpected_message && pair->client.state.client.phase == qsc_tls_client_phase_failed));
}

static bool test_malformed_handshake_length(void)
{
    stage30_connection_pair* pair;
    qsc_tls_record_state sender;
    uint8_t hs[4U] = { (uint8_t)qsc_tls_handshake_type_new_session_ticket, 0x20U, 0U, 0U };
    uint8_t record[TEST_RECORD_BUFFER] = { 0U };
    uint8_t appout[1U] = { 0U };
    size_t recordlen;
    size_t consumed;
    size_t appwritten;
    qsc_tls_status status;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    recordlen = 0U;
    consumed = 0U;
    appwritten = 0U;

    if (setup_pair(&pair->client, &pair->server, true) == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    sender = pair->server.state.server.writerecord;
    status = qsc_tls_record_encrypt(&sender, record, sizeof(record), &recordlen, qsc_tls_record_content_handshake, hs, sizeof(hs));

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_engine_read_application_data_ex(&pair->client, record, recordlen, &consumed, appout, sizeof(appout), &appwritten, NULL, 0U, NULL);
    }

    return stage30_connection_pair_result(pair, (status == qsc_tls_status_invalid_length && consumed == recordlen
        && pair->client.state.client.lastalert == qsc_tls_alert_decode_error && pair->client.state.client.phase == qsc_tls_client_phase_failed));
}

static bool test_close_notify_interaction(void)
{
    stage30_connection_pair* pair;
    qsc_tls_record_state sender;
    uint8_t alert[2U] = { (uint8_t)qsc_tls_alert_level_warning, (uint8_t)qsc_tls_alert_close_notify };
    uint8_t ku[5U] = { (uint8_t)qsc_tls_handshake_type_key_update, 0U, 0U, 1U, 0U };
    uint8_t record1[TEST_RECORD_BUFFER] = { 0U };
    uint8_t record2[TEST_RECORD_BUFFER] = { 0U };
    uint8_t appout[1U] = { 0U };
    size_t len1;
    size_t len2;
    size_t appwritten;
    uint64_t readseq;
    qsc_tls_status status;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    len1 = 0U;
    len2 = 0U;
    appwritten = 0U;

    if (setup_pair(&pair->client, &pair->server, true) == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    sender = pair->server.state.server.writerecord;
    status = qsc_tls_record_encrypt(&sender, record1, sizeof(record1), &len1, qsc_tls_record_content_alert, alert, sizeof(alert));
    status = (status == qsc_tls_status_success)
        ? qsc_tls_record_encrypt(&sender, record2, sizeof(record2), &len2, qsc_tls_record_content_handshake, ku, sizeof(ku))
        : status;

    if (status != qsc_tls_status_success || read_one(&pair->client, record1, len1, appout, sizeof(appout), &appwritten) == false
        || pair->client.state.client.closenotifyreceived == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    readseq = pair->client.state.client.readrecord.sequence;

    return stage30_connection_pair_result(pair, (read_one(&pair->client, record2, len2, appout, sizeof(appout), &appwritten) == true
        && pair->client.state.client.readrecord.sequence == readseq && pair->client.state.client.phase == qsc_tls_client_phase_established));
}

static bool test_pending_reciprocal_key_update(void)
{
    stage30_connection_pair* pair;
    uint8_t request[TEST_RECORD_BUFFER] = { 0U };
    uint8_t response_and_app[TEST_RECORD_BUFFER * 2U] = { 0U };
    uint8_t appout[32U] = { 0U };
    const uint8_t payload[3U] = { 'o', 'k', '!' };
    size_t requestlen;
    size_t appwritten;
    size_t totalwritten;
    size_t firstlen;
    size_t secondlen;
    size_t consumed;
    qsc_tls_status status;
    bool complete;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    requestlen = 0U;
    appwritten = 0U;
    totalwritten = 0U;
    firstlen = 0U;
    secondlen = 0U;
    consumed = 0U;
    complete = false;

    if (setup_pair(&pair->client, &pair->server, true) == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    status = qsc_tls_engine_request_key_update(&pair->server, true, request, sizeof(request), &requestlen);

    if (status != qsc_tls_status_success || read_one(&pair->client, request, requestlen, appout, sizeof(appout), &appwritten) == false
        || pair->client.keyupdateresponsepending == false || pair->server.keyupdaterequestoutstanding == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    status = qsc_tls_engine_write_application_data(&pair->client, payload, sizeof(payload), response_and_app, sizeof(response_and_app), &totalwritten);

    if (status != qsc_tls_status_success || pair->client.keyupdateresponsepending == true)
    {
        return stage30_connection_pair_result(pair, false);
    }

    status = qsc_tls_record_try_get_span_length(response_and_app, totalwritten, &firstlen, &complete);

    if (status != qsc_tls_status_success || complete == false || firstlen >= totalwritten)
    {
        return stage30_connection_pair_result(pair, false);
    }

    complete = false;
    status = qsc_tls_record_try_get_span_length(response_and_app + firstlen, totalwritten - firstlen, &secondlen, &complete);

    if (status != qsc_tls_status_success || complete == false || (firstlen + secondlen) != totalwritten)
    {
        return stage30_connection_pair_result(pair, false);
    }

    status = qsc_tls_engine_read_application_data(&pair->server, response_and_app, firstlen, &consumed, appout, sizeof(appout), &appwritten);

    if (status != qsc_tls_status_success || consumed != firstlen || pair->server.keyupdaterequestoutstanding == true)
    {
        return stage30_connection_pair_result(pair, false);
    }

    consumed = 0U;
    appwritten = 0U;
    status = qsc_tls_engine_read_application_data(&pair->server, response_and_app + firstlen, secondlen, &consumed, appout, sizeof(appout), &appwritten);

    return stage30_connection_pair_result(pair, (status == qsc_tls_status_success && consumed == secondlen && appwritten == sizeof(payload)
        && memcmp(appout, payload, sizeof(payload)) == 0));
}

static bool test_application_buffer_retry(void)
{
    stage30_connection_pair* pair;
    uint8_t record[TEST_RECORD_BUFFER] = { 0U };
    uint8_t small[1U] = { 0U };
    uint8_t output[16U] = { 0U };
    const uint8_t payload[5U] = { 1U, 2U, 3U, 4U, 5U };
    size_t recordlen;
    size_t consumed;
    size_t written;
    qsc_tls_status status;

    pair = stage30_connection_pair_allocate();

    if (pair == NULL)
    {
        return stage30_connection_pair_result(pair, false);
    }

    recordlen = 0U;
    consumed = 0U;
    written = 0U;

    if (setup_pair(&pair->client, &pair->server, true) == false)
    {
        return stage30_connection_pair_result(pair, false);
    }

    status = qsc_tls_engine_write_application_data(&pair->server, payload, sizeof(payload), record, sizeof(record), &recordlen);

    if (status != qsc_tls_status_success)
    {
        return stage30_connection_pair_result(pair, false);
    }

    status = qsc_tls_engine_read_application_data(&pair->client, record, recordlen, &consumed, small, sizeof(small), &written);

    if (status != qsc_tls_status_buffer_too_small || consumed != 0U || pair->client.state.client.readrecord.sequence != 0U)
    {
        return stage30_connection_pair_result(pair, false);
    }

    status = qsc_tls_engine_read_application_data(&pair->client, record, recordlen, &consumed, output, sizeof(output), &written);

    return stage30_connection_pair_result(pair, (status == qsc_tls_status_success && consumed == recordlen && written == sizeof(payload)
        && memcmp(output, payload, sizeof(payload)) == 0));
}

bool qsctest_tls_stage30_tests(void)
{
    bool res;

    res = true;

#define STAGE30_RUN(fn, label) do { if ((fn)() == true) { qsctest_print_line("[PASS] TLS Stage 30 " label "."); } else { qsctest_print_line("[FAIL] TLS Stage 30 " label "."); res = false; } } while (0)
    STAGE30_RUN(test_key_update_unfragmented, "unfragmented post-handshake KeyUpdate test");
    STAGE30_RUN(test_key_update_fragmented, "fragmented post-handshake KeyUpdate test");
    STAGE30_RUN(test_ticket_unfragmented, "NewSessionTicket dispatch test");
    STAGE30_RUN(test_ticket_fragmented, "fragmented NewSessionTicket dispatch test");
    STAGE30_RUN(test_ticket_ignored_when_disabled, "disabled-resumption NewSessionTicket ignore test");
    STAGE30_RUN(test_unexpected_handshake, "unexpected post-handshake message rejection test");
    STAGE30_RUN(test_malformed_handshake_length, "malformed post-handshake length rejection test");
    STAGE30_RUN(test_close_notify_interaction, "close-notify post-handshake interaction test");
    STAGE30_RUN(test_pending_reciprocal_key_update, "pending reciprocal KeyUpdate test");
    STAGE30_RUN(test_application_buffer_retry, "application-buffer retry test");
#undef STAGE30_RUN

    return res;
}
