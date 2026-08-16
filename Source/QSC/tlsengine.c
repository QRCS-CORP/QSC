#include "tlsengine.h"
#include "tlsalert.h"
#include "csp.h"
#include "memutils.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlsrecord.h"
#include "tlskeyschedule.h"
#include "tlshandshake.h"
#include "tlssession.h"
#include "intutils.h"
#include "stringutils.h"
#include "timestamp.h"

static qsc_tls_status tls_engine_apply_peer_key_update(qsc_tls_connection* connection)
{
    uint8_t next_secret[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t new_key[32U] = { 0U };
    uint8_t new_iv[12U] = { 0U };
    qsc_tls_record_state* read_record;
    uint8_t* read_traffic_secret;
    size_t digest_size;
    size_t keylen;
    size_t ivlen;
    qsc_tls_hash_algorithm hash;
    qsc_tls_cipher_suite suite;
    qsc_tls_status status;

    keylen = 0U;
    ivlen = 0U;

    if (connection->role == qsc_tls_role_client)
    {
        read_record = &connection->state.client.readrecord;
        read_traffic_secret = connection->state.client.keyschedule.serverapplicationtrafficsecret;
        hash = connection->state.client.negotiatedhash;
        suite = connection->state.client.negotiatedsuite;
        digest_size = connection->state.client.keyschedule.digestsize;
    }
    else
    {
        read_record = &connection->state.server.readrecord;
        read_traffic_secret = connection->state.server.keyschedule.clientapplicationtrafficsecret;
        hash = connection->state.server.negotiatedhash;
        suite = connection->state.server.negotiatedsuite;
        digest_size = connection->state.server.keyschedule.digestsize;
    }

    status = qsc_tls_keyschedule_advance_traffic_secret(hash, read_traffic_secret, digest_size, next_secret);

    if (status == qsc_tls_status_success)
    {
        qsc_memutils_copy(read_traffic_secret, next_secret, digest_size);
        status = qsc_tls_keyschedule_suite_record_sizes(suite, &keylen, &ivlen);
    }

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_keyschedule_derive_traffic_keys(hash, read_traffic_secret, digest_size, keylen, ivlen, new_key, new_iv);
    }

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_record_state_install_keys(read_record, suite, new_key, keylen, new_iv, ivlen);
    }

    qsc_memutils_secure_erase(next_secret, sizeof(next_secret));
    qsc_memutils_secure_erase(new_key, sizeof(new_key));
    qsc_memutils_secure_erase(new_iv, sizeof(new_iv));

    return status;
}

static void tls_engine_fail_connection(qsc_tls_connection* connection, qsc_tls_alert_description alert)
{
    if (connection != NULL)
    {
        if (connection->role == qsc_tls_role_client)
        {
            connection->state.client.lastalert = alert;
            connection->state.client.phase = qsc_tls_client_phase_failed;
        }
        else
        {
            connection->state.server.lastalert = alert;
            connection->state.server.phase = qsc_tls_server_phase_failed;
        }
    }
}

static qsc_tls_status tls_engine_process_new_session_ticket(qsc_tls_connection* connection, const uint8_t* input, size_t inlen)
{
    qsc_tls_session_ticket ticket = { 0U };
    qsc_tls_client_state* client;
    qsc_tls_status status;
    bool retain;

    client = (qsc_tls_client_state*)NULL;
    status = qsc_tls_status_invalid_input;
    retain = false;

    if (connection != NULL && input != NULL)
    {
        if (connection->role == qsc_tls_role_client && qsc_tls_engine_is_handshake_complete(connection) == true)
        {
            client = &connection->state.client;

            if (client->config.enableresumption == false && client->config.offeredticket == NULL)
            {
                status = qsc_tls_status_success;
            }
            else
            {
                status = qsc_tls_session_ticket_decode(input, inlen, &ticket);

                if (status == qsc_tls_status_not_supported)
                {
                    status = qsc_tls_status_success;
                }
                else if (status == qsc_tls_status_success)
                {
                    ticket.maxearlydatasize = 0U;
                    retain = (ticket.lifetime != 0U && ticket.lifetime <= QSC_TLS_SESSION_TICKET_LIFETIME_MAX
                        && (client->config.enableresumption == true || client->config.offeredticket != NULL));

                    if (retain == true)
                    {
                        ticket.receipttimems = qsc_timestamp_epochtime_milliseconds();
                        ticket.protocolversion = QSC_TLS_PROTOCOL_VERSION_13;
                        ticket.suite = client->negotiatedsuite;
                        ticket.resumptionsecretlen = client->keyschedule.digestsize;

                        if (ticket.receipttimems == 0ULL)
                        {
                            retain = false;
                        }
                        else
                        {
                            if (client->config.hostname != NULL)
                            {
                                ticket.servernamelen = qsc_stringutils_string_size(client->config.hostname);

                                if (ticket.servernamelen > QSC_TLS_MAX_HOSTNAME_SIZE)
                                {
                                    retain = false;
                                }
                                else if (ticket.servernamelen != 0U)
                                {
                                    qsc_memutils_copy(ticket.servername, (const uint8_t*)client->config.hostname, ticket.servernamelen);
                                }
                            }

                            if (retain == true && client->alpnselected == true && client->selectedalpnlen <= QSC_TLS_MAX_ALPN_SIZE)
                            {
                                qsc_memutils_copy(ticket.alpn, client->selectedalpn, client->selectedalpnlen);
                                ticket.alpnlen = client->selectedalpnlen;
                            }
                        }

                        if (retain == true)
                        {
                            status = qsc_tls_keyschedule_derive_resumption_psk(&client->keyschedule, ticket.nonce, ticket.noncelen, ticket.resumptionsecret, ticket.resumptionsecretlen);
                        }
                    }
                }
            }

            if (status == qsc_tls_status_success && retain == true)
            {
                if (connection->hasreceivedticket == true)
                {
                    qsc_tls_session_ticket_dispose(&connection->receivedticket);
                }

                qsc_memutils_copy(&connection->receivedticket, &ticket, sizeof(ticket));
                connection->hasreceivedticket = true;
            }
        }
        else
        {
            status = qsc_tls_status_invalid_state;
        }
    }

    qsc_memutils_secure_erase(&ticket, sizeof(ticket));

    return status;
}

static void tls_engine_fail_key_usage(qsc_tls_connection* connection)
{
    qsc_tls_record_state* write_record;

    write_record = (qsc_tls_record_state*)NULL;

    if (connection != NULL)
    {
        if (connection->role == qsc_tls_role_client)
        {
            connection->state.client.lastalert = qsc_tls_alert_internal_error;
            connection->state.client.phase = qsc_tls_client_phase_failed;
            write_record = &connection->state.client.writerecord;
        }
        else
        {
            connection->state.server.lastalert = qsc_tls_alert_internal_error;
            connection->state.server.phase = qsc_tls_server_phase_failed;
            write_record = &connection->state.server.writerecord;
        }

        if (write_record != (qsc_tls_record_state*)NULL)
        {
            qsc_tls_record_state_dispose(write_record);
        }
    }
}

static bool tls_engine_write_key_update_required(const qsc_tls_connection* connection)
{
    const qsc_tls_record_state* write_record;
    bool res;

    write_record = (const qsc_tls_record_state*)NULL;
    res = false;

    if (connection != NULL)
    {
        write_record = (connection->role == qsc_tls_role_client)
            ? &connection->state.client.writerecord
            : &connection->state.server.writerecord;

        if (write_record->initialized == true)
        {
            switch (write_record->suite)
            {
                case qsc_tls_cipher_suite_tls_aes_128_gcm_sha256:
                case qsc_tls_cipher_suite_tls_aes_256_gcm_sha384:
                {
                    res = (write_record->sequence >= (QSC_TLS_AES_GCM_KEY_USAGE_LIMIT - 1ULL));
                    break;
                }
                case qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256:
                {
                    res = (write_record->sequence >= (UINT64_MAX - 1ULL));
                    break;
                }
                default:
                {
                    break;
                }
            }
        }
    }

    return res;
}

static size_t tls_engine_protected_record_size(size_t contentlen)
{
    return QSC_TLS_RECORD_HEADER_SIZE + contentlen + QSC_TLS_INNER_CONTENT_TYPE_SIZE + QSC_TLS_GCM_TAG_SIZE;
}

qsc_tls_status qsc_tls_engine_initialize_client(qsc_tls_connection* connection, const qsc_tls_client_config* config)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(config != NULL);

    qsc_tls_status status;

    if (connection == NULL)
    {
        status = qsc_tls_status_invalid_input;
    }
    else
    {
        qsc_memutils_clear(connection, sizeof(*connection));
        connection->role = qsc_tls_role_client;
        status = qsc_tls_client_initialize(&connection->state.client, config);
    }

    return status;
}

qsc_tls_status qsc_tls_engine_initialize_server(qsc_tls_connection* connection, const qsc_tls_server_config* config)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(config != NULL);

    qsc_tls_status status;

    if (connection == NULL)
    {
        status = qsc_tls_status_invalid_input;
    }
    else
    {
        qsc_memutils_clear(connection, sizeof(*connection));
        connection->role = qsc_tls_role_server;
        status = qsc_tls_server_initialize(&connection->state.server, config);
    }

    return status;
}

void qsc_tls_engine_dispose(qsc_tls_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    if (connection != NULL)
    {
        if (connection->role == qsc_tls_role_client)
        {
            qsc_tls_client_dispose(&connection->state.client);
        }
        else
        {
            qsc_tls_server_dispose(&connection->state.server);
        }

        qsc_memutils_secure_erase(connection, sizeof(*connection));
    }
}

qsc_tls_status qsc_tls_engine_handshake(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, size_t* consumed, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(consumed != NULL);
    QSC_ASSERT(written != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (consumed != NULL) 
    {
        *consumed = 0U; 
    }

    if (written != NULL)
    {
        *written = 0U; 
    }

    if (connection != NULL && consumed != NULL && written != NULL)
    {
        if (connection->role == qsc_tls_role_client)
        {
            /* if client has not yet emitted ClientHello, do so and return the flight */
            if (connection->state.client.phase == qsc_tls_client_phase_initial)
            {
                (void)input; (void)inlen;
                status = qsc_tls_client_send_hello(&connection->state.client, output, outlen, written);

                return status;
            }

            /* otherwise feed any input to the state machine */
            status = qsc_tls_client_process_record(&connection->state.client, input, inlen, consumed, output, outlen, written);
        }
        else
        {
            status = qsc_tls_server_process_record(&connection->state.server, input, inlen, consumed, output, outlen, written);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_engine_write_application_data(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);

    qsc_tls_record_state* write_record;
    size_t applicationwritten;
    size_t required;
    size_t updatewritten;
    qsc_tls_status status;
    bool established;
    bool sendupdate;

    applicationwritten = 0U;
    required = 0U;
    updatewritten = 0U;
    status = qsc_tls_status_invalid_input;
    established = false;
    sendupdate = false;
    write_record = (qsc_tls_record_state*)NULL;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (connection != NULL && input != NULL && output != NULL && written != NULL)
    {
        established = qsc_tls_engine_is_handshake_complete(connection);

        if (established == false)
        {
            status = qsc_tls_status_invalid_state;
        }
        else if (inlen > QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE)
        {
            status = qsc_tls_status_invalid_length;
        }
        else
        {
            write_record = (connection->role == qsc_tls_role_client)
                ? &connection->state.client.writerecord
                : &connection->state.server.writerecord;

            if (established == true)
            {
                sendupdate = (connection->keyupdateresponsepending == true || tls_engine_write_key_update_required(connection) == true);
            }

            if (sendupdate == true)
            {
                if (connection->writekeyupdateepoch >= QSC_TLS_KEY_UPDATE_EPOCH_LIMIT)
                {
                    tls_engine_fail_key_usage(connection);
                    status = qsc_tls_status_invalid_state;
                }
                else
                {
                    required = tls_engine_protected_record_size(5U) + tls_engine_protected_record_size(inlen);

                    if (outlen < required)
                    {
                        status = qsc_tls_status_buffer_too_small;
                    }
                    else
                    {
                        status = qsc_tls_engine_request_key_update(connection, false, output, outlen, &updatewritten);

                        if (status == qsc_tls_status_success)
                        {
                            status = qsc_tls_record_encrypt(write_record, output + updatewritten, outlen - updatewritten,
                                &applicationwritten, qsc_tls_record_content_application_data, input, inlen);

                            if (status == qsc_tls_status_success)
                            {
                                *written = updatewritten + applicationwritten;
                            }
                        }
                    }
                }
            }
            else
            {
                status = qsc_tls_record_encrypt(write_record, output, outlen, written, qsc_tls_record_content_application_data, input, inlen);
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_engine_read_application_data(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, size_t* consumed, uint8_t* output, size_t outlen, size_t* written)
{
    /* Backward-compatible wrapper: when a peer requests a reciprocal KeyUpdate and no
     * response buffer is supplied, the response is queued and emitted before the next
     * outbound Application Data record. */
    return qsc_tls_engine_read_application_data_ex(connection, input, inlen, consumed, output, outlen, written, NULL, 0U, NULL);
}

qsc_tls_status qsc_tls_engine_read_application_data_ex(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, size_t* consumed, uint8_t* output, 
    size_t outlen, size_t* written, uint8_t* responseoutput, size_t responseoutlen, size_t* responsewritten)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);

    qsc_tls_record_state* r;
    const uint8_t* payload;
    uint8_t* handshakebuffer;
    size_t* handshakebufferlen;
    bool* closenotifyreceived;
    size_t payloadlen;
    size_t recordwritten;
    size_t reclen;
    qsc_tls_record_content_type inner;
    qsc_tls_record_content_type outer;
    qsc_tls_status status;
    bool complete;

    status = qsc_tls_status_invalid_input;
    payload = NULL;
    handshakebuffer = NULL;
    handshakebufferlen = NULL;
    closenotifyreceived = NULL;
    payloadlen = 0U;
    recordwritten = 0U;
    reclen = 0U;
    inner = qsc_tls_record_content_invalid;
    outer = qsc_tls_record_content_invalid;
    complete = false;

    if (consumed != NULL)
    {
        *consumed = 0U;
    }

    if (written != NULL)
    {
        *written = 0U;
    }

    if (responsewritten != NULL)
    {
        *responsewritten = 0U;
    }

    if (connection != NULL && input != NULL && consumed != NULL && output != NULL && written != NULL)
    {
        if (qsc_tls_engine_is_handshake_complete(connection) == false)
        {
            status = qsc_tls_status_invalid_state;
        }
        else
        {
            r = (connection->role == qsc_tls_role_client)
                ? &connection->state.client.readrecord
                : &connection->state.server.readrecord;
            handshakebuffer = (connection->role == qsc_tls_role_client)
                ? connection->state.client.handshakebuffer
                : connection->state.server.handshakebuffer;
            handshakebufferlen = (connection->role == qsc_tls_role_client)
                ? &connection->state.client.handshakebufferlen
                : &connection->state.server.handshakebufferlen;
            closenotifyreceived = (connection->role == qsc_tls_role_client)
                ? &connection->state.client.closenotifyreceived
                : &connection->state.server.closenotifyreceived;

            status = qsc_tls_record_try_get_span_length(input, inlen, &reclen, &complete);

            if (status == qsc_tls_status_record_overflow)
            {
                tls_engine_fail_connection(connection, qsc_tls_alert_record_overflow);
            }
            else if (status == qsc_tls_status_success && complete == true)
            {
                if (*closenotifyreceived == true)
                {
                    /* RFC 9846 Section 6.1: data received after close_notify is ignored. */
                    *consumed = reclen;
                }
                else
                {
                    status = qsc_tls_record_decode_plaintext(input, reclen, &outer, &payload, &payloadlen);

                    if (status == qsc_tls_status_success)
                    {
                        if (outer == qsc_tls_record_content_change_cipher_spec)
                        {
                            tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                            *consumed = reclen;
                            status = qsc_tls_status_invalid_message;
                        }
                        else if (outer != qsc_tls_record_content_application_data)
                        {
                            tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                            *consumed = reclen;
                            status = qsc_tls_status_invalid_message;
                        }
                        else
                        {
                            qsc_memutils_clear(connection->applicationbuffer, sizeof(connection->applicationbuffer));
                            connection->applicationbufferlen = 0U;
                            status = qsc_tls_record_decrypt(r, connection->applicationbuffer, sizeof(connection->applicationbuffer), &recordwritten, &inner, input, reclen);

                            if (status == qsc_tls_status_record_overflow)
                            {
                                tls_engine_fail_connection(connection, qsc_tls_alert_record_overflow);
                                *consumed = reclen;
                            }
                            else if (status == qsc_tls_status_authentication_failure)
                            {
                                tls_engine_fail_connection(connection, qsc_tls_alert_bad_record_mac);
                                *consumed = reclen;
                            }
                            else if (status == qsc_tls_status_success)
                            {
                                connection->applicationbufferlen = recordwritten;
                                *consumed = reclen;

                                if (*handshakebufferlen != 0U && inner != qsc_tls_record_content_handshake)
                                {
                                    tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                                    status = qsc_tls_status_invalid_message;
                                }
                                else if (inner == qsc_tls_record_content_application_data)
                                {
                                    if (recordwritten > outlen)
                                    {
                                        if (r->sequence != 0U)
                                        {
                                            r->sequence -= 1U;
                                        }

                                        *consumed = 0U;
                                        status = qsc_tls_status_buffer_too_small;
                                    }
                                    else
                                    {
                                        qsc_memutils_copy(output, connection->applicationbuffer, recordwritten);
                                        *written = recordwritten;
                                    }
                                }
                                else if (inner == qsc_tls_record_content_change_cipher_spec)
                                {
                                    tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                                    status = qsc_tls_status_invalid_message;
                                }
                                else if (inner == qsc_tls_record_content_alert)
                                {
                                    qsc_tls_alert_description alert;

                                    if (recordwritten == 0U)
                                    {
                                        alert = qsc_tls_alert_unexpected_message;
                                        status = qsc_tls_status_invalid_message;
                                    }
                                    else
                                    {
                                        status = qsc_tls_alert_decode(connection->applicationbuffer, recordwritten, &alert);

                                        if (status != qsc_tls_status_success)
                                        {
                                            alert = qsc_tls_alert_decode_error;
                                        }
                                    }

                                    if (connection->role == qsc_tls_role_client)
                                    {
                                        connection->state.client.lastalert = alert;
                                    }
                                    else
                                    {
                                        connection->state.server.lastalert = alert;
                                    }

                                    if (status != qsc_tls_status_success)
                                    {
                                        tls_engine_fail_connection(connection, alert);
                                    }
                                    else if (alert == qsc_tls_alert_close_notify)
                                    {
                                        *closenotifyreceived = true;
                                    }
                                    else if (alert != qsc_tls_alert_user_canceled)
                                    {
                                        tls_engine_fail_connection(connection, alert);
                                        status = qsc_tls_status_failure;
                                    }
                                }
                                else if (inner == qsc_tls_record_content_handshake)
                                {
                                    size_t offset;

                                    if (recordwritten == 0U)
                                    {
                                        tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                                        status = qsc_tls_status_invalid_message;
                                    }
                                    else if (recordwritten > (QSC_TLS_STREAM_BUFFER_MAX_SIZE - *handshakebufferlen))
                                    {
                                        tls_engine_fail_connection(connection, qsc_tls_alert_decode_error);
                                        status = qsc_tls_status_invalid_length;
                                    }
                                    else
                                    {
                                        qsc_memutils_copy(handshakebuffer + *handshakebufferlen, connection->applicationbuffer, recordwritten);
                                        *handshakebufferlen += recordwritten;
                                        offset = 0U;

                                        while (status == qsc_tls_status_success && (*handshakebufferlen - offset) >= 4U)
                                        {
                                            qsc_tls_handshake_type htype;
                                            size_t hbodylen;
                                            size_t hdroff;

                                            hdroff = offset;
                                            status = qsc_tls_handshake_read_header(handshakebuffer, *handshakebufferlen, &offset, &htype, &hbodylen);

                                            if (status != qsc_tls_status_success)
                                            {
                                                tls_engine_fail_connection(connection, qsc_tls_alert_decode_error);
                                            }
                                            else if (hbodylen > (QSC_TLS_STREAM_BUFFER_MAX_SIZE - 4U))
                                            {
                                                tls_engine_fail_connection(connection, qsc_tls_alert_decode_error);
                                                status = qsc_tls_status_invalid_length;
                                            }
                                            else if (hbodylen > (*handshakebufferlen - offset))
                                            {
                                                offset = hdroff;
                                                break;
                                            }
                                            else if (htype == qsc_tls_handshake_type_key_update && (offset + hbodylen) != *handshakebufferlen)
                                            {
                                                tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                                                status = qsc_tls_status_invalid_message;
                                            }
                                            else if (htype == qsc_tls_handshake_type_key_update)
                                            {
                                                bool requestupdate;

                                                requestupdate = false;

                                                if (qsc_tls_engine_is_handshake_complete(connection) == false)
                                                {
                                                    tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                                                    status = qsc_tls_status_invalid_message;
                                                }
                                                else
                                                {
                                                    status = qsc_tls_handshake_decode_key_update(handshakebuffer + offset, hbodylen, &requestupdate);

                                                    if (status != qsc_tls_status_success)
                                                    {
                                                        tls_engine_fail_connection(connection, (status == qsc_tls_status_invalid_message)
                                                            ? qsc_tls_alert_illegal_parameter
                                                            : qsc_tls_alert_decode_error);
                                                    }
                                                    else
                                                    {
                                                        status = tls_engine_apply_peer_key_update(connection);

                                                        if (status != qsc_tls_status_success)
                                                        {
                                                            tls_engine_fail_connection(connection, qsc_tls_alert_internal_error);
                                                        }
                                                        else
                                                        {
                                                            connection->keyupdaterequestoutstanding = false;

                                                            if (requestupdate == true && connection->writekeyupdateepoch < QSC_TLS_KEY_UPDATE_EPOCH_LIMIT)
                                                            {
                                                                connection->keyupdateresponsepending = true;

                                                                if (responseoutput != NULL && responseoutlen != 0U && responsewritten != NULL)
                                                                {
                                                                    status = qsc_tls_engine_request_key_update(connection, false, responseoutput, responseoutlen, responsewritten);

                                                                    if (status != qsc_tls_status_success)
                                                                    {
                                                                        tls_engine_fail_connection(connection, qsc_tls_alert_internal_error);
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            else if (htype == qsc_tls_handshake_type_new_session_ticket)
                                            {
                                                if (connection->role != qsc_tls_role_client || qsc_tls_engine_is_handshake_complete(connection) == false)
                                                {
                                                    tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                                                    status = qsc_tls_status_invalid_message;
                                                }
                                                else
                                                {
                                                    status = tls_engine_process_new_session_ticket(connection, handshakebuffer + offset, hbodylen);

                                                    if (status != qsc_tls_status_success)
                                                    {
                                                        if (status == qsc_tls_status_invalid_message)
                                                        {
                                                            tls_engine_fail_connection(connection, qsc_tls_alert_illegal_parameter);
                                                        }
                                                        else
                                                        {
                                                            tls_engine_fail_connection(connection, (status == qsc_tls_status_invalid_input
                                                                || status == qsc_tls_status_invalid_length)
                                                                ? qsc_tls_alert_decode_error
                                                                : qsc_tls_alert_internal_error);
                                                        }
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                /* Post-handshake authentication is not advertised by QSC. CertificateRequest and
                                                 * every other context-invalid Handshake message therefore require unexpected_message. */
                                                tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                                                status = qsc_tls_status_invalid_message;
                                            }

                                            if (status == qsc_tls_status_success)
                                            {
                                                offset += hbodylen;
                                            }
                                        }

                                        if (status == qsc_tls_status_success && offset != 0U)
                                        {
                                            const size_t remaining = *handshakebufferlen - offset;

                                            if (remaining != 0U)
                                            {
                                                qsc_memutils_move(handshakebuffer, handshakebuffer + offset, remaining);
                                            }

                                            *handshakebufferlen = remaining;
                                        }
                                    }
                                }
                                else
                                {
                                    tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                                    status = qsc_tls_status_invalid_message;
                                }
                            }

                            qsc_memutils_secure_erase(connection->applicationbuffer, sizeof(connection->applicationbuffer));
                            connection->applicationbufferlen = 0U;
                        }
                    }
                }
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_engine_request_key_update(qsc_tls_connection* connection, bool requestpeerupdate, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);

    uint8_t next_secret[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t new_key[32U] = { 0U };
    uint8_t new_iv[12U] = { 0U };
    uint8_t hs[5U] = { 0U };
    qsc_tls_record_state* write_record;
    uint8_t* write_traffic_secret;
    size_t digest_size;
    size_t hsoff;
    size_t ivlen;
    size_t keylen;
    qsc_tls_hash_algorithm hash;
    qsc_tls_cipher_suite suite;
    qsc_tls_status status;

    write_record = (qsc_tls_record_state*)NULL;
    write_traffic_secret = (uint8_t*)NULL;
    digest_size = 0U;
    hsoff = 0U;
    ivlen = 0U;
    keylen = 0U;
    hash = qsc_tls_hash_none;
    suite = qsc_tls_cipher_suite_none;
    status = qsc_tls_status_invalid_input;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (connection != NULL && output != NULL && written != NULL)
    {
        if (qsc_tls_engine_is_handshake_complete(connection) == false)
        {
            status = qsc_tls_status_invalid_state;
        }
        else if (connection->writekeyupdateepoch >= QSC_TLS_KEY_UPDATE_EPOCH_LIMIT)
        {
            status = qsc_tls_status_invalid_state;
        }
        else if (requestpeerupdate == true &&
            (connection->keyupdaterequestoutstanding == true || connection->keyupdateresponsepending == true))
        {
            status = qsc_tls_status_invalid_state;
        }
        else
        {
            if (connection->role == qsc_tls_role_client)
            {
                write_record = &connection->state.client.writerecord;
                write_traffic_secret = connection->state.client.keyschedule.clientapplicationtrafficsecret;
                hash = connection->state.client.negotiatedhash;
                suite = connection->state.client.negotiatedsuite;
                digest_size = connection->state.client.keyschedule.digestsize;
            }
            else
            {
                write_record = &connection->state.server.writerecord;
                write_traffic_secret = connection->state.server.keyschedule.serverapplicationtrafficsecret;
                hash = connection->state.server.negotiatedhash;
                suite = connection->state.server.negotiatedsuite;
                digest_size = connection->state.server.keyschedule.digestsize;
            }

            status = qsc_tls_keyschedule_advance_traffic_secret(hash, write_traffic_secret, digest_size, next_secret);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_keyschedule_suite_record_sizes(suite, &keylen, &ivlen);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_keyschedule_derive_traffic_keys(hash, next_secret, digest_size, keylen, ivlen, new_key, new_iv);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_key_update, 1U);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_handshake_encode_key_update(hs, sizeof(hs), &hsoff, requestpeerupdate);
            }

            if (status == qsc_tls_status_success)
            {
                /* RFC 9846 Section 4.7.3: KeyUpdate is protected with the old key. */
                status = qsc_tls_record_encrypt(write_record, output, outlen, written, qsc_tls_record_content_handshake, hs, hsoff);

                if (status == qsc_tls_status_authentication_failure)
                {
                    tls_engine_fail_key_usage(connection);
                }
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_record_state_install_keys(write_record, suite, new_key, keylen, new_iv, ivlen);

                if (status == qsc_tls_status_success)
                {
                    qsc_memutils_copy(write_traffic_secret, next_secret, digest_size);
                    connection->writekeyupdateepoch += 1ULL;

                    if (requestpeerupdate == true)
                    {
                        connection->keyupdaterequestoutstanding = true;
                    }
                    else
                    {
                        connection->keyupdateresponsepending = false;
                    }
                }
                else
                {
                    tls_engine_fail_key_usage(connection);
                    *written = 0U;
                }
            }
        }
    }

    qsc_memutils_secure_erase(next_secret, sizeof(next_secret));
    qsc_memutils_secure_erase(new_key, sizeof(new_key));
    qsc_memutils_secure_erase(new_iv, sizeof(new_iv));
    qsc_memutils_secure_erase(hs, sizeof(hs));

    return status;
}

qsc_tls_status qsc_tls_engine_emit_session_ticket(qsc_tls_connection* connection, uint32_t lifetime_seconds, uint8_t* output, size_t outlen, size_t* written, qsc_tls_session_ticket* ticketout)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);
    QSC_ASSERT(ticketout != NULL);

    uint8_t nstbody[256U + QSC_TLS_TICKET_MAX_SIZE + 64U] = { 0U };
    uint8_t hsmsg[4U + sizeof(nstbody)] = { 0U };
    uint8_t ageaddbytes[4U] = { 0U };
    uint8_t ticketbytes[32U] = { 0U };
    qsc_tls_server_state* s;
    size_t hsoff;
    size_t nstbodylen;
    qsc_tls_status status;

    s = (qsc_tls_server_state*)NULL;
    hsoff = 0U;
    nstbodylen = 0U;
    status = qsc_tls_status_invalid_input;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (connection != NULL && output != NULL && written != NULL && ticketout != NULL)
    {
        if (connection->role == qsc_tls_role_server && qsc_tls_engine_is_handshake_complete(connection) == true)
        {
            s = &connection->state.server;

            if (lifetime_seconds > QSC_TLS_SESSION_TICKET_LIFETIME_MAX)
            {
                status = qsc_tls_status_invalid_length;
            }
            else if (s->clientpskdhemodeoffered == false || s->config.requestclientauth == true || connection->sessionticketnonce == UINT64_MAX)
            {
                status = qsc_tls_status_invalid_state;
            }
            else if (qsc_csp_generate(ageaddbytes, sizeof(ageaddbytes)) == false || qsc_csp_generate(ticketbytes, sizeof(ticketbytes)) == false)
            {
                status = qsc_tls_status_failure;
            }
            else
            {
                qsc_memutils_clear(ticketout, sizeof(*ticketout));
                ticketout->issuetimems = qsc_timestamp_epochtime_milliseconds();
                ticketout->lifetime = lifetime_seconds;
                ticketout->maxearlydatasize = 0U;
                ticketout->protocolversion = QSC_TLS_PROTOCOL_VERSION_13;
                ticketout->ageadd = ((uint32_t)ageaddbytes[0U] << 24)
                    | ((uint32_t)ageaddbytes[1U] << 16)
                    | ((uint32_t)ageaddbytes[2U] << 8)
                    | ((uint32_t)ageaddbytes[3U]);
                qsc_intutils_be64to8(ticketout->nonce, connection->sessionticketnonce);
                ticketout->noncelen = sizeof(uint64_t);
                qsc_memutils_copy(ticketout->ticket, ticketbytes, sizeof(ticketbytes));
                ticketout->ticketlen = sizeof(ticketbytes);
                ticketout->suite = s->negotiatedsuite;

                if (s->servernamereceived == true && s->servernamelen <= QSC_TLS_MAX_HOSTNAME_SIZE)
                {
                    qsc_memutils_copy(ticketout->servername, (const uint8_t*)s->servername, s->servernamelen);
                    ticketout->servernamelen = s->servernamelen;
                }

                if (s->alpnselected == true && s->selectedalpnlen <= QSC_TLS_MAX_ALPN_SIZE)
                {
                    qsc_memutils_copy(ticketout->alpn, s->selectedalpn, s->selectedalpnlen);
                    ticketout->alpnlen = s->selectedalpnlen;
                }

                if (ticketout->issuetimems == 0ULL)
                {
                    status = qsc_tls_status_failure;
                }
                else
                {
                    ticketout->resumptionsecretlen = s->keyschedule.digestsize;
                    status = qsc_tls_keyschedule_derive_resumption_psk(&s->keyschedule, ticketout->nonce, ticketout->noncelen, ticketout->resumptionsecret, ticketout->resumptionsecretlen);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_session_ticket_encode(ticketout, nstbody, sizeof(nstbody), &nstbodylen);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_handshake_write_header(hsmsg, sizeof(hsmsg), &hsoff, qsc_tls_handshake_type_new_session_ticket, nstbodylen);
                }

                if (status == qsc_tls_status_success)
                {
                    qsc_memutils_copy(hsmsg + hsoff, nstbody, nstbodylen);
                    hsoff += nstbodylen;
                    status = qsc_tls_record_encrypt(&s->writerecord, output, outlen, written, qsc_tls_record_content_handshake, hsmsg, hsoff);

                    if (status == qsc_tls_status_success)
                    {
                        connection->sessionticketnonce += 1ULL;
                    }
                }
            }
        }
        else
        {
            status = qsc_tls_status_invalid_state;
        }
    }

    qsc_memutils_secure_erase(ageaddbytes, sizeof(ageaddbytes));
    qsc_memutils_secure_erase(ticketbytes, sizeof(ticketbytes));
    qsc_memutils_secure_erase(nstbody, sizeof(nstbody));
    qsc_memutils_secure_erase(hsmsg, sizeof(hsmsg));

    return status;
}

qsc_tls_status qsc_tls_engine_consume_session_ticket(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, size_t* consumed, qsc_tls_session_ticket* ticketout)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(consumed != NULL);
    QSC_ASSERT(ticketout != NULL);

    uint8_t applicationdata[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    size_t applicationwritten;
    qsc_tls_status status;

    applicationwritten = 0U;
    status = qsc_tls_status_invalid_input;

    if (consumed != NULL)
    {
        *consumed = 0U;
    }

    if (ticketout != NULL)
    {
        qsc_memutils_clear(ticketout, sizeof(*ticketout));
    }

    if (connection != NULL && input != NULL && consumed != NULL && ticketout != NULL)
    {
        if (connection->role == qsc_tls_role_client && qsc_tls_engine_is_handshake_complete(connection) == true)
        {
            status = qsc_tls_engine_read_application_data_ex(connection, input, inlen, consumed, applicationdata, sizeof(applicationdata), &applicationwritten, NULL, 0U, NULL);

            if (status == qsc_tls_status_success)
            {
                if (applicationwritten != 0U)
                {
                    tls_engine_fail_connection(connection, qsc_tls_alert_unexpected_message);
                    status = qsc_tls_status_invalid_message;
                }
                else if (connection->hasreceivedticket == true)
                {
                    status = qsc_tls_engine_take_session_ticket(connection, ticketout);
                }
            }
        }
        else
        {
            status = qsc_tls_status_invalid_state;
        }
    }

    qsc_memutils_secure_erase(applicationdata, sizeof(applicationdata));

    return status;
}

qsc_tls_status qsc_tls_engine_take_session_ticket(qsc_tls_connection* connection, qsc_tls_session_ticket* ticketout)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(ticketout != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (connection != NULL && ticketout != NULL)
    {
        if (connection->role == qsc_tls_role_client && connection->hasreceivedticket == true)
        {
            qsc_memutils_copy(ticketout, &connection->receivedticket, sizeof(*ticketout));
            qsc_tls_session_ticket_dispose(&connection->receivedticket);
            connection->hasreceivedticket = false;
            status = qsc_tls_status_success;
        }
        else
        {
            status = qsc_tls_status_invalid_state;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_engine_close(qsc_tls_connection* connection, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);

    /* produce an encrypted close_notify if we have app keys, otherwise a plaintext alert */
    uint8_t alert[2U] = { 0U };
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (written != NULL) 
    { 
        *written = 0U; 
    }

    if (connection != NULL && output != NULL && written != NULL)
    {
        alert[0U] = (uint8_t)qsc_tls_alert_level_warning;
        alert[1U] = (uint8_t)qsc_tls_alert_close_notify;

        if (qsc_tls_engine_is_handshake_complete(connection))
        {
            qsc_tls_record_state* w = (connection->role == qsc_tls_role_client)
                ? &connection->state.client.writerecord
                : &connection->state.server.writerecord;

            status = qsc_tls_record_encrypt(w, output, outlen, written, qsc_tls_record_content_alert, alert, sizeof(alert));
        }
        else
        {
            status = qsc_tls_record_encode_plaintext(output, outlen, written, qsc_tls_record_content_alert, alert, sizeof(alert));
        }
    }

    return status;
}

bool qsc_tls_engine_is_handshake_complete(const qsc_tls_connection* connection)
{
    QSC_ASSERT(connection != NULL);

    bool res;

    res = false;

    if (connection != NULL)
    {
        if (connection->role == qsc_tls_role_client)
        {
            res = qsc_tls_client_is_handshake_complete(&connection->state.client);
        }
        else
        {
            res = qsc_tls_server_is_handshake_complete(&connection->state.server);
        }
    }

    return res;
}
