#include "tlsengine.h"
#include "csp.h"
#include "memutils.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlsrecord.h"
#include "tlskeyschedule.h"
#include "tlshandshake.h"
#include "tlssession.h"

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

    qsc_tls_status status;
    qsc_tls_record_state* w;

    status = qsc_tls_status_invalid_input;

    if (written != NULL)
    { 
        *written = 0U; 
    }

    if (connection != NULL && input != NULL && output != NULL && written != NULL)
    {
        if (!qsc_tls_engine_is_handshake_complete(connection))
        {
            /* permit 0-RTT writes: client role, has emitted CH with early_data, and the
             * write record holds a key (early_traffic_secret was installed in send_hello) */
            bool allowearly = (connection->role == qsc_tls_role_client
                && connection->state.client.earlydataoffered
                && connection->state.client.writerecord.initialized);

            if (allowearly == false)
            {
                return qsc_tls_status_invalid_state;
            }
        }

        w = (connection->role == qsc_tls_role_client)
            ? &connection->state.client.writerecord
            : &connection->state.server.writerecord;

        status = qsc_tls_record_encrypt(w, output, outlen, written, qsc_tls_record_content_application_data, input, inlen);
    }

    return status;
}

qsc_tls_status qsc_tls_engine_read_application_data(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, size_t* consumed, uint8_t* output, size_t outlen, size_t* written)
{
    /* backward-compatible wrapper: no response buffer, post-handshake responses are dropped */
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
    size_t reclen;
    qsc_tls_record_content_type inner;
    qsc_tls_status status;
    bool complete;

    status = qsc_tls_status_invalid_input;
    reclen = 0U;
    inner = qsc_tls_record_content_invalid;
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

    if (connection != NULL && input != NULL && consumed != NULL && written != NULL)
    {
        if (!qsc_tls_engine_is_handshake_complete(connection))
        {
            /* permit server reads of 0-RTT app data while in waiting_end_of_early_data phase
             * read record currently holds the early_traffic key for incoming 0-RTT records */
            bool allow_early = (connection->role == qsc_tls_role_server
                && connection->state.server.earlydataaccepted
                && connection->state.server.phase == qsc_tls_server_phase_waiting_end_of_early_data
                && connection->state.server.readrecord.initialized);

            if (allow_early == false)
            {
                return qsc_tls_status_invalid_state;
            }
        }

        r = (connection->role == qsc_tls_role_client)
            ? &connection->state.client.readrecord
            : &connection->state.server.readrecord;

        status = qsc_tls_record_try_get_span_length(input, inlen, &reclen, &complete);

        if (status != qsc_tls_status_success)
        {
            return status;
        }

        if (complete == false)
        {
            return qsc_tls_status_success;
        }

        status = qsc_tls_record_decrypt(r, output, outlen, written, &inner, input, reclen);

        if (status != qsc_tls_status_success)
        {
            return status;
        }

        *consumed = reclen;

        if (inner == qsc_tls_record_content_application_data)
        {
            /* already written into the caller's output buffer; done */
            return qsc_tls_status_success;
        }

        if (inner == qsc_tls_record_content_alert)
        {
            /* surface the alert to the caller by leaving *written populated; caller inspects */
            return qsc_tls_status_success;
        }

        if (inner == qsc_tls_record_content_handshake)
        {
            /* post-handshake handshake messages Currently supported: KeyUpdate */
            size_t hbodylen;
            size_t hswritten;
            size_t offset;
            qsc_tls_handshake_type htype;

            hswritten = *written;
            offset = 0U;

            /* reset written: handshake plaintext isn't "application data" for the caller */
            *written = 0U;

            while (offset < hswritten)
            {
                status = qsc_tls_handshake_read_header(output, hswritten, &offset, &htype, &hbodylen);

                if (status != qsc_tls_status_success)
                {
                    return status;
                }

                if (offset + hbodylen > hswritten)
                {
                    return qsc_tls_status_invalid_length;
                }

                if (htype == qsc_tls_handshake_type_key_update)
                {
                    bool request_update = false;

                    request_update = false;

                    status = qsc_tls_handshake_decode_key_update(output + offset, hbodylen, &request_update);

                    if (status != qsc_tls_status_success)
                    {
                        return status;
                    }

                    /* apply the peer's rekey on our READ side */
                    status = tls_engine_apply_peer_key_update(connection);

                    if (status != qsc_tls_status_success)
                    {
                        return status;
                    }

                    /* if peer requested we update too, emit our own KeyUpdate (update_not_requested)
                     * into the response buffer The response is encrypted under our write key, then
                     * our write key gets rotated by request_key_update itself */
                    if (request_update)
                    {
                        if (responseoutput == NULL || responseoutlen == 0U || responsewritten == NULL)
                        {
                            /* RFC 8446 s4.6.3 - when the peer sends KeyUpdate(update_requested),
                             * the receiver MUST send its own KeyUpdate in response.  Silently skipping
                             * it desynchronises traffic keys, so we must treat the missing output buffer
                             * as a fatal protocol error rather than a recoverable omission. */
                            return qsc_tls_status_invalid_state;
                        }
                        else
                        {
                            status = qsc_tls_engine_request_key_update(connection, false, responseoutput, responseoutlen, responsewritten);

                            if (status != qsc_tls_status_success)
                            {
                                return status;
                            }
                        }
                    }
                }

                offset += hbodylen;
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

    /* RFC 8446 4.6.3 KeyUpdate Emit a KeyUpdate handshake message encrypted under the CURRENT write key, 
     * then advance our write traffic secret and install the new write key The peer will do the reverse: 
     * decrypt under the old read key, advance, install the new read key */

    uint8_t next_secret[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t new_key[32U] = { 0U };
    uint8_t new_iv[12U] = { 0U };
    uint8_t hs[4U + 1U] = { 0U };
    qsc_tls_record_state* write_record;
    uint8_t* write_traffic_secret;
    size_t digest_size;
    size_t hsoff;
    size_t ivlen;
    size_t keylen;
    qsc_tls_hash_algorithm hash;
    qsc_tls_cipher_suite suite;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (written != NULL) 
    {
        *written = 0U;
    }

    if (connection != NULL && output != NULL && written != NULL)
    {
        if (qsc_tls_engine_is_handshake_complete(connection) == true)
        {
            /* locate the caller's outbound record state, traffic secret, hash, and suite */
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

            /* build KeyUpdate handshake message: type(24) || length(0x000001) || body(1 byte) */
            hsoff = 0U;
            status = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_key_update, 1U);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_handshake_encode_key_update(hs, sizeof(hs), &hsoff, requestpeerupdate);

                if (status == qsc_tls_status_success)
                {
                    /* encrypt under the CURRENT write key, emit the record */
                    status = qsc_tls_record_encrypt(write_record, output, outlen, written, qsc_tls_record_content_handshake, hs, hsoff);

                    if (status == qsc_tls_status_success)
                    {
                        /* now advance our write traffic secret and reinstall the write key */
                        status = qsc_tls_keyschedule_advance_traffic_secret(hash, write_traffic_secret, digest_size, next_secret);

                        if (status == qsc_tls_status_success)
                        {
                            qsc_memutils_copy(write_traffic_secret, next_secret, digest_size);
                            status = qsc_tls_keyschedule_suite_record_sizes(suite, &keylen, &ivlen);

                            if (status == qsc_tls_status_success)
                            {
                                status = qsc_tls_keyschedule_derive_traffic_keys(hash, write_traffic_secret, digest_size, keylen, ivlen, new_key, new_iv);

                                if (status == qsc_tls_status_success)
                                {
                                    status = qsc_tls_record_state_install_keys(write_record, suite, new_key, keylen, new_iv, ivlen);
                                }
                            }
                        }

                        qsc_memutils_secure_erase(next_secret, sizeof(next_secret));
                        qsc_memutils_secure_erase(new_key, sizeof(new_key));
                        qsc_memutils_secure_erase(new_iv, sizeof(new_iv));
                    }
                }
            }
        }
        else
        {
            status = qsc_tls_status_invalid_state;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_engine_emit_session_ticket(qsc_tls_connection* connection, uint32_t lifetime_seconds, uint8_t* output, size_t outlen, size_t* written, qsc_tls_session_ticket* ticketout)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);
    QSC_ASSERT(ticketout != NULL);

    /* server role, post-handshake Build a NewSessionTicket handshake message,
     * encrypt under the server's write key, return the record + the filled
     * ticket struct (so the caller can stash it keyed on ticket bytes) */
    uint8_t nstbody[256U + QSC_TLS_TICKET_MAX_SIZE + 64U] = { 0U };
    uint8_t hsmsg[4U + sizeof(nstbody)] = { 0U };
    uint8_t ageaddbytes[4U] = { 0U };
    uint8_t noncebytes[8U] = { 0U };
    uint8_t ticketbytes[32U] = { 0U };
    qsc_tls_status status;
    qsc_tls_server_state* s;
    size_t hsoff;
    size_t nstbodylen;

    hsoff = 0U;
    nstbodylen = 0U;
    status = qsc_tls_status_invalid_input;

    if (written != NULL) 
    { 
        *written = 0U;
    }

    if (connection != NULL && output != NULL && written != NULL && ticketout != NULL)
    {
        if (connection->role == qsc_tls_role_server)
        {
            if (qsc_tls_engine_is_handshake_complete(connection) == true)
            {
                s = &connection->state.server;

                /* generate ticket_age_add (random 32-bit), 8-byte nonce, 32-byte opaque ticket id */
                if (qsc_csp_generate(ageaddbytes, sizeof(ageaddbytes)) == true)
                {
                    if (qsc_csp_generate(noncebytes, sizeof(noncebytes)) == true)
                    {
                        if (qsc_csp_generate(ticketbytes, sizeof(ticketbytes)) == true)
                        {
                            qsc_memutils_clear(ticketout, sizeof(*ticketout));
                            ticketout->lifetime = lifetime_seconds;

                            ticketout->ageadd = ((uint32_t)ageaddbytes[0U] << 24)
                                | ((uint32_t)ageaddbytes[1U] << 16)
                                | ((uint32_t)ageaddbytes[2U] << 8)
                                | ((uint32_t)ageaddbytes[3U]);

                            qsc_memutils_copy(ticketout->nonce, noncebytes, sizeof(noncebytes));
                            ticketout->noncelen = sizeof(noncebytes);
                            qsc_memutils_copy(ticketout->ticket, ticketbytes, sizeof(ticketbytes));
                            ticketout->ticketlen = sizeof(ticketbytes);
                            ticketout->suite = s->negotiatedsuite;

                            /* derive the per-ticket resumption PSK from resumption_master_secret + nonce */
                            ticketout->resumptionsecretlen = s->keyschedule.digestsize;

                            status = qsc_tls_keyschedule_derive_resumption_psk(&s->keyschedule, ticketout->nonce, ticketout->noncelen,
                                ticketout->resumptionsecret, ticketout->resumptionsecretlen);

                            if (status == qsc_tls_status_success)
                            {
                                /* encode NST body */
                                status = qsc_tls_session_ticket_encode(ticketout, nstbody, sizeof(nstbody), &nstbodylen);

                                if (status == qsc_tls_status_success)
                                {
                                    /* wrap in handshake header */
                                    status = qsc_tls_handshake_write_header(hsmsg, sizeof(hsmsg), &hsoff, qsc_tls_handshake_type_new_session_ticket, nstbodylen);

                                    if (status == qsc_tls_status_success)
                                    {
                                        qsc_memutils_copy(hsmsg + hsoff, nstbody, nstbodylen);
                                        hsoff += nstbodylen;

                                        /* encrypt as a post-established handshake record under the server's write key */
                                        status = qsc_tls_record_encrypt(&s->writerecord, output, outlen, written, qsc_tls_record_content_handshake, hsmsg, hsoff);

                                        qsc_memutils_secure_erase(nstbody, sizeof(nstbody));
                                        qsc_memutils_secure_erase(hsmsg, sizeof(hsmsg));
                                    }
                                }
                            }
                        }
                        else
                        {
                            status = qsc_tls_status_failure;
                        }
                    }
                    else
                    {
                        status = qsc_tls_status_failure;
                    }
                }
                else
                {
                    status = qsc_tls_status_failure;
                }
            }
            else
            {
                status = qsc_tls_status_invalid_state;
            }
        }
        else
        {
            status = qsc_tls_status_invalid_state;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_engine_consume_session_ticket(qsc_tls_connection* connection, const uint8_t* input, size_t inlen, size_t* consumed, qsc_tls_session_ticket* ticketout)
{
    QSC_ASSERT(connection != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(consumed != NULL);
    QSC_ASSERT(ticketout != NULL);

    /* client role, post-handshake Decrypt a handshake-inner record, expect
     * NewSessionTicket, parse it, derive the PSK, fill ticketout */
    uint8_t plaintext[4U + QSC_TLS_TICKET_MAX_SIZE + 256U] = { 0U };
    qsc_tls_client_state* c;
    size_t bodylen;
    size_t offset;
    size_t plainlen;
    size_t reclen;
    qsc_tls_record_content_type inner;
    qsc_tls_handshake_type htype;
    qsc_tls_status status;
    bool complete = false;

    plainlen = 0U;
    reclen = 0U;
    inner = qsc_tls_record_content_invalid;
    complete = false;
    status = qsc_tls_status_invalid_input;

    if (consumed != NULL) 
    {
        *consumed = 0U; 
    }

    if (connection != NULL && input != NULL && consumed != NULL && ticketout != NULL)
    {
        if (connection->role == qsc_tls_role_client)
        {
            if (qsc_tls_engine_is_handshake_complete(connection) == true)
            {
                c = &connection->state.client;

                status = qsc_tls_record_try_get_span_length(input, inlen, &reclen, &complete);

                if (status == qsc_tls_status_success)
                {
                    if (complete == false)
                    {
                        status = qsc_tls_status_success;
                    }
                    else
                    {
                        status = qsc_tls_record_decrypt(&c->readrecord, plaintext, sizeof(plaintext), &plainlen, &inner, input, reclen);

                        if (status == qsc_tls_status_success)
                        {
                            if (inner == qsc_tls_record_content_handshake)
                            {
                                /* expect handshake header + NewSessionTicket body */
                                offset = 0U;
                                status = qsc_tls_handshake_read_header(plaintext, plainlen, &offset, &htype, &bodylen);

                                if (status == qsc_tls_status_success)
                                {
                                    if (htype == qsc_tls_handshake_type_new_session_ticket)
                                    {
                                        if (offset + bodylen <= plainlen)
                                        {
                                            status = qsc_tls_session_ticket_decode(plaintext + offset, bodylen, ticketout);

                                            if (status == qsc_tls_status_success)
                                            {
                                                /* derive the PSK locally from the client's resumption_master_secret */
                                                ticketout->suite = c->negotiatedsuite;
                                                ticketout->resumptionsecretlen = c->keyschedule.digestsize;

                                                status = qsc_tls_keyschedule_derive_resumption_psk(&c->keyschedule, ticketout->nonce, ticketout->noncelen, ticketout->resumptionsecret, ticketout->resumptionsecretlen);

                                                if (status == qsc_tls_status_success)
                                                {
                                                    *consumed = reclen;
                                                    qsc_memutils_secure_erase(plaintext, sizeof(plaintext));
                                                }
                                            }
                                        }
                                        else
                                        {
                                            status = qsc_tls_status_invalid_length;
                                        }
                                    }
                                    else
                                    {
                                        status = qsc_tls_status_invalid_message;
                                    }
                                }
                            }
                            else
                            {
                                status = qsc_tls_status_invalid_message;
                            }
                        }
                    }
                }
            }
            else
            {
                status = qsc_tls_status_invalid_state;
            }
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
