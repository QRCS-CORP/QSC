#include "tlsio.h"
#include "tlsalert.h"
#include "memutils.h"
#include "socketbase.h"
#include "sysutils.h"
#include "tlskeyschedule.h"
#include "tlsrecord.h"

static qsc_tls_status tls_io_deadline_remaining(uint64_t startms, uint32_t timeoutms, uint32_t* remainingms)
{
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (remainingms != NULL)
    {
        uint64_t elapsed;
        uint64_t nowms;

        *remainingms = 0U;
        status = qsc_tls_status_success;

        if (timeoutms != 0U)
        {
            nowms = qsc_sysutils_system_uptime();
            elapsed = (nowms >= startms) ? (nowms - startms) : UINT64_MAX;

            if (elapsed >= (uint64_t)timeoutms)
            {
                status = qsc_tls_status_timeout;
            }
            else
            {
                *remainingms = timeoutms - (uint32_t)elapsed;
            }
        }
    }

    return status;
}

static qsc_tls_status tls_io_wait_ready(const qsc_socket* socket, bool sendready, uint64_t startms, uint32_t timeoutms)
{
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (socket != NULL)
    {
        status = qsc_tls_status_success;

        if (timeoutms != 0U)
        {
            struct timeval tv;
            uint32_t remainingms;
            bool ready;

            remainingms = 0U;
            ready = false;
            status = tls_io_deadline_remaining(startms, timeoutms, &remainingms);

            if (status == qsc_tls_status_success)
            {
                tv.tv_sec = (long)(remainingms / 1000U);
                tv.tv_usec = (long)((remainingms % 1000U) * 1000U);
                ready = (sendready == true) ? qsc_socket_send_ready(socket, &tv) : qsc_socket_receive_ready(socket, &tv);

                if (ready == false)
                {
                    status = tls_io_deadline_remaining(startms, timeoutms, &remainingms);

                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_status_failure;
                    }
                }
                else
                {
                    status = tls_io_deadline_remaining(startms, timeoutms, &remainingms);
                }
            }
        }
    }

    return status;
}

static qsc_tls_status tls_io_send_all_timed(qsc_socket* socket, const uint8_t* input, size_t inlen, uint64_t startms, uint32_t timeoutms)
{
    qsc_tls_status status;
    size_t sent;

    status = qsc_tls_status_invalid_input;

    if (socket != NULL && input != NULL)
    {
        sent = 0U;
        status = qsc_tls_status_success;

        while (sent < inlen)
        {
            size_t n;

            status = tls_io_wait_ready(socket, true, startms, timeoutms);

            if (status != qsc_tls_status_success)
            {
                break;
            }

            n = qsc_socket_send(socket, input + sent, inlen - sent, qsc_socket_send_flag_none);

            if (n == 0U)
            {
                status = qsc_tls_status_failure;
                break;
            }

            sent += n;
        }
    }

    return status;
}

static qsc_tls_status tls_io_send_all(qsc_socket* socket, const uint8_t* input, size_t inlen)
{
    return tls_io_send_all_timed(socket, input, inlen, 0U, 0U);
}

static qsc_tls_status tls_io_encode_server_application_alert(qsc_tls_server_state* state, const uint8_t* alert, size_t alertlen, uint8_t* output, size_t outlen, size_t* written)
{
    qsc_tls_record_state record;
    uint8_t trafficsecret[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t key[32U] = { 0U };
    uint8_t iv[12U] = { 0U };
    size_t keylen;
    size_t ivlen;
    qsc_tls_status status;

    qsc_memutils_clear(&record, sizeof(record));
    keylen = 0U;
    ivlen = 0U;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && alert != NULL && output != NULL && written != NULL && state->keyschedule.masterdone == true && state->stashedserverfinhashlen != 0U)
    {
        status = qsc_tls_keyschedule_derive_secret_with_hash(state->negotiatedhash, state->keyschedule.mastersecret, state->keyschedule.digestsize,
            "s ap traffic", 12U, state->stashedserverfinhash, state->stashedserverfinhashlen, trafficsecret, state->keyschedule.digestsize);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_keyschedule_suite_record_sizes(state->negotiatedsuite, &keylen, &ivlen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, trafficsecret, state->keyschedule.digestsize, keylen, ivlen, key, iv);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_record_state_install_keys(&record, state->negotiatedsuite, key, keylen, iv, ivlen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_record_encrypt(&record, output, outlen, written, qsc_tls_record_content_alert, alert, alertlen);
        }
    }

    qsc_tls_record_state_dispose(&record);
    qsc_memutils_secure_erase(trafficsecret, sizeof(trafficsecret));
    qsc_memutils_secure_erase(key, sizeof(key));
    qsc_memutils_secure_erase(iv, sizeof(iv));

    return status;
}

static qsc_tls_status tls_io_encode_fatal_alert(qsc_tls_connection* engine, qsc_tls_status originstatus, bool handshakefailure, uint8_t* output, size_t outlen, size_t* written)
{
    uint8_t alert[QSC_TLS_ALERT_SIZE] = { 0U };
    qsc_tls_record_state* writerecord;
    qsc_tls_alert_description description;
    qsc_tls_status status;

    writerecord = (qsc_tls_record_state*)NULL;
    description = qsc_tls_alert_close_notify;
    status = qsc_tls_status_invalid_input;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (engine != NULL && output != NULL && written != NULL)
    {
        if (engine->role == qsc_tls_role_client)
        {
            description = engine->state.client.lastalert;
            writerecord = &engine->state.client.writerecord;
        }
        else
        {
            description = engine->state.server.lastalert;
            writerecord = &engine->state.server.writerecord;
        }

        if (qsc_tls_alert_is_valid(description) == false || description == qsc_tls_alert_close_notify || description == qsc_tls_alert_user_canceled)
        {
            description = qsc_tls_alert_from_status(originstatus);
        }

        if (qsc_tls_alert_is_valid(description) == true && description != qsc_tls_alert_close_notify && description != qsc_tls_alert_user_canceled)
        {
            status = qsc_tls_alert_encode(alert, sizeof(alert), description);

            if (status == qsc_tls_status_success)
            {
                if (handshakefailure == true && engine->role == qsc_tls_role_server && engine->state.server.keyschedule.masterdone == true &&
                    engine->state.server.stashedserverfinhashlen != 0U)
                {
                    status = tls_io_encode_server_application_alert(&engine->state.server, alert, sizeof(alert), output, outlen, written);
                }
                else if (writerecord != NULL && writerecord->initialized == true)
                {
                    status = qsc_tls_record_encrypt(writerecord, output, outlen, written, qsc_tls_record_content_alert, alert, sizeof(alert));
                }
                else
                {
                    status = qsc_tls_record_encode_plaintext(output, outlen, written, qsc_tls_record_content_alert, alert, sizeof(alert));
                }
            }
        }
        else
        {
            status = qsc_tls_status_invalid_state;
        }
    }

    qsc_memutils_secure_erase(alert, sizeof(alert));

    return status;
}

static void tls_io_rx_shift(qsc_tls_io_connection* io, size_t consumed)
{
    if (io != NULL && consumed > 0U)
    {
        if (consumed < io->rxbufferlen)
        {
            qsc_memutils_move(io->rxbuffer, io->rxbuffer + consumed, io->rxbufferlen - consumed);
            io->rxbufferlen -= consumed;
        }
        else
        {
            io->rxbufferlen = 0U;
        }
    }
}

static qsc_tls_status tls_io_rx_read_more_timed(qsc_tls_io_connection* io, uint64_t startms, uint32_t timeoutms)
{
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (io != NULL && io->socket != NULL)
    {
        if (io->rxbufferlen < sizeof(io->rxbuffer))
        {
            size_t got;
            size_t space;
            size_t request;

            space = sizeof(io->rxbuffer) - io->rxbufferlen;
            request = (space < QSC_TLS_IO_RECV_CHUNK) ? space : QSC_TLS_IO_RECV_CHUNK;
            status = tls_io_wait_ready(io->socket, false, startms, timeoutms);

            if (status == qsc_tls_status_success)
            {
                got = qsc_socket_receive(io->socket, io->rxbuffer + io->rxbufferlen, request, qsc_socket_receive_flag_none);

                if (got != 0U)
                {
                    io->rxbufferlen += got;
                }
                else
                {
                    status = qsc_tls_status_failure;
                }
            }
        }
        else
        {
            status = qsc_tls_status_buffer_too_small;
        }
    }

    return status;
}

static qsc_tls_status tls_io_rx_read_more(qsc_tls_io_connection* io)
{
    return tls_io_rx_read_more_timed(io, 0U, 0U);
}

static size_t tls_io_plaintext_take(qsc_tls_io_connection* io, uint8_t* output, size_t outlen)
{
    size_t available;
    size_t take;

    available = 0U;
    take = 0U;

    if (io != NULL && output != NULL && outlen != 0U && io->plaintextbufferoffset < io->plaintextbufferlen)
    {
        available = io->plaintextbufferlen - io->plaintextbufferoffset;
        take = (available < outlen) ? available : outlen;
        qsc_memutils_copy(output, io->plaintextbuffer + io->plaintextbufferoffset, take);
        io->plaintextbufferoffset += take;

        if (io->plaintextbufferoffset == io->plaintextbufferlen)
        {
            qsc_memutils_secure_erase(io->plaintextbuffer, io->plaintextbufferlen);
            io->plaintextbufferlen = 0U;
            io->plaintextbufferoffset = 0U;
        }
    }

    return take;
}

static qsc_tls_status tls_io_rx_has_complete_record(const qsc_tls_io_connection* io, bool* complete)
{
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (complete != NULL)
    {
        *complete = false;
    }

    if (io != NULL && complete != NULL)
    {
        size_t recordlen;

        recordlen = 0U;
        status = qsc_tls_record_try_get_span_length(io->rxbuffer, io->rxbufferlen, &recordlen, complete);
        (void)recordlen;
    }

    return status;
}

qsc_tls_status qsc_tls_io_attach(qsc_tls_io_connection* io, qsc_tls_connection* engine, qsc_socket* socket)
{
    QSC_ASSERT(io != NULL);
    QSC_ASSERT(engine != NULL);
    QSC_ASSERT(socket != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (io != NULL && engine != NULL && socket != NULL)
    {
        qsc_memutils_clear(io, sizeof(*io));
        io->engine = engine;
        io->socket = socket;
        status = qsc_tls_status_success;
    }

    return status;
}

qsc_tls_status qsc_tls_io_handshake(qsc_tls_io_connection* io)
{
    return qsc_tls_io_handshake_ex(io, QSC_TLS_IO_HANDSHAKE_TIMEOUT_DEFAULT);
}

qsc_tls_status qsc_tls_io_handshake_ex(qsc_tls_io_connection* io, uint32_t timeoutms)
{
    QSC_ASSERT(io != NULL);

    uint8_t* outbuf;
    qsc_tls_status status;
    uint64_t startms;

    outbuf = (uint8_t*)NULL;
    startms = qsc_sysutils_system_uptime();
    status = qsc_tls_status_invalid_input;

    if (io != NULL && io->engine != NULL && io->socket != NULL)
    {
        outbuf = (uint8_t*)qsc_memutils_malloc(QSC_TLS_STREAM_BUFFER_MAX_SIZE);

        if (outbuf == (uint8_t*)NULL)
        {
            status = qsc_tls_status_failure;
        }
        else
        {
            qsc_memutils_clear(outbuf, QSC_TLS_STREAM_BUFFER_MAX_SIZE);
            status = qsc_tls_status_success;

            while (qsc_tls_engine_is_handshake_complete(io->engine) == false)
            {
                size_t consumed;
                size_t produced;
                uint32_t remainingms;

                consumed = 0U;
                produced = 0U;
                remainingms = 0U;
                status = tls_io_deadline_remaining(startms, timeoutms, &remainingms);

                if (status != qsc_tls_status_success)
                {
                    break;
                }

                status = qsc_tls_engine_handshake(io->engine, io->rxbuffer, io->rxbufferlen, &consumed, outbuf, QSC_TLS_STREAM_BUFFER_MAX_SIZE, &produced);

                if (status != qsc_tls_status_success)
                {
                    qsc_tls_status originstatus;

                    originstatus = status;

                    if (originstatus != qsc_tls_status_failure && originstatus != qsc_tls_status_timeout)
                    {
                        produced = 0U;

                        if (tls_io_encode_fatal_alert(io->engine, originstatus, true, outbuf, QSC_TLS_STREAM_BUFFER_MAX_SIZE, &produced) == qsc_tls_status_success && produced != 0U)
                        {
                            (void)tls_io_send_all_timed(io->socket, outbuf, produced, startms, timeoutms);
                        }
                    }

                    status = originstatus;
                    break;
                }

                status = tls_io_deadline_remaining(startms, timeoutms, &remainingms);

                if (status != qsc_tls_status_success)
                {
                    break;
                }

                tls_io_rx_shift(io, consumed);

                if (produced > 0U)
                {
                    status = tls_io_send_all_timed(io->socket, outbuf, produced, startms, timeoutms);

                    if (status != qsc_tls_status_success)
                    {
                        break;
                    }
                }

                if (qsc_tls_engine_is_handshake_complete(io->engine) == true)
                {
                    status = tls_io_deadline_remaining(startms, timeoutms, &remainingms);
                    break;
                }

                if (consumed == 0U && produced == 0U)
                {
                    status = tls_io_rx_read_more_timed(io, startms, timeoutms);

                    if (status != qsc_tls_status_success)
                    {
                        break;
                    }
                }
            }

            qsc_memutils_secure_erase(outbuf, QSC_TLS_STREAM_BUFFER_MAX_SIZE);
            qsc_memutils_alloc_free(outbuf);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_io_send(qsc_tls_io_connection* io, const uint8_t* input, size_t inlen, size_t* written)
{
    QSC_ASSERT(io != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(written != NULL);

    uint8_t outbuf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    size_t produced;
    qsc_tls_status status;

    produced = 0U;
    status = qsc_tls_status_invalid_input;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (io != NULL && io->engine != NULL && io->socket != NULL && input != NULL && written != NULL)
    {
        status = qsc_tls_engine_write_application_data(io->engine, input, inlen, outbuf, sizeof(outbuf), &produced);

        if (status == qsc_tls_status_success)
        {
            status = tls_io_send_all(io->socket, outbuf, produced);

            if (status == qsc_tls_status_success)
            {
                *written = inlen;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_io_receive(qsc_tls_io_connection* io, uint8_t* output, size_t outlen, size_t* read)
{
    QSC_ASSERT(io != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(read != NULL);

    uint8_t response[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (read != NULL)
    {
        *read = 0U;
    }

    if (io != NULL && io->engine != NULL && io->socket != NULL && output != NULL && outlen != 0U && read != NULL)
    {
        *read = tls_io_plaintext_take(io, output, outlen);
        status = qsc_tls_status_success;

        while (*read == 0U)
        {
            bool complete;

            complete = false;
            status = tls_io_rx_has_complete_record(io, &complete);

            if (status != qsc_tls_status_success)
            {
                break;
            }

            while (complete == false)
            {
                status = tls_io_rx_read_more(io);

                if (status != qsc_tls_status_success)
                {
                    break;
                }

                status = tls_io_rx_has_complete_record(io, &complete);

                if (status != qsc_tls_status_success)
                {
                    break;
                }
            }

            if (status != qsc_tls_status_success)
            {
                break;
            }

            if (complete == true)
            {
                size_t applicationwritten;
                size_t consumed;
                size_t responsewritten;

                applicationwritten = 0U;
                consumed = 0U;
                responsewritten = 0U;
                status = qsc_tls_engine_read_application_data_ex(io->engine, io->rxbuffer, io->rxbufferlen, &consumed, io->plaintextbuffer,
                    sizeof(io->plaintextbuffer), &applicationwritten, response, sizeof(response), &responsewritten);

                if (status != qsc_tls_status_success)
                {
                    qsc_tls_status originstatus;

                    originstatus = status;

                    if (originstatus != qsc_tls_status_failure && originstatus != qsc_tls_status_timeout)
                    {
                        responsewritten = 0U;

                        if (tls_io_encode_fatal_alert(io->engine, originstatus, false, response, sizeof(response), &responsewritten) == qsc_tls_status_success && responsewritten != 0U)
                        {
                            (void)tls_io_send_all(io->socket, response, responsewritten);
                        }
                    }

                    status = originstatus;
                    break;
                }

                tls_io_rx_shift(io, consumed);

                if (responsewritten > 0U)
                {
                    status = tls_io_send_all(io->socket, response, responsewritten);

                    if (status != qsc_tls_status_success)
                    {
                        break;
                    }
                }

                if (consumed == 0U)
                {
                    status = qsc_tls_status_invalid_state;
                    break;
                }

                if (applicationwritten != 0U)
                {
                    io->plaintextbufferlen = applicationwritten;
                    io->plaintextbufferoffset = 0U;
                    *read = tls_io_plaintext_take(io, output, outlen);
                }
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_io_shutdown(qsc_tls_io_connection* io)
{
    QSC_ASSERT(io != NULL);

    uint8_t outbuf[64U] = { 0U };
    size_t produced;
    qsc_tls_status status;

    produced = 0U;
    status = qsc_tls_status_invalid_input;

    if (io != NULL && io->engine != NULL)
    {
        status = qsc_tls_engine_close(io->engine, outbuf, sizeof(outbuf), &produced);

        if (status == qsc_tls_status_success && produced > 0U && io->socket != NULL)
        {
            status = tls_io_send_all(io->socket, outbuf, produced);
        }
    }

    return status;
}
