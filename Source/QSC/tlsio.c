#include "tlsio.h"
#include "memutils.h"
#include "socketbase.h"
#include "tlsrecord.h"

static qsc_tls_status tls_io_send_all(qsc_socket* socket, const uint8_t* input, size_t inlen)
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

static qsc_tls_status tls_io_rx_read_more(qsc_tls_io_connection* io)
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
            got = qsc_socket_receive(io->socket, io->rxbuffer + io->rxbufferlen, request, qsc_socket_receive_flag_none);

            if (got != 0U)
            {
                io->rxbufferlen += got;
                status = qsc_tls_status_success;
            }
            else
            {
                status = qsc_tls_status_failure;
            }
        }
        else
        {
            status = qsc_tls_status_buffer_too_small;
        }
    }

    return status;
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
    QSC_ASSERT(io != NULL);

    uint8_t outbuf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (io != NULL && io->engine != NULL && io->socket != NULL)
    {
        status = qsc_tls_status_success;

        while (qsc_tls_engine_is_handshake_complete(io->engine) == false)
        {
            size_t consumed;
            size_t produced;

            consumed = 0U;
            produced = 0U;

            status = qsc_tls_engine_handshake(io->engine, io->rxbuffer, io->rxbufferlen, &consumed, outbuf, sizeof(outbuf), &produced);

            if (status != qsc_tls_status_success)
            {
                break;
            }

            tls_io_rx_shift(io, consumed);

            if (produced > 0U)
            {
                status = tls_io_send_all(io->socket, outbuf, produced);

                if (status != qsc_tls_status_success)
                {
                    break;
                }
            }

            if (qsc_tls_engine_is_handshake_complete(io->engine) == true)
            {
                break;
            }

            if (consumed == 0U && produced == 0U)
            {
                status = tls_io_rx_read_more(io);

                if (status != qsc_tls_status_success)
                {
                    break;
                }
            }
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

    if (io != NULL && io->engine != NULL && io->socket != NULL && output != NULL && read != NULL)
    {
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
                size_t consumed;
                size_t responsewritten;

                consumed = 0U;
                responsewritten = 0U;

                status = qsc_tls_engine_read_application_data_ex(io->engine, io->rxbuffer, io->rxbufferlen, &consumed,
                    output, outlen, read, response, sizeof(response), &responsewritten);

                if (status != qsc_tls_status_success)
                {
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
