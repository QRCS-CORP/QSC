#include "tlsio.h"
#include "memutils.h"
#include "socketbase.h"

#define QSC_TLS_IO_RECV_CHUNK 4096U

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

    uint8_t inbuf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    uint8_t outbuf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    size_t buflen;
    qsc_tls_status status;

    buflen = 0U;

    if (io != NULL && io->engine != NULL && io->socket != NULL)
    {
        /* driver loop: let the engine produce output, send it; receive input, feed it */
        while (!qsc_tls_engine_is_handshake_complete(io->engine))
        {
            size_t consumed;
            size_t produced;

            consumed = 0U;
            produced = 0U;

            status = qsc_tls_engine_handshake(io->engine, inbuf, buflen, &consumed, outbuf, sizeof(outbuf), &produced);

            if (status != qsc_tls_status_success)
            {
                return status;
            }

            /* shift any unconsumed inbound bytes */
            if (consumed > 0U && consumed < buflen)
            {
                qsc_memutils_move(inbuf, inbuf + consumed, buflen - consumed);
                buflen -= consumed;
            }
            else if (consumed == buflen)
            {
                buflen = 0U;
            }

            /* flush any output we produced */
            if (produced > 0U)
            {
                size_t n;
                size_t sent;
                size_t tosend;

                sent = 0U;
                tosend = produced;

                while (sent < tosend)
                {
                    n = qsc_socket_send(io->socket, outbuf + sent, tosend - sent, qsc_socket_send_flag_none);

                    if (n == 0U)
                    {
                        return qsc_tls_status_failure;
                    }

                    sent += n;
                }
            }

            /* if the handshake is now complete, stop looping */
            if (qsc_tls_engine_is_handshake_complete(io->engine) == true)
            {
                break;
            }

            /* if we have no unconsumed input and produced nothing this iteration, receive more */
            if (buflen == 0U && produced == 0U)
            {
                size_t got;
                size_t space;

                space = sizeof(inbuf) - buflen;
                got = qsc_socket_receive(io->socket, inbuf + buflen, space < QSC_TLS_IO_RECV_CHUNK ?
                    space : QSC_TLS_IO_RECV_CHUNK, qsc_socket_receive_flag_none);

                if (got == 0U)
                {
                    return qsc_tls_status_failure;
                }

                buflen += got;
            }
            else if (produced == 0U)
            {
                /* engine consumed nothing AND produced nothing while we have inbound bytes
                 * and the handshake is not done - partial record Receive more */
                size_t got;
                size_t space;

                space = sizeof(inbuf) - buflen;

                if (space == 0U)
                {
                    return qsc_tls_status_buffer_too_small;
                }

                got = qsc_socket_receive(io->socket, inbuf + buflen, space < QSC_TLS_IO_RECV_CHUNK ?
                    space : QSC_TLS_IO_RECV_CHUNK, qsc_socket_receive_flag_none);

                if (got == 0U)
                {
                    return qsc_tls_status_failure;
                }

                buflen += got;
            }
        }
    }
    else
    {
        return qsc_tls_status_invalid_input;
    }

    return qsc_tls_status_success;
}

qsc_tls_status qsc_tls_io_send(qsc_tls_io_connection* io, const uint8_t* input, size_t inlen, size_t* written)
{
    QSC_ASSERT(io != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(written != NULL);

    uint8_t outbuf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    size_t n;
    size_t produced;
    size_t sent;
    qsc_tls_status status;

    produced = 0U;
    status = qsc_tls_status_invalid_input;

    if (io != NULL && io->engine != NULL && io->socket != NULL && input != NULL && written != NULL)
    {
        *written = 0U;
        status = qsc_tls_engine_write_application_data(io->engine, input, inlen, outbuf, sizeof(outbuf), &produced);

        if (status == qsc_tls_status_success)
        {
            sent = 0U;

            while (sent < produced)
            {
                n = qsc_socket_send(io->socket, outbuf + sent, produced - sent, qsc_socket_send_flag_none);

                if (n == 0U)
                {
                    status = qsc_tls_status_failure;
                    break;
                }

                sent += n;
            }

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

    uint8_t inbuf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    size_t buflen;
    size_t consumed;
    size_t got;
    qsc_tls_status status;

    buflen = 0U;
    consumed = 0U;
    status = qsc_tls_status_invalid_input;

    if (io != NULL && io->engine != NULL && io->socket != NULL && output != NULL && read != NULL)
    {
        *read = 0U;

        /* pull one record's worth */
        while (buflen < sizeof(inbuf))
        {
            got = qsc_socket_receive(io->socket, inbuf + buflen, sizeof(inbuf) - buflen < QSC_TLS_IO_RECV_CHUNK ? sizeof(inbuf) - buflen : QSC_TLS_IO_RECV_CHUNK, qsc_socket_receive_flag_none);

            if (got != 0U)
            {
                buflen += got;

                status = qsc_tls_engine_read_application_data(io->engine, inbuf, buflen, &consumed, output, outlen, read);

                if (status == qsc_tls_status_success)
                {
                    if (consumed > 0U)
                    {
                        break;
                    }
                }
                else
                {
                    break;
                }
            }
            else
            {
                status = qsc_tls_status_failure;
                break;
            }
        }

        if (status == qsc_tls_status_success && consumed == 0U)
        {
            status = qsc_tls_status_buffer_too_small;
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
            size_t n;
            size_t sent;

            sent = 0U;

            while (sent < produced)
            {
                n = qsc_socket_send(io->socket, outbuf + sent, produced - sent, qsc_socket_send_flag_none);

                if (n == 0U)
                {
                    break;
                }

                sent += n;
            }
        }
    }

    return status;
}
