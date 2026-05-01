#include "tlssession.h"
#include "memutils.h"
#include "tlscodec.h"

qsc_tls_status qsc_tls_session_ticket_encode(const qsc_tls_session_ticket* ticket, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(ticket != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);

    size_t exthdr;
    size_t oft;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (ticket != NULL && output != NULL && written != NULL)
    {
        if (ticket->noncelen <= 255U && ticket->ticketlen != 0U && ticket->ticketlen <= QSC_TLS_TICKET_MAX_SIZE)
        {
            oft = 0U;
            status = qsc_tls_codec_write_u32(output, outlen, &oft, ticket->lifetime);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_write_u32(output, outlen, &oft, ticket->ageadd);

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_codec_write_vector8(output, outlen, &oft, ticket->nonce, ticket->noncelen);

                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_codec_write_vector16(output, outlen, &oft, ticket->ticket, ticket->ticketlen);

                        if (status == qsc_tls_status_success)
                        {
                            status = qsc_tls_codec_vector_begin_u16(output, outlen, &oft, &exthdr);

                            if (status == qsc_tls_status_success)
                            {
                                status = qsc_tls_codec_vector_end_u16(output, outlen, &oft, exthdr);
                            }

                            if (status == qsc_tls_status_success)
                            {
                                *written = oft;
                            }
                        }
                    }
                }
            }
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_session_ticket_decode(const uint8_t* input, size_t inplen, qsc_tls_session_ticket* ticket)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(ticket != NULL);

    const uint8_t* extspan;
    const uint8_t* noncespan;
    const uint8_t* ticketspan;
    size_t extlen;
    size_t noncelen;
    size_t oft;
    size_t ticketlen;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && ticket != NULL)
    {
        qsc_memutils_clear(ticket, sizeof(*ticket));
        oft = 0U;

        status = qsc_tls_codec_read_u32(input, inplen, &oft, &ticket->lifetime);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_u32(input, inplen, &oft, &ticket->ageadd);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_read_vector8_span(input, inplen, &oft, &noncespan, &noncelen);

                if (status == qsc_tls_status_success)
                {
                    if (noncelen <= sizeof(ticket->nonce))
                    {
                        qsc_memutils_copy(ticket->nonce, noncespan, noncelen);
                        ticket->noncelen = noncelen;

                        status = qsc_tls_codec_read_vector16_span(input, inplen, &oft, &ticketspan, &ticketlen);

                        if (status == qsc_tls_status_success)
                        {
                            if (ticketlen != 0U && ticketlen <= sizeof(ticket->ticket))
                            {
                                qsc_memutils_copy(ticket->ticket, ticketspan, ticketlen);
                                ticket->ticketlen = ticketlen;

                                /* extensions span is read past and ignored in this MVP decoder. */
                                status = qsc_tls_codec_read_vector16_span(input, inplen, &oft, &extspan, &extlen);

                                if (status == qsc_tls_status_success)
                                {
                                    (void)extspan; 
                                    (void)extlen;

                                    if (oft != inplen)
                                    {
                                        status = qsc_tls_status_invalid_length;
                                    }
                                }
                            }
                            else
                            {
                                status = qsc_tls_status_invalid_length;
                            }
                        }
                    }
                    else
                    {
                        status = qsc_tls_status_invalid_length;
                    }
                }
            }
        }
    }

    return status;
}

void qsc_tls_session_ticket_dispose(qsc_tls_session_ticket* ticket)
{
    QSC_ASSERT(ticket != NULL);

    if (ticket != NULL)
    {
        qsc_memutils_secure_erase(ticket, sizeof(*ticket));
    }
}
