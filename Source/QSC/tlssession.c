#include "tlssession.h"
#include "memutils.h"
#include "tlscodec.h"
#include "tlsextensions.h"

qsc_tls_status qsc_tls_session_ticket_encode(const qsc_tls_session_ticket* ticket, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(ticket != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);

    size_t exthdr;
    size_t oft;
    qsc_tls_status status;

    exthdr = 0U;
    oft = 0U;
    status = qsc_tls_status_invalid_input;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (ticket != NULL && output != NULL && written != NULL)
    {
        if (ticket->lifetime <= QSC_TLS_SESSION_TICKET_LIFETIME_MAX && ticket->noncelen <= 255U &&
            ticket->ticketlen != 0U && ticket->ticketlen <= QSC_TLS_TICKET_MAX_SIZE)
        {
            status = qsc_tls_codec_write_u32(output, outlen, &oft, ticket->lifetime);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_write_u32(output, outlen, &oft, ticket->ageadd);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_write_vector8(output, outlen, &oft, ticket->nonce, ticket->noncelen);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_write_vector16(output, outlen, &oft, ticket->ticket, ticket->ticketlen);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_vector_begin_u16(output, outlen, &oft, &exthdr);
            }

            if (status == qsc_tls_status_success && ticket->maxearlydatasize != 0U)
            {
                status = qsc_tls_extensions_encode_early_data_max(output, outlen, &oft, ticket->maxearlydatasize);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_vector_end_u16(output, outlen, &oft, exthdr);
            }

            if (status == qsc_tls_status_success)
            {
                *written = oft;
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

    uint8_t seen[8192U] = { 0U };
    const uint8_t* extspan;
    const uint8_t* extbody;
    const uint8_t* noncespan;
    const uint8_t* ticketspan;
    size_t extbodylen;
    size_t extlen;
    size_t extoff;
    size_t index;
    size_t noncelen;
    size_t oft;
    size_t ticketlen;
    uint16_t exttype;
    uint8_t mask;
    qsc_tls_status status;
    bool retainable;

    extbody = NULL;
    extbodylen = 0U;
    extlen = 0U;
    extoff = 0U;
    extspan = NULL;
    index = 0U;
    noncelen = 0U;
    noncespan = NULL;
    oft = 0U;
    ticketlen = 0U;
    ticketspan = NULL;
    exttype = 0U;
    mask = 0U;
    status = qsc_tls_status_invalid_input;
    retainable = true;

    if (input != NULL && ticket != NULL)
    {
        qsc_memutils_clear(ticket, sizeof(*ticket));
        status = qsc_tls_codec_read_u32(input, inplen, &oft, &ticket->lifetime);

        if (status == qsc_tls_status_success)
        {
            if (ticket->lifetime > QSC_TLS_SESSION_TICKET_LIFETIME_MAX)
            {
                status = qsc_tls_status_invalid_length;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_u32(input, inplen, &oft, &ticket->ageadd);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector8_span(input, inplen, &oft, &noncespan, &noncelen);
        }

        if (status == qsc_tls_status_success)
        {
            if (noncelen <= sizeof(ticket->nonce))
            {
                qsc_memutils_copy(ticket->nonce, noncespan, noncelen);
                ticket->noncelen = noncelen;
            }
            else
            {
                status = qsc_tls_status_invalid_length;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector16_span(input, inplen, &oft, &ticketspan, &ticketlen);
        }

        if (status == qsc_tls_status_success)
        {
            if (ticketlen == 0U)
            {
                status = qsc_tls_status_invalid_length;
            }
            else if (ticketlen <= sizeof(ticket->ticket))
            {
                qsc_memutils_copy(ticket->ticket, ticketspan, ticketlen);
                ticket->ticketlen = ticketlen;
            }
            else
            {
                retainable = false;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector16_span(input, inplen, &oft, &extspan, &extlen);
        }

        if (status == qsc_tls_status_success && oft != inplen)
        {
            status = qsc_tls_status_invalid_length;
        }

        while (status == qsc_tls_status_success && extoff < extlen)
        {
            extbody = NULL;
            extbodylen = 0U;
            status = qsc_tls_codec_read_u16(extspan, extlen, &extoff, &exttype);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_read_vector16_span(extspan, extlen, &extoff, &extbody, &extbodylen);
            }

            if (status == qsc_tls_status_success)
            {
                index = ((size_t)exttype >> 3U);
                mask = (uint8_t)(1U << (exttype & 7U));

                if ((seen[index] & mask) != 0U)
                {
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    seen[index] |= mask;
                }
            }

            if (status == qsc_tls_status_success && exttype == (uint16_t)qsc_tls_extension_early_data)
            {
                status = qsc_tls_extensions_decode_early_data_max(extbody, extbodylen, &ticket->maxearlydatasize);
            }
        }

        if (status == qsc_tls_status_success && retainable == false)
        {
            status = qsc_tls_status_not_supported;
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
