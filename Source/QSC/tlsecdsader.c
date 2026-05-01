#include "tlsecdsader.h"
#include "memutils.h"

static size_t ecdsa_der_leading_zero_skip(const uint8_t* comp, size_t complen)
{
    size_t skip;

    skip = 0U;

    while (skip < complen - 1U && comp[skip] == 0x00U)
    {
        skip += 1U;
    }

    return skip;
}

static size_t ecdsa_der_integer_content_length(const uint8_t* comp, size_t complen)
{
    size_t skip;
    size_t stripped;
    size_t res;

    skip = ecdsa_der_leading_zero_skip(comp, complen);
    stripped = complen - skip;
    res = stripped;

    if ((comp[skip] & 0x80U) != 0U)
    {
        res += 1U;
    }

    return res;
}

static size_t ecdsa_der_length_field_size(size_t content_length)
{
    size_t n;

    if (content_length < 0x80U)
    {
        n = 1U;
    }
    else if (content_length < 0x100U)
    {
        n = 2U;
    }
    else
    {
        n = 3U;
    }
    return n;
}

static size_t ecdsa_der_write_length(uint8_t* out, size_t value)
{
    size_t written;

    if (value < 0x80U)
    {
        out[0U] = (uint8_t)value;
        written = 1U;
    }
    else if (value < 0x100U)
    {
        out[0U] = 0x81U;
        out[1U] = (uint8_t)value;
        written = 2U;
    }
    else
    {
        out[0U] = 0x82U;
        out[1U] = (uint8_t)((value >> 8) & 0xFFU);
        out[2U] = (uint8_t)(value & 0xFFU);
        written = 3U;
    }
    return written;
}

static size_t ecdsa_der_write_integer(uint8_t* out, const uint8_t* comp, size_t complen)
{
    size_t skip;
    size_t stripped;
    size_t contentlen;
    size_t offset;

    skip = ecdsa_der_leading_zero_skip(comp, complen);
    stripped = complen - skip;
    contentlen = stripped + (((comp[skip] & 0x80U) != 0U) ? 1U : 0U);

    out[0U] = 0x02U;
    offset = 1U;
    offset += ecdsa_der_write_length(out + offset, contentlen);

    if ((comp[skip] & 0x80U) != 0U)
    {
        out[offset] = 0x00U;
        offset += 1U;
    }

    qsc_memutils_copy(out + offset, comp + skip, stripped);
    offset += stripped;

    return offset;
}

qsc_tls_status qsc_tls_ecdsa_der_encode(const uint8_t* rs, size_t componentsize, uint8_t* output, size_t outlen, size_t* written)
{
    qsc_tls_status status;

    if (written != NULL) 
    { 
        *written = 0U; 
    }

    if (rs == NULL || output == NULL || written == NULL || componentsize == 0U || componentsize > 133U)
    {
        status = qsc_tls_status_invalid_input;
    }
    else
    {
        size_t offset;
        size_t rcontentlen;
        size_t rtotal;
        size_t scontentlen;
        size_t seqcontentlen;
        size_t seqheaderlen;
        size_t stotal;
        size_t total;

        rcontentlen = ecdsa_der_integer_content_length(rs, componentsize);
        scontentlen = ecdsa_der_integer_content_length(rs + componentsize, componentsize);
        rtotal = 1U + ecdsa_der_length_field_size(rcontentlen) + rcontentlen;
        stotal = 1U + ecdsa_der_length_field_size(scontentlen) + scontentlen;
        seqcontentlen = rtotal + stotal;
        seqheaderlen = 1U + ecdsa_der_length_field_size(seqcontentlen);
        total = seqheaderlen + seqcontentlen;

        if (total > outlen)
        {
            status = qsc_tls_status_buffer_too_small;
        }
        else
        {
            offset = 0U;
            output[offset] = 0x30U;
            offset += 1U;
            offset += ecdsa_der_write_length(output + offset, seqcontentlen);
            offset += ecdsa_der_write_integer(output + offset, rs, componentsize);
            offset += ecdsa_der_write_integer(output + offset, rs + componentsize, componentsize);
            *written = offset;
            status = qsc_tls_status_success;
        }
    }

    return status;
}

static qsc_tls_status ecdsa_der_read_length(const uint8_t* buf, size_t buflen, size_t* offset, size_t* length_out)
{
    qsc_tls_status status;

    status = qsc_tls_status_success;
    *length_out = 0U;

    if (*offset >= buflen)
    {
        status = qsc_tls_status_invalid_length;
    }
    else
    {
        uint8_t first = buf[*offset];

        if ((first & 0x80U) == 0U)
        {
            *length_out = (size_t)first;
            *offset += 1U;
        }
        else if (first == 0x81U)
        {
            if (*offset + 1U >= buflen)
            {
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                *length_out = (size_t)buf[*offset + 1U];
                *offset += 2U;

                if (*length_out < 0x80U)
                { 
                    status = qsc_tls_status_invalid_length; 
                }
            }
        }
        else if (first == 0x82U)
        {
            if (*offset + 2U >= buflen)
            {
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                *length_out = ((size_t)buf[*offset + 1U] << 8) | (size_t)buf[*offset + 2U];
                *offset += 3U;

                if (*length_out < 0x100U) 
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

    return status;
}

static qsc_tls_status ecdsa_der_read_integer(const uint8_t* buf, size_t buflen, size_t* offset, uint8_t* out, size_t componentsize)
{
    const uint8_t* content;
    size_t contentlen;
    qsc_tls_status status;

    status = qsc_tls_status_success;

    if (*offset >= buflen || buf[*offset] != 0x02U)
    {
        status = qsc_tls_status_invalid_message;
    }
    else
    {
        *offset += 1U;
        status = ecdsa_der_read_length(buf, buflen, offset, &contentlen);

        if (status == qsc_tls_status_success)
        {
            if (contentlen == 0U || *offset + contentlen > buflen)
            {
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                content = buf + *offset;
                *offset += contentlen;

                if (contentlen > 1U && content[0U] == 0x00U && (content[1] & 0x80U) != 0U)
                {
                    content += 1U;
                    contentlen -= 1U;
                }

                while (contentlen > 1U && content[0U] == 0x00U)
                {
                    content += 1U;
                    contentlen -= 1U;
                }

                if (contentlen > componentsize)
                {
                    status = qsc_tls_status_invalid_length;
                }
                else
                {
                    qsc_memutils_clear(out, componentsize);
                    qsc_memutils_copy(out + (componentsize - contentlen), content, contentlen);
                }
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_ecdsa_der_decode(const uint8_t* der, size_t derlen, size_t componentsize, uint8_t* output, size_t outlen)
{
    qsc_tls_status status;

    if (der == NULL || output == NULL || componentsize == 0U || componentsize > 133U)
    {
        status = qsc_tls_status_invalid_input;
    }
    else if (outlen < 2U * componentsize)
    {
        status = qsc_tls_status_buffer_too_small;
    }
    else if (derlen < 8U || der[0U] != 0x30U)
    {
        status = qsc_tls_status_invalid_message;
    }
    else
    {
        size_t offset;
        size_t seqcontentlen;

        offset = 1U;
        status = ecdsa_der_read_length(der, derlen, &offset, &seqcontentlen);

        if (status == qsc_tls_status_success)
        {
            if (offset + seqcontentlen != derlen)
            {
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                status = ecdsa_der_read_integer(der, derlen, &offset, output, componentsize);

                if (status == qsc_tls_status_success)
                {
                    status = ecdsa_der_read_integer(der, derlen, &offset, output + componentsize, componentsize);
                }
                if (status == qsc_tls_status_success && offset != derlen)
                {
                    status = qsc_tls_status_invalid_length;
                }
            }
        }
    }

    return status;
}
