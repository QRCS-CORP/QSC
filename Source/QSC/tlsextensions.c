#include "tlsextensions.h"
#include "intutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "tlscodec.h"
#include "tlsdefs.h"

static qsc_tls_status ext_begin(uint8_t* out, size_t outlen, size_t* offset, uint16_t type, size_t* hdrpos)
{
    qsc_tls_status status;

    status = qsc_tls_codec_write_u16(out, outlen, offset, type);

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_codec_vector_begin_u16(out, outlen, offset, hdrpos);
    }

    return status;
}

static qsc_tls_status ext_end(uint8_t* out, size_t outlen, size_t* offset, size_t hdrpos)
{
    return qsc_tls_codec_vector_end_u16(out, outlen, offset, hdrpos);
}

void qsc_tls_extensions_bitmap_initialize(qsc_tls_extension_bitmap* bitmap)
{
    QSC_ASSERT(bitmap != NULL);

    if (bitmap != NULL)
    { 
        qsc_memutils_clear(bitmap, sizeof(*bitmap)); 
    }
}

bool qsc_tls_extensions_bitmap_set(qsc_tls_extension_bitmap* bitmap, uint16_t extensiontype)
{
    QSC_ASSERT(bitmap != NULL);

    uint64_t* cell;
    uint64_t mask;
    bool added;

    added = false;

    if (bitmap != NULL)
    {
        if (extensiontype < 64U)
        {
            cell = &bitmap->lowmask;
            mask = (uint64_t)1 << extensiontype;
        }
        else if (extensiontype < 128U)
        {
            cell = &bitmap->highmask;
            mask = (uint64_t)1 << (extensiontype - 64U);
        }
        else if (extensiontype < 192U)
        {
            cell = &bitmap->psk_ke_mask;
            mask = (uint64_t)1 << (extensiontype - 128U);
        }
        else
        {
            cell = &bitmap->tailmask;
            mask = (uint64_t)1 << ((extensiontype - 192U) & 63U);
        }

        if ((*cell & mask) == 0U)
        {
            *cell |= mask;
            added = true;
        }
    }

    return added;
}

bool qsc_tls_extensions_is_permitted(qsc_tls_handshake_type message, qsc_tls_extension_type extensiontype)
{
    /* per RFC 8446 4.2 "Table 4 - Extensions allowed in each message" */
    bool res;

    res = false;

    switch (extensiontype)
    {
        case qsc_tls_extension_server_name:
        {
            res = (message == qsc_tls_handshake_type_client_hello || message == qsc_tls_handshake_type_encrypted_extensions);
            break;
        }
        case qsc_tls_extension_supported_groups:
        {
            res = (message == qsc_tls_handshake_type_client_hello || message == qsc_tls_handshake_type_encrypted_extensions);
            break;
        }
        case qsc_tls_extension_signature_algorithms:
        case qsc_tls_extension_signature_algorithms_cert:
        {
            res = (message == qsc_tls_handshake_type_client_hello || message == qsc_tls_handshake_type_certificate_request);
            break;
        }
        case qsc_tls_extension_application_layer_protocol_negotiation:
        {
            res = (message == qsc_tls_handshake_type_client_hello || message == qsc_tls_handshake_type_encrypted_extensions);
            break;
        }
        case qsc_tls_extension_supported_versions:
        {
            /* in ClientHello + ServerHello (and HRR which is a pseudo-ServerHello) */
            res = (message == qsc_tls_handshake_type_client_hello || message == qsc_tls_handshake_type_server_hello);
            break;
        }
        case qsc_tls_extension_psk_key_exchange_modes:
        {
            res = (message == qsc_tls_handshake_type_client_hello);
            break;
        }
        case qsc_tls_extension_key_share:
        {
            res = (message == qsc_tls_handshake_type_client_hello || message == qsc_tls_handshake_type_server_hello);
            break;
        }
        case qsc_tls_extension_pre_shared_key:
        {
            res = (message == qsc_tls_handshake_type_client_hello || message == qsc_tls_handshake_type_server_hello);
            break;
        }
        case qsc_tls_extension_early_data:
        {
            res = (message == qsc_tls_handshake_type_client_hello || message == qsc_tls_handshake_type_encrypted_extensions || message == qsc_tls_handshake_type_new_session_ticket);
            break;
        }
        default:
        {
            break;
        }
    }

    return res;
}

qsc_tls_status qsc_tls_extensions_encode_supported_versions_client(uint8_t* output, size_t outlen, size_t* offset)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);

    size_t hdr;
    size_t inner;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_supported_versions, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_begin_u8(output, outlen, offset, &inner);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u16(output, outlen, offset, QSC_TLS_PROTOCOL_VERSION_13);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_end_u8(output, outlen, offset, inner);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_supported_versions_server(uint8_t* output, size_t outlen, size_t* offset)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);

    size_t hdr;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_supported_versions, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u16(output, outlen, offset, QSC_TLS_PROTOCOL_VERSION_13);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_supported_groups(uint8_t* output, size_t outlen, size_t* offset, const qsc_tls_named_group* groups, size_t groupcount)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);

    size_t hdr;
    size_t i;
    size_t inner;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (groups != NULL && groupcount != 0U)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_supported_groups, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_begin_u16(output, outlen, offset, &inner);
        }

        for (i = 0U; i < groupcount && status == qsc_tls_status_success; ++i)
        {
            status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)groups[i]);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_end_u16(output, outlen, offset, inner);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_signature_algorithms(uint8_t* output, size_t outlen, size_t* offset, const qsc_tls_signature_scheme* schemes, size_t schemecount)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(schemes != NULL);

    size_t hdr;
    size_t inner;
    size_t i;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL && schemes != NULL && schemecount != 0U)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_signature_algorithms, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_begin_u16(output, outlen, offset, &inner);
        }

        for (i = 0U; i < schemecount && status == qsc_tls_status_success; ++i)
        {
            status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)schemes[i]);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_end_u16(output, outlen, offset, inner);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_signature_algorithms_cert(uint8_t* output, size_t outlen, size_t* offset, const qsc_tls_signature_scheme* schemes, size_t schemecount)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(schemes != NULL);

    size_t hdr;
    size_t inner;
    size_t i;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL && schemes != NULL && schemecount != 0U)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_signature_algorithms_cert, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_begin_u16(output, outlen, offset, &inner);
        }

        for (i = 0U; i < schemecount && status == qsc_tls_status_success; ++i)
        {
            status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)schemes[i]);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_end_u16(output, outlen, offset, inner);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_key_share_client(uint8_t* output, size_t outlen, size_t* offset, qsc_tls_named_group group, const uint8_t* publicshare, size_t publicsharelen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(publicshare != NULL);

    size_t hdr;
    size_t listhdr;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL && publicshare != NULL && publicsharelen != 0U)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_key_share, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_begin_u16(output, outlen, offset, &listhdr);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)group);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_vector16(output, outlen, offset, publicshare, publicsharelen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_end_u16(output, outlen, offset, listhdr);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_key_share_server(uint8_t* output, size_t outlen, size_t* offset, qsc_tls_named_group group, const uint8_t* publicshare, size_t publicsharelen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(publicshare != NULL);

    size_t hdr;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL && publicshare != NULL && publicsharelen != 0U)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_key_share, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)group);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_vector16(output, outlen, offset, publicshare, publicsharelen);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_key_share_hello_retry(uint8_t* output, size_t outlen, size_t* offset, qsc_tls_named_group group)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);

    size_t hdr;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_key_share, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)group);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_server_name(uint8_t* output, size_t outlen, size_t* offset, const char* hostname)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(hostname != NULL);

    size_t hdr;
    size_t listhdr;
    size_t hostlen;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL && hostname != NULL)
    {
        hostlen = qsc_stringutils_string_size(hostname);

        if (hostlen != 0U && hostlen <= QSC_TLS_MAX_HOSTNAME_SIZE)
        {
            status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_server_name, &hdr);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_vector_begin_u16(output, outlen, offset, &listhdr);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_write_u8(output, outlen, offset, 0U);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_write_vector16(output, outlen, offset, (const uint8_t*)hostname, hostlen);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_vector_end_u16(output, outlen, offset, listhdr);
            }

            if (status == qsc_tls_status_success)
            {
                status = ext_end(output, outlen, offset, hdr);
            }
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_psk_key_exchange_modes(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* modes, size_t modecount)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(modes != NULL);

    size_t hdr;
    size_t inner;
    size_t i;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL && modes != NULL && modecount != 0U)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_psk_key_exchange_modes, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_begin_u8(output, outlen, offset, &inner);
        }

        for (i = 0U; i < modecount && status == qsc_tls_status_success; ++i)
        {
            status = qsc_tls_codec_write_u8(output, outlen, offset, modes[i]);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_end_u8(output, outlen, offset, inner);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_supported_versions_client(const uint8_t* input, size_t inplen, bool* acceptstls13)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(acceptstls13 != NULL);

    const uint8_t* list;
    size_t listlen;
    size_t i;
    size_t off;
    uint16_t v;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && acceptstls13 != NULL)
    {
        *acceptstls13 = false;

        off = 0U;
        status = qsc_tls_codec_read_vector8_span(input, inplen, &off, &list, &listlen);

        if (status == qsc_tls_status_success)
        {
            if ((listlen % 2U) == 0U)
            {
                for (i = 0U; i + 2U <= listlen; i += 2U)
                {
                    v = qsc_intutils_be8to16(list + i);

                    if (v == QSC_TLS_PROTOCOL_VERSION_13)
                    {
                        *acceptstls13 = true;
                        break;
                    }
                }
            }
            else
            {
                status = qsc_tls_status_invalid_length;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_supported_versions_server(const uint8_t* input, size_t inplen, uint16_t* selectedversion)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(selectedversion != NULL);

    size_t oft;
    qsc_tls_status status;

    oft = 0U;
    status = qsc_tls_status_invalid_input;

    if (input != NULL && selectedversion != NULL)
    {
        if (inplen == 2U)
        {
            status = qsc_tls_codec_read_u16(input, inplen, &oft, selectedversion);
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_supported_groups(const uint8_t* input, size_t inplen, qsc_tls_named_group* groups, size_t groupcapacity, size_t* groupcount)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(groups != NULL);
    QSC_ASSERT(groupcount != NULL);

    const uint8_t* list;
    size_t listlen;
    size_t i;
    size_t n;
    size_t off;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && groups != NULL && groupcount != NULL)
    {
        *groupcount = 0U;
        off = 0U;
        status = qsc_tls_codec_read_vector16_span(input, inplen, &off, &list, &listlen);

        if (status == qsc_tls_status_success)
        {
            if ((listlen % 2U) == 0U)
            {
                n = 0U;

                for (i = 0U; i + 2U <= listlen; i += 2U)
                {
                    if (n < groupcapacity)
                    {
                        groups[n] = (qsc_tls_named_group)qsc_intutils_be8to16(list + i);
                        n += 1U;
                    }
                    else
                    {
                        return qsc_tls_status_invalid_length;
                    }
                }

                *groupcount = n;
            }
            else
            {
                status = qsc_tls_status_invalid_length;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_signature_algorithms(const uint8_t* input, size_t inplen, qsc_tls_signature_scheme* schemes, size_t schemecapacity, size_t* schemecount)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(schemes != NULL);
    QSC_ASSERT(schemecount != NULL);

    const uint8_t* list;
    size_t listlen;
    size_t i;
    size_t n;
    size_t off;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && schemes != NULL && schemecount != NULL)
    {
        *schemecount = 0U;
        off = 0U;
        status = qsc_tls_codec_read_vector16_span(input, inplen, &off, &list, &listlen);

        if (status == qsc_tls_status_success)
        {
            if ((listlen % 2U) == 0U)
            {
                n = 0U;

                for (i = 0U; i + 2U <= listlen; i += 2U)
                {
                    if (n < schemecapacity)
                    {
                        schemes[n] = (qsc_tls_signature_scheme)qsc_intutils_be8to16(list + i);
                        n += 1U;
                    }
                    else
                    {
                        return qsc_tls_status_invalid_length;
                    }
                }

                *schemecount = n;
            }
            else
            {
                status = qsc_tls_status_invalid_length;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_key_share_client_hello(const uint8_t* input, size_t inplen, qsc_tls_named_group* groups, const uint8_t** shares, 
    size_t* sharelens, size_t capacity, size_t* count)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(groups != NULL);
    QSC_ASSERT(shares != NULL);
    QSC_ASSERT(sharelens != NULL);
    QSC_ASSERT(count != NULL);

    const uint8_t* list;
    size_t i;
    size_t listlen;
    size_t n;
    size_t off;
    uint16_t gid;
    uint16_t sharelen;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && groups != NULL && shares != NULL && sharelens != NULL && count != NULL)
    {
        *count = 0U;

        off = 0U;
        status = qsc_tls_codec_read_vector16_span(input, inplen, &off, &list, &listlen);

        if (status == qsc_tls_status_success)
        {
            n = 0U;
            i = 0U;

            while (i + 4U <= listlen)
            {
                gid = qsc_intutils_be8to16(list + i);
                i += 2U;

                sharelen = qsc_intutils_be8to16(list + i);
                i += 2U;

                if ((size_t)sharelen > listlen - i)
                {
                    return qsc_tls_status_invalid_length;
                }

                if (n >= capacity)
                {
                    return qsc_tls_status_invalid_length;
                }

                groups[n] = (qsc_tls_named_group)gid;
                shares[n] = list + i;
                sharelens[n] = (size_t)sharelen;
                i += sharelen;
                n += 1U;
            }

            if (i != listlen)
            {
                status = qsc_tls_status_invalid_length;
            }

            *count = n;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_key_share_server_hello(const uint8_t* input, size_t inplen, qsc_tls_named_group* selectedgroup, const uint8_t** share, size_t* sharelen)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(selectedgroup != NULL);
    QSC_ASSERT(share != NULL);
    QSC_ASSERT(sharelen != NULL);

    size_t off;
    uint16_t gid;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && selectedgroup != NULL && share != NULL && sharelen != NULL)
    {
        *share = NULL;
        *sharelen = 0U;
        off = 0U;
        status = qsc_tls_codec_read_u16(input, inplen, &off, &gid);

        if (status == qsc_tls_status_success)
        {
            *selectedgroup = (qsc_tls_named_group)gid;
            status = qsc_tls_codec_read_vector16_span(input, inplen, &off, share, sharelen);

            if (status == qsc_tls_status_success && off != inplen)
            {
                status = qsc_tls_status_invalid_length;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_key_share_hello_retry(const uint8_t* input, size_t inplen, qsc_tls_named_group* requestedgroup)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(requestedgroup != NULL);

    size_t off;
    uint16_t gid;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && requestedgroup != NULL)
    {
        if (inplen == 2U)
        {
            off = 0U;
            status = qsc_tls_codec_read_u16(input, inplen, &off, &gid);

            if (status == qsc_tls_status_success)
            {
                *requestedgroup = (qsc_tls_named_group)gid;
            }
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_server_name(const uint8_t* input, size_t inplen, const char** hostname, size_t* hostnamelen)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(hostname != NULL);
    QSC_ASSERT(hostnamelen != NULL);

    const uint8_t* hostspan;
    const uint8_t* list;
    size_t hostspanlen;
    size_t inneroft;
    size_t listlen;
    size_t oft;
    uint8_t nametype;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && hostname != NULL && hostnamelen != NULL)
    {
        *hostname = NULL;
        *hostnamelen = 0U;

        oft = 0U;
        status = qsc_tls_codec_read_vector16_span(input, inplen, &oft, &list, &listlen);

        if (status == qsc_tls_status_success)
        {
            inneroft = 0U;
            status = qsc_tls_codec_read_u8(list, listlen, &inneroft, &nametype);

            if (status == qsc_tls_status_success)
            {
                if (nametype == 0U)
                {
                    status = qsc_tls_codec_read_vector16_span(list, listlen, &inneroft, &hostspan, &hostspanlen);

                    if (status == qsc_tls_status_success)
                    {
                        if (hostspanlen != 0U && hostspanlen <= QSC_TLS_MAX_HOSTNAME_SIZE)
                        {
                            *hostname = (const char*)hostspan;
                            *hostnamelen = hostspanlen;
                        }
                        else
                        {
                            status = qsc_tls_status_invalid_length;
                        }
                    }
                }
                else
                {
                    status = qsc_tls_status_not_supported;
                }
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_select_cipher_suite(const uint8_t* clientsuites, size_t clientsuiteslen, const qsc_tls_cipher_suite* serverpreference, 
    size_t serverpreferencecount, qsc_tls_cipher_suite* selected)
{
    QSC_ASSERT(clientsuites != NULL);
    QSC_ASSERT(serverpreference != NULL);
    QSC_ASSERT(selected != NULL);

    size_t i;
    size_t j;
    uint16_t v;
    qsc_tls_status status;

    status = qsc_tls_status_not_supported;

    if (clientsuites != NULL && serverpreference != NULL && selected != NULL)
    {
        if ((clientsuiteslen % 2U) == 0U)
        {
            *selected = qsc_tls_cipher_suite_none;

            for (i = 0U; i < serverpreferencecount; ++i)
            {
                for (j = 0U; j + 2U <= clientsuiteslen; j += 2U)
                {
                    v = qsc_intutils_be8to16(clientsuites + j);

                    if ((uint16_t)serverpreference[i] == v)
                    {
                        *selected = serverpreference[i];

                        return qsc_tls_status_success;
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

qsc_tls_status qsc_tls_extensions_select_key_share(const qsc_tls_named_group* groups, size_t groupcount, const qsc_tls_named_group* serverpreference,
    size_t serverpreferencecount, qsc_tls_named_group* selected)
{
    size_t i;
    size_t j;

    if (groups == NULL || serverpreference == NULL || selected == NULL)
    {
        return qsc_tls_status_invalid_input;
    }

    *selected = qsc_tls_group_none;

    for (i = 0U; i < serverpreferencecount; ++i)
    {
        for (j = 0U; j < groupcount; ++j)
        {
            if (serverpreference[i] == groups[j])
            {
                *selected = serverpreference[i];
                return qsc_tls_status_success;
            }
        }
    }

    return qsc_tls_status_not_supported;
}

qsc_tls_status qsc_tls_extensions_encode_early_data_empty(uint8_t* output, size_t outlen, size_t* offset)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);

    size_t hdr;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_early_data, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_early_data_max(uint8_t* output, size_t outlen, size_t* offset, uint32_t maxearlydatasize)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);

    size_t hdr;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_early_data, &hdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u32(output, outlen, offset, maxearlydatasize);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, hdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_early_data_max(const uint8_t* input, size_t inplen, uint32_t* maxearlydatasize)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(maxearlydatasize != NULL);

    size_t oft;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && maxearlydatasize != NULL)
    {
        if (inplen == 4U)
        {
            oft = 0U;
            status = qsc_tls_codec_read_u32(input, inplen, &oft, maxearlydatasize);
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_encode_pre_shared_key_offer(uint8_t* output, size_t outlen, size_t* offset, 
    const qsc_tls_psk_identity_view* identities, size_t identitycount, size_t binderlen, size_t* binderoffset)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(identities != NULL);
    QSC_ASSERT(binderoffset != NULL);

    size_t exthdr;
    size_t idhdr;
    size_t binderhdr;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL && identities != NULL && identitycount != 0U && binderoffset != NULL)
    {
        if (binderlen != 0U && binderlen <= 255U)
        {
            status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_pre_shared_key, &exthdr);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_vector_begin_u16(output, outlen, offset, &idhdr);

                for (size_t i = 0; status == qsc_tls_status_success && i < identitycount; ++i)
                {
                    status = qsc_tls_codec_write_vector16(output, outlen, offset, identities[i].identity, identities[i].identitylen);

                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_codec_write_u32(output, outlen, offset, identities[i].obfuscatedticketage);
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_codec_vector_end_u16(output, outlen, offset, idhdr);
                }

                if (status == qsc_tls_status_success)
                {
                    /* binders<33..2^16-1> - vector of opaque<1..255> Emit zero placeholders */
                    status = qsc_tls_codec_vector_begin_u16(output, outlen, offset, &binderhdr);

                    if (status == qsc_tls_status_success)
                    {
                        /* record offset of first binder byte Layout: 1-byte length + binderlen bytes */
                        *binderoffset = *offset + 1U;

                        for (size_t i = 0; status == qsc_tls_status_success && i < identitycount; ++i)
                        {
                            if (*offset + 1U + binderlen > outlen)
                            {
                                status = qsc_tls_status_buffer_too_small; break;
                            }

                            output[*offset] = (uint8_t)binderlen;
                            *offset += 1U;
                            qsc_memutils_clear(output + *offset, binderlen);
                            *offset += binderlen;
                        }

                        if (status == qsc_tls_status_success)
                        {
                            status = qsc_tls_codec_vector_end_u16(output, outlen, offset, binderhdr);
                        }

                        if (status == qsc_tls_status_success)
                        {
                            status = ext_end(output, outlen, offset, exthdr);
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

qsc_tls_status qsc_tls_extensions_encode_pre_shared_key_server(uint8_t* output, size_t outlen, size_t* offset, uint16_t selidentity)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);

    size_t exthdr;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL)
    {
        status = ext_begin(output, outlen, offset, (uint16_t)qsc_tls_extension_pre_shared_key, &exthdr);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u16(output, outlen, offset, selidentity);
        }

        if (status == qsc_tls_status_success)
        {
            status = ext_end(output, outlen, offset, exthdr);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_pre_shared_key_offer(const uint8_t* input, size_t inplen, qsc_tls_psk_identity_view* identities, 
    const uint8_t** binders, size_t* binderlens, size_t capacity, size_t* count, size_t* binderblockoffset)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(identities != NULL);
    QSC_ASSERT(binders != NULL);
    QSC_ASSERT(binderlens != NULL);
    QSC_ASSERT(count != NULL);
    QSC_ASSERT(binderblockoffset != NULL);

    const uint8_t* binderblock;
    const uint8_t* idblock;
    size_t binderblocklen;
    size_t binderidx;
    size_t binderoft;
    size_t idblocklen;
    size_t ididx;
    size_t idoft;
    size_t oft;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && identities != NULL && binders != NULL && binderlens != NULL && count != NULL && binderblockoffset != NULL)
    {
        oft = 0U;
        status = qsc_tls_codec_read_vector16_span(input, inplen, &oft, &idblock, &idblocklen);

        if (status == qsc_tls_status_success)
        {
            /* record absolute offset of the binder-block length prefix (2 bytes before binders) */
            *binderblockoffset = oft;
            status = qsc_tls_codec_read_vector16_span(input, inplen, &oft, &binderblock, &binderblocklen);

            if (status == qsc_tls_status_success)
            {
                if (oft == inplen)
                {
                    /* walk identities */
                    ididx = 0U;
                    idoft = 0U;

                    while (idoft < idblocklen)
                    {
                        const uint8_t* id;
                        size_t idlen;
                        uint32_t age;

                        status = qsc_tls_codec_read_vector16_span(idblock, idblocklen, &idoft, &id, &idlen);

                        if (status != qsc_tls_status_success)
                        {
                            return status;
                        }

                        status = qsc_tls_codec_read_u32(idblock, idblocklen, &idoft, &age);

                        if (status != qsc_tls_status_success)
                        {
                            return status;
                        }

                        if (ididx < capacity)
                        {
                            identities[ididx].identity = id;
                            identities[ididx].identitylen = idlen;
                            identities[ididx].obfuscatedticketage = age;
                        }

                        ++ididx;
                    }

                    /* walk binders */
                    binderidx = 0U;
                    binderoft = 0U;

                    while (binderoft < binderblocklen)
                    {
                        const uint8_t* b;
                        size_t blen;

                        status = qsc_tls_codec_read_vector8_span(binderblock, binderblocklen, &binderoft, &b, &blen);

                        if (status != qsc_tls_status_success)
                        {
                            return status;
                        }
                        if (binderidx < capacity)
                        {
                            binders[binderidx] = b;
                            binderlens[binderidx] = blen;
                        }

                        ++binderidx;
                    }

                    if (ididx != binderidx)
                    {
                        return qsc_tls_status_invalid_message;
                    }

                    *count = ididx;
                }
                else
                {
                    status = qsc_tls_status_invalid_length;
                }
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_extensions_decode_pre_shared_key_server(const uint8_t* input, size_t inplen, uint16_t* selidentity)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(selidentity != NULL);

    qsc_tls_status status;
    size_t oft;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && selidentity != NULL)
    {
        if (inplen == 2U)
        {
            oft = 0U;
            status = qsc_tls_codec_read_u16(input, inplen, &oft, selidentity);
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}
