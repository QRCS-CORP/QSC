#include "tlshandshake.h"
#include "tlsrecord.h"
#include "tlscodec.h"
#include "memutils.h"

qsc_tls_status qsc_tls_handshake_write_header(uint8_t* output, size_t outlen, size_t* offset, qsc_tls_handshake_type type, size_t bodylen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL)
    {
        if (bodylen <= 0xFFFFFFU)
        {
            status = qsc_tls_codec_write_u8(output, outlen, offset, (uint8_t)type);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_write_u24(output, outlen, offset, (uint32_t)bodylen);
            }
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_handshake_read_header(const uint8_t* input, size_t inlen, size_t* offset, qsc_tls_handshake_type* type, size_t* bodylen)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(type != NULL);
    QSC_ASSERT(bodylen != NULL);

    uint32_t bl;
    uint8_t t;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && offset != NULL && type != NULL && bodylen != NULL)
    {
        status = qsc_tls_codec_read_u8(input, inlen, offset, &t);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_u24(input, inlen, offset, &bl);

            if (status == qsc_tls_status_success)
            {
                *type = (qsc_tls_handshake_type)t;
                *bodylen = (size_t)bl;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_handshake_send_change_cipher_spec_compat(uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);

    const uint8_t payload = 0x01U;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && written != NULL)
    {
        *written = 0U;
        status = qsc_tls_record_encode_plaintext(output, outlen, written, qsc_tls_record_content_change_cipher_spec, &payload, 1U);
    }

    return status;
}

qsc_tls_status qsc_tls_handshake_encode_finished(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* verifydata, size_t verifydatalen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(verifydata != NULL);
    QSC_ASSERT(verifydatalen != 0U);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL && verifydata != NULL && verifydatalen != 0U)
    {
        status = qsc_tls_codec_write_bytes(output, outlen, offset, verifydata, verifydatalen);
    }

    return status;
}

qsc_tls_status qsc_tls_handshake_decode_finished(const uint8_t* input, size_t inlen, const uint8_t** verifydata, size_t* verifydatalen)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(verifydata != NULL);
    QSC_ASSERT(verifydatalen != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (input != NULL && verifydata != NULL && verifydatalen != NULL)
    {
        if (inlen != 0U)
        {
            *verifydata = input;
            *verifydatalen = inlen;
            status = qsc_tls_status_success;
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_handshake_encode_certificate_verify(uint8_t* output, size_t outlen, size_t* offset, qsc_tls_signature_scheme scheme, const uint8_t* signature, size_t signaturelen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(offset != NULL);
    QSC_ASSERT(signature != NULL);
    QSC_ASSERT(signaturelen != 0U);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (output != NULL && offset != NULL && signature != NULL && signaturelen != 0U)
    {
        status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)scheme);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_vector16(output, outlen, offset, signature, signaturelen);
        }
    }

    return status;
}

qsc_tls_status qsc_tls_handshake_decode_certificate_verify(const uint8_t* input, size_t inlen, qsc_tls_signature_scheme* scheme, const uint8_t** signature, size_t* signaturelen)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(scheme != NULL);
    QSC_ASSERT(signature != NULL);
    QSC_ASSERT(signaturelen != NULL);

    size_t oft;
    uint16_t s;
    qsc_tls_status status;

    oft = 0U;
    status = qsc_tls_status_invalid_input;

    if (input != NULL && scheme != NULL && signature != NULL && signaturelen != NULL)
    {
        status = qsc_tls_codec_read_u16(input, inlen, &oft, &s);

        if (status == qsc_tls_status_success)
        {
            *scheme = (qsc_tls_signature_scheme)s;
            status = qsc_tls_codec_read_vector16_span(input, inlen, &oft, signature, signaturelen);

            if (status == qsc_tls_status_success && oft != inlen)
            {
                status = qsc_tls_status_invalid_length;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_handshake_encode_encrypted_extensions(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* extensions, size_t extensionslen)
{
    return qsc_tls_codec_write_vector16(output, outlen, offset, extensions, extensionslen);
}

qsc_tls_status qsc_tls_handshake_encode_key_update(uint8_t* output, size_t outlen, size_t* offset, bool requestupdate)
{
    return qsc_tls_codec_write_u8(output, outlen, offset, requestupdate ? 1U : 0U);
}

qsc_tls_status qsc_tls_handshake_decode_key_update(const uint8_t* input, size_t inlen, bool* requestupdate)
{
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(requestupdate != NULL);

    size_t oft;
    uint8_t v;
    qsc_tls_status status;

    oft = 0U;
    status = qsc_tls_status_invalid_input;

    if (input != NULL && requestupdate != NULL)
    {
        status = qsc_tls_codec_read_u8(input, inlen, &oft, &v);

        if (status == qsc_tls_status_success)
        {
            if (v > 1U)
            {
                status = qsc_tls_status_invalid_message;
            }
            else
            {
                *requestupdate = (v == 1U);
            }
        }
    }

    return status;
}
