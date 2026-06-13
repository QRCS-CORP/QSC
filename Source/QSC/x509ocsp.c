#include "x509ocsp.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "oid.h"
#include "sha2.h"
#include "time.h"
#include "x509name.h"
#include "x509sig.h"
#include "x509spki.h"
#include "x509sigver.h"
#include "x509store.h"
#include "x509verify.h"
#include "x509write.h"

#define X509_OCSP_MAX_RESPONSE_CERT_DER 8192U
#define X509_OCSP_REQUEST_MAX 512U
#define X509_OCSP_SHA1_HASH_SIZE 20U
#define X509_OCSP_HASH_BUFFER_MAX 64U
#define X509_OCSP_NAME_DER_MAX 1024U
#define X509_OCSP_TAG_ENUMERATED 10U

static bool x509_asn1_is_octet_string(const qsc_encoding_ber_element* element)
{
    return (qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OCTET_STRING) == QSC_ASN1_STATUS_SUCCESS);
}

static bool x509_ocsp_oid_equals(const qsc_asn1_oid* oid, const uint8_t* data, size_t datalen)
{
    return (oid != (const qsc_asn1_oid*)NULL && data != (const uint8_t*)NULL && oid->length == datalen && qsc_memutils_are_equal(oid->data, data, datalen));
}

static void x509_ocsp_response_initialize(qsc_x509_ocsp_response* response)
{
    if (response != (qsc_x509_ocsp_response*)NULL)
    {
        qsc_memutils_clear((uint8_t*)response, sizeof(qsc_x509_ocsp_response));
        response->status = QSC_X509_OCSP_STATUS_UNKNOWN;
    }
}

static qsc_asn1_status x509_ocsp_decode_enumerated_u64(const qsc_encoding_ber_element* element, uint64_t* value)
{
    qsc_asn1_status status;
    uint64_t val;
    size_t i;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != (const qsc_encoding_ber_element*)NULL && value != (uint64_t*)NULL)
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, X509_OCSP_TAG_ENUMERATED);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (element->length == 0U || element->length > sizeof(uint64_t) || element->value == (const uint8_t*)NULL)
            {
                status = QSC_ASN1_STATUS_OUT_OF_RANGE;
            }
            else if ((element->value[0U] & 0x80U) != 0U)
            {
                status = QSC_ASN1_STATUS_UNSUPPORTED;
            }
            else if (element->length > 1U && element->value[0U] == 0U && (element->value[1U] & 0x80U) == 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                val = 0U;

                for (i = 0U; i < element->length; ++i)
                {
                    val = (val << 8) | element->value[i];
                }

                *value = val;
            }
        }
    }

    return status;
}

static qsc_asn1_status x509_ocsp_copy_unsigned_integer(const qsc_encoding_ber_element* element, uint8_t* output, size_t otplen, size_t* outlen)
{
    qsc_asn1_status status;
    size_t ofs;
    size_t ilen;

    status = QSC_ASN1_STATUS_FAILURE;
    ofs = 0U;
    ilen = 0U;

    if (element == (const qsc_encoding_ber_element*)NULL || output == (uint8_t*)NULL || outlen == (size_t*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_INTEGER);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (element->length == 0U || element->value == (const uint8_t*)NULL)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else if ((element->value[0U] & 0x80U) != 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                if (element->length > 1U && element->value[0U] == 0x00U)
                {
                    if ((element->value[1U] & 0x80U) == 0U)
                    {
                        status = QSC_ASN1_STATUS_INVALID_ENCODING;
                    }
                    else
                    {
                        ofs = 1U;
                    }
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    ilen = element->length - ofs;

                    if (otplen < ilen)
                    {
                        *outlen = ilen;
                        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                    }
                    else
                    {
                        qsc_memutils_copy(output, element->value + ofs, ilen);
                        *outlen = ilen;
                    }
                }
            }
        }
    }

    return status;
}

static bool x509_ocsp_serial_bytes_equal(const uint8_t* left, size_t leftlen, const uint8_t* right, size_t rightlen)
{
    size_t lofs;
    size_t rofs;

    lofs = 0U;
    rofs = 0U;

    while (lofs + 1U < leftlen && left[lofs] == 0x00U)
    {
        lofs += 1U;
    }

    while (rofs + 1U < rightlen && right[rofs] == 0x00U)
    {
        rofs += 1U;
    }

    return ((leftlen - lofs) == (rightlen - rofs)) && qsc_memutils_are_equal(left + lofs, right + rofs, leftlen - lofs);
}

static void x509_ocsp_sha1_compute(uint8_t* output, const uint8_t* message, size_t msglen)
{
    static const uint32_t iv[5U] =
    {
        0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL
    };
    uint32_t h[5U] = { 0U };
    uint32_t w[80U] = { 0U };
    uint8_t block[64U] = { 0U };
    uint64_t bitlen;
    size_t i;
    size_t j;
    size_t pos;

    if (output == (uint8_t*)NULL)
    {
        return;
    }

    h[0U] = iv[0U];
    h[1U] = iv[1U];
    h[2U] = iv[2U];
    h[3U] = iv[3U];
    h[4U] = iv[4U];
    pos = 0U;
    bitlen = (uint64_t)msglen * 8ULL;

    while (msglen - pos >= 64U)
    {
        for (i = 0U; i < 16U; ++i)
        {
            j = i * 4U;
            w[i] = ((uint32_t)message[pos + j] << 24) |
                   ((uint32_t)message[pos + j + 1U] << 16) |
                   ((uint32_t)message[pos + j + 2U] << 8) |
                   (uint32_t)message[pos + j + 3U];
        }

        for (i = 16U; i < 80U; ++i)
        {
            uint32_t t = w[i - 3U] ^ w[i - 8U] ^ w[i - 14U] ^ w[i - 16U];
            w[i] = (t << 1) | (t >> 31);
        }

        {
            uint32_t a = h[0U];
            uint32_t b = h[1U];
            uint32_t c = h[2U];
            uint32_t d = h[3U];
            uint32_t e = h[4U];
            uint32_t f;
            uint32_t k;
            uint32_t temp;

            for (i = 0U; i < 80U; ++i)
            {
                if (i < 20U)
                {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999UL;
                }
                else if (i < 40U)
                {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1UL;
                }
                else if (i < 60U)
                {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDCUL;
                }
                else
                {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6UL;
                }

                temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;
            }

            h[0U] += a;
            h[1U] += b;
            h[2U] += c;
            h[3U] += d;
            h[4U] += e;
        }

        pos += 64U;
    }

    qsc_memutils_clear(block, sizeof(block));

    if (msglen > pos)
    {
        qsc_memutils_copy(block, message + pos, msglen - pos);
    }

    block[msglen - pos] = 0x80U;

    if ((msglen - pos) >= 56U)
    {
        for (i = 0U; i < 16U; ++i)
        {
            j = i * 4U;
            w[i] = ((uint32_t)block[j] << 24) |
                   ((uint32_t)block[j + 1U] << 16) |
                   ((uint32_t)block[j + 2U] << 8) |
                   (uint32_t)block[j + 3U];
        }

        for (i = 16U; i < 80U; ++i)
        {
            uint32_t t = w[i - 3U] ^ w[i - 8U] ^ w[i - 14U] ^ w[i - 16U];
            w[i] = (t << 1) | (t >> 31);
        }

        {
            uint32_t a = h[0U];
            uint32_t b = h[1U];
            uint32_t c = h[2U];
            uint32_t d = h[3U];
            uint32_t e = h[4U];
            uint32_t f;
            uint32_t k;
            uint32_t temp;

            for (i = 0U; i < 80U; ++i)
            {
                if (i < 20U)
                {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999UL;
                }
                else if (i < 40U)
                {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1UL;
                }
                else if (i < 60U)
                {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDCUL;
                }
                else
                {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6UL;
                }

                temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;
            }

            h[0U] += a;
            h[1U] += b;
            h[2U] += c;
            h[3U] += d;
            h[4U] += e;
        }

        qsc_memutils_clear(block, sizeof(block));
    }

    block[56U] = (uint8_t)(bitlen >> 56);
    block[57U] = (uint8_t)(bitlen >> 48);
    block[58U] = (uint8_t)(bitlen >> 40);
    block[59U] = (uint8_t)(bitlen >> 32);
    block[60U] = (uint8_t)(bitlen >> 24);
    block[61U] = (uint8_t)(bitlen >> 16);
    block[62U] = (uint8_t)(bitlen >> 8);
    block[63U] = (uint8_t)bitlen;

    for (i = 0U; i < 16U; ++i)
    {
        j = i * 4U;
        w[i] = ((uint32_t)block[j] << 24) |
               ((uint32_t)block[j + 1U] << 16) |
               ((uint32_t)block[j + 2U] << 8) |
               (uint32_t)block[j + 3U];
    }

    for (i = 16U; i < 80U; ++i)
    {
        uint32_t t = w[i - 3U] ^ w[i - 8U] ^ w[i - 14U] ^ w[i - 16U];
        w[i] = (t << 1) | (t >> 31);
    }

    {
        uint32_t a = h[0U];
        uint32_t b = h[1U];
        uint32_t c = h[2U];
        uint32_t d = h[3U];
        uint32_t e = h[4U];
        uint32_t f;
        uint32_t k;
        uint32_t temp;

        for (i = 0U; i < 80U; ++i)
        {
            if (i < 20U)
            {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999UL;
            }
            else if (i < 40U)
            {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1UL;
            }
            else if (i < 60U)
            {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCUL;
            }
            else
            {
                f = b ^ c ^ d;
                k = 0xCA62C1D6UL;
            }

            temp = ((a << 5) | (a >> 27)) + f + e + k + w[i];
            e = d;
            d = c;
            c = (b << 30) | (b >> 2);
            b = a;
            a = temp;
        }

        h[0U] += a;
        h[1U] += b;
        h[2U] += c;
        h[3U] += d;
        h[4U] += e;
    }

    for (i = 0U; i < 5U; ++i)
    {
        output[(i * 4U)] = (uint8_t)(h[i] >> 24);
        output[(i * 4U) + 1U] = (uint8_t)(h[i] >> 16);
        output[(i * 4U) + 2U] = (uint8_t)(h[i] >> 8);
        output[(i * 4U) + 3U] = (uint8_t)h[i];
    }

    qsc_memutils_secure_erase((uint8_t*)h, sizeof(h));
    qsc_memutils_secure_erase((uint8_t*)w, sizeof(w));
    qsc_memutils_secure_erase((uint8_t*)block, sizeof(block));
}

static bool x509_ocsp_hash_octets(const qsc_asn1_oid* hashoid, const uint8_t* data, size_t datalen, uint8_t* output, size_t* outputlen)
{
    qsc_oid_id oidid;
    bool res;

    res = false;

    if (hashoid != (const qsc_asn1_oid*)NULL && data != (const uint8_t*)NULL && output != (uint8_t*)NULL && outputlen != (size_t*)NULL)
    {
        oidid = qsc_oid_identify(hashoid);

        switch (oidid)
        {
            case QSC_OID_ID_SHA1:
            {
                x509_ocsp_sha1_compute(output, data, datalen);
                *outputlen = X509_OCSP_SHA1_HASH_SIZE;
                res = true;
                break;
            }
            case QSC_OID_ID_SHA256:
            {
                qsc_sha256_compute(output, data, datalen);
                *outputlen = QSC_SHA2_256_HASH_SIZE;
                res = true;
                break;
            }
            case QSC_OID_ID_SHA384:
            {
                qsc_sha384_compute(output, data, datalen);
                *outputlen = QSC_SHA2_384_HASH_SIZE;
                res = true;
                break;
            }
            case QSC_OID_ID_SHA512:
            {
                qsc_sha512_compute(output, data, datalen);
                *outputlen = QSC_SHA2_512_HASH_SIZE;
                res = true;
                break;
            }
            default:
            {
                break;
            }
        }
    }

    return res;
}

static bool x509_ocsp_build_sha256_algorithm_identifier(uint8_t* output, size_t* outputlen)
{
    qsc_asn1_oid oid = { 0 };
    qsc_asn1_status status;
    uint8_t content[32U] = { 0U };
    uint8_t nullbuf[8U] = { 0U };
    size_t len;
    size_t pos;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    pos = 0U;

    if (output != (uint8_t*)NULL && outputlen != (size_t*)NULL)
    {
        if (qsc_oid_to_asn1(QSC_OID_ID_SHA256, &oid) == true)
        {
            len = sizeof(content) - pos;
            status = qsc_x509_write_oid(&oid, content + pos, &len);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                pos += len;
                len = sizeof(nullbuf);
                status = qsc_x509_write_null(nullbuf, &len);
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                if ((sizeof(content) - pos) < len)
                {
                    status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    qsc_memutils_copy(content + pos, nullbuf, len);
                    pos += len;
                    status = qsc_x509_write_sequence(content, pos, output, outputlen);
                }
            }
        }
        else
        {
            status = QSC_ASN1_STATUS_NOT_FOUND;
        }
    }

    return (status == QSC_ASN1_STATUS_SUCCESS);
}

static bool x509_ocsp_build_request(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, uint8_t* output, size_t* outputlen)
{
    qsc_asn1_oid hashoid = { 0 };
    uint8_t algid[32U] = { 0U };
    uint8_t certid[256U] = { 0U };
    uint8_t requestseq[320U] = { 0U };
    uint8_t requestlist[384U] = { 0U };
    uint8_t tbsrequest[448U] = { 0U };
    uint8_t nameder[X509_OCSP_NAME_DER_MAX] = { 0U };
    uint8_t issuernamehash[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t issuerkeyhash[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t serialder[QSC_X509_SERIAL_NUMBER_MAX + 8U] = { 0U };
    size_t algidlen;
    size_t certidlen;
    size_t issuernamehashlen;
    size_t issuerkeyhashlen;
    size_t len;
    size_t namederlen;
    size_t pos;
    size_t requestlistlen;
    size_t requestseqlen;
    size_t serialderlen;
    size_t tbsrequestlen;
    bool res;

    res = false;

    if (certificate != (const qsc_x509_certificate*)NULL && issuer != (const qsc_x509_certificate*)NULL && output != (uint8_t*)NULL && outputlen != (size_t*)NULL)
    {
        namederlen = sizeof(nameder);
        algidlen = sizeof(algid);
        serialderlen = sizeof(serialder);

        if (qsc_oid_to_asn1(QSC_OID_ID_SHA256, &hashoid) == true &&
            qsc_x509_write_name(&issuer->subject, nameder, &namederlen) == QSC_ASN1_STATUS_SUCCESS &&
            x509_ocsp_build_sha256_algorithm_identifier(algid, &algidlen) == true &&
            qsc_x509_write_integer(certificate->serialnumber, certificate->serialnumberlen, serialder, &serialderlen) == QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_sha256_compute(issuernamehash, nameder, namederlen);
            qsc_sha256_compute(issuerkeyhash, issuer->subjectpublickeyinfo.publickey, issuer->subjectpublickeyinfo.publickeylen);
            issuernamehashlen = QSC_SHA2_256_HASH_SIZE;
            issuerkeyhashlen = QSC_SHA2_256_HASH_SIZE;
            pos = 0U;

            if ((sizeof(certid) - pos) >= algidlen)
            {
                qsc_memutils_copy(certid + pos, algid, algidlen);
                pos += algidlen;
                len = sizeof(certid) - pos;
                if (qsc_x509_write_octet_string(issuernamehash, issuernamehashlen, certid + pos, &len) == QSC_ASN1_STATUS_SUCCESS)
                {
                    pos += len;
                    len = sizeof(certid) - pos;
                    if (qsc_x509_write_octet_string(issuerkeyhash, issuerkeyhashlen, certid + pos, &len) == QSC_ASN1_STATUS_SUCCESS)
                    {
                        pos += len;
                        if ((sizeof(certid) - pos) >= serialderlen)
                        {
                            qsc_memutils_copy(certid + pos, serialder, serialderlen);
                            pos += serialderlen;
                            certidlen = sizeof(certid);

                            if (qsc_x509_write_sequence(certid, pos, certid, &certidlen) == QSC_ASN1_STATUS_SUCCESS)
                            {
                                requestseqlen = sizeof(requestseq);

                                if (qsc_x509_write_sequence(certid, certidlen, requestseq, &requestseqlen) == QSC_ASN1_STATUS_SUCCESS)
                                {
                                    requestlistlen = sizeof(requestlist);

                                    if (qsc_x509_write_sequence(requestseq, requestseqlen, requestlist, &requestlistlen) == QSC_ASN1_STATUS_SUCCESS)
                                    {
                                        tbsrequestlen = sizeof(tbsrequest);

                                        if (qsc_x509_write_sequence(requestlist, requestlistlen, tbsrequest, &tbsrequestlen) == QSC_ASN1_STATUS_SUCCESS)
                                        {
                                            res = (qsc_x509_write_sequence(tbsrequest, tbsrequestlen, output, outputlen) == QSC_ASN1_STATUS_SUCCESS);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return res;
}

static bool x509_ocsp_get_basic_response_octets(const uint8_t* der, size_t derlen, const uint8_t** octets, size_t* octetlen)
{
    static const uint8_t OID_ID_PKIX_OCSP_BASIC[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x30U, 0x01U, 0x01U };
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* child;
    const qsc_encoding_ber_element* rb;
    const qsc_encoding_ber_element* rocts;
    const qsc_encoding_ber_element* rtype;
    qsc_asn1_oid oid = { 0 };
    uint64_t responsestatus;
    size_t consumed;
    qsc_asn1_status status;
    bool res;

    if (der == (const uint8_t*)NULL || octets == (const uint8_t**)NULL || octetlen == (size_t*)NULL)
    {
        res = false;
    }
    else
    {
        *octets = (const uint8_t*)NULL;
        *octetlen = 0U;
        consumed = 0U;
        root = qsc_encoding_der_decode_element(der, derlen, &consumed);

        if (root == (qsc_encoding_ber_element*)NULL || consumed != derlen)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else
        {
            status = qsc_asn1_require_sequence(root, 1U, 2U);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(root, 0U);
            status = x509_ocsp_decode_enumerated_u64(child, &responsestatus);

            if (status == QSC_ASN1_STATUS_SUCCESS && responsestatus == 0U && qsc_asn1_child_count(root) == 2U)
            {
                child = qsc_asn1_get_child(root, 1U);
                status = qsc_asn1_get_explicit_child(child, &rb);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = qsc_asn1_require_sequence(rb, 2U, 2U);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    rtype = qsc_asn1_get_child(rb, 0U);
                    rocts = qsc_asn1_get_child(rb, 1U);
                    status = qsc_asn1_decode_oid(rtype, &oid);

                    if (status == QSC_ASN1_STATUS_SUCCESS && x509_asn1_is_octet_string(rocts) == true &&
                        x509_ocsp_oid_equals(&oid, OID_ID_PKIX_OCSP_BASIC, sizeof(OID_ID_PKIX_OCSP_BASIC)) == true)
                    {
                        *octets = rocts->value;
                        *octetlen = rocts->length;
                    }
                }
            }
        }

        qsc_encoding_ber_free_element(root);
        res = (*octets != (const uint8_t*)NULL && *octetlen != 0U);
    }

    return res;
}

static bool x509_ocsp_parse_single_response(const qsc_encoding_ber_element* single, qsc_x509_ocsp_response* response)
{
    const qsc_encoding_ber_element* revinfo;
    const qsc_encoding_ber_element* revtime;
    const qsc_encoding_ber_element* statusel;
    qsc_asn1_status status;
    bool res;

    res = false;

    if (qsc_asn1_require_sequence(single, 3U, 5U) != QSC_ASN1_STATUS_SUCCESS)
    {
        res = false;
    }
    else
    {
        statusel = qsc_asn1_get_child(single, 1U);

        if (qsc_asn1_element_is_tag(statusel, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 0U) == true)
        {
            response->status = QSC_X509_OCSP_STATUS_GOOD;
            res = true;
        }
        else if (qsc_asn1_element_is_tag(statusel, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 2U) == true)
        {
            response->status = QSC_X509_OCSP_STATUS_UNKNOWN;
            res = true;
        }
        else if (qsc_asn1_element_is_tag(statusel, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 1U) == true)
        {
            response->status = QSC_X509_OCSP_STATUS_REVOKED;
            status = qsc_asn1_get_explicit_child(statusel, &revinfo);

            if (status == QSC_ASN1_STATUS_SUCCESS && qsc_asn1_require_sequence(revinfo, 1U, 2U) == QSC_ASN1_STATUS_SUCCESS)
            {
                revtime = qsc_asn1_get_child(revinfo, 0U);

                if (qsc_asn1_decode_time(revtime, &response->revocationtime) == QSC_ASN1_STATUS_SUCCESS)
                {
                    res = true;
                }
            }
        }
    }

    return res;
}

static bool x509_ocsp_extract_tbs_and_signature(const uint8_t* basicder, size_t basiclen, const uint8_t** tbsdata, size_t* tbsdatalen,
    qsc_x509_algorithm_identifier* sigalg, const uint8_t** sigdata, size_t* siglen, uint8_t* sigunused, qsc_x509_certificate* responder)
{
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* certsctx;
    const qsc_encoding_ber_element* certseq;
    qsc_asn1_bit_string sig = { 0 };
    uint8_t certder[X509_OCSP_MAX_RESPONSE_CERT_DER] = { 0U };
    size_t certderlen;
    size_t consumed;
    qsc_asn1_status status;
    bool res;

    res = false;

    if (tbsdata == (const uint8_t**)NULL || tbsdatalen == (size_t*)NULL || sigalg == (qsc_x509_algorithm_identifier*)NULL ||
        sigdata == (const uint8_t**)NULL || siglen == (size_t*)NULL || sigunused == (uint8_t*)NULL)
    {
        res = false;
    }
    else
    {
        *tbsdata = (const uint8_t*)NULL;
        *tbsdatalen = 0U;
        *sigdata = (const uint8_t*)NULL;
        *siglen = 0U;
        *sigunused = 0U;
        consumed = 0U;
        root = qsc_encoding_der_decode_element(basicder, basiclen, &consumed);

        if (root == (qsc_encoding_ber_element*)NULL || consumed != basiclen)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else
        {
            status = qsc_asn1_require_sequence(root, 3U, 4U);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            const uint8_t* tbsslice;
            size_t tbsslicelen;
            qsc_asn1_status tbsstatus;

            tbsslice = (const uint8_t*)NULL;
            tbsslicelen = 0U;
            tbsstatus = qsc_asn1_der_get_child_region(basicder, basiclen, 0U, &tbsslice, &tbsslicelen);

            if (tbsstatus != QSC_ASN1_STATUS_SUCCESS || tbsslice == (const uint8_t*)NULL || tbsslicelen == 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                *tbsdata = tbsslice;
                *tbsdatalen = tbsslicelen;
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_x509_signature_algorithm_decode(qsc_asn1_get_child(root, 1U), sigalg);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_asn1_decode_bit_string(qsc_asn1_get_child(root, 2U), &sig);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                *sigdata = sig.data;
                *siglen = sig.length;
                *sigunused = sig.unused;
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS && responder != (qsc_x509_certificate*)NULL)
        {
            qsc_memutils_clear((uint8_t*)responder, sizeof(qsc_x509_certificate));
            certsctx = qsc_asn1_find_context_child(root, 0U);

            if (certsctx != (const qsc_encoding_ber_element*)NULL)
            {
                status = qsc_asn1_get_explicit_child(certsctx, &certseq);

                if (status == QSC_ASN1_STATUS_SUCCESS && qsc_asn1_require_sequence(certseq, 1U, SIZE_MAX) == QSC_ASN1_STATUS_SUCCESS)
                {
                    certderlen = qsc_encoding_der_encode_element((qsc_encoding_ber_element*)qsc_asn1_get_child(certseq, 0U), certder, sizeof(certder));

                    if (certderlen == 0U)
                    {
                        status = QSC_ASN1_STATUS_INVALID_LENGTH;
                    }
                    else
                    {
                        status = qsc_x509_certificate_decode_der(certder, certderlen, responder);
                    }
                }
            }
        }

        qsc_encoding_ber_free_element(root);
        res = (status == QSC_ASN1_STATUS_SUCCESS && *tbsdata != (const uint8_t*)NULL && *sigdata != (const uint8_t*)NULL);
    }

    return res;
}

static bool x509_ocsp_certificate_same_identity(const qsc_x509_certificate* left, const qsc_x509_certificate* right)
{
    if (left == (const qsc_x509_certificate*)NULL || right == (const qsc_x509_certificate*)NULL)
    {
        return false;
    }

    if (left->serialnumberlen != right->serialnumberlen)
    {
        return false;
    }

    if (qsc_memutils_are_equal(left->serialnumber, right->serialnumber, left->serialnumberlen) == false)
    {
        return false;
    }

    return (qsc_x509_name_equals(&left->issuer, &right->issuer) == true && qsc_x509_name_equals(&left->subject, &right->subject) == true);
}

static bool x509_ocsp_extract_name_der(const qsc_x509_name* name, uint8_t* output, size_t otplen, size_t* outlen)
{
    size_t len;
    bool res;

    res = false;

    if (name != (const qsc_x509_name*)NULL && output != (uint8_t*)NULL && outlen != (size_t*)NULL)
    {
        len = otplen;
        res = (qsc_x509_write_name(name, output, &len) == QSC_ASN1_STATUS_SUCCESS);

        if (res == true)
        {
            *outlen = len;
        }
    }

    return res;
}

static bool x509_ocsp_match_responder_id(const qsc_encoding_ber_element* responsedata, const qsc_x509_certificate* responder)
{
    const qsc_encoding_ber_element* responderid;
    const qsc_encoding_ber_element* ridchild;
    uint8_t expected[X509_OCSP_NAME_DER_MAX] = { 0U };
    uint8_t actual[X509_OCSP_NAME_DER_MAX] = { 0U };
    uint8_t keyhash[X509_OCSP_SHA1_HASH_SIZE] = { 0U };
    size_t idx;
    size_t expectedlen;
    size_t actuallen;
    bool res;

    res = false;
    expectedlen = 0U;
    actuallen = 0U;

    if (responsedata != (const qsc_encoding_ber_element*)NULL && responder != (const qsc_x509_certificate*)NULL)
    {
        idx = 0U;

        if (qsc_asn1_child_count(responsedata) >= 1U)
        {
            const qsc_encoding_ber_element* first;
            first = qsc_asn1_get_child(responsedata, 0U);

            if (first != (const qsc_encoding_ber_element*)NULL &&
                first->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC &&
                first->tagnumber == 0U)
            {
                idx = 1U;
            }
        }

        responderid = qsc_asn1_get_child(responsedata, idx);

        if (responderid != (const qsc_encoding_ber_element*)NULL)
        {
            if (responderid->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC && responderid->tagnumber == 1U)
            {
                if (qsc_asn1_get_explicit_child(responderid, &ridchild) == QSC_ASN1_STATUS_SUCCESS)
                {
                    expectedlen = sizeof(expected);
                    actuallen = qsc_encoding_der_encode_element((qsc_encoding_ber_element*)ridchild, actual, sizeof(actual));

                    if (actuallen != 0U && x509_ocsp_extract_name_der(&responder->subject, expected, sizeof(expected), &expectedlen) == true)
                    {
                        res = (expectedlen == actuallen) && qsc_memutils_are_equal(expected, actual, expectedlen);
                    }
                }
            }
            else if (responderid->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC && responderid->tagnumber == 2U)
            {
                if (qsc_asn1_get_explicit_child(responderid, &ridchild) == QSC_ASN1_STATUS_SUCCESS && x509_asn1_is_octet_string(ridchild) == true)
                {
                    x509_ocsp_sha1_compute(keyhash, responder->subjectpublickeyinfo.publickey, responder->subjectpublickeyinfo.publickeylen);
                    res = (ridchild->length == X509_OCSP_SHA1_HASH_SIZE) && qsc_memutils_are_equal(ridchild->value, keyhash, X509_OCSP_SHA1_HASH_SIZE);
                }
            }
        }
    }

    return res;
}

static bool x509_ocsp_parse_single_response_for_certificate(const qsc_encoding_ber_element* single, const qsc_x509_certificate* certificate,
    const qsc_x509_certificate* issuer, const qsc_asn1_time* now, qsc_x509_ocsp_response* response)
{
    qsc_asn1_time nextupdate = { 0 };
    qsc_asn1_time thisupdate = { 0 };
    qsc_x509_algorithm_identifier hashalg = { 0 };
    const qsc_encoding_ber_element* algel;
    const qsc_encoding_ber_element* certid;
    const qsc_encoding_ber_element* keyhashel;
    const qsc_encoding_ber_element* namehashel;
    const qsc_encoding_ber_element* nextupdatectx;
    const qsc_encoding_ber_element* nextupdateel;
    const qsc_encoding_ber_element* serialel;
    const qsc_encoding_ber_element* statusel;
    const qsc_encoding_ber_element* thisupdateel;
    uint8_t expectedkeyhash[X509_OCSP_HASH_BUFFER_MAX] = { 0U };
    uint8_t expectednamehash[X509_OCSP_HASH_BUFFER_MAX] = { 0U };
    uint8_t nameder[X509_OCSP_NAME_DER_MAX] = { 0U };
    uint8_t serial[QSC_X509_SERIAL_NUMBER_MAX] = { 0U };
    size_t expectedkeyhashlen;
    size_t expectednamehashlen;
    size_t namederlen;
    size_t seriallen;
    bool hasnext;
    bool matched;
    bool res;

    res = false;
    matched = false;
    hasnext = false;
    namederlen = 0U;
    expectednamehashlen = 0U;
    expectedkeyhashlen = 0U;
    seriallen = 0U;

    if (single == (const qsc_encoding_ber_element*)NULL || certificate == (const qsc_x509_certificate*)NULL || issuer == (const qsc_x509_certificate*)NULL ||
        now == (const qsc_asn1_time*)NULL || response == (qsc_x509_ocsp_response*)NULL)
    {
        return false;
    }

    if (qsc_asn1_require_sequence(single, 3U, 5U) != QSC_ASN1_STATUS_SUCCESS)
    {
        return false;
    }

    certid = qsc_asn1_get_child(single, 0U);
    statusel = qsc_asn1_get_child(single, 1U);
    thisupdateel = qsc_asn1_get_child(single, 2U);

    if (certid == (const qsc_encoding_ber_element*)NULL || statusel == (const qsc_encoding_ber_element*)NULL || thisupdateel == (const qsc_encoding_ber_element*)NULL ||
        qsc_asn1_require_sequence(certid, 4U, 4U) != QSC_ASN1_STATUS_SUCCESS)
    {
        return false;
    }

    algel = qsc_asn1_get_child(certid, 0U);
    namehashel = qsc_asn1_get_child(certid, 1U);
    keyhashel = qsc_asn1_get_child(certid, 2U);
    serialel = qsc_asn1_get_child(certid, 3U);

    if (algel == (const qsc_encoding_ber_element*)NULL || namehashel == (const qsc_encoding_ber_element*)NULL ||
        keyhashel == (const qsc_encoding_ber_element*)NULL || serialel == (const qsc_encoding_ber_element*)NULL ||
        qsc_x509_algorithm_identifier_decode(algel, &hashalg) != QSC_ASN1_STATUS_SUCCESS)
    {
        return false;
    }

    if (namehashel->tagclass != QSC_ENCODING_BER_CLASS_UNIVERSAL || namehashel->tagnumber != BER_ASN1_OCTET_STRING ||
        keyhashel->tagclass != QSC_ENCODING_BER_CLASS_UNIVERSAL || keyhashel->tagnumber != BER_ASN1_OCTET_STRING)
    {
        return false;
    }

    if (x509_ocsp_copy_unsigned_integer(serialel, serial, sizeof(serial), &seriallen) != QSC_ASN1_STATUS_SUCCESS)
    {
        return false;
    }

    if (x509_ocsp_extract_name_der(&issuer->subject, nameder, sizeof(nameder), &namederlen) == false)
    {
        return false;
    }

    if (x509_ocsp_hash_octets(&hashalg.algorithm_oid, nameder, namederlen, expectednamehash, &expectednamehashlen) == false ||
        x509_ocsp_hash_octets(&hashalg.algorithm_oid, issuer->subjectpublickeyinfo.publickey, issuer->subjectpublickeyinfo.publickeylen,
            expectedkeyhash, &expectedkeyhashlen) == false)
    {
        return false;
    }

    matched = (expectednamehashlen == namehashel->length) &&
        qsc_memutils_are_equal(expectednamehash, namehashel->value, expectednamehashlen) &&
        (expectedkeyhashlen == keyhashel->length) &&
        qsc_memutils_are_equal(expectedkeyhash, keyhashel->value, expectedkeyhashlen) &&
        x509_ocsp_serial_bytes_equal(serial, seriallen, certificate->serialnumber, certificate->serialnumberlen);

    if (matched == false)
    {
        return false;
    }

    if (qsc_asn1_decode_time(thisupdateel, &thisupdate) != QSC_ASN1_STATUS_SUCCESS)
    {
        return false;
    }

    if (qsc_asn1_time_compare(now, &thisupdate) < 0)
    {
        return false;
    }

    nextupdatectx = qsc_asn1_find_context_child(single, 0U);

    if (nextupdatectx != (const qsc_encoding_ber_element*)NULL)
    {
        if (qsc_asn1_get_explicit_child(nextupdatectx, &nextupdateel) != QSC_ASN1_STATUS_SUCCESS ||
            qsc_asn1_decode_time(nextupdateel, &nextupdate) != QSC_ASN1_STATUS_SUCCESS)
        {
            return false;
        }

        hasnext = true;
    }

    if (hasnext == true && qsc_asn1_time_compare(now, &nextupdate) > 0)
    {
        return false;
    }

    x509_ocsp_response_initialize(response);
    res = x509_ocsp_parse_single_response(single, response);
    return res;
}

static bool x509_ocsp_find_response_for_certificate(const qsc_encoding_ber_element* responsedata, const qsc_x509_certificate* certificate,
    const qsc_x509_certificate* issuer, const qsc_asn1_time* now, qsc_x509_ocsp_response* response)
{
    const qsc_encoding_ber_element* responses;
    const qsc_encoding_ber_element* child;
    size_t idx;
    size_t i;
    bool res;

    res = false;
    idx = 0U;

    if (responsedata != (const qsc_encoding_ber_element*)NULL && certificate != (const qsc_x509_certificate*)NULL &&
        issuer != (const qsc_x509_certificate*)NULL && now != (const qsc_asn1_time*)NULL && response != (qsc_x509_ocsp_response*)NULL)
    {
        if (qsc_asn1_require_sequence(responsedata, 3U, 5U) == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(responsedata, 0U);

            if (child != (const qsc_encoding_ber_element*)NULL &&
                qsc_asn1_element_is_tag(child, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 0U) == true)
            {
                idx = 1U;
            }

            idx += 2U;
            responses = qsc_asn1_get_child(responsedata, idx);

            if (responses != (const qsc_encoding_ber_element*)NULL && qsc_asn1_require_sequence(responses, 1U, SIZE_MAX) == QSC_ASN1_STATUS_SUCCESS)
            {
                for (i = 0U; i < qsc_asn1_child_count(responses); ++i)
                {
                    if (x509_ocsp_parse_single_response_for_certificate(qsc_asn1_get_child(responses, i), certificate, issuer, now, response) == true)
                    {
                        res = true;
                        break;
                    }
                }
            }
        }
    }

    return res;
}

static bool x509_ocsp_current_utc_time(qsc_asn1_time* astime)
{
    time_t tnow;
    struct tm tmv;
    bool res;

    res = false;

    if (astime != (qsc_asn1_time*)NULL)
    {
        tnow = time((time_t*)NULL);

        if (tnow != (time_t)-1)
        {
#if defined(QSC_SYSTEM_OS_WINDOWS)
            if (gmtime_s(&tmv, &tnow) == 0)
#else
            if (gmtime_r(&tnow, &tmv) != (struct tm*)NULL)
#endif
            {
                astime->year = (uint16_t)(tmv.tm_year + 1900);
                astime->month = (uint8_t)(tmv.tm_mon + 1);
                astime->day = (uint8_t)tmv.tm_mday;
                astime->hour = (uint8_t)tmv.tm_hour;
                astime->minute = (uint8_t)tmv.tm_min;
                astime->second = (uint8_t)tmv.tm_sec;
                astime->generalized = true;
                res = true;
            }
        }
    }

    return res;
}

bool qsc_x509_ocsp_parse_response(const uint8_t* der, size_t derlen, qsc_x509_ocsp_response* response)
{
    qsc_x509_algorithm_identifier sigalg = { 0 };
    qsc_x509_certificate responder = { 0 };
    const uint8_t* basicoctets;
    const uint8_t* sigdata;
    const uint8_t* tbsdata;
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* responsedata;
    size_t basicoctetslen;
    size_t consumed;
    size_t siglen;
    size_t tbsdatalen;
    uint8_t sigunused;
    qsc_asn1_status status;
    bool res;

    QSC_ASSERT(der != NULL);
    QSC_ASSERT(response != NULL);

    res = false;
    status = QSC_ASN1_STATUS_INVALID_INPUT;
    basicoctets = (const uint8_t*)NULL;
    basicoctetslen = 0U;
    sigdata = (const uint8_t*)NULL;
    siglen = 0U;
    tbsdata = (const uint8_t*)NULL;
    tbsdatalen = 0U;
    sigunused = 0U;
    root = (qsc_encoding_ber_element*)NULL;
    responsedata = (const qsc_encoding_ber_element*)NULL;

    if (der != (const uint8_t*)NULL && response != (qsc_x509_ocsp_response*)NULL)
    {
        x509_ocsp_response_initialize(response);

        if (x509_ocsp_get_basic_response_octets(der, derlen, &basicoctets, &basicoctetslen) == true &&
            x509_ocsp_extract_tbs_and_signature(basicoctets, basicoctetslen, &tbsdata, &tbsdatalen,
                &sigalg, &sigdata, &siglen, &sigunused, &responder) == true)
        {
            consumed = 0U;
            root = qsc_encoding_der_decode_element(basicoctets, basicoctetslen, &consumed);

            if (root != (qsc_encoding_ber_element*)NULL && consumed == basicoctetslen)
            {
                responsedata = qsc_asn1_get_child(root, 0U);
                status = qsc_asn1_require_sequence(responsedata, 3U, 5U);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    size_t idx;
                    const qsc_encoding_ber_element* responses;

                    idx = 2U;
                    responses = (const qsc_encoding_ber_element*)NULL;

                    if (qsc_asn1_child_count(responsedata) >= 1U)
                    {
                        const qsc_encoding_ber_element* first;
                        first = qsc_asn1_get_child(responsedata, 0U);

                        if (first != (const qsc_encoding_ber_element*)NULL &&
                            first->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC &&
                            first->tagnumber == 0U)
                        {
                            idx = 3U;
                        }
                    }

                    responses = qsc_asn1_get_child(responsedata, idx);
                    status = qsc_asn1_require_sequence(responses, 1U, SIZE_MAX);

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        if (x509_ocsp_parse_single_response(qsc_asn1_get_child(responses, 0U), response) == false)
                        {
                            status = QSC_ASN1_STATUS_FAILURE;
                        }
                    }
                }

                qsc_encoding_ber_free_element(root);
            }
        }

        if (responder.der != (const uint8_t*)NULL)
        {
            qsc_x509_certificate_clear(&responder);
        }

        res = (status == QSC_ASN1_STATUS_SUCCESS);
    }

    return res;
}

bool qsc_x509_ocsp_validate(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer,
    const char* url, qsc_x509_ocsp_fetch_callback fetch, void* context, const qsc_asn1_time* now, qsc_x509_ocsp_response* response)
{
    qsc_x509_algorithm_identifier sigalg = { 0 };
    qsc_x509_certificate responder = { 0 };
    qsc_x509_verify_state verifystate = { 0 };
    qsc_asn1_time currenttime = { 0 };
    uint8_t verifybuffer[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
    uint8_t ocspresponse[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
    uint8_t request[X509_OCSP_REQUEST_MAX] = { 0U };
    const qsc_encoding_ber_element* responsedata;
    const qsc_x509_subject_public_key_info* verifierspki;
    const uint8_t* basicoctets;
    const uint8_t* sigdata;
    const uint8_t* tbsdata;
    qsc_encoding_ber_element* root;
    size_t basicoctetslen;
    size_t requestlen;
    size_t responselen;
    size_t siglen;
    size_t tbsdatalen;
    uint8_t sigunused;
    bool res;

    QSC_ASSERT(certificate != NULL);
    QSC_ASSERT(issuer != NULL);
    QSC_ASSERT(url != NULL);
    QSC_ASSERT(fetch != NULL);
    QSC_ASSERT(response != NULL);

    res = false;
    root = (qsc_encoding_ber_element*)NULL;
    responsedata = (const qsc_encoding_ber_element*)NULL;
    basicoctets = (const uint8_t*)NULL;
    basicoctetslen = 0U;
    sigdata = (const uint8_t*)NULL;
    siglen = 0U;
    sigunused = 0U;
    tbsdata = (const uint8_t*)NULL;
    tbsdatalen = 0U;
    verifierspki = (const qsc_x509_subject_public_key_info*)NULL;

    if (certificate != (const qsc_x509_certificate*)NULL && issuer != (const qsc_x509_certificate*)NULL && url != (const char*)NULL &&
        fetch != (qsc_x509_ocsp_fetch_callback)NULL && response != (qsc_x509_ocsp_response*)NULL)
    {
        x509_ocsp_response_initialize(response);

        if (now == (const qsc_asn1_time*)NULL)
        {
            if (x509_ocsp_current_utc_time(&currenttime) == false)
            {
                return false;
            }

            now = &currenttime;
        }

        requestlen = sizeof(request);
        responselen = sizeof(ocspresponse);

        if (x509_ocsp_build_request(certificate, issuer, request, &requestlen) == true &&
            fetch(url, request, requestlen, ocspresponse, &responselen, context) == true &&
            x509_ocsp_get_basic_response_octets(ocspresponse, responselen, &basicoctets, &basicoctetslen) == true &&
            x509_ocsp_extract_tbs_and_signature(basicoctets, basicoctetslen, &tbsdata, &tbsdatalen, &sigalg, &sigdata,
                &siglen, &sigunused, &responder) == true)
        {
            if (responder.der != (const uint8_t*)NULL && responder.derlen != 0U)
            {
                if (qsc_x509_ocsp_verify_responder(&responder, issuer, (const qsc_x509_store*)NULL, now) == true)
                {
                    verifierspki = &responder.subjectpublickeyinfo;
                }
            }
            else
            {
                verifierspki = &issuer->subjectpublickeyinfo;
            }

            if (verifierspki != (const qsc_x509_subject_public_key_info*)NULL)
            {
                qsc_x509_qsc_verify_state_initialize(&verifystate, verifybuffer, sizeof(verifybuffer));

                if (qsc_x509_qsc_verify_signed_data(tbsdata, tbsdatalen, sigdata, siglen, sigunused, sigalg.signature, verifierspki, &verifystate) == true)
                {
                    size_t consumed;

                    consumed = 0U;
                    root = qsc_encoding_der_decode_element(basicoctets, basicoctetslen, &consumed);

                    if (root != (qsc_encoding_ber_element*)NULL && consumed == basicoctetslen && qsc_asn1_require_sequence(root, 3U, 4U) == QSC_ASN1_STATUS_SUCCESS)
                    {
                        responsedata = qsc_asn1_get_child(root, 0U);

                        if (qsc_asn1_require_sequence(responsedata, 3U, 5U) == QSC_ASN1_STATUS_SUCCESS)
                        {
                            if ((responder.der == (const uint8_t*)NULL || responder.derlen == 0U || x509_ocsp_match_responder_id(responsedata, &responder) == true) &&
                                x509_ocsp_find_response_for_certificate(responsedata, certificate, issuer, now, response) == true)
                            {
                                res = true;
                            }
                        }

                        qsc_encoding_ber_free_element(root);
                    }
                }
            }
        }

        if (responder.der != (const uint8_t*)NULL)
        {
            qsc_x509_certificate_clear(&responder);
        }
    }

    return res;
}

bool qsc_x509_ocsp_verify_responder(const qsc_x509_certificate* responder, const qsc_x509_certificate* issuer, const qsc_x509_store* store, const qsc_asn1_time* now)
{
    qsc_x509_verify_state verifystate = { 0 };
    qsc_x509_verify_status status = { 0 };
    uint8_t verifybuffer[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
    uint32_t ekubits;
    uint32_t kubits;
    bool directissuer;
    bool trustedresponder;
    bool res;

    QSC_ASSERT(responder != NULL);
    QSC_ASSERT(issuer != NULL);

    res = false;
    ekubits = 0U;
    kubits = 0U;
    directissuer = false;
    trustedresponder = false;

    if (responder != (const qsc_x509_certificate*)NULL && issuer != (const qsc_x509_certificate*)NULL && now != (const qsc_asn1_time*)NULL)
    {
        if (qsc_x509_certificate_check_validity(responder, now) == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            directissuer = x509_ocsp_certificate_same_identity(responder, issuer);
            trustedresponder = (store != (const qsc_x509_store*)NULL && qsc_x509_store_contains_anchor(store, responder) == true);
            res = true;

            if (directissuer == false)
            {
                if (responder->extensions.extendedkeyusage.present == false)
                {
                    res = false;
                }
                else
                {
                    ekubits = responder->extensions.extendedkeyusage.bits;

                    if (((ekubits & QSC_X509_EXTENDED_KEY_USAGE_ANY) == 0U) && ((ekubits & QSC_X509_EXTENDED_KEY_USAGE_OCSP_SIGNING) == 0U))
                    {
                        res = false;
                    }
                }
            }

            if (res == true && responder->extensions.keyusage.present == true)
            {
                kubits = responder->extensions.keyusage.bits;

                if ((kubits & QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE) == 0U)
                {
                    res = false;
                }
            }

            if (res == true)
            {
                if (trustedresponder == true)
                {
                    res = true;
                }
                else
                {
                    qsc_x509_qsc_verify_state_initialize(&verifystate, verifybuffer, sizeof(verifybuffer));
                    status = qsc_x509_certificate_verify(responder, issuer, now, qsc_x509_qsc_signature_verify, &verifystate);
                    res = (status == QSC_X509_VERIFY_STATUS_SUCCESS);
                }
            }
        }
    }

    return res;
}
