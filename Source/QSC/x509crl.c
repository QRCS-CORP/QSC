#include "x509crl.h"
#include "encoding.h"
#include "memutils.h"
#include "x509crlwrite.h"
#include "x509ext.h"
#include "x509name.h"
#include "x509time.h"
#include "x509sig.h"
#include "x509write.h"

#define QSC_ASN1_CLASS_UNIVERSAL 0x00U
#define QSC_ASN1_CLASS_CONTEXT 0x80U
#define QSC_ASN1_TAG_INTEGER 2U
#define QSC_ASN1_TAG_SEQUENCE 16U
#define QSC_ASN1_TAG_UTC_TIME 23U
#define QSC_ASN1_TAG_GENERALIZED_TIME 24U

static qsc_asn1_status x509_crl_copy_unsigned_integer(const qsc_encoding_ber_element* element, uint8_t* output, size_t otplen, size_t* outlen)
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
        status = qsc_asn1_require_tag(element, QSC_ASN1_CLASS_UNIVERSAL, false, QSC_ASN1_TAG_INTEGER);

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

                    if (ilen == 0U)
                    {
                        status = QSC_ASN1_STATUS_INVALID_LENGTH;
                    }
                    else if (ilen > otplen)
                    {
                        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                    }
                    else
                    {
                        qsc_memutils_clear(output, otplen);
                        qsc_memutils_copy(output, element->value + ofs, ilen);
                        *outlen = ilen;
                        status = QSC_ASN1_STATUS_SUCCESS;
                    }
                }
            }
        }
    }

    return status;
}

static bool x509_crl_algorithm_identifiers_equal(const qsc_x509_algorithm_identifier* a, const qsc_x509_algorithm_identifier* b)
{
    bool res;

    res = false;

    if (a != (const qsc_x509_algorithm_identifier*)NULL && b != (const qsc_x509_algorithm_identifier*)NULL)
    {
        if (a->oid == b->oid &&
            a->publickey == b->publickey &&
            a->signature == b->signature &&
            a->hash == b->hash &&
            a->curve == b->curve &&
            a->parameters_present == b->parameters_present &&
            a->parameters_null == b->parameters_null &&
            a->parameters_oid == b->parameters_oid &&
            qsc_asn1_oid_compare(&a->algorithm_oid, &b->algorithm_oid) == true)
        {
            if (a->parameters_oid == false || qsc_asn1_oid_compare(&a->parameter_oid, &b->parameter_oid) == true)
            {
                res = true;
            }
        }
    }

    return res;
}

static qsc_asn1_status x509_crl_decode_revoked_entry(const qsc_encoding_ber_element* element, qsc_x509_crl_entry* entry)
{
    qsc_asn1_status status;
    const qsc_encoding_ber_element* child;

    status = QSC_ASN1_STATUS_FAILURE;
    child = (const qsc_encoding_ber_element*)NULL;

    if (element == (const qsc_encoding_ber_element*)NULL || entry == (qsc_x509_crl_entry*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_memutils_clear((uint8_t*)entry, sizeof(qsc_x509_crl_entry));
        status = qsc_asn1_require_sequence(element, 2U, 3U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, 0U);
            status = x509_crl_copy_unsigned_integer(child, entry->serialnumber, sizeof(entry->serialnumber), &entry->serialnumberlen);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, 1U);

            if (child == (const qsc_encoding_ber_element*)NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else if (qsc_x509_time_decode(&entry->revocationdate, child) == false)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS && element->ccount == 3U)
        {
            size_t enclen;

            child = qsc_asn1_get_child(element, 2U);

            if (child == (const qsc_encoding_ber_element*)NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                enclen = qsc_encoding_der_encode_element((qsc_encoding_ber_element*)child, entry->rawextensions, sizeof(entry->rawextensions));

                if (enclen == 0U)
                {
                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                }
                else if (enclen > sizeof(entry->rawextensions))
                {
                    status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                }
                else
                {
                    entry->rawextensionslen = enclen;
                }
            }
        }
    }

    return status;
}

static qsc_asn1_status x509_crl_decode_tbs(const qsc_encoding_ber_element* element, qsc_x509_crl* crl)
{
    qsc_asn1_status status;
    const qsc_encoding_ber_element* child;
    size_t idx;
    bool hasversion;
    uint64_t version;

    status = QSC_ASN1_STATUS_FAILURE;
    child = (const qsc_encoding_ber_element*)NULL;
    idx = 0U;
    hasversion = false;
    version = 0U;

    if (element == (const qsc_encoding_ber_element*)NULL || crl == (qsc_x509_crl*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        status = qsc_asn1_require_sequence(element, 3U, 7U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, idx);

            if (child != (const qsc_encoding_ber_element*)NULL && qsc_asn1_is_integer(child) == true)
            {
                status = qsc_asn1_decode_integer_u64(child, &version);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    if (version > 1U)
                    {
                        status = QSC_ASN1_STATUS_UNSUPPORTED;
                    }
                    else
                    {
                        crl->version = (uint32_t)(version + 1U);
                        idx += 1U;
                        hasversion = true;
                    }
                }
            }
            else
            {
                crl->version = 1U;
                status = QSC_ASN1_STATUS_SUCCESS;
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, idx);
            status = qsc_x509_signature_algorithm_decode(child, &crl->tbsignature);
            idx += 1U;
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, idx);
            status = qsc_x509_name_parse(child, &crl->issuer);
            idx += 1U;
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, idx);

            if (child == (const qsc_encoding_ber_element*)NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else if (qsc_x509_time_decode(&crl->thisupdate, child) == false)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                idx += 1U;
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS && idx < element->ccount)
        {
            child = qsc_asn1_get_child(element, idx);

            if (child != (const qsc_encoding_ber_element*)NULL &&
                child->tagclass == QSC_ASN1_CLASS_UNIVERSAL &&
                (child->tagnumber == QSC_ASN1_TAG_UTC_TIME || child->tagnumber == QSC_ASN1_TAG_GENERALIZED_TIME))
            {
                if (qsc_x509_time_decode(&crl->nextupdate, child) == false)
                {
                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                }
                else
                {
                    crl->nextupdate_present = true;
                    idx += 1U;
                }
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS && idx < element->ccount)
        {
            child = qsc_asn1_get_child(element, idx);

            if (child != (const qsc_encoding_ber_element*)NULL &&
                child->tagclass == QSC_ASN1_CLASS_UNIVERSAL &&
                child->constructed == true &&
                child->tagnumber == QSC_ASN1_TAG_SEQUENCE)
            {
                if (child->ccount > QSC_X509_CRL_REVOKED_MAX)
                {
                    status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    for (size_t i = 0U; i < child->ccount && status == QSC_ASN1_STATUS_SUCCESS; ++i)
                    {
                        status = x509_crl_decode_revoked_entry(child->children[i], &crl->revoked[i]);
                    }

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        crl->revokedcount = child->ccount;
                        idx += 1U;
                    }
                }
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS && idx < element->ccount)
        {
            /* optional CRL extensions are accepted only as [0] EXPLICIT. */
            child = qsc_asn1_get_child(element, idx);

            if (child == (const qsc_encoding_ber_element*)NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else if (hasversion == false)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else if (child->tagclass != QSC_ASN1_CLASS_CONTEXT || child->tagnumber != 0U)
            {
                status = QSC_ASN1_STATUS_UNSUPPORTED;
            }
            else if (child->constructed == false || child->ccount != 1U)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                status = qsc_x509_extensions_decode(child->children[0U], &crl->extensions);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    ++idx;
                }
            }
        }
    }

    return status;
}

void qsc_x509_crl_clear(qsc_x509_crl* crl)
{
    QSC_ASSERT(crl != NULL);

    if (crl != (qsc_x509_crl*)NULL)
    {
        if (crl->der != (const uint8_t*)NULL && crl->derlen != 0U)
        {
            qsc_memutils_secure_erase((void*)crl->der, crl->derlen);
            qsc_memutils_alloc_free((void*)crl->der);
        }

        qsc_memutils_clear((uint8_t*)crl, sizeof(qsc_x509_crl));
    }
}

static void x509_crl_copy_to_builder(const qsc_x509_crl* crl, qsc_x509_crl_builder* builder)
{
    QSC_ASSERT(crl != NULL);
    QSC_ASSERT(builder != NULL);

    qsc_x509_crl_builder_initialize(builder);
    builder->version = crl->version;
    builder->issuer = crl->issuer;
    builder->validity.notbefore = crl->thisupdate;

    if (crl->nextupdate_present == true)
    {
        builder->validity.notafter = crl->nextupdate;
    }
    else
    {
        qsc_memutils_clear((uint8_t*)&builder->validity.notafter, sizeof(builder->validity.notafter));
    }

    builder->signaturealgorithm = crl->tbsignature;
    builder->extensions = crl->extensions;
    builder->entrycount = crl->revokedcount;

    for (size_t i = 0U; i < crl->revokedcount; ++i)
    {
        builder->entries[i] = crl->revoked[i];
    }
}

qsc_asn1_status qsc_x509_crl_encode_der(const qsc_x509_crl* crl, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(crl != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t tbs[QSC_X509_CRL_WRITE_MAX] = { 0U };
    uint8_t content[QSC_X509_CRL_WRITE_MAX] = { 0U };
    qsc_x509_crl_builder builder;
    qsc_asn1_status status;
    size_t tbslen;
    size_t pos;
    size_t len;

    if (crl == (const qsc_x509_crl*)NULL || outputlen == (size_t*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (crl->signaturelen == 0U)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        x509_crl_copy_to_builder(crl, &builder);
        tbslen = sizeof(tbs);
        status = qsc_x509_crl_builder_encode_tbs_der(&builder, tbs, &tbslen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            pos = 0U;

            if ((sizeof(content) - pos) < tbslen)
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                qsc_memutils_copy(content + pos, tbs, tbslen);
                pos += tbslen;
                len = sizeof(content) - pos;
                status = qsc_x509_write_algorithm_identifier(&crl->signaturealgorithm, content + pos, &len);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    pos += len;
                    len = sizeof(content) - pos;
                    status = qsc_x509_write_bit_string(crl->signature, crl->signaturelen, crl->signatureunusedbits, content + pos, &len);

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        pos += len;
                        status = qsc_x509_write_sequence(content, pos, output, outputlen);
                    }
                }
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_crl_decode_der(const uint8_t* der, size_t derlen, qsc_x509_crl* crl)
{
    QSC_ASSERT(der != NULL);
    QSC_ASSERT(crl != NULL);

    qsc_asn1_bit_string bs = { 0 };
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* child;
    uint8_t* dercopy;
    const uint8_t* tbsraw;
    size_t tbsrawlen;
    ptrdiff_t tbsoffset;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    root = (qsc_encoding_ber_element*)NULL;
    child = (const qsc_encoding_ber_element*)NULL;
    tbsraw = (const uint8_t*)NULL;
    tbsoffset = 0;
    dercopy = (uint8_t*)NULL;
    tbsrawlen = 0U;

    if (der == (const uint8_t*)NULL || crl == (qsc_x509_crl*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_x509_crl_clear(crl);
        status = qsc_asn1_der_decode_exact(der, derlen, &root);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_asn1_der_get_child_region(der, derlen, 0U, &tbsraw, &tbsrawlen);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            tbsoffset = (ptrdiff_t)(tbsraw - der);

            if (tbsoffset < 0 || (size_t)tbsoffset >= derlen || tbsrawlen > (derlen - (size_t)tbsoffset))
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            dercopy = (uint8_t*)qsc_memutils_malloc(derlen);

            if (dercopy == (uint8_t*)NULL)
            {
                status = QSC_ASN1_STATUS_FAILURE;
            }
            else
            {
                qsc_memutils_copy(dercopy, der, derlen);
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_asn1_require_sequence(root, 3U, 3U);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(root, 0U);

            if (child == (const qsc_encoding_ber_element*)NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                crl->tbsdata = dercopy + (size_t)tbsoffset;
                crl->tbsdatalen = tbsrawlen;
                status = x509_crl_decode_tbs(child, crl);
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(root, 1U);
            status = qsc_x509_signature_algorithm_decode(child, &crl->signaturealgorithm);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(root, 2U);
            status = qsc_asn1_decode_bit_string(child, &bs);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                if (bs.length == 0U)
                {
                    status = QSC_ASN1_STATUS_INVALID_LENGTH;
                }
                else if (bs.length > sizeof(crl->signature))
                {
                    status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    qsc_memutils_copy(crl->signature, bs.data, bs.length);
                    crl->signaturelen = bs.length;
                    crl->signatureunusedbits = bs.unused;
                }
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            crl->der = dercopy;
            crl->derlen = derlen;
            dercopy = (uint8_t*)NULL;
        }

        if (root != (qsc_encoding_ber_element*)NULL)
        {
            qsc_encoding_ber_free_element(root);
        }

        if (status != QSC_ASN1_STATUS_SUCCESS && dercopy != (uint8_t*)NULL)
        {
            qsc_memutils_secure_erase(dercopy, derlen);
            qsc_memutils_alloc_free(dercopy);
        }
    }

    return status;
}

bool qsc_x509_crl_is_current(const qsc_x509_crl* crl, const qsc_asn1_time* now)
{
    QSC_ASSERT(crl != NULL);
    QSC_ASSERT(now != NULL);

    bool res;

    res = false;

    if (crl != (const qsc_x509_crl*)NULL && now != (const qsc_asn1_time*)NULL)
    {
        if (qsc_x509_time_compare(now, &crl->thisupdate) >= 0)
        {
            if (crl->nextupdate_present == false || qsc_x509_time_compare(now, &crl->nextupdate) <= 0)
            {
                res = true;
            }
        }
    }

    return res;
}

qsc_x509_crl_verify_status qsc_x509_crl_check_algorithms(const qsc_x509_crl* crl)
{
    QSC_ASSERT(crl != NULL);

    qsc_x509_crl_verify_status status;

    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;

    if (crl == (const qsc_x509_crl*)NULL)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;
    }
    else if (crl->signatureunusedbits != 0U)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
    }
    else if (x509_crl_algorithm_identifiers_equal(&crl->tbsignature, &crl->signaturealgorithm) == false)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_ALGORITHM_MISMATCH;
    }
    else if (crl->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_NONE)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_UNSUPPORTED;
    }
    else
    {
        status = QSC_X509_CRL_VERIFY_STATUS_SUCCESS;
    }

    return status;
}

const qsc_x509_crl_entry* qsc_x509_crl_find_serial(const qsc_x509_crl* crl, const uint8_t* serial, size_t seriallen)
{
    QSC_ASSERT(crl != NULL);
    QSC_ASSERT(serial != NULL);

    const qsc_x509_crl_entry* entry;

    entry = (const qsc_x509_crl_entry*)NULL;

    if (crl != (const qsc_x509_crl*)NULL && serial != (const uint8_t*)NULL)
    {
        for (size_t i = 0U; i < crl->revokedcount; ++i)
        {
            if (crl->revoked[i].serialnumberlen == seriallen &&
                qsc_memutils_are_equal(crl->revoked[i].serialnumber, serial, seriallen) == true)
            {
                entry = &crl->revoked[i];
                break;
            }
        }
    }

    return entry;
}

bool qsc_x509_certificate_is_revoked_by_crl(const qsc_x509_certificate* certificate, const qsc_x509_crl* crl)
{
    QSC_ASSERT(certificate != NULL);
    QSC_ASSERT(crl != NULL);

    bool res;

    res = false;

    if (certificate != (const qsc_x509_certificate*)NULL && crl != (const qsc_x509_crl*)NULL)
    {
        if (qsc_x509_name_equals(&certificate->issuer, &crl->issuer) == true)
        {
            if (qsc_x509_crl_find_serial(crl, certificate->serialnumber, certificate->serialnumberlen) != (const qsc_x509_crl_entry*)NULL)
            {
                res = true;
            }
        }
    }

    return res;
}

qsc_x509_crl_verify_status qsc_x509_crl_verify(const qsc_x509_crl* crl, const qsc_x509_certificate* issuer, const qsc_asn1_time* now, qsc_x509_crl_signature_verify_callback callback, void* state)
{
    QSC_ASSERT(crl != NULL);
    QSC_ASSERT(issuer != NULL);
    QSC_ASSERT(now != NULL);

    qsc_x509_crl_verify_status status;

    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;

    if (crl == (const qsc_x509_crl*)NULL || issuer == (const qsc_x509_certificate*)NULL || now == (const qsc_asn1_time*)NULL || callback == (qsc_x509_crl_signature_verify_callback)NULL)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;
    }
    else
    {
        status = qsc_x509_crl_check_algorithms(crl);

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            if (qsc_x509_name_equals(&crl->issuer, &issuer->subject) == false)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_ISSUER_MISMATCH;
            }
        }

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            if (qsc_x509_time_compare(now, &crl->thisupdate) < 0)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_NOT_YET_VALID;
            }
            else if (crl->nextupdate_present == true && qsc_x509_time_compare(now, &crl->nextupdate) > 0)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_EXPIRED;
            }
        }

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            if (issuer->extensions.keyusage.present == true)
            {
                if ((issuer->extensions.keyusage.bits & QSC_X509_KEY_USAGE_CRL_SIGN) == 0U)
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_KEY_USAGE_REJECTED;
                }
            }
        }

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            if (callback(crl, issuer, state) == false)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_SIGNATURE_REJECTED;
            }
        }
    }

    return status;
}

bool qsc_x509_crl_is_revoked(const qsc_x509_crl* crl, const qsc_x509_certificate* certificate)
{
    QSC_ASSERT(crl != NULL);
    QSC_ASSERT(certificate != NULL);

    bool res;

    res = false;

    if (crl != (const qsc_x509_crl*)NULL && certificate != (const qsc_x509_certificate*)NULL)
    {
        res = qsc_x509_certificate_is_revoked_by_crl(certificate, crl);
    }

    return res;
}
