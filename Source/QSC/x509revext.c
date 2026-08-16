#include "x509revext.h"
#include "asn1.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "oid.h"
#include "sha2.h"
#include "x509ext.h"
#include "x509name.h"
#include "x509ocsp.h"
#include "x509sig.h"
#include "x509sigver.h"
#include "x509spki.h"
#include "x509time.h"
#include "x509verify.h"
#include <time.h>

#define X509_ASN1_TAG_ENUMERATED 10U
#define X509_OID_CRL_NUMBER_LEN 3U
#define X509_OID_DELTA_CRL_INDICATOR_LEN 3U
#define X509_OID_ISSUING_DISTRIBUTION_POINT_LEN 3U
#define X509_OID_REASON_CODE_LEN 3U

static const uint8_t X509_OID_CRL_NUMBER[X509_OID_CRL_NUMBER_LEN] = { 0x55U, 0x1DU, 0x14U };
static const uint8_t X509_OID_DELTA_CRL_INDICATOR[X509_OID_DELTA_CRL_INDICATOR_LEN] = { 0x55U, 0x1DU, 0x1BU };
static const uint8_t X509_OID_ISSUING_DISTRIBUTION_POINT[X509_OID_ISSUING_DISTRIBUTION_POINT_LEN] = { 0x55U, 0x1DU, 0x1CU };
static const uint8_t X509_OID_REASON_CODE[X509_OID_REASON_CODE_LEN] = { 0x55U, 0x1DU, 0x15U };

static bool x509_revext_oid_equal(const qsc_asn1_oid* oid, const uint8_t* data, size_t datalen)
{
    bool res;

    res = false;

    if (oid != (const qsc_asn1_oid*)NULL && data != (const uint8_t*)NULL)
    {
        if (oid->length == datalen && qsc_intutils_are_equal8(oid->data, data, datalen) == true)
        {
            res = true;
        }
    }

    return res;
}

static qsc_asn1_status x509_revext_copy_unsigned_integer(const qsc_encoding_ber_element* element, uint8_t* output, size_t otplen, size_t* outlen)
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
                        qsc_memutils_secure_erase(output, otplen);
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

static qsc_asn1_status x509_revext_decode_revoked_entry(const qsc_encoding_ber_element* element, qsc_x509_crl_entry* entry)
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
            status = x509_revext_copy_unsigned_integer(child, entry->serialnumber, sizeof(entry->serialnumber), &entry->serialnumberlen);
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
    }

    return status;
}

static qsc_asn1_status x509_revext_decode_der_root(const uint8_t* der, size_t derlen, qsc_encoding_ber_element** root)
{
    qsc_asn1_status status;
    size_t consumed;

    status = QSC_ASN1_STATUS_FAILURE;
    consumed = 0U;

    if (der == (const uint8_t*)NULL || root == (qsc_encoding_ber_element**)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        *root = qsc_encoding_der_decode_element(der, derlen, &consumed);

        if (*root == (qsc_encoding_ber_element*)NULL)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if (consumed != derlen)
        {
            qsc_encoding_ber_free_element(*root);
            *root = (qsc_encoding_ber_element*)NULL;
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
        else
        {
            status = qsc_asn1_require_sequence(*root, 3U, 3U);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                qsc_encoding_ber_free_element(*root);
                *root = (qsc_encoding_ber_element*)NULL;
            }
        }
    }

    return status;
}

static qsc_asn1_status x509_revext_get_tbs_components(const qsc_x509_crl* crl, qsc_encoding_ber_element** root, const qsc_encoding_ber_element** tbs, 
    const qsc_encoding_ber_element** revokedseq, const qsc_encoding_ber_element** extseq)
{
    qsc_asn1_status status;
    const qsc_encoding_ber_element* child;
    size_t idx;

    status = QSC_ASN1_STATUS_FAILURE;
    child = (const qsc_encoding_ber_element*)NULL;
    idx = 0U;

    if (root == (qsc_encoding_ber_element**)NULL || tbs == (const qsc_encoding_ber_element**)NULL ||
        revokedseq == (const qsc_encoding_ber_element**)NULL || extseq == (const qsc_encoding_ber_element**)NULL ||
        crl == (const qsc_x509_crl*)NULL || crl->der == (const uint8_t*)NULL || crl->derlen == 0U)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        *root = (qsc_encoding_ber_element*)NULL;
        *tbs = (const qsc_encoding_ber_element*)NULL;
        *revokedseq = (const qsc_encoding_ber_element*)NULL;
        *extseq = (const qsc_encoding_ber_element*)NULL;
        status = x509_revext_decode_der_root(crl->der, crl->derlen, root);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            *tbs = qsc_asn1_get_child(*root, 0U);

            if (*tbs == (const qsc_encoding_ber_element*)NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                status = qsc_asn1_require_sequence(*tbs, 3U, 7U);
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(*tbs, idx);

            if (child != (const qsc_encoding_ber_element*)NULL && qsc_asn1_is_integer(child) == true)
            {
                idx += 1U;
            }

            idx += 1U; /* signature */
            idx += 1U; /* issuer */
            idx += 1U; /* thisUpdate */

            child = qsc_asn1_get_child(*tbs, idx);

            if (child != (const qsc_encoding_ber_element*)NULL)
            {
                if ((child->tagclass == QSC_ENCODING_BER_CLASS_UNIVERSAL) &&
                    (child->tagnumber == BER_ASN1_UTCTIME || child->tagnumber == BER_ASN1_GENERALIZEDTIME))
                {
                    idx += 1U;
                }
            }

            child = qsc_asn1_get_child(*tbs, idx);

            if (child != (const qsc_encoding_ber_element*)NULL &&
                child->tagclass == QSC_ENCODING_BER_CLASS_UNIVERSAL && child->constructed == true && child->tagnumber == BER_ASN1_SEQUENCE)
            {
                *revokedseq = child;
                idx += 1U;
            }

            child = qsc_asn1_get_child(*tbs, idx);

            if (child != (const qsc_encoding_ber_element*)NULL && child->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC &&
                child->tagnumber == 0U && child->constructed == true)
            {
                status = qsc_asn1_get_explicit_child(child, extseq);
            }
            else
            {
                status = QSC_ASN1_STATUS_SUCCESS;
            }
        }

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            if (*root != (qsc_encoding_ber_element*)NULL)
            {
                qsc_encoding_ber_free_element(*root);
                *root = (qsc_encoding_ber_element*)NULL;
            }

            *tbs = (const qsc_encoding_ber_element*)NULL;
            *revokedseq = (const qsc_encoding_ber_element*)NULL;
            *extseq = (const qsc_encoding_ber_element*)NULL;
        }
    }

    return status;
}

static qsc_asn1_status x509_revext_decode_small_integer(const uint8_t* der, size_t derlen, uint64_t* value, uint32_t expectedtag)
{
    qsc_asn1_status status;
    qsc_encoding_ber_element* root;
    size_t consumed;
    uint64_t acc;

    status = QSC_ASN1_STATUS_FAILURE;
    root = (qsc_encoding_ber_element*)NULL;
    consumed = 0U;
    acc = 0U;

    if (der == (const uint8_t*)NULL || value == (uint64_t*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        root = qsc_encoding_der_decode_element(der, derlen, &consumed);

        if (root == (qsc_encoding_ber_element*)NULL)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if (consumed != derlen)
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
        else
        {
            status = qsc_asn1_require_tag(root, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, expectedtag);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (root->length == 0U || root->value == (uint8_t*)NULL || root->length > sizeof(uint64_t))
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else if ((root->value[0U] & 0x80U) != 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                for (size_t i = 0U; i < root->length; ++i)
                {
                    acc = (acc << 8) | root->value[i];
                }

                *value = acc;
                status = QSC_ASN1_STATUS_SUCCESS;
            }
        }

        if (root != (qsc_encoding_ber_element*)NULL)
        {
            qsc_encoding_ber_free_element(root);
        }
    }

    return status;
}

static qsc_asn1_status x509_revext_parse_crl_metadata(const qsc_x509_crl* crl, bool* iscrl, bool* isdelta, uint64_t* crlnumber, uint64_t* basecrlnumber,
    uint8_t* idpbuf, size_t idpbufcap, size_t* idpvaluelen, bool* hasentryextensions)
{
    qsc_x509_extension ext = { 0 };
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* tbs;
    const qsc_encoding_ber_element* revokedseq;
    const qsc_encoding_ber_element* extseq;
    const qsc_encoding_ber_element* entry;
    const qsc_encoding_ber_element* entryext;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    root = (qsc_encoding_ber_element*)NULL;
    tbs = (const qsc_encoding_ber_element*)NULL;
    revokedseq = (const qsc_encoding_ber_element*)NULL;
    extseq = (const qsc_encoding_ber_element*)NULL;

    if (crl == (const qsc_x509_crl*)NULL || iscrl == (bool*)NULL || isdelta == (bool*)NULL ||
        crlnumber == (uint64_t*)NULL || basecrlnumber == (uint64_t*)NULL ||
        idpbuf == (uint8_t*)NULL || idpvaluelen == (size_t*)NULL || hasentryextensions == (bool*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        *iscrl = false;
        *isdelta = false;
        *crlnumber = 0U;
        *basecrlnumber = 0U;
        /* idpbuf is caller-supplied; zero the length indicator */
        *idpvaluelen = 0U;
        *hasentryextensions = false;
        status = x509_revext_get_tbs_components(crl, &root, &tbs, &revokedseq, &extseq);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            *iscrl = true;

            if (revokedseq != (const qsc_encoding_ber_element*)NULL)
            {
                for (size_t i = 0U; i < revokedseq->ccount; ++i)
                {
                    entry = revokedseq->children[i];

                    if (entry == (const qsc_encoding_ber_element*)NULL)
                    {
                        status = QSC_ASN1_STATUS_NOT_FOUND;
                        break;
                    }

                    status = qsc_asn1_require_sequence(entry, 2U, 3U);

                    if (status != QSC_ASN1_STATUS_SUCCESS)
                    {
                        break;
                    }

                    if (entry->ccount == 3U)
                    {
                        entryext = qsc_asn1_get_child(entry, 2U);

                        if (entryext == (const qsc_encoding_ber_element*)NULL)
                        {
                            status = QSC_ASN1_STATUS_NOT_FOUND;
                            break;
                        }

                        *hasentryextensions = true;
                    }
                }
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS && extseq != (const qsc_encoding_ber_element*)NULL)
        {
            status = qsc_asn1_require_sequence(extseq, 1U, QSC_X509_EXTENSIONS_MAX);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS && extseq != (const qsc_encoding_ber_element*)NULL)
        {
            for (size_t i = 0U; i < extseq->ccount; ++i)
            {
                qsc_memutils_clear((uint8_t*)&ext, sizeof(qsc_x509_extension));
                status = qsc_x509_extension_decode(extseq->children[i], &ext);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    break;
                }

                if (x509_revext_oid_equal(&ext.extension_oid, X509_OID_CRL_NUMBER, sizeof(X509_OID_CRL_NUMBER)) == true)
                {
                    status = x509_revext_decode_small_integer(ext.value, ext.valuelen, crlnumber, BER_ASN1_INTEGER);
                }
                else if (x509_revext_oid_equal(&ext.extension_oid, X509_OID_DELTA_CRL_INDICATOR, sizeof(X509_OID_DELTA_CRL_INDICATOR)) == true)
                {
                    if (ext.critical == false)
                    {
                        status = QSC_ASN1_STATUS_INVALID_ENCODING;
                    }
                    else
                    {
                        status = x509_revext_decode_small_integer(ext.value, ext.valuelen, basecrlnumber, BER_ASN1_INTEGER);

                        if (status == QSC_ASN1_STATUS_SUCCESS)
                        {
                            *isdelta = true;
                        }
                    }
                }
                else if (x509_revext_oid_equal(&ext.extension_oid, X509_OID_ISSUING_DISTRIBUTION_POINT, sizeof(X509_OID_ISSUING_DISTRIBUTION_POINT)) == true)
                {
                    if (ext.valuelen > idpbufcap)
                    {
                        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                    }
                    else
                    {
                        qsc_memutils_copy(idpbuf, ext.value, ext.valuelen);
                        *idpvaluelen = ext.valuelen;
                        status = QSC_ASN1_STATUS_SUCCESS;
                    }
                }

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    break;
                }
            }
        }

        if (root != (qsc_encoding_ber_element*)NULL)
        {
            qsc_encoding_ber_free_element(root);
        }
    }

    return status;
}

static qsc_asn1_status x509_revext_get_delta_reason_code(const qsc_encoding_ber_element* extensions, uint64_t* reasoncode)
{
    qsc_x509_extension ext = { 0 };
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_SUCCESS;

    if (extensions == (const qsc_encoding_ber_element*)NULL || reasoncode == (uint64_t*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        *reasoncode = 0U;
        status = qsc_asn1_require_sequence(extensions, 1U, QSC_X509_EXTENSIONS_MAX);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            for (size_t i = 0U; i < extensions->ccount; ++i)
            {
                qsc_memutils_clear((uint8_t*)&ext, sizeof(qsc_x509_extension));
                status = qsc_x509_extension_decode(extensions->children[i], &ext);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    break;
                }

                if (x509_revext_oid_equal(&ext.extension_oid, X509_OID_REASON_CODE, sizeof(X509_OID_REASON_CODE)) == true)
                {
                    status = x509_revext_decode_small_integer(ext.value, ext.valuelen, reasoncode, X509_ASN1_TAG_ENUMERATED);
                    break;
                }
            }
        }
    }

    return status;
}

static bool x509_revext_serial_equal(const qsc_x509_crl_entry* a, const qsc_x509_crl_entry* b)
{
    bool res;

    res = false;

    if (a != (const qsc_x509_crl_entry*)NULL && b != (const qsc_x509_crl_entry*)NULL)
    {
        if (a->serialnumberlen == b->serialnumberlen &&
            qsc_intutils_are_equal8(a->serialnumber, b->serialnumber, a->serialnumberlen) == true)
        {
            res = true;
        }
    }

    return res;
}

static size_t x509_revext_find_output_entry(const qsc_x509_crl* crl, const qsc_x509_crl_entry* needle)
{
    size_t idx;

    idx = QSC_X509_CRL_REVOKED_MAX;

    if (crl != (const qsc_x509_crl*)NULL && needle != (const qsc_x509_crl_entry*)NULL)
    {
        for (size_t i = 0U; i < crl->revokedcount; ++i)
        {
            if (x509_revext_serial_equal(&crl->revoked[i], needle) == true)
            {
                idx = i;
                break;
            }
        }
    }

    return idx;
}

static void x509_revext_remove_output_index(qsc_x509_crl* crl, size_t idx)
{
    if (crl != (qsc_x509_crl*)NULL && idx < crl->revokedcount)
    {
        for (size_t i = idx + 1U; i < crl->revokedcount; ++i)
        {
            crl->revoked[i - 1U] = crl->revoked[i];
        }

        qsc_memutils_secure_erase((uint8_t*)&crl->revoked[crl->revokedcount - 1U], sizeof(qsc_x509_crl_entry));
        crl->revokedcount -= 1U;
    }
}

static qsc_x509_crl_verify_status x509_revext_merge_delta_entries(qsc_x509_crl* mergedcrl, const qsc_x509_crl* deltacrl)
{
    qsc_x509_crl_entry parsed = { 0 };
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* tbs;
    const qsc_encoding_ber_element* revokedseq;
    const qsc_encoding_ber_element* extseq;
    const qsc_encoding_ber_element* entry;
    const qsc_encoding_ber_element* entryext;
    qsc_x509_crl_verify_status status;
    uint64_t reasoncode;
    size_t idx;

    status = QSC_X509_CRL_VERIFY_STATUS_SUCCESS;
    root = (qsc_encoding_ber_element*)NULL;
    tbs = (const qsc_encoding_ber_element*)NULL;
    revokedseq = (const qsc_encoding_ber_element*)NULL;
    extseq = (const qsc_encoding_ber_element*)NULL;
    reasoncode = 0U;

    if (mergedcrl == (qsc_x509_crl*)NULL || deltacrl == (const qsc_x509_crl*)NULL)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;
    }
    else
    {
        if (x509_revext_get_tbs_components(deltacrl, &root, &tbs, &revokedseq, &extseq) != QSC_ASN1_STATUS_SUCCESS)
        {
            status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
        }
        else if (revokedseq != (const qsc_encoding_ber_element*)NULL)
        {
            for (size_t i = 0U; i < revokedseq->ccount; ++i)
            {
                entry = revokedseq->children[i];
                qsc_memutils_clear((uint8_t*)&parsed, sizeof(qsc_x509_crl_entry));

                if (entry == (const qsc_encoding_ber_element*)NULL)
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                    break;
                }

                if (qsc_asn1_require_sequence(entry, 2U, 3U) != QSC_ASN1_STATUS_SUCCESS)
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                    break;
                }

                if (x509_revext_decode_revoked_entry(entry, &parsed) != QSC_ASN1_STATUS_SUCCESS)
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                    break;
                }

                reasoncode = 0U;

                if (entry->ccount == 3U)
                {
                    entryext = qsc_asn1_get_child(entry, 2U);

                    if (entryext == (const qsc_encoding_ber_element*)NULL)
                    {
                        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                        break;
                    }

                    if (x509_revext_get_delta_reason_code(entryext, &reasoncode) != QSC_ASN1_STATUS_SUCCESS)
                    {
                        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                        break;
                    }
                }

                idx = x509_revext_find_output_entry(mergedcrl, &parsed);

                if (reasoncode == 8U)
                {
                    if (idx < mergedcrl->revokedcount)
                    {
                        x509_revext_remove_output_index(mergedcrl, idx);
                    }
                }
                else
                {
                    if (idx < mergedcrl->revokedcount)
                    {
                        mergedcrl->revoked[idx] = parsed;
                    }
                    else if (mergedcrl->revokedcount < QSC_X509_CRL_REVOKED_MAX)
                    {
                        mergedcrl->revoked[mergedcrl->revokedcount] = parsed;
                        mergedcrl->revokedcount += 1U;
                    }
                    else
                    {
                        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                        break;
                    }
                }
            }
        }

        if (root != (qsc_encoding_ber_element*)NULL)
        {
            qsc_encoding_ber_free_element(root);
        }
    }

    return status;
}

static qsc_x509_crl_verify_status x509_revext_copy_crl_backing(qsc_x509_crl* destination, const qsc_x509_crl* source)
{
    uint8_t* dercopy;
    ptrdiff_t tbsoffset;
    qsc_x509_crl_verify_status status;

    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
    dercopy = (uint8_t*)NULL;
    tbsoffset = 0;

    if (destination == (qsc_x509_crl*)NULL || source == (const qsc_x509_crl*)NULL ||
        source->der == (const uint8_t*)NULL || source->derlen == 0U ||
        source->tbsdata == (const uint8_t*)NULL || source->tbsdatalen == 0U)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;
    }
    else
    {
        tbsoffset = (ptrdiff_t)(source->tbsdata - source->der);

        if (tbsoffset < 0 || (size_t)tbsoffset >= source->derlen || source->tbsdatalen > (source->derlen - (size_t)tbsoffset))
        {
            status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
        }
        else
        {
            dercopy = (uint8_t*)qsc_memutils_malloc(source->derlen);

            if (dercopy != (uint8_t*)NULL)
            {
                qsc_memutils_copy(dercopy, source->der, source->derlen);
                destination->der = dercopy;
                destination->derlen = source->derlen;
                destination->tbsdata = dercopy + (size_t)tbsoffset;
                destination->tbsdatalen = source->tbsdatalen;
                status = QSC_X509_CRL_VERIFY_STATUS_SUCCESS;
            }
        }
    }

    return status;
}

static bool x509_revext_current_utc_time(qsc_asn1_time* now)
{
    time_t tnow;
    struct tm tmv;

    if (now == (qsc_asn1_time*)NULL)
    {
        return false;
    }

    tnow = time((time_t*)NULL);

    if (tnow == (time_t)-1)
    {
        return false;
    }

#if defined(_WIN32)
    if (gmtime_s(&tmv, &tnow) != 0)
    {
        return false;
    }
#else
    if (gmtime_r(&tnow, &tmv) == (struct tm*)NULL)
    {
        return false;
    }
#endif

    now->year = (uint16_t)(tmv.tm_year + 1900);
    now->month = (uint8_t)(tmv.tm_mon + 1);
    now->day = (uint8_t)tmv.tm_mday;
    now->hour = (uint8_t)tmv.tm_hour;
    now->minute = (uint8_t)tmv.tm_min;
    now->second = (uint8_t)tmv.tm_sec;
    now->generalized = true;

    return true;
}

static void x509_revext_sha1_compute(uint8_t* output, const uint8_t* message, size_t msglen)
{
    static const uint32_t iv[5U] = { 0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL };
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

    qsc_memutils_secure_erase((uint8_t*)w, sizeof(w));
    qsc_memutils_secure_erase((uint8_t*)block, sizeof(block));
}

static bool x509_revext_hash_octets(const qsc_asn1_oid* hashoid, const uint8_t* data, size_t datalen, uint8_t* output, size_t* outputlen)
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
                x509_revext_sha1_compute(output, data, datalen);
                *outputlen = 20U;
                res = true;
                break;
            }
            case QSC_OID_ID_SHA256:
            {
                qsc_sha256_compute(output, data, datalen);
                *outputlen = 32U;
                res = true;
                break;
            }
            case QSC_OID_ID_SHA384:
            {
                qsc_sha384_compute(output, data, datalen);
                *outputlen = 48U;
                res = true;
                break;
            }
            case QSC_OID_ID_SHA512:
            {
                qsc_sha512_compute(output, data, datalen);
                *outputlen = 64U;
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

static bool x509_revext_copy_positive_integer(const qsc_encoding_ber_element* element, uint8_t* output, size_t otplen, size_t* outlen)
{
    return (x509_revext_copy_unsigned_integer(element, output, otplen, outlen) == QSC_ASN1_STATUS_SUCCESS);
}

static bool x509_revext_serial_bytes_equal(const uint8_t* left, size_t leftlen, const uint8_t* right, size_t rightlen)
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

    return ((leftlen - lofs) == (rightlen - rofs)) && qsc_intutils_are_equal8(left + lofs, right + rofs, leftlen - lofs);
}

static bool x509_revext_extract_cert_name_der(const qsc_x509_certificate* certificate, bool subject, uint8_t* output, size_t otplen, size_t* outlen)
{
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* tbs;
    const qsc_encoding_ber_element* child;
    size_t idx;
    size_t consumed;
    bool res;

    root = (qsc_encoding_ber_element*)NULL;
    tbs = (const qsc_encoding_ber_element*)NULL;
    child = (const qsc_encoding_ber_element*)NULL;
    idx = 0U;
    consumed = 0U;
    res = false;

    if (outlen != (size_t*)NULL)
    {
        *outlen = 0U;
    }

    if (certificate == (const qsc_x509_certificate*)NULL || certificate->der == (const uint8_t*)NULL || output == (uint8_t*)NULL || outlen == (size_t*)NULL)
    {
        return false;
    }

    root = qsc_encoding_der_decode_element(certificate->der, certificate->derlen, &consumed);

    if (root != (qsc_encoding_ber_element*)NULL && consumed == certificate->derlen && qsc_asn1_require_sequence(root, 3U, 3U) == QSC_ASN1_STATUS_SUCCESS)
    {
        tbs = qsc_asn1_get_child(root, 0U);

        if (tbs != (const qsc_encoding_ber_element*)NULL && qsc_asn1_require_sequence(tbs, 6U, 10U) == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(tbs, 0U);

            if (child != (const qsc_encoding_ber_element*)NULL && qsc_asn1_element_is_tag(child, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 0U) == true)
            {
                idx = 1U;
            }

            idx += 2U; /* serial, signature */
            if (subject == true)
            {
                idx += 2U; /* issuer, validity */
            }

            child = qsc_asn1_get_child(tbs, idx);

            if (child != (const qsc_encoding_ber_element*)NULL)
            {
                *outlen = qsc_encoding_der_encode_element((qsc_encoding_ber_element*)child, output, otplen);
                res = (*outlen != 0U);
            }
        }
    }

    if (root != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(root);
    }

    return res;
}

static bool x509_revext_ocsp_get_basic_response_octets(const uint8_t* der, size_t derlen, const uint8_t** octets, size_t* octetlen)
{
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* child;
    const qsc_encoding_ber_element* rb;
    const qsc_encoding_ber_element* rtype;
    const qsc_encoding_ber_element* rocts;
    const uint8_t* octetregion;
    const uint8_t* responsebytes;
    const uint8_t* responsectx;
    size_t consumed;
    size_t octetheaderlen;
    size_t octetregionlen;
    size_t responsebyteslen;
    size_t responsectxlen;
    uint64_t response_status;
    qsc_asn1_oid oid;
    qsc_asn1_status status;
    bool res;

    root = (qsc_encoding_ber_element*)NULL;
    child = (const qsc_encoding_ber_element*)NULL;
    rb = (const qsc_encoding_ber_element*)NULL;
    rtype = (const qsc_encoding_ber_element*)NULL;
    rocts = (const qsc_encoding_ber_element*)NULL;
    octetregion = (const uint8_t*)NULL;
    responsebytes = (const uint8_t*)NULL;
    responsectx = (const uint8_t*)NULL;
    consumed = 0U;
    octetheaderlen = 0U;
    octetregionlen = 0U;
    responsebyteslen = 0U;
    responsectxlen = 0U;
    response_status = 0U;
    status = QSC_ASN1_STATUS_INVALID_ENCODING;
    res = false;
    *octets = (const uint8_t*)NULL;
    *octetlen = 0U;

    root = qsc_encoding_der_decode_element(der, derlen, &consumed);

    if (root != (qsc_encoding_ber_element*)NULL && consumed == derlen && qsc_asn1_require_sequence(root, 1U, 2U) == QSC_ASN1_STATUS_SUCCESS)
    {
        child = qsc_asn1_get_child(root, 0U);

        if (child != (const qsc_encoding_ber_element*)NULL &&
            qsc_asn1_require_tag(child, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, X509_ASN1_TAG_ENUMERATED) == QSC_ASN1_STATUS_SUCCESS &&
            child->length == 1U && child->value != (uint8_t*)NULL)
        {
            response_status = child->value[0U];
        }

        if (response_status == 0U && qsc_asn1_child_count(root) == 2U)
        {
            child = qsc_asn1_get_child(root, 1U);

            if (qsc_asn1_get_explicit_child(child, &rb) == QSC_ASN1_STATUS_SUCCESS && qsc_asn1_require_sequence(rb, 2U, 2U) == QSC_ASN1_STATUS_SUCCESS)
            {
                rtype = qsc_asn1_get_child(rb, 0U);
                rocts = qsc_asn1_get_child(rb, 1U);

                if (rtype != (const qsc_encoding_ber_element*)NULL && rocts != (const qsc_encoding_ber_element*)NULL &&
                    qsc_asn1_decode_oid(rtype, &oid) == QSC_ASN1_STATUS_SUCCESS &&
                    rocts->tagclass == QSC_ENCODING_BER_CLASS_UNIVERSAL && rocts->tagnumber == BER_ASN1_OCTET_STRING &&
                    oid.length == 9U && oid.data[0U] == 0x2BU && oid.data[1U] == 0x06U && oid.data[2U] == 0x01U && oid.data[3U] == 0x05U &&
                    oid.data[4U] == 0x05U && oid.data[5U] == 0x07U && oid.data[6U] == 0x30U && oid.data[7U] == 0x01U && oid.data[8U] == 0x01U)
                {
                    status = qsc_asn1_der_get_child_region(der, derlen, 1U, &responsectx, &responsectxlen);

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        status = qsc_asn1_der_get_child_region(responsectx, responsectxlen, 0U, &responsebytes, &responsebyteslen);
                    }

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        status = qsc_asn1_der_get_child_region(responsebytes, responsebyteslen, 1U, &octetregion, &octetregionlen);
                    }

                    if (status == QSC_ASN1_STATUS_SUCCESS && octetregion != (const uint8_t*)NULL &&
                        rocts->length != 0U && octetregionlen > rocts->length)
                    {
                        octetheaderlen = octetregionlen - rocts->length;

                        if (octetheaderlen != 0U && octetheaderlen <= octetregionlen)
                        {
                            *octets = octetregion + octetheaderlen;
                            *octetlen = rocts->length;
                            res = true;
                        }
                    }
                }
            }
        }
    }

    if (root != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(root);
    }

    return res;
}

static bool x509_revext_ocsp_extensions_are_acceptable(const qsc_encoding_ber_element* extensions)
{
    qsc_x509_extension extension = { 0 };
    size_t i;
    bool res;

    res = false;

    if (extensions != (const qsc_encoding_ber_element*)NULL && qsc_asn1_require_sequence(extensions, 1U, SIZE_MAX) == QSC_ASN1_STATUS_SUCCESS)
    {
        res = true;

        for (i = 0U; i < extensions->ccount; ++i)
        {
            qsc_memutils_clear((uint8_t*)&extension, sizeof(qsc_x509_extension));

            if (qsc_x509_extension_decode(extensions->children[i], &extension) != QSC_ASN1_STATUS_SUCCESS || extension.critical == true)
            {
                res = false;
                break;
            }
        }
    }

    return res;
}

static bool x509_revext_ocsp_match_responder_id(const qsc_encoding_ber_element* responsedata, const qsc_x509_certificate* responder)
{
    const qsc_encoding_ber_element* responderid;
    const qsc_encoding_ber_element* ridchild;
    uint8_t expected[1024U] = { 0U };
    uint8_t actual[1024U] = { 0U };
    uint8_t keyhash[20U] = { 0U };
    size_t idx;
    size_t expectedlen;
    size_t actuallen;
    bool res;

    responderid = (const qsc_encoding_ber_element*)NULL;
    ridchild = (const qsc_encoding_ber_element*)NULL;
    idx = 0U;
    expectedlen = 0U;
    actuallen = 0U;
    res = false;

    if (responsedata != (const qsc_encoding_ber_element*)NULL && responder != (const qsc_x509_certificate*)NULL)
    {
        if (qsc_asn1_child_count(responsedata) >= 1U)
        {
            const qsc_encoding_ber_element* first;

            first = qsc_asn1_get_child(responsedata, 0U);

            if (first != (const qsc_encoding_ber_element*)NULL &&
                first->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC && first->tagnumber == 0U)
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

                    if (actuallen != 0U && x509_revext_extract_cert_name_der(responder, true, expected, sizeof(expected), &expectedlen) == true)
                    {
                        res = (expectedlen == actuallen) && qsc_intutils_are_equal8(expected, actual, expectedlen);
                    }
                }
            }
            else if (responderid->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC && responderid->tagnumber == 2U)
            {
                if (qsc_asn1_get_explicit_child(responderid, &ridchild) == QSC_ASN1_STATUS_SUCCESS &&
                    qsc_asn1_require_tag(ridchild, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OCTET_STRING) == QSC_ASN1_STATUS_SUCCESS)
                {
                    x509_revext_sha1_compute(keyhash, responder->subjectpublickeyinfo.publickey, responder->subjectpublickeyinfo.publickeylen);
                    res = (ridchild->length == sizeof(keyhash)) && qsc_intutils_are_equal8(ridchild->value, keyhash, sizeof(keyhash));
                }
            }
        }
    }

    return res;
}

static bool x509_revext_ocsp_extract_basic_signature(const uint8_t* basicder, size_t basiclen, const uint8_t** tbsdata, size_t* tbsdatalen,
    qsc_x509_algorithm_identifier* sigalg, const uint8_t** sigdata, size_t* siglen, uint8_t* sigunused, qsc_x509_certificate* responder)
{
    qsc_asn1_bit_string sig = { 0 };
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* certsctx;
    const qsc_encoding_ber_element* certseq;
    const uint8_t* certregion;
    const uint8_t* certseqregion;
    const uint8_t* certsregion;
    const uint8_t* sigregion;
    const uint8_t* tbsslice;
    size_t certregionlen;
    size_t certseqregionlen;
    size_t certsregionlen;
    size_t consumed;
    size_t sigheaderlen;
    size_t sigregionlen;
    size_t tbsslicelen;
    qsc_asn1_status status;
    bool res;

    root = (qsc_encoding_ber_element*)NULL;
    certsctx = (const qsc_encoding_ber_element*)NULL;
    certseq = (const qsc_encoding_ber_element*)NULL;
    certregion = (const uint8_t*)NULL;
    certseqregion = (const uint8_t*)NULL;
    certsregion = (const uint8_t*)NULL;
    sigregion = (const uint8_t*)NULL;
    tbsslice = (const uint8_t*)NULL;
    certregionlen = 0U;
    certseqregionlen = 0U;
    certsregionlen = 0U;
    consumed = 0U;
    sigheaderlen = 0U;
    sigregionlen = 0U;
    tbsslicelen = 0U;
    status = QSC_ASN1_STATUS_INVALID_ENCODING;
    res = false;
    *tbsdata = (const uint8_t*)NULL;
    *tbsdatalen = 0U;
    *sigdata = (const uint8_t*)NULL;
    *siglen = 0U;
    *sigunused = 0U;
    qsc_memutils_clear((uint8_t*)sigalg, sizeof(qsc_x509_algorithm_identifier));
    qsc_memutils_clear((uint8_t*)responder, sizeof(qsc_x509_certificate));

    root = qsc_encoding_der_decode_element(basicder, basiclen, &consumed);

    if (root != (qsc_encoding_ber_element*)NULL && consumed == basiclen && qsc_asn1_require_sequence(root, 3U, 4U) == QSC_ASN1_STATUS_SUCCESS)
    {
        status = qsc_asn1_der_get_child_region(basicder, basiclen, 0U, &tbsslice, &tbsslicelen);

        if (status == QSC_ASN1_STATUS_SUCCESS && tbsslice != (const uint8_t*)NULL && tbsslicelen != 0U && tbsslicelen <= basiclen)
        {
            *tbsdata = tbsslice;
            *tbsdatalen = tbsslicelen;
        }
        else
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_x509_signature_algorithm_decode(qsc_asn1_get_child(root, 1U), sigalg);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_asn1_decode_bit_string(qsc_asn1_get_child(root, 2U), &sig);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_asn1_der_get_child_region(basicder, basiclen, 2U, &sigregion, &sigregionlen);

            if (status == QSC_ASN1_STATUS_SUCCESS && sigregion != (const uint8_t*)NULL && sig.length < sigregionlen)
            {
                sigheaderlen = sigregionlen - sig.length - 1U;

                if (sigheaderlen < sigregionlen && sigregion[sigheaderlen] == sig.unused)
                {
                    *sigdata = sigregion + sigheaderlen + 1U;
                    *siglen = sig.length;
                    *sigunused = sig.unused;
                    res = true;
                }
                else
                {
                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                }
            }
        }

        if (res == true)
        {
            certsctx = qsc_asn1_find_context_child(root, 0U);

            if (certsctx != (const qsc_encoding_ber_element*)NULL && qsc_asn1_get_explicit_child(certsctx, &certseq) == QSC_ASN1_STATUS_SUCCESS &&
                qsc_asn1_require_sequence(certseq, 1U, SIZE_MAX) == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_asn1_der_get_child_region(basicder, basiclen, 3U, &certsregion, &certsregionlen);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = qsc_asn1_der_get_child_region(certsregion, certsregionlen, 0U, &certseqregion, &certseqregionlen);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    const qsc_encoding_ber_element* responsedata;
                    qsc_x509_certificate* candidate;
                    size_t i;
                    bool found;

                    found = false;
                    candidate = qsc_memutils_malloc(sizeof(qsc_x509_certificate));

                    if (candidate != NULL)
                    {
                        qsc_memutils_clear(candidate, sizeof(qsc_x509_certificate));
                        responsedata = qsc_asn1_get_child(root, 0U);

                        for (i = 0U; i < certseq->ccount && found == false; ++i)
                        {
                            certregion = (const uint8_t*)NULL;
                            certregionlen = 0U;
                            status = qsc_asn1_der_get_child_region(certseqregion, certseqregionlen, i, &certregion, &certregionlen);

                            if (status == QSC_ASN1_STATUS_SUCCESS)
                            {
                                qsc_memutils_clear((uint8_t*)candidate, sizeof(qsc_x509_certificate));
                                status = qsc_x509_certificate_decode_der(certregion, certregionlen, candidate);

                                if (status == QSC_ASN1_STATUS_SUCCESS && x509_revext_ocsp_match_responder_id(responsedata, candidate) == true)
                                {
                                    qsc_memutils_copy(responder, candidate, sizeof(qsc_x509_certificate));
                                    found = true;
                                }
                            }
                        }

                        qsc_memutils_secure_erase(candidate, sizeof(qsc_x509_certificate));
                        qsc_memutils_alloc_free(candidate);
                    }
                    else
                    {
                        status = QSC_ASN1_STATUS_FAILURE;
                    }

                    if (status == QSC_ASN1_STATUS_SUCCESS && found == false)
                    {
                        qsc_memutils_clear((uint8_t*)responder, sizeof(qsc_x509_certificate));
                    }
                }
            }
        }
    }

    if (root != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(root);
    }

    return res;
}

static bool x509_revext_ocsp_parse_single_response_for_cert(const qsc_encoding_ber_element* single, const qsc_x509_certificate* certificate,
    const qsc_x509_certificate* issuer, const qsc_asn1_time* now, bool* isgood)
{
    qsc_asn1_time nextupdate = { 0 };
    qsc_asn1_time revocationtime = { 0 };
    qsc_asn1_time thisupdate = { 0 };
    qsc_x509_algorithm_identifier hashalg = { 0 };
    const qsc_encoding_ber_element* algel;
    const qsc_encoding_ber_element* certid;
    const qsc_encoding_ber_element* child;
    const qsc_encoding_ber_element* extensions;
    const qsc_encoding_ber_element* keyhashel;
    const qsc_encoding_ber_element* namehashel;
    const qsc_encoding_ber_element* nextupdatectx;
    const qsc_encoding_ber_element* nextupdateel;
    const qsc_encoding_ber_element* reasonctx;
    const qsc_encoding_ber_element* reasonel;
    const qsc_encoding_ber_element* revtime;
    const qsc_encoding_ber_element* serialel;
    const qsc_encoding_ber_element* singleextensionsctx;
    const qsc_encoding_ber_element* statusel;
    const qsc_encoding_ber_element* thisupdateel;
    uint8_t name_der[1024U] = { 0U };
    uint8_t expected_name_hash[64U] = { 0U };
    uint8_t expected_key_hash[64U] = { 0U };
    uint8_t serial[QSC_X509_SERIAL_NUMBER_MAX] = { 0U };
    size_t childcount;
    size_t expected_key_hash_len;
    size_t expected_name_hash_len;
    size_t name_derlen;
    size_t seriallen;
    size_t statuscount;
    bool hasnext;
    bool matched;
    bool optionalvalid;
    bool res;
    bool statusvalid;

    algel = (const qsc_encoding_ber_element*)NULL;
    certid = (const qsc_encoding_ber_element*)NULL;
    child = (const qsc_encoding_ber_element*)NULL;
    extensions = (const qsc_encoding_ber_element*)NULL;
    keyhashel = (const qsc_encoding_ber_element*)NULL;
    namehashel = (const qsc_encoding_ber_element*)NULL;
    nextupdatectx = (const qsc_encoding_ber_element*)NULL;
    nextupdateel = (const qsc_encoding_ber_element*)NULL;
    reasonctx = (const qsc_encoding_ber_element*)NULL;
    reasonel = (const qsc_encoding_ber_element*)NULL;
    revtime = (const qsc_encoding_ber_element*)NULL;
    serialel = (const qsc_encoding_ber_element*)NULL;
    singleextensionsctx = (const qsc_encoding_ber_element*)NULL;
    statusel = (const qsc_encoding_ber_element*)NULL;
    thisupdateel = (const qsc_encoding_ber_element*)NULL;
    childcount = 0U;
    expected_key_hash_len = 0U;
    expected_name_hash_len = 0U;
    name_derlen = 0U;
    seriallen = 0U;
    statuscount = 0U;
    hasnext = false;
    matched = false;
    optionalvalid = true;
    res = false;
    statusvalid = false;

    if (isgood != (bool*)NULL)
    {
        *isgood = false;
    }

    if (single != (const qsc_encoding_ber_element*)NULL &&
        certificate != (const qsc_x509_certificate*)NULL &&
        issuer != (const qsc_x509_certificate*)NULL &&
        now != (const qsc_asn1_time*)NULL &&
        isgood != (bool*)NULL &&
        qsc_asn1_require_sequence(single, 3U, 5U) == QSC_ASN1_STATUS_SUCCESS)
    {
        childcount = qsc_asn1_child_count(single);
        certid = qsc_asn1_get_child(single, 0U);
        statusel = qsc_asn1_get_child(single, 1U);
        thisupdateel = qsc_asn1_get_child(single, 2U);

        if (certid != (const qsc_encoding_ber_element*)NULL &&
            statusel != (const qsc_encoding_ber_element*)NULL &&
            thisupdateel != (const qsc_encoding_ber_element*)NULL &&
            qsc_asn1_require_sequence(certid, 4U, 4U) == QSC_ASN1_STATUS_SUCCESS &&
            qsc_asn1_element_is_tag(thisupdateel, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_GENERALIZEDTIME) == true)
        {
            if (childcount >= 4U)
            {
                child = qsc_asn1_get_child(single, 3U);

                if (child != (const qsc_encoding_ber_element*)NULL)
                {
                    if (qsc_asn1_element_is_tag(child, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 0U) == true)
                    {
                        nextupdatectx = child;
                        hasnext = true;
                    }
                    else if (qsc_asn1_element_is_tag(child, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 1U) == true)
                    {
                        singleextensionsctx = child;
                    }
                    else
                    {
                        optionalvalid = false;
                    }
                }
                else
                {
                    optionalvalid = false;
                }
            }

            if (optionalvalid == true && childcount == 5U)
            {
                child = qsc_asn1_get_child(single, 4U);

                if (child == (const qsc_encoding_ber_element*)NULL ||
                    hasnext == false ||
                    singleextensionsctx != (const qsc_encoding_ber_element*)NULL ||
                    qsc_asn1_element_is_tag(child, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 1U) == false)
                {
                    optionalvalid = false;
                }
                else
                {
                    singleextensionsctx = child;
                }
            }

            if (optionalvalid == true && hasnext == true)
            {
                if (qsc_asn1_get_explicit_child(nextupdatectx, &nextupdateel) != QSC_ASN1_STATUS_SUCCESS ||
                    qsc_asn1_element_is_tag(nextupdateel, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_GENERALIZEDTIME) == false ||
                    qsc_asn1_decode_time(nextupdateel, &nextupdate) != QSC_ASN1_STATUS_SUCCESS)
                {
                    optionalvalid = false;
                }
            }

            if (optionalvalid == true &&
                singleextensionsctx != (const qsc_encoding_ber_element*)NULL)
            {
                if (qsc_asn1_get_explicit_child(singleextensionsctx, &extensions) != QSC_ASN1_STATUS_SUCCESS ||
                    x509_revext_ocsp_extensions_are_acceptable(extensions) == false)
                {
                    optionalvalid = false;
                }
            }

            /*
             * Validate CertStatus independently of nextUpdate.
             * GOOD and UNKNOWN are IMPLICIT NULL.
             * REVOKED is IMPLICIT RevokedInfo, so its children are direct
             * children of statusel.
             */
            if (optionalvalid == true)
            {
                if (qsc_asn1_element_is_tag(statusel, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 0U) == true &&
                    statusel->length == 0U)
                {
                    *isgood = true;
                    statusvalid = true;
                }
                else if (qsc_asn1_element_is_tag(statusel, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 2U) == true &&
                    statusel->length == 0U)
                {
                    *isgood = false;
                    statusvalid = true;
                }
                else if (qsc_asn1_element_is_tag(statusel, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 1U) == true)
                {
                    statuscount = qsc_asn1_child_count(statusel);

                    if (statuscount >= 1U && statuscount <= 2U)
                    {
                        revtime = qsc_asn1_get_child(statusel, 0U);

                        if (revtime != (const qsc_encoding_ber_element*)NULL &&
                            qsc_asn1_element_is_tag(revtime, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_GENERALIZEDTIME) == true &&
                            qsc_asn1_decode_time(revtime, &revocationtime) == QSC_ASN1_STATUS_SUCCESS)
                        {
                            statusvalid = true;
                            *isgood = false;

                            if (statuscount == 2U)
                            {
                                reasonctx = qsc_asn1_get_child(statusel, 1U);

                                if (reasonctx == (const qsc_encoding_ber_element*)NULL ||
                                    qsc_asn1_element_is_tag(reasonctx, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 0U) == false ||
                                    qsc_asn1_get_explicit_child(reasonctx, &reasonel) != QSC_ASN1_STATUS_SUCCESS ||
                                    qsc_asn1_require_tag(reasonel, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, X509_ASN1_TAG_ENUMERATED) != QSC_ASN1_STATUS_SUCCESS ||
                                    reasonel->length == 0U ||
                                    reasonel->value == (const uint8_t*)NULL || (reasonel->value[0U] & 0x80U) != 0U)
                                {
                                    statusvalid = false;
                                }
                            }
                        }
                    }
                }
            }

            if (optionalvalid == true && statusvalid == true)
            {
                algel = qsc_asn1_get_child(certid, 0U);
                namehashel = qsc_asn1_get_child(certid, 1U);
                keyhashel = qsc_asn1_get_child(certid, 2U);
                serialel = qsc_asn1_get_child(certid, 3U);

                if (algel != (const qsc_encoding_ber_element*)NULL &&
                    namehashel != (const qsc_encoding_ber_element*)NULL &&
                    keyhashel != (const qsc_encoding_ber_element*)NULL &&
                    serialel != (const qsc_encoding_ber_element*)NULL &&
                    qsc_x509_algorithm_identifier_decode(algel, &hashalg) == QSC_ASN1_STATUS_SUCCESS &&
                    namehashel->tagclass == QSC_ENCODING_BER_CLASS_UNIVERSAL &&
                    namehashel->tagnumber == BER_ASN1_OCTET_STRING &&
                    keyhashel->tagclass == QSC_ENCODING_BER_CLASS_UNIVERSAL &&
                    keyhashel->tagnumber == BER_ASN1_OCTET_STRING &&
                    x509_revext_copy_positive_integer(serialel, serial, sizeof(serial), &seriallen) == true &&
                    x509_revext_extract_cert_name_der(issuer, true, name_der, sizeof(name_der), &name_derlen) == true &&
                    x509_revext_hash_octets(&hashalg.algorithm_oid, name_der, name_derlen, expected_name_hash, &expected_name_hash_len) == true &&
                    x509_revext_hash_octets(&hashalg.algorithm_oid, issuer->subjectpublickeyinfo.publickey, issuer->subjectpublickeyinfo.publickeylen, expected_key_hash, &expected_key_hash_len) == true)
                {
                    matched = (expected_name_hash_len == namehashel->length) &&
                        qsc_intutils_are_equal8(expected_name_hash, namehashel->value, expected_name_hash_len) &&
                        (expected_key_hash_len == keyhashel->length) &&
                        qsc_intutils_are_equal8(expected_key_hash, keyhashel->value, expected_key_hash_len) &&
                        x509_revext_serial_bytes_equal(serial, seriallen, certificate->serialnumber, certificate->serialnumberlen);

                    if (matched == true &&
                        qsc_asn1_decode_time(thisupdateel, &thisupdate) == QSC_ASN1_STATUS_SUCCESS &&
                        qsc_asn1_time_compare(now, &thisupdate) >= 0 &&
                        (hasnext == false || qsc_asn1_time_compare(now, &nextupdate) <= 0))
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

static bool x509_revext_ocsp_response_matches_certificate(const uint8_t* basicder, size_t basiclen, const qsc_x509_certificate* certificate,
    const qsc_x509_certificate* issuer, const qsc_asn1_time* now, bool* isgood)
{
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* response_data;
    const qsc_encoding_ber_element* responses;
    const qsc_encoding_ber_element* child;
    size_t idx;
    size_t i;
    size_t consumed;
    bool res;
    bool good;

    root = (qsc_encoding_ber_element*)NULL;
    response_data = (const qsc_encoding_ber_element*)NULL;
    responses = (const qsc_encoding_ber_element*)NULL;
    child = (const qsc_encoding_ber_element*)NULL;
    idx = 0U;
    consumed = 0U;
    res = false;
    *isgood = false;

    root = qsc_encoding_der_decode_element(basicder, basiclen, &consumed);

    if (root != (qsc_encoding_ber_element*)NULL && consumed == basiclen && qsc_asn1_require_sequence(root, 3U, 4U) == QSC_ASN1_STATUS_SUCCESS)
    {
        response_data = qsc_asn1_get_child(root, 0U);

        if (response_data != (const qsc_encoding_ber_element*)NULL && qsc_asn1_require_sequence(response_data, 3U, 5U) == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(response_data, 0U);

            if (child != (const qsc_encoding_ber_element*)NULL &&
                qsc_asn1_element_is_tag(child, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 0U) == true)
            {
                idx = 1U;
            }

            idx += 2U; /* responderID, producedAt */
            responses = qsc_asn1_get_child(response_data, idx);

            if (responses != (const qsc_encoding_ber_element*)NULL && qsc_asn1_require_sequence(responses, 1U, SIZE_MAX) == QSC_ASN1_STATUS_SUCCESS)
            {
                const qsc_encoding_ber_element* responseextensionsctx;
                const qsc_encoding_ber_element* responseextensions;
                bool extensionsvalid;

                responseextensionsctx = qsc_asn1_get_child(response_data, idx + 1U);
                responseextensions = (const qsc_encoding_ber_element*)NULL;
                extensionsvalid = true;

                if (responseextensionsctx != (const qsc_encoding_ber_element*)NULL)
                {
                    if (qsc_asn1_element_is_tag(responseextensionsctx, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 1U) == false ||
                        qsc_asn1_get_explicit_child(responseextensionsctx, &responseextensions) != QSC_ASN1_STATUS_SUCCESS ||
                        x509_revext_ocsp_extensions_are_acceptable(responseextensions) == false)
                    {
                        extensionsvalid = false;
                    }
                }

                for (i = 0U; i < qsc_asn1_child_count(responses) && extensionsvalid == true; ++i)
                {
                    if (x509_revext_ocsp_parse_single_response_for_cert(qsc_asn1_get_child(responses, i), certificate, issuer, now, &good) == true)
                    {
                        *isgood = good;
                        res = true;
                        break;
                    }
                }
            }
        }
    }

    if (root != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(root);
    }

    return res;
}

static qsc_asn1_status x509_revext_decode_implicit_boolean(const qsc_encoding_ber_element* element, bool* value)
{
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != (const qsc_encoding_ber_element*)NULL && value != (bool*)NULL)
    {
        if (element->constructed == true || element->length != 1U || element->value == (const uint8_t*)NULL)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if (element->value[0U] == 0x00U)
        {
            *value = false;
            status = QSC_ASN1_STATUS_SUCCESS;
        }
        else if (element->value[0U] == 0xFFU)
        {
            *value = true;
            status = QSC_ASN1_STATUS_SUCCESS;
        }
        else
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }

    return status;
}

static qsc_x509_crl_verify_status x509_revext_check_idp_scope(const qsc_x509_extension* extension, const qsc_x509_certificate* certificate)
{
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* child;
    size_t consumed;
    size_t i;
    uint8_t seen;
    bool indirect;
    bool onlyattr;
    bool onlyca;
    bool onlyuser;
    qsc_asn1_status astatus;
    qsc_x509_crl_verify_status status;

    root = (qsc_encoding_ber_element*)NULL;
    consumed = 0U;
    seen = 0U;
    indirect = false;
    onlyattr = false;
    onlyca = false;
    onlyuser = false;
    astatus = QSC_ASN1_STATUS_FAILURE;
    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;

    if (extension == (const qsc_x509_extension*)NULL || certificate == (const qsc_x509_certificate*)NULL)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;
    }
    else if (extension->critical == false || extension->value == (const uint8_t*)NULL || extension->valuelen == 0U)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
    }
    else
    {
        root = qsc_encoding_der_decode_element(extension->value, extension->valuelen, &consumed);

        if (root == (qsc_encoding_ber_element*)NULL || consumed != extension->valuelen ||
            qsc_asn1_require_sequence(root, 1U, 6U) != QSC_ASN1_STATUS_SUCCESS)
        {
            status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
        }
        else
        {
            status = QSC_X509_CRL_VERIFY_STATUS_SUCCESS;

            for (i = 0U; i < root->ccount && status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS; ++i)
            {
                child = qsc_asn1_get_child(root, i);

                if (child == (const qsc_encoding_ber_element*)NULL || child->tagclass != QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC || child->tagnumber > 5U)
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                }
                else if ((seen & (uint8_t)(1U << child->tagnumber)) != 0U)
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                }
                else
                {
                    seen |= (uint8_t)(1U << child->tagnumber);

                    switch (child->tagnumber)
                    {
                        case 0U:
                        case 3U:
                        {
                            /* Named distribution points and reason-partitioned CRLs require the full
                             * RFC 5280 reasons-mask algorithm. They are intentionally fail-closed until
                             * that complete algorithm is enabled. */
                            status = QSC_X509_CRL_VERIFY_STATUS_UNSUPPORTED;
                            break;
                        }
                        case 1U:
                        {
                            astatus = x509_revext_decode_implicit_boolean(child, &onlyuser);
                            status = (astatus == QSC_ASN1_STATUS_SUCCESS) ? QSC_X509_CRL_VERIFY_STATUS_SUCCESS : QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                            break;
                        }
                        case 2U:
                        {
                            astatus = x509_revext_decode_implicit_boolean(child, &onlyca);
                            status = (astatus == QSC_ASN1_STATUS_SUCCESS) ? QSC_X509_CRL_VERIFY_STATUS_SUCCESS : QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                            break;
                        }
                        case 4U:
                        {
                            astatus = x509_revext_decode_implicit_boolean(child, &indirect);
                            status = (astatus == QSC_ASN1_STATUS_SUCCESS) ? QSC_X509_CRL_VERIFY_STATUS_SUCCESS : QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                            break;
                        }
                        case 5U:
                        {
                            astatus = x509_revext_decode_implicit_boolean(child, &onlyattr);
                            status = (astatus == QSC_ASN1_STATUS_SUCCESS) ? QSC_X509_CRL_VERIFY_STATUS_SUCCESS : QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                            break;
                        }
                        default:
                        {
                            status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                            break;
                        }
                    }
                }
            }

            if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
            {
                if ((onlyuser == true && onlyca == true) || (onlyuser == true && onlyattr == true) || (onlyca == true && onlyattr == true))
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
                }
                else if (indirect == true || onlyattr == true)
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_UNSUPPORTED;
                }
                else if (onlyuser == true && certificate->extensions.basicconstraints.present == true && certificate->extensions.basicconstraints.ca == true)
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_UNSUPPORTED;
                }
                else if (onlyca == true && (certificate->extensions.basicconstraints.present == false || certificate->extensions.basicconstraints.ca == false))
                {
                    status = QSC_X509_CRL_VERIFY_STATUS_UNSUPPORTED;
                }
            }
        }

        if (root != (qsc_encoding_ber_element*)NULL)
        {
            qsc_encoding_ber_free_element(root);
        }
    }

    return status;
}

qsc_x509_crl_verify_status qsc_x509_crl_check_certificate_scope(const qsc_x509_crl* crl, const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer)
{
    const qsc_x509_extension* extension;
    size_t i;
    qsc_x509_crl_verify_status status;

    extension = (const qsc_x509_extension*)NULL;
    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;

    if (crl != (const qsc_x509_crl*)NULL && certificate != (const qsc_x509_certificate*)NULL && issuer != (const qsc_x509_certificate*)NULL)
    {
        if (qsc_x509_name_equals(&crl->issuer, &issuer->subject) == false)
        {
            status = QSC_X509_CRL_VERIFY_STATUS_ISSUER_MISMATCH;
        }
        else
        {
            status = QSC_X509_CRL_VERIFY_STATUS_SUCCESS;

            for (i = 0U; i < crl->extensions.count && status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS; ++i)
            {
                if (x509_revext_oid_equal(&crl->extensions.entries[i].extension_oid, X509_OID_DELTA_CRL_INDICATOR,
                    sizeof(X509_OID_DELTA_CRL_INDICATOR)) == true)
                {
                    /* A delta CRL is not complete status information by itself. It is
                     * usable only after qsc_x509_apply_delta_crl combines it with its
                     * matching complete base CRL. */
                    status = QSC_X509_CRL_VERIFY_STATUS_UNSUPPORTED;
                }
                else if (x509_revext_oid_equal(&crl->extensions.entries[i].extension_oid, X509_OID_ISSUING_DISTRIBUTION_POINT,
                    sizeof(X509_OID_ISSUING_DISTRIBUTION_POINT)) == true)
                {
                    extension = &crl->extensions.entries[i];
                }
            }

            if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS && extension != (const qsc_x509_extension*)NULL)
            {
                status = x509_revext_check_idp_scope(extension, certificate);
            }
        }
    }

    return status;
}

qsc_x509_crl_verify_status qsc_x509_apply_delta_crl(qsc_x509_crl* mergedcrl, const qsc_x509_crl* basecrl, const qsc_x509_crl* deltacrl, const qsc_x509_certificate* issuer,
    const qsc_asn1_time* now, qsc_x509_crl_signature_verify_callback callback, void* state)
{
    uint8_t baseidpbuf[QSC_X509_SPKI_MAX];
    uint8_t deltaidpbuf[QSC_X509_SPKI_MAX];
    uint64_t basecrlnumber;
    uint64_t deltacrlnumber;
    uint64_t referencedbase;
    size_t baseidplen;
    size_t deltaidplen;
    size_t i;
    qsc_asn1_status astatus;
    qsc_x509_crl_verify_status status;
    bool hasentryext;
    bool isbase;
    bool isdelta;

    status = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;
    astatus = QSC_ASN1_STATUS_FAILURE;
    isbase = false;
    isdelta = false;
    hasentryext = false;
    basecrlnumber = 0U;
    deltacrlnumber = 0U;
    referencedbase = 0U;
    qsc_memutils_clear(baseidpbuf, sizeof(baseidpbuf));
    qsc_memutils_clear(deltaidpbuf, sizeof(deltaidpbuf));
    baseidplen = 0U;
    deltaidplen = 0U;

    if (mergedcrl == (qsc_x509_crl*)NULL || basecrl == (const qsc_x509_crl*)NULL || deltacrl == (const qsc_x509_crl*)NULL ||
        issuer == (const qsc_x509_certificate*)NULL || now == (const qsc_asn1_time*)NULL || callback == (qsc_x509_crl_signature_verify_callback)NULL)
    {
        status = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_x509_crl_clear(mergedcrl);
        status = qsc_x509_crl_verify(basecrl, issuer, now, callback, state);

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            status = qsc_x509_crl_verify(deltacrl, issuer, now, callback, state);
        }

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            if (qsc_x509_name_equals(&basecrl->issuer, &deltacrl->issuer) == false)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_ISSUER_MISMATCH;
            }
        }

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            astatus = x509_revext_parse_crl_metadata(basecrl, &isbase, &isdelta, &basecrlnumber, &referencedbase, baseidpbuf, sizeof(baseidpbuf), &baseidplen, &hasentryext);

            if (astatus != QSC_ASN1_STATUS_SUCCESS || isbase == false || isdelta == true)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
            }
        }

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            hasentryext = false;
            astatus = x509_revext_parse_crl_metadata(deltacrl, &isbase, &isdelta, &deltacrlnumber, &referencedbase, deltaidpbuf, sizeof(deltaidpbuf), &deltaidplen, &hasentryext);

            if (astatus != QSC_ASN1_STATUS_SUCCESS || isbase == false || isdelta == false)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
            }

        }

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            if (basecrlnumber < referencedbase || basecrlnumber >= deltacrlnumber)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
            }
            else if (baseidplen != deltaidplen)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
            }
            else if (baseidplen != 0U && qsc_intutils_are_equal8(baseidpbuf, deltaidpbuf, baseidplen) == false)
            {
                status = QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL;
            }
        }

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            *mergedcrl = *basecrl;

            for (i = 0U; i < mergedcrl->extensions.count; ++i)
            {
                if (mergedcrl->extensions.entries[i].rawextnvalue.data != (const uint8_t*)NULL)
                {
                    mergedcrl->extensions.entries[i].rawextnvalue.data = mergedcrl->extensions.entries[i].value;
                    mergedcrl->extensions.entries[i].rawextnvalue.length = mergedcrl->extensions.entries[i].valuelen;
                    mergedcrl->extensions.entries[i].rawextnvalue.storage = QSC_X509_STORAGE_CLASS_BORROWED;
                }
            }

            mergedcrl->tbsdata = (const uint8_t*)NULL;
            mergedcrl->tbsdatalen = 0U;
            mergedcrl->der = (const uint8_t*)NULL;
            mergedcrl->derlen = 0U;
            status = x509_revext_merge_delta_entries(mergedcrl, deltacrl);
        }

        if (status == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
        {
            mergedcrl->thisupdate = deltacrl->thisupdate;
            mergedcrl->nextupdate_present = deltacrl->nextupdate_present;
            mergedcrl->nextupdate = deltacrl->nextupdate;
            mergedcrl->tbsignature = deltacrl->tbsignature;
            mergedcrl->signaturealgorithm = deltacrl->signaturealgorithm;
            qsc_memutils_copy(mergedcrl->signature, deltacrl->signature, sizeof(mergedcrl->signature));
            mergedcrl->signaturelen = deltacrl->signaturelen;
            mergedcrl->signatureunusedbits = deltacrl->signatureunusedbits;
            mergedcrl->version = deltacrl->version;
            status = x509_revext_copy_crl_backing(mergedcrl, deltacrl);
        }
    }

    return status;
}

bool qsc_x509_ocsp_stapled_verify(const uint8_t* stapled, size_t stapledlen, const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer)
{
    qsc_x509_algorithm_identifier sigalg = { 0 };
    qsc_encoding_ber_element* root;
    qsc_x509_certificate* responder;
    qsc_x509_verify_state verifystate = { 0 };
    uint8_t* verifybuffer;
    const qsc_encoding_ber_element* responsedata;
    const qsc_x509_certificate* signercertificate;
    const qsc_x509_subject_public_key_info* verifierspki;
    const uint8_t* basicoctets;
    const uint8_t* sigdata;
    const uint8_t* tbsdata;
    size_t basicoctetslen;
    size_t consumed;
    size_t siglen;
    uint8_t sigunused;
    size_t tbsdatalen;
    qsc_asn1_time now;
    bool statusgood;

    root = (qsc_encoding_ber_element*)NULL;
    responder = (qsc_x509_certificate*)NULL;
    verifybuffer = (uint8_t*)NULL;
    responsedata = (const qsc_encoding_ber_element*)NULL;
    signercertificate = (const qsc_x509_certificate*)NULL;
    verifierspki = (const qsc_x509_subject_public_key_info*)NULL;
    basicoctets = (const uint8_t*)NULL;
    basicoctetslen = 0U;
    consumed = 0U;
    sigdata = (const uint8_t*)NULL;
    siglen = 0U;
    sigunused = 0U;
    tbsdata = (const uint8_t*)NULL;
    tbsdatalen = 0U;
    statusgood = false;

    if (stapled != (const uint8_t*)NULL && stapledlen != 0U && certificate != (const qsc_x509_certificate*)NULL && issuer != (const qsc_x509_certificate*)NULL)
    {
        responder = qsc_memutils_malloc(sizeof(qsc_x509_certificate));
        verifybuffer = qsc_memutils_malloc(QSC_X509_SIGNATURE_MAX + (2U * QSC_X509_CERTIFICATE_WRITE_MAX));

        if (responder != (qsc_x509_certificate*)NULL)
        {
            qsc_memutils_clear(responder, sizeof(qsc_x509_certificate));
        }

        if (verifybuffer != (uint8_t*)NULL)
        {
            qsc_memutils_clear(verifybuffer, QSC_X509_SIGNATURE_MAX + (2U * QSC_X509_CERTIFICATE_WRITE_MAX));
        }

        if (responder != (qsc_x509_certificate*)NULL && verifybuffer != (uint8_t*)NULL)
        {
            qsc_memutils_clear((uint8_t*)&sigalg, sizeof(sigalg));

            if (x509_revext_current_utc_time(&now) == true &&
                qsc_x509_certificate_check_validity(certificate, &now) == QSC_X509_VERIFY_STATUS_SUCCESS &&
                qsc_x509_certificate_check_validity(issuer, &now) == QSC_X509_VERIFY_STATUS_SUCCESS &&
                x509_revext_ocsp_get_basic_response_octets(stapled, stapledlen, &basicoctets, &basicoctetslen) == true &&
                x509_revext_ocsp_extract_basic_signature(basicoctets, basicoctetslen, &tbsdata, &tbsdatalen, &sigalg, &sigdata, &siglen, &sigunused, responder) == true)
            {
                if (responder->der != (const uint8_t*)NULL && responder->derlen != 0U)
                {
                    if (qsc_x509_ocsp_verify_responder(responder, issuer, (const qsc_x509_store*)NULL, &now) == true &&
                        qsc_x509_certificate_check_validity(responder, &now) == QSC_X509_VERIFY_STATUS_SUCCESS)
                    {
                        verifierspki = &responder->subjectpublickeyinfo;
                    }
                }
                else
                {
                    verifierspki = &issuer->subjectpublickeyinfo;
                }

                if (verifierspki != (const qsc_x509_subject_public_key_info*)NULL)
                {
                    qsc_x509_qsc_verify_state_initialize(&verifystate, verifybuffer, QSC_X509_SIGNATURE_MAX + (2U * QSC_X509_CERTIFICATE_WRITE_MAX));

                    if (qsc_x509_qsc_verify_signed_data(tbsdata, tbsdatalen, sigdata, siglen, sigunused, sigalg.signature, verifierspki, &verifystate) == true)
                    {
                        signercertificate = (responder->der != (const uint8_t*)NULL && responder->derlen != 0U) ? responder : issuer;
                        root = qsc_encoding_der_decode_element(basicoctets, basicoctetslen, &consumed);

                        if (root != (qsc_encoding_ber_element*)NULL && consumed == basicoctetslen && qsc_asn1_require_sequence(root, 3U, 4U) == QSC_ASN1_STATUS_SUCCESS)
                        {
                            responsedata = qsc_asn1_get_child(root, 0U);

                            if (responsedata != (const qsc_encoding_ber_element*)NULL && x509_revext_ocsp_match_responder_id(responsedata, signercertificate) == true)
                            {
                                (void)x509_revext_ocsp_response_matches_certificate(basicoctets, basicoctetslen, certificate, issuer, &now, &statusgood);
                            }
                        }
                    }
                }
            }
        }
    }

    if (root != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(root);
    }

    if (responder != (qsc_x509_certificate*)NULL)
    {
        qsc_x509_certificate_clear(responder);
        qsc_memutils_alloc_free(responder);
    }

    if (verifybuffer != (uint8_t*)NULL)
    {
        qsc_memutils_secure_erase(verifybuffer, QSC_X509_SIGNATURE_MAX + (2U * QSC_X509_CERTIFICATE_WRITE_MAX));
        qsc_memutils_alloc_free(verifybuffer);
    }

    return statusgood;
}
