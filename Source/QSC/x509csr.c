#include "x509csr.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "stringutils.h"
#include "x509ext.h"
#include "x509name.h"
#include "x509sig.h"
#include "x509spki.h"
#include "x509write.h"
#include "x509sigver.h"

#define QSC_X509_CSR_PEM_LINE 64U
#define QSC_X509_CSR_PEM_BEGIN "-----BEGIN CERTIFICATE REQUEST-----\n"
#define QSC_X509_CSR_PEM_END "-----END CERTIFICATE REQUEST-----\n"

#define QSC_ASN1_CLASS_UNIVERSAL 0x00U
#define QSC_ASN1_CLASS_CONTEXT 0x80U
#define QSC_ASN1_TAG_INTEGER 2U
#define QSC_ASN1_TAG_BIT_STRING 3U
#define QSC_ASN1_TAG_OCTET_STRING 4U
#define QSC_ASN1_TAG_OBJECT_IDENTIFIER 6U
#define QSC_ASN1_TAG_SEQUENCE 16U
#define QSC_ASN1_TAG_SET 17U

static const char qsc_x509_csr_b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void x509_csr_release_preserved_der(qsc_x509_csr* csr)
{
    if (csr != NULL)
    {
        if ((csr->derowned == true) && (csr->der != NULL))
        {
            qsc_memutils_alloc_free((void*)csr->der);
        }

        csr->infodata = (const uint8_t*)NULL;
        csr->infodatalen = 0U;
        csr->der = (const uint8_t*)NULL;
        csr->derlen = 0U;
        csr->derowned = false;
    }
}

static qsc_asn1_status x509_csr_upsert_extension(qsc_x509_extensions* extensions, qsc_x509_extension_type type, qsc_oid_id oidid, bool critical, const uint8_t* value, size_t valuelen)
{
    size_t idx;
    qsc_x509_extension* extension;

    if ((extensions == NULL) || ((value == NULL) && (valuelen != 0U)))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    extension = NULL;

    for (idx = 0U; idx < extensions->count; ++idx)
    {
        if (extensions->entries[idx].type == type)
        {
            extension = &extensions->entries[idx];
            break;
        }
    }

    if (extension == NULL)
    {
        if (extensions->count >= QSC_X509_EXTENSIONS_MAX)
        {
            return QSC_ASN1_STATUS_OUT_OF_RANGE;
        }

        extension = &extensions->entries[extensions->count++];
        qsc_memutils_clear(extension, sizeof(qsc_x509_extension));
    }

    if (valuelen > sizeof(extension->value))
    {
        return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    extension->type = type;
    extension->oid = oidid;
    extension->critical = critical;
    extension->valuelen = valuelen;

    if (valuelen != 0U)
    {
        qsc_memutils_copy(extension->value, value, valuelen);
    }

    return QSC_ASN1_STATUS_SUCCESS;
}

static qsc_asn1_status x509_csr_validate_signer_spki(const qsc_x509_csr* csr, const qsc_x509_subject_public_key_info* signerspki)
{
    qsc_asn1_status status;

    if ((csr == NULL) || (signerspki == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (qsc_x509_spki_validate(signerspki) != QSC_ASN1_STATUS_SUCCESS)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (qsc_x509_signature_algorithm_matches_spki(csr->signaturealgorithm.signature, signerspki) == false)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

static void x509_csr_build_extension_request_oid(qsc_asn1_oid* oid)
{
    static const uint32_t arcs[] = { 1U, 2U, 840U, 113549U, 1U, 9U, 14U };
    static const uint8_t data[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x09U, 0x0EU };

    qsc_memutils_clear(oid, sizeof(qsc_asn1_oid));
    oid->arcscount = sizeof(arcs) / sizeof(arcs[0]);
    qsc_memutils_copy(oid->arcs, arcs, sizeof(arcs));
    oid->length = sizeof(data);
    qsc_memutils_copy(oid->data, data, sizeof(data));
}

static bool x509_csr_oid_is_extension_request(const qsc_asn1_oid* oid)
{
    qsc_asn1_oid extoid;
    bool res;

    res = false;

    if (oid != NULL)
    {
        x509_csr_build_extension_request_oid(&extoid);
        res = qsc_asn1_oid_are_equal(oid, &extoid);
    }

    return res;
}

static qsc_asn1_status x509_csr_decode_attributes(const qsc_encoding_ber_element* element, qsc_x509_csr* csr, qsc_x509_extensions* extensions)
{
    if ((element == NULL) || (extensions == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (qsc_asn1_require_tag(element, QSC_ASN1_CLASS_CONTEXT, true, 0U) != QSC_ASN1_STATUS_SUCCESS)
    {
        return QSC_ASN1_STATUS_INVALID_TAG;
    }

    for (size_t i = 0U; i < qsc_asn1_child_count(element); ++i)
    {
        const qsc_encoding_ber_element* attr = qsc_asn1_child_at(element, i);
        const qsc_encoding_ber_element* typeel = NULL;
        const qsc_encoding_ber_element* valuesel = NULL;
        const qsc_encoding_ber_element* value0 = NULL;
        qsc_asn1_oid oid;
        qsc_asn1_status status;
        size_t enclen;

        if (attr == NULL)
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        status = qsc_asn1_require_sequence(attr, 2U, 2U);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        typeel = qsc_asn1_child_at(attr, 0U);
        valuesel = qsc_asn1_child_at(attr, 1U);

        if ((typeel == NULL) || (valuesel == NULL))
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        status = qsc_asn1_decode_oid(typeel, &oid);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        if (qsc_asn1_require_tag(valuesel, QSC_ASN1_CLASS_UNIVERSAL, true, QSC_ASN1_TAG_SET) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_INVALID_TAG;
        }

        if (qsc_asn1_child_count(valuesel) != 1U)
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        value0 = qsc_asn1_child_at(valuesel, 0U);

        if (value0 == NULL)
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        if (csr != NULL)
        {
            enclen = qsc_encoding_der_encode_element((qsc_encoding_ber_element*)value0, NULL, 0U);

            if ((enclen == 0U) || (enclen > QSC_X509_CSR_ATTRIBUTE_VALUE_MAX))
            {
                return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }

            if (csr->attributecount >= QSC_X509_CSR_ATTRIBUTES_MAX)
            {
                return QSC_ASN1_STATUS_OUT_OF_RANGE;
            }

            qsc_memutils_clear(&csr->attributes[csr->attributecount], sizeof(csr->attributes[csr->attributecount]));
            csr->attributes[csr->attributecount].oid = oid;
            csr->attributes[csr->attributecount].valuelen = qsc_encoding_der_encode_element((qsc_encoding_ber_element*)value0, csr->attributes[csr->attributecount].value, enclen);
            
            if (csr->attributes[csr->attributecount].valuelen != enclen)
            {
                return QSC_ASN1_STATUS_INVALID_ENCODING;
            }

            ++csr->attributecount;
        }

        if (x509_csr_oid_is_extension_request(&oid) == true)
        {
            status = qsc_x509_extensions_decode(value0, extensions);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }
        }
    }

    return QSC_ASN1_STATUS_SUCCESS;
}

static qsc_asn1_status x509_csr_prepare_extensions(const qsc_x509_extensions* source, qsc_x509_extensions* prepared)
{
    uint8_t payload[QSC_X509_SPKI_MAX] = { 0U };
    size_t payloadlen;
    qsc_asn1_status status;

    if ((source == NULL) || (prepared == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    qsc_memutils_copy(prepared, source, sizeof(*prepared));

    if (source->basicconstraints.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_basic_constraints(&source->basicconstraints, payload, &payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = x509_csr_upsert_extension(prepared, QSC_X509_EXTENSION_BASIC_CONSTRAINTS,
            QSC_OID_ID_BASIC_CONSTRAINTS, source->basicconstraints.critical, payload, payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }
    }

    if (source->keyusage.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_key_usage(&source->keyusage, payload, &payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = x509_csr_upsert_extension(prepared, QSC_X509_EXTENSION_KEY_USAGE,
            QSC_OID_ID_KEY_USAGE, source->keyusage.critical, payload, payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }
    }

    if (source->extendedkeyusage.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_extended_key_usage(&source->extendedkeyusage, payload, &payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = x509_csr_upsert_extension(prepared, QSC_X509_EXTENSION_EXTENDED_KEY_USAGE,
            QSC_OID_ID_EXTENDED_KEY_USAGE, source->extendedkeyusage.critical, payload, payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }
    }

    if (source->subjectkeyidentifier.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_subject_key_identifier(&source->subjectkeyidentifier, payload, &payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = x509_csr_upsert_extension(prepared, QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER,
            QSC_OID_ID_SUBJECT_KEY_IDENTIFIER, source->subjectkeyidentifier.critical, payload, payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }
    }

    if (source->authoritykeyidentifier.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_authority_key_identifier(&source->authoritykeyidentifier, payload, &payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = x509_csr_upsert_extension(prepared, QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER,
            QSC_OID_ID_AUTHORITY_KEY_IDENTIFIER, source->authoritykeyidentifier.critical, payload, payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }
    }

    if (source->subjectaltname.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_subject_alt_name(&source->subjectaltname, payload, &payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = x509_csr_upsert_extension(prepared, QSC_X509_EXTENSION_SUBJECT_ALT_NAME,
            QSC_OID_ID_SUBJECT_ALT_NAME, source->subjectaltname.critical, payload, payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }
    }

    if (source->issueraltname.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_issuer_alt_name(&source->issueraltname, payload, &payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = x509_csr_upsert_extension(prepared, QSC_X509_EXTENSION_ISSUER_ALT_NAME,
            QSC_OID_ID_ISSUER_ALT_NAME, source->issueraltname.critical, payload, payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }
    }

    return QSC_ASN1_STATUS_SUCCESS;
}

static qsc_asn1_status x509_csr_encode_attributes(const qsc_x509_csr* csr, uint8_t* output, size_t* outputlen)
{
    uint8_t attrs[QSC_X509_CSR_WRITE_MAX] = { 0U };
    uint8_t attrcontent[QSC_X509_CSR_WRITE_MAX] = { 0U };
    uint8_t valueset[QSC_X509_CSR_WRITE_MAX] = { 0U };
    uint8_t attrder[QSC_X509_CSR_WRITE_MAX] = { 0U };
    qsc_asn1_oid extoid;
    qsc_x509_extensions prepared;
    size_t attrcontentlen;
    size_t attrderlen;
    size_t attrslen;
    size_t extlen;
    size_t len;
    bool hasextensions;
    size_t i;

    hasextensions = false;
    attrslen = 0U;
    extlen = 0U;
    len = 0U;
    i = 0U;

    if ((csr == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if ((csr->extensions.basicconstraints.present == true) ||
        (csr->extensions.keyusage.present == true) ||
        (csr->extensions.extendedkeyusage.present == true) ||
        (csr->extensions.subjectkeyidentifier.present == true) ||
        (csr->extensions.authoritykeyidentifier.present == true) ||
        (csr->extensions.subjectaltname.present == true) ||
        (csr->extensions.issueraltname.present == true))
    {
        hasextensions = true;
    }

    for (i = 0U; i < csr->extensions.count; ++i)
    {
        if (csr->extensions.entries[i].valuelen != 0U)
        {
            hasextensions = true;
            break;
        }
    }

    if (hasextensions == true)
    {
        attrcontentlen = 0U;
        attrderlen = 0U;
        len = sizeof(attrder);

        if (x509_csr_prepare_extensions(&csr->extensions, &prepared) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_FAILURE;
        }

        if (qsc_x509_write_extensions(&prepared, attrder, &len) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_FAILURE;
        }

        extlen = len;
        len = sizeof(valueset);

        if (qsc_x509_write_set(attrder, extlen, valueset, &len) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_FAILURE;
        }

        x509_csr_build_extension_request_oid(&extoid);
        attrcontentlen = sizeof(attrcontent);

        if (qsc_x509_write_oid(&extoid, attrcontent, &attrcontentlen) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_FAILURE;
        }

        if ((attrcontentlen + len) > sizeof(attrcontent))
        {
            return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }

        qsc_memutils_copy(attrcontent + attrcontentlen, valueset, len);
        attrcontentlen += len;
        attrderlen = sizeof(attrder);

        if (qsc_x509_write_sequence(attrcontent, attrcontentlen, attrder, &attrderlen) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_FAILURE;
        }

        if ((attrslen + attrderlen) > sizeof(attrs))
        {
            return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }

        qsc_memutils_copy(attrs + attrslen, attrder, attrderlen);
        attrslen += attrderlen;
    }

    for (i = 0U; i < csr->attributecount; ++i)
    {
        attrcontentlen = 0U;
        attrderlen = 0U;

        if (x509_csr_oid_is_extension_request(&csr->attributes[i].oid) == true)
        {
            continue;
        }

        if ((csr->attributes[i].oid.length == 0U) || (csr->attributes[i].valuelen == 0U))
        {
            return QSC_ASN1_STATUS_INVALID_INPUT;
        }

        attrcontentlen = sizeof(attrcontent);

        if (qsc_x509_write_oid(&csr->attributes[i].oid, attrcontent, &attrcontentlen) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_FAILURE;
        }

        len = sizeof(valueset);

        if (qsc_x509_write_set(csr->attributes[i].value, csr->attributes[i].valuelen, valueset, &len) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_FAILURE;
        }

        if ((attrcontentlen + len) > sizeof(attrcontent))
        {
            return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }

        qsc_memutils_copy(attrcontent + attrcontentlen, valueset, len);
        attrcontentlen += len;
        attrderlen = sizeof(attrder);

        if (qsc_x509_write_sequence(attrcontent, attrcontentlen, attrder, &attrderlen) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_FAILURE;
        }

        if ((attrslen + attrderlen) > sizeof(attrs))
        {
            return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }

        qsc_memutils_copy(attrs + attrslen, attrder, attrderlen);
        attrslen += attrderlen;
    }

    return qsc_x509_write_raw(QSC_ASN1_CLASS_CONTEXT, true, 0U, attrs, attrslen, output, outputlen);
}

void qsc_x509_csr_initialize(qsc_x509_csr* csr)
{
    QSC_ASSERT(csr != NULL);

    if (csr != NULL)
    {
        qsc_memutils_clear(csr, sizeof(qsc_x509_csr));
        csr->version = 0U;
    }
}

void qsc_x509_csr_clear(qsc_x509_csr* csr)
{
    QSC_ASSERT(csr != NULL);

    if (csr != NULL)
    {
        x509_csr_release_preserved_der(csr);
        qsc_memutils_clear(csr, sizeof(qsc_x509_csr));
    }
}

qsc_asn1_status qsc_x509_csr_set_subject(qsc_x509_csr* csr, const qsc_x509_name* subject)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(subject != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (subject != NULL))
    {
        x509_csr_release_preserved_der(csr);
        qsc_memutils_copy(&csr->subject, subject, sizeof(qsc_x509_name));
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_set_spki(qsc_x509_csr* csr, const qsc_x509_subject_public_key_info* spki)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(spki != NULL);

    qsc_asn1_status status;

    if ((csr == NULL) || (spki == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (qsc_x509_spki_validate(spki) != QSC_ASN1_STATUS_SUCCESS)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        x509_csr_release_preserved_der(csr);
        qsc_memutils_copy(&csr->spki, spki, sizeof(qsc_x509_subject_public_key_info));
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_set_signature_algorithm(qsc_x509_csr* csr, const qsc_x509_algorithm_identifier* signaturealgorithm)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(signaturealgorithm != NULL);

    qsc_asn1_status status;

    if ((csr == NULL) || (signaturealgorithm == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        x509_csr_release_preserved_der(csr);
        qsc_memutils_copy(&csr->signaturealgorithm, signaturealgorithm, sizeof(qsc_x509_algorithm_identifier));
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_set_extension_request(qsc_x509_csr* csr, const qsc_x509_extensions* extensions)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(extensions != NULL);

    qsc_asn1_status status;

    if ((csr == NULL) || (extensions == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        x509_csr_release_preserved_der(csr);
        qsc_memutils_copy(&csr->extensions, extensions, sizeof(qsc_x509_extensions));
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

const qsc_x509_extensions* qsc_x509_csr_get_extension_request(const qsc_x509_csr* csr)
{
    QSC_ASSERT(csr != NULL);

    const qsc_x509_extensions* ext;

    if (csr != NULL)
    {
        ext = &csr->extensions;
    }
    else
    {
        ext = NULL;
    }

    return ext;
}

qsc_asn1_status qsc_x509_csr_copy_extension_request(const qsc_x509_csr* csr, qsc_x509_extensions* extensions)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(extensions != NULL);

    qsc_asn1_status status;

    if ((csr == NULL) || (extensions == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_memutils_copy(extensions, &csr->extensions, sizeof(qsc_x509_extensions));
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_add_attribute(qsc_x509_csr* csr, const qsc_asn1_oid* oid, const uint8_t* value, size_t valuelen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(oid != NULL);

    qsc_asn1_status status;

    if ((csr == NULL) || (oid == NULL) || ((value == NULL) && (valuelen != 0U)))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((oid->length == 0U) || (valuelen == 0U))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    else if (valuelen > QSC_X509_CSR_ATTRIBUTE_VALUE_MAX)
    {
        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    else if (csr->attributecount >= QSC_X509_CSR_ATTRIBUTES_MAX)
    {
        status = QSC_ASN1_STATUS_OUT_OF_RANGE;
    }
    else
    {
        x509_csr_release_preserved_der(csr);
        qsc_memutils_clear(&csr->attributes[csr->attributecount], sizeof(csr->attributes[csr->attributecount]));
        csr->attributes[csr->attributecount].oid = *oid;
        qsc_memutils_copy(csr->attributes[csr->attributecount].value, value, valuelen);
        csr->attributes[csr->attributecount].valuelen = valuelen;
        ++csr->attributecount;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

const qsc_x509_csr_attribute* qsc_x509_csr_get_attribute(const qsc_x509_csr* csr, const qsc_asn1_oid* oid)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(oid != NULL);

    if ((csr == NULL) || (oid == NULL))
    {
        return NULL;
    }

    for (size_t i = 0U; i < csr->attributecount; ++i)
    {
        if (qsc_asn1_oid_are_equal(&csr->attributes[i].oid, oid) == true)
        {
            return &csr->attributes[i];
        }
    }

    return NULL;
}

qsc_asn1_status qsc_x509_csr_set_subject_alt_name(qsc_x509_csr* csr, const qsc_x509_subject_alt_name* subjectaltname)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(subjectaltname != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (subjectaltname != NULL))
    {
        x509_csr_release_preserved_der(csr);
        csr->extensions.subjectaltname = *subjectaltname;
        csr->extensions.subjectaltname.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_add_san_dns(qsc_x509_csr* csr, const char* dnsname, size_t dnsnamelen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(dnsname != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (dnsname != NULL) && (dnsnamelen != 0U))
    {
        x509_csr_release_preserved_der(csr);
        status = qsc_x509_ext_subject_alt_name_add_dns(&csr->extensions.subjectaltname, dnsname, dnsnamelen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            csr->extensions.subjectaltname.present = true;
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_add_san_ip(qsc_x509_csr* csr, const uint8_t* address, size_t addresslen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(address != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (address != NULL) && (addresslen != 0U))
    {
        x509_csr_release_preserved_der(csr);
        status = qsc_x509_ext_subject_alt_name_add_ip(&csr->extensions.subjectaltname, address, addresslen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            csr->extensions.subjectaltname.present = true;
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_set_extended_key_usage(qsc_x509_csr* csr, const qsc_x509_extended_key_usage* extendedkeyusage)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(extendedkeyusage != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (extendedkeyusage != NULL))
    {
        x509_csr_release_preserved_der(csr);
        csr->extensions.extendedkeyusage = *extendedkeyusage;
        csr->extensions.extendedkeyusage.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_set_subject_key_identifier(qsc_x509_csr* csr, const qsc_x509_subject_key_identifier* subjectkeyidentifier)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(subjectkeyidentifier != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (subjectkeyidentifier != NULL))
    {
        x509_csr_release_preserved_der(csr);
        csr->extensions.subjectkeyidentifier = *subjectkeyidentifier;
        csr->extensions.subjectkeyidentifier.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_set_ml_dsa_signature_algorithm(qsc_x509_csr* csr, uint32_t level)
{
    QSC_ASSERT(csr != NULL);
    
    qsc_x509_pqc_parameter_set parameterset;
    qsc_asn1_status status;

    parameterset = QSC_X509_PQC_PARAMETER_SET_NONE;
    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (csr != NULL)
    {
        if (level == 44U)
        {
            parameterset = QSC_X509_PQC_PARAMETER_SET_ML_DSA_44;
        }
        else if (level == 65U)
        {
            parameterset = QSC_X509_PQC_PARAMETER_SET_ML_DSA_65;
        }
        else if (level == 87U)
        {
            parameterset = QSC_X509_PQC_PARAMETER_SET_ML_DSA_87;
        }
        else
        {
            status = QSC_ASN1_STATUS_OUT_OF_RANGE;
        }

        if (status != QSC_ASN1_STATUS_OUT_OF_RANGE)
        {
            x509_csr_release_preserved_der(csr);
            status = qsc_x509_algorithm_identifier_initialize_mldsa(&csr->signaturealgorithm, parameterset);
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_set_ml_dsa_spki(qsc_x509_csr* csr, uint32_t level, const uint8_t* publickey, size_t publickeylen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(publickey != NULL);

    qsc_x509_pqc_parameter_set parameterset;
    qsc_asn1_status status;

    parameterset = QSC_X509_PQC_PARAMETER_SET_NONE;
    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (publickey != NULL))
    {
        if (level == 44U)
        {
            parameterset = QSC_X509_PQC_PARAMETER_SET_ML_DSA_44;
        }
        else if (level == 65U)
        {
            parameterset = QSC_X509_PQC_PARAMETER_SET_ML_DSA_65;
        }
        else if (level == 87U)
        {
            parameterset = QSC_X509_PQC_PARAMETER_SET_ML_DSA_87;
        }
        else
        {
            status = QSC_ASN1_STATUS_OUT_OF_RANGE;
        }

        if (status != QSC_ASN1_STATUS_OUT_OF_RANGE)
        {
            x509_csr_release_preserved_der(csr);
            status = qsc_x509_spki_initialize_ml_dsa(&csr->spki, parameterset, publickey, publickeylen);
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_set_ml_kem_spki(qsc_x509_csr* csr, uint32_t level, const uint8_t* publickey, size_t publickeylen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(publickey != NULL);

    qsc_x509_pqc_parameter_set parameterset;
    qsc_asn1_status status;

    parameterset = QSC_X509_PQC_PARAMETER_SET_NONE;
    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (publickey != NULL))
    {
        if (level == 512U)
        {
            parameterset = QSC_X509_PQC_PARAMETER_SET_ML_KEM_512;
        }
        else if (level == 768U)
        {
            parameterset = QSC_X509_PQC_PARAMETER_SET_ML_KEM_768;
        }
        else if (level == 1024U)
        {
            parameterset = QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024;
        }
        else
        {
            status = QSC_ASN1_STATUS_OUT_OF_RANGE;
        }

        if (status != QSC_ASN1_STATUS_OUT_OF_RANGE)
        {
            x509_csr_release_preserved_der(csr);
            status = qsc_x509_spki_initialize_ml_kem(&csr->spki, parameterset, publickey, publickeylen);
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_encode_info_der(const qsc_x509_csr* csr, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t content[QSC_X509_CSR_WRITE_MAX] = { 0U };
    uint8_t attrs[QSC_X509_CSR_WRITE_MAX] = { 0U };
    uint8_t ver[8U] = { 0U };
    size_t pos;
    size_t len;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (outputlen != NULL))
    {
        pos = 0U;
        len = 0U;
        uint8_t versionbytes[5U] = { 0U };
        size_t versionlen = 0U;
        uint32_t versionvalue;

        versionvalue = csr->version;

        if (versionvalue > 0xFFFFFFU)
        {
            versionbytes[versionlen++] = (uint8_t)((versionvalue >> 24U) & 0xFFU);
        }
        if ((versionlen != 0U) || (versionvalue > 0xFFFFU))
        {
            versionbytes[versionlen++] = (uint8_t)((versionvalue >> 16U) & 0xFFU);
        }
        if ((versionlen != 0U) || (versionvalue > 0xFFU))
        {
            versionbytes[versionlen++] = (uint8_t)((versionvalue >> 8U) & 0xFFU);
        }
        versionbytes[versionlen++] = (uint8_t)(versionvalue & 0xFFU);

        len = sizeof(ver);
        status = qsc_x509_write_integer(versionbytes, versionlen, ver, &len);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_memutils_copy(content + pos, ver, len);
            pos += len;
            len = sizeof(content) - pos;
            status = qsc_x509_write_name(&csr->subject, content + pos, &len);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                pos += len;
                len = sizeof(content) - pos;
                status = qsc_x509_write_spki(&csr->spki, content + pos, &len);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    pos += len;
                    len = sizeof(attrs);
                    status = x509_csr_encode_attributes(csr, attrs, &len);

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        if ((sizeof(content) - pos) < len)
                        {
                            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                        }
                        else
                        {
                            qsc_memutils_copy(content + pos, attrs, len);
                            pos += len;

                            status = qsc_x509_write_sequence(content, pos, output, outputlen);
                        }
                    }
                }
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_encode_der(const qsc_x509_csr* csr, qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t info[QSC_X509_CSR_WRITE_MAX] = { 0U };
    uint8_t content[QSC_X509_CSR_WRITE_MAX] = { 0U };
    uint8_t signature[QSC_X509_SIGNATURE_MAX] = { 0U };
    size_t infolen = sizeof(info);
    size_t pos;
    size_t len;
    size_t siglen;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (signcallback != NULL) && (outputlen != NULL))
    {
        pos = 0U;
        len = 0U;
        siglen = sizeof(signature);
        status = qsc_x509_csr_encode_info_der(csr, info, &infolen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = signcallback(csr->signaturealgorithm.signature, info, infolen, signature, &siglen, context);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                if (siglen > QSC_X509_SIGNATURE_MAX)
                {
                    status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                }
                else
                {
                    qsc_memutils_copy(content + pos, info, infolen);
                    pos += infolen;
                    len = sizeof(content) - pos;
                    status = qsc_x509_write_algorithm_identifier(&csr->signaturealgorithm, content + pos, &len);

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        pos += len;
                        len = sizeof(content) - pos;
                        status = qsc_x509_write_bit_string(signature, siglen, 0U, content + pos, &len);

                        if (status == QSC_ASN1_STATUS_SUCCESS)
                        {
                            pos += len;
                            status = qsc_x509_write_sequence(content, pos, output, outputlen);
                        }
                    }
                }
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_csr_sign(const qsc_x509_csr* csr, qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(outputlen != NULL);

    qsc_asn1_status status;

    status = qsc_x509_csr_encode_der(csr, signcallback, context, output, outputlen);

    return status;
}

qsc_asn1_status qsc_x509_csr_decode_der(qsc_x509_csr* csr, const uint8_t* input, size_t inputlen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(input != NULL);

    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* info;
    const qsc_encoding_ber_element* sigalg;
    const qsc_encoding_ber_element* sigval;
    const qsc_encoding_ber_element* ver;
    const qsc_encoding_ber_element* subj;
    const qsc_encoding_ber_element* spki;
    const qsc_encoding_ber_element* attrs;
    const uint8_t* inforaw;
    ptrdiff_t infooffset;
    qsc_asn1_bit_string bits;
    size_t infoenc;
    uint64_t version;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (input != NULL) && (inputlen != 0U))
    {
        info = NULL;
        sigalg = NULL;
        sigval = NULL;
        ver = NULL;
        subj = NULL;
        spki = NULL;
        attrs = NULL;
        inforaw = NULL;
        infoenc = 0U;
        version = 0U;
        infooffset = 0;

        qsc_x509_csr_clear(csr);
        root = NULL;
        status = qsc_asn1_der_decode_exact(input, inputlen, &root);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = qsc_asn1_der_get_child_region(input, inputlen, 0U, &inforaw, &infoenc);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_encoding_ber_free_element(root);
            return status;
        }

        infooffset = (ptrdiff_t)(inforaw - input);

        if ((infooffset < 0) || ((size_t)infooffset >= inputlen) || (infoenc > (inputlen - (size_t)infooffset)))
        {
            qsc_encoding_ber_free_element(root);
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        status = qsc_asn1_require_sequence(root, 3U, 3U);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_encoding_ber_free_element(root);
            return status;
        }

        info = qsc_asn1_child_at(root, 0U);
        sigalg = qsc_asn1_child_at(root, 1U);
        sigval = qsc_asn1_child_at(root, 2U);

        if ((info == NULL) || (sigalg == NULL) || (sigval == NULL))
        {
            qsc_encoding_ber_free_element(root);
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        status = qsc_asn1_require_sequence(info, 3U, 4U);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_encoding_ber_free_element(root);
            return status;
        }

        ver = qsc_asn1_child_at(info, 0U);
        subj = qsc_asn1_child_at(info, 1U);
        spki = qsc_asn1_child_at(info, 2U);
        attrs = (qsc_asn1_child_count(info) > 3U) ? qsc_asn1_child_at(info, 3U) : NULL;
        status = qsc_asn1_decode_uint64(ver, &version);

        if ((status != QSC_ASN1_STATUS_SUCCESS) || (version != 0U))
        {
            qsc_encoding_ber_free_element(root);
            return (status == QSC_ASN1_STATUS_SUCCESS) ? QSC_ASN1_STATUS_INVALID_ENCODING : status;
        }

        csr->version = (uint32_t)version;
        status = qsc_x509_name_parse(subj, &csr->subject);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_encoding_ber_free_element(root);
            return status;
        }

        status = qsc_x509_subject_public_key_info_decode(spki, &csr->spki);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_encoding_ber_free_element(root);
            return status;
        }

        status = qsc_x509_spki_validate(&csr->spki);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_encoding_ber_free_element(root);
            return status;
        }

        if (attrs != NULL)
        {
            status = x509_csr_decode_attributes(attrs, csr, &csr->extensions);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                qsc_encoding_ber_free_element(root);
                return status;
            }
        }

        status = qsc_x509_signature_algorithm_decode(sigalg, &csr->signaturealgorithm);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_encoding_ber_free_element(root);
            return status;
        }

        status = qsc_asn1_decode_bit_string(sigval, &bits);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_encoding_ber_free_element(root);
            return status;
        }

        if (bits.unused != 0U)
        {
            qsc_encoding_ber_free_element(root);
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if (bits.length > sizeof(csr->signature))
        {
            qsc_encoding_ber_free_element(root);
            return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }

        qsc_memutils_copy(csr->signature, bits.data, bits.length);
        csr->signaturelen = bits.length;
        csr->signatureunusedbits = bits.unused;

        csr->der = (const uint8_t*)qsc_memutils_malloc(inputlen);

        if (csr->der == NULL)
        {
            qsc_encoding_ber_free_element(root);
            return QSC_ASN1_STATUS_FAILURE;
        }

        qsc_memutils_copy((void*)csr->der, input, inputlen);
        csr->derlen = inputlen;
        csr->derowned = true;
        csr->infodata = csr->der + (size_t)infooffset;
        csr->infodatalen = infoenc;

        qsc_encoding_ber_free_element(root);
    }

    return status; /* FIX-01: was return QSC_ASN1_STATUS_SUCCESS - bypassed INVALID_INPUT for null/zero inputs */
}

qsc_asn1_status qsc_x509_csr_decode_pem(qsc_x509_csr* csr, const char* input, size_t inputlen)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(input != NULL);

    uint8_t der[QSC_X509_CSR_WRITE_MAX] = { 0U };
    const char* begin;
    const char* end;
    size_t derlen;
    size_t regionlen;
    qsc_asn1_status status;
    /* FIX-12 (CSR-UNUSED-01): removed unused 'enclen' variable */

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((csr != NULL) && (input != NULL) && (inputlen != 0U))
    {
        derlen = 0U;
        regionlen = 0U;

        begin = qsc_stringutils_sub_string(input, "-----BEGIN CERTIFICATE REQUEST-----");
        end = qsc_stringutils_sub_string(input, "-----END CERTIFICATE REQUEST-----");

        if ((begin == NULL) || (end == NULL) || (end <= begin))
        {
            begin = qsc_stringutils_sub_string(input, "-----BEGIN NEW CERTIFICATE REQUEST-----");
            end = qsc_stringutils_sub_string(input, "-----END NEW CERTIFICATE REQUEST-----");
        }

        if ((begin == NULL) || (end == NULL) || (end <= begin))
        {
            status = QSC_ASN1_STATUS_NOT_FOUND;
        }
        else
        {
            regionlen = (size_t)(end - begin);

            if (regionlen > inputlen)
            {
                regionlen = inputlen;
            }

            if (qsc_encoding_pem_decode(begin, inputlen, der, sizeof(der), &derlen) == false)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                status = qsc_x509_csr_decode_der(csr, der, derlen);
            }
        }
    }

    return status;
}

const qsc_x509_extension* qsc_x509_csr_find_extension(const qsc_x509_csr* csr, qsc_x509_extension_type type)
{
    QSC_ASSERT(csr != NULL);

    if (csr == NULL)
    {
        return NULL;
    }

    for (size_t i = 0U; i < csr->extensions.count; ++i)
    {
        if (csr->extensions.entries[i].type == type)
        {
            return &csr->extensions.entries[i];
        }
    }

    return NULL;
}

bool qsc_x509_csr_verify_ex(const qsc_x509_csr* csr, qsc_x509_csr_signature_verify_callback verifycallback, void* state)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(state != NULL);

    bool res;

    if ((csr == NULL) || (verifycallback == (qsc_x509_csr_signature_verify_callback)NULL) || (csr->signaturelen == 0U))
    {
        res = false;
    }
    else
    {
        res = verifycallback(csr, state);
    }

    return res;
}

bool qsc_x509_csr_verify(const qsc_x509_csr* csr)
{
    QSC_ASSERT(csr != NULL);

    qsc_x509_verify_state vstate = { 0 };
    uint8_t buffer[(2U * QSC_X509_CSR_WRITE_MAX) + QSC_X509_SIGNATURE_MAX] = { 0U };
    bool res;

    if (csr != NULL)
    {
        qsc_x509_qsc_verify_state_initialize(&vstate, buffer, sizeof(buffer));
        res = qsc_x509_csr_verify_ex(csr, qsc_x509_qsc_csr_signature_verify, &vstate);
    }
    else
    {
        res = false;
    }

    return res;
}

bool qsc_x509_csr_verify_with_spki(const qsc_x509_csr* csr, const qsc_x509_subject_public_key_info* signerspki)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(signerspki != NULL);

    qsc_x509_verify_state vstate = { 0 };
    uint8_t buffer[(2U * QSC_X509_CSR_WRITE_MAX) + QSC_X509_SIGNATURE_MAX];
    uint8_t info[QSC_X509_CSR_WRITE_MAX];
    const uint8_t* infodata = NULL;
    size_t infodatalen = 0U;
    bool res;

    res = false;

    if ((csr != NULL) && (signerspki != NULL))
    {
        qsc_x509_qsc_verify_state_initialize(&vstate, buffer, sizeof(buffer));

        if (x509_csr_validate_signer_spki(csr, signerspki) != QSC_ASN1_STATUS_SUCCESS)
        {
            return false;
        }

        infodata = csr->infodata;
        infodatalen = csr->infodatalen;

        if ((infodata == NULL) || (infodatalen == 0U))
        {
            infodatalen = sizeof(info);

            if (qsc_x509_csr_encode_info_der(csr, info, &infodatalen) != QSC_ASN1_STATUS_SUCCESS)
            {
                return false;
            }

            infodata = info;
        }

        res = qsc_x509_qsc_verify_signed_data(infodata, infodatalen,
            csr->signature, csr->signaturelen, csr->signatureunusedbits,
            csr->signaturealgorithm.signature, signerspki, &vstate);
    }

    return res;
}

qsc_asn1_status qsc_x509_csr_encode_pem(const uint8_t* der, size_t derlen, char* output, size_t* outputlen)
{
    QSC_ASSERT(der != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(outputlen != NULL);

    const char* begin;
    const char* end;
    size_t beginlen;
    size_t endlen;
    size_t b64len;
    size_t lines;
    size_t required;
    size_t i;
    size_t j;
    size_t linecount;
    size_t rem;
    uint32_t v;
    qsc_asn1_status status;

    if (((der == NULL) && (derlen != 0U)) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((output == NULL) || (*outputlen == 0U))
    {
        *outputlen = 0U;
        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        begin = QSC_X509_CSR_PEM_BEGIN;
        end = QSC_X509_CSR_PEM_END;
        beginlen = qsc_stringutils_string_size(begin);
        endlen = qsc_stringutils_string_size(end);
        b64len = ((derlen + 2U) / 3U) * 4U;
        lines = (b64len + (QSC_X509_CSR_PEM_LINE - 1U)) / QSC_X509_CSR_PEM_LINE;
        required = beginlen + b64len + lines + endlen + 1U;

        if (*outputlen < required)
        {
            *outputlen = required;
            return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }

        i = 0U;
        j = 0U;
        linecount = 0U;

        qsc_memutils_copy(output + j, begin, beginlen);
        j += beginlen;

        for (i = 0U; i < derlen; i += 3U)
        {
            v = ((uint32_t)der[i]) << 16U;
            rem = derlen - i;

            if (rem > 1U)
            {
                v |= ((uint32_t)der[i + 1U]) << 8U;
            }
            if (rem > 2U)
            {
                v |= der[i + 2U];
            }

            output[j] = qsc_x509_csr_b64_table[(v >> 18U) & 0x3FU];
            ++j;
            output[j] = qsc_x509_csr_b64_table[(v >> 12U) & 0x3FU];
            ++j;
            output[j] = (rem > 1U) ? qsc_x509_csr_b64_table[(v >> 6U) & 0x3FU] : '=';
            ++j;
            output[j] = (rem > 2U) ? qsc_x509_csr_b64_table[v & 0x3FU] : '=';
            ++j;

            linecount += 4U;
            if (linecount == QSC_X509_CSR_PEM_LINE)
            {
                output[j] = '\n';
                ++j;
                linecount = 0U;
            }
        }

        if (linecount != 0U)
        {
            output[j] = '\n';
            ++j;
        }

        qsc_memutils_copy(output + j, end, endlen);
        j += endlen;
        output[j] = '\0';
        *outputlen = j + 1U;

        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}
