#include "x509certwrite.h"
#include "asn1.h"
#include "memutils.h"
#include "stringutils.h"
#include "sha2.h"
#include "x509name.h"
#include "x509sig.h"
#include "x509spki.h"
#include "x509write.h"

#define QSC_X509_CERTWRITE_PEM_LINE 64U
#define QSC_X509_CERTWRITE_PEM_BEGIN "-----BEGIN CERTIFICATE-----\n"
#define QSC_X509_CERTWRITE_PEM_END "-----END CERTIFICATE-----\n"

static const char qsc_x509_certwrite_b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t qsc_x509_certwrite_get_pem_length(size_t derlen)
{
    const size_t b64len = ((derlen + 2U) / 3U) * 4U;
    const size_t lines = (b64len + (QSC_X509_CERTWRITE_PEM_LINE - 1U)) / QSC_X509_CERTWRITE_PEM_LINE;

    return qsc_stringutils_string_size(QSC_X509_CERTWRITE_PEM_BEGIN) + b64len + lines + qsc_stringutils_string_size(QSC_X509_CERTWRITE_PEM_END) + 1U;
}

static void qsc_x509_certwrite_build_extension_request_oid(qsc_asn1_oid* oid)
{
    static const uint32_t arcs[] = { 1U, 2U, 840U, 113549U, 1U, 9U, 14U };
    size_t i = 0U;

    if (oid != NULL)
    {
        static const uint8_t data[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x09U, 0x0EU };

        qsc_memutils_clear(oid, sizeof(qsc_asn1_oid));
        oid->arcscount = sizeof(arcs) / sizeof(arcs[0]);
        oid->length = sizeof(data);

        for (i = 0U; i < oid->arcscount; ++i)
        {
            oid->arcs[i] = arcs[i];
        }

        qsc_memutils_copy(oid->data, data, sizeof(data));
    }
}

static bool qsc_x509_certwrite_extension_type_is_known(qsc_x509_extension_type type)
{
    return ((type == QSC_X509_EXTENSION_BASIC_CONSTRAINTS) ||
            (type == QSC_X509_EXTENSION_KEY_USAGE) ||
            (type == QSC_X509_EXTENSION_EXTENDED_KEY_USAGE) ||
            (type == QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER) ||
            (type == QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER) ||
            (type == QSC_X509_EXTENSION_SUBJECT_ALT_NAME) ||
            (type == QSC_X509_EXTENSION_ISSUER_ALT_NAME));
}

static bool qsc_x509_certwrite_extension_allowed_by_policy(const qsc_x509_extension* extension, uint32_t policyflags)
{
    bool res;

    res = false;

    if (extension != NULL)
    {
        switch (extension->type)
        {
        case QSC_X509_EXTENSION_SUBJECT_ALT_NAME:
            res = ((policyflags & QSC_X509_CERT_ISSUANCE_PROPAGATE_SUBJECT_ALT_NAME) != 0U);
            break;
        case QSC_X509_EXTENSION_EXTENDED_KEY_USAGE:
            res = ((policyflags & QSC_X509_CERT_ISSUANCE_PROPAGATE_EXTENDED_KEY_USAGE) != 0U);
            break;
        case QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER:
            res = ((policyflags & QSC_X509_CERT_ISSUANCE_PROPAGATE_SUBJECT_KEY_IDENTIFIER) != 0U);
            break;
        case QSC_X509_EXTENSION_UNKNOWN:
            res = (((policyflags & QSC_X509_CERT_ISSUANCE_PROPAGATE_UNKNOWN_NON_CRITICAL) != 0U) && (extension->critical == false));
            break;
        default:
            res = false;
        }
    }

    return res;
}

static bool qsc_x509_certwrite_has_duplicate_requested_extensions(const qsc_x509_extensions* extensions)
{
    size_t i = 0U;
    size_t j = 0U;
    bool res;

    res = false;

    if (extensions != NULL)
    {
        for (i = 0U; i < extensions->count; ++i)
        {
            const qsc_x509_extension* left;

            left = &extensions->entries[i];

            for (j = i + 1U; j < extensions->count; ++j)
            {
                const qsc_x509_extension* right = &extensions->entries[j];

                if ((left->type != QSC_X509_EXTENSION_UNKNOWN) && (left->type == right->type))
                {
                    res = true;
                }

                else if ((left->extension_oid.length != 0U) &&
                    (right->extension_oid.length != 0U) &&
                    (qsc_asn1_oid_compare(&left->extension_oid, &right->extension_oid) == true))
                {
                    res = true;
                }
            }
        }
    }

    return res;
}

static bool qsc_x509_certwrite_has_duplicate_csr_attributes(const qsc_x509_csr* csr)
{
    qsc_asn1_oid extensionrequest;
    size_t extreqcount;
    size_t i;
    size_t j;
    bool res;

    res = false;

    if (csr == NULL)
    {
        res = true;
    }
    else
    {
        extreqcount = 0U;
        i = 0U;
        j = 0U;
        qsc_x509_certwrite_build_extension_request_oid(&extensionrequest);

        for (i = 0U; i < csr->attributecount; ++i)
        {
            if (qsc_asn1_oid_compare(&csr->attributes[i].oid, &extensionrequest) == true)
            {
                ++extreqcount;

                if (extreqcount > 1U)
                {
                    res = true;
                    break;
                }
            }

            for (j = i + 1U; j < csr->attributecount; ++j)
            {
                if (qsc_asn1_oid_compare(&csr->attributes[i].oid, &csr->attributes[j].oid) == true)
                {
                    res = true;
                    break;
                }
            }

            if (res == true)
            {
                break;
            }
        }
    }

    return res;
}

static qsc_asn1_status qsc_x509_certwrite_copy_filtered_extension(qsc_x509_extensions* destination, const qsc_x509_extension* extension)
{
    if ((destination == NULL) || (extension == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (destination->count >= QSC_X509_EXTENSIONS_MAX)
    {
        return QSC_ASN1_STATUS_OUT_OF_RANGE;
    }

    qsc_memutils_copy(&destination->entries[destination->count], extension, sizeof(*extension));
    destination->count++;
    return QSC_ASN1_STATUS_SUCCESS;
}

static qsc_asn1_status qsc_x509_certwrite_upsert_extension(qsc_x509_extensions* extensions, qsc_x509_extension_type type, qsc_oid_id oidid, bool critical, const uint8_t* value, size_t valuelen)
{
    size_t idx = 0U;
    qsc_x509_extension* extension = NULL;

    if ((extensions == NULL) || ((value == NULL) && (valuelen != 0U)))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

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

    extension->type = type;
    extension->oid = oidid;
    extension->critical = critical;
    extension->valuelen = valuelen;

    if (valuelen != 0U)
    {
        if (valuelen > sizeof(extension->value))
        {
            return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }

        qsc_memutils_copy(extension->value, value, valuelen);
    }

    return QSC_ASN1_STATUS_SUCCESS;
}

static bool qsc_x509_certwrite_is_self_issued(const qsc_x509_certificate_builder* builder)
{
    if (builder == NULL)
    {
        return false;
    }

    return qsc_x509_name_equals(&builder->issuer, &builder->subject);
}

static qsc_asn1_status qsc_x509_certwrite_prepare_extensions(const qsc_x509_certificate_builder* builder, qsc_x509_extensions* extensions)
{
    uint8_t payload[QSC_X509_SPKI_MAX] = { 0U };
    size_t payloadlen = sizeof(payload);
    qsc_asn1_status status = QSC_ASN1_STATUS_SUCCESS;

    if ((builder == NULL) || (extensions == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    qsc_memutils_copy(extensions, &builder->extensions, sizeof(*extensions));

    if (builder->extensions.basicconstraints.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_basic_constraints(&builder->extensions.basicconstraints, payload, &payloadlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = qsc_x509_certwrite_upsert_extension(
            extensions,
            QSC_X509_EXTENSION_BASIC_CONSTRAINTS,
            QSC_OID_ID_BASIC_CONSTRAINTS,
            builder->extensions.basicconstraints.critical,
            payload,
            payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;
    }

    if (builder->extensions.keyusage.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_key_usage(&builder->extensions.keyusage, payload, &payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;

        status = qsc_x509_certwrite_upsert_extension(
            extensions,
            QSC_X509_EXTENSION_KEY_USAGE,
            QSC_OID_ID_KEY_USAGE,
            builder->extensions.keyusage.critical,
            payload,
            payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;
    }

    if (builder->extensions.extendedkeyusage.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_extended_key_usage(&builder->extensions.extendedkeyusage, payload, &payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;

        status = qsc_x509_certwrite_upsert_extension(
            extensions,
            QSC_X509_EXTENSION_EXTENDED_KEY_USAGE,
            QSC_OID_ID_EXTENDED_KEY_USAGE,
            builder->extensions.extendedkeyusage.critical,
            payload,
            payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;
    }

    {
        qsc_x509_subject_key_identifier ski = { 0 };

        if (builder->extensions.subjectkeyidentifier.present == true)
        {
            ski = builder->extensions.subjectkeyidentifier;
        }
        else
        {
            status = qsc_x509_compute_subject_key_identifier(&builder->spki, &ski);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }
        }

        payloadlen = sizeof(payload);
        status = qsc_x509_write_subject_key_identifier(&ski, payload, &payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;

        status = qsc_x509_certwrite_upsert_extension(
            extensions,
            QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER,
            QSC_OID_ID_SUBJECT_KEY_IDENTIFIER,
            ski.critical,
            payload,
            payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;

        if (builder->extensions.authoritykeyidentifier.present == false)
        {
            qsc_x509_authority_key_identifier aki = { 0 };

            if (qsc_x509_certwrite_is_self_issued(builder) == true)
            {
                aki.present = true;
                aki.critical = false;
                aki.keyidentifierlen = ski.identifierlen;
                qsc_memutils_copy(aki.keyidentifier, ski.identifier, ski.identifierlen);
                payloadlen = sizeof(payload);
                status = qsc_x509_write_authority_key_identifier(&aki, payload, &payloadlen);
                if (status != QSC_ASN1_STATUS_SUCCESS) return status;

                status = qsc_x509_certwrite_upsert_extension(
                    extensions,
                    QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER,
                    QSC_OID_ID_AUTHORITY_KEY_IDENTIFIER,
                    aki.critical,
                    payload,
                    payloadlen);
                if (status != QSC_ASN1_STATUS_SUCCESS) return status;
            }
        }
    }

    if (builder->extensions.authoritykeyidentifier.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_authority_key_identifier(&builder->extensions.authoritykeyidentifier, payload, &payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;

        status = qsc_x509_certwrite_upsert_extension(
            extensions,
            QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER,
            QSC_OID_ID_AUTHORITY_KEY_IDENTIFIER,
            builder->extensions.authoritykeyidentifier.critical,
            payload,
            payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;
    }

    if (builder->extensions.subjectaltname.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_subject_alt_name(&builder->extensions.subjectaltname, payload, &payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;

        status = qsc_x509_certwrite_upsert_extension(
            extensions,
            QSC_X509_EXTENSION_SUBJECT_ALT_NAME,
            QSC_OID_ID_SUBJECT_ALT_NAME,
            builder->extensions.subjectaltname.critical,
            payload,
            payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;
    }

    if (builder->extensions.issueraltname.present == true)
    {
        payloadlen = sizeof(payload);
        status = qsc_x509_write_issuer_alt_name(&builder->extensions.issueraltname, payload, &payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;

        status = qsc_x509_certwrite_upsert_extension(
            extensions,
            QSC_X509_EXTENSION_ISSUER_ALT_NAME,
            QSC_OID_ID_ISSUER_ALT_NAME,
            builder->extensions.issueraltname.critical,
            payload,
            payloadlen);
        if (status != QSC_ASN1_STATUS_SUCCESS) return status;
    }

    return QSC_ASN1_STATUS_SUCCESS;
}

static bool qsc_x509_certwrite_key_usage_has_bits(const qsc_x509_key_usage* keyusage, uint16_t bits)
{
    return ((keyusage != NULL) && (keyusage->present == true) && ((keyusage->bits & bits) == bits));
}

static bool qsc_x509_certwrite_signature_algorithm_is_supported(const qsc_x509_algorithm_identifier* signaturealgorithm)
{
    if ((signaturealgorithm == NULL) || (signaturealgorithm->algorithm_oid.length == 0U))
    {
        return false;
    }

    return (qsc_x509_signature_algorithm_is_ecdsa(signaturealgorithm->signature) == true) ||
        (qsc_x509_signature_algorithm_is_ml_dsa(signaturealgorithm->signature) == true);
}

static bool qsc_x509_certwrite_spki_is_signature_capable(const qsc_x509_subject_public_key_info* spki)
{
    return (spki != NULL) &&
        ((spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_RSA) ||
         (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC) ||
         (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA));
}

static uint16_t qsc_x509_certwrite_default_tls_key_usage(const qsc_x509_subject_public_key_info* spki)
{
    if (spki != NULL)
    {
        if (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA)
        {
            return QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE;
        }

        if (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM)
        {
            return QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT;
        }
    }

    return (uint16_t)(QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE | QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT);
}

static bool qsc_x509_certwrite_name_is_empty(const qsc_x509_name* name)
{
    return ((name == NULL) || (name->count == 0U));
}

static qsc_asn1_status qsc_x509_certwrite_derive_key_identifier(const qsc_x509_subject_public_key_info* spki, uint8_t* keyid, size_t* keyidlen)
{
    uint8_t digest[QSC_SHA2_256_HASH_SIZE] = { 0U };

    if ((spki == NULL) || (keyid == NULL) || (keyidlen == NULL) || (spki->publickeylen == 0U))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (*keyidlen < QSC_SHA2_256_HASH_SIZE)
    {
        *keyidlen = QSC_SHA2_256_HASH_SIZE;
        return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    qsc_sha256_compute(digest, spki->publickey, spki->publickeylen);
    qsc_memutils_copy(keyid, digest, QSC_SHA2_256_HASH_SIZE);
    *keyidlen = QSC_SHA2_256_HASH_SIZE;
    return QSC_ASN1_STATUS_SUCCESS;
}

static qsc_asn1_status qsc_x509_certwrite_build_version(uint32_t version, uint8_t* output, size_t* outputlen)
{
    uint8_t integer[8] = { 0U };
    uint8_t value[4] = { 0U };
    size_t integerlen = sizeof(integer);
    size_t outerlen;
    qsc_asn1_status status;

    if ((output == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if ((version == 0U) || (version > 255U))
    {
        return QSC_ASN1_STATUS_OUT_OF_RANGE;
    }

    value[0] = (uint8_t)(version - 1U);

    status = qsc_x509_write_integer(value, 1U, integer, &integerlen);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    outerlen = *outputlen;
    status = qsc_x509_write_explicit(0U, integer, integerlen, output, &outerlen);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    *outputlen = outerlen;
    return QSC_ASN1_STATUS_SUCCESS;
}

static qsc_asn1_status qsc_x509_certwrite_has_extensions(const qsc_x509_certificate_builder* builder, bool* present)
{
    size_t idx = 0U;

    if ((builder == NULL) || (present == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    *present = false;

    if ((builder->extensions.basicconstraints.present == true) ||
        (builder->extensions.keyusage.present == true) ||
        (builder->extensions.extendedkeyusage.present == true) ||
        (builder->extensions.subjectkeyidentifier.present == true) ||
        (builder->extensions.authoritykeyidentifier.present == true) ||
        (builder->extensions.subjectaltname.present == true) ||
        (builder->extensions.issueraltname.present == true))
    {
        *present = true;
        return QSC_ASN1_STATUS_SUCCESS;
    }

    for (idx = 0U; idx < builder->extensions.count; ++idx)
    {
        if (builder->extensions.entries[idx].valuelen != 0U)
        {
            *present = true;
            break;
        }
    }

    return QSC_ASN1_STATUS_SUCCESS;
}

void qsc_x509_certificate_builder_initialize(qsc_x509_certificate_builder* builder)
{
    QSC_ASSERT(builder != NULL);

    if (builder != NULL)
    {
        qsc_memutils_clear(builder, sizeof(qsc_x509_certificate_builder));
        builder->version = 3U;
    }
}

void qsc_x509_certificate_builder_clear(qsc_x509_certificate_builder* builder)
{
    QSC_ASSERT(builder != NULL);

    if (builder != NULL)
    {
        qsc_memutils_clear(builder, sizeof(qsc_x509_certificate_builder));
    }
}

qsc_asn1_status qsc_x509_certificate_builder_set_serial(qsc_x509_certificate_builder* builder, const uint8_t* serialnumber, size_t serialnumberlen)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(serialnumber != NULL);

    size_t offset;
    size_t effectivelen;
    qsc_asn1_status status;

    if ((builder == NULL) || ((serialnumber == NULL) && (serialnumberlen != 0U)) || (serialnumberlen == 0U))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        offset = 0U;

        while ((offset < serialnumberlen) && (serialnumber[offset] == 0U))
        {
            ++offset;
        }

        effectivelen = serialnumberlen - offset;

        if (effectivelen == 0U)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if (effectivelen > sizeof(builder->serialnumber))
        {
            status = QSC_ASN1_STATUS_OUT_OF_RANGE;
        }
        else
        {
            qsc_memutils_clear(builder->serialnumber, sizeof(builder->serialnumber));
            qsc_memutils_copy(builder->serialnumber, serialnumber + offset, effectivelen);
            builder->serialnumberlen = effectivelen;
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_issuer(qsc_x509_certificate_builder* builder, const qsc_x509_name* issuer)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(issuer != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (issuer != NULL))
    {
        qsc_memutils_copy(&builder->issuer, issuer, sizeof(*issuer));
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_subject(qsc_x509_certificate_builder* builder, const qsc_x509_name* subject)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(subject != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (subject != NULL))
    {
        qsc_memutils_copy(&builder->subject, subject, sizeof(*subject));
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_validity(qsc_x509_certificate_builder* builder, const qsc_x509_validity* validity)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(validity != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (validity != NULL))
    {
        if (qsc_asn1_time_compare(&validity->notbefore, &validity->notafter) > 0)
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
        else
        {
            qsc_memutils_copy(&builder->validity, validity, sizeof(*validity));
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_spki(qsc_x509_certificate_builder* builder, const qsc_x509_subject_public_key_info* spki)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(spki != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (spki != NULL))
    {
        status = qsc_x509_spki_validate(spki);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_memutils_copy(&builder->spki, spki, sizeof(*spki));
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_signature_algorithm(qsc_x509_certificate_builder* builder, const qsc_x509_algorithm_identifier* signaturealgorithm)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(signaturealgorithm != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (signaturealgorithm != NULL))
    {
        if (qsc_x509_certwrite_signature_algorithm_is_supported(signaturealgorithm) == false)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else
        {
            qsc_memutils_copy(&builder->signaturealgorithm, signaturealgorithm, sizeof(*signaturealgorithm));
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_basic_constraints(qsc_x509_certificate_builder* builder, const qsc_x509_basic_constraints* basicconstraints)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(basicconstraints != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (basicconstraints != NULL))
    {
        qsc_memutils_copy(&builder->extensions.basicconstraints, basicconstraints, sizeof(*basicconstraints));
        builder->extensions.basicconstraints.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_key_usage(qsc_x509_certificate_builder* builder, const qsc_x509_key_usage* keyusage)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(keyusage != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (keyusage != NULL))
    {
        qsc_memutils_copy(&builder->extensions.keyusage, keyusage, sizeof(*keyusage));
        builder->extensions.keyusage.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_extended_key_usage(qsc_x509_certificate_builder* builder, const qsc_x509_extended_key_usage* extendedkeyusage)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(extendedkeyusage != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (extendedkeyusage != NULL))
    {
        qsc_memutils_copy(&builder->extensions.extendedkeyusage, extendedkeyusage, sizeof(*extendedkeyusage));
        builder->extensions.extendedkeyusage.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_subject_key_identifier(qsc_x509_certificate_builder* builder, const qsc_x509_subject_key_identifier* subjectkeyidentifier)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(subjectkeyidentifier != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (subjectkeyidentifier != NULL))
    {
        qsc_memutils_copy(&builder->extensions.subjectkeyidentifier, subjectkeyidentifier, sizeof(*subjectkeyidentifier));
        builder->extensions.subjectkeyidentifier.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_set_authority_key_identifier(qsc_x509_certificate_builder* builder, const qsc_x509_authority_key_identifier* authoritykeyidentifier)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(authoritykeyidentifier != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (authoritykeyidentifier != NULL))
    {
        qsc_memutils_copy(&builder->extensions.authoritykeyidentifier, authoritykeyidentifier, sizeof(*authoritykeyidentifier));
        builder->extensions.authoritykeyidentifier.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_add_subject_alt_name_dns(qsc_x509_certificate_builder* builder, const char* dnsname, size_t dnsnamelen)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(dnsname != NULL);

    qsc_x509_general_name* entry = NULL;
    qsc_asn1_status status;

    if ((builder == NULL) || ((dnsname == NULL) && (dnsnamelen != 0U)) || (dnsnamelen == 0U))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (dnsnamelen > QSC_X509_NAME_ATTRIBUTE_STRING_MAX)
    {
        status = QSC_ASN1_STATUS_OUT_OF_RANGE;
    }
    else if (builder->extensions.subjectaltname.count >= QSC_X509_SAN_ENTRIES_MAX)
    {
        status = QSC_ASN1_STATUS_OUT_OF_RANGE;
    }
    else
    {
        entry = &builder->extensions.subjectaltname.entries[builder->extensions.subjectaltname.count++];
        qsc_memutils_clear(entry, sizeof(qsc_x509_general_name));
        entry->type = QSC_X509_GENERAL_NAME_DNS_NAME;
        entry->length = dnsnamelen;
        qsc_memutils_copy(entry->data, dnsname, dnsnamelen);
        builder->extensions.subjectaltname.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_add_subject_alt_name_ip(qsc_x509_certificate_builder* builder, const uint8_t* address, size_t addresslen)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(address != NULL);

    qsc_x509_general_name* entry = NULL;
    qsc_asn1_status status;

    if ((builder == NULL) || ((address == NULL) && (addresslen != 0U)))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((addresslen != 4U) && (addresslen != 16U))
    {
        status = QSC_ASN1_STATUS_OUT_OF_RANGE;
    }
    else if (builder->extensions.subjectaltname.count >= QSC_X509_SAN_ENTRIES_MAX)
    {
        status = QSC_ASN1_STATUS_OUT_OF_RANGE;
    }
    else
    {
        entry = &builder->extensions.subjectaltname.entries[builder->extensions.subjectaltname.count++];
        qsc_memutils_clear(entry, sizeof(qsc_x509_general_name));
        entry->type = QSC_X509_GENERAL_NAME_IP_ADDRESS;
        entry->length = addresslen;
        qsc_memutils_copy(entry->data, address, addresslen);
        builder->extensions.subjectaltname.present = true;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_add_extension(qsc_x509_certificate_builder* builder, const qsc_x509_extension* extension)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(extension != NULL);

    qsc_asn1_status status;
    size_t i;
    bool duplicate;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    i = 0U;
    duplicate = false;

    if ((builder != NULL) && (extension != NULL))
    {
        if (builder->extensions.count >= QSC_X509_EXTENSIONS_MAX)
        {
            status = QSC_ASN1_STATUS_OUT_OF_RANGE;
        }
        else
        {
            for (i = 0U; i < builder->extensions.count; ++i)
            {
                const qsc_x509_extension* current;

                current = &builder->extensions.entries[i];

                if ((((extension->type != QSC_X509_EXTENSION_UNKNOWN) && (current->type == extension->type)) ||
                    ((extension->extension_oid.length != 0U) &&
                        (current->extension_oid.length != 0U) &&
                        (qsc_asn1_oid_compare(&current->extension_oid, &extension->extension_oid) == true))))
                {
                    duplicate = true;
                    break;
                }
            }

            if (duplicate == true)
            {
                status = QSC_ASN1_STATUS_INVALID_INPUT;
            }
            else
            {
                qsc_memutils_copy(&builder->extensions.entries[builder->extensions.count], extension, sizeof(*extension));
                builder->extensions.count++;
                status = QSC_ASN1_STATUS_SUCCESS;
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_encode_tbs_der(const qsc_x509_certificate_builder* builder, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t content[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
    uint8_t extensionsseq[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
    qsc_x509_extensions extensions;
    size_t pos = 0U;
    size_t len = 0U;
    bool hasextensions = false;
    qsc_asn1_status status;

    if ((builder == NULL) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (builder->serialnumberlen == 0U)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        len = sizeof(content) - pos;
        status = qsc_x509_certwrite_build_version(builder->version, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
        len = sizeof(content) - pos;
        status = qsc_x509_write_integer(builder->serialnumber, builder->serialnumberlen, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
        len = sizeof(content) - pos;
        status = qsc_x509_write_algorithm_identifier(&builder->signaturealgorithm, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
        len = sizeof(content) - pos;
        status = qsc_x509_write_name(&builder->issuer, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
        len = sizeof(content) - pos;
        status = qsc_x509_write_validity(&builder->validity, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
        len = sizeof(content) - pos;
        status = qsc_x509_write_name(&builder->subject, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
        len = sizeof(content) - pos;
        status = qsc_x509_write_spki(&builder->spki, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
        status = qsc_x509_certwrite_has_extensions(builder, &hasextensions);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        if (hasextensions == true)
        {
            qsc_memutils_clear(&extensions, sizeof(qsc_x509_extensions));
            status = qsc_x509_certwrite_prepare_extensions(builder, &extensions);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }

            len = sizeof(extensionsseq);
            status = qsc_x509_write_extensions(&extensions, extensionsseq, &len);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }

            {
                size_t explen = sizeof(content) - pos;
                status = qsc_x509_write_explicit(3U, extensionsseq, len, content + pos, &explen);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    return status;
                }

                pos += explen;
            }
        }

        status = qsc_x509_write_sequence(content, pos, output, outputlen);
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_sign(const qsc_x509_certificate_builder* builder, qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(signcallback != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t tbs[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
    uint8_t content[QSC_X509_CERTIFICATE_WRITE_MAX] = { 0U };
    uint8_t signature[QSC_X509_SIGNATURE_MAX] = { 0U };
    size_t tbslen;
    size_t pos;
    size_t len;
    size_t siglen;
    qsc_asn1_status status;

    tbslen = sizeof(tbs);
    pos = 0U;
    len = 0U;
    siglen = sizeof(signature);

    if ((builder == NULL) || (signcallback == NULL) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (qsc_x509_certwrite_signature_algorithm_is_supported(&builder->signaturealgorithm) == false)
    {
        status = QSC_ASN1_STATUS_UNSUPPORTED;
    }
    else
    {
        status = qsc_x509_certificate_builder_encode_tbs_der(builder, tbs, &tbslen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = signcallback(builder->signaturealgorithm.signature, tbs, tbslen, signature, &siglen, context);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                if (siglen > QSC_X509_SIGNATURE_MAX)
                {
                    status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                }
                else if ((sizeof(content) - pos) < tbslen)
                {
                    status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    qsc_memutils_copy(content + pos, tbs, tbslen);
                    pos += tbslen;
                    len = sizeof(content) - pos;
                    status = qsc_x509_write_algorithm_identifier(&builder->signaturealgorithm, content + pos, &len);

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

qsc_asn1_status qsc_x509_certificate_builder_set_issuer_from_certificate(qsc_x509_certificate_builder* builder, const qsc_x509_certificate* issuer)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(issuer != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (issuer != NULL))
    {
        qsc_memutils_copy(&builder->issuer, &issuer->subject, sizeof(builder->issuer));
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_compute_subject_key_identifier(const qsc_x509_subject_public_key_info* spki, qsc_x509_subject_key_identifier* subjectkeyidentifier)
{
    QSC_ASSERT(spki != NULL);
    QSC_ASSERT(subjectkeyidentifier != NULL);

    size_t keyidlen;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((spki != NULL) && (subjectkeyidentifier != NULL))
    {
        keyidlen = QSC_X509_KEY_IDENTIFIER_MAX;
        qsc_memutils_clear(subjectkeyidentifier, sizeof(qsc_x509_subject_key_identifier));
        subjectkeyidentifier->present = true;
        subjectkeyidentifier->critical = false;
        status = qsc_x509_certwrite_derive_key_identifier(spki, subjectkeyidentifier->identifier, &keyidlen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            subjectkeyidentifier->identifierlen = keyidlen;
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_compute_authority_key_identifier(const qsc_x509_certificate* issuer, qsc_x509_authority_key_identifier* authoritykeyidentifier)
{
    QSC_ASSERT(issuer != NULL);
    QSC_ASSERT(authoritykeyidentifier != NULL);

    size_t keyidlen;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((issuer != NULL) && (authoritykeyidentifier != NULL))
    {
        keyidlen = QSC_X509_KEY_IDENTIFIER_MAX;
        qsc_memutils_clear(authoritykeyidentifier, sizeof(qsc_x509_authority_key_identifier));
        authoritykeyidentifier->present = true;
        authoritykeyidentifier->critical = false;

        if ((issuer->extensions.subjectkeyidentifier.present == true) && (issuer->extensions.subjectkeyidentifier.identifierlen != 0U))
        {
            authoritykeyidentifier->keyidentifierlen = issuer->extensions.subjectkeyidentifier.identifierlen;
            qsc_memutils_copy(authoritykeyidentifier->keyidentifier, issuer->extensions.subjectkeyidentifier.identifier, issuer->extensions.subjectkeyidentifier.identifierlen);
            status = QSC_ASN1_STATUS_SUCCESS;
        }
        else
        {
            status = qsc_x509_certwrite_derive_key_identifier(&issuer->subjectpublickeyinfo, authoritykeyidentifier->keyidentifier, &keyidlen);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                authoritykeyidentifier->keyidentifierlen = keyidlen;
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_apply_generated_identifiers(qsc_x509_certificate_builder* builder, const qsc_x509_certificate* issuer)
{
    QSC_ASSERT(builder != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_SUCCESS;

    if (builder != NULL)
    {
        if (builder->extensions.subjectkeyidentifier.present == false)
        {
            status = qsc_x509_compute_subject_key_identifier(&builder->spki, &builder->extensions.subjectkeyidentifier);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (builder->extensions.authoritykeyidentifier.present == false)
            {
                if (issuer != NULL)
                {
                    status = qsc_x509_compute_authority_key_identifier(issuer, &builder->extensions.authoritykeyidentifier);
                }
                else if (qsc_x509_certwrite_is_self_issued(builder) == true)
                {
                    builder->extensions.authoritykeyidentifier.present = true;
                    builder->extensions.authoritykeyidentifier.critical = false;
                    builder->extensions.authoritykeyidentifier.keyidentifierlen = builder->extensions.subjectkeyidentifier.identifierlen;

                    qsc_memutils_copy(builder->extensions.authoritykeyidentifier.keyidentifier,
                        builder->extensions.subjectkeyidentifier.identifier,
                        builder->extensions.subjectkeyidentifier.identifierlen);
                }
            }
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_apply_profile(qsc_x509_certificate_builder* builder, uint32_t profile)
{
    QSC_ASSERT(builder != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (builder != NULL)
    {
        switch (profile)
        {
            case QSC_X509_CERT_PROFILE_ROOT_CA:
            case QSC_X509_CERT_PROFILE_INTERMEDIATE_CA:
            {
                qsc_memutils_clear(&builder->extensions.basicconstraints, sizeof(builder->extensions.basicconstraints));
                builder->extensions.basicconstraints.present = true;
                builder->extensions.basicconstraints.critical = true;
                builder->extensions.basicconstraints.ca = true;
                qsc_memutils_clear(&builder->extensions.keyusage, sizeof(builder->extensions.keyusage));
                builder->extensions.keyusage.present = true;
                builder->extensions.keyusage.critical = true;
                builder->extensions.keyusage.bits = (uint16_t)(QSC_X509_KEY_USAGE_KEY_CERT_SIGN | QSC_X509_KEY_USAGE_CRL_SIGN);
                status = QSC_ASN1_STATUS_SUCCESS;
                break;
            }
            case QSC_X509_CERT_PROFILE_TLS_SERVER:
            {
                qsc_memutils_clear(&builder->extensions.basicconstraints, sizeof(builder->extensions.basicconstraints));
                builder->extensions.basicconstraints.present = true;
                builder->extensions.basicconstraints.critical = true;
                builder->extensions.basicconstraints.ca = false;
                builder->extensions.basicconstraints.pathlen_present = false;
                qsc_memutils_clear(&builder->extensions.keyusage, sizeof(builder->extensions.keyusage));
                builder->extensions.keyusage.present = true;
                builder->extensions.keyusage.critical = true;
                builder->extensions.keyusage.bits = qsc_x509_certwrite_default_tls_key_usage(&builder->spki);
                qsc_memutils_clear(&builder->extensions.extendedkeyusage, sizeof(builder->extensions.extendedkeyusage));
                builder->extensions.extendedkeyusage.present = true;
                builder->extensions.extendedkeyusage.critical = false;
                builder->extensions.extendedkeyusage.bits = QSC_X509_EXTENDED_KEY_USAGE_SERVER_AUTH;
                status = QSC_ASN1_STATUS_SUCCESS;
                break;
            }
            case QSC_X509_CERT_PROFILE_TLS_CLIENT:
            {
                qsc_memutils_clear(&builder->extensions.basicconstraints, sizeof(builder->extensions.basicconstraints));
                builder->extensions.basicconstraints.present = true;
                builder->extensions.basicconstraints.critical = true;
                builder->extensions.basicconstraints.ca = false;
                builder->extensions.basicconstraints.pathlen_present = false;
                qsc_memutils_clear(&builder->extensions.keyusage, sizeof(builder->extensions.keyusage));
                builder->extensions.keyusage.present = true;
                builder->extensions.keyusage.critical = true;
                builder->extensions.keyusage.bits = qsc_x509_certwrite_default_tls_key_usage(&builder->spki);
                qsc_memutils_clear(&builder->extensions.extendedkeyusage, sizeof(builder->extensions.extendedkeyusage));
                builder->extensions.extendedkeyusage.present = true;
                builder->extensions.extendedkeyusage.critical = false;
                builder->extensions.extendedkeyusage.bits = QSC_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH;
                status = QSC_ASN1_STATUS_SUCCESS;
                break;
            }
            case QSC_X509_CERT_PROFILE_NONE:
            {
                status = QSC_ASN1_STATUS_SUCCESS;
                break;
            }
            default:
                status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_builder_validate_profile(const qsc_x509_certificate_builder* builder, const qsc_x509_certificate* issuer, uint32_t profile)
{
    QSC_ASSERT(builder != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_SUCCESS;

    if ((builder == NULL) || (builder->serialnumberlen == 0U) ||
        (qsc_x509_certwrite_name_is_empty(&builder->issuer) == true) ||
        (qsc_x509_certwrite_name_is_empty(&builder->subject) == true) ||
        (builder->spki.publickeylen == 0U) ||
        (builder->signaturealgorithm.algorithm_oid.length == 0U))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (builder->extensions.subjectkeyidentifier.present == false)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (qsc_asn1_time_compare(&builder->validity.notbefore, &builder->validity.notafter) > 0)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (qsc_x509_certwrite_signature_algorithm_is_supported(&builder->signaturealgorithm) == false)
    {
        status = QSC_ASN1_STATUS_UNSUPPORTED;
    }
    else if (qsc_x509_spki_validate(&builder->spki) != QSC_ASN1_STATUS_SUCCESS)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (qsc_x509_certwrite_is_self_issued(builder) == true)
    {
        if ((qsc_x509_certwrite_spki_is_signature_capable(&builder->spki) == false) ||
            (qsc_x509_signature_algorithm_matches_spki(builder->signaturealgorithm.signature, &builder->spki) == false))
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
    }
    else if (issuer != NULL)
    {
        if ((qsc_x509_certwrite_spki_is_signature_capable(&issuer->subjectpublickeyinfo) == false) ||
            (qsc_x509_signature_algorithm_matches_spki(builder->signaturealgorithm.signature, &issuer->subjectpublickeyinfo) == false))
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
    }

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        switch (profile)
        {
            case QSC_X509_CERT_PROFILE_ROOT_CA:
            {
                if ((qsc_x509_certwrite_is_self_issued(builder) == false) ||
                    (builder->extensions.basicconstraints.present == false) ||
                    (builder->extensions.basicconstraints.ca == false) ||
                    (qsc_x509_certwrite_key_usage_has_bits(&builder->extensions.keyusage, QSC_X509_KEY_USAGE_KEY_CERT_SIGN) == false))
                {
                    status = QSC_ASN1_STATUS_INVALID_INPUT;
                }

                if ((status == QSC_ASN1_STATUS_SUCCESS) &&
                    (builder->extensions.authoritykeyidentifier.present == true) &&
                    ((builder->extensions.authoritykeyidentifier.keyidentifierlen != builder->extensions.subjectkeyidentifier.identifierlen) ||
                     (qsc_memutils_are_equal(builder->extensions.authoritykeyidentifier.keyidentifier,
                      builder->extensions.subjectkeyidentifier.identifier,
                      builder->extensions.subjectkeyidentifier.identifierlen) == false)))
                {
                    status = QSC_ASN1_STATUS_INVALID_INPUT;
                }

                break;
            }
            case QSC_X509_CERT_PROFILE_INTERMEDIATE_CA:
            {
                if ((issuer == NULL) ||
                    (issuer->extensions.basicconstraints.ca == false) ||
                    (qsc_x509_certwrite_key_usage_has_bits(&issuer->extensions.keyusage, QSC_X509_KEY_USAGE_KEY_CERT_SIGN) == false) ||
                    (builder->extensions.basicconstraints.present == false) ||
                    (builder->extensions.basicconstraints.ca == false) ||
                    (qsc_x509_certwrite_key_usage_has_bits(&builder->extensions.keyusage, QSC_X509_KEY_USAGE_KEY_CERT_SIGN) == false) ||
                    (qsc_x509_name_equals(&builder->issuer, &issuer->subject) == false) ||
                    (builder->extensions.authoritykeyidentifier.present == false))
                {
                    status = QSC_ASN1_STATUS_INVALID_INPUT;
                }

                break;
            }
            case QSC_X509_CERT_PROFILE_TLS_SERVER:
            {
                if ((issuer == NULL) ||
                    (issuer->extensions.basicconstraints.ca == false) ||
                    (qsc_x509_certwrite_key_usage_has_bits(&issuer->extensions.keyusage, QSC_X509_KEY_USAGE_KEY_CERT_SIGN) == false) ||
                    (builder->extensions.basicconstraints.present == false) ||
                    (builder->extensions.basicconstraints.ca == true) ||
                    (builder->extensions.basicconstraints.pathlen_present == true) ||
                    ((builder->extensions.keyusage.bits & (QSC_X509_KEY_USAGE_KEY_CERT_SIGN | QSC_X509_KEY_USAGE_CRL_SIGN)) != 0U) ||
                    (builder->extensions.extendedkeyusage.present == false) ||
                    ((builder->extensions.extendedkeyusage.bits & QSC_X509_EXTENDED_KEY_USAGE_SERVER_AUTH) == 0U) ||
                    (builder->extensions.authoritykeyidentifier.present == false) ||
                    (qsc_x509_name_equals(&builder->issuer, &issuer->subject) == false))
                {
                    status = QSC_ASN1_STATUS_INVALID_INPUT;
                }

                break;
            }
            case QSC_X509_CERT_PROFILE_TLS_CLIENT:
            {
                if ((issuer == NULL) ||
                    (issuer->extensions.basicconstraints.ca == false) ||
                    (qsc_x509_certwrite_key_usage_has_bits(&issuer->extensions.keyusage, QSC_X509_KEY_USAGE_KEY_CERT_SIGN) == false) ||
                    (builder->extensions.basicconstraints.present == false) ||
                    (builder->extensions.basicconstraints.ca == true) ||
                    (builder->extensions.basicconstraints.pathlen_present == true) ||
                    ((builder->extensions.keyusage.bits & (QSC_X509_KEY_USAGE_KEY_CERT_SIGN | QSC_X509_KEY_USAGE_CRL_SIGN)) != 0U) ||
                    (builder->extensions.extendedkeyusage.present == false) ||
                    ((builder->extensions.extendedkeyusage.bits & QSC_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH) == 0U) ||
                    (builder->extensions.authoritykeyidentifier.present == false) ||
                    (qsc_x509_name_equals(&builder->issuer, &issuer->subject) == false))
                {
                    status = QSC_ASN1_STATUS_INVALID_INPUT;
                }

                break;
            }
            case QSC_X509_CERT_PROFILE_NONE:
            {
                break;
            }
            default:
            {
                status = QSC_ASN1_STATUS_UNSUPPORTED;
                break;
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_certificate_encode_pem(const uint8_t* der, size_t derlen, char* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    const char* begin;
    const char* end;
    size_t beginlen;
    size_t endlen;
    size_t required;
    size_t i;
    size_t o;
    size_t linecount;
    qsc_asn1_status status;

    begin = QSC_X509_CERTWRITE_PEM_BEGIN;
    end = QSC_X509_CERTWRITE_PEM_END;
    beginlen = qsc_stringutils_string_size(begin);
    endlen = qsc_stringutils_string_size(end);
    required = qsc_x509_certwrite_get_pem_length(derlen);
    i = 0U;
    o = 0U;
    linecount = 0U;
    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (((der == NULL) && (derlen != 0U)) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((output == NULL) || (*outputlen < required))
    {
        *outputlen = required;
        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        qsc_memutils_copy(output + o, begin, beginlen);
        o += beginlen;

        for (i = 0U; i < derlen; i += 3U)
        {
            uint32_t v;
            size_t rem;

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

            output[o] = qsc_x509_certwrite_b64_table[(v >> 18U) & 0x3FU];
            ++o;
            output[o] = qsc_x509_certwrite_b64_table[(v >> 12U) & 0x3FU];
            ++o;
            output[o] = (rem > 1U) ? qsc_x509_certwrite_b64_table[(v >> 6U) & 0x3FU] : '=';
            ++o;
            output[o] = (rem > 2U) ? qsc_x509_certwrite_b64_table[v & 0x3FU] : '=';
            ++o;

            linecount += 4U;

            if ((linecount == QSC_X509_CERTWRITE_PEM_LINE) && (o < required))
            {
                output[o] = '\n';
                ++o;
                linecount = 0U;
            }
        }

        if (linecount != 0U)
        {
            output[o] = '\n';
            ++o;
        }

        qsc_memutils_copy(output + o, end, endlen);
        o += endlen;
        output[o] = '\0';
        *outputlen = o + 1U;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_cert_issuance_validate_csr(const qsc_x509_csr* csr)
{
    QSC_ASSERT(csr != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_SUCCESS;

    if (csr != NULL)
    {
        if ((csr->subject.count == 0U) ||
            (csr->spki.publickeylen == 0U) ||
            (csr->signaturealgorithm.algorithm_oid.length == 0U) ||
            (csr->extensions.count > QSC_X509_EXTENSIONS_MAX) ||
            (csr->attributecount > QSC_X509_CSR_ATTRIBUTES_MAX))
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
        else if (qsc_x509_certwrite_has_duplicate_csr_attributes(csr) == true)
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
        else if (qsc_x509_certwrite_has_duplicate_requested_extensions(&csr->extensions) == true)
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }

        else if (qsc_x509_spki_validate(&csr->spki) != QSC_ASN1_STATUS_SUCCESS)
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
        else
        {
            switch (csr->signaturealgorithm.signature)
            {
                case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256:
                case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384:
                case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512:
                case QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44:
                case QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65:
                case QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87:
                {
                    if ((csr->signaturelen == 0U) ||
                        ((csr->infodata == NULL) && (csr->infodatalen != 0U)))
                    {
                        status = QSC_ASN1_STATUS_INVALID_INPUT;
                    }

                    if (qsc_x509_csr_verify(csr) == false)
                    {
                        status = QSC_ASN1_STATUS_FAILURE;
                    }

                    break;
                }

                default:
                {
                    status = QSC_ASN1_STATUS_UNSUPPORTED;
                }
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_cert_issuance_filter_requested_extensions(const qsc_x509_csr* csr, uint32_t policyflags, qsc_x509_extensions* filteredextensions)
{
    QSC_ASSERT(csr != NULL);
    QSC_ASSERT(filteredextensions != NULL);

    size_t i = 0U;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_SUCCESS;

    if ((csr != NULL) && (filteredextensions != NULL))
    {
        qsc_memutils_clear(filteredextensions, sizeof(qsc_x509_extensions));
        status = qsc_x509_cert_issuance_validate_csr(csr);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            for (i = 0U; i < csr->extensions.count; ++i)
            {
                const qsc_x509_extension* extension;

                extension = &csr->extensions.entries[i];

                if (qsc_x509_certwrite_extension_allowed_by_policy(extension, policyflags) == false)
                {
                    if ((extension->critical == true) ||
                        (qsc_x509_certwrite_extension_type_is_known(extension->type) == true))
                    {
                        status = QSC_ASN1_STATUS_UNSUPPORTED;
                        break;
                    }

                    continue;
                }

                status = qsc_x509_certwrite_copy_filtered_extension(filteredextensions, extension);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    break;
                }

                switch (extension->type)
                {
                    case QSC_X509_EXTENSION_SUBJECT_ALT_NAME:
                    {
                        filteredextensions->subjectaltname = csr->extensions.subjectaltname;
                        filteredextensions->subjectaltname.present = true;
                        break;
                    }
                    case QSC_X509_EXTENSION_EXTENDED_KEY_USAGE:
                    {
                        filteredextensions->extendedkeyusage = csr->extensions.extendedkeyusage;
                        filteredextensions->extendedkeyusage.present = true;
                        break;
                    }
                    case QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER:
                    {
                        filteredextensions->subjectkeyidentifier = csr->extensions.subjectkeyidentifier;
                        filteredextensions->subjectkeyidentifier.present = true;
                        break;
                    }
                    default:
                        break;
                }
            }
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_cert_issuance_apply_csr_extensions(qsc_x509_certificate_builder* builder, const qsc_x509_csr* csr, uint32_t policyflags)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(csr != NULL);

    qsc_x509_extensions filtered;
    qsc_asn1_status status;
    size_t i;

    status = QSC_ASN1_STATUS_SUCCESS;
    i = 0U;

    if ((builder != NULL) && (csr != NULL))
    {
        status = qsc_x509_cert_issuance_filter_requested_extensions(csr, policyflags, &filtered);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if ((filtered.subjectaltname.present == true) && (builder->extensions.subjectaltname.present == false))
            {
                builder->extensions.subjectaltname = filtered.subjectaltname;
            }

            if ((filtered.extendedkeyusage.present == true) && (builder->extensions.extendedkeyusage.present == false))
            {
                builder->extensions.extendedkeyusage = filtered.extendedkeyusage;
            }

            if ((filtered.subjectkeyidentifier.present == true) && (builder->extensions.subjectkeyidentifier.present == false))
            {
                builder->extensions.subjectkeyidentifier = filtered.subjectkeyidentifier;
            }

            for (i = 0U; i < filtered.count; ++i)
            {
                const qsc_x509_extension* extension;
                bool duplicate = false;
                size_t j;

                j = 0U;
                extension = &filtered.entries[i];

                if (extension != NULL)
                {
                    switch (extension->type)
                    {
                        case QSC_X509_EXTENSION_SUBJECT_ALT_NAME:
                        case QSC_X509_EXTENSION_EXTENDED_KEY_USAGE:
                        case QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER:
                            continue;
                        default:
                            break;
                    }

                    for (j = 0U; j < builder->extensions.count; ++j)
                    {
                        const qsc_x509_extension* current = &builder->extensions.entries[j];

                        if (((extension->type != QSC_X509_EXTENSION_UNKNOWN) && (current->type == extension->type)) ||
                            ((extension->extension_oid.length != 0U) &&
                                (current->extension_oid.length != 0U) &&
                                (qsc_asn1_oid_compare(&current->extension_oid, &extension->extension_oid) == true)))
                        {
                            duplicate = true;
                            break;
                        }
                    }

                    if (duplicate == false)
                    {
                        status = qsc_x509_certificate_builder_add_extension(builder, extension);

                        if (status != QSC_ASN1_STATUS_SUCCESS)
                        {
                            break;
                        }
                    }
                }
                else
                {
                    status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                    break;
                }
            }
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}
