#include "x509crlwrite.h"
#include "encoding.h"
#include "memutils.h"
#include "stringutils.h"
#include "x509certwrite.h"
#include "x509name.h"
#include "x509sig.h"
#include "x509write.h"

#define QSC_X509_CRLWRITE_PEM_LABEL "X509 CRL"

static size_t qsc_x509_crlwrite_get_pem_length(size_t derlen)
{
    return ((derlen + 2U) / 3U) * 4U + 128U;
}

static qsc_asn1_status qsc_x509_crl_build_version(uint32_t version, uint8_t* output, size_t* outputlen)
{
    uint8_t value[4U] = { 0U };
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((output != NULL) && (outputlen != NULL))
    {
        if ((version == 0U) || (version > 255U))
        {
            status = QSC_ASN1_STATUS_OUT_OF_RANGE;
        }
        else
        {
            value[0U] = (uint8_t)(version - 1U);
            status = qsc_x509_write_integer(value, 1U, output, outputlen);
        }
    }

    return status;
}

static qsc_asn1_status qsc_x509_crl_write_time_choice(const qsc_asn1_time* value, uint8_t* output, size_t* outputlen)
{
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((value != NULL) && (outputlen != NULL))
    {
        if ((value->year < 1950U) || (value->year > 2049U))
        {
            status = qsc_x509_write_generalized_time(value, output, outputlen);
        }
        else
        {
            status = qsc_x509_write_utctime(value, output, outputlen);
        }
    }

    return status;
}

static bool qsc_x509_crlwrite_signature_algorithm_is_supported(const qsc_x509_algorithm_identifier* signaturealgorithm)
{
    bool res;

    res = false;

    if ((signaturealgorithm != NULL) && (signaturealgorithm->algorithm_oid.length != 0U))
    {
        res = (qsc_x509_signature_algorithm_is_ecdsa(signaturealgorithm->signature) == true) ||
            (qsc_x509_signature_algorithm_is_ml_dsa(signaturealgorithm->signature) == true);
    }

    return res;
}

static bool qsc_x509_crlwrite_spki_is_signature_capable(const qsc_x509_subject_public_key_info* spki)
{
    bool res;

    res = (spki != NULL) &&
        ((spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_RSA) ||
         (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC) ||
         (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA));

    return res;
}

static size_t qsc_x509_crlwrite_trim_serial_offset(const uint8_t* serialnumber, size_t serialnumberlen)
{
    size_t offset;

    offset = 0U;

    if (serialnumber != NULL)
    {
        while ((offset < serialnumberlen) && (serialnumber[offset] == 0U))
        {
            ++offset;
        }
    }

    return offset;
}

static qsc_asn1_status qsc_x509_crlwrite_copy_normalized_integer(const uint8_t* value, size_t valuelen, uint8_t* output, size_t outputcap, size_t* outputlen)
{
    size_t offset;
    size_t length;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((value == NULL) || (output == NULL) || (outputlen == NULL))
    {
        return status;
    }

    offset = qsc_x509_crlwrite_trim_serial_offset(value, valuelen);
    length = valuelen - offset;

    if (length == 0U)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (length > outputcap)
    {
        return QSC_ASN1_STATUS_OUT_OF_RANGE;
    }

    qsc_memutils_clear(output, outputcap);
    qsc_memutils_copy(output, value + offset, length);
    *outputlen = length;

    return QSC_ASN1_STATUS_SUCCESS;
}

static bool qsc_x509_crlwrite_serials_equal(const uint8_t* left, size_t leftlen, const uint8_t* right, size_t rightlen)
{
    size_t leftoffset;
    size_t rightoffset;
    size_t lefttrimmed;
    size_t righttrimmed;
    bool res;

    leftoffset = qsc_x509_crlwrite_trim_serial_offset(left, leftlen);
    rightoffset = qsc_x509_crlwrite_trim_serial_offset(right, rightlen);
    lefttrimmed = leftlen - leftoffset;
    righttrimmed = rightlen - rightoffset;
    res = false;

    if ((lefttrimmed != 0U) && (lefttrimmed == righttrimmed) && (left != NULL) && (right != NULL))
    {
        res = qsc_memutils_are_equal(left + leftoffset, right + rightoffset, lefttrimmed);
    }

    return res;
}

static qsc_asn1_status qsc_x509_crl_has_extensions(const qsc_x509_extensions* extensions, bool* present)
{
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((extensions != NULL) && (present != NULL))
    {
        *present = false;

        if ((extensions->authoritykeyidentifier.present == true) ||
            (extensions->issueraltname.present == true) ||
            (extensions->crlnumber.present == true))
        {
            *present = true;
            status = QSC_ASN1_STATUS_SUCCESS;
        }

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            for (size_t i = 0U; i < extensions->count; ++i)
            {
                if (extensions->entries[i].valuelen != 0U)
                {
                    *present = true;
                    break;
                }
            }

            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    return status;
}

static qsc_asn1_status qsc_x509_crl_upsert_extension(qsc_x509_extensions* extensions, qsc_x509_extension_type type, qsc_oid_id oidid, bool critical, const uint8_t* value, size_t valuelen)
{
    qsc_x509_extension* entry;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_SUCCESS;

    if ((extensions == NULL) || ((value == NULL) && (valuelen != 0U)))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        entry = NULL;

        for (size_t idx = 0U; idx < extensions->count; ++idx)
        {
            if (extensions->entries[idx].type == type)
            {
                entry = &extensions->entries[idx];
                break;
            }
        }

        if (entry == NULL)
        {
            if (extensions->count >= QSC_X509_EXTENSIONS_MAX)
            {
                status = QSC_ASN1_STATUS_OUT_OF_RANGE;
            }
            else
            {
                entry = &extensions->entries[extensions->count++];
                qsc_memutils_clear(entry, sizeof(*entry));
            }
        }

        if (status != QSC_ASN1_STATUS_OUT_OF_RANGE)
        {
            entry->type = type;
            entry->oid = oidid;
            entry->critical = critical;
            entry->valuelen = valuelen;

            if (valuelen > sizeof(entry->value))
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                if (valuelen != 0U)
                {
                    qsc_memutils_copy(entry->value, value, valuelen);
                }
            }
        }
    }

    return status;
}

static qsc_asn1_status qsc_x509_crl_prepare_extensions(const qsc_x509_extensions* input, qsc_x509_extensions* output)
{
    uint8_t payload[QSC_X509_CRL_WRITE_MAX] = { 0U };
    size_t payloadlen;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_SUCCESS;

    if ((input == NULL) || (output == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_memutils_copy(output, input, sizeof(*output));

        if (input->authoritykeyidentifier.present == true)
        {
            payloadlen = sizeof(payload);
            status = qsc_x509_write_authority_key_identifier(&input->authoritykeyidentifier, payload, &payloadlen);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_x509_crl_upsert_extension(output,
                    QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER,
                    QSC_OID_ID_AUTHORITY_KEY_IDENTIFIER,
                    input->authoritykeyidentifier.critical,
                    payload,
                    payloadlen);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    return status;
                }
            }
        }

        if (input->issueraltname.present == true)
        {
            payloadlen = sizeof(payload);
            status = qsc_x509_write_issuer_alt_name(&input->issueraltname, payload, &payloadlen);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_x509_crl_upsert_extension(output,
                    QSC_X509_EXTENSION_ISSUER_ALT_NAME,
                    QSC_OID_ID_ISSUER_ALT_NAME,
                    input->issueraltname.critical,
                    payload,
                    payloadlen);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    return status;
                }
            }
        }

        if (input->crlnumber.present == true)
        {
            payloadlen = sizeof(payload);
            status = qsc_x509_write_integer(input->crlnumber.value, input->crlnumber.valuelen, payload, &payloadlen);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_x509_crl_upsert_extension(output,
                    QSC_X509_EXTENSION_CRL_NUMBER,
                    QSC_OID_ID_CRL_NUMBER,
                    input->crlnumber.critical,
                    payload,
                    payloadlen);
            }
        }
    }

    return status;
}

static qsc_asn1_status qsc_x509_crl_encode_revoked_entry(const qsc_x509_crl_entry* entry, uint8_t* output, size_t* outputlen)
{
    uint8_t content[QSC_X509_CRL_ENTRY_MAX] = { 0U };
    size_t pos;
    size_t len;
    qsc_asn1_status status = QSC_ASN1_STATUS_SUCCESS;

    if ((entry == NULL) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (entry->serialnumberlen == 0U)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        pos = 0U;
        len = sizeof(content) - pos;
        status = qsc_x509_write_integer(entry->serialnumber, entry->serialnumberlen, content + pos, &len);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            pos += len;
            len = sizeof(content) - pos;
            status = qsc_x509_crl_write_time_choice(&entry->revocationdate, content + pos, &len);
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            pos += len;

            if (entry->rawextensionslen != 0U)
            {
                if (entry->rawextensionslen > (sizeof(content) - pos))
                {
                    status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                }
                else
                {
                    qsc_memutils_copy(content + pos, entry->rawextensions, entry->rawextensionslen);
                    pos += entry->rawextensionslen;
                }
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_x509_write_sequence(content, pos, output, outputlen);
        }
    }

    return status;
}

void qsc_x509_crl_builder_initialize(qsc_x509_crl_builder* builder)
{
    QSC_ASSERT(builder != NULL);

    if (builder != NULL)
    {
        qsc_memutils_clear(builder, sizeof(qsc_x509_crl_builder));
        builder->version = 2U;
    }
}

void qsc_x509_crl_builder_clear(qsc_x509_crl_builder* builder)
{
    QSC_ASSERT(builder != NULL);

    if (builder != NULL)
    {
        qsc_memutils_clear(builder, sizeof(qsc_x509_crl_builder));
    }
}

qsc_asn1_status qsc_x509_crl_builder_set_issuer(qsc_x509_crl_builder* builder, const qsc_x509_name* issuer)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(issuer != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (issuer != NULL))
    {
        qsc_memutils_copy(&builder->issuer, issuer, sizeof(qsc_x509_name));
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_crl_builder_set_update_times(qsc_x509_crl_builder* builder, const qsc_asn1_time* thisupdate, const qsc_asn1_time* nextupdate)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(thisupdate != NULL);
    QSC_ASSERT(nextupdate != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (thisupdate != NULL) && (nextupdate != NULL))
    {
        if (qsc_asn1_time_compare(thisupdate, nextupdate) > 0)
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
        else
        {
            qsc_memutils_copy(&builder->validity.notbefore, thisupdate, sizeof(*thisupdate));
            qsc_memutils_copy(&builder->validity.notafter, nextupdate, sizeof(*nextupdate));
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_crl_builder_set_signature_algorithm(qsc_x509_crl_builder* builder, const qsc_x509_algorithm_identifier* signaturealgorithm)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(signaturealgorithm != NULL);
    
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (signaturealgorithm != NULL))
    {
        if (qsc_x509_crlwrite_signature_algorithm_is_supported(signaturealgorithm) == false)
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

qsc_asn1_status qsc_x509_crl_builder_set_authority_key_identifier(qsc_x509_crl_builder* builder, const qsc_x509_authority_key_identifier* authoritykeyidentifier)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(authoritykeyidentifier != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (authoritykeyidentifier != NULL))
    {
        qsc_memutils_copy(&builder->extensions.authoritykeyidentifier, authoritykeyidentifier, sizeof(qsc_x509_authority_key_identifier));
        builder->extensions.authoritykeyidentifier.present = (builder->extensions.authoritykeyidentifier.keyidentifierlen != 0U) ||
            (builder->extensions.authoritykeyidentifier.issuer_present == true) ||
            (builder->extensions.authoritykeyidentifier.serial_present == true);
        status = builder->extensions.authoritykeyidentifier.present ? QSC_ASN1_STATUS_SUCCESS : QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_crl_builder_set_authority_key_identifier_from_issuer(qsc_x509_crl_builder* builder, const qsc_x509_certificate* issuer)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(issuer != NULL);

    qsc_x509_authority_key_identifier authoritykeyidentifier;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    qsc_memutils_clear(&authoritykeyidentifier, sizeof(authoritykeyidentifier));

    if ((builder != NULL) && (issuer != NULL))
    {
        status = qsc_x509_compute_authority_key_identifier(issuer, &authoritykeyidentifier);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_x509_crl_builder_set_authority_key_identifier(builder, &authoritykeyidentifier);
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_compute_authority_key_identifier_from_issuer(const qsc_x509_certificate* issuer, qsc_x509_authority_key_identifier* authoritykeyidentifier)
{
    QSC_ASSERT(issuer != NULL);
    QSC_ASSERT(authoritykeyidentifier != NULL);

    if ((issuer == NULL) || (authoritykeyidentifier == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return qsc_x509_compute_authority_key_identifier(issuer, authoritykeyidentifier);
}

qsc_asn1_status qsc_x509_crl_builder_set_crl_number(qsc_x509_crl_builder* builder, const uint8_t* value, size_t valuelen, bool critical)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(value != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (value != NULL))
    {
        status = qsc_x509_crlwrite_copy_normalized_integer(value, valuelen, builder->extensions.crlnumber.value, sizeof(builder->extensions.crlnumber.value), &builder->extensions.crlnumber.valuelen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            builder->extensions.crlnumber.present = true;
            builder->extensions.crlnumber.critical = critical;
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_crl_builder_validate_issuer(const qsc_x509_crl_builder* builder, const qsc_x509_certificate* issuer)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(issuer != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_SUCCESS;

    if ((builder != NULL) && (issuer != NULL))
    {
        if (qsc_x509_crlwrite_signature_algorithm_is_supported(&builder->signaturealgorithm) == false)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else if (qsc_x509_name_equals(&builder->issuer, &issuer->subject) == false)
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
        else if ((issuer->extensions.basicconstraints.present == false) ||
            (issuer->extensions.basicconstraints.ca == false))
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
        else if ((qsc_x509_crlwrite_spki_is_signature_capable(&issuer->subjectpublickeyinfo) == false) ||
            (qsc_x509_signature_algorithm_matches_spki(builder->signaturealgorithm.signature, &issuer->subjectpublickeyinfo) == false))
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
        else if ((issuer->extensions.keyusage.present == true) &&
            ((issuer->extensions.keyusage.bits & QSC_X509_KEY_USAGE_CRL_SIGN) == 0U))
        {
            status = QSC_ASN1_STATUS_INVALID_INPUT;
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_crl_builder_add_revoked_serial(qsc_x509_crl_builder* builder, const uint8_t* serialnumber, size_t serialnumberlen, const qsc_asn1_time* revocationdate)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(serialnumber != NULL);
    QSC_ASSERT(revocationdate != NULL);

    qsc_x509_crl_entry* entry;
    size_t i;
    size_t offset;
    size_t effectivelen;
    qsc_asn1_status status;

    entry = NULL;
    i = 0U;
    offset = 0U;
    effectivelen = 0U;
    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((builder != NULL) && (revocationdate != NULL) && (serialnumber != NULL))
    {
        if ((serialnumberlen == 0U) || (serialnumberlen > QSC_X509_SERIAL_NUMBER_MAX))
        {
            status = QSC_ASN1_STATUS_OUT_OF_RANGE;
        }
        else if (builder->entrycount >= QSC_X509_CRL_REVOKED_MAX)
        {
            status = QSC_ASN1_STATUS_OUT_OF_RANGE;
        }
        else
        {
            offset = qsc_x509_crlwrite_trim_serial_offset(serialnumber, serialnumberlen);
            effectivelen = serialnumberlen - offset;

            if (effectivelen == 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                status = QSC_ASN1_STATUS_SUCCESS;

                for (i = 0U; i < builder->entrycount; ++i)
                {
                    if (qsc_x509_crlwrite_serials_equal(builder->entries[i].serialnumber, builder->entries[i].serialnumberlen, serialnumber, serialnumberlen) == true)
                    {
                        status = QSC_ASN1_STATUS_INVALID_INPUT;
                        break;
                    }
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    entry = &builder->entries[builder->entrycount++];
                    qsc_memutils_clear(entry, sizeof(*entry));
                    qsc_memutils_copy(entry->serialnumber, serialnumber + offset, effectivelen);
                    entry->serialnumberlen = effectivelen;
                    qsc_memutils_copy(&entry->revocationdate, revocationdate, sizeof(*revocationdate));
                }
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_crl_builder_add_extension(qsc_x509_crl_builder* builder, const qsc_x509_extension* extension)
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

qsc_asn1_status qsc_x509_crl_builder_encode_tbs_der(const qsc_x509_crl_builder* builder, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t content[QSC_X509_CRL_WRITE_MAX] = { 0U };
    uint8_t revokedseq[QSC_X509_CRL_WRITE_MAX] = { 0U };
    uint8_t extseq[QSC_X509_CRL_WRITE_MAX] = { 0U };
    qsc_x509_extensions prepared = { 0 };
    size_t pos;
    size_t len;
    size_t i;
    bool hasextensions;
    qsc_asn1_status status;

    pos = 0U;
    len = 0U;
    i = 0U;
    hasextensions = false;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((builder == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    len = sizeof(content) - pos;
    status = qsc_x509_crl_build_version(builder->version, content + pos, &len);

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
    status = qsc_x509_crl_write_time_choice(&builder->validity.notbefore, content + pos, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos += len;
    len = sizeof(content) - pos;
    status = qsc_x509_crl_write_time_choice(&builder->validity.notafter, content + pos, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos += len;

    if (builder->entrycount != 0U)
    {
        size_t revokedpos = 0U;

        for (i = 0U; i < builder->entrycount; ++i)
        {
            len = sizeof(revokedseq) - revokedpos;
            status = qsc_x509_crl_encode_revoked_entry(&builder->entries[i], revokedseq + revokedpos, &len);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }

            revokedpos += len;
        }

        len = sizeof(content) - pos;
        status = qsc_x509_write_sequence(revokedseq, revokedpos, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    status = qsc_x509_crl_has_extensions(&builder->extensions, &hasextensions);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    if (hasextensions == true)
    {
        size_t extlen = sizeof(extseq);

        status = qsc_x509_crl_prepare_extensions(&builder->extensions, &prepared);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = qsc_x509_write_extensions(&prepared, extseq, &extlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        len = sizeof(content) - pos;
        status = qsc_x509_write_explicit(0U, extseq, extlen, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

qsc_asn1_status qsc_x509_crl_builder_sign(const qsc_x509_crl_builder* builder, qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(builder != NULL);
    QSC_ASSERT(signcallback != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t tbs[QSC_X509_CRL_WRITE_MAX] = { 0U };
    uint8_t content[QSC_X509_CRL_WRITE_MAX] = { 0U };
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
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((builder == NULL) || (signcallback == NULL) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (qsc_x509_crlwrite_signature_algorithm_is_supported(&builder->signaturealgorithm) == false)
    {
        status = QSC_ASN1_STATUS_UNSUPPORTED;
    }
    else
    {
        status = qsc_x509_crl_builder_encode_tbs_der(builder, tbs, &tbslen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = signcallback(builder->signaturealgorithm.signature, tbs, tbslen, signature, &siglen, context);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                if ((sizeof(content) - pos) < tbslen)
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

qsc_asn1_status qsc_x509_crl_der_encode_pem(const uint8_t* der, size_t derlen, char* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (((der == NULL) && (derlen != 0U)) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((output == NULL) || (*outputlen == 0U))
    {
        *outputlen = qsc_x509_crlwrite_get_pem_length(derlen);
        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }
    else if (qsc_encoding_pem_encode(QSC_X509_CRLWRITE_PEM_LABEL, output, *outputlen, der, derlen) == false)
    {
        *outputlen = qsc_x509_crlwrite_get_pem_length(derlen);
        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        *outputlen = qsc_stringutils_string_size(output) + 1U;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

qsc_asn1_status qsc_x509_crl_encode_pem(const qsc_x509_crl* crl, char* output, size_t* outputlen)
{
    QSC_ASSERT(crl != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t der[QSC_X509_CRL_WRITE_MAX] = { 0U };
    size_t derlen;
    qsc_asn1_status status;

    if (crl == NULL || outputlen == NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        derlen = sizeof(der);
        status = qsc_x509_crl_encode_der(crl, der, &derlen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_x509_crl_der_encode_pem(der, derlen, output, outputlen); 
        }
    }

    return status;
}
