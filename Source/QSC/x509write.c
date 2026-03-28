#include "x509write.h"
#include "x509spki.h"
#include "memutils.h"
#include "stringutils.h"

#define QSC_X509_WRITE_TAG_CONSTRUCTED 0x20U
#define QSC_X509_WRITE_TAG_NUMBER_MASK 0x1FU
#define QSC_X509_WRITE_MAX_IDENTIFIER_BYTES 8U
#define QSC_X509_WRITE_UTC_TIME_TEXT_LENGTH 13U
#define QSC_X509_WRITE_GENERALIZED_TIME_TEXT_LENGTH 15U
#define QSC_X509_WRITE_STACK_BUFFER 4096U
#define QSC_X509_WRITE_MAX_RDN_BUFFER 1024U
#define QSC_X509_WRITE_MAX_NAME_BUFFER 4096U

static bool qsc_x509_write_is_leap_year(uint16_t year)
{
    return (((year % 4U) == 0U) && (((year % 100U) != 0U) || ((year % 400U) == 0U)));
}

static uint8_t qsc_x509_write_days_in_month(uint16_t year, uint8_t month)
{
    static const uint8_t days[12U] =
    {
        31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U
    };
    uint8_t res = 0U;

    if ((month >= 1U) && (month <= 12U))
    {
        res = days[month - 1U];

        if ((month == 2U) && (qsc_x509_write_is_leap_year(year) == true))
        {
            res = 29U;
        }
    }

    return res;
}

static qsc_asn1_status qsc_x509_write_check_output(uint8_t* output, size_t* outputlen, size_t required)
{
    QSC_ASSERT(outputlen != NULL);

    if (outputlen == NULL)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if ((output == NULL) || (*outputlen < required))
    {
        *outputlen = required;
        return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    *outputlen = required;
    return QSC_ASN1_STATUS_SUCCESS;
}

static void qsc_x509_write_u32_to_dec2(uint32_t value, uint8_t* output)
{
    output[0U] = (uint8_t)('0' + ((value / 10U) % 10U));
    output[1U] = (uint8_t)('0' + (value % 10U));
}

static void qsc_x509_write_u32_to_dec4(uint32_t value, uint8_t* output)
{
    output[0U] = (uint8_t)('0' + ((value / 1000U) % 10U));
    output[1U] = (uint8_t)('0' + ((value / 100U) % 10U));
    output[2U] = (uint8_t)('0' + ((value / 10U) % 10U));
    output[3U] = (uint8_t)('0' + (value % 10U));
}

static bool qsc_x509_write_is_printable_char(char value)
{
    if (((value >= 'A') && (value <= 'Z')) ||
        ((value >= 'a') && (value <= 'z')) ||
        ((value >= '0') && (value <= '9')))
    {
        return true;
    }

    switch (value)
    {
        case ' ':
        case '\'':
        case '(':
        case ')':
        case '+':
        case ',':
        case '-':
        case '.':
        case '/':
        case ':':
        case '=':
        case '?':
            return true;
        default:
            return false;
    }
}

static bool qsc_x509_write_validate_time(const qsc_asn1_time* value)
{
    uint8_t mdays = 0U;

    if (value == NULL)
    {
        return false;
    }

    mdays = qsc_x509_write_days_in_month(value->year, value->month);

    return ((value->year <= 9999U) &&
        (value->month >= 1U) && (value->month <= 12U) &&
        (value->day >= 1U) && (value->day <= mdays) &&
        (value->hour <= 23U) &&
        (value->minute <= 59U) &&
        (value->second <= 59U));
}

static size_t qsc_x509_write_length_size(size_t length)
{
    size_t res = 1U;

    if (length >= 128U)
    {
        res = 1U;

        while (length != 0U)
        {
            ++res;
            length >>= 8U;
        }
    }

    return res;
}

static size_t qsc_x509_write_identifier_size(uint32_t tagnumber)
{
    size_t res = 1U;
    uint32_t tmp = tagnumber;

    if (tagnumber >= 31U)
    {
        res = 2U;
        tmp >>= 7U;

        while (tmp != 0U)
        {
            ++res;
            tmp >>= 7U;
        }
    }

    return res;
}

static qsc_asn1_status qsc_x509_write_primitive_string(uint32_t tagnumber, const char* value, size_t valuelen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    if (((value == NULL) && (valuelen != 0U)) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, tagnumber, (const uint8_t*)value, valuelen, output, outputlen);
}

static qsc_asn1_status qsc_x509_write_time_core(const qsc_asn1_time* value, bool generalized, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(value != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t text[QSC_X509_WRITE_GENERALIZED_TIME_TEXT_LENGTH] = { 0U };

    if ((value == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (qsc_x509_write_validate_time(value) == false)
    {
        return QSC_ASN1_STATUS_OUT_OF_RANGE;
    }

    if (generalized == false)
    {
        if ((value->year < 1950U) || (value->year > 2049U))
        {
            return QSC_ASN1_STATUS_OUT_OF_RANGE;
        }

        qsc_x509_write_u32_to_dec2((uint32_t)(value->year % 100U), text);
        qsc_x509_write_u32_to_dec2((uint32_t)value->month, text + 2U);
        qsc_x509_write_u32_to_dec2((uint32_t)value->day, text + 4U);
        qsc_x509_write_u32_to_dec2((uint32_t)value->hour, text + 6U);
        qsc_x509_write_u32_to_dec2((uint32_t)value->minute, text + 8U);
        qsc_x509_write_u32_to_dec2((uint32_t)value->second, text + 10U);
        text[12U] = (uint8_t)'Z';

        return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_UTCTIME, text, QSC_X509_WRITE_UTC_TIME_TEXT_LENGTH, output, outputlen);
    }

    qsc_x509_write_u32_to_dec4((uint32_t)value->year, text);
    qsc_x509_write_u32_to_dec2((uint32_t)value->month, text + 4U);
    qsc_x509_write_u32_to_dec2((uint32_t)value->day, text + 6U);
    qsc_x509_write_u32_to_dec2((uint32_t)value->hour, text + 8U);
    qsc_x509_write_u32_to_dec2((uint32_t)value->minute, text + 10U);
    qsc_x509_write_u32_to_dec2((uint32_t)value->second, text + 12U);
    text[14U] = (uint8_t)'Z';

    return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_GENERALIZEDTIME, text, QSC_X509_WRITE_GENERALIZED_TIME_TEXT_LENGTH, output, outputlen);
}

static qsc_oid_id qsc_x509_write_name_type_to_oid(qsc_x509_name_attribute_type type)
{
    switch (type)
    {
        case QSC_X509_NAME_ATTRIBUTE_COMMON_NAME:
            return QSC_OID_ID_COMMON_NAME;
        case QSC_X509_NAME_ATTRIBUTE_SURNAME:
            return QSC_OID_ID_SURNAME;
        case QSC_X509_NAME_ATTRIBUTE_SERIAL_NUMBER:
            return QSC_OID_ID_SERIAL_NUMBER;
        case QSC_X509_NAME_ATTRIBUTE_COUNTRY_NAME:
            return QSC_OID_ID_COUNTRY_NAME;
        case QSC_X509_NAME_ATTRIBUTE_LOCALITY_NAME:
            return QSC_OID_ID_LOCALITY_NAME;
        case QSC_X509_NAME_ATTRIBUTE_STATE_OR_PROVINCE:
            return QSC_OID_ID_STATE_OR_PROVINCE_NAME;
        case QSC_X509_NAME_ATTRIBUTE_STREET_ADDRESS:
            return QSC_OID_ID_STREET_ADDRESS;
        case QSC_X509_NAME_ATTRIBUTE_ORGANIZATION_NAME:
            return QSC_OID_ID_ORGANIZATION_NAME;
        case QSC_X509_NAME_ATTRIBUTE_ORGANIZATIONAL_UNIT:
            return QSC_OID_ID_ORGANIZATIONAL_UNIT_NAME;
        case QSC_X509_NAME_ATTRIBUTE_TITLE:
            return QSC_OID_ID_TITLE;
        case QSC_X509_NAME_ATTRIBUTE_DESCRIPTION:
            return QSC_OID_ID_DESCRIPTION;
        case QSC_X509_NAME_ATTRIBUTE_GIVEN_NAME:
            return QSC_OID_ID_GIVEN_NAME;
        case QSC_X509_NAME_ATTRIBUTE_INITIALS:
            return QSC_OID_ID_INITIALS;
        case QSC_X509_NAME_ATTRIBUTE_GENERATION_QUALIFIER:
            return QSC_OID_ID_GENERATION_QUALIFIER;
        case QSC_X509_NAME_ATTRIBUTE_DN_QUALIFIER:
            return QSC_OID_ID_DN_QUALIFIER;
        case QSC_X509_NAME_ATTRIBUTE_PSEUDONYM:
            return QSC_OID_ID_PSEUDONYM;
        case QSC_X509_NAME_ATTRIBUTE_DOMAIN_COMPONENT:
            return QSC_OID_ID_DOMAIN_COMPONENT;
        case QSC_X509_NAME_ATTRIBUTE_EMAIL_ADDRESS:
            return QSC_OID_ID_EMAIL_ADDRESS;
        default:
            return QSC_OID_ID_NONE;
    }
}

static uint8_t qsc_x509_write_default_name_string_tag(const qsc_x509_name_attribute* attribute)
{
    if (attribute->string_tag != 0U)
    {
        return attribute->string_tag;
    }

    switch (attribute->type)
    {
        case QSC_X509_NAME_ATTRIBUTE_COUNTRY_NAME:
        case QSC_X509_NAME_ATTRIBUTE_SERIAL_NUMBER:
        case QSC_X509_NAME_ATTRIBUTE_DN_QUALIFIER:
            return BER_ASN1_PRINTABLE_STRING;
        case QSC_X509_NAME_ATTRIBUTE_DOMAIN_COMPONENT:
        case QSC_X509_NAME_ATTRIBUTE_EMAIL_ADDRESS:
            return BER_ASN1_IA5_STRING;
        default:
            return BER_ASN1_UTF8_STRING;
    }
}

static qsc_asn1_status qsc_x509_write_name_attribute_value(const qsc_x509_name_attribute* attribute, uint8_t* output, size_t* outputlen)
{
    uint8_t tag = 0U;

    if ((attribute == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    tag = qsc_x509_write_default_name_string_tag(attribute);

    switch (tag)
    {
        case BER_ASN1_PRINTABLE_STRING:
            return qsc_x509_write_printable_string(attribute->value, attribute->length, output, outputlen);
        case BER_ASN1_IA5_STRING:
            return qsc_x509_write_ia5_string(attribute->value, attribute->length, output, outputlen);
        case BER_ASN1_UTF8_STRING:
            return qsc_x509_write_utf8_string(attribute->value, attribute->length, output, outputlen);
        default:
            return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, tag, (const uint8_t*)attribute->value, attribute->length, output, outputlen);
    }
}

static qsc_asn1_status qsc_x509_write_build_oid_from_id(qsc_oid_id id, qsc_asn1_oid* oid)
{
    if ((id == QSC_OID_ID_NONE) || (oid == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (qsc_oid_to_asn1(id, oid) == false)
    {
        return QSC_ASN1_STATUS_NOT_FOUND;
    }

    return QSC_ASN1_STATUS_SUCCESS;
}


static qsc_asn1_status qsc_x509_write_algorithm_identifier_core(const qsc_asn1_oid* algorithm_oid, bool parameters_present, bool parameters_null, bool parameters_oid, const qsc_asn1_oid* parameter_oid, uint8_t* output, size_t* outputlen)
{
    uint8_t content[QSC_X509_WRITE_STACK_BUFFER] = { 0U };
    size_t pos;
    size_t len;
    qsc_asn1_status status;

    pos = 0U;
    len = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((algorithm_oid == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    len = sizeof(content) - pos;
    status = qsc_x509_write_oid(algorithm_oid, content + pos, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos += len;

    if (parameters_present == true)
    {
        if (parameters_null == true)
        {
            len = sizeof(content) - pos;
            status = qsc_x509_write_null(content + pos, &len);
        }
        else if (parameters_oid == true)
        {
            if (parameter_oid == NULL)
            {
                return QSC_ASN1_STATUS_INVALID_INPUT;
            }

            len = sizeof(content) - pos;
            status = qsc_x509_write_oid(parameter_oid, content + pos, &len);
        }
        else
        {
            return QSC_ASN1_STATUS_UNSUPPORTED;
        }

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

static qsc_asn1_status qsc_x509_write_algorithm_identifier_from_signature(qsc_x509_signature_algorithm signature, uint8_t* output, size_t* outputlen)
{
    qsc_asn1_oid oid = { 0U };
    qsc_oid_id id;

    id = QSC_OID_ID_NONE;

    switch (signature)
    {
        case QSC_X509_SIGNATURE_ALGORITHM_RSA_MD5:
            id = QSC_OID_ID_MD5_WITH_RSA_ENCRYPTION;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA1:
            id = QSC_OID_ID_SHA1_WITH_RSA_ENCRYPTION;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA256:
            id = QSC_OID_ID_SHA256_WITH_RSA_ENCRYPTION;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA384:
            id = QSC_OID_ID_SHA384_WITH_RSA_ENCRYPTION;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA512:
            id = QSC_OID_ID_SHA512_WITH_RSA_ENCRYPTION;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA1:
            id = QSC_OID_ID_ECDSA_WITH_SHA1;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256:
            id = QSC_OID_ID_ECDSA_WITH_SHA256;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384:
            id = QSC_OID_ID_ECDSA_WITH_SHA384;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512:
            id = QSC_OID_ID_ECDSA_WITH_SHA512;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44:
            id = QSC_OID_ID_ML_DSA_44;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65:
            id = QSC_OID_ID_ML_DSA_65;
            break;
        case QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87:
            id = QSC_OID_ID_ML_DSA_87;
            break;
        default:
            return QSC_ASN1_STATUS_UNSUPPORTED;
    }

    if (qsc_x509_write_build_oid_from_id(id, &oid) != QSC_ASN1_STATUS_SUCCESS)
    {
        return QSC_ASN1_STATUS_NOT_FOUND;
    }

    if ((signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_MD5) ||
        (signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA1) ||
        (signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA256) ||
        (signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA384) ||
        (signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA512))
    {
        return qsc_x509_write_algorithm_identifier_core(&oid, true, true, false, NULL, output, outputlen);
    }

    return qsc_x509_write_algorithm_identifier_core(&oid, false, false, false, NULL, output, outputlen);
}

static qsc_asn1_status qsc_x509_write_algorithm_identifier_from_public_key(qsc_x509_public_key_algorithm publickey, qsc_x509_named_curve curve, qsc_x509_pqc_parameter_set pqcparameter, uint8_t* output, size_t* outputlen)
{
    qsc_asn1_oid oid = { 0U };
    qsc_asn1_oid paramoid = { 0U };
    qsc_oid_id id;
    qsc_oid_id pid;

    id = QSC_OID_ID_NONE;
    pid = QSC_OID_ID_NONE;

    switch (publickey)
    {
        case QSC_X509_PUBLIC_KEY_ALGORITHM_RSA:
            id = QSC_OID_ID_RSA_ENCRYPTION;
            break;
        case QSC_X509_PUBLIC_KEY_ALGORITHM_EC:
            id = QSC_OID_ID_EC_PUBLIC_KEY;
            switch (curve)
            {
                case QSC_X509_NAMED_CURVE_PRIME256V1:
                    pid = QSC_OID_ID_PRIME256V1;
                    break;
                case QSC_X509_NAMED_CURVE_SECP384R1:
                    pid = QSC_OID_ID_SECP384R1;
                    break;
                case QSC_X509_NAMED_CURVE_SECP521R1:
                    pid = QSC_OID_ID_SECP521R1;
                    break;
                default:
                    return QSC_ASN1_STATUS_UNSUPPORTED;
            }
            break;
        case QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA:
            switch (pqcparameter)
            {
                case QSC_X509_PQC_PARAMETER_SET_ML_DSA_44:
                    id = QSC_OID_ID_ML_DSA_44;
                    break;
                case QSC_X509_PQC_PARAMETER_SET_ML_DSA_65:
                    id = QSC_OID_ID_ML_DSA_65;
                    break;
                case QSC_X509_PQC_PARAMETER_SET_ML_DSA_87:
                    id = QSC_OID_ID_ML_DSA_87;
                    break;
                default:
                    return QSC_ASN1_STATUS_UNSUPPORTED;
            }
            break;
        case QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM:
            switch (pqcparameter)
            {
                case QSC_X509_PQC_PARAMETER_SET_ML_KEM_512:
                    id = QSC_OID_ID_ML_KEM_512;
                    break;
                case QSC_X509_PQC_PARAMETER_SET_ML_KEM_768:
                    id = QSC_OID_ID_ML_KEM_768;
                    break;
                case QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024:
                    id = QSC_OID_ID_ML_KEM_1024;
                    break;
                default:
                    return QSC_ASN1_STATUS_UNSUPPORTED;
            }
            break;
        default:
            return QSC_ASN1_STATUS_UNSUPPORTED;
    }

    if (qsc_x509_write_build_oid_from_id(id, &oid) != QSC_ASN1_STATUS_SUCCESS)
    {
        return QSC_ASN1_STATUS_NOT_FOUND;
    }

    if (publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_RSA)
    {
        return qsc_x509_write_algorithm_identifier_core(&oid, true, true, false, NULL, output, outputlen);
    }

    if (publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC)
    {
        if (qsc_x509_write_build_oid_from_id(pid, &paramoid) != QSC_ASN1_STATUS_SUCCESS)
        {
            return QSC_ASN1_STATUS_NOT_FOUND;
        }

        return qsc_x509_write_algorithm_identifier_core(&oid, true, false, true, &paramoid, output, outputlen);
    }

    return qsc_x509_write_algorithm_identifier_core(&oid, false, false, false, NULL, output, outputlen);
}

static qsc_asn1_status qsc_x509_write_sequence_of_general_names(const qsc_x509_general_name* entries, size_t count, uint8_t* output, size_t* outputlen)
{
    uint8_t content[QSC_X509_WRITE_STACK_BUFFER] = { 0U };
    size_t len;
    size_t pos;
    qsc_asn1_status status;

    pos = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if (((entries == NULL) && (count != 0U)) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    for (size_t i = 0U; i < count; ++i)
    {
        len = sizeof(content) - pos;
        status = qsc_x509_write_general_name(&entries[i], content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

static qsc_asn1_status qsc_x509_write_eku_oid(qsc_oid_id id, uint8_t* output, size_t* outputlen)
{
    qsc_asn1_oid oid = { 0U };
    qsc_asn1_status status;

    status = qsc_x509_write_build_oid_from_id(id, &oid);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    return qsc_x509_write_oid(&oid, output, outputlen);
}

qsc_asn1_status qsc_x509_write_length(size_t length, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    size_t required;
    size_t idx;
    size_t count;
    size_t shift;
    qsc_asn1_status status;

    required = qsc_x509_write_length_size(length);
    idx = 0U;
    count = 0U;
    shift = 0U;
    status = qsc_x509_write_check_output(output, outputlen, required);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    if (length < 128U)
    {
        output[0U] = (uint8_t)length;
        *outputlen = 1U;
    }
    else
    {
        count = required - 1U;
        output[0U] = (uint8_t)(0x80U | (uint8_t)count);

        for (idx = 0U; idx < count; ++idx)
        {
            shift = (count - idx - 1U) * 8U;
            output[1U + idx] = (uint8_t)((length >> shift) & 0xFFU);
        }

        *outputlen = required;
    }

    return QSC_ASN1_STATUS_SUCCESS;
}

qsc_asn1_status qsc_x509_write_tag(uint8_t tagclass, bool constructed, uint32_t tagnumber, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    uint8_t tmp[QSC_X509_WRITE_MAX_IDENTIFIER_BYTES] = { 0U };
    uint8_t stack[5U] = { 0U };
    size_t required;
    size_t count;
    size_t idx;
    qsc_asn1_status status;

    required = qsc_x509_write_identifier_size(tagnumber);
    count = 0U;
    idx = 0U;
    status = qsc_x509_write_check_output(output, outputlen, required);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    tmp[0U] = (uint8_t)(tagclass & 0xC0U);

    if (constructed == true)
    {
        tmp[0U] |= QSC_X509_WRITE_TAG_CONSTRUCTED;
    }

    if (tagnumber < 31U)
    {
        tmp[0U] |= (uint8_t)(tagnumber & QSC_X509_WRITE_TAG_NUMBER_MASK);
        qsc_memutils_copy(output, tmp, 1U);
        *outputlen = 1U;
        return QSC_ASN1_STATUS_SUCCESS;
    }

    tmp[0U] |= QSC_X509_WRITE_TAG_NUMBER_MASK;
    stack[count++] = (uint8_t)(tagnumber & 0x7FU);
    tagnumber >>= 7U;

    while (tagnumber != 0U)
    {
        stack[count++] = (uint8_t)(0x80U | (uint8_t)(tagnumber & 0x7FU));
        tagnumber >>= 7U;
    }

    for (idx = 0U; idx < count; ++idx)
    {
        tmp[1U + idx] = stack[count - idx - 1U];
    }

    qsc_memutils_copy(output, tmp, 1U + count);
    *outputlen = 1U + count;

    return QSC_ASN1_STATUS_SUCCESS;
}

qsc_asn1_status qsc_x509_write_raw(uint8_t tagclass, bool constructed, uint32_t tagnumber, const uint8_t* content, size_t contentlen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    size_t taglen;
    size_t len;
    size_t required;
    qsc_asn1_status status;

    taglen = qsc_x509_write_identifier_size(tagnumber);
    len = qsc_x509_write_length_size(contentlen);
    required = taglen + len + contentlen;
    status = QSC_ASN1_STATUS_SUCCESS;

    if (((content == NULL) && (contentlen != 0U)) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    status = qsc_x509_write_check_output(output, outputlen, required);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    status = qsc_x509_write_tag(tagclass, constructed, tagnumber, output, &taglen);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    status = qsc_x509_write_length(contentlen, output + taglen, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    if (contentlen != 0U)
    {
        qsc_memutils_copy(output + taglen + len, content, contentlen);
    }

    *outputlen = required;

    return QSC_ASN1_STATUS_SUCCESS;
}

qsc_asn1_status qsc_x509_write_integer(const uint8_t* value, size_t valuelen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    size_t offset;
    size_t contentlen;
    size_t taglen;
    size_t len;
    size_t required;
    bool prependzero;
    qsc_asn1_status status;

    offset = 0U;
    contentlen = 0U;
    taglen = 0U;
    len = 0U;
    required = 0U;
    prependzero = false;
    status = QSC_ASN1_STATUS_SUCCESS;

    if (((value == NULL) && (valuelen != 0U)) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    while ((offset < valuelen) && (value[offset] == 0U))
    {
        ++offset;
    }

    if (offset == valuelen)
    {
        contentlen = 1U;
    }
    else
    {
        prependzero = ((value[offset] & 0x80U) != 0U);
        contentlen = (valuelen - offset) + (prependzero == true ? 1U : 0U);
    }

    taglen = qsc_x509_write_identifier_size(BER_ASN1_INTEGER);
    len = qsc_x509_write_length_size(contentlen);
    required = taglen + len + contentlen;
    status = qsc_x509_write_check_output(output, outputlen, required);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    status = qsc_x509_write_tag(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_INTEGER, output, &taglen);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    status = qsc_x509_write_length(contentlen, output + taglen, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    if (offset == valuelen)
    {
        output[taglen + len] = 0U;
    }
    else
    {
        size_t pos = taglen + len;

        if (prependzero == true)
        {
            output[pos++] = 0U;
        }

        qsc_memutils_copy(output + pos, value + offset, valuelen - offset);
    }

    *outputlen = required;

    return QSC_ASN1_STATUS_SUCCESS;
}

qsc_asn1_status qsc_x509_write_boolean(bool value, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    const uint8_t content = value == true ? 0xFFU : 0x00U;
    return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_BOOLEAN, &content, 1U, output, outputlen);
}

qsc_asn1_status qsc_x509_write_null(uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_NULL, NULL, 0U, output, outputlen);
}

qsc_asn1_status qsc_x509_write_oid(const qsc_asn1_oid* oid, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(oid != NULL);
    QSC_ASSERT(outputlen != NULL);

    if ((oid == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if ((oid->length == 0U) || (oid->length > QSC_ASN1_OID_MAX_SIZE))
    {
        return QSC_ASN1_STATUS_INVALID_ENCODING;
    }

    return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OBJECT_IDENTIFIER, oid->data, oid->length, output, outputlen);
}

qsc_asn1_status qsc_x509_write_octet_string(const uint8_t* value, size_t valuelen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    if (((value == NULL) && (valuelen != 0U)) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OCTET_STRING, value, valuelen, output, outputlen);
}

qsc_asn1_status qsc_x509_write_bit_string(const uint8_t* value, size_t valuelen, uint8_t unusedbits, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    size_t taglen;
    size_t len;
    size_t required;
    qsc_asn1_status status;

    taglen = qsc_x509_write_identifier_size(BER_ASN1_BIT_STRING);
    len = qsc_x509_write_length_size(valuelen + 1U);
    required = taglen + len + valuelen + 1U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if (((value == NULL) && (valuelen != 0U)) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (unusedbits > QSC_ASN1_BIT_STRING_MAX_UNUSED_BITS)
    {
        return QSC_ASN1_STATUS_OUT_OF_RANGE;
    }

    if ((valuelen == 0U) && (unusedbits != 0U))
    {
        return QSC_ASN1_STATUS_INVALID_ENCODING;
    }

    status = qsc_x509_write_check_output(output, outputlen, required);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    status = qsc_x509_write_tag(QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_BIT_STRING, output, &taglen);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    status = qsc_x509_write_length(valuelen + 1U, output + taglen, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    output[taglen + len] = unusedbits;

    if (valuelen != 0U)
    {
        qsc_memutils_copy(output + taglen + len + 1U, value, valuelen);
    }

    *outputlen = required;

    return QSC_ASN1_STATUS_SUCCESS;
}

qsc_asn1_status qsc_x509_write_utf8_string(const char* value, size_t valuelen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    return qsc_x509_write_primitive_string(BER_ASN1_UTF8_STRING, value, valuelen, output, outputlen);
}

qsc_asn1_status qsc_x509_write_printable_string(const char* value, size_t valuelen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    size_t i = 0U;

    if (((value == NULL) && (valuelen != 0U)) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    for (i = 0U; i < valuelen; ++i)
    {
        if (qsc_x509_write_is_printable_char(value[i]) == false)
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }

    return qsc_x509_write_primitive_string(BER_ASN1_PRINTABLE_STRING, value, valuelen, output, outputlen);
}

qsc_asn1_status qsc_x509_write_ia5_string(const char* value, size_t valuelen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    if (((value == NULL) && (valuelen != 0U)) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    for (size_t i = 0U; i < valuelen; ++i)
    {
        if ((((uint8_t)value[i]) & 0x80U) != 0U)
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }

    return qsc_x509_write_primitive_string(BER_ASN1_IA5_STRING, value, valuelen, output, outputlen);
}

qsc_asn1_status qsc_x509_write_utctime(const qsc_asn1_time* value, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(value != NULL);
    QSC_ASSERT(outputlen != NULL);

    return qsc_x509_write_time_core(value, false, output, outputlen);
}

qsc_asn1_status qsc_x509_write_generalized_time(const qsc_asn1_time* value, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(value != NULL);
    QSC_ASSERT(outputlen != NULL);

    return qsc_x509_write_time_core(value, true, output, outputlen);
}

qsc_asn1_status qsc_x509_write_sequence(const uint8_t* content, size_t contentlen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, true, BER_ASN1_SEQUENCE, content, contentlen, output, outputlen);
}

qsc_asn1_status qsc_x509_write_set(const uint8_t* content, size_t contentlen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_UNIVERSAL, true, BER_ASN1_SET, content, contentlen, output, outputlen);
}

qsc_asn1_status qsc_x509_write_explicit(uint32_t tagnumber, const uint8_t* content, size_t contentlen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, tagnumber, content, contentlen, output, outputlen);
}

qsc_asn1_status qsc_x509_write_algorithm_identifier(const qsc_x509_algorithm_identifier* algorithm, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(algorithm != NULL);
    QSC_ASSERT(outputlen != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_UNSUPPORTED;

    if ((algorithm == NULL) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (algorithm->algorithm_oid.length != 0U)
    {
        status = qsc_x509_write_algorithm_identifier_core(
            &algorithm->algorithm_oid,
            algorithm->parameters_present,
            algorithm->parameters_null,
            algorithm->parameters_oid,
            algorithm->parameters_oid == true ? &algorithm->parameter_oid : NULL,
            output,
            outputlen);
    }
    else if (algorithm->signature != QSC_X509_SIGNATURE_ALGORITHM_NONE)
    {
        status = qsc_x509_write_algorithm_identifier_from_signature(algorithm->signature, output, outputlen);
    }
    else if (algorithm->publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_NONE)
    {
        status = qsc_x509_write_algorithm_identifier_from_public_key(algorithm->publickey, algorithm->curve, algorithm->pqcparameter, output, outputlen);
    }

    return status;
}

qsc_asn1_status qsc_x509_write_algorithm_identifier_for_signature(qsc_x509_signature_algorithm signature, uint8_t* output, size_t* outputlen)
{
    return qsc_x509_write_algorithm_identifier_from_signature(signature, output, outputlen);
}

qsc_asn1_status qsc_x509_write_algorithm_identifier_for_public_key(qsc_x509_public_key_algorithm publickey, qsc_x509_named_curve curve, qsc_x509_pqc_parameter_set pqcparameter, uint8_t* output, size_t* outputlen)
{
    return qsc_x509_write_algorithm_identifier_from_public_key(publickey, curve, pqcparameter, output, outputlen);
}

qsc_asn1_status qsc_x509_write_spki_ec(qsc_x509_named_curve curve, const uint8_t* publickey, size_t publickeylen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(outputlen != NULL);

    qsc_x509_subject_public_key_info spki;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((publickey != NULL) && (outputlen != NULL))
    {
        status = qsc_x509_spki_initialize_ec(&spki, curve, publickey, publickeylen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_x509_write_spki(&spki, output, outputlen);
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_write_spki_ml_dsa(qsc_x509_pqc_parameter_set parameterset, const uint8_t* publickey, size_t publickeylen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(outputlen != NULL);

    qsc_x509_subject_public_key_info spki;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((publickey != NULL) && (outputlen != NULL))
    {
        status = qsc_x509_spki_initialize_ml_dsa(&spki, parameterset, publickey, publickeylen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_x509_write_spki(&spki, output, outputlen);
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_write_spki_ml_kem(qsc_x509_pqc_parameter_set parameterset, const uint8_t* publickey, size_t publickeylen, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(publickey != NULL);
    QSC_ASSERT(outputlen != NULL);

    qsc_x509_subject_public_key_info spki;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if ((publickey != NULL) && (outputlen != NULL))
    {
        status = qsc_x509_spki_initialize_ml_kem(&spki, parameterset, publickey, publickeylen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_x509_write_spki(&spki, output, outputlen);
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_write_name(const qsc_x509_name* name, uint8_t* output, size_t* outputlen)
{
    uint8_t content[QSC_X509_WRITE_MAX_NAME_BUFFER] = { 0U };
    uint8_t setcontent[QSC_X509_WRITE_MAX_RDN_BUFFER] = { 0U };
    uint8_t attrcontent[QSC_X509_WRITE_MAX_RDN_BUFFER] = { 0U };
    qsc_asn1_oid oid = { 0U };
    size_t pos;
    size_t idx;
    qsc_asn1_status status;

    pos = 0U;
    idx = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((name == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    while (idx < name->count)
    {
        uint16_t rdn = name->attributes[idx].rdn_index;
        size_t setpos = 0U;

        while ((idx < name->count) && (name->attributes[idx].rdn_index == rdn))
        {
            size_t attrpos = 0U;
            size_t len = 0U;
            qsc_oid_id oidid = name->attributes[idx].oid;

            if (oidid == QSC_OID_ID_NONE)
            {
                oidid = qsc_x509_write_name_type_to_oid(name->attributes[idx].type);
            }

            if (oidid != QSC_OID_ID_NONE)
            {
                status = qsc_x509_write_build_oid_from_id(oidid, &oid);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    return status;
                }

                len = sizeof(attrcontent) - attrpos;
                status = qsc_x509_write_oid(&oid, attrcontent + attrpos, &len);
            }
            else if (name->attributes[idx].attribute_oid.length != 0U)
            {
                len = sizeof(attrcontent) - attrpos;
                status = qsc_x509_write_oid(&name->attributes[idx].attribute_oid, attrcontent + attrpos, &len);
            }
            else
            {
                return QSC_ASN1_STATUS_UNSUPPORTED;
            }

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }

            attrpos += len;
            len = sizeof(attrcontent) - attrpos;
            status = qsc_x509_write_name_attribute_value(&name->attributes[idx], attrcontent + attrpos, &len);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }

            attrpos += len;
            len = sizeof(setcontent) - setpos;
            status = qsc_x509_write_sequence(attrcontent, attrpos, setcontent + setpos, &len);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }

            setpos += len;
            ++idx;
        }

        {
            size_t len = sizeof(content) - pos;
            status = qsc_x509_write_set(setcontent, setpos, content + pos, &len);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }

            pos += len;
        }
    }

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

qsc_asn1_status qsc_x509_write_validity(const qsc_x509_validity* validity, uint8_t* output, size_t* outputlen)
{
    uint8_t content[64U] = { 0U };
    size_t pos;
    size_t len;
    qsc_asn1_status status;

    pos = 0U;
    len = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((validity == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    len = sizeof(content) - pos;

    if ((validity->notbefore.year < 1950U) || (validity->notbefore.year > 2049U))
    {
        status = qsc_x509_write_generalized_time(&validity->notbefore, content + pos, &len);
    }
    else
    {
        status = qsc_x509_write_utctime(&validity->notbefore, content + pos, &len);
    }

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos += len;
    len = sizeof(content) - pos;

    if ((validity->notafter.year < 1950U) || (validity->notafter.year > 2049U))
    {
        status = qsc_x509_write_generalized_time(&validity->notafter, content + pos, &len);
    }
    else
    {
        status = qsc_x509_write_utctime(&validity->notafter, content + pos, &len);
    }

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos += len;

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

qsc_asn1_status qsc_x509_write_general_name(const qsc_x509_general_name* name, uint8_t* output, size_t* outputlen)
{
    if ((name == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    switch (name->type)
    {
        case QSC_X509_GENERAL_NAME_RFC822_NAME:
            return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 1U, name->data, name->length, output, outputlen);
        case QSC_X509_GENERAL_NAME_DNS_NAME:
            return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 2U, name->data, name->length, output, outputlen);
        case QSC_X509_GENERAL_NAME_UNIFORM_RESOURCE_IDENTIFIER:
            return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 6U, name->data, name->length, output, outputlen);
        case QSC_X509_GENERAL_NAME_IP_ADDRESS:
            return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 7U, name->data, name->length, output, outputlen);
        case QSC_X509_GENERAL_NAME_REGISTERED_ID:
            if (name->registeredid.length == 0U)
            {
                return QSC_ASN1_STATUS_INVALID_INPUT;
            }
            return qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 8U, name->registeredid.data, name->registeredid.length, output, outputlen);
        default:
            return QSC_ASN1_STATUS_UNSUPPORTED;
    }
}

qsc_asn1_status qsc_x509_write_spki(const qsc_x509_subject_public_key_info* spki, uint8_t* output, size_t* outputlen)
{
    uint8_t content[QSC_X509_WRITE_STACK_BUFFER] = { 0U };
    size_t pos;
    size_t len;
    qsc_asn1_status status;

    pos = 0U;
    len = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((spki == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    len = sizeof(content) - pos;
    status = qsc_x509_write_algorithm_identifier(&spki->algorithm, content + pos, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos += len;
    len = sizeof(content) - pos;
    status = qsc_x509_write_bit_string(spki->publickey, spki->publickeylen, spki->unusedbits, content + pos, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos += len;

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

qsc_asn1_status qsc_x509_write_extension(const qsc_x509_extension* extension, uint8_t* output, size_t* outputlen)
{
    uint8_t content[QSC_X509_WRITE_STACK_BUFFER] = { 0U };
    qsc_asn1_oid oid = { 0U };
    qsc_oid_id oidid;
    size_t pos;
    size_t len;
    qsc_asn1_status status;

    oidid = QSC_OID_ID_NONE;
    pos = 0U;
    len = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((extension == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    oidid = extension->oid;

    if ((oidid == QSC_OID_ID_NONE) && (extension->type != QSC_X509_EXTENSION_UNKNOWN))
    {
        switch (extension->type)
        {
            case QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER:
                oidid = QSC_OID_ID_SUBJECT_KEY_IDENTIFIER;
                break;
            case QSC_X509_EXTENSION_KEY_USAGE:
                oidid = QSC_OID_ID_KEY_USAGE;
                break;
            case QSC_X509_EXTENSION_SUBJECT_ALT_NAME:
                oidid = QSC_OID_ID_SUBJECT_ALT_NAME;
                break;
            case QSC_X509_EXTENSION_ISSUER_ALT_NAME:
                oidid = QSC_OID_ID_ISSUER_ALT_NAME;
                break;
            case QSC_X509_EXTENSION_BASIC_CONSTRAINTS:
                oidid = QSC_OID_ID_BASIC_CONSTRAINTS;
                break;
            case QSC_X509_EXTENSION_NAME_CONSTRAINTS:
                oidid = QSC_OID_ID_NAME_CONSTRAINTS;
                break;
            case QSC_X509_EXTENSION_CRL_DISTRIBUTION_POINTS:
                oidid = QSC_OID_ID_CRL_DISTRIBUTION_POINTS;
                break;
            case QSC_X509_EXTENSION_CERTIFICATE_POLICIES:
                oidid = QSC_OID_ID_CERTIFICATE_POLICIES;
                break;
            case QSC_X509_EXTENSION_CRL_NUMBER:
                oidid = QSC_OID_ID_CRL_NUMBER;
                break;
            case QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER:
                oidid = QSC_OID_ID_AUTHORITY_KEY_IDENTIFIER;
                break;
            case QSC_X509_EXTENSION_EXTENDED_KEY_USAGE:
                oidid = QSC_OID_ID_EXTENDED_KEY_USAGE;
                break;
            case QSC_X509_EXTENSION_AUTHORITY_INFO_ACCESS:
                oidid = QSC_OID_ID_AUTHORITY_INFO_ACCESS;
                break;
            case QSC_X509_EXTENSION_SUBJECT_INFO_ACCESS:
                oidid = QSC_OID_ID_SUBJECT_INFO_ACCESS;
                break;
            default:
                break;
        }
    }

    if (oidid != QSC_OID_ID_NONE)
    {
        status = qsc_x509_write_build_oid_from_id(oidid, &oid);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        len = sizeof(content) - pos;
        status = qsc_x509_write_oid(&oid, content + pos, &len);
    }
    else if (extension->extension_oid.length != 0U)
    {
        len = sizeof(content) - pos;
        status = qsc_x509_write_oid(&extension->extension_oid, content + pos, &len);
    }
    else
    {
        return QSC_ASN1_STATUS_UNSUPPORTED;
    }

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos += len;

    if (extension->critical == true)
    {
        len = sizeof(content) - pos;
        status = qsc_x509_write_boolean(true, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    len = sizeof(content) - pos;
    status = qsc_x509_write_octet_string(extension->value, extension->valuelen, content + pos, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos += len;

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

qsc_asn1_status qsc_x509_write_extensions(const qsc_x509_extensions* extensions, uint8_t* output, size_t* outputlen)
{
    uint8_t content[QSC_X509_WRITE_STACK_BUFFER] = { 0U };
    size_t pos;
    size_t idx;
    qsc_asn1_status status;

    pos = 0U;
    idx = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((extensions == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    for (idx = 0U; idx < extensions->count; ++idx)
    {
        size_t len = sizeof(content) - pos;
        status = qsc_x509_write_extension(&extensions->entries[idx], content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

qsc_asn1_status qsc_x509_write_basic_constraints(const qsc_x509_basic_constraints* basicconstraints, uint8_t* output, size_t* outputlen)
{
    uint8_t content[32U] = { 0U };
    size_t pos;
    size_t len;
    qsc_asn1_status status;

    pos = 0U;
    len = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((basicconstraints == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (basicconstraints->ca == true)
    {
        len = sizeof(content) - pos;
        status = qsc_x509_write_boolean(true, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    if (basicconstraints->pathlen_present == true)
    {
        uint8_t pathbytes[5] = { 0U };
        size_t pathlen = 0U;
        uint32_t value = basicconstraints->pathlen;

        if (value > 0xFFFFFFU)
        {
            pathbytes[pathlen++] = (uint8_t)((value >> 24) & 0xFFU);
        }
        if ((pathlen != 0U) || (value > 0xFFFFU))
        {
            pathbytes[pathlen++] = (uint8_t)((value >> 16) & 0xFFU);
        }
        if ((pathlen != 0U) || (value > 0xFFU))
        {
            pathbytes[pathlen++] = (uint8_t)((value >> 8) & 0xFFU);
        }
        pathbytes[pathlen++] = (uint8_t)(value & 0xFFU);

        len = sizeof(content) - pos;
        status = qsc_x509_write_integer(pathbytes, pathlen, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

qsc_asn1_status qsc_x509_write_key_usage(const qsc_x509_key_usage* keyusage, uint8_t* output, size_t* outputlen)
{
    uint8_t bits[2U] = { 0U };
    uint8_t unusedbits;
    size_t bytelen;
    uint16_t mask;
    int32_t bit;

    unusedbits = 0U;
    bytelen = 0U;
    mask = 0U;
    bit = 0;

    if ((keyusage == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    mask = keyusage->bits;

    if (mask == 0U)
    {
        bits[0] = 0U;
        bytelen = 1U;
        unusedbits = 7U;
    }
    else
    {
        for (bit = 0; bit < 9; ++bit)
        {
            if ((mask & (uint16_t)(1U << bit)) != 0U)
            {
                size_t bytepos = (size_t)bit / 8U;
                uint8_t bitmask = (uint8_t)(0x80U >> ((size_t)bit % 8U));
                bits[bytepos] |= bitmask;
                if (bytepos + 1U > bytelen)
                {
                    bytelen = bytepos + 1U;
                }
            }
        }

        if (bytelen == 0U)
        {
            bytelen = 1U;
        }

        if ((bits[bytelen - 1U] & 0x01U) != 0U)
        {
            unusedbits = 0U;
        }
        else if ((bits[bytelen - 1U] & 0x02U) != 0U)
        {
            unusedbits = 1U;
        }
        else if ((bits[bytelen - 1U] & 0x04U) != 0U)
        {
            unusedbits = 2U;
        }
        else if ((bits[bytelen - 1U] & 0x08U) != 0U)
        {
            unusedbits = 3U;
        }
        else if ((bits[bytelen - 1U] & 0x10U) != 0U)
        {
            unusedbits = 4U;
        }
        else if ((bits[bytelen - 1U] & 0x20U) != 0U)
        {
            unusedbits = 5U;
        }
        else if ((bits[bytelen - 1U] & 0x40U) != 0U)
        {
            unusedbits = 6U;
        }
        else
        {
            unusedbits = 7U;
        }
    }

    return qsc_x509_write_bit_string(bits, bytelen, unusedbits, output, outputlen);
}

qsc_asn1_status qsc_x509_write_extended_key_usage(const qsc_x509_extended_key_usage* extendedkeyusage, uint8_t* output, size_t* outputlen)
{
    uint8_t content[256U] = { 0U };
    size_t pos;
    qsc_asn1_status status;

    pos = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((extendedkeyusage == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if ((extendedkeyusage->bits & QSC_X509_EXTENDED_KEY_USAGE_ANY) != 0U)
    {
        size_t len = sizeof(content) - pos;

        status = qsc_x509_write_eku_oid(QSC_OID_ID_ANY_EXTENDED_KEY_USAGE, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    if ((extendedkeyusage->bits & QSC_X509_EXTENDED_KEY_USAGE_SERVER_AUTH) != 0U)
    {
        size_t len = sizeof(content) - pos;

        status = qsc_x509_write_eku_oid(QSC_OID_ID_SERVER_AUTH, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    if ((extendedkeyusage->bits & QSC_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH) != 0U)
    {
        size_t len = sizeof(content) - pos;

        status = qsc_x509_write_eku_oid(QSC_OID_ID_CLIENT_AUTH, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    if ((extendedkeyusage->bits & QSC_X509_EXTENDED_KEY_USAGE_CODE_SIGNING) != 0U)
    {
        size_t len = sizeof(content) - pos;

        status = qsc_x509_write_eku_oid(QSC_OID_ID_CODE_SIGNING, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    if ((extendedkeyusage->bits & QSC_X509_EXTENDED_KEY_USAGE_EMAIL_PROTECTION) != 0U)
    {
        size_t len = sizeof(content) - pos;

        status = qsc_x509_write_eku_oid(QSC_OID_ID_EMAIL_PROTECTION, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    if ((extendedkeyusage->bits & QSC_X509_EXTENDED_KEY_USAGE_TIME_STAMPING) != 0U)
    {
        size_t len = sizeof(content) - pos;

        status = qsc_x509_write_eku_oid(QSC_OID_ID_TIME_STAMPING, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    if ((extendedkeyusage->bits & QSC_X509_EXTENDED_KEY_USAGE_OCSP_SIGNING) != 0U)
    {
        size_t len = sizeof(content) - pos;

        status = qsc_x509_write_eku_oid(QSC_OID_ID_OCSP_SIGNING, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

qsc_asn1_status qsc_x509_write_subject_key_identifier(const qsc_x509_subject_key_identifier* subjectkeyidentifier, uint8_t* output, size_t* outputlen)
{
    if ((subjectkeyidentifier == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return qsc_x509_write_octet_string(subjectkeyidentifier->identifier, subjectkeyidentifier->identifierlen, output, outputlen);
}

qsc_asn1_status qsc_x509_write_authority_key_identifier(const qsc_x509_authority_key_identifier* authoritykeyidentifier, uint8_t* output, size_t* outputlen)
{
    uint8_t content[QSC_X509_WRITE_STACK_BUFFER] = { 0U };
    size_t pos;
    qsc_asn1_status status;

    pos = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    if ((authoritykeyidentifier == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (authoritykeyidentifier->keyidentifierlen != 0U)
    {
        size_t len = sizeof(content) - pos;
        status = qsc_x509_write_raw(
            QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC,
            false,
            0U,
            authoritykeyidentifier->keyidentifier,
            authoritykeyidentifier->keyidentifierlen,
            content + pos,
            &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    if ((authoritykeyidentifier->issuer_present == true) && (authoritykeyidentifier->issuername_present == true))
    {
        qsc_x509_general_name dirname = { 0 };
        uint8_t names[QSC_X509_WRITE_STACK_BUFFER] = { 0U };
        uint8_t dir[QSC_X509_WRITE_STACK_BUFFER] = { 0U };
        size_t dirlen;
        size_t nameslen;

        nameslen = sizeof(names);
        dirlen = sizeof(dir);
        dirname.type = QSC_X509_GENERAL_NAME_DIRECTORY_NAME;

        status = qsc_x509_write_name(&authoritykeyidentifier->issuername, dir, &dirlen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        status = qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 4U, dir, dirlen, names, &nameslen);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        (void)dirname;

        {
            size_t len = sizeof(content) - pos;
            status = qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 1U, names, nameslen, content + pos, &len);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                return status;
            }

            pos += len;
        }
    }

    if (authoritykeyidentifier->serial_present == true)
    {
        size_t len = sizeof(content) - pos;
        status = qsc_x509_write_raw(QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 2U, authoritykeyidentifier->serial, authoritykeyidentifier->seriallen, content + pos, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            return status;
        }

        pos += len;
    }

    return qsc_x509_write_sequence(content, pos, output, outputlen);
}

qsc_asn1_status qsc_x509_write_subject_alt_name(const qsc_x509_subject_alt_name* subjectaltname, uint8_t* output, size_t* outputlen)
{
    if ((subjectaltname == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return qsc_x509_write_sequence_of_general_names(subjectaltname->entries, subjectaltname->count, output, outputlen);
}

qsc_asn1_status qsc_x509_write_issuer_alt_name(const qsc_x509_issuer_alt_name* issueraltname, uint8_t* output, size_t* outputlen)
{
    if ((issueraltname == NULL) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return qsc_x509_write_sequence_of_general_names(issueraltname->entries, issueraltname->count, output, outputlen);
}
