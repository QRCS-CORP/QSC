#include "x509name.h"
#include "memutils.h"
#include "stringutils.h"

#define QSC_X509_TAG_SEQUENCE 16U
#define QSC_X509_TAG_SET 17U
#define QSC_X509_TAG_OBJECT_IDENTIFIER 6U

static const char* x509_name_attribute_short_name_internal(qsc_x509_name_attribute_type type)
{
    const char* name;

    switch (type)
    {
        case QSC_X509_NAME_ATTRIBUTE_COMMON_NAME:
        {
            name = "CN";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_SURNAME:
        {
            name = "SN";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_SERIAL_NUMBER:
        {
            name = "SERIALNUMBER";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_COUNTRY_NAME:
        {
            name = "C";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_LOCALITY_NAME:
        {
            name = "L";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_STATE_OR_PROVINCE:
        {
            name = "ST";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_STREET_ADDRESS:
        {
            name = "STREET";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_ORGANIZATION_NAME:
        {
            name = "O";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_ORGANIZATIONAL_UNIT:
        {
            name = "OU";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_TITLE:
        {
            name = "T";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_DESCRIPTION:
        {
            name = "DESCRIPTION";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_GIVEN_NAME:
        {
            name = "GN";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_INITIALS:
        {
            name = "INITIALS";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_GENERATION_QUALIFIER:
        {
            name = "GENERATION";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_DN_QUALIFIER:
        {
            name = "DNQUALIFIER";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_PSEUDONYM:
        {
            name = "PSEUDONYM";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_DOMAIN_COMPONENT:
        {
            name = "DC";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_EMAIL_ADDRESS:
        {
            name = "EMAIL";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_UNKNOWN:
        {
            name = "OID";
            break;
        }
        default:
        {
            name = NULL;
            break;
        }
    }

    return name;
}

static const char* x509_name_attribute_long_name_internal(qsc_x509_name_attribute_type type)
{
    const char* name;

    switch (type)
    {
        case QSC_X509_NAME_ATTRIBUTE_COMMON_NAME:
        {
            name = "commonName";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_SURNAME:
        {
            name = "surname";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_SERIAL_NUMBER:
        {
            name = "serialNumber";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_COUNTRY_NAME:
        {
            name = "countryName";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_LOCALITY_NAME:
        {
            name = "localityName";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_STATE_OR_PROVINCE:
        {
            name = "stateOrProvinceName";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_STREET_ADDRESS:
        {
            name = "streetAddress";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_ORGANIZATION_NAME:
        {
            name = "organizationName";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_ORGANIZATIONAL_UNIT:
        {
            name = "organizationalUnitName";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_TITLE:
        {
            name = "title";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_DESCRIPTION:
        {
            name = "description";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_GIVEN_NAME:
        {
            name = "givenName";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_INITIALS:
        {
            name = "initials";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_GENERATION_QUALIFIER:
        {
            name = "generationQualifier";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_DN_QUALIFIER:
        {
            name = "dnQualifier";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_PSEUDONYM:
        {
            name = "pseudonym";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_DOMAIN_COMPONENT:
        {
            name = "domainComponent";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_EMAIL_ADDRESS:
        {
            name = "emailAddress";
            break;
        }
        case QSC_X509_NAME_ATTRIBUTE_UNKNOWN:
        {
            name = "unknown";
            break;
        }
        default:
        {
            name = NULL;
            break;
        }
    }

    return name;
}

static qsc_asn1_status x509_name_parse_attribute(const qsc_encoding_ber_element* element, qsc_x509_name_attribute* attribute)
{
    const qsc_encoding_ber_element* oidelem;
    const qsc_encoding_ber_element* valelem;
    qsc_asn1_oid oid;
    size_t i;
    size_t outlen;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    outlen = 0U;

    if (element != NULL && attribute != NULL)
    {
        status = qsc_asn1_require_tag(element, 0U, true, QSC_X509_TAG_SEQUENCE);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (qsc_asn1_child_count(element) != 2U)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else
            {
                oidelem = qsc_asn1_child_at(element, 0U);
                valelem = qsc_asn1_child_at(element, 1U);
                status = qsc_asn1_require_tag(oidelem, 0U, false, QSC_X509_TAG_OBJECT_IDENTIFIER);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = qsc_asn1_decode_oid(oidelem, &oid);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    qsc_memutils_clear(attribute, sizeof(qsc_x509_name_attribute));
                    attribute->oid = qsc_oid_identify(&oid);
                    attribute->type = qsc_x509_name_attribute_type_from_oid(attribute->oid);
                    attribute->attribute_oid = oid;
                    attribute->string_tag = (uint8_t)valelem->tagnumber;
                    status = qsc_asn1_decode_string(valelem, attribute->value, sizeof(attribute->value), &outlen);

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        attribute->length = outlen;

                        if (attribute->type == QSC_X509_NAME_ATTRIBUTE_COMMON_NAME)
                        {
                            for (i = 0U; i < outlen; ++i)
                            {
                                if (attribute->value[i] == '\0')
                                {
                                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                                    break;
                                }
                            }
                        }
                    }
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

static qsc_asn1_status x509_name_append_attribute(qsc_x509_name* name, const qsc_x509_name_attribute* attribute)
{
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;

    if (name != NULL && attribute != NULL)
    {
        if (name->count < QSC_X509_NAME_ATTRIBUTES_MAX)
        {
            name->attributes[name->count] = *attribute;
            name->count += 1U;
            status = QSC_ASN1_STATUS_SUCCESS;
        }
        else
        {
            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

static bool x509_name_is_space_char(char c)
{
    return (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v');
}

static uint8_t x509_name_fold_ascii(uint8_t c)
{
    if (c >= (uint8_t)'A' && c <= (uint8_t)'Z')
    {
        c = (uint8_t)(c - (uint8_t)'A' + (uint8_t)'a');
    }

    return c;
}

static bool x509_name_value_equals_canonical(const char* a, size_t alen, const char* b, size_t blen)
{
    /* Non-ASCII UTF-8 octets are compared byte-for-byte; ASCII letters are case-folded and ASCII whitespace is normalized. */
    size_t ia;
    size_t ib;
    size_t enda;
    size_t endb;
    bool inspacea;
    bool inspaceb;
    bool res;

    res = false;

    if (a != NULL && b != NULL)
    {
        ia = 0U;
        ib = 0U;
        enda = alen;
        endb = blen;

        while (ia < enda && x509_name_is_space_char(a[ia]) == true)
        {
            ia += 1U;
        }

        while (ib < endb && x509_name_is_space_char(b[ib]) == true)
        {
            ib += 1U;
        }

        while (enda > ia && x509_name_is_space_char(a[enda - 1U]) == true)
        {
            enda -= 1U;
        }

        while (endb > ib && x509_name_is_space_char(b[endb - 1U]) == true)
        {
            endb -= 1U;
        }

        inspacea = false;
        inspaceb = false;
        res = true;

        for (;;)
        {
            uint8_t ca;
            uint8_t cb;

            while (ia < enda && x509_name_is_space_char(a[ia]) == true)
            {
                inspacea = true;
                ia += 1U;
            }

            while (ib < endb && x509_name_is_space_char(b[ib]) == true)
            {
                inspaceb = true;
                ib += 1U;
            }

            if (ia == enda || ib == endb)
            {
                break;
            }

            if (inspacea != inspaceb)
            {
                res = false;
                break;
            }

            if (inspacea == true)
            {
                inspacea = false;
                inspaceb = false;
            }

            ca = x509_name_fold_ascii((uint8_t)a[ia]);
            cb = x509_name_fold_ascii((uint8_t)b[ib]);

            if (ca != cb)
            {
                res = false;
                break;
            }

            ia += 1U;
            ib += 1U;
        }

        if (res == true)
        {
            while (ia < enda && x509_name_is_space_char(a[ia]) == true)
            {
                ia += 1U;
            }

            while (ib < endb && x509_name_is_space_char(b[ib]) == true)
            {
                ib += 1U;
            }

            res = (ia == enda && ib == endb);
        }
    }

    return res;
}

static bool x509_name_attribute_equals(const qsc_x509_name_attribute* a, const qsc_x509_name_attribute* b)
{
    bool res;

    res = false;

    if (a != NULL && b != NULL && a->type == b->type)
    {
        if (a->type > QSC_X509_NAME_ATTRIBUTE_NONE && a->type < QSC_X509_NAME_ATTRIBUTE_UNKNOWN)
        {
            if (a->oid != QSC_OID_ID_NONE && b->oid != QSC_OID_ID_NONE)
            {
                res = (a->oid == b->oid);
            }
            else
            {
                res = true;
            }
        }
        else if (a->type == QSC_X509_NAME_ATTRIBUTE_UNKNOWN &&
            a->attribute_oid.length != 0U && b->attribute_oid.length != 0U)
        {
            res = qsc_asn1_oid_are_equal(&a->attribute_oid, &b->attribute_oid);
        }

        if (res == true)
        {
            res = x509_name_value_equals_canonical(a->value, a->length, b->value, b->length);
        }
    }

    return res;
}

static size_t x509_name_rdn_end(const qsc_x509_name* name, size_t start)
{
    size_t end;
    uint16_t rdn;

    end = start;
    rdn = name->attributes[start].rdn_index;

    while (end < name->count && name->attributes[end].rdn_index == rdn)
    {
        end += 1U;
    }

    return end;
}

static qsc_asn1_status x509_name_append_chars(char* output, size_t otplen, size_t* pos, const char* src, size_t srclen)
{
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (output != NULL && pos != NULL && src != NULL)
    {
        if (*pos >= otplen)
        {
            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }
        else if ((srclen + 1U) > (otplen - *pos))
        {
            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            if (srclen > 0U)
            {
                qsc_memutils_copy((uint8_t*)(output + *pos), (const uint8_t*)src, srclen);
                *pos += srclen;
            }

            output[*pos] = '\0';
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    return status;
}

static qsc_asn1_status x509_name_append_cstring(char* output, size_t otplen, size_t* pos, const char* src)
{
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (src != NULL)
    {
        status = x509_name_append_chars(output, otplen, pos, src, qsc_stringutils_string_size(src));
    }

    return status;
}

void qsc_x509_name_clear(qsc_x509_name* name)
{
    QSC_ASSERT(name != NULL);

    if (name != NULL)
    {
        qsc_memutils_clear(name, sizeof(qsc_x509_name));
    }
}

qsc_x509_name_attribute_type qsc_x509_name_attribute_type_from_oid(qsc_oid_id id)
{
    qsc_x509_name_attribute_type type;

    switch (id)
    {
        case QSC_OID_ID_COMMON_NAME:
        {
            type = QSC_X509_NAME_ATTRIBUTE_COMMON_NAME;
            break;
        }
        case QSC_OID_ID_SURNAME:
        {
            type = QSC_X509_NAME_ATTRIBUTE_SURNAME;
            break;
        }
        case QSC_OID_ID_SERIAL_NUMBER:
        {
            type = QSC_X509_NAME_ATTRIBUTE_SERIAL_NUMBER;
            break;
        }
        case QSC_OID_ID_COUNTRY_NAME:
        {
            type = QSC_X509_NAME_ATTRIBUTE_COUNTRY_NAME;
            break;
        }
        case QSC_OID_ID_LOCALITY_NAME:
        {
            type = QSC_X509_NAME_ATTRIBUTE_LOCALITY_NAME;
            break;
        }
        case QSC_OID_ID_STATE_OR_PROVINCE_NAME:
        {
            type = QSC_X509_NAME_ATTRIBUTE_STATE_OR_PROVINCE;
            break;
        }
        case QSC_OID_ID_STREET_ADDRESS:
        {
            type = QSC_X509_NAME_ATTRIBUTE_STREET_ADDRESS;
            break;
        }
        case QSC_OID_ID_ORGANIZATION_NAME:
        {
            type = QSC_X509_NAME_ATTRIBUTE_ORGANIZATION_NAME;
            break;
        }
        case QSC_OID_ID_ORGANIZATIONAL_UNIT_NAME:
        {
            type = QSC_X509_NAME_ATTRIBUTE_ORGANIZATIONAL_UNIT;
            break;
        }
        case QSC_OID_ID_TITLE:
        {
            type = QSC_X509_NAME_ATTRIBUTE_TITLE;
            break;
        }
        case QSC_OID_ID_DESCRIPTION:
        {
            type = QSC_X509_NAME_ATTRIBUTE_DESCRIPTION;
            break;
        }
        case QSC_OID_ID_GIVEN_NAME:
        {
            type = QSC_X509_NAME_ATTRIBUTE_GIVEN_NAME;
            break;
        }
        case QSC_OID_ID_INITIALS:
        {
            type = QSC_X509_NAME_ATTRIBUTE_INITIALS;
            break;
        }
        case QSC_OID_ID_GENERATION_QUALIFIER:
        {
            type = QSC_X509_NAME_ATTRIBUTE_GENERATION_QUALIFIER;
            break;
        }
        case QSC_OID_ID_DN_QUALIFIER:
        {
            type = QSC_X509_NAME_ATTRIBUTE_DN_QUALIFIER;
            break;
        }
        case QSC_OID_ID_PSEUDONYM:
        {
            type = QSC_X509_NAME_ATTRIBUTE_PSEUDONYM;
            break;
        }
        case QSC_OID_ID_DOMAIN_COMPONENT:
        {
            type = QSC_X509_NAME_ATTRIBUTE_DOMAIN_COMPONENT;
            break;
        }
        case QSC_OID_ID_EMAIL_ADDRESS:
        {
            type = QSC_X509_NAME_ATTRIBUTE_EMAIL_ADDRESS;
            break;
        }
        default:
        {
            type = QSC_X509_NAME_ATTRIBUTE_UNKNOWN;
            break;
        }
    }

    return type;
}

const char* qsc_x509_name_attribute_short_name(qsc_x509_name_attribute_type type)
{
    QSC_ASSERT(type >= QSC_X509_NAME_ATTRIBUTE_UNKNOWN && type <= QSC_X509_NAME_ATTRIBUTE_EMAIL_ADDRESS);

    return x509_name_attribute_short_name_internal(type);
}

const char* qsc_x509_name_attribute_long_name(qsc_x509_name_attribute_type type)
{
    QSC_ASSERT(type >= QSC_X509_NAME_ATTRIBUTE_UNKNOWN && type <= QSC_X509_NAME_ATTRIBUTE_EMAIL_ADDRESS);

    return x509_name_attribute_long_name_internal(type);
}

qsc_asn1_status qsc_x509_name_parse(const qsc_encoding_ber_element* element, qsc_x509_name* name)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(name != NULL);

    const qsc_encoding_ber_element* rdn;
    const qsc_encoding_ber_element* attr;
    qsc_x509_name_attribute parsed;
    qsc_asn1_status status;
    size_t i;
    size_t j;

    status = QSC_ASN1_STATUS_FAILURE;

    if (element != NULL && name != NULL)
    {
        qsc_x509_name_clear(name);
        status = qsc_asn1_require_tag(element, 0U, true, QSC_X509_TAG_SEQUENCE);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            for (i = 0U; i < qsc_asn1_child_count(element); ++i)
            {
                rdn = qsc_asn1_child_at(element, i);
                status = qsc_asn1_require_tag(rdn, 0U, true, QSC_X509_TAG_SET);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    break;
                }

                if (qsc_asn1_child_count(rdn) == 0U)
                {
                    status = QSC_ASN1_STATUS_INVALID_LENGTH;
                    break;
                }

                for (j = 0U; j < qsc_asn1_child_count(rdn); ++j)
                {
                    attr = qsc_asn1_child_at(rdn, j);
                    status = x509_name_parse_attribute(attr, &parsed);

                    if (status != QSC_ASN1_STATUS_SUCCESS)
                    {
                        break;
                    }

                    parsed.rdn_index = (uint16_t)i;
                    status = x509_name_append_attribute(name, &parsed);

                    if (status != QSC_ASN1_STATUS_SUCCESS)
                    {
                        break;
                    }
                }

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    break;
                }
            }
        }

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_x509_name_clear(name);
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

const qsc_x509_name_attribute* qsc_x509_name_find_first(const qsc_x509_name* name, qsc_x509_name_attribute_type type)
{
    QSC_ASSERT(name != NULL);

    const qsc_x509_name_attribute* attribute;
    size_t i;

    attribute = NULL;

    if (name != NULL)
    {
        for (i = 0U; i < name->count; ++i)
        {
            if (name->attributes[i].type == type)
            {
                attribute = &name->attributes[i];
                break;
            }
        }
    }

    return attribute;
}

bool qsc_x509_name_equals(const qsc_x509_name* a, const qsc_x509_name* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    size_t ia;
    size_t ib;
    bool res;

    res = false;

    if (a != NULL && b != NULL && a->count == b->count)
    {
        ia = 0U;
        ib = 0U;
        res = true;

        while (ia < a->count && ib < b->count)
        {
            size_t enda;
            size_t endb;
            size_t acount;
            size_t bcount;
            bool matched[QSC_X509_NAME_ATTRIBUTES_MAX];
            size_t i;

            enda = x509_name_rdn_end(a, ia);
            endb = x509_name_rdn_end(b, ib);
            acount = enda - ia;
            bcount = endb - ib;

            if (acount != bcount)
            {
                res = false;
                break;
            }

            qsc_memutils_clear((uint8_t*)matched, sizeof(matched));

            for (i = ia; i < enda; ++i)
            {
                bool found;
                size_t j;

                found = false;

                for (j = ib; j < endb; ++j)
                {
                    size_t mj;

                    mj = j - ib;

                    if (matched[mj] == false && x509_name_attribute_equals(&a->attributes[i], &b->attributes[j]) == true)
                    {
                        matched[mj] = true;
                        found = true;
                        break;
                    }
                }

                if (found == false)
                {
                    res = false;
                    break;
                }
            }

            if (res == false)
            {
                break;
            }

            ia = enda;
            ib = endb;
        }

        if (res == true)
        {
            res = (ia == a->count && ib == b->count);
        }
    }

    return res;
}

qsc_asn1_status qsc_x509_name_to_string(const qsc_x509_name* name, char* output, size_t otplen, size_t* outlen)
{
    QSC_ASSERT(name != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(outlen != NULL);

    const char* label;
    size_t pos;
    qsc_asn1_status status;
    char oidstr[96U] = { 0 };
    size_t i;

    status = QSC_ASN1_STATUS_FAILURE;
    pos = 0U;
    label = NULL;

    if (outlen != NULL)
    {
        *outlen = 0U;
    }

    if (name != NULL && output != NULL && otplen != 0U && outlen != NULL)
    {
        output[0U] = '\0';
        status = QSC_ASN1_STATUS_SUCCESS;

        for (i = 0U; i < name->count; ++i)
        {
            if (i != 0U)
            {
                status = x509_name_append_cstring(output, otplen, &pos, ", ");
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                label = x509_name_attribute_short_name_internal(name->attributes[i].type);

                if (label == NULL)
                {
                    status = qsc_asn1_oid_to_string(&name->attributes[i].attribute_oid, oidstr, sizeof(oidstr));

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        label = oidstr;
                    }
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = x509_name_append_cstring(output, otplen, &pos, label);
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = x509_name_append_cstring(output, otplen, &pos, "=");
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = x509_name_append_chars(output, otplen, &pos, name->attributes[i].value, name->attributes[i].length);
            }

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                break;
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            *outlen = pos;
        }
        else
        {
            output[0U] = '\0';
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}
