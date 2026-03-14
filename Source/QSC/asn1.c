#include "asn1.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include <stdio.h>

static bool asn1_is_valid_month_day(uint16_t year, uint8_t month, uint8_t day)
{
    static const uint8_t mdays[12U] =
    {
        31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U
    };
    uint8_t dim;
    bool leap;
    bool res;

    res = false;

    if (month >= 1U && month <= 12U && day >= 1U)
    {
        dim = mdays[month - 1U];
        leap = (((year % 4U) == 0U) && (((year % 100U) != 0U) || ((year % 400U) == 0U)));

        if (month == 2U && leap == true)
        {
            dim = 29U;
        }

        res = (day <= dim);
    }

    return res;
}

static qsc_asn1_status asn1_parse_decimal_pair(const uint8_t* input, uint8_t* value)
{
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_ENCODING;

    if (input != NULL && value != NULL)
    {
        if (input[0U] >= '0' && input[0U] <= '9' && input[1U] >= '0' && input[1U] <= '9')
        {
            *value = (uint8_t)(((uint8_t)(input[0U] - '0') * 10U) + (uint8_t)(input[1U] - '0'));
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

static qsc_asn1_status asn1_parse_decimal_quad(const uint8_t* input, uint16_t* value)
{
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_ENCODING;

    if (input != NULL && value != NULL)
    {
        if (input[0U] >= '0' && input[0U] <= '9' &&
            input[1U] >= '0' && input[1U] <= '9' &&
            input[2U] >= '0' && input[2U] <= '9' &&
            input[3U] >= '0' && input[3U] <= '9')
        {
            *value = (uint16_t)((uint16_t)(input[0U] - '0') * 1000U) +
                (uint16_t)((uint16_t)(input[1U] - '0') * 100U) +
                (uint16_t)((uint16_t)(input[2U] - '0') * 10U) +
                (uint16_t)(input[3U] - '0');

            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

static size_t asn1_length_field_size(size_t length)
{
    size_t count;
    size_t value;

    if (length < 128U)
    {
        count = 1U;
    }
    else
    {
        count = 0U;
        value = length;

        while (value != 0U)
        {
            ++count;
            value >>= 8;
        }

        count += 1U;
    }

    return count;
}

static qsc_asn1_status asn1_decode_bmp_string(const qsc_encoding_ber_element* element, char* output, size_t otplen, size_t* outlen)
{
    qsc_asn1_status status;
    size_t i;
    size_t chars;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && output != NULL && otplen != 0U && outlen != NULL)
    {
        if ((element->length % 2U) != 0U)
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
        else
        {
            chars = element->length / 2U;

            if ((chars + 1U) > otplen)
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                status = QSC_ASN1_STATUS_SUCCESS;

                for (i = 0U; i < chars; ++i)
                {
                    const uint8_t hi = element->value[(i * 2U)];
                    const uint8_t lo = element->value[(i * 2U) + 1U];

                    if (hi != 0U || lo > 0x7FU)
                    {
                        status = QSC_ASN1_STATUS_UNSUPPORTED;
                        break;
                    }

                    output[i] = (char)lo;
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    output[chars] = '\0';
                    *outlen = chars;
                }
            }
        }
    }

    return status;
}

static qsc_asn1_status asn1_decode_universal_string(const qsc_encoding_ber_element* element, char* output, size_t otplen, size_t* outlen)
{
    qsc_asn1_status status;
    size_t i;
    size_t chars;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && output != NULL && otplen != 0U && outlen != NULL)
    {
        if ((element->length % 4U) != 0U)
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
        else
        {
            chars = element->length / 4U;

            if ((chars + 1U) > otplen)
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                status = QSC_ASN1_STATUS_SUCCESS;

                for (i = 0U; i < chars; ++i)
                {
                    const uint8_t b0 = element->value[(i * 4U)];
                    const uint8_t b1 = element->value[(i * 4U) + 1U];
                    const uint8_t b2 = element->value[(i * 4U) + 2U];
                    const uint8_t b3 = element->value[(i * 4U) + 3U];

                    if (b0 != 0U || b1 != 0U || b2 != 0U || b3 > 0x7FU)
                    {
                        status = QSC_ASN1_STATUS_UNSUPPORTED;
                        break;
                    }

                    output[i] = (char)b3;
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    output[chars] = '\0';
                    *outlen = chars;
                }
            }
        }
    }

    return status;
}

bool qsc_asn1_oid_compare(const qsc_asn1_oid* a, const qsc_asn1_oid* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res;

    res = false;

    if (a != NULL && b != NULL)
    {
        res = qsc_asn1_oid_are_equal(a, b);
    }

    return res;
}

qsc_asn1_status qsc_asn1_require_sequence(const qsc_encoding_ber_element* element, size_t minchildren, size_t maxchildren)
{
    QSC_ASSERT(element != NULL);

    qsc_asn1_status status;
    size_t count;

    status = QSC_ASN1_STATUS_FAILURE;

    if (element != NULL)
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, true, BER_ASN1_SEQUENCE);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            count = qsc_asn1_child_count(element);

            if (count < minchildren || count > maxchildren)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
        }
    }

    return status;
}

const qsc_encoding_ber_element* qsc_asn1_get_child(const qsc_encoding_ber_element* element, size_t index)
{
    QSC_ASSERT(element != NULL);

    qsc_encoding_ber_element* elem;

    if (element != NULL)
    {
        elem = qsc_asn1_child_at(element, index);
    }
    else
    {
        elem = NULL;
    }

    return elem;
}

bool qsc_asn1_is_boolean(const qsc_encoding_ber_element* element)
{
    QSC_ASSERT(element != NULL);

    bool res;

    res = false;

    if (element != NULL)
    {
        res = qsc_asn1_element_is_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_BOOLEAN);
    }

    return res;
}

bool qsc_asn1_is_integer(const qsc_encoding_ber_element* element)
{
    QSC_ASSERT(element != NULL);

    bool res;

    res = false;

    if (element != NULL)
    {
        res = qsc_asn1_element_is_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_INTEGER);
    }

    return res;
}

qsc_asn1_status qsc_asn1_decode_integer_u64(const qsc_encoding_ber_element* element, uint64_t* value)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(value != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;

    if (element != NULL)
    {
        status = qsc_asn1_decode_uint64(element, value);
    }

    return status;
}

bool qsc_asn1_is_null(const qsc_encoding_ber_element* element)
{
    QSC_ASSERT(element != NULL);

    bool res;

    res = false;

    if (element != NULL)
    {
        res = qsc_asn1_element_is_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_NULL);
    }

    return res;
}

bool qsc_asn1_is_oid(const qsc_encoding_ber_element* element)
{
    QSC_ASSERT(element != NULL);

    bool res;

    res = false;

    if (element != NULL)
    {
        res = qsc_asn1_element_is_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OBJECT_IDENTIFIER);
    }

    return res;
}

bool qsc_asn1_element_is_tag(const qsc_encoding_ber_element* element, uint8_t tagclass, bool constructed, uint32_t tagnumber)
{
    QSC_ASSERT(element != NULL);

    bool res;

    res = false;

    if (element != NULL)
    {
        res = (element->tagclass == tagclass && element->constructed == constructed && element->tagnumber == tagnumber);
    }

    return res;
}

qsc_asn1_status qsc_asn1_require_tag(const qsc_encoding_ber_element* element, uint8_t tagclass, bool constructed, uint32_t tagnumber)
{
    QSC_ASSERT(element != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL)
    {
        status = qsc_asn1_element_is_tag(element, tagclass, constructed, tagnumber) ?
            QSC_ASN1_STATUS_SUCCESS : QSC_ASN1_STATUS_INVALID_TAG;
    }

    return status;
}

size_t qsc_asn1_child_count(const qsc_encoding_ber_element* element)
{
    QSC_ASSERT(element != NULL);

    size_t count;

    count = 0U;

    if (element != NULL && element->constructed == true && element->children != NULL)
    {
        count = element->ccount;
    }

    return count;
}

const qsc_encoding_ber_element* qsc_asn1_child_at(const qsc_encoding_ber_element* element, size_t index)
{
    QSC_ASSERT(element != NULL);

    const qsc_encoding_ber_element* child;

    child = NULL;

    if (element != NULL && element->constructed == true && element->children != NULL && index < element->ccount)
    {
        child = element->children[index];
    }

    return child;
}

const qsc_encoding_ber_element* qsc_asn1_find_context_child(const qsc_encoding_ber_element* element, uint32_t tagnumber)
{
    QSC_ASSERT(element != NULL);

    const qsc_encoding_ber_element* child;
    size_t i;

    child = NULL;

    if (element != NULL && element->constructed == true && element->children != NULL)
    {
        for (i = 0U; i < element->ccount; ++i)
        {
            const qsc_encoding_ber_element* cur;

            cur = element->children[i];

            if (cur != NULL && cur->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC && cur->tagnumber == tagnumber)
            {
                child = cur;
                break;
            }
        }
    }

    return child;
}

qsc_asn1_status qsc_asn1_get_explicit_child(const qsc_encoding_ber_element* element, const qsc_encoding_ber_element** child)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(child != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && child != NULL)
    {
        if (element->tagclass != QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC || element->constructed == false)
        {
            status = QSC_ASN1_STATUS_INVALID_TAG;
        }
        else if (element->ccount != 1U || element->children == NULL || element->children[0U] == NULL)
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
        else
        {
            *child = element->children[0U];
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    return status;
}

qsc_asn1_status qsc_asn1_decode_boolean(const qsc_encoding_ber_element* element, bool* value)
{
    QSC_ASSERT(element != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && value != NULL)
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_BOOLEAN);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (value == NULL)
            {
                status = QSC_ASN1_STATUS_INVALID_INPUT;
            }
            else if (element->length != 1U || element->value == NULL)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else
            {
                *value = (element->value[0U] != 0U);
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_asn1_decode_uint64(const qsc_encoding_ber_element* element, uint64_t* value)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(value != NULL);

    qsc_asn1_status status;
    uint64_t val;
    size_t i;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && value != NULL)
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_INTEGER);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (value == NULL)
            {
                status = QSC_ASN1_STATUS_INVALID_INPUT;
            }
            else if (element->length == 0U || element->length > sizeof(uint64_t) || element->value == NULL)
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

qsc_asn1_status qsc_asn1_decode_octet_string(const qsc_encoding_ber_element* element, uint8_t* output, size_t otplen, size_t* outlen)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(outlen != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && output != NULL && outlen != NULL)
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OCTET_STRING);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (output == NULL || outlen == NULL)
            {
                status = QSC_ASN1_STATUS_INVALID_INPUT;
            }
            else if (element->length > otplen)
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else if (element->length != 0U && element->value == NULL)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else
            {
                if (element->length != 0U)
                {
                    qsc_memutils_copy(output, element->value, element->length);
                }

                *outlen = element->length;
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_asn1_decode_bit_string(const qsc_encoding_ber_element* element, qsc_asn1_bit_string* value)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(value != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && value != NULL)
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_BIT_STRING);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (value == NULL)
            {
                status = QSC_ASN1_STATUS_INVALID_INPUT;
            }
            else if (element->length == 0U || element->value == NULL)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else if (element->value[0U] > QSC_ASN1_BIT_STRING_MAX_UNUSED_BITS)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else if (element->length == 1U && element->value[0U] != 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                value->unused = element->value[0U];
                value->data = element->value + 1U;
                value->length = element->length - 1U;

                if (value->length != 0U && value->unused != 0U)
                {
                    const uint8_t mask = (uint8_t)((1U << value->unused) - 1U);

                    if ((value->data[value->length - 1U] & mask) != 0U)
                    {
                        status = QSC_ASN1_STATUS_INVALID_ENCODING;
                    }
                }
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_asn1_decode_null(const qsc_encoding_ber_element* element)
{
    QSC_ASSERT(element != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL)
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_NULL);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (element->length != 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_asn1_decode_oid(const qsc_encoding_ber_element* element, qsc_asn1_oid* oid)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(oid != NULL);

    qsc_asn1_status status;
    size_t i;
    size_t acount;
    uint32_t value;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && oid != NULL)
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OBJECT_IDENTIFIER);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (oid == NULL)
            {
                status = QSC_ASN1_STATUS_INVALID_INPUT;
            }
            else if (element->length == 0U || element->length > QSC_ASN1_OID_MAX_SIZE || element->value == NULL)
            {
                status = QSC_ASN1_STATUS_OUT_OF_RANGE;
            }
            else
            {
                qsc_memutils_clear((uint8_t*)oid, sizeof(qsc_asn1_oid));
                qsc_memutils_copy(oid->data, element->value, element->length);
                oid->length = element->length;
                oid->arcs[0U] = element->value[0U] / 40U;
                oid->arcs[1U] = element->value[0U] % 40U;
                acount = 2U;
                value = 0U;

                for (i = 1U; i < element->length; ++i)
                {
                    const uint8_t b = element->value[i];

                    if ((value & 0xFE000000U) != 0U)
                    {
                        status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                        break;
                    }

                    value = (value << 7) | (uint32_t)(b & 0x7FU);

                    if ((b & 0x80U) == 0U)
                    {
                        if (acount >= QSC_ASN1_OID_MAX_ARCS)
                        {
                            status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                            break;
                        }

                        oid->arcs[acount] = value;
                        ++acount;
                        value = 0U;
                    }
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    if ((element->value[element->length - 1U] & 0x80U) != 0U)
                    {
                        status = QSC_ASN1_STATUS_INVALID_ENCODING;
                    }
                    else
                    {
                        oid->arcscount = acount;
                    }
                }
            }
        }
    }

    return status;
}

bool qsc_asn1_oid_are_equal(const qsc_asn1_oid* a, const qsc_asn1_oid* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    bool res;

    res = false;

    if (a != NULL && b != NULL && a->length == b->length)
    {
        res = qsc_memutils_are_equal(a->data, b->data, a->length);
    }

    return res;
}

qsc_asn1_status qsc_asn1_oid_to_string(const qsc_asn1_oid* oid, char* output, size_t otplen)
{
    QSC_ASSERT(oid != NULL);

    qsc_asn1_status status;
    int32_t count;
    size_t used;
    size_t i;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (oid != NULL && output != NULL && otplen != 0U)
    {
        if (oid->arcscount < 2U)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else
        {
            count = snprintf(output, otplen, "%u.%u", oid->arcs[0U], oid->arcs[1U]);

            if (count <= 0 || (size_t)count >= otplen)
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                used = (size_t)count;
                status = QSC_ASN1_STATUS_SUCCESS;

                for (i = 2U; i < oid->arcscount; ++i)
                {
                    count = snprintf(output + used, otplen - used, ".%u", oid->arcs[i]);

                    if (count <= 0 || (size_t)count >= (otplen - used))
                    {
                        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                        break;
                    }

                    used += (size_t)count;
                }
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_asn1_decode_string(const qsc_encoding_ber_element* element, char* output, size_t otplen, size_t* outlen)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(outlen != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && output != NULL && otplen != 0U && outlen != NULL)
    {
        if (element->constructed == true || element->value == NULL)
        {
            status = QSC_ASN1_STATUS_INVALID_TAG;
        }
        else
        {
            switch (element->tagnumber)
            {
            case BER_ASN1_PRINTABLE_STRING:
            case BER_ASN1_UTF8_STRING:
            case BER_ASN1_IA5_STRING:
            case BER_ASN1_T61_STRING:
            case BER_ASN1_VISIBLE_STRING:
            case BER_ASN1_NUMERIC_STRING:
            case BER_ASN1_GENERAL_STRING:
            {
                if ((element->length + 1U) > otplen)
                {
                    status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    qsc_memutils_copy((uint8_t*)output, element->value, element->length);
                    output[element->length] = '\0';
                    *outlen = element->length;
                    status = QSC_ASN1_STATUS_SUCCESS;
                }
                break;
            }
            case BER_ASN1_BMP_STRING:
            {
                status = asn1_decode_bmp_string(element, output, otplen, outlen);
                break;
            }
            case BER_ASN1_UNIVERSAL_STRING:
            {
                status = asn1_decode_universal_string(element, output, otplen, outlen);
                break;
            }
            default:
            {
                status = QSC_ASN1_STATUS_UNSUPPORTED;
                break;
            }
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_asn1_decode_time(const qsc_encoding_ber_element* element, qsc_asn1_time* value)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(value != NULL);

    qsc_asn1_status status;
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    uint16_t year;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && value != NULL)
    {
        qsc_memutils_clear((uint8_t*)value, sizeof(qsc_asn1_time));

        if (qsc_asn1_element_is_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_UTCTIME))
        {
            if (element->length != 13U || element->value == NULL || element->value[12U] != 'Z')
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                uint8_t yy;

                status = asn1_parse_decimal_pair(element->value, &yy);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    year = (yy >= 50U) ? (uint16_t)(1900U + yy) : (uint16_t)(2000U + yy);
                    status = asn1_parse_decimal_pair(element->value + 2U, &month);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = asn1_parse_decimal_pair(element->value + 4U, &day);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = asn1_parse_decimal_pair(element->value + 6U, &hour);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = asn1_parse_decimal_pair(element->value + 8U, &minute);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = asn1_parse_decimal_pair(element->value + 10U, &second);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    if (asn1_is_valid_month_day(year, month, day) == false || hour > 23U || minute > 59U || second > 59U)
                    {
                        status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                    }
                    else
                    {
                        value->year = year;
                        value->month = month;
                        value->day = day;
                        value->hour = hour;
                        value->minute = minute;
                        value->second = second;
                        value->generalized = false;
                    }
                }
            }
        }
        else if (qsc_asn1_element_is_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_GENERALIZEDTIME))
        {
            if (element->length != 15U || element->value == NULL || element->value[14U] != 'Z')
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                status = asn1_parse_decimal_quad(element->value, &year);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = asn1_parse_decimal_pair(element->value + 4U, &month);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = asn1_parse_decimal_pair(element->value + 6U, &day);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = asn1_parse_decimal_pair(element->value + 8U, &hour);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = asn1_parse_decimal_pair(element->value + 10U, &minute);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = asn1_parse_decimal_pair(element->value + 12U, &second);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    if (asn1_is_valid_month_day(year, month, day) == false || hour > 23U || minute > 59U || second > 59U)
                    {
                        status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                    }
                    else
                    {
                        value->year = year;
                        value->month = month;
                        value->day = day;
                        value->hour = hour;
                        value->minute = minute;
                        value->second = second;
                        value->generalized = true;
                    }
                }
            }
        }
        else
        {
            status = QSC_ASN1_STATUS_INVALID_TAG;
        }
    }

    return status;
}

int32_t qsc_asn1_time_compare(const qsc_asn1_time* a, const qsc_asn1_time* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    int32_t result;

    result = 0;

    if (a != NULL && b != NULL)
    {
        if (a->year != b->year)
        {
            result = (a->year < b->year) ? -1 : 1;
        }
        else if (a->month != b->month)
        {
            result = (a->month < b->month) ? -1 : 1;
        }
        else if (a->day != b->day)
        {
            result = (a->day < b->day) ? -1 : 1;
        }
        else if (a->hour != b->hour)
        {
            result = (a->hour < b->hour) ? -1 : 1;
        }
        else if (a->minute != b->minute)
        {
            result = (a->minute < b->minute) ? -1 : 1;
        }
        else if (a->second != b->second)
        {
            result = (a->second < b->second) ? -1 : 1;
        }
    }

    return result;
}

qsc_asn1_status qsc_asn1_der_size(const qsc_encoding_ber_element* element, size_t* length)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(length != NULL);

    qsc_asn1_status status;
    size_t content;
    size_t i;

    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (element != NULL && length != NULL)
    {
        if (element->indefinite == true)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else
        {
            if (element->constructed == true)
            {
                content = 0U;

                for (i = 0U; i < element->ccount; ++i)
                {
                    size_t childsz;

                    if (element->children == NULL || element->children[i] == NULL)
                    {
                        status = QSC_ASN1_STATUS_INVALID_LENGTH;
                        break;
                    }

                    status = qsc_asn1_der_size(element->children[i], &childsz);

                    if (status != QSC_ASN1_STATUS_SUCCESS)
                    {
                        break;
                    }

                    content += childsz;
                }
            }
            else
            {
                content = element->length;
            }

            if (status == QSC_ASN1_STATUS_INVALID_INPUT)
            {
                status = QSC_ASN1_STATUS_SUCCESS;
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                uint8_t tagbuf[10U] = { 0U };
                const size_t taglen = qsc_encoding_ber_encode_tag(element->tagclass, element->constructed, element->tagnumber, tagbuf, sizeof(tagbuf));

                if (taglen == 0U)
                {
                    status = QSC_ASN1_STATUS_FAILURE;
                }
                else
                {
                    *length = taglen + asn1_length_field_size(content) + content;
                }
            }
        }
    }

    return status;
}
