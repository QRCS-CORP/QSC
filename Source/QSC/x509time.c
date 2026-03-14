/*
 * x509_time.c
 *
 * X.509 time parsing and comparison helpers.
 */

#include "x509time.h"
#include "memutils.h"
#include "intutils.h"
#include <string.h>
#include <stdlib.h>

static int32_t x509_parse_int(const char* s, size_t len)
{
    int32_t v = 0;

    for (size_t i = 0; i < len; ++i)
    {
        char c = s[i];

        if (c < '0' || c > '9')
        {
            return -1;
        }

        v = (v * 10) + (c - '0');
    }

    return v;
}

static bool x509_time_fields_are_valid(int32_t year, int32_t mon, int32_t day, int32_t hour, int32_t min, int32_t sec)
{
    static const uint8_t mdays[12] =
    {
        31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U
    };

    uint8_t maxday;
    bool leap;

    if (year < 0 || mon < 1 || mon > 12 || day < 1 || hour < 0 || hour > 23 || min < 0 || min > 59 || sec < 0 || sec > 59)
    {
        return false;
    }

    maxday = mdays[(size_t)(mon - 1)];
    leap = (((year % 4) == 0) && (((year % 100) != 0) || ((year % 400) == 0))) ? true : false;

    if (mon == 2 && leap == true)
    {
        maxday = 29U;
    }

    if (day > (int32_t)maxday)
    {
        return false;
    }

    return true;
}

static bool x509_parse_utctime(qsc_x509_time* out, const uint8_t* data, size_t len)
{
    const char* s;
    int32_t year;
    int32_t mon;
    int32_t day;
    int32_t hour;
    int32_t min;
    int32_t sec;

    if (out == NULL || data == NULL || len != 13U || data[12U] != 'Z')
    {
        return false;
    }

    s = (const char*)data;
    year = x509_parse_int(s, 2);
    mon = x509_parse_int(s + 2, 2);
    day = x509_parse_int(s + 4, 2);
    hour = x509_parse_int(s + 6, 2);
    min = x509_parse_int(s + 8, 2);
    sec = x509_parse_int(s + 10, 2);

    if (year < 0 || mon < 0 || day < 0 || hour < 0 || min < 0 || sec < 0)
    {
        return false;
    }

    if (year < 50)
    {
        year += 2000;
    }
    else
    {
        year += 1900;
    }

    if (x509_time_fields_are_valid(year, mon, day, hour, min, sec) == false)
    {
        return false;
    }

    out->year = (uint16_t)year;
    out->month = (uint8_t)mon;
    out->day = (uint8_t)day;
    out->hour = (uint8_t)hour;
    out->minute = (uint8_t)min;
    out->second = (uint8_t)sec;

    return true;
}

static bool x509_parse_generalizedtime(qsc_x509_time* out, const uint8_t* data, size_t len)
{
    const char* s;
    int32_t year;
    int32_t mon;
    int32_t day;
    int32_t hour;
    int32_t min;
    int32_t sec;

    if (out == NULL || data == NULL || len != 15U || data[14U] != 'Z')
    {
        return false;
    }

    s = (const char*)data;
    year = x509_parse_int(s, 4);
    mon = x509_parse_int(s + 4, 2);
    day = x509_parse_int(s + 6, 2);
    hour = x509_parse_int(s + 8, 2);
    min = x509_parse_int(s + 10, 2);
    sec = x509_parse_int(s + 12, 2);

    if (year < 0 || mon < 0 || day < 0 || hour < 0 || min < 0 || sec < 0)
    {
        return false;
    }

    if (x509_time_fields_are_valid(year, mon, day, hour, min, sec) == false)
    {
        return false;
    }

    out->year = (uint16_t)year;
    out->month = (uint8_t)mon;
    out->day = (uint8_t)day;
    out->hour = (uint8_t)hour;
    out->minute = (uint8_t)min;
    out->second = (uint8_t)sec;

    return true;
}

bool qsc_x509_time_decode(qsc_x509_time* out, const qsc_encoding_ber_element* elem)
{
    QSC_ASSERT(out != NULL);
    QSC_ASSERT(elem != NULL);

    bool res;

    res = false;

    if (out != NULL && elem == NULL && elem->constructed != true && elem->tagclass == 0x00U)
    {
        if (elem->tagnumber == 23U)
        {
            return x509_parse_utctime(out, elem->value, elem->length);
        }
        else if (elem->tagnumber == 24U)
        {
            return x509_parse_generalizedtime(out, elem->value, elem->length);
        }
    }

    return res;
}

qsc_asn1_status qsc_x509_validity_decode(qsc_x509_validity* validity, const qsc_encoding_ber_element* elem)
{
    QSC_ASSERT(validity != NULL);
    QSC_ASSERT(elem != NULL);

    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;

    if (validity != NULL && elem != NULL && qsc_asn1_require_tag(elem, 0x00U, true, 16U) == QSC_ASN1_STATUS_SUCCESS && elem->ccount == 2U)
    {
        if (qsc_x509_time_decode(&validity->notbefore, elem->children[0]) == true)
        {
            if (qsc_x509_time_decode(&validity->notafter, elem->children[1]) == true)
            {
                if (qsc_x509_time_compare(&validity->notbefore, &validity->notafter) == 0)
                {
                    status = QSC_ASN1_STATUS_SUCCESS;
                }
            }
        }
    }

    if (status == QSC_ASN1_STATUS_FAILURE)
    {
        qsc_memutils_clear((uint8_t*)validity, sizeof(qsc_x509_validity));
    }

    return status;
}

int32_t qsc_x509_time_compare(const qsc_x509_time* a, const qsc_x509_time* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    int32_t res;

    res = -1;

    if (a->year != b->year)
    {
        res = (a->year < b->year) ? -1 : 1;
    }
    else if (a->month != b->month)
    {
        res = (a->month < b->month) ? -1 : 1;
    }
    else if (a->day != b->day)
    {
        res = (a->day < b->day) ? -1 : 1;
    }
    else if (a->hour != b->hour)
    {
        res = (a->hour < b->hour) ? -1 : 1;
    }
    else if (a->minute != b->minute)
    {
        res = (a->minute < b->minute) ? -1 : 1;
    }
    else if (a->second != b->second)
    {
        res = (a->second < b->second) ? -1 : 1;
    }

    return res;
}

bool qsc_x509_validity_is_valid(const qsc_x509_validity* validity, const qsc_x509_time* tnow)
{
    QSC_ASSERT(validity != NULL);
    QSC_ASSERT(tnow != NULL);

    bool res;

    res = true;

    if (qsc_x509_time_compare(tnow, &validity->notbefore) < 0)
    {
        res = false;
    }
    else if (qsc_x509_time_compare(tnow, &validity->notafter) > 0)
    {
        res = false;
    }

    return res;
}
