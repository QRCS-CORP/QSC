#include "x509time.h"
#include "memutils.h"

static int32_t x509_parse_int(const char* s, size_t len)
{
    int32_t v;
    size_t i;

    v = 0;

    for (i = 0U; i < len; ++i)
    {
        const char c = s[i];

        if (c < '0' || c > '9')
        {
            v = -1;
            break;
        }

        v = (v * 10) + (int32_t)(c - '0');
    }

    return v;
}

static bool x509_time_fields_are_valid(int32_t year, int32_t mon, int32_t day, int32_t hour, int32_t min, int32_t sec)
{
    static const uint8_t mdays[12U] =
    {
        31U, 28U, 31U, 30U, 31U, 30U, 31U, 31U, 30U, 31U, 30U, 31U
    };

    uint8_t maxday;
    bool leap;
    bool res;

    res = false;

    if (year >= 0 && mon >= 1 && mon <= 12 && day >= 1 && hour >= 0 && hour <= 23 && min >= 0 && min <= 59 && sec >= 0 && sec <= 59)
    {
        maxday = mdays[(size_t)(mon - 1)];
        leap = (((year % 4) == 0) && (((year % 100) != 0) || ((year % 400) == 0))) ? true : false;

        if (mon == 2 && leap == true)
        {
            maxday = 29U;
        }

        if (day <= (int32_t)maxday)
        {
            res = true;
        }
    }

    return res;
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
    bool res;

    res = false;

    if (out != NULL && data != NULL && len == 13U && data[12U] == 'Z')
    {
        s = (const char*)data;
        year = x509_parse_int(s, 2U);
        mon = x509_parse_int(s + 2, 2U);
        day = x509_parse_int(s + 4, 2U);
        hour = x509_parse_int(s + 6, 2U);
        min = x509_parse_int(s + 8, 2U);
        sec = x509_parse_int(s + 10, 2U);

        if (year >= 0 && mon >= 0 && day >= 0 && hour >= 0 && min >= 0 && sec >= 0)
        {
            if (year < 50)
            {
                year += 2000;
            }
            else
            {
                year += 1900;
            }

            if (x509_time_fields_are_valid(year, mon, day, hour, min, sec) == true)
            {
                out->year = (uint16_t)year;
                out->month = (uint8_t)mon;
                out->day = (uint8_t)day;
                out->hour = (uint8_t)hour;
                out->minute = (uint8_t)min;
                out->second = (uint8_t)sec;
                res = true;
            }
        }
    }

    return res;
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
    bool res;

    res = false;

    if (out != NULL && data != NULL && len == 15U && data[14U] == 'Z')
    {
        s = (const char*)data;
        year = x509_parse_int(s, 4U);
        mon = x509_parse_int(s + 4, 2U);
        day = x509_parse_int(s + 6, 2U);
        hour = x509_parse_int(s + 8, 2U);
        min = x509_parse_int(s + 10, 2U);
        sec = x509_parse_int(s + 12, 2U);

        if (year >= 0 && mon >= 0 && day >= 0 && hour >= 0 && min >= 0 && sec >= 0)
        {
            if (x509_time_fields_are_valid(year, mon, day, hour, min, sec) == true)
            {
                out->year = (uint16_t)year;
                out->month = (uint8_t)mon;
                out->day = (uint8_t)day;
                out->hour = (uint8_t)hour;
                out->minute = (uint8_t)min;
                out->second = (uint8_t)sec;
                res = true;
            }
        }
    }

    return res;
}

bool qsc_x509_time_decode(qsc_x509_time* out, const qsc_encoding_ber_element* elem)
{
    QSC_ASSERT(out != NULL);
    QSC_ASSERT(elem != NULL);

    bool res;

    res = false;

    if (out != NULL && elem != NULL)
    {
        qsc_memutils_clear(out, sizeof(qsc_x509_time));

        if (elem->constructed == false && elem->tagclass == 0x00U)
        {
            if (elem->tagnumber == 23U)
            {
                res = x509_parse_utctime(out, elem->value, elem->length);
            }
            else if (elem->tagnumber == 24U)
            {
                res = x509_parse_generalizedtime(out, elem->value, elem->length);
            }
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

    if (validity != NULL && elem != NULL)
    {
        qsc_memutils_clear(validity, sizeof(qsc_x509_validity));
        status = qsc_asn1_require_tag(elem, 0x00U, true, 16U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (elem->ccount == 2U)
            {
                if (qsc_x509_time_decode(&validity->notbefore, elem->children[0]) == true &&
                    qsc_x509_time_decode(&validity->notafter, elem->children[1]) == true &&
                    qsc_x509_time_compare(&validity->notbefore, &validity->notafter) <= 0)
                {
                    status = QSC_ASN1_STATUS_SUCCESS;
                }
                else
                {
                    status = QSC_ASN1_STATUS_FAILURE;
                }
            }
            else
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
        }

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_memutils_secure_erase(validity, sizeof(qsc_x509_validity));
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

int32_t qsc_x509_time_compare(const qsc_x509_time* a, const qsc_x509_time* b)
{
    QSC_ASSERT(a != NULL);
    QSC_ASSERT(b != NULL);

    int32_t res;

    res = 0;

    if (a != NULL && b != NULL)
    {
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
    }

    return res;
}

bool qsc_x509_time_is_valid(const qsc_x509_time* time)
{
    QSC_ASSERT(time != NULL);

    bool res;

    res = false;

    if (time != NULL)
    {
        res = x509_time_fields_are_valid((int32_t)time->year, (int32_t)time->month, (int32_t)time->day,
            (int32_t)time->hour, (int32_t)time->minute, (int32_t)time->second);
    }

    return res;
}

bool qsc_x509_validity_is_valid(const qsc_x509_validity* validity, const qsc_x509_time* tnow)
{
    QSC_ASSERT(validity != NULL);
    QSC_ASSERT(tnow != NULL);

    bool res;

    res = false;

    if (validity != NULL && tnow != NULL)
    {
        if (qsc_x509_time_is_valid(&validity->notbefore) == true &&
            qsc_x509_time_is_valid(&validity->notafter) == true &&
            qsc_x509_time_is_valid(tnow) == true &&
            qsc_x509_time_compare(tnow, &validity->notbefore) >= 0 &&
            qsc_x509_time_compare(tnow, &validity->notafter) <= 0)
        {
            res = true;
        }
    }

    return res;
}

bool qsc_x509_time_parse_utctime(const char* s, size_t len, qsc_x509_time* out)
{
    QSC_ASSERT(s != NULL);
    QSC_ASSERT(out != NULL);

    bool res;

    res = false;

    if (s != NULL && out != NULL)
    {
        qsc_memutils_clear(out, sizeof(qsc_x509_time));
        res = x509_parse_utctime(out, (const uint8_t*)s, len);
    }

    return res;
}

bool qsc_x509_time_parse_generalizedtime(const char* s, size_t len, qsc_x509_time* out)
{
    QSC_ASSERT(s != NULL);
    QSC_ASSERT(out != NULL);

    bool res;

    res = false;

    if (s != NULL && out != NULL)
    {
        qsc_memutils_clear(out, sizeof(qsc_x509_time));
        res = x509_parse_generalizedtime(out, (const uint8_t*)s, len);
    }

    return res;
}
