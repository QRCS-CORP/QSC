#include "x509host.h"
#include "memutils.h"
#include "stringutils.h"

static int32_t x509_ascii_tolower(int32_t c)
{
    int32_t res;

    res = c;

    if (c >= 'A' && c <= 'Z')
    {
        res = c + 32;
    }

    return res;
}

static bool x509_ascii_case_equal_n(const char* left, const char* right, size_t length)
{
    bool res;
    size_t i;

    res = true;

    for (i = 0U; i < length; ++i)
    {
        if (left[i] == '\0' || right[i] == '\0')
        {
            res = false;
            break;
        }

        if (x509_ascii_tolower((uint8_t)left[i]) != x509_ascii_tolower((uint8_t)right[i]))
        {
            res = false;
            break;
        }
    }

    return res;
}

static bool x509_ascii_case_equal(const char* left, const char* right)
{
    size_t llen;
    size_t rlen;
    bool res;

    res = false;

    if (left != (const char*)NULL && right != (const char*)NULL)
    {
        llen = qsc_stringutils_string_size(left);
        rlen = qsc_stringutils_string_size(right);

        if (llen == rlen)
        {
            res = x509_ascii_case_equal_n(left, right, llen);
        }
    }

    return res;
}

static const char* x509_find_char(const char* s, char c)
{
    const char* res;

    res = (const char*)NULL;

    if (s != (const char*)NULL)
    {
        while (*s != '\0')
        {
            if (*s == c)
            {
                res = s;
                break;
            }

            ++s;
        }
    }

    return res;
}

static bool x509_dns_label_has_wildcard(const char* pattern)
{
    const char* dot;
    const char* p;
    bool res;

    res = false;

    if (pattern != (const char*)NULL)
    {
        dot = x509_find_char(pattern, '.');
        p = pattern;

        while (*p != '\0' && (dot == (const char*)NULL || p < dot))
        {
            if (*p == '*')
            {
                res = true;
                break;
            }

            ++p;
        }
    }

    return res;
}

static bool x509_dns_first_label_is_idna(const char* name)
{
    bool res;

    res = false;

    if (name != (const char*)NULL)
    {
        res = (x509_ascii_tolower((uint8_t)name[0U]) == 'x' &&
            x509_ascii_tolower((uint8_t)name[1U]) == 'n' &&
            name[2U] == '-' && name[3U] == '-');
    }

    return res;
}

static bool x509_dns_pattern_is_valid(const char* pattern)
{
    const char* dot;
    size_t plen;
    bool res;

    res = false;

    if (pattern != (const char*)NULL && pattern[0U] != '\0')
    {
        plen = qsc_stringutils_string_size(pattern);

        if (plen != 0U && pattern[0U] != '.' && pattern[plen - 1U] != '.')
        {
            if (x509_dns_label_has_wildcard(pattern) == false)
            {
                res = true;
            }
            else
            {
                dot = x509_find_char(pattern, '.');

                if (dot != (const char*)NULL)
                {
                    if (pattern[0U] == '*' && pattern[1U] == '.' && x509_find_char(dot + 1, '.') != (const char*)NULL)
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

bool qsc_x509_dns_name_match(const char* pattern, const char* hostname)
{
    QSC_ASSERT(pattern != NULL);
    QSC_ASSERT(hostname != NULL);

    const char* hdot;
    const char* suffix;
    bool res;

    res = false;

    if (pattern != (const char*)NULL && hostname != (const char*)NULL)
    {
        if (x509_dns_pattern_is_valid(pattern) == true)
        {
            if (pattern[0U] != '*')
            {
                res = x509_ascii_case_equal(pattern, hostname);
            }
            else if (hostname[0U] != '.' && hostname[0U] != '\0')
            {
                hdot = x509_find_char(hostname, '.');

                if (hdot != (const char*)NULL && x509_find_char(hdot + 1, '.') != (const char*)NULL)
                {
                    if (x509_dns_first_label_is_idna(hostname) == false && x509_dns_first_label_is_idna(pattern + 2) == false)
                    {
                        suffix = pattern + 1;
                        res = x509_ascii_case_equal(suffix, hdot);
                    }
                }
            }
        }
    }

    return res;
}

bool qsc_x509_certificate_match_dns_name(const qsc_x509_certificate* certificate, const char* hostname)
{
    QSC_ASSERT(certificate != NULL);
    QSC_ASSERT(hostname != NULL);

    size_t i;
    bool res;
    bool sawdns;

    res = false;
    sawdns = false;

    if (certificate != (const qsc_x509_certificate*)NULL && hostname != (const char*)NULL)
    {
        if (certificate->extensions.subjectaltname.present == true)
        {
            for (i = 0U; i < certificate->extensions.subjectaltname.count; ++i)
            {
                const qsc_x509_general_name* name;

                name = &certificate->extensions.subjectaltname.entries[i];

                if (name->type == QSC_X509_GENERAL_NAME_DNS_NAME)
                {
                    sawdns = true;

                    if (qsc_x509_dns_name_match((const char*)name->data, hostname) == true)
                    {
                        res = true;
                        break;
                    }
                }
            }
        }

        if (res == false && sawdns == false)
        {
            for (i = 0U; i < certificate->subject.count; ++i)
            {
                const qsc_x509_name_attribute* attr;

                attr = &certificate->subject.attributes[i];

                if (attr->type == QSC_X509_NAME_ATTRIBUTE_COMMON_NAME)
                {
                    if (qsc_x509_dns_name_match(attr->value, hostname) == true)
                    {
                        res = true;
                        break;
                    }
                }
            }
        }
    }

    return res;
}

bool qsc_x509_certificate_match_ip_address(const qsc_x509_certificate* certificate, const uint8_t* address, size_t addresslen)
{
    QSC_ASSERT(certificate != NULL);
    QSC_ASSERT(address != NULL);

    bool res;
    size_t i;

    res = false;

    if (certificate != (const qsc_x509_certificate*)NULL && address != (const uint8_t*)NULL)
    {
        if ((addresslen == 4U || addresslen == 16U) && certificate->extensions.subjectaltname.present == true)
        {
            for (i = 0U; i < certificate->extensions.subjectaltname.count; ++i)
            {
                const qsc_x509_general_name* name;

                name = &certificate->extensions.subjectaltname.entries[i];

                if (name->type == QSC_X509_GENERAL_NAME_IP_ADDRESS && name->length == addresslen)
                {
                    if (qsc_memutils_are_equal(name->data, address, addresslen) == true)
                    {
                        res = true;
                        break;
                    }
                }
            }
        }
    }

    return res;
}

bool qsc_x509_certificate_match_hostname(const qsc_x509_certificate* certificate, const char* hostname)
{
    QSC_ASSERT(certificate != NULL);
    QSC_ASSERT(hostname != NULL);

    bool res;

    res = false;

    if (certificate != (const qsc_x509_certificate*)NULL && hostname != (const char*)NULL)
    {
        res = qsc_x509_certificate_match_dns_name(certificate, hostname);
    }

    return res;
}

bool qsc_x509_certificate_match_endpoint(const qsc_x509_certificate* certificate, const char* hostname, const uint8_t* address, size_t addresslen)
{
    QSC_ASSERT(certificate != NULL);

    bool res;

    res = false;

    if (certificate != (const qsc_x509_certificate*)NULL)
    {
        if (hostname != (const char*)NULL)
        {
            res = qsc_x509_certificate_match_dns_name(certificate, hostname);
        }

        if (res == false && address != (const uint8_t*)NULL)
        {
            res = qsc_x509_certificate_match_ip_address(certificate, address, addresslen);
        }
    }

    return res;
}
