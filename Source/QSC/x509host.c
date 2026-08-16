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

static bool x509_ascii_case_equal_ex(const uint8_t* left, size_t leftlen, const char* right, size_t rightlen)
{
    size_t i;
    bool res;

    res = false;

    if (left != (const uint8_t*)NULL && right != (const char*)NULL && leftlen == rightlen && leftlen != 0U)
    {
        res = true;

        for (i = 0U; i < leftlen; ++i)
        {
            if (left[i] == 0U || left[i] > 0x7FU || right[i] == '\0' || (uint8_t)right[i] > 0x7FU ||
                x509_ascii_tolower(left[i]) != x509_ascii_tolower((uint8_t)right[i]))
            {
                res = false;
                break;
            }
        }
    }

    return res;
}

static bool x509_dns_name_is_valid(const uint8_t* name, size_t namelen, bool allowwildcard)
{
    size_t wildcards;
    size_t i;
    bool res;

    wildcards = 0U;
    res = false;

    if (name != (const uint8_t*)NULL && namelen != 0U && name[0U] != '.' && name[namelen - 1U] != '.')
    {
        res = true;

        for (i = 0U; i < namelen; ++i)
        {
            if (name[i] == 0U || name[i] > 0x7FU || (name[i] == '.' && i != 0U && name[i - 1U] == '.'))
            {
                res = false;
                break;
            }

            if (name[i] == '*')
            {
                ++wildcards;
            }
        }

        if (res == true && wildcards != 0U)
        {
            if (allowwildcard == false || wildcards != 1U || namelen < 3U || name[0U] != '*' || name[1U] != '.')
            {
                res = false;
            }
        }
    }

    return res;
}

static bool x509_dns_name_match_ex(const uint8_t* pattern, size_t patternlen, const char* hostname, size_t hostnamelen)
{
    size_t hostdot;
    size_t i;
    bool founddot;
    bool res;

    hostdot = 0U;
    founddot = false;
    res = false;

    if (pattern != (const uint8_t*)NULL && hostname != (const char*)NULL &&
        x509_dns_name_is_valid(pattern, patternlen, true) == true &&
        x509_dns_name_is_valid((const uint8_t*)hostname, hostnamelen, false) == true)
    {
        if (pattern[0U] != '*')
        {
            res = x509_ascii_case_equal_ex(pattern, patternlen, hostname, hostnamelen);
        }
        else
        {
            for (i = 0U; i < hostnamelen; ++i)
            {
                if (hostname[i] == '.')
                {
                    hostdot = i;
                    founddot = true;
                    break;
                }
            }

            if (founddot == true && hostdot != 0U && (hostnamelen - hostdot) == (patternlen - 1U))
            {
                res = x509_ascii_case_equal_ex(pattern + 1U, patternlen - 1U, hostname + hostdot, hostnamelen - hostdot);
            }
        }
    }

    return res;
}

bool qsc_x509_dns_name_match(const char* pattern, const char* hostname)
{
    QSC_ASSERT(pattern != NULL);
    QSC_ASSERT(hostname != NULL);

    size_t hostnamelen;
    size_t patternlen;
    bool res;

    res = false;

    if (pattern != (const char*)NULL && hostname != (const char*)NULL)
    {
        patternlen = qsc_stringutils_string_size(pattern);
        hostnamelen = qsc_stringutils_string_size(hostname);
        res = x509_dns_name_match_ex((const uint8_t*)pattern, patternlen, hostname, hostnamelen);
    }

    return res;
}

bool qsc_x509_certificate_match_dns_name(const qsc_x509_certificate* certificate, const char* hostname)
{
    QSC_ASSERT(certificate != NULL);
    QSC_ASSERT(hostname != NULL);

    const qsc_x509_general_name* name;
    size_t hostnamelen;
    size_t i;
    bool res;

    res = false;

    if (certificate != (const qsc_x509_certificate*)NULL && hostname != (const char*)NULL &&
        certificate->extensions.subjectaltname.present == true)
    {
        hostnamelen = qsc_stringutils_string_size(hostname);

        if (hostnamelen != 0U)
        {
            for (i = 0U; i < certificate->extensions.subjectaltname.count; ++i)
            {
                name = &certificate->extensions.subjectaltname.entries[i];

                if (name->type == QSC_X509_GENERAL_NAME_DNS_NAME && name->length != 0U &&
                    name->length <= QSC_X509_NAME_ATTRIBUTE_STRING_MAX &&
                    x509_dns_name_match_ex(name->data, name->length, hostname, hostnamelen) == true)
                {
                    res = true;
                    break;
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
