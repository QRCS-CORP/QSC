#include "ipinfo.h"
#include "memutils.h"
#include "stringutils.h"
#include <ctype.h>
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
#	define WIN32_LEAN_AND_MEAN
#	define VC_EXTRALEAN
#	include <winsock2.h>
#	include <ws2tcpip.h>
#else
#	include <arpa/inet.h>
#	include <netinet/in.h>
#endif

static bool ipinfo_hexfield_valid(const char** pp)
{
	QSC_ASSERT(pp != NULL);

    uint32_t value;
    uint32_t digits;
    const char* p;
	bool res;

	res = false;

	if (pp != NULL)
	{
		value  = 0U;
		digits = 0U;
		p  = *pp;

		if (*pp != NULL)
		{
			while ((digits < 4U) && (p[0U] != '\0') && (p[0U] != ':'))
			{
				uint32_t nibble;

				if ((p[0U] >= '0') && (p[0U] <= '9'))
				{
					nibble = (uint32_t)(p[0U] - '0');
				}
				else if ((p[0U] >= 'A') && (p[0U] <= 'F'))
				{
					nibble = (uint32_t)(10U + (p[0U] - 'A'));
				}
				else if ((p[0U] >= 'a') && (p[0U] <= 'f'))
				{
					nibble = (uint32_t)(10U + (p[0U] - 'a'));
				}
				else
				{
					break;
				}

				value = (value << 4U) | nibble;
				++digits;
				++p;
			}

			if (digits > 0U)
			{
				*pp = p;
				res = true;
			}
		}
	}

	return res;
}

qsc_ipinfo_address_types qsc_ipinfo_get_address_type(const char* address)
{
	QSC_ASSERT(address != NULL);
	
	qsc_ipinfo_address_types tadd;

	tadd = qsc_ipinfo_address_type_unknown;

	if (address != NULL)
	{
		if (qsc_stringutils_string_size(address) <= QSC_IPINFO_IPV4_STRNLEN)
		{
			qsc_ipinfo_ipv4_address ipv4;

			ipv4 = qsc_ipinfo_ipv4_address_from_string(address);

			if (qsc_ipinfo_ipv4_address_is_valid(&ipv4) == true)
			{
				tadd = qsc_ipinfo_address_type_ipv4;
			}
		}
		else if (qsc_stringutils_string_size(address) <= QSC_IPINFO_IPV6_STRNLEN)
		{
			qsc_ipinfo_ipv6_address ipv6;

			ipv6 = qsc_ipinfo_ipv6_address_from_string(address);

			if (qsc_ipinfo_ipv6_address_is_valid(&ipv6) == true)
			{
				tadd = qsc_ipinfo_address_type_ipv6;
			}
		}
	}

	return tadd;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_any(void)
{
	qsc_ipinfo_ipv4_address res;

	res.ipv4[0U] = 0U;
    res.ipv4[1U] = 0U;
    res.ipv4[2U] = 0U;
    res.ipv4[3U] = 0U;

	return res;
}

void qsc_ipinfo_ipv4_address_clear(qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	if (address != NULL)
	{
		qsc_memutils_clear(address->ipv4, QSC_IPINFO_IPV4_BYTELEN);
	}
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_array(const uint8_t* address)
{
	QSC_ASSERT(address != NULL);

	qsc_ipinfo_ipv4_address res = { 0U };

	if (address != NULL)
	{
		qsc_memutils_copy(res.ipv4, address, QSC_IPINFO_IPV4_BYTELEN);
	}

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_bytes(uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4)
{
	qsc_ipinfo_ipv4_address res = 
	{
		.ipv4[0U] = a1,
		.ipv4[1U] = a2,
		.ipv4[2U] = a3,
		.ipv4[3U] = a4 
	};

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_string(const char input[QSC_IPINFO_IPV4_STRNLEN])
{
    qsc_ipinfo_ipv4_address res = { 0U };
    bool bok;

    QSC_ASSERT(input != NULL);

	bok = false;

    if (input != NULL)
    {
        size_t len = strlen(input);

        /* minimum length: "0.0.0.0" = 7 characters */
        if (len >= 7U)
        {
            const char* p = input;
            size_t idx;
            uint8_t tmp[4U] = { 0U };

            bok = true;
            for (idx = 0U; idx < 4U && bok; ++idx)
            {
                size_t digits = 0U;
                uint32_t val  = 0U;

                /* parse up to three digits */
                while (*p != '\0' && *p != '.' && digits < 3U)
                {
                    char c = *p;

                    if ((c < '0') || (c > '9'))
                    {
                        bok = false;
                        break;
                    }

                    val = val * 10U + (uint32_t)(c - '0');

                    if (val > 255U)
                    {
                        bok = false;
                        break;
                    }

                    ++digits;
                    ++p;
                }

                if (digits == 0U)
                {
                    bok = false;
                }

                if (bok)
                {
                    tmp[idx] = (uint8_t)val;
                    if (idx < 3U)
                    {
                        if (*p != '.')
                        {
                            bok = false;
                        }

                        ++p;
                    }
                }
            }

            if (bok)
            {
                /* commit only on full success */
                for (size_t i = 0U; i < 4U; ++i)
                {
                    res.ipv4[i] = tmp[i];
                }
            }
        }
    }

    return res;
}

bool qsc_ipinfo_ipv4_address_is_equal(const qsc_ipinfo_ipv4_address* a, const qsc_ipinfo_ipv4_address* b)
{
	QSC_ASSERT(a != NULL);
	QSC_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		res = true;

		for (size_t i = 0U; i < sizeof(a->ipv4); ++i)
		{
			if (a->ipv4[i] != b->ipv4[i])
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

bool qsc_ipinfo_ipv4_address_is_routable(const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv4[0U] == 192U && address->ipv4[1U] == 168U)
		{
			res = false;
		}
		else if (address->ipv4[0U] == 172U && (address->ipv4[1U] >= 16U && address->ipv4[1U] <= 31U))
		{
			res = false;
		}
		else if (address->ipv4[0U] == 10U)
		{
			res = false;
		}
		else if (address->ipv4[0U] == 127U)
		{
			res = false;
		}
		else if (address->ipv4[0U] > 223U)
		{
			res = false;
		}
		else
		{
			res = true;
		}
	}

	return res;
}

bool qsc_ipinfo_ipv4_address_is_valid(const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	uint8_t a;
	uint8_t b;
	bool res;

	res = false;

	if (address != NULL)
	{
		a = address->ipv4[0U];
		b = address->ipv4[1U];

		if (a != 0U)
		{
			if (a != 169U || b != 254U)
			{
				if (a < 224U)
				{
					res = true;
				}
			}
		}
	}

	return res;
}

bool qsc_ipinfo_ipv4_address_string_is_valid(const char* address)
{
	QSC_ASSERT(address != NULL);

	bool res;
	qsc_ipinfo_ipv4_address add = { 0 };

	add = qsc_ipinfo_ipv4_address_from_string(address);
	res = (address != NULL && (uint8_t)add.ipv4[0] < 224 && (uint8_t)add.ipv4[1] != 255 && (uint8_t)add.ipv4[2] != 255 && (uint8_t)add.ipv4[3] != 255);

	return res;
}

bool qsc_ipinfo_ipv4_address_is_zeroed(const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		res = (address != NULL && address->ipv4[0U] == 0U && address->ipv4[1U] == 0U && address->ipv4[2U] == 0U && address->ipv4[3U] == 0U);
	}

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_loopback(void)
{
	qsc_ipinfo_ipv4_address res = {
		.ipv4[0U] = 127U,
		.ipv4[1U] = 0U,
		.ipv4[2U] = 0U,
		.ipv4[3U] = 1U };

	return res;
}

void qsc_ipinfo_ipv4_address_get_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);
	QSC_ASSERT(mask != NULL);

	if (address != NULL && mask != NULL)
	{
		qsc_memutils_clear(mask, QSC_IPINFO_IPV4_MASK_STRNLEN);

		if (address->ipv4[0U] > 0U && address->ipv4[0U] < 127U)
		{
			qsc_stringutils_copy_string(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, "255.0.0.0");
		}
		else if (address->ipv4[0U] > 127U && address->ipv4[0U] < 192U)
		{
			qsc_stringutils_copy_string(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, "255.255.0.0");
		}
		else if (address->ipv4[0U] > 191U && address->ipv4[0U] < 224U)
		{
			qsc_stringutils_copy_string(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, "255.255.255.0");
		}
		else
		{
			qsc_stringutils_copy_string(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, "255.255.255.255");
		}
	}
}

uint8_t qsc_ipinfo_ipv4_address_get_cidr_mask(const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(address != NULL);

	uint8_t nmsk;

	nmsk = 0;

	if (address != NULL)
	{
		if (address->ipv4[0U] > 0U && address->ipv4[0U] < 127U)
		{
			nmsk = 8U;
		}
		else if (address->ipv4[0U] > 127U && address->ipv4[0U] < 192U)
		{
			nmsk = 16U;
		}
		else if (address->ipv4[0U] > 191U && address->ipv4[0U] < 224U)
		{
			nmsk = 24U;
		}
		else
		{
			nmsk = 32U;
		}
	}

	return nmsk;
}

void qsc_ipinfo_ipv4_address_to_array(uint8_t* output, const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		qsc_memutils_copy(output, address->ipv4, sizeof(address->ipv4));
	}
}

void qsc_ipinfo_ipv4_address_to_string(char output[QSC_IPINFO_IPV4_STRNLEN], const qsc_ipinfo_ipv4_address* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		const char DELIM = '.';
		size_t pos;

#if defined(QSC_SYSTEM_OS_WINDOWS)
		bool bok;
		int32_t ret;

		bok = false;
		pos = 0U;
		ret = 0;

        /* first octet */
        ret = snprintf(output, QSC_IPINFO_IPV4_STRNLEN, "%u", address->ipv4[0U]);
        if (ret >= 0 && (size_t)ret < QSC_IPINFO_IPV4_STRNLEN)
        {
            pos = (size_t)ret;
            output[pos] = DELIM;
			++pos;

            /* second octet */
            ret = snprintf(output + pos, QSC_IPINFO_IPV4_STRNLEN - pos, "%u", address->ipv4[1U]);

            if (ret >= 0 && (size_t)ret < QSC_IPINFO_IPV4_STRNLEN - pos)
            {
                pos += (size_t)ret;
                output[pos] = DELIM;
				++pos;

                /* third octet */
                ret = snprintf(output + pos, QSC_IPINFO_IPV4_STRNLEN - pos, "%u", address->ipv4[2U]);

                if (ret >= 0 && (size_t)ret < QSC_IPINFO_IPV4_STRNLEN - pos)
                {
                    pos += (size_t)ret;
                    output[pos] = DELIM;
					++pos;

                    /* fourth octet */
                    ret = snprintf(output + pos, QSC_IPINFO_IPV4_STRNLEN - pos, "%u", address->ipv4[3U]);
                    if (ret >= 0 && (size_t)ret < QSC_IPINFO_IPV4_STRNLEN - pos)
                    {
                        pos += (size_t)ret;
                        bok = true;
                    }
                }
            }
        }

        if (bok)
        {
            qsc_memutils_clear(output + pos, QSC_IPINFO_IPV4_STRNLEN - pos);
        }

#else

		pos = (size_t)snprintf(output, QSC_IPINFO_IPV4_STRNLEN, "%u", (unsigned)address->ipv4[0U]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)snprintf(output + pos, QSC_IPINFO_IPV4_STRNLEN, "%u", (unsigned)address->ipv4[1U]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)snprintf(output + pos, QSC_IPINFO_IPV4_STRNLEN, "%u", (unsigned)address->ipv4[2U]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)snprintf(output + pos, QSC_IPINFO_IPV4_STRNLEN, "%u", (unsigned)address->ipv4[3U]);

#endif
		qsc_memutils_clear(output + pos, QSC_IPINFO_IPV4_STRNLEN - pos);
	}
}

void qsc_ipinfo_ipv4_array_to_string(char output[QSC_IPINFO_IPV4_STRNLEN], const uint8_t* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		const char DELIM = '.';
		size_t pos;

#if defined(QSC_SYSTEM_OS_WINDOWS)

		pos = (size_t)sprintf_s(output, QSC_IPINFO_IPV4_STRNLEN, "%d", address[0U]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf_s((output + pos), QSC_IPINFO_IPV4_STRNLEN - pos, "%d", address[1U]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf_s((output + pos), QSC_IPINFO_IPV4_STRNLEN - pos, "%d", address[2U]);
		output[pos] = DELIM;
		++pos;
		pos += sprintf_s((output + pos), QSC_IPINFO_IPV4_STRNLEN - pos, "%d", address[3U]);

#else

		pos = (size_t)sprintf(output, "%d", address[0U]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf((output + pos), "%d", address[1U]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf((output + pos), "%d", address[2U]);
		output[pos] = DELIM;
		++pos;
		pos += sprintf((output + pos), "%d", address[3U]);

#endif
		qsc_memutils_clear(output + pos, QSC_IPINFO_IPV4_STRNLEN - pos);
	}
}

uint8_t qsc_ipinfo_ipv4_mask_to_cidr(const char mask[QSC_IPINFO_IPV4_MASK_STRNLEN])
{
	QSC_ASSERT(mask != NULL);

	uint32_t ta[4U] = { 0U };
	const char* tmp = mask;
	uint32_t bmask;
	uint8_t bits;

	bits = 0U;

	if (mask != NULL)
	{
		for (size_t i = 0U; i < 4U; ++i)
		{
			ta[i] = (uint32_t)qsc_stringutils_string_to_int(tmp);

			if (i < 3U)
			{
				const char* dot = strchr(tmp, '.');

				if (dot != NULL)
				{
					tmp = dot + 1;
				}
			}
		}


		bits = 0U;
		bmask = ((ta[0U] << 24U) + (ta[1U] << 16U) + (ta[2U] << 8U) + (ta[3U]));

		while (bmask != 0)
		{
			bits += bmask & 1U;
			bmask >>= 1;
		}
	}

	return bits;
}

void qsc_ipinfo_ipv4_cidr_to_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], uint8_t cidr)
{
	QSC_ASSERT(mask != NULL);

	qsc_stringutils_clear_string(mask);
	uint32_t tmpn;

	if (mask != NULL)
	{
		tmpn = 0;

		if (cidr <= 8U)
		{
			const char tail[] = ".0.0.0";

			for (size_t i = 0U; i < 8U; ++i)
			{
				if (cidr == 0U)
				{
					break;
				}

				tmpn |= (1U << (7U - i));
				--cidr;
			}

			qsc_stringutils_int_to_string(tmpn, mask, QSC_IPINFO_IPV4_MASK_STRNLEN);
			qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tail);
		}
		else if (cidr <= 16U)
		{
			const char head[] = "255.";
			const char tail[] = ".0.0";
			char tmask[4U] = { 0U };

			cidr -= 8U;

			for (size_t i = 0U; i < 8U; ++i)
			{
				if (cidr == 0U)
				{
					break;
				}

				tmpn |= (1U << (7U - i));
				--cidr;
			}

			qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, head);
			qsc_stringutils_int_to_string(tmpn, tmask, sizeof(tmask));
			qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tmask);
			qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tail);
		}
		else if (cidr <= 24)
		{
			const char head[] = "255.255.";
			const char tail[] = ".0";
			char tmask[4U] = { 0U };

			cidr -= 16U;

			for (size_t i = 0U; i < 8U; ++i)
			{
				if (cidr == 0U)
				{
					break;
				}

				tmpn |= (1U << (7U - i));
				--cidr;
			}

			qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, head);
			qsc_stringutils_int_to_string(tmpn, tmask, sizeof(tmask));
			qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tmask);
			qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tail);
		}
		else
		{
			const char head[] = "255.255.255.";
			char tmask[4U] = { 0U };

			cidr -= 24U;

			for (size_t i = 0U; i < 8U; ++i)
			{
				if (cidr == 0U)
				{
					break;
				}

				tmpn |= (1U << (7 - i));
				--cidr;
			}

			qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, head);
			qsc_stringutils_int_to_string(tmpn, tmask, sizeof(tmask));
			qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tmask);
		}
	}
}

qsc_ipv6_address_prefix_types qsc_ipinfo_ipv6_address_type(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	qsc_ipv6_address_prefix_types ptype;

	ptype = qsc_ipv6_prefix_none;

	if (address != NULL)
	{
		if (address->ipv6[0U] == 0xFFU)
		{
			ptype = qsc_ipv6_prefix_multicast;
		}
		else if (address->ipv6[0U] == 0xFEU)
		{
			ptype = qsc_ipv6_prefix_link_local;
		}
		else if (address->ipv6[0U] == 0xFDU || address->ipv6[0U] == 0xFCU)
		{
			ptype = qsc_ipv6_prefix_unique_local;
		}
		else
		{
			ptype = qsc_ipv6_prefix_global;
		}
	}

	return ptype;
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_any(void)
{
	qsc_ipinfo_ipv6_address res = { 0U };

	return res;
}

void qsc_ipinfo_ipv6_address_clear(qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	if (address != NULL)
	{
		qsc_memutils_clear(address->ipv6, QSC_IPINFO_IPV6_BYTELEN);
	}
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_array(const uint8_t* address)
{
	QSC_ASSERT(address != NULL);

	qsc_ipinfo_ipv6_address res = { 0U };

	if (address != NULL)
	{
		qsc_memutils_copy(res.ipv6, address, QSC_IPINFO_IPV6_BYTELEN);
	}

	return res;
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_string(const char input[QSC_IPINFO_IPV6_STRNLEN])
{
	QSC_ASSERT(input != NULL);

	qsc_ipinfo_ipv6_address res = { 0U };

	if (input != NULL)
	{
#if defined(QSC_SYSTEM_SOCKETS_WINDOWS)
		struct in6_addr tmp6;

		if (InetPton(AF_INET6, input, &tmp6) == 1)
		{
			qsc_memutils_copy(res.ipv6, &tmp6, QSC_IPINFO_IPV6_BYTELEN);
		}
#else
		struct in6_addr tmp6;

		if (inet_pton(AF_INET6, input, &tmp6) == 1)
		{
			qsc_memutils_copy(res.ipv6, &tmp6, QSC_IPINFO_IPV6_BYTELEN);
		}
#endif
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_is_equal(const qsc_ipinfo_ipv6_address* a, const qsc_ipinfo_ipv6_address* b)
{
	QSC_ASSERT(a != NULL);
	QSC_ASSERT(b != NULL);

	bool res;

	res = true;

	if (a != NULL && b != NULL)
	{
		for (size_t i = 0U; i < sizeof(a->ipv6); ++i)
		{
			if (a->ipv6[i] != b->ipv6[i])
			{
				res = false;
				break;
			}
		}
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_is_routable(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv6[0U] == 0U)
		{
			res = false;
		}
		else if (address->ipv6[0U] == 1U)
		{
			res = false;
		}
		else if (address->ipv6[0U] == 255U && address->ipv6[1U] == 0U)
		{
			res = false;
		}
		else if (address->ipv6[0U] == 254U && address->ipv6[1U] == 128U)
		{
			res = false;
		}
		else
		{
			qsc_ipv6_address_prefix_types ptype;

			ptype = qsc_ipinfo_ipv6_address_type(address);
			res = (ptype != qsc_ipv6_prefix_link_local && ptype != qsc_ipv6_prefix_unique_local);
		}
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_is_valid(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv6[0U] == 0U)
		{
			res = false;
		}
		else if (address->ipv6[0U] == 1U)
		{
			res = false;
		}
		else if (address->ipv6[2U] == 219U && address->ipv6[3U] == 128U)
		{
			res = false;
		}
		else
		{
			res = true;
		}
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_string_is_valid(const char* address)
{
    QSC_ASSERT(address != NULL);

    bool res;
    uint32_t fields;
    bool dblcolon;
    bool bok;

	res = false;

    if (address != NULL)
    {
		fields = 0U;
		bok = true;
		dblcolon = false;
        const char * p = address;

        if (p[0U] != '\0')
        {
            while ((bok == true) && (fields < 8U) && (p[0U] != '\0'))
            {
                bok = ipinfo_hexfield_valid(&p);

                if (bok == true)
                {
                    ++fields;

                    if (p[0U] == ':')
                    {
                        if (p[1U] == ':')
                        {
                            if (dblcolon == true)
                            {
                                bok = false;
                            }
                            else
                            {
                                dblcolon = true;
                                p += 2;
                            }
                        }
                        else
                        {
                            ++p;
                        }
                    }
                }
            }

            if (bok == true)
            {
                bool bfcount;

                if (dblcolon == true)
                {
                    bfcount = (fields <= 8U);
                }
                else
                {
                    bfcount = (fields == 8U);
                }

                res = (bfcount == true) && (p[0U] == '\0');
            }
        }
    }

    return res;
}

bool qsc_ipinfo_ipv6_address_is_zeroed(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv6[0U] == 0U && address->ipv6[1U] == 0U && address->ipv6[2U] == 0U && address->ipv6[3U] == 0U &&
			address->ipv6[4U] == 0U && address->ipv6[5U] == 0U && address->ipv6[6U] == 0U && address->ipv6[7U] == 0U &&
			address->ipv6[8U] == 0U && address->ipv6[9U] == 0U && address->ipv6[10U] == 0U && address->ipv6[11U] == 0U &&
			address->ipv6[12U] == 0U && address->ipv6[13U] == 0U && address->ipv6[14U] == 0U && address->ipv6[15U] == 0U)
		{
			res = true;
		}
	}

	return res;
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_loopback(void)
{
	qsc_ipinfo_ipv6_address add;

	add.ipv6[0U] = 0U;
    add.ipv6[1U] = 0U;
    add.ipv6[2U] = 0U;
    add.ipv6[3U] = 0U;
    add.ipv6[4U] = 0U;
    add.ipv6[5U] = 0U;
    add.ipv6[6U] = 0U;
    add.ipv6[7U] = 0U;
    add.ipv6[8U] = 0U;
    add.ipv6[9U] = 0U;
    add.ipv6[10U] = 0U;
    add.ipv6[11U] = 0U;
    add.ipv6[12U] = 0U;
    add.ipv6[13U] = 0U;
    add.ipv6[14U] = 0U;
    add.ipv6[15U] = 1U;

	return add;
}

void qsc_ipinfo_ipv6_address_get_mask(char mask[QSC_IPINFO_IPV6_MASK_STRNLEN], const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(mask != NULL);
	QSC_ASSERT(address != NULL);

	size_t ctr;

	if (mask != NULL && address != NULL)
	{
		ctr = QSC_IPINFO_IPV6_BYTELEN;

		do
		{
			--ctr;

			if (address->ipv6[ctr] == 0U)
			{
				mask[ctr] = 'f';
			}
			else
			{
				break;
			}
		} while (ctr != 0U);
	}
}

uint8_t qsc_ipinfo_ipv6_address_get_cidr_mask(const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(address != NULL);

	size_t ctr;
	uint8_t nmsk;

	nmsk = 0U;

	if (address != NULL)
	{
		ctr = QSC_IPINFO_IPV6_BYTELEN;

		do
		{
			--ctr;

			if (address->ipv6[ctr] == 0U)
			{
				++nmsk;
			}
			else
			{
				break;
			}
		} while (ctr != 0U);
	}

	return nmsk;
}

void qsc_ipinfo_ipv6_address_to_array(uint8_t* output, const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		qsc_memutils_copy(output, address->ipv6, sizeof(address->ipv6));
	}
}

void qsc_ipinfo_ipv6_address_to_string(char output[QSC_IPINFO_IPV6_STRNLEN], const qsc_ipinfo_ipv6_address* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		const char DELIM = ':';
		uint16_t n;

		qsc_memutils_clear(output, QSC_IPINFO_IPV6_STRNLEN);

		n = qsc_intutils_be8to16(&address->ipv6[0U]);
		qsc_arrayutils_uint16_to_hex(&output[0U], 5, n);
		output[4U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[2U]);
		qsc_arrayutils_uint16_to_hex(&output[5U], 5U, n);
		output[9U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[4U]);
		qsc_arrayutils_uint16_to_hex(&output[10U], 5U, n);
		output[14U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[6U]);
		qsc_arrayutils_uint16_to_hex(&output[15U], 5U, n);
		output[19U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[8U]);
		qsc_arrayutils_uint16_to_hex(&output[20U], 5U, n);
		output[24U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[10U]);
		qsc_arrayutils_uint16_to_hex(&output[25U], 5U, n);
		output[29U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[12U]);
		qsc_arrayutils_uint16_to_hex(&output[30U], 5U, n);
		output[34U] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[14U]);
		qsc_arrayutils_uint16_to_hex(&output[35U], 5U, n);
	}
}

void qsc_ipinfo_ipv6_array_to_string(char output[QSC_IPINFO_IPV6_STRNLEN], const uint8_t* address)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(address != NULL);

	if (address != NULL && output != NULL)
	{
		const char DELIM = ':';
		uint16_t n;

		qsc_memutils_clear(output, QSC_IPINFO_IPV6_STRNLEN);

		n = qsc_intutils_be8to16(&address[0U]);
		qsc_arrayutils_uint16_to_hex(&output[0U], 5, n);
		output[4U] = DELIM;
		n = qsc_intutils_be8to16(&address[2U]);
		qsc_arrayutils_uint16_to_hex(&output[5U], 5U, n);
		output[9U] = DELIM;
		n = qsc_intutils_be8to16(&address[4U]);
		qsc_arrayutils_uint16_to_hex(&output[10U], 5U, n);
		output[14U] = DELIM;
		n = qsc_intutils_be8to16(&address[6U]);
		qsc_arrayutils_uint16_to_hex(&output[15U], 5U, n);
		output[19U] = DELIM;
		n = qsc_intutils_be8to16(&address[8U]);
		qsc_arrayutils_uint16_to_hex(&output[20U], 5U, n);
		output[24U] = DELIM;
		n = qsc_intutils_be8to16(&address[10U]);
		qsc_arrayutils_uint16_to_hex(&output[25U], 5U, n);
		output[29U] = DELIM;
		n = qsc_intutils_be8to16(&address[12U]);
		qsc_arrayutils_uint16_to_hex(&output[30U], 5U, n);
		output[34U] = DELIM;
		n = qsc_intutils_be8to16(&address[14U]);
		qsc_arrayutils_uint16_to_hex(&output[35U], 5U, n);
	}
}
