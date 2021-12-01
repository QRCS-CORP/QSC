#include "ipinfo.h"
#include "memutils.h"
#include "stringutils.h"

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_any()
{
	qsc_ipinfo_ipv4_address res;
	res.ipv4[0] = 0;
    res.ipv4[1] = 0;
    res.ipv4[2] = 0;
    res.ipv4[3] = 0;

	return res;
}

void qsc_ipinfo_ipv4_address_clear(qsc_ipinfo_ipv4_address* address)
{
	assert(address != NULL);

	if (address != NULL)
	{
		qsc_memutils_clear(address->ipv4, QSC_IPINFO_IPV4_BYTELEN);
	}
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_array(const uint8_t* address)
{
	assert(address != NULL);

	qsc_ipinfo_ipv4_address res = { 0 };

	if (address != NULL)
	{
		qsc_memutils_copy(res.ipv4, address, QSC_IPINFO_IPV4_BYTELEN);
	}

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_bytes(uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4)
{
	qsc_ipinfo_ipv4_address res = {
		.ipv4[0] = a1,
		.ipv4[1] = a2,
		.ipv4[2] = a3,
		.ipv4[3] = a4 };

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_from_string(const char input[QSC_IPINFO_IPV4_STRNLEN])
{
	assert(input != NULL);

	qsc_ipinfo_ipv4_address res = { 0 };
	size_t pos;
	int32_t a;
	int32_t cnt;
	int32_t ret;

	ret = 0;

	if (input != NULL && strlen(input) >= 7)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		cnt = sscanf_s(input, "%d %n", &a, &ret);

		if (cnt > 0)
		{
			res.ipv4[0] = (uint8_t)a;
			pos = (size_t)ret + 1;
			cnt = sscanf_s((input + pos), "%d %n", &a, &ret);
		}

		if (cnt > 0)
		{
			res.ipv4[1] = (uint8_t)a;
			pos += (size_t)ret + 1;
			cnt = sscanf_s((input + pos), "%d %n", &a, &ret);
		}

		if (cnt > 0)
		{
			res.ipv4[2] = (uint8_t)a;
			pos += (size_t)ret + 1;
			cnt = sscanf_s((input + pos), "%d", &a);

			if (cnt > 0)
			{
				res.ipv4[3] = (uint8_t)a;
			}
		}
#else
		cnt = sscanf(input, "%d %n", &a, &ret);

		if (cnt > 0)
		{
			res.ipv4[0] = (uint8_t)a;
			pos = ret + 1;
			cnt = sscanf((input + pos), "%d %n", &a, &ret);
		}

		if (cnt > 0)
		{
			res.ipv4[1] = (uint8_t)a;
			pos += ret + 1;
			cnt = sscanf((input + pos), "%d %n", &a, &ret);
		}

		if (cnt > 0)
		{
			res.ipv4[2] = (uint8_t)a;
			pos += ret + 1;
			cnt = sscanf((input + pos), "%d", &a);

			if (cnt > 0)
			{
				res.ipv4[3] = (uint8_t)a;
			}
		}
#endif
	}

	return res;
}

bool qsc_ipinfo_ipv4_address_is_equal(const qsc_ipinfo_ipv4_address* a, const qsc_ipinfo_ipv4_address* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

	res = true;

	if (a != NULL && b != NULL)
	{
		for (size_t i = 0; i < sizeof(a->ipv4); ++i)
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
	assert(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv4[0] == 192 && address->ipv4[1] == 168)
		{
			res = false;
		}
		else if (address->ipv4[0] == 172 && (address->ipv4[1] >= 16 && address->ipv4[1] <= 31))
		{
			res = false;
		}
		else if (address->ipv4[0] == 10)
		{
			res = false;
		}
		else if (address->ipv4[0] == 127)
		{
			res = false;
		}
		else if (address->ipv4[0] > 223)
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
	assert(address != NULL);

	bool res;

	res = (address != NULL && address->ipv4[0] <= 224 && address->ipv4[1] != 255 && address->ipv4[2] != 255 && address->ipv4[3] != 255);

	return res;
}

bool qsc_ipinfo_ipv4_address_is_zeroed(const qsc_ipinfo_ipv4_address* address)
{
	assert(address != NULL);

	bool res;

	res = (address != NULL && address->ipv4[0] == 0 && address->ipv4[1] == 0 && address->ipv4[2] == 0 && address->ipv4[3] == 0);

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_loopback()
{
	qsc_ipinfo_ipv4_address res = {
		.ipv4[0] = 127,
		.ipv4[1] = 0,
		.ipv4[2] = 0,
		.ipv4[3] = 1 };

	return res;
}

void qsc_ipinfo_ipv4_address_get_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], const qsc_ipinfo_ipv4_address* address)
{
	qsc_memutils_clear(mask, QSC_IPINFO_IPV4_MASK_STRNLEN);

	if (address->ipv4[0] > 0 && address->ipv4[0] < 127)
	{
		mask = "255.0.0.0";
	}
	else if (address->ipv4[0] > 127 && address->ipv4[0] < 192)
	{
		mask = "255.255.0.0";
	}
	else if (address->ipv4[0] > 191 && address->ipv4[0] < 224)
	{
		mask = "255.255.255.0";
	}
	else
	{
		mask = "255.255.255.255";
	}
}

uint8_t qsc_ipinfo_ipv4_address_get_cidr_mask(const qsc_ipinfo_ipv4_address* address)
{
	uint8_t nmsk;

	if (address->ipv4[0] > 0 && address->ipv4[0] < 127)
	{
		nmsk = 8;
	}
	else if (address->ipv4[0] > 127 && address->ipv4[0] < 192)
	{
		nmsk = 16;
	}
	else if (address->ipv4[0] > 191 && address->ipv4[0] < 224)
	{
		nmsk = 24;
	}
	else
	{
		nmsk = 32;
	}

	return nmsk;
}

void qsc_ipinfo_ipv4_address_to_array(uint8_t* output, const qsc_ipinfo_ipv4_address* address)
{
	assert(address != NULL);
	assert(output != NULL);

	if (address != NULL && output != NULL)
	{
		qsc_memutils_copy(output, address->ipv4, sizeof(address->ipv4));
	}
}

void qsc_ipinfo_ipv4_address_to_string(char output[QSC_IPINFO_IPV4_STRNLEN], const qsc_ipinfo_ipv4_address* address)
{
	assert(address != NULL);
	assert(output != NULL);

	if (address != NULL && output != NULL)
	{
		const char DELIM = '.';
		size_t pos;

		qsc_memutils_clear(output, QSC_IPINFO_IPV4_STRNLEN);
		output[QSC_IPINFO_IPV4_STRNLEN - 1] = '\0';

#if defined(QSC_SYSTEM_OS_WINDOWS)

		pos = (size_t)sprintf_s(output, QSC_IPINFO_IPV4_STRNLEN, "%d", address->ipv4[0]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf_s((output + pos), QSC_IPINFO_IPV4_STRNLEN - pos, "%d", address->ipv4[1]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf_s((output + pos), QSC_IPINFO_IPV4_STRNLEN - pos, "%d", address->ipv4[2]);
		output[pos] = DELIM;
		++pos;
		sprintf_s((output + pos), QSC_IPINFO_IPV4_STRNLEN - pos, "%d", address->ipv4[3]);

#else

		pos = (size_t)sprintf(output, "%d", address->ipv4[0]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf((output + pos), "%d", address->ipv4[1]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf((output + pos), "%d", address->ipv4[2]);
		output[pos] = DELIM;
		++pos;
		sprintf((output + pos), "%d", address->ipv4[3]);

#endif

	}
}

qsc_ipv6_address_prefix_types qsc_ipinfo_ipv6_address_type(const qsc_ipinfo_ipv6_address* address)
{
	assert(address != NULL);

	qsc_ipv6_address_prefix_types ptype;

	ptype = qsc_ipv6_prefix_none;

	if (address != NULL)
	{
		if (address->ipv6[0] == 0xFF)
		{
			ptype = qsc_ipv6_prefix_multicast;
		}
		else if (address->ipv6[0] == 0xFE)
		{
			ptype = qsc_ipv6_prefix_link_local;
		}
		else if (address->ipv6[0] == 0xFD || address->ipv6[0] == 0xFC)
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

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_any()
{
	qsc_ipinfo_ipv6_address res = { 0 };

	return res;
}

void qsc_ipinfo_ipv6_address_clear(qsc_ipinfo_ipv6_address* address)
{
	assert(address != NULL);

	if (address != NULL)
	{
		qsc_memutils_clear(address->ipv6, QSC_IPINFO_IPV6_BYTELEN);
	}
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_array(const uint8_t* address)
{
	assert(address != NULL);

	qsc_ipinfo_ipv6_address res = { 0 };

	if (address != NULL)
	{
		qsc_memutils_copy(res.ipv6, address, QSC_IPINFO_IPV6_BYTELEN);
	}

	return res;
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_from_string(const char input[QSC_IPINFO_IPV6_STRNLEN])
{
	assert(input != NULL);

	qsc_ipinfo_ipv6_address res = { 0 };

	if (input != NULL)
	{
		if (qsc_stringutils_string_contains(input, "::1") == true)
		{
			res = qsc_ipinfo_ipv6_address_loopback();
		}
		else
		{
			res.ipv6[0] = qsc_arrayutils_hex_to_uint8(input, 2);
			res.ipv6[1] = qsc_arrayutils_hex_to_uint8((input + 2), 2);
			res.ipv6[2] = qsc_arrayutils_hex_to_uint8((input + 5), 2);
			res.ipv6[3] = qsc_arrayutils_hex_to_uint8((input + 7), 2);
			res.ipv6[4] = qsc_arrayutils_hex_to_uint8((input + 10), 2);
			res.ipv6[5] = qsc_arrayutils_hex_to_uint8((input + 12), 2);
			res.ipv6[6] = qsc_arrayutils_hex_to_uint8((input + 15), 2);
			res.ipv6[7] = qsc_arrayutils_hex_to_uint8((input + 17), 2);
			res.ipv6[8] = qsc_arrayutils_hex_to_uint8((input + 20), 2);
			res.ipv6[9] = qsc_arrayutils_hex_to_uint8((input + 22), 2);
			res.ipv6[10] = qsc_arrayutils_hex_to_uint8((input + 25), 2);
			res.ipv6[11] = qsc_arrayutils_hex_to_uint8((input + 27), 2);
			res.ipv6[12] = qsc_arrayutils_hex_to_uint8((input + 30), 2);
			res.ipv6[13] = qsc_arrayutils_hex_to_uint8((input + 32), 2);
			res.ipv6[14] = qsc_arrayutils_hex_to_uint8((input + 35), 2);
			res.ipv6[15] = qsc_arrayutils_hex_to_uint8((input + 37), 2);
		}
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_is_equal(const qsc_ipinfo_ipv6_address* a, const qsc_ipinfo_ipv6_address* b)
{
	assert(a != NULL);
	assert(b != NULL);

	bool res;

	res = true;

	if (a != NULL && b != NULL)
	{
		for (size_t i = 0; i < sizeof(a->ipv6); ++i)
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
	assert(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv6[0] == 0)
		{
			res = false;
		}
		else if (address->ipv6[0] == 1)
		{
			res = false;
		}
		else if (address->ipv6[0] == 255 && address->ipv6[1] == 0)
		{
			res = false;
		}
		else if (address->ipv6[0] == 254 && address->ipv6[1] == 128)
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
	assert(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv6[0] == 0)
		{
			res = false;
		}
		else if (address->ipv6[0] == 1)
		{
			res = false;
		}
		else if (address->ipv6[2] == 219 && address->ipv6[3] == 128)
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

bool qsc_ipinfo_ipv6_address_is_zeroed(const qsc_ipinfo_ipv6_address* address)
{
	assert(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv6[0] == 0 && address->ipv6[1] == 0 && address->ipv6[2] == 0 && address->ipv6[3] == 0 &&
			address->ipv6[4] == 0 && address->ipv6[5] == 0 && address->ipv6[6] == 0 && address->ipv6[7] == 0 &&
			address->ipv6[8] == 0 && address->ipv6[9] == 0 && address->ipv6[10] == 0 && address->ipv6[11] == 0 &&
			address->ipv6[12] == 0 && address->ipv6[13] == 0 && address->ipv6[14] == 0 && address->ipv6[15] == 0)
		{
			res = true;
		}
	}

	return res;
}

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_loopback()
{
	qsc_ipinfo_ipv6_address add;

	add.ipv6[0] = 0;
    add.ipv6[1] = 0;
    add.ipv6[2] = 0;
    add.ipv6[3] = 0;
    add.ipv6[4] = 0;
    add.ipv6[5] = 0;
    add.ipv6[6] = 0;
    add.ipv6[7] = 0;
    add.ipv6[8] = 0;
    add.ipv6[9] = 0;
    add.ipv6[10] = 0;
    add.ipv6[11] = 0;
    add.ipv6[12] = 0;
    add.ipv6[13] = 0;
    add.ipv6[14] = 0;
    add.ipv6[15] = 1;

	return add;
}

void qsc_ipinfo_ipv6_address_get_mask(char mask[QSC_IPINFO_IPV6_MASK_STRNLEN], const qsc_ipinfo_ipv6_address* address)
{
	size_t ctr;

	ctr = QSC_IPINFO_IPV6_BYTELEN;

	do
	{
		--ctr;

		if (address->ipv6[ctr] == 0)
		{
			mask[ctr] = 'f';
		}
		else
		{
			break;
		}
	}
	while (ctr != 0);
}

uint8_t qsc_ipinfo_ipv6_address_get_cidr_mask(const qsc_ipinfo_ipv6_address* address)
{
	size_t ctr;
	uint8_t nmsk;

	nmsk = 0;
	ctr = QSC_IPINFO_IPV6_BYTELEN;

	do
	{
		--ctr;

		if (address->ipv6[ctr] == 0)
		{
			++nmsk;
		}
		else
		{
			break;
		}
	}
	while (ctr != 0);

	return nmsk;
}

void qsc_ipinfo_ipv6_address_to_array(uint8_t* output, const qsc_ipinfo_ipv6_address* address)
{
	assert(address != NULL);
	assert(output != NULL);

	if (address != NULL && output != NULL)
	{
		qsc_memutils_copy(output, address->ipv6, sizeof(address->ipv6));
	}
}

void qsc_ipinfo_ipv6_address_to_string(char output[QSC_IPINFO_IPV6_STRNLEN], const qsc_ipinfo_ipv6_address* address)
{
	assert(address != NULL);
	assert(output != NULL);

	if (address != NULL && output != NULL)
	{
		const char DELIM = ':';
		uint16_t n;

		qsc_memutils_clear(output, QSC_IPINFO_IPV6_STRNLEN);

		n = qsc_intutils_be8to16(&address->ipv6[0]);
		qsc_arrayutils_uint16_to_hex(&output[0], 5, n);
		output[4] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[2]);
		qsc_arrayutils_uint16_to_hex(&output[5], 5, n);
		output[9] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[4]);
		qsc_arrayutils_uint16_to_hex(&output[10], 5, n);
		output[14] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[6]);
		qsc_arrayutils_uint16_to_hex(&output[15], 5, n);
		output[19] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[8]);
		qsc_arrayutils_uint16_to_hex(&output[20], 5, n);
		output[24] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[10]);
		qsc_arrayutils_uint16_to_hex(&output[25], 5, n);
		output[29] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[12]);
		qsc_arrayutils_uint16_to_hex(&output[30], 5, n);
		output[34] = DELIM;
		n = qsc_intutils_be8to16(&address->ipv6[14]);
		qsc_arrayutils_uint16_to_hex(&output[35], 5, n);
	}
}

uint8_t qsc_ipinfo_ipv4_mask_to_cidr(const char mask[QSC_IPINFO_IPV4_MASK_STRNLEN])
{
	uint32_t ta[4] = { 0 };
	const char* tmp = mask;
	uint32_t bmask;
	int32_t pos;
	uint8_t bits;

	for (size_t i = 0; i < 4; ++i)
	{
		pos = qsc_stringutils_find_string(tmp, ".");
		ta[i] += qsc_stringutils_string_to_int(tmp);
		tmp += (size_t)pos + 1;
	}

	bits = 0;
	bmask = ((ta[0] << 24) + (ta[1] << 16) + (ta[2] << 8) + (ta[3]));

	while (bmask != 0)
	{
		bits += bmask & 1;
		bmask >>= 1;
	}

	return bits;
}

void qsc_ipinfo_ipv4_cidr_to_mask(char mask[QSC_IPINFO_IPV4_MASK_STRNLEN], uint8_t cidr)
{
	qsc_stringutils_clear_string(mask);
	uint32_t tmpn;

	tmpn = 0;

	if (cidr <= 8)
	{
		char tail[] = ".0.0.0";

		for (size_t i = 0; i < 8; ++i)
		{
			if (cidr == 0)
			{
				break;
			}

			tmpn |= 1 << (7 - i);
			--cidr;
		}

		qsc_stringutils_int_to_string(tmpn, mask, QSC_IPINFO_IPV4_MASK_STRNLEN);
		qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tail);
	}
	else if (cidr <= 16)
	{
		char head[] = "255.";
		char tail[] = ".0.0";
		char tmask[4] = { 0 };

		cidr -= 8;

		for (size_t i = 0; i < 8; ++i)
		{
			if (cidr == 0)
			{
				break;
			}

			tmpn |= 1 << (7 - i);
			--cidr;
		}

		qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, head);
		qsc_stringutils_int_to_string(tmpn, tmask, sizeof(tmask));
		qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tmask);
		qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tail);
	}
	else if (cidr <= 24)
	{
		char head[] = "255.255.";
		char tail[] = ".0";
		char tmask[4] = { 0 };

		cidr -= 16;

		for (size_t i = 0; i < 8; ++i)
		{
			if (cidr == 0)
			{
				break;
			}

			tmpn |= 1 << (7 - i);
			--cidr;
		}

		qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, head);
		qsc_stringutils_int_to_string(tmpn, tmask, sizeof(tmask));
		qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tmask);
		qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tail);
	}
	else
	{
		char head[] = "255.255.255.";
		char tmask[4] = { 0 };

		cidr -= 24;

		for (size_t i = 0; i < 8; ++i)
		{
			if (cidr == 0)
			{
				break;
			}

			tmpn |= 1 << (7 - i);
			--cidr;
		}

		qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, head);
		qsc_stringutils_int_to_string(tmpn, tmask, sizeof(tmask));
		qsc_stringutils_concat_strings(mask, QSC_IPINFO_IPV4_MASK_STRNLEN, tmask);
	}
}
