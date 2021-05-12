#include "ipinfo.h"
#include "stringutils.h"

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_any()
{
	qsc_ipinfo_ipv4_address res = { 0, 0, 0, 0 };

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
	int32_t ret;

	ret = 0;

	if (input != NULL)
	{
		if (strlen(input) >= 7)
		{
#if defined(QSC_SYSTEM_OS_WINDOWS)
			sscanf_s(input, "%d %n", &a, &ret);
			res.ipv4[0] = a;
			pos = ret + 1;
			sscanf_s(((char*)input + pos), "%d %n", &a, &ret);
			res.ipv4[1] = a;
			pos += ret + 1;
			sscanf_s(((char*)input + pos), "%d %n", &a, &ret);
			res.ipv4[2] = a;
			pos += ret + 1;
			sscanf_s(((char*)input + pos), "%d", &a);
			res.ipv4[3] = a;
#else
			sscanf(input, "%d %n", &a, &ret);
			res.ipv4[0] = a;
			pos = ret + 1;
			sscanf(((char*)input + pos), "%d %n", &a, &ret);
			res.ipv4[1] = a;
			pos += ret + 1;
			sscanf(((char*)input + pos), "%d %n", &a, &ret);
			res.ipv4[2] = a;
			pos += ret + 1;
			sscanf(((char*)input + pos), "%d", &a);
			res.ipv4[3] = a;
#endif
		}
	}

	return res;
}

bool qsc_ipinfo_ipv4_address_is_equal(qsc_ipinfo_ipv4_address* a, qsc_ipinfo_ipv4_address* b)
{
	assert(a != NULL);
	assert(b != NULL);

	size_t i;
	bool res;

	res = true;

	if (a != NULL && b != NULL)
	{
		for (i = 0; i < sizeof(a->ipv4); ++i)
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

bool qsc_ipinfo_ipv4_address_is_routable(qsc_ipinfo_ipv4_address* address)
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
		else if (address->ipv4[0] <= 10 || address->ipv4[0] > 223)
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

bool qsc_ipinfo_ipv4_address_is_valid(qsc_ipinfo_ipv4_address* address)
{
	assert(address != NULL);

	bool res;

	res = false;

	if (address != NULL)
	{
		if (address->ipv4[0] >= 1 && address->ipv4[1] <= 224)
		{
			res = true;
		}
	}

	return res;
}

qsc_ipinfo_ipv4_address qsc_ipinfo_ipv4_address_loop_back()
{
	qsc_ipinfo_ipv4_address res = {
		.ipv4[0] = 127,
		.ipv4[1] = 0,
		.ipv4[2] = 0,
		.ipv4[3] = 1 };

	return res;
}

void qsc_ipinfo_ipv4_address_to_array(uint8_t* output, qsc_ipinfo_ipv4_address* address)
{
	assert(address != NULL);
	assert(output != NULL);

	if (address != NULL && output != NULL)
	{
		qsc_memutils_copy(output, address->ipv4, sizeof(address->ipv4));
	}
}

void qsc_ipinfo_ipv4_address_to_string(char output[QSC_IPINFO_IPV4_STRNLEN], qsc_ipinfo_ipv4_address* address)
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

		pos = (size_t)sprintf_s(output, sizeof(output), "%d", address->ipv4[0]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf_s(((uint8_t*)output + pos), sizeof(output), "%d", address->ipv4[1]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf_s(((uint8_t*)output + pos), sizeof(output), "%d", address->ipv4[2]);
		output[pos] = DELIM;
		++pos;
		sprintf_s(((uint8_t*)output + pos), sizeof(output), "%d", address->ipv4[3]);

#else

		pos = (size_t)sprintf(output, sizeof(output), "%d", address->ipv4[0]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf(((uint8_t*)output + pos), sizeof(output), "%d", address->ipv4[1]);
		output[pos] = DELIM;
		++pos;
		pos += (size_t)sprintf(((uint8_t*)output + pos), sizeof(output), "%d", address->ipv4[2]);
		output[pos] = DELIM;
		++pos;
		sprintf_s(((uint8_t*)output + pos), sizeof(output), "%d", address->ipv4[3]);

#endif

	}
}

qsc_ipv6_address_prefix_types qsc_ipinfo_ipv6_address_type(qsc_ipinfo_ipv6_address* address)
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

void qsc_ipinfo_ipv6_address_destroy(qsc_ipinfo_ipv6_address* address)
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
			res = qsc_ipinfo_ipv6_address_loop_back();
		}
		else
		{
			res.ipv6[0] = qsc_arrayutils_hex_to_uint8(input, 2);
			res.ipv6[1] = qsc_arrayutils_hex_to_uint8(((char*)input + 2), 2);
			res.ipv6[2] = qsc_arrayutils_hex_to_uint8(((char*)input + 5), 2);
			res.ipv6[3] = qsc_arrayutils_hex_to_uint8(((char*)input + 7), 2);
			res.ipv6[4] = qsc_arrayutils_hex_to_uint8(((char*)input + 10), 2);
			res.ipv6[5] = qsc_arrayutils_hex_to_uint8(((char*)input + 12), 2);
			res.ipv6[6] = qsc_arrayutils_hex_to_uint8(((char*)input + 15), 2);
			res.ipv6[7] = qsc_arrayutils_hex_to_uint8(((char*)input + 17), 2);
			res.ipv6[8] = qsc_arrayutils_hex_to_uint8(((char*)input + 20), 2);
			res.ipv6[9] = qsc_arrayutils_hex_to_uint8(((char*)input + 22), 2);
			res.ipv6[10] = qsc_arrayutils_hex_to_uint8(((char*)input + 25), 2);
			res.ipv6[11] = qsc_arrayutils_hex_to_uint8(((char*)input + 27), 2);
			res.ipv6[12] = qsc_arrayutils_hex_to_uint8(((char*)input + 30), 2);
			res.ipv6[13] = qsc_arrayutils_hex_to_uint8(((char*)input + 32), 2);
			res.ipv6[14] = qsc_arrayutils_hex_to_uint8(((char*)input + 35), 2);
			res.ipv6[15] = qsc_arrayutils_hex_to_uint8(((char*)input + 37), 2);
		}
	}

	return res;
}

bool qsc_ipinfo_ipv6_address_is_equal(qsc_ipinfo_ipv6_address* a, qsc_ipinfo_ipv6_address* b)
{
	assert(a != NULL);
	assert(b != NULL);

	size_t i;
	bool res;

	res = true;

	if (a != NULL && b != NULL)
	{
		for (i = 0; i < sizeof(a->ipv6); ++i)
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

bool qsc_ipinfo_ipv6_address_is_routable(qsc_ipinfo_ipv6_address* address)
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

bool qsc_ipinfo_ipv6_address_is_valid(qsc_ipinfo_ipv6_address* address)
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

qsc_ipinfo_ipv6_address qsc_ipinfo_ipv6_address_loop_back()
{
	qsc_ipinfo_ipv6_address add = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

	return add;
}

void qsc_ipinfo_ipv6_address_to_array(uint8_t* output, qsc_ipinfo_ipv6_address* address)
{
	assert(address != NULL);
	assert(output != NULL);

	if (address != NULL && output != NULL)
	{
		qsc_memutils_copy(output, address->ipv6, sizeof(address->ipv6));
	}
}

char* qsc_ipinfo_ipv6_address_to_string(char output[QSC_IPINFO_IPV6_STRNLEN], qsc_ipinfo_ipv6_address* address)
{
	assert(address != NULL);
	assert(output != NULL);

	if (address != NULL && output != NULL)
	{
		const char DELIM = ':';

		memset(output, 0x00, QSC_IPINFO_IPV6_STRNLEN);
		qsc_arrayutils_uint8_to_hex(output, 2, address->ipv6[0]);
		qsc_arrayutils_uint8_to_hex(((char*)output + 2), 2, address->ipv6[1]);
		output[4] = DELIM;
		qsc_arrayutils_uint8_to_hex(((char*)output + 5), 2, address->ipv6[2]);
		qsc_arrayutils_uint8_to_hex(((char*)output + 7), 2, address->ipv6[3]);
		output[9] = DELIM;
		qsc_arrayutils_uint8_to_hex(((char*)output + 10), 2, address->ipv6[4]);
		qsc_arrayutils_uint8_to_hex(((char*)output + 12), 2, address->ipv6[5]);
		output[14] = DELIM;
		qsc_arrayutils_uint8_to_hex(((char*)output + 15), 2, address->ipv6[6]);
		qsc_arrayutils_uint8_to_hex(((char*)output + 17), 2, address->ipv6[7]);
		output[19] = DELIM;
		qsc_arrayutils_uint8_to_hex(((char*)output + 20), 2, address->ipv6[8]);
		qsc_arrayutils_uint8_to_hex(((char*)output + 22), 2, address->ipv6[9]);
		output[24] = DELIM;
		qsc_arrayutils_uint8_to_hex(((char*)output + 25), 2, address->ipv6[10]);
		qsc_arrayutils_uint8_to_hex(((char*)output + 27), 2, address->ipv6[11]);
		output[29] = DELIM;
		qsc_arrayutils_uint8_to_hex(((char*)output + 30), 2, address->ipv6[12]);
		qsc_arrayutils_uint8_to_hex(((char*)output + 32), 2, address->ipv6[13]);
		output[34] = DELIM;
		qsc_arrayutils_uint8_to_hex(((char*)output + 35), 2, address->ipv6[14]);
		qsc_arrayutils_uint8_to_hex(((char*)output + 37), 2, address->ipv6[15]);
	}

	return output;
}