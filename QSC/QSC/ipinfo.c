#include "ipinfo.h"

qsc_ipv4_address qsc_ipv4_address_any()
{
	qsc_ipv4_address res = { 0, 0, 0, 0 };

	return res;
}

void qsc_ipv4_address_destroy(qsc_ipv4_address* ctx)
{
	qsc_memutils_clear(ctx->ipv4, QSC_IPV4_BYTELEN);
}

qsc_ipv4_address qsc_ipv4_address_from_array(uint8_t badd[QSC_IPV4_BYTELEN])
{
	qsc_ipv4_address res = { 0 };

	qsc_memutils_copy(res.ipv4, badd, QSC_IPV4_BYTELEN);

	return res;
}

qsc_ipv4_address qsc_ipv4_address_from_bytes(uint8_t a1, uint8_t a2, uint8_t a3, uint8_t a4)
{
	qsc_ipv4_address res = {
		.ipv4[0] = a1,
		.ipv4[1] = a2,
		.ipv4[2] = a3,
		.ipv4[3] = a4 };

	return res;
}

qsc_ipv4_address qsc_ipv4_address_from_string(const char sadd[QSC_IPV4_STRNLEN])
{
	qsc_ipv4_address res = { 0 };
	size_t pos;
	int32_t a;
	int32_t ret;

	ret = 0;

#if defined(QSC_SYSTEM_OS_WINDOWS)
	sscanf_s(sadd, "%d %n", &a, &ret);
	res.ipv4[0] = a;
	pos = ret + 1;
	sscanf_s(((char*)sadd + pos), "%d %n", &a, &ret);
	res.ipv4[1] = a;
	pos += ret + 1;
	sscanf_s(((char*)sadd + pos), "%d %n", &a, &ret);
	res.ipv4[2] = a;
	pos += ret + 1;
	sscanf_s(((char*)sadd + pos), "%d", &a);
	res.ipv4[3] = a;
#else
	sscanf(sadd, "%d %n", &a, &ret);
	res.ipv4[0] = a;
	pos = ret + 1;
	sscanf(((char*)sadd + pos), "%d %n", &a, &ret);
	res.ipv4[1] = a;
	pos += ret + 1;
	sscanf(((char*)sadd + pos), "%d %n", &a, &ret);
	res.ipv4[2] = a;
	pos += ret + 1;
	sscanf(((char*)sadd + pos), "%d", &a);
	res.ipv4[3] = a;
#endif

	return res;
}

bool qsc_ipv4_is_equal(qsc_ipv4_address* a, qsc_ipv4_address* b)
{
	assert(a != NULL);
	assert(b != NULL);

	size_t i;
	bool res;

	res = (a != NULL && b != NULL);

	if (res)
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

qsc_ipv4_address qsc_ipv4_address_loop_back()
{
	qsc_ipv4_address res = {
		.ipv4[0] = 127,
		.ipv4[0] = 0,
		.ipv4[0] = 0,
		.ipv4[0] = 1 };

	return res;
}

void qsc_ipv4_address_to_string(char output[QSC_IPV4_STRNLEN], const qsc_ipv4_address* ctx)
{
	const char DELIM = ':';
	size_t pos;

	memset(output, 0x00, sizeof(output));
	output[QSC_IPV4_STRNLEN - 1] = '\0';

#if defined(QSC_SYSTEM_OS_WINDOWS)
	pos = (size_t)sprintf_s(output, sizeof(output), "%d", ctx->ipv4[0]);
	output[pos] = DELIM;
	++pos;
	pos += (size_t)sprintf_s(((uint8_t*)output + pos), sizeof(output), "%d", ctx->ipv4[1]);
	output[pos] = DELIM;
	++pos;
	pos += (size_t)sprintf_s(((uint8_t*)output + pos), sizeof(output), "%d", ctx->ipv4[2]);
	output[pos] = DELIM;
	++pos;
	sprintf_s(((uint8_t*)output + pos), sizeof(output), "%d", ctx->ipv4[3]);
#else
	pos = (size_t)sprintf(output, sizeof(output), "%d", ctx->ipv4[0]);
	output[pos] = DELIM;
	++pos;
	pos += (size_t)sprintf(((uint8_t*)output + pos), sizeof(output), "%d", ctx->ipv4[1]);
	output[pos] = DELIM;
	++pos;
	pos += (size_t)sprintf(((uint8_t*)output + pos), sizeof(output), "%d", ctx->ipv4[2]);
	output[pos] = DELIM;
	++pos;
	sprintf_s(((uint8_t*)output + pos), sizeof(output), "%d", ctx->ipv4[3]);
#endif
}

qsc_ipv6_address_prefix_types qsc_ipv6_address_address_type(qsc_ipv6_address* ctx)
{
	qsc_ipv6_address_prefix_types ptype;

	if (ctx->ipv6[0] == 0xFF)
	{
		ptype = ipv6_prefix_multicast;
	}
	else if (ctx->ipv6[0] == 0xFE)
	{
		ptype = ipv6_prefix_link_local;
	}
	else if (ctx->ipv6[0] == 0xFD || ctx->ipv6[0] == 0xFC)
	{
		ptype = ipv6_prefix_unique_local;
	}
	else
	{
		ptype = ipv6_prefix_global;
	}

	return ptype;
}

qsc_ipv6_address qsc_ipv6_address_any()
{
	qsc_ipv6_address res = { 0 };

	return res;
}

void qsc_ipv6_address_destroy(qsc_ipv6_address* ctx)
{
	qsc_memutils_clear(ctx->ipv6, QSC_IPV6_BYTELEN);
}

qsc_ipv6_address qsc_ipv6_address_from_array(uint8_t badd[QSC_IPV6_BYTELEN])
{
	qsc_ipv6_address res = { 0 };

	qsc_memutils_copy(res.ipv6, badd, QSC_IPV6_BYTELEN);

	return res;
}

qsc_ipv6_address qsc_ipv6_address_from_string(const char sadd[QSC_IPV6_STRNLEN])
{
	qsc_ipv6_address res = { 0 };
	int32_t ret;

	ret = 0;
	res.ipv6[0] = qsc_arrayutils_hex_to_uint8(sadd, QSC_IPV6_STRNLEN);
	res.ipv6[1] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 2), QSC_IPV6_STRNLEN);
	res.ipv6[2] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 5), QSC_IPV6_STRNLEN);
	res.ipv6[3] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 7), QSC_IPV6_STRNLEN);
	res.ipv6[4] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 10), QSC_IPV6_STRNLEN);
	res.ipv6[5] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 12), QSC_IPV6_STRNLEN);
	res.ipv6[6] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 15), QSC_IPV6_STRNLEN);
	res.ipv6[7] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 17), QSC_IPV6_STRNLEN);
	res.ipv6[8] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 20), QSC_IPV6_STRNLEN);
	res.ipv6[9] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 22), QSC_IPV6_STRNLEN);
	res.ipv6[10] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 25), QSC_IPV6_STRNLEN);
	res.ipv6[11] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 27), QSC_IPV6_STRNLEN);
	res.ipv6[12] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 30), QSC_IPV6_STRNLEN);
	res.ipv6[13] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 32), QSC_IPV6_STRNLEN);
	res.ipv6[14] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 35), QSC_IPV6_STRNLEN);
	res.ipv6[15] = qsc_arrayutils_hex_to_uint8(((char*)sadd + 37), QSC_IPV6_STRNLEN);

	return res;
}

bool qsc_ipv6_is_equal(qsc_ipv6_address* a, qsc_ipv6_address* b)
{
	assert(a != NULL);
	assert(b != NULL);

	size_t i;
	bool res;

	res = (a != NULL && b != NULL);

	if (res)
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

bool qsc_ipv6_address_is_routable(qsc_ipv6_address* address)
{
	qsc_ipv6_address_prefix_types ptype;
	bool ret;

	ptype = qsc_ipv6_address_address_type(address);
	ret = (ptype != ipv6_prefix_link_local && ptype != ipv6_prefix_unique_local);

	return ret;
}

qsc_ipv6_address qsc_ipv6_address_loop_back()
{
	qsc_ipv6_address add = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

	return add;
}

char* qsc_ipv6_address_to_string(char output[QSC_IPV6_STRNLEN], const qsc_ipv6_address* ctx)
{
	const char DELIM = ':';

	output[QSC_IPV6_STRNLEN - 1] = '\0';
	qsc_arrayutils_uint8_to_hex(output, QSC_IPV6_STRNLEN, ctx->ipv6[0]);
	qsc_arrayutils_uint8_to_hex(((char*)output + 2), QSC_IPV6_STRNLEN, ctx->ipv6[1]);
	output[4] = DELIM;
	qsc_arrayutils_uint8_to_hex(((char*)output + 5), QSC_IPV6_STRNLEN, ctx->ipv6[2]);
	qsc_arrayutils_uint8_to_hex(((char*)output + 7), QSC_IPV6_STRNLEN, ctx->ipv6[3]);
	output[9] = DELIM;
	qsc_arrayutils_uint8_to_hex(((char*)output + 10), QSC_IPV6_STRNLEN, ctx->ipv6[4]);
	qsc_arrayutils_uint8_to_hex(((char*)output + 12), QSC_IPV6_STRNLEN, ctx->ipv6[5]);
	output[14] = DELIM;
	qsc_arrayutils_uint8_to_hex(((char*)output + 15), QSC_IPV6_STRNLEN, ctx->ipv6[6]);
	qsc_arrayutils_uint8_to_hex(((char*)output + 17), QSC_IPV6_STRNLEN, ctx->ipv6[7]);
	output[19] = DELIM;
	qsc_arrayutils_uint8_to_hex(((char*)output + 20), QSC_IPV6_STRNLEN, ctx->ipv6[8]);
	qsc_arrayutils_uint8_to_hex(((char*)output + 22), QSC_IPV6_STRNLEN, ctx->ipv6[9]);
	output[24] = DELIM;
	qsc_arrayutils_uint8_to_hex(((char*)output + 25), QSC_IPV6_STRNLEN, ctx->ipv6[10]);
	qsc_arrayutils_uint8_to_hex(((char*)output + 27), QSC_IPV6_STRNLEN, ctx->ipv6[11]);
	output[29] = DELIM;
	qsc_arrayutils_uint8_to_hex(((char*)output + 30), QSC_IPV6_STRNLEN, ctx->ipv6[12]);
	qsc_arrayutils_uint8_to_hex(((char*)output + 32), QSC_IPV6_STRNLEN, ctx->ipv6[13]);
	output[34] = DELIM;
	qsc_arrayutils_uint8_to_hex(((char*)output + 35), QSC_IPV6_STRNLEN, ctx->ipv6[14]);
	qsc_arrayutils_uint8_to_hex(((char*)output + 37), QSC_IPV6_STRNLEN, ctx->ipv6[15]);
	output[38] = DELIM;

	return output;
}

bool qsc_ip_address_self_test()
{
	char ipv4s[QSC_IPV4_STRNLEN] = { 0 };
	char ipv6s[QSC_IPV6_STRNLEN] = { 0 };
	qsc_ipv4_address ipv4a = { 192, 168, 1, 1 };
	qsc_ipv6_address ipv6a = { 20, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
	size_t i;
	bool res;

	res = true;

	qsc_ipv4_address_to_string(ipv4s, &ipv4a);
	qsc_ipv4_address ipv4b = qsc_ipv4_address_from_string(ipv4s);

	for (i = 0; i < 4; ++i)
	{
		if (ipv4a.ipv4[i] != ipv4b.ipv4[i])
		{
			res = false;
			break;
		}
	}

	qsc_ipv6_address_to_string(ipv6s, &ipv6a);
	qsc_ipv6_address ipv6b = qsc_ipv6_address_from_string(ipv6s);

	for (i = 0; i < 16; ++i)
	{
		if (ipv6a.ipv6[i] != ipv6b.ipv6[i])
		{
			res = false;
			break;
		}
	}

	return res;
}
