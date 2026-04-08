#include "tlsextensions.h"
#include "tlscodec.h"
#include "tlslimits.h"
#include "tlsgroups.h"
#include "tlssigalgs.h"

static qsc_tls_status tls_extensions_write_header(uint8_t* output, size_t outlen, size_t* offset, qsc_tls_extension_type type, uint16_t bodylen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)type);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, offset, bodylen);
		}
	}

	return status;
}

static bool tls_extensions_has_duplicate_group(const qsc_tls_named_group* groups, size_t count, qsc_tls_named_group value)
{
	bool res;

	res = false;

	for (size_t i = 0U; i < count; ++i)
	{
		if (groups[i] == value)
		{
			res = true;
			break;
		}
	}

	return res;
}

static bool tls_extensions_has_duplicate_signature(const qsc_tls_signature_scheme* sigschemes, size_t count, qsc_tls_signature_scheme value)
{
	bool res;

	res = false;

	for (size_t i = 0U; i < count; ++i)
	{
		if (sigschemes[i] == value)
		{
			res = true;
			break;
		}
	}

	return res;
}

static bool tls_extensions_group_list_is_valid(const qsc_tls_named_group* groups, size_t groupcount)
{
	bool res;
	size_t i;

	res = true;
	i = 0U;

	while (i < groupcount)
	{
		if (qsc_tls_group_descriptor_get(groups[i]) == NULL || tls_extensions_has_duplicate_group(groups, i, groups[i]) == true)
		{
			res = false;
			break;
		}

		++i;
	}

	return res;
}

static bool tls_extensions_signature_list_is_valid(const qsc_tls_signature_scheme* sigschemes, size_t sigcount)
{
	bool res;
	size_t i;

	res = true;
	i = 0U;

	while (i < sigcount)
	{
		if (qsc_tls_signature_scheme_descriptor_get(sigschemes[i]) == NULL || tls_extensions_has_duplicate_signature(sigschemes, i, sigschemes[i]) == true)
		{
			res = false;
			break;
		}

		++i;
	}

	return res;
}

static qsc_tls_status tls_extensions_read_header(const uint8_t* input, size_t inlen, size_t* offset, uint16_t* type, uint16_t* bodylen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || type == NULL || bodylen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_codec_read_u16(input, inlen, offset, type);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, offset, bodylen);
		}
	}

	return status;
}

static qsc_tls_status tls_extensions_encode_signature_scheme_list(uint8_t* output, size_t outlen, size_t* extlen, qsc_tls_extension_type type, const qsc_tls_signature_scheme* sigschemes, size_t sigcount)
{
	size_t i;
	size_t offset;
	uint16_t listlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	i = 0U;
	offset = 0U;
	listlen = 0U;

	if (output == NULL || extlen == NULL || sigschemes == NULL || sigcount == 0U || sigcount > QSC_TLS_MAX_SIGNATURE_SCHEMES)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*extlen = 0U;

		if (tls_extensions_signature_list_is_valid(sigschemes, sigcount) == false)
		{
			status = qsc_tls_status_not_supported;
		}

		if (status == qsc_tls_status_success)
		{
			listlen = (uint16_t)(sigcount * sizeof(uint16_t));
			status = tls_extensions_write_header(output, outlen, &offset, type, (uint16_t)(QSC_TLS_VECTOR16_HEADER_SIZE + listlen));
	
			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u16(output, outlen, &offset, listlen);
			}
	
			for (i = 0U; i < sigcount && status == qsc_tls_status_success; ++i)
			{
				status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)sigschemes[i]);
			}
		}
	}

	if (status == qsc_tls_status_success)
	{
		*extlen = offset;
	}

	return status;
}

static qsc_tls_status tls_extensions_decode_signature_scheme_list(const uint8_t* input, size_t inlen, qsc_tls_extension_type typeid, qsc_tls_signature_scheme* sigschemes, size_t maxschemes, size_t* sigcount)
{
	size_t count;
	size_t i;
	size_t offset;
	uint16_t type;
	uint16_t bodylen;
	uint16_t listlen;
	uint16_t value;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	i = 0U;
	offset = 0U;
	count = 0U;
	type = 0U;
	bodylen = 0U;
	listlen = 0U;
	value = 0U;

	if (input == NULL || sigschemes == NULL || sigcount == NULL || maxschemes == 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*sigcount = 0U;
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)typeid)
		{
			status = qsc_tls_status_invalid_state;
		}

		if (status == qsc_tls_status_success && (size_t)bodylen != (inlen - offset))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &listlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (((size_t)listlen != (inlen - offset)) || ((listlen & 1U) != 0U))
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				count = (size_t)listlen / sizeof(uint16_t);

				if (count > maxschemes)
				{
					status = qsc_tls_status_buffer_too_small;
				}
			}
		}

		for (i = 0U; i < count && status == qsc_tls_status_success; ++i)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &value);

			if (status == qsc_tls_status_success)
			{
				sigschemes[i] = (qsc_tls_signature_scheme)value;

				if (qsc_tls_signature_scheme_descriptor_get(sigschemes[i]) == NULL || tls_extensions_has_duplicate_signature(sigschemes, i, sigschemes[i]) == true)
				{
					status = qsc_tls_status_not_supported;
				}
			}
		}
	}

	if (status == qsc_tls_status_success)
	{
		*sigcount = count;
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_encode_supported_groups(uint8_t* output, size_t outlen, size_t* extlen, const qsc_tls_named_group* groups, size_t groupcount)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(extlen != NULL);
	QSC_ASSERT(groups != NULL);

	size_t i;
	size_t offset;
	uint16_t listlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	i = 0U;
	offset = 0U;
	listlen = 0U;

	if (output == NULL || extlen == NULL || groups == NULL || groupcount == 0U || groupcount > QSC_TLS_MAX_GROUPS)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*extlen = 0U;

		if (tls_extensions_group_list_is_valid(groups, groupcount) == false)
		{
			status = qsc_tls_status_not_supported;
		}

		if (status == qsc_tls_status_success)
		{
			listlen = (uint16_t)(groupcount * sizeof(uint16_t));
			status = tls_extensions_write_header(output, outlen, &offset, qsc_tls_extension_supported_groups, (uint16_t)(QSC_TLS_VECTOR16_HEADER_SIZE + listlen));

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u16(output, outlen, &offset, listlen);
			}

			for (i = 0U; i < groupcount && status == qsc_tls_status_success; ++i)
			{
				status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)groups[i]);
			}
		}
	}

	if (status == qsc_tls_status_success)
	{
		*extlen = offset;
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_decode_supported_groups(const uint8_t* input, size_t inlen, qsc_tls_named_group* groups, size_t maxgroups, size_t* groupcount)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(groups != NULL);
	QSC_ASSERT(groupcount != NULL);

	size_t count;
	size_t i;
	size_t offset;
	uint16_t type;
	uint16_t bodylen;
	uint16_t listlen;
	uint16_t value;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	i = 0U;
	offset = 0U;
	count = 0U;
	type = 0U;
	bodylen = 0U;
	listlen = 0U;
	value = 0U;

	if (input == NULL || groups == NULL || groupcount == NULL || maxgroups == 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*groupcount = 0U;
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)qsc_tls_extension_supported_groups)
		{
			status = qsc_tls_status_invalid_state;
		}

		if (status == qsc_tls_status_success && (size_t)bodylen != (inlen - offset))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &listlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (((size_t)listlen != (inlen - offset)) || ((listlen & 1U) != 0U))
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				count = (size_t)listlen / sizeof(uint16_t);

				if (count > maxgroups)
				{
					status = qsc_tls_status_buffer_too_small;
				}
			}
		}

		for (i = 0U; i < count && status == qsc_tls_status_success; ++i)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &value);

			if (status == qsc_tls_status_success)
			{
				groups[i] = (qsc_tls_named_group)value;

				if (qsc_tls_group_descriptor_get(groups[i]) == NULL || tls_extensions_has_duplicate_group(groups, i, groups[i]) == true)
				{
					status = qsc_tls_status_not_supported;
				}
			}
		}
	}

	if (status == qsc_tls_status_success)
	{
		*groupcount = count;
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_encode_signature_algorithms(uint8_t* output, size_t outlen, size_t* extlen, const qsc_tls_signature_scheme* sigschemes, size_t sigcount)
{
	return tls_extensions_encode_signature_scheme_list(output, outlen, extlen, qsc_tls_extension_signature_algorithms, sigschemes, sigcount);
}

qsc_tls_status qsc_tls_extensions_decode_signature_algorithms(const uint8_t* input, size_t inlen, qsc_tls_signature_scheme* sigschemes, size_t maxschemes, size_t* sigcount)
{
	return tls_extensions_decode_signature_scheme_list(input, inlen, qsc_tls_extension_signature_algorithms, sigschemes, maxschemes, sigcount);
}

qsc_tls_status qsc_tls_extensions_encode_signature_algorithms_cert(uint8_t* output, size_t outlen, size_t* extlen, const qsc_tls_signature_scheme* sigschemes, size_t sigcount)
{
	return tls_extensions_encode_signature_scheme_list(output, outlen, extlen, qsc_tls_extension_signature_algorithms_cert, sigschemes, sigcount);
}

qsc_tls_status qsc_tls_extensions_decode_signature_algorithms_cert(const uint8_t* input, size_t inlen, qsc_tls_signature_scheme* sigschemes, size_t maxschemes, size_t* sigcount)
{
	return tls_extensions_decode_signature_scheme_list(input, inlen, qsc_tls_extension_signature_algorithms_cert, sigschemes, maxschemes, sigcount);
}

qsc_tls_status qsc_tls_extensions_encode_key_share_single(uint8_t* output, size_t outlen, size_t* extlen, qsc_tls_named_group group, const uint8_t* keyshare, size_t keysharelen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(extlen != NULL);
	QSC_ASSERT(keyshare != NULL);

	size_t offset;
	uint16_t bodylen;
	uint16_t listlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	bodylen = 0U;
	listlen = 0U;

	if (output == NULL || extlen == NULL || keyshare == NULL || keysharelen == 0U || keysharelen > QSC_TLS_MAX_KEYSHARE_SIZE)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*extlen = 0U;

		if (qsc_tls_group_descriptor_get(group) == NULL)
		{
			status = qsc_tls_status_not_supported;
		}

		if (status == qsc_tls_status_success)
		{
			listlen = (uint16_t)(QSC_TLS_KEYSHARE_ENTRY_HEADER_SIZE + keysharelen);
			bodylen = (uint16_t)(QSC_TLS_VECTOR16_HEADER_SIZE + listlen);
			status = tls_extensions_write_header(output, outlen, &offset, qsc_tls_extension_key_share, bodylen);

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u16(output, outlen, &offset, listlen);
			}

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)group);
			}

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)keysharelen);
			}

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_bytes(output, outlen, &offset, keyshare, keysharelen);
			}
		}
	}

	if (status == qsc_tls_status_success)
	{
		*extlen = offset;
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_decode_key_share_single(const uint8_t* input, size_t inlen, qsc_tls_named_group* group, const uint8_t** keyshare, size_t* keysharelen)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(group != NULL);
	QSC_ASSERT(keyshare != NULL);
	QSC_ASSERT(keysharelen != NULL);

	size_t offset;
	uint16_t type;
	uint16_t bodylen;
	uint16_t listlen;
	uint16_t value;
	uint16_t sharelen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	type = 0U;
	bodylen = 0U;
	listlen = 0U;
	value = 0U;
	sharelen = 0U;

	if (input == NULL || group == NULL || keyshare == NULL || keysharelen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*group = qsc_tls_group_none;
		*keyshare = NULL;
		*keysharelen = 0U;
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)qsc_tls_extension_key_share)
		{
			status = qsc_tls_status_invalid_state;
		}

		if (status == qsc_tls_status_success && (size_t)bodylen != (inlen - offset))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &listlen);
		}

		if (status == qsc_tls_status_success && (size_t)listlen != (inlen - offset))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &value);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &sharelen);
		}

		if (status == qsc_tls_status_success && ((size_t)sharelen != (inlen - offset) || sharelen == 0U || (size_t)sharelen > QSC_TLS_MAX_KEYSHARE_SIZE))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success && qsc_tls_group_descriptor_get((qsc_tls_named_group)value) == NULL)
		{
			status = qsc_tls_status_not_supported;
		}

		if (status == qsc_tls_status_success)
		{
			*group = (qsc_tls_named_group)value;
			*keyshare = input + offset;
			*keysharelen = (size_t)sharelen;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_encode_key_share_hello_retry_request(uint8_t* output, size_t outlen, size_t* extlen, qsc_tls_named_group group)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(extlen != NULL);

	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;

	if (output == NULL || extlen == NULL || group == qsc_tls_group_none)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*extlen = 0U;

		if (qsc_tls_group_descriptor_get(group) == NULL)
		{
			status = qsc_tls_status_not_supported;
		}

		if (status == qsc_tls_status_success)
		{
			status = tls_extensions_write_header(output, outlen, &offset, qsc_tls_extension_key_share, 2U);

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)group);
			}
		}
	}

	if (status == qsc_tls_status_success)
	{
		*extlen = offset;
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_decode_key_share_hello_retry_request(const uint8_t* input, size_t inlen, qsc_tls_named_group* group)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(group != NULL);

	size_t offset;
	uint16_t type;
	uint16_t bodylen;
	uint16_t value;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	type = 0U;
	bodylen = 0U;
	value = 0U;

	if (input == NULL || group == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*group = qsc_tls_group_none;
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)qsc_tls_extension_key_share)
		{
			status = qsc_tls_status_invalid_state;
		}

		if (status == qsc_tls_status_success && ((size_t)bodylen != 2U || (inlen - offset) != 2U))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &value);
		}

		if (status == qsc_tls_status_success && qsc_tls_group_descriptor_get((qsc_tls_named_group)value) == NULL)
		{
			status = qsc_tls_status_not_supported;
		}

		if (status == qsc_tls_status_success)
		{
			*group = (qsc_tls_named_group)value;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_encode_psk_key_exchange_modes(uint8_t* output, size_t outlen, size_t* extlen, bool permitpskdhe)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(extlen != NULL);

	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;

	if (output == NULL || extlen == NULL || permitpskdhe == false)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = tls_extensions_write_header(output, outlen, &offset, qsc_tls_extension_psk_key_exchange_modes, 2U);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &offset, 1U);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &offset, 1U);
		}
	}

	if (status == qsc_tls_status_success)
	{
		*extlen = offset;
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_decode_psk_key_exchange_modes(const uint8_t* input, size_t inlen, bool* permitpskdhe)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(permitpskdhe != NULL);

	size_t offset;
	uint16_t type;
	uint16_t bodylen;
	uint8_t listlen;
	uint8_t mode;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	type = 0U;
	bodylen = 0U;
	listlen = 0U;
	mode = 0U;

	if (input == NULL || permitpskdhe == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*permitpskdhe = false;
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)qsc_tls_extension_psk_key_exchange_modes)
		{
			status = qsc_tls_status_invalid_state;
		}

		if (status == qsc_tls_status_success && (size_t)bodylen != (inlen - offset))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u8(input, inlen, &offset, &listlen);
		}

		if (status == qsc_tls_status_success)
		{
			if ((size_t)bodylen != (size_t)(listlen + 1U) || (inlen - offset) != (size_t)listlen || listlen == 0U)
			{
				status = qsc_tls_status_invalid_length;
			}
		}

		while (status == qsc_tls_status_success && listlen != 0U)
		{
			status = qsc_tls_codec_read_u8(input, inlen, &offset, &mode);

			if (status == qsc_tls_status_success && mode == 1U)
			{
				*permitpskdhe = true;
			}

			if (status == qsc_tls_status_success)
			{
				--listlen;
			}
		}

		if (status == qsc_tls_status_success && offset != inlen)
		{
			status = qsc_tls_status_invalid_length;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_encode_pre_shared_key_client(uint8_t* output, size_t outlen, size_t* extlen, const uint8_t* identity, size_t identitylen, uint32_t obfuscatedage, size_t binderlen, size_t* binderoffset)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(extlen != NULL);
	QSC_ASSERT(binderoffset != NULL);
	QSC_ASSERT(identity != NULL);

	size_t offset;
	size_t boff;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	boff = 0U;

	if (output == NULL || extlen == NULL || binderoffset == NULL || identity == NULL || identitylen == 0U || identitylen > 65535U || binderlen == 0U || binderlen > 255U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*extlen = 0U;
		*binderoffset = 0U;
		status = tls_extensions_write_header(output, outlen, &offset, qsc_tls_extension_pre_shared_key, (uint16_t)(2U + 2U + identitylen + 4U + 2U + 1U + binderlen));
		
		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)(2U + identitylen + 4U));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_vector16(output, outlen, &offset, identity, identitylen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u32(output, outlen, &offset, obfuscatedage);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)(1U + binderlen));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &offset, (uint8_t)binderlen);
			boff = offset;
		}

		while (status == qsc_tls_status_success && binderlen != 0U)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &offset, 0U);
			--binderlen;
		}
	}

	if (status == qsc_tls_status_success)
	{
		*extlen = offset;
		*binderoffset = boff;
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_decode_pre_shared_key_client(const uint8_t* input, size_t inlen, const uint8_t** identity, size_t* identitylen, uint32_t* obfuscatedage, const uint8_t** binder, size_t* binderlen, size_t* binderoffset)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(identity != NULL);
	QSC_ASSERT(identitylen != NULL);
	QSC_ASSERT(obfuscatedage != NULL);
	QSC_ASSERT(binder != NULL);
	QSC_ASSERT(binderoffset != NULL);

	const uint8_t* span;
	size_t binderlistlen;
	size_t idlistlen;
	size_t offset;
	size_t spanlen;
	uint16_t type;
	uint16_t bodylen;
	uint32_t age;
	uint8_t u8len;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	idlistlen = 0U;
	binderlistlen = 0U;
	span = NULL;
	spanlen = 0U;
	type = 0U;
	bodylen = 0U;
	age = 0U;
	u8len = 0U;

	if (input == NULL || identity == NULL || identitylen == NULL || obfuscatedage == NULL || binder == NULL || binderlen == NULL || binderoffset == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*identity = NULL;
		*identitylen = 0U;
		*obfuscatedage = 0U;
		*binder = NULL;
		*binderlen = 0U;
		*binderoffset = 0U;
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)qsc_tls_extension_pre_shared_key)
		{
			status = qsc_tls_status_invalid_state;
		}

		if (status == qsc_tls_status_success && (size_t)bodylen != (inlen - offset))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			uint16_t idlistlen16;
			idlistlen16 = 0U;
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &idlistlen16);
			idlistlen = idlistlen16;
		}

		if (status == qsc_tls_status_success)
		{
			if (idlistlen == 0U || idlistlen > (inlen - offset))
			{
				status = qsc_tls_status_invalid_length;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector16_span(input, inlen, &offset, &span, &spanlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u32(input, inlen, &offset, &age);
		}

		if (status == qsc_tls_status_success)
		{
			if ((offset - 4U) != (2U + idlistlen))
			{
				status = qsc_tls_status_invalid_length;
			}
		}

		if (status == qsc_tls_status_success)
		{
			uint16_t binderlistlen16;
			binderlistlen16 = 0U;
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &binderlistlen16);
			binderlistlen = binderlistlen16;
		}

		if (status == qsc_tls_status_success)
		{
			if (binderlistlen == 0U || binderlistlen > (inlen - offset))
			{
				status = qsc_tls_status_invalid_length;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u8(input, inlen, &offset, &u8len);
			*binderoffset = offset;
		}

		if (status == qsc_tls_status_success)
		{
			if ((size_t)u8len == 0U || (size_t)u8len > (inlen - offset) || binderlistlen != (size_t)(1U + u8len) || (size_t)bodylen != (inlen - 4U))
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				*identity = span;
				*identitylen = spanlen;
				*obfuscatedage = age;
				*binder = input + offset;
				*binderlen = (size_t)u8len;
			}
		}

		if (status == qsc_tls_status_success && ((offset + *binderlen) != inlen))
		{
			status = qsc_tls_status_invalid_length;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_encode_pre_shared_key_server(uint8_t* output, size_t outlen, size_t* extlen, uint16_t selectedidentity)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(extlen != NULL);
	
	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;

	if (output == NULL || extlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*extlen = 0U;
		status = tls_extensions_write_header(output, outlen, &offset, qsc_tls_extension_pre_shared_key, 2U);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, selectedidentity);
		}
	}

	if (status == qsc_tls_status_success)
	{
		*extlen = offset;
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_decode_pre_shared_key_server(const uint8_t* input, size_t inlen, uint16_t* selectedidentity)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(selectedidentity != NULL);

	size_t offset;
	uint16_t type;
	uint16_t bodylen;
	uint16_t value;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	type = 0U;
	bodylen = 0U;
	value = 0U;

	if (input == NULL || selectedidentity == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*selectedidentity = 0U;
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)qsc_tls_extension_pre_shared_key)
		{
			status = qsc_tls_status_invalid_state;
		}

		if (status == qsc_tls_status_success && ((size_t)bodylen != 2U || (inlen - offset) != 2U))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &value);
		}

		if (status == qsc_tls_status_success && offset != inlen)
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			*selectedidentity = value;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_encode_server_name_client(uint8_t* output, size_t outlen, size_t* extlen, const uint8_t* hostname, size_t hostnamelen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(extlen != NULL);
	QSC_ASSERT(hostname != NULL);

	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;

	if (output == NULL || extlen == NULL || hostname == NULL || hostnamelen == 0U || hostnamelen > QSC_TLS_MAX_HOSTNAME_SIZE)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*extlen = 0U;
		status = tls_extensions_write_header(output, outlen, &offset, qsc_tls_extension_server_name, (uint16_t)(5U + hostnamelen));

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)(3U + hostnamelen));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &offset, 0U);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)hostnamelen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &offset, hostname, hostnamelen);
		}

		if (status == qsc_tls_status_success)
		{
			*extlen = offset;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_decode_server_name_client(const uint8_t* input, size_t inlen, const uint8_t** hostname, size_t* hostnamelen)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(hostname != NULL);
	QSC_ASSERT(hostnamelen != NULL);

	const uint8_t* host;
	const uint8_t* namespan;
	size_t listlen;
	size_t offset;
	size_t hostlen;
	uint16_t bodylen;
	uint16_t type;
	uint16_t n16;
	uint8_t n8;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	namespan = NULL;
	host = NULL;
	listlen = 0U;
	offset = 0U;
	hostlen = 0U;
	bodylen = 0U;
	type = 0U;
	n16 = 0U;
	n8 = 0U;

	if (input == NULL || hostname == NULL || hostnamelen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*hostname = NULL;
		*hostnamelen = 0U;
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)qsc_tls_extension_server_name)
		{
			status = qsc_tls_status_invalid_state;
		}

		if (status == qsc_tls_status_success && (size_t)bodylen != (inlen - offset))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector16_span(input, inlen, &offset, &namespan, &listlen);
		}

		if (status == qsc_tls_status_success)
		{
			size_t noff;
			noff = 0U;
			status = qsc_tls_codec_read_u8(namespan, listlen, &noff, &n8);

			if (status == qsc_tls_status_success && n8 != 0U)
			{
				status = qsc_tls_status_not_supported;
			}

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_read_u16(namespan, listlen, &noff, &n16);
			}

			if (status == qsc_tls_status_success)
			{
				hostlen = (size_t)n16;

				if (hostlen == 0U || hostlen > QSC_TLS_MAX_HOSTNAME_SIZE || hostlen != (listlen - noff))
				{
					status = qsc_tls_status_invalid_length;
				}
				else
				{
					host = namespan + noff;
				}
			}
		}

		if (status == qsc_tls_status_success && offset != inlen)
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			*hostname = host;
			*hostnamelen = hostlen;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_encode_server_name_ack(uint8_t* output, size_t outlen, size_t* extlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(extlen != NULL);

	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;

	if (output == NULL || extlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*extlen = 0U;
		status = tls_extensions_write_header(output, outlen, &offset, qsc_tls_extension_server_name, 0U);
		if (status == qsc_tls_status_success)
		{
			*extlen = offset;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_decode_server_name_ack(const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(input != NULL);
	
	size_t offset;
	uint16_t bodylen;
	uint16_t type;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	bodylen = 0U;
	type = 0U;

	if (input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)qsc_tls_extension_server_name)
		{
			status = qsc_tls_status_invalid_state;
		}
		if (status == qsc_tls_status_success && ((size_t)bodylen != (inlen - offset) || bodylen != 0U))
		{
			status = qsc_tls_status_invalid_length;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_encode_alpn_client(uint8_t* output, size_t outlen, size_t* extlen, const uint8_t* protocol, size_t protocollen)
{
	return qsc_tls_extensions_encode_alpn_server(output, outlen, extlen, protocol, protocollen);
}

qsc_tls_status qsc_tls_extensions_decode_alpn_client(const uint8_t* input, size_t inlen, const uint8_t** protocol, size_t* protocollen)
{
	return qsc_tls_extensions_decode_alpn_server(input, inlen, protocol, protocollen);
}

qsc_tls_status qsc_tls_extensions_encode_alpn_server(uint8_t* output, size_t outlen, size_t* extlen, const uint8_t* protocol, size_t protocollen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(extlen != NULL);
	QSC_ASSERT(protocol != NULL);

	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;

	if (output == NULL || extlen == NULL || protocol == NULL || protocollen == 0U || protocollen > QSC_TLS_MAX_ALPN_SIZE)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*extlen = 0U;
		status = tls_extensions_write_header(output, outlen, &offset, qsc_tls_extension_application_layer_protocol_negotiation, (uint16_t)(3U + protocollen));
		
		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)(1U + protocollen));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u8(output, outlen, &offset, (uint8_t)protocollen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &offset, protocol, protocollen);
		}

		if (status == qsc_tls_status_success)
		{
			*extlen = offset;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_extensions_decode_alpn_server(const uint8_t* input, size_t inlen, const uint8_t** protocol, size_t* protocollen)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(protocol != NULL);
	QSC_ASSERT(protocollen != NULL);

	const uint8_t* listspan;
	const uint8_t* name;
	size_t listlen;
	size_t namelen;
	size_t offset;
	uint16_t bodylen;
	uint16_t type;
	qsc_tls_status status;
	uint8_t n8;

	status = qsc_tls_status_success;
	name = NULL;
	namelen = 0U;
	offset = 0U;
	listspan = NULL;
	listlen = 0U;
	bodylen = 0U;
	type = 0U;
	n8 = 0U;

	if (input == NULL || protocol == NULL || protocollen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*protocol = NULL;
		*protocollen = 0U;
		status = tls_extensions_read_header(input, inlen, &offset, &type, &bodylen);

		if (status == qsc_tls_status_success && type != (uint16_t)qsc_tls_extension_application_layer_protocol_negotiation)
		{
			status = qsc_tls_status_invalid_state;
		}

		if (status == qsc_tls_status_success && (size_t)bodylen != (inlen - offset))
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector16_span(input, inlen, &offset, &listspan, &listlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (listlen < 2U)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				size_t loff;

				loff = 0U;
				status = qsc_tls_codec_read_u8(listspan, listlen, &loff, &n8);

				if (status == qsc_tls_status_success)
				{
					namelen = (size_t)n8;

					if (namelen == 0U || namelen > QSC_TLS_MAX_ALPN_SIZE || namelen != (listlen - loff))
					{
						status = qsc_tls_status_invalid_length;
					}
					else
					{
						name = listspan + loff;
					}
				}
			}
		}

		if (status == qsc_tls_status_success && offset != inlen)
		{
			status = qsc_tls_status_invalid_length;
		}

		if (status == qsc_tls_status_success)
		{
			*protocol = name;
			*protocollen = namelen;
		}
	}

	return status;
}
