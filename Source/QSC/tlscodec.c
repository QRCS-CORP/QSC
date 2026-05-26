#include "tlscodec.h"
#include "intutils.h"
#include "memutils.h"

static bool tls_codec_can_write(size_t outlen, size_t offset, size_t needlen)
{
	return (offset <= outlen && needlen <= (outlen - offset));
}

static bool tls_codec_can_read(size_t inplen, size_t offset, size_t needlen)
{
	return (offset <= inplen && needlen <= (inplen - offset));
}

qsc_tls_status qsc_tls_codec_write_u8(uint8_t* output, size_t outlen, size_t* offset, uint8_t value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (*offset >= outlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		output[*offset] = value;
		*offset += 1U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_u16(uint8_t* output, size_t outlen, size_t* offset, uint16_t value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_write(outlen, *offset, 2U) == false)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		qsc_intutils_be16to8(output + *offset, value);
		*offset += 2U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_u24(uint8_t* output, size_t outlen, size_t* offset, uint32_t value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (value > 0xFFFFFFUL)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (tls_codec_can_write(outlen, *offset, 3U) == false)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		output[*offset] = (uint8_t)((value >> 16) & 0xFFU);
		output[*offset + 1U] = (uint8_t)((value >> 8) & 0xFFU);
		output[*offset + 2U] = (uint8_t)(value & 0xFFU);
		*offset += 3U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_u32(uint8_t* output, size_t outlen, size_t* offset, uint32_t value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_write(outlen, *offset, 4U) == false)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		qsc_intutils_be32to8(output + *offset, value);
		*offset += 4U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_bytes(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inplen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if ((output == NULL || offset == NULL) || (input == NULL && inplen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_write(outlen, *offset, inplen) == false)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else if (inplen != 0U)
	{
		qsc_memutils_copy(output + *offset, input, inplen);
		*offset += inplen;
	}
	else
	{
		/* no action */
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_vector8(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inplen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (inplen > 255U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_write_u8(output, outlen, offset, (uint8_t)inplen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, offset, input, inplen);
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_vector16(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inplen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (inplen > 65535U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)inplen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, offset, input, inplen);
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_vector24(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inplen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (inplen > 16777215U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_write_u24(output, outlen, offset, (uint32_t)inplen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, offset, input, inplen);
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_u8(const uint8_t* input, size_t inplen, size_t* offset, uint8_t* value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || value == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (*offset >= inplen)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		*value = input[*offset];
		*offset += 1U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_u16(const uint8_t* input, size_t inplen, size_t* offset, uint16_t* value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || value == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_read(inplen, *offset, 2U) == false)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		*value = qsc_intutils_be8to16(input + *offset);
		*offset += 2U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_u24(const uint8_t* input, size_t inplen, size_t* offset, uint32_t* value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || value == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_read(inplen, *offset, 3U) == false)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		*value = ((uint32_t)input[*offset] << 16) | ((uint32_t)input[*offset + 1U] << 8) | input[*offset + 2U];
		*offset += 3U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_u32(const uint8_t* input, size_t inplen, size_t* offset, uint32_t* value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || value == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_read(inplen, *offset, 4U) == false)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		*value = qsc_intutils_be8to32(input + *offset);
		*offset += 4U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_bytes(const uint8_t* input, size_t inplen, size_t* offset, uint8_t* output, size_t outlen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || (output == NULL && outlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_read(inplen, *offset, outlen) == false)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		if (outlen != 0U)
		{
			qsc_memutils_copy(output, input + *offset, outlen);
		}

		*offset += outlen;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_vector8_span(const uint8_t* input, size_t inplen, size_t* offset, const uint8_t** span, size_t* spanlen)
{
	uint8_t len8;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	len8 = 0U;

	if (input == NULL || offset == NULL || span == NULL || spanlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*span = NULL;
		*spanlen = 0U;
		status = qsc_tls_codec_read_u8(input, inplen, offset, &len8);

		if (status == qsc_tls_status_success)
		{
			if (tls_codec_can_read(inplen, *offset, (size_t)len8) == false)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				*span = input + *offset;
				*spanlen = (size_t)len8;
				*offset += (size_t)len8;
			}
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_vector16_span(const uint8_t* input, size_t inplen, size_t* offset, const uint8_t** span, size_t* spanlen)
{
	uint16_t len16;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	len16 = 0U;

	if (input == NULL || offset == NULL || span == NULL || spanlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*span = NULL;
		*spanlen = 0U;
		status = qsc_tls_codec_read_u16(input, inplen, offset, &len16);

		if (status == qsc_tls_status_success)
		{
			if (tls_codec_can_read(inplen, *offset, (size_t)len16) == false)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				*span = input + *offset;
				*spanlen = (size_t)len16;
				*offset += (size_t)len16;
			}
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_vector24_span(const uint8_t* input, size_t inplen, size_t* offset, const uint8_t** span, size_t* spanlen)
{
	uint32_t len24;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	len24 = 0U;

	if (input == NULL || offset == NULL || span == NULL || spanlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*span = NULL;
		*spanlen = 0U;
		status = qsc_tls_codec_read_u24(input, inplen, offset, &len24);

		if (status == qsc_tls_status_success)
		{
			if (tls_codec_can_read(inplen, *offset, (size_t)len24) == false)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				*span = input + *offset;
				*spanlen = (size_t)len24;
				*offset += (size_t)len24;
			}
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_u64(const uint8_t* input, size_t inplen, size_t* offset, uint64_t* value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || value == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_read(inplen, *offset, 8U) == false)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		*value = qsc_intutils_be8to64(input + *offset);
		*offset += 8U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_vector_begin_u8(uint8_t* output, size_t outlen, size_t* offset, size_t* headerposition)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL || headerposition == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_write(outlen, *offset, 1U) == false)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		*headerposition = *offset;
		output[*offset] = 0U;
		*offset += 1U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_vector_begin_u16(uint8_t* output, size_t outlen, size_t* offset, size_t* headerposition)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL || headerposition == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_write(outlen, *offset, 2U) == false)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		*headerposition = *offset;
		output[*offset] = 0U;
		output[*offset + 1U] = 0U;
		*offset += 2U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_vector_begin_u24(uint8_t* output, size_t outlen, size_t* offset, size_t* headerposition)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL || headerposition == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_write(outlen, *offset, 3U) == false)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		*headerposition = *offset;
		output[*offset] = 0U;
		output[*offset + 1U] = 0U;
		output[*offset + 2U] = 0U;
		*offset += 3U;
	}

	return status;
}

qsc_tls_status qsc_tls_codec_vector_end_u8(uint8_t* output, size_t outlen, const size_t* offset, size_t headerposition)
{
	size_t bodylen;
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (headerposition >= outlen || *offset < (headerposition + 1U) || *offset > outlen)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		bodylen = *offset - (headerposition + 1U);

		if (bodylen > 0xFFU)
		{
			status = qsc_tls_status_invalid_length;
		}
		else
		{
			output[headerposition] = (uint8_t)bodylen;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_vector_end_u16(uint8_t* output, size_t outlen, const size_t* offset, size_t headerposition)
{
	size_t bodylen;
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if ((headerposition + 2U) > outlen || *offset < (headerposition + 2U) || *offset > outlen)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		bodylen = *offset - (headerposition + 2U);

		if (bodylen > 0xFFFFU)
		{
			status = qsc_tls_status_invalid_length;
		}
		else
		{
			qsc_intutils_be16to8(output + headerposition, (uint16_t)bodylen);
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_vector_end_u24(uint8_t* output, size_t outlen, const size_t* offset, size_t headerposition)
{
	size_t bodylen;
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || offset == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if ((headerposition + 3U) > outlen || *offset < (headerposition + 3U) || *offset > outlen)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		bodylen = *offset - (headerposition + 3U);

		if (bodylen > 0xFFFFFFU)
		{
			status = qsc_tls_status_invalid_length;
		}
		else
		{
			output[headerposition] = (uint8_t)((bodylen >> 16) & 0xFFU);
			output[headerposition + 1U] = (uint8_t)((bodylen >> 8) & 0xFFU);
			output[headerposition + 2U] = (uint8_t)(bodylen & 0xFFU);
		}
	}

	return status;
}
