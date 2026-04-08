#include "tlscodec.h"
#include "intutils.h"
#include "memutils.h"

static bool tls_codec_can_write(size_t outlen, size_t offset, size_t needlen)
{
	return (offset <= outlen && needlen <= (outlen - offset));
}

static bool tls_codec_can_read(size_t inlen, size_t offset, size_t needlen)
{
	return (offset <= inlen && needlen <= (inlen - offset));
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

qsc_tls_status qsc_tls_codec_write_bytes(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inlen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if ((output == NULL || offset == NULL) || (input == NULL && inlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_write(outlen, *offset, inlen) == false)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else if (inlen != 0U)
	{
		qsc_memutils_copy(output + *offset, input, inlen);
		*offset += inlen;
	}
	else
	{
		/* no action */
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_vector8(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inlen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (inlen > 255U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_write_u8(output, outlen, offset, (uint8_t)inlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, offset, input, inlen);
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_vector16(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inlen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (inlen > 65535U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_write_u16(output, outlen, offset, (uint16_t)inlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, offset, input, inlen);
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_write_vector24(uint8_t* output, size_t outlen, size_t* offset, const uint8_t* input, size_t inlen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (inlen > 16777215U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_write_u24(output, outlen, offset, (uint32_t)inlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, offset, input, inlen);
		}
	}

	return status;
}

qsc_tls_status qsc_tls_codec_read_u8(const uint8_t* input, size_t inlen, size_t* offset, uint8_t* value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || value == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (*offset >= inlen)
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

qsc_tls_status qsc_tls_codec_read_u16(const uint8_t* input, size_t inlen, size_t* offset, uint16_t* value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || value == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_read(inlen, *offset, 2U) == false)
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

qsc_tls_status qsc_tls_codec_read_u24(const uint8_t* input, size_t inlen, size_t* offset, uint32_t* value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || value == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_read(inlen, *offset, 3U) == false)
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

qsc_tls_status qsc_tls_codec_read_u32(const uint8_t* input, size_t inlen, size_t* offset, uint32_t* value)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || value == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_read(inlen, *offset, 4U) == false)
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

qsc_tls_status qsc_tls_codec_read_bytes(const uint8_t* input, size_t inlen, size_t* offset, uint8_t* output, size_t outlen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (input == NULL || offset == NULL || (output == NULL && outlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_codec_can_read(inlen, *offset, outlen) == false)
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

qsc_tls_status qsc_tls_codec_read_vector8_span(const uint8_t* input, size_t inlen, size_t* offset, const uint8_t** span, size_t* spanlen)
{
	qsc_tls_status status;
	uint8_t len8;

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
		status = qsc_tls_codec_read_u8(input, inlen, offset, &len8);

		if (status == qsc_tls_status_success)
		{
			if (tls_codec_can_read(inlen, *offset, (size_t)len8) == false)
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

qsc_tls_status qsc_tls_codec_read_vector16_span(const uint8_t* input, size_t inlen, size_t* offset, const uint8_t** span, size_t* spanlen)
{
	qsc_tls_status status;
	uint16_t len16;

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
		status = qsc_tls_codec_read_u16(input, inlen, offset, &len16);

		if (status == qsc_tls_status_success)
		{
			if (tls_codec_can_read(inlen, *offset, (size_t)len16) == false)
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

qsc_tls_status qsc_tls_codec_read_vector24_span(const uint8_t* input, size_t inlen, size_t* offset, const uint8_t** span, size_t* spanlen)
{
	qsc_tls_status status;
	uint32_t len24;

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
		status = qsc_tls_codec_read_u24(input, inlen, offset, &len24);

		if (status == qsc_tls_status_success)
		{
			if (tls_codec_can_read(inlen, *offset, (size_t)len24) == false)
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
