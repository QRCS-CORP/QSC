#include "tlsio.h"
#include "memutils.h"

void qsc_tls_iobuf_initialize(qsc_tls_iobuf* buffer, uint8_t* data, size_t length)
{
	QSC_ASSERT(buffer != NULL);

	if (buffer != NULL)
	{
		buffer->data = data;
		buffer->length = length;
		buffer->position = 0U;
	}
}

void qsc_tls_iobuf_reset(qsc_tls_iobuf* buffer)
{
	QSC_ASSERT(buffer != NULL);

	if (buffer != NULL)
	{
		buffer->position = 0U;
	}
}

qsc_tls_status qsc_tls_iobuf_set_position(qsc_tls_iobuf* buffer, size_t position)
{
	QSC_ASSERT(buffer != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (buffer == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (position > buffer->length)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		buffer->position = position;
	}

	return status;
}

qsc_tls_status qsc_tls_iobuf_advance(qsc_tls_iobuf* buffer, size_t length)
{
	QSC_ASSERT(buffer != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (buffer == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_iobuf_remaining(buffer) < length)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		buffer->position += length;
	}

	return status;
}

size_t qsc_tls_iobuf_remaining(const qsc_tls_iobuf* buffer)
{
	QSC_ASSERT(buffer != NULL);

	size_t res;

	res = 0U;

	if (buffer != NULL && buffer->position <= buffer->length)
	{
		res = buffer->length - buffer->position;
	}

	return res;
}

qsc_tls_status qsc_tls_iobuf_write(qsc_tls_iobuf* buffer, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(buffer != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (buffer == NULL || (inlen != 0U && input == NULL))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (buffer->position > buffer->length)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (buffer->data == NULL && buffer->length != 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_iobuf_remaining(buffer) < inlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else if (inlen != 0U)
	{
		qsc_memutils_copy((buffer->data + buffer->position), input, inlen);
		buffer->position += inlen;
	}
	else
	{
		buffer->position += 0U;
	}

	return status;
}

qsc_tls_status qsc_tls_iobuf_read(qsc_tls_iobuf* buffer, uint8_t* output, size_t outlen)
{
	QSC_ASSERT(buffer != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (buffer == NULL || (outlen != 0U && output == NULL))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (buffer->position > buffer->length)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (buffer->data == NULL && buffer->length != 0U)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_iobuf_remaining(buffer) < outlen)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (outlen != 0U)
	{
		qsc_memutils_copy(output, (buffer->data + buffer->position), outlen);
		buffer->position += outlen;
	}
	else
	{
		buffer->position += 0U;
	}

	return status;
}
