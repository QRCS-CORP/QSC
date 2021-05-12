#include "qsmp.h"
#include "intutils.h"
#include "memutils.h"

void qsc_qsmp_packet_clear(qsc_qsmp_packet* packet)
{
	packet->flag = (uint8_t)qsc_qsmp_message_none;
	packet->msglen = 0;
	packet->sequence = 0;
	qsc_memutils_clear(packet->message, sizeof(packet->message));
}

void qsc_qsmp_packet_error_message(qsc_qsmp_packet* packet, qsc_qsmp_errors error)
{
	assert(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = qsc_qsmp_message_error_condition;
		packet->message[0] = (uint8_t)error;
		packet->msglen = 1;
		packet->sequence = 0xFF;
	}
}

void qsc_qsmp_packet_header_deserialize(const uint8_t* header, qsc_qsmp_packet* packet)
{
	assert(header != NULL);
	assert(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		packet->flag = header[0];
		packet->msglen = qsc_intutils_le8to32(((uint8_t*)header + sizeof(uint8_t)));
		packet->sequence = qsc_intutils_le8to32(((uint8_t*)header + sizeof(uint8_t) + sizeof(uint32_t)));
	}
}

void qsc_qsmp_packet_header_serialize(const qsc_qsmp_packet* packet, uint8_t* header)
{
	assert(header != NULL);
	assert(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		header[0] = packet->flag;
		qsc_intutils_le32to8(((uint8_t*)header + sizeof(uint8_t)), packet->msglen);
		qsc_intutils_le32to8(((uint8_t*)header + sizeof(uint8_t) + sizeof(uint32_t)), packet->sequence);
	}
}

size_t qsc_qsmp_packet_to_stream(const qsc_qsmp_packet* packet, uint8_t* pstream)
{
	assert(packet != NULL);
	assert(pstream != NULL);

	size_t res;

	res = 0;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0] = packet->flag;
		qsc_intutils_le32to8(((uint8_t*)pstream + sizeof(uint8_t)), packet->msglen);
		qsc_intutils_le32to8(((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t)), packet->sequence);

		if (packet->msglen <= QSC_QSMP_MESSAGE_MAX)
		{
			qsc_memutils_copy(((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t)), (uint8_t*)&packet->message, packet->msglen);
			res = QSC_QSMP_HEADER_SIZE + packet->msglen;
		}
	}

	return res;
}

void qsc_qsmp_stream_to_packet(const uint8_t* pstream, qsc_qsmp_packet* packet)
{
	assert(packet != NULL);
	assert(pstream != NULL);

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0];
		packet->msglen = qsc_intutils_le8to32(((uint8_t*)pstream + sizeof(uint8_t)));
		packet->sequence = qsc_intutils_le8to32(((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t)));

		if (packet->msglen <= QSC_QSMP_MESSAGE_MAX)
		{
			qsc_memutils_copy((uint8_t*)&packet->message, ((uint8_t*)pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t)), packet->msglen);
		}
	}
}