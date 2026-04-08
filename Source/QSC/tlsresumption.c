#include "tlsresumption.h"
#include "intutils.h"
#include "memutils.h"
#include "secrand.h"
#include "sha2.h"
#include "tlscodec.h"
#include "tlsextensions.h"
#include "tlshandshake.h"
#include "tlsschedule.h"

static qsc_tls_status tls_resumption_hmac_hash(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* message, size_t msglen)
{
	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);

	if (output == NULL || key == NULL || (message == NULL && msglen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (outlen < hlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		switch (hash)
		{
		case qsc_tls_hash_sha256:
			qsc_hmac256_compute(output, message, msglen, key, keylen);
			break;
		case qsc_tls_hash_sha384:
			qsc_hmac384_compute(output, message, msglen, key, keylen);
			break;
		case qsc_tls_hash_sha512:
			qsc_hmac512_compute(output, message, msglen, key, keylen);
			break;
		default:
			status = qsc_tls_status_not_supported;
			break;
		}
	}

	return status;
}

static qsc_tls_status tls_resumption_fill_random(uint8_t* output, size_t outlen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_secrand_generate(output, outlen) == false)
	{
		status = qsc_tls_status_failure;
	}

	return status;
}

void qsc_tls_session_ticket_initialize(qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(ticket != NULL);

	if (ticket != NULL)
	{
		qsc_memutils_clear((uint8_t*)ticket, sizeof(qsc_tls_session_ticket));
	}
}

void qsc_tls_session_ticket_dispose(qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(ticket != NULL);

	if (ticket != NULL)
	{
		qsc_memutils_secure_erase((uint8_t*)ticket, sizeof(qsc_tls_session_ticket));
	}
}

bool qsc_tls_session_ticket_is_valid(const qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(ticket != NULL);

	bool res;
	size_t hlen;

	res = false;
	hlen = 0U;

	if (ticket != NULL)
	{
		hlen = qsc_tls_transcript_hash_size(ticket->hash);
		res = (ticket->valid == true && ticket->hash != qsc_tls_hash_none && ticket->ciphersuite != qsc_tls_cipher_suite_none &&
			ticket->ticketlen != 0U && ticket->ticketlen <= QSC_TLS_TICKET_MAX_SIZE &&
			ticket->noncelen <= QSC_TLS_TICKET_NONCE_MAX_SIZE && hlen != 0U &&
			ticket->resumptionsecretlen == hlen);
	}

	return res;
}

qsc_tls_status qsc_tls_session_ticket_encode(const qsc_tls_session_ticket* ticket, uint8_t* output, size_t outlen, size_t* msglen)
{
	QSC_ASSERT(ticket != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(msglen != NULL);

	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;

	if (ticket == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_session_ticket_is_valid(ticket) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)ticket->hash);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)ticket->ciphersuite);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u32(output, outlen, &offset, ticket->ageadd);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u32(output, outlen, &offset, ticket->lifetime);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u32(output, outlen, &offset, ticket->maxearlydata);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_vector16(output, outlen, &offset, ticket->ticket, ticket->ticketlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_vector8(output, outlen, &offset, ticket->nonce, ticket->noncelen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_vector8(output, outlen, &offset, ticket->resumptionsecret, ticket->resumptionsecretlen);
		}
	}

	*msglen = (status == qsc_tls_status_success) ? offset : 0U;

	return status;
}

qsc_tls_status qsc_tls_session_ticket_decode(const uint8_t* input, size_t inlen, qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(ticket != NULL);

	const uint8_t* span;
	size_t offset;
	size_t spanlen;
	uint16_t hashid;
	uint16_t suiteid;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	hashid = 0U;
	suiteid = 0U;
	span = NULL;
	spanlen = 0U;

	if (input == NULL || ticket == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		qsc_tls_session_ticket_initialize(ticket);
		status = qsc_tls_codec_read_u16(input, inlen, &offset, &hashid);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &suiteid);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u32(input, inlen, &offset, &ticket->ageadd);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u32(input, inlen, &offset, &ticket->lifetime);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u32(input, inlen, &offset, &ticket->maxearlydata);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector16_span(input, inlen, &offset, &span, &spanlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (spanlen == 0U || spanlen > sizeof(ticket->ticket))
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				qsc_memutils_copy(ticket->ticket, span, spanlen);
				ticket->ticketlen = spanlen;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector8_span(input, inlen, &offset, &span, &spanlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (spanlen > sizeof(ticket->nonce))
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				if (spanlen != 0U)
				{
					qsc_memutils_copy(ticket->nonce, span, spanlen);
				}
				ticket->noncelen = spanlen;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector8_span(input, inlen, &offset, &span, &spanlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (spanlen > sizeof(ticket->resumptionsecret))
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				if (spanlen != 0U)
				{
					qsc_memutils_copy(ticket->resumptionsecret, span, spanlen);
				}

				ticket->resumptionsecretlen = spanlen;
				ticket->hash = (qsc_tls_hash_algorithm)hashid;
				ticket->ciphersuite = (qsc_tls_cipher_suite)suiteid;
				ticket->valid = (offset == inlen);
			}
		}
	}

	if (status == qsc_tls_status_success && qsc_tls_session_ticket_is_valid(ticket) == false)
	{
		status = qsc_tls_status_invalid_state;
	}

	return status;
}

qsc_tls_status qsc_tls_resumption_binder_key(qsc_tls_hash_algorithm hash, const uint8_t* psk, size_t psklen, bool externalpsk, uint8_t* output, size_t outlen)
{
	QSC_ASSERT(psk != NULL);
	QSC_ASSERT(output != NULL);

	uint8_t earlysecret[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t emptyhash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);

	if (psk == NULL || output == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (outlen < hlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		status = qsc_tls_schedule_extract(hash, earlysecret, sizeof(earlysecret), psk, psklen, NULL, 0U);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_schedule_empty_hash(hash, emptyhash, sizeof(emptyhash));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_schedule_derive_secret_from_hash(hash, output, outlen, earlysecret, hlen,
				externalpsk ? QSC_TLS_EXT_BINDER_LABEL : QSC_TLS_RES_BINDER_LABEL, emptyhash, hlen);
		}
	}

	qsc_memutils_secure_erase(earlysecret, sizeof(earlysecret));
	qsc_memutils_secure_erase(emptyhash, sizeof(emptyhash));

	return status;
}

qsc_tls_status qsc_tls_resumption_binder_verify_data(qsc_tls_hash_algorithm hash, const uint8_t* binderkey, size_t binderkeylen, const uint8_t* transcript, size_t transcriptlen, uint8_t* output, size_t outlen)
{
	QSC_ASSERT(binderkey != NULL);
	QSC_ASSERT(output != NULL);

	uint8_t finishedkey[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t transcripthash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);

	if (binderkey == NULL || output == NULL || (transcript == NULL && transcriptlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (binderkeylen != hlen || outlen < hlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		status = qsc_tls_schedule_finished_key(hash, finishedkey, sizeof(finishedkey), binderkey, binderkeylen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_schedule_empty_hash(hash, transcripthash, sizeof(transcripthash));

			if (status == qsc_tls_status_success && transcriptlen != 0U)
			{
				switch (hash)
				{
				case qsc_tls_hash_sha256:
					qsc_sha256_compute(transcripthash, transcript, transcriptlen);
					break;
				case qsc_tls_hash_sha384:
					qsc_sha384_compute(transcripthash, transcript, transcriptlen);
					break;
				case qsc_tls_hash_sha512:
					qsc_sha512_compute(transcripthash, transcript, transcriptlen);
					break;
				default:
					status = qsc_tls_status_not_supported;
					break;
				}
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = tls_resumption_hmac_hash(hash, output, outlen, finishedkey, hlen, transcripthash, hlen);
		}
	}

	qsc_memutils_secure_erase(finishedkey, sizeof(finishedkey));
	qsc_memutils_secure_erase(transcripthash, sizeof(transcripthash));

	return status;
}

qsc_tls_status qsc_tls_resumption_compute_psk_binder(const qsc_tls_session_ticket* ticket, const uint8_t* transcript, size_t transcriptlen, uint8_t* output, size_t outlen)
{
	QSC_ASSERT(ticket != NULL);
	QSC_ASSERT(output != NULL);

	uint8_t binderkey[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (ticket == NULL || output == NULL || (transcript == NULL && transcriptlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_session_ticket_is_valid(ticket) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_resumption_binder_key(ticket->hash, ticket->resumptionsecret, ticket->resumptionsecretlen, false, binderkey, sizeof(binderkey));

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_resumption_binder_verify_data(ticket->hash, binderkey, qsc_tls_transcript_hash_size(ticket->hash), transcript, transcriptlen, output, outlen);
		}
	}

	qsc_memutils_secure_erase(binderkey, sizeof(binderkey));

	return status;
}

qsc_tls_status qsc_tls_resumption_encode_new_session_ticket(const qsc_tls_session_ticket* ticket, uint8_t* output, size_t outlen, size_t* msglen)
{
	QSC_ASSERT(ticket != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(msglen == NULL);

	size_t extoffset;
	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	extoffset = 0U;
	offset = 0U;

	if (ticket == NULL || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_session_ticket_is_valid(ticket) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_codec_write_u32(output, outlen, &offset, ticket->lifetime);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u32(output, outlen, &offset, ticket->ageadd);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_vector8(output, outlen, &offset, ticket->nonce, ticket->noncelen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_vector16(output, outlen, &offset, ticket->ticket, ticket->ticketlen);
		}

		if (status == qsc_tls_status_success)
		{
			extoffset = offset;
			status = qsc_tls_codec_write_u16(output, outlen, &offset, 0U);
		}

		if (status == qsc_tls_status_success && ticket->maxearlydata != 0U)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)qsc_tls_extension_early_data);
		}

		if (status == qsc_tls_status_success && ticket->maxearlydata != 0U)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, 4U);
		}

		if (status == qsc_tls_status_success && ticket->maxearlydata != 0U)
		{
			status = qsc_tls_codec_write_u32(output, outlen, &offset, ticket->maxearlydata);
		}

		if (status == qsc_tls_status_success)
		{
			output[extoffset] = (uint8_t)(((uint16_t)(offset - extoffset - 2U)) >> 8);
			output[extoffset + 1U] = (uint8_t)((uint16_t)(offset - extoffset - 2U));
		}

		*msglen = (status == qsc_tls_status_success) ? offset : 0U;
	}

	return status;
}

qsc_tls_status qsc_tls_resumption_decode_new_session_ticket(const qsc_tls_connection_state* state, const uint8_t* input, size_t inlen, qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(ticket != NULL);
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(input == NULL);

	const uint8_t* span;
	size_t extoff;
	size_t extlen;
	size_t offset;
	size_t spanlen;
	uint16_t extbodylen;
	uint16_t extid;
	uint16_t extlistlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	span = NULL;
	extoff = 0U;
	extlen = 0U;
	offset = 0U;
	spanlen = 0U;
	extbodylen = 0U;
	extid = 0U;
	extlistlen = 0U;

	if (state == NULL || input == NULL || ticket == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (state->params.hash == qsc_tls_hash_none || state->params.ciphersuite == qsc_tls_cipher_suite_none)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		qsc_tls_session_ticket_initialize(ticket);
		status = qsc_tls_codec_read_u32(input, inlen, &offset, &ticket->lifetime);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u32(input, inlen, &offset, &ticket->ageadd);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector8_span(input, inlen, &offset, &span, &spanlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (spanlen > QSC_TLS_TICKET_NONCE_MAX_SIZE)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				if (spanlen != 0U)
				{
					qsc_memutils_copy(ticket->nonce, span, spanlen);
				}

				ticket->noncelen = spanlen;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_vector16_span(input, inlen, &offset, &span, &spanlen);
		}

		if (status == qsc_tls_status_success)
		{
			if (spanlen == 0U || spanlen > QSC_TLS_TICKET_MAX_SIZE)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				qsc_memutils_copy(ticket->ticket, span, spanlen);
				ticket->ticketlen = spanlen;
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &extlistlen);
		}

		if (status == qsc_tls_status_success)
		{
			if ((size_t)extlistlen != (inlen - offset))
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				extoff = 0U;
				extlen = (size_t)extlistlen;

				while (status == qsc_tls_status_success && extoff < extlen)
				{
					status = qsc_tls_codec_read_u16(input + offset, extlen, &extoff, &extid);

					if (status == qsc_tls_status_success)
					{
						status = qsc_tls_codec_read_u16(input + offset, extlen, &extoff, &extbodylen);
					}
					if (status == qsc_tls_status_success)
					{
						if ((size_t)extbodylen > (extlen - extoff))
						{
							status = qsc_tls_status_invalid_length;
						}
						else if (extid == (uint16_t)qsc_tls_extension_early_data)
						{
							if (extbodylen != 4U)
							{
								status = qsc_tls_status_invalid_length;
							}
							else
							{
								status = qsc_tls_codec_read_u32(input + offset, extlen, &extoff, &ticket->maxearlydata);
							}
						}
						else
						{
							extoff += (size_t)extbodylen;
						}
					}
				}
			}
		}

		if (status == qsc_tls_status_success)
		{
			ticket->hash = state->params.hash;
			ticket->ciphersuite = state->params.ciphersuite;
			status = qsc_tls_schedule_expand_label(ticket->hash, ticket->resumptionsecret, sizeof(ticket->resumptionsecret), state->mastersecret, state->mastersecretlen, QSC_TLS_RESUMPTION_LABEL, ticket->nonce, ticket->noncelen);
			
			if (status == qsc_tls_status_success)
			{
				ticket->resumptionsecretlen = qsc_tls_transcript_hash_size(ticket->hash);
				ticket->valid = true;
			}
		}
	}

	if (status == qsc_tls_status_success && qsc_tls_session_ticket_is_valid(ticket) == false)
	{
		status = qsc_tls_status_invalid_state;
	}

	return status;
}

qsc_tls_status qsc_tls_connection_state_generate_resumption_ticket(const qsc_tls_connection_state* state, uint32_t lifetime, qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(ticket != NULL);
	QSC_ASSERT(state != NULL);

	uint8_t ageaddbytes[4U] = { 0U };
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (state == NULL || ticket == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (state->mastersecretlen == 0U || state->params.hash == qsc_tls_hash_none || state->params.ciphersuite == qsc_tls_cipher_suite_none)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		qsc_tls_session_ticket_initialize(ticket);
		status = tls_resumption_fill_random(ticket->ticket, 32U);

		if (status == qsc_tls_status_success)
		{
			ticket->ticketlen = 32U;
			status = tls_resumption_fill_random(ticket->nonce, 16U);
		}

		if (status == qsc_tls_status_success)
		{
			ticket->noncelen = 16U;
			status = tls_resumption_fill_random(ageaddbytes, sizeof(ageaddbytes));
		}

		if (status == qsc_tls_status_success)
		{
			ticket->ageadd = qsc_intutils_be8to32(ageaddbytes);
			ticket->lifetime = lifetime;
			ticket->maxearlydata = 0U;
			ticket->hash = state->params.hash;
			ticket->ciphersuite = state->params.ciphersuite;
			status = qsc_tls_schedule_expand_label(ticket->hash, ticket->resumptionsecret, sizeof(ticket->resumptionsecret), state->mastersecret, state->mastersecretlen, QSC_TLS_RESUMPTION_LABEL, ticket->nonce, ticket->noncelen);
			
			if (status == qsc_tls_status_success)
			{
				ticket->resumptionsecretlen = qsc_tls_transcript_hash_size(ticket->hash);
				ticket->valid = true;
			}
		}
	}

	qsc_memutils_secure_erase(ageaddbytes, sizeof(ageaddbytes));

	return status;
}

qsc_tls_status qsc_tls_connection_state_enable_resumption(qsc_tls_connection_state* state, const qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(ticket != NULL);
	QSC_ASSERT(state != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (state == NULL || ticket == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_session_ticket_is_valid(ticket) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		qsc_tls_session_ticket_dispose(&state->resumptionticket);
		qsc_memutils_copy((uint8_t*)&state->resumptionticket, (const uint8_t*)ticket, sizeof(qsc_tls_session_ticket));
		state->resumptionenabled = true;
		state->resumedhandshake = false;
	}

	return status;
}

bool qsc_tls_connection_state_is_resumption_enabled(const qsc_tls_connection_state* state)
{
	QSC_ASSERT(state != NULL);
	
	bool res;

	res = false;

	if (state != NULL)
	{
		res = (state->resumptionenabled == true && qsc_tls_session_ticket_is_valid(&state->resumptionticket) == true);
	}

	return res;
}

qsc_tls_status qsc_tls_connection_state_build_resumption_ticket(const qsc_tls_connection_state* state, const uint8_t* newticket, size_t newticketlen, const uint8_t* nonce, size_t noncelen, uint32_t lifetime, uint32_t ageadd, qsc_tls_session_ticket* ticket)
{
	QSC_ASSERT(newticket != NULL);
	QSC_ASSERT(ticket != NULL);
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(nonce == NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (state == NULL || ticket == NULL || newticket == NULL || nonce == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (newticketlen == 0U || newticketlen > QSC_TLS_TICKET_MAX_SIZE || noncelen > QSC_TLS_TICKET_NONCE_MAX_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (state->mastersecretlen == 0U || state->params.hash == qsc_tls_hash_none || state->params.ciphersuite == qsc_tls_cipher_suite_none)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		qsc_tls_session_ticket_initialize(ticket);
		qsc_memutils_copy(ticket->ticket, newticket, newticketlen);
		ticket->ticketlen = newticketlen;

		if (noncelen != 0U)
		{
			qsc_memutils_copy(ticket->nonce, nonce, noncelen);
		}

		ticket->noncelen = noncelen;
		ticket->ageadd = ageadd;
		ticket->lifetime = lifetime;
		ticket->maxearlydata = 0U;
		ticket->hash = state->params.hash;
		ticket->ciphersuite = state->params.ciphersuite;
		status = qsc_tls_schedule_expand_label(ticket->hash, ticket->resumptionsecret, sizeof(ticket->resumptionsecret), state->mastersecret, state->mastersecretlen, QSC_TLS_RESUMPTION_LABEL, ticket->nonce, ticket->noncelen);
		
		if (status == qsc_tls_status_success)
		{
			ticket->resumptionsecretlen = qsc_tls_transcript_hash_size(ticket->hash);
			ticket->valid = true;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_connection_state_get_psk_binder(const qsc_tls_connection_state* state, const uint8_t* transcript, size_t transcriptlen, uint8_t* output, size_t outlen)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(output != NULL);
	
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (state == NULL || output == NULL || (transcript == NULL && transcriptlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_connection_state_is_resumption_enabled(state) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		status = qsc_tls_resumption_compute_psk_binder(&state->resumptionticket, transcript, transcriptlen, output, outlen);
	}

	return status;
}
