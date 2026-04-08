#include "tlscertmsg.h"
#include "memutils.h"
#include "tlssigalgs.h"

static qsc_tls_status tls_certmsg_build_sigalgs_extension(const qsc_tls_signature_scheme* sigschemes, size_t sigschemecount, uint8_t* output, size_t outlen, size_t* extlen)
{
	qsc_tls_status status;
	size_t offset;
	size_t i;
	uint16_t listlen;

	status = qsc_tls_status_success;
	offset = 0U;
	listlen = 0U;
	i = 0U;

	if ((sigschemes == NULL && sigschemecount != 0U) || output == NULL || extlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (sigschemecount > QSC_TLS_MAX_SIGNATURE_SCHEMES)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		listlen = (uint16_t)(sigschemecount * sizeof(uint16_t));
		status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)qsc_tls_extension_signature_algorithms);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)(2U + listlen));
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, listlen);
		}

		while (status == qsc_tls_status_success && i < sigschemecount)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)sigschemes[i]);
			++i;
		}
	}

	if (extlen != NULL)
	{
		*extlen = offset;
	}

	return status;
}

bool qsc_tls_certificate_verify_scheme_allowed(qsc_tls_signature_scheme scheme)
{
	bool ret;

	ret = qsc_tls_signature_scheme_is_certificate_verify_capable(scheme);

	return ret;
}

qsc_tls_status qsc_tls_certificate_verify_input_build(bool isserver, const uint8_t* transcripthash, size_t transcripthashlen, uint8_t* output, size_t outlen, size_t* outputlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(outputlen != NULL);

	static const uint8_t servercontext[] = "TLS 1.3, server CertificateVerify";
	static const uint8_t clientcontext[] = "TLS 1.3, client CertificateVerify";
	const uint8_t* context;
	size_t contextlen;
	size_t i;
	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	context = isserver ? servercontext : clientcontext;
	contextlen = isserver ? (sizeof(servercontext) - 1U) : (sizeof(clientcontext) - 1U);
	offset = 0U;
	i = 0U;

	if ((transcripthash == NULL && transcripthashlen != 0U) || output == NULL || outputlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (outlen < (64U + contextlen + 1U + transcripthashlen))
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		while (i < 64U)
		{
			output[offset + i] = 0x20U;
			++i;
		}

		offset += 64U;
		qsc_memutils_copy(output + offset, context, contextlen);
		offset += contextlen;
		output[offset] = 0U;
		++offset;
		qsc_memutils_copy(output + offset, transcripthash, transcripthashlen);
		offset += transcripthashlen;
	}

	*outputlen = (status == qsc_tls_status_success) ? offset : 0U;

	return status;
}

qsc_tls_status qsc_tls_certificate_message_build(const uint8_t* requestcontext, size_t requestcontextlen, 
	const qsc_tls_certificate_entry_view* entries, size_t entrycount, uint8_t* output, size_t outlen, size_t* msglen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(msglen != NULL);

	size_t i;
	size_t listoffset;
	size_t liststart;
	size_t listlen;
	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	i = 0U;
	listoffset = 0U;
	liststart = 0U;
	listlen = 0U;

	if (((requestcontext == NULL) && requestcontextlen != 0U) || ((entries == NULL) && entrycount != 0U) || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (requestcontextlen > QSC_TLS_CERTIFICATE_REQUEST_CONTEXT_MAX_SIZE || entrycount > QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_write_u8(output, outlen, &offset, (uint8_t)requestcontextlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &offset, requestcontext, requestcontextlen);
		}

		if (status == qsc_tls_status_success)
		{
			listoffset = offset;
			status = qsc_tls_codec_write_u24(output, outlen, &offset, 0U);
			liststart = offset;
		}

		while (status == qsc_tls_status_success && i < entrycount)
		{
			if ((entries[i].certdata == NULL && entries[i].certdatalen != 0U) || (entries[i].extensions == NULL && entries[i].extensionslen != 0U) || entries[i].certdatalen > QSC_TLS_CERTIFICATE_MAX_SIZE || entries[i].extensionslen > QSC_TLS_MAX_EXTENSION_SIZE)
			{
				status = qsc_tls_status_invalid_input;
			}
			else
			{
				status = qsc_tls_codec_write_u24(output, outlen, &offset, (uint32_t)entries[i].certdatalen);

				if (status == qsc_tls_status_success)
				{
					status = qsc_tls_codec_write_bytes(output, outlen, &offset, entries[i].certdata, entries[i].certdatalen);
				}

				if (status == qsc_tls_status_success)
				{
					status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)entries[i].extensionslen);
				}

				if (status == qsc_tls_status_success)
				{
					status = qsc_tls_codec_write_bytes(output, outlen, &offset, entries[i].extensions, entries[i].extensionslen);
				}
			}

			++i;
		}

		if (status == qsc_tls_status_success)
		{
			listlen = offset - liststart;

			if (listlen > 0xFFFFFFUL)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				output[listoffset] = (uint8_t)((listlen >> 16) & 0xFFU);
				output[listoffset + 1U] = (uint8_t)((listlen >> 8) & 0xFFU);
				output[listoffset + 2U] = (uint8_t)(listlen & 0xFFU);
			}
		}

		*msglen = (status == qsc_tls_status_success) ? offset : 0U;
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_message_parse(const uint8_t* input, size_t inlen, qsc_tls_certificate_message_view* message)
{
	QSC_ASSERT(message != NULL);

	size_t listend;
	size_t offset;
	uint32_t listlen;
	uint32_t certlen;
	uint16_t extlen;
	uint8_t ctxlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	ctxlen = 0U;
	listlen = 0U;
	listend = 0U;
	certlen = 0U;
	extlen = 0U;

	if (input == NULL || message == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)message, sizeof(qsc_tls_certificate_message_view));
		status = qsc_tls_codec_read_u8(input, inlen, &offset, &ctxlen);

		if (status == qsc_tls_status_success)
		{
			message->requestcontextlen = (size_t)ctxlen;
			status = qsc_tls_codec_read_bytes(input, inlen, &offset, message->requestcontext, message->requestcontextlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u24(input, inlen, &offset, &listlen);
		}

		if (status == qsc_tls_status_success)
		{
			if ((inlen - offset) != (size_t)listlen)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				listend = offset + (size_t)listlen;
			}
		}

		while (status == qsc_tls_status_success && offset < listend)
		{
			if (message->entrycount >= QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				status = qsc_tls_codec_read_u24(input, inlen, &offset, &certlen);

				if (status == qsc_tls_status_success)
				{
					if (certlen == 0U || (size_t)certlen > QSC_TLS_CERTIFICATE_MAX_SIZE)
					{
						status = qsc_tls_status_invalid_length;
					}
					else if ((inlen - offset) < (size_t)certlen)
					{
						status = qsc_tls_status_invalid_length;
					}
					else
					{
						message->entries[message->entrycount].certdata = input + offset;
						message->entries[message->entrycount].certdatalen = (size_t)certlen;
						offset += (size_t)certlen;
					}
				}

				if (status == qsc_tls_status_success)
				{
					status = qsc_tls_codec_read_u16(input, inlen, &offset, &extlen);
				}

				if (status == qsc_tls_status_success)
				{
					if ((size_t)extlen > QSC_TLS_MAX_EXTENSION_SIZE)
					{
						status = qsc_tls_status_invalid_length;
					}
					else if ((inlen - offset) < (size_t)extlen)
					{
						status = qsc_tls_status_invalid_length;
					}
					else
					{
						message->entries[message->entrycount].extensions = input + offset;
						message->entries[message->entrycount].extensionslen = (size_t)extlen;
						offset += (size_t)extlen;
						++message->entrycount;
					}
				}
			}
		}

		if (status == qsc_tls_status_success && offset != listend)
		{
			status = qsc_tls_status_invalid_length;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_request_build(const uint8_t* requestcontext, size_t requestcontextlen, const qsc_tls_signature_scheme* sigschemes, 
	size_t sigschemecount, uint8_t* output, size_t outlen, size_t* msglen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(msglen != NULL);

	size_t offset;
	size_t extlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	extlen = 0U;

	if (((requestcontext == NULL) && requestcontextlen != 0U) || ((sigschemes == NULL) && sigschemecount != 0U) || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (requestcontextlen > QSC_TLS_CERTIFICATE_REQUEST_CONTEXT_MAX_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_write_u8(output, outlen, &offset, (uint8_t)requestcontextlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &offset, requestcontext, requestcontextlen);
		}

		if (status == qsc_tls_status_success)
		{
			if ((outlen - offset) < 2U)
			{
				status = qsc_tls_status_buffer_too_small;
			}
			else
			{
				status = tls_certmsg_build_sigalgs_extension(sigschemes, sigschemecount, output + offset + 2U, outlen - offset - 2U, &extlen);
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)extlen);
		}

		if (status == qsc_tls_status_success)
		{
			offset += extlen;
		}

		*msglen = (status == qsc_tls_status_success) ? offset : 0U;
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_request_parse(const uint8_t* input, size_t inlen, qsc_tls_certificate_request_message* message)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(message != NULL);

	size_t extend;
	size_t offset;
	uint16_t extblocklen;
	uint16_t exttype;
	uint16_t extsize;
	uint16_t siglistlen;
	uint16_t scheme;
	uint8_t ctxlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	ctxlen = 0U;
	extblocklen = 0U;
	extend = 0U;
	exttype = 0U;
	extsize = 0U;
	siglistlen = 0U;
	scheme = 0U;

	if (input == NULL || message == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)message, sizeof(qsc_tls_certificate_request_message));
		status = qsc_tls_codec_read_u8(input, inlen, &offset, &ctxlen);

		if (status == qsc_tls_status_success)
		{
			if ((size_t)ctxlen > QSC_TLS_CERTIFICATE_REQUEST_CONTEXT_MAX_SIZE)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				message->requestcontextlen = (size_t)ctxlen;
				status = qsc_tls_codec_read_bytes(input, inlen, &offset, message->requestcontext, message->requestcontextlen);
			}
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &extblocklen);
		}

		if (status == qsc_tls_status_success)
		{
			if ((inlen - offset) != (size_t)extblocklen)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				extend = offset + (size_t)extblocklen;
			}
		}

		while (status == qsc_tls_status_success && offset < extend)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &exttype);

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_read_u16(input, inlen, &offset, &extsize);
			}

			if (status == qsc_tls_status_success)
			{
				if ((inlen - offset) < (size_t)extsize)
				{
					status = qsc_tls_status_invalid_length;
				}
				else if (exttype == (uint16_t)qsc_tls_extension_signature_algorithms)
				{
					status = qsc_tls_codec_read_u16(input, inlen, &offset, &siglistlen);

					if (status == qsc_tls_status_success)
					{
						if (siglistlen + 2U != extsize || (siglistlen & 1U) != 0U)
						{
							status = qsc_tls_status_invalid_length;
						}
					}
					while (status == qsc_tls_status_success && siglistlen != 0U)
					{
						if (message->sigschemecount >= QSC_TLS_MAX_SIGNATURE_SCHEMES)
						{
							status = qsc_tls_status_invalid_length;
						}
						else
						{
							status = qsc_tls_codec_read_u16(input, inlen, &offset, &scheme);

							if (status == qsc_tls_status_success)
							{
								message->sigschemes[message->sigschemecount] = (qsc_tls_signature_scheme)scheme;
								++message->sigschemecount;
								siglistlen = (uint16_t)(siglistlen - 2U);
							}
						}
					}
				}
				else
				{
					offset += (size_t)extsize;
				}
			}
		}

		if (status == qsc_tls_status_success && offset != extend)
		{
			status = qsc_tls_status_invalid_length;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_verify_build(qsc_tls_signature_scheme scheme, const uint8_t* signature, size_t signaturelen, uint8_t* output, size_t outlen, size_t* msglen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(msglen != NULL);

	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;

	if ((signature == NULL && signaturelen != 0U) || output == NULL || msglen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (signaturelen > QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (qsc_tls_certificate_verify_scheme_allowed(scheme) == false)
	{
		status = qsc_tls_status_not_supported;
	}
	else
	{
		status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)scheme);
		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)signaturelen);
		}
		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &offset, signature, signaturelen);
		}

		*msglen = (status == qsc_tls_status_success) ? offset : 0U;
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_verify_parse(const uint8_t* input, size_t inlen, qsc_tls_certificate_verify_message* message)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(message != NULL);

	size_t offset;
	uint16_t scheme;
	uint16_t siglen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	scheme = 0U;
	siglen = 0U;

	if (input == NULL || message == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		qsc_memutils_clear((uint8_t*)message, sizeof(qsc_tls_certificate_verify_message));
		status = qsc_tls_codec_read_u16(input, inlen, &offset, &scheme);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &siglen);
		}
		if (status == qsc_tls_status_success)
		{
			if ((inlen - offset) != (size_t)siglen)
			{
				status = qsc_tls_status_invalid_length;
			}
			else if (qsc_tls_certificate_verify_scheme_allowed((qsc_tls_signature_scheme)scheme) == false)
			{
				status = qsc_tls_status_not_supported;
			}
			else
			{
				message->scheme = (qsc_tls_signature_scheme)scheme;
				message->signature = input + offset;
				message->signaturelen = (size_t)siglen;
			}
		}
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_validate_peer(const qsc_tls_certificate_message_view* message, const qsc_tls_certificate_validation_context* context, const qsc_tls_certificate_interface* iface)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(context != NULL);
	QSC_ASSERT(iface != NULL);

	qsc_tls_certificate_view chain[QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES] = { 0 };
	size_t i;
	bool valid;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	i = 0U;
	valid = false;

	if (message == NULL || context == NULL || iface == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_certificate_interface_is_valid(iface) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else if (context->requirepeercertificate == true && message->entrycount == 0U)
	{
		status = qsc_tls_status_invalid_message;
	}
	else
	{
		while (i < message->entrycount)
		{
			chain[i].data = message->entries[i].certdata;
			chain[i].datalen = message->entries[i].certdatalen;
			++i;
		}

		valid = iface->validatechain(chain, message->entrycount, context, iface->state);
		if (valid == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_certificate_validate_verify(const qsc_tls_certificate_message_view* message, const qsc_tls_certificate_verify_message* verify, 
	const uint8_t* verifyinput, size_t verifyinputlen, const qsc_tls_certificate_interface* iface)
{
	QSC_ASSERT(message != NULL);
	QSC_ASSERT(verify != NULL);
	QSC_ASSERT(iface != NULL);

	qsc_tls_certificate_view signer;
	bool valid;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	valid = false;
	signer.data = NULL;
	signer.datalen = 0U;

	if (message == NULL || verify == NULL || iface == NULL || (verifyinput == NULL && verifyinputlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (qsc_tls_certificate_interface_is_valid(iface) == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else if (message->entrycount == 0U)
	{
		status = qsc_tls_status_invalid_message;
	}
	else
	{
		signer.data = message->entries[0U].certdata;
		signer.datalen = message->entries[0U].certdatalen;
		valid = iface->verifycertificateverify(verify->scheme, verifyinput, verifyinputlen, verify->signature, verify->signaturelen, &signer, iface->state);

		if (valid == false)
		{
			status = qsc_tls_status_authentication_failure;
		}
	}

	return status;
}
