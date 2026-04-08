#include "tlsschedule.h"
#include "tlsdefs.h"
#include "tlslimits.h"
#include "memutils.h"
#include "stringutils.h"

static const char tls_schedule_label_client_handshake_traffic[] = "c hs traffic";
static const char tls_schedule_label_server_handshake_traffic[] = "s hs traffic";
static const char tls_schedule_label_client_application_traffic[] = "c ap traffic";
static const char tls_schedule_label_server_application_traffic[] = "s ap traffic";

static qsc_tls_status tls_schedule_hash_buffer(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* input, size_t inlen)
{
	size_t hlen;
	qsc_tls_status status;
	const uint8_t* msg;
	uint8_t zero;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);
	msg = input;
	zero = 0U;

	if (output == NULL || (input == NULL && inlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (outlen < hlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		if (msg == NULL)
		{
			msg = &zero;
		}

		switch (hash)
		{
		case qsc_tls_hash_sha256:
			qsc_sha256_compute(output, msg, inlen);
			break;
		case qsc_tls_hash_sha384:
			qsc_sha384_compute(output, msg, inlen);
			break;
		case qsc_tls_hash_sha512:
			qsc_sha512_compute(output, msg, inlen);
			break;
		default:
			status = qsc_tls_status_not_supported;
			break;
		}
	}

	return status;
}

static qsc_tls_status tls_schedule_build_label(uint8_t* output, size_t outlen, size_t* msglen, size_t reclen, const char* label, const uint8_t* context, size_t contextlen)
{
	qsc_tls_status status;
	size_t offset;
	size_t labellen;

	status = qsc_tls_status_success;
	offset = 0U;
	labellen = 0U;

	if (output == NULL || msglen == NULL || label == NULL || (context == NULL && contextlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		labellen = qsc_stringutils_string_size(label);

		if (labellen > QSC_TLS_LABEL_MAX_SIZE || contextlen > QSC_TLS_CONTEXT_MAX_SIZE)
		{
			status = qsc_tls_status_invalid_length;
		}
		else if ((QSC_TLS_HKDF_LABEL_PREFIX_SIZE + labellen) > 255U || contextlen > 255U || reclen > 65535U)
		{
			status = qsc_tls_status_invalid_length;
		}
		else
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)reclen);

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u8(output, outlen, &offset, (uint8_t)(QSC_TLS_HKDF_LABEL_PREFIX_SIZE + labellen));
			}

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_bytes(output, outlen, &offset, (const uint8_t*)QSC_TLS_HKDF_LABEL_PREFIX, QSC_TLS_HKDF_LABEL_PREFIX_SIZE);
			}

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_bytes(output, outlen, &offset, (const uint8_t*)label, labellen);
			}

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_u8(output, outlen, &offset, (uint8_t)contextlen);
			}

			if (status == qsc_tls_status_success)
			{
				status = qsc_tls_codec_write_bytes(output, outlen, &offset, context, contextlen);
			}
		}
	}

	*msglen = (status == qsc_tls_status_success) ? offset : 0U;

	return status;
}

static qsc_tls_status tls_schedule_expand_dispatch(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* secret, size_t secretlen, const uint8_t* info, size_t infolen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || secret == NULL || info == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		switch (hash)
		{
		case qsc_tls_hash_sha256:
			qsc_hkdf256_expand(output, outlen, secret, secretlen, info, infolen);
			break;
		case qsc_tls_hash_sha384:
			qsc_hkdf384_expand(output, outlen, secret, secretlen, info, infolen);
			break;
		case qsc_tls_hash_sha512:
			qsc_hkdf512_expand(output, outlen, secret, secretlen, info, infolen);
			break;
		default:
			status = qsc_tls_status_not_supported;
			break;
		}
	}

	return status;
}

static qsc_tls_status tls_schedule_extract_dispatch(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || (key == NULL && keylen != 0U) || (salt == NULL && saltlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		switch (hash)
		{
		case qsc_tls_hash_sha256:
			qsc_hkdf256_extract(output, outlen, key, keylen, salt, saltlen);
			break;
		case qsc_tls_hash_sha384:
			qsc_hkdf384_extract(output, outlen, key, keylen, salt, saltlen);
			break;
		case qsc_tls_hash_sha512:
			qsc_hkdf512_extract(output, outlen, key, keylen, salt, saltlen);
			break;
		default:
			status = qsc_tls_status_not_supported;
			break;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_schedule_extract(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen)
{
	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);

	if (output == NULL || (key == NULL && keylen != 0U) || (salt == NULL && saltlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (outlen < hlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		status = tls_schedule_extract_dispatch(hash, output, hlen, key, keylen, salt, saltlen);
	}

	return status;
}

qsc_tls_status qsc_tls_schedule_expand_label(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* secret, size_t secretlen, const char* label, const uint8_t* context, size_t contextlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(label != NULL);

	uint8_t hkdflabel[QSC_TLS_HKDF_LABEL_MAX_WIRE_SIZE] = { 0U };
	size_t hkdflen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hkdflen = 0U;

	if (output == NULL || secret == NULL || label == NULL || (context == NULL && contextlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = tls_schedule_build_label(hkdflabel, sizeof(hkdflabel), &hkdflen, outlen, label, context, contextlen);

		if (status == qsc_tls_status_success)
		{
			status = tls_schedule_expand_dispatch(hash, output, outlen, secret, secretlen, hkdflabel, hkdflen);
		}
	}

	qsc_memutils_secure_erase(hkdflabel, sizeof(hkdflabel));

	return status;
}

qsc_tls_status qsc_tls_schedule_derive_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* secret, size_t secretlen, const char* label, const qsc_tls_transcript_state* transcript)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(label != NULL);
	QSC_ASSERT(transcript != NULL);

	uint8_t digest[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = 0U;

	if (output == NULL || secret == NULL || label == NULL || transcript == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_transcript_snapshot(transcript, digest, sizeof(digest), &hlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_schedule_expand_label(hash, output, outlen, secret, secretlen, label, digest, hlen);
		}
	}

	qsc_memutils_secure_erase(digest, sizeof(digest));

	return status;
}

qsc_tls_status qsc_tls_schedule_derive_secret_from_hash(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* secret, size_t secretlen, const char* label, const uint8_t* transcript_hash, size_t transcript_hashlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(secret != NULL);
	QSC_ASSERT(label != NULL);
	QSC_ASSERT(transcript_hash != NULL);

	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);

	if (output == NULL || secret == NULL || label == NULL || transcript_hash == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (transcript_hashlen != hlen)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_schedule_expand_label(hash, output, outlen, secret, secretlen, label, transcript_hash, transcript_hashlen);
	}

	return status;
}

qsc_tls_status qsc_tls_schedule_derive_handshake_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* sharedsecret, size_t sharedsecretlen, const uint8_t* psk, size_t psklen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(sharedsecret != NULL);

	uint8_t earlysecret[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t emptyhash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t derivedsecret[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);

	if (output == NULL || sharedsecret == NULL || (psk == NULL && psklen != 0U))
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
			status = qsc_tls_schedule_expand_label(hash, derivedsecret, hlen, earlysecret, hlen, QSC_TLS_DERIVED_LABEL, emptyhash, hlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_schedule_extract(hash, output, outlen, sharedsecret, sharedsecretlen, derivedsecret, hlen);
		}
	}

	qsc_memutils_secure_erase(earlysecret, sizeof(earlysecret));
	qsc_memutils_secure_erase(emptyhash, sizeof(emptyhash));
	qsc_memutils_secure_erase(derivedsecret, sizeof(derivedsecret));

	return status;
}

qsc_tls_status qsc_tls_schedule_derive_master_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* handshakesecret, size_t handshakesecretlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(handshakesecret != NULL);

	uint8_t emptyhash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	uint8_t derivedsecret[QSC_TLS_HASH_MAX_SIZE] = { 0U };
	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);

	if (output == NULL || handshakesecret == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (outlen < hlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		status = qsc_tls_schedule_empty_hash(hash, emptyhash, sizeof(emptyhash));

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_schedule_expand_label(hash, derivedsecret, hlen, handshakesecret, handshakesecretlen, QSC_TLS_DERIVED_LABEL, emptyhash, hlen);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_schedule_extract(hash, output, outlen, NULL, 0U, derivedsecret, hlen);
		}
	}

	qsc_memutils_secure_erase(emptyhash, sizeof(emptyhash));
	qsc_memutils_secure_erase(derivedsecret, sizeof(derivedsecret));

	return status;
}

qsc_tls_status qsc_tls_schedule_derive_client_handshake_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* handshakesecret, size_t handshakesecretlen, const uint8_t* transcript_hash, size_t transcript_hashlen)
{
	return qsc_tls_schedule_derive_secret_from_hash(hash, output, outlen, handshakesecret, handshakesecretlen, tls_schedule_label_client_handshake_traffic, transcript_hash, transcript_hashlen);
}

qsc_tls_status qsc_tls_schedule_derive_server_handshake_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* handshakesecret, size_t handshakesecretlen, const uint8_t* transcript_hash, size_t transcript_hashlen)
{
	return qsc_tls_schedule_derive_secret_from_hash(hash, output, outlen, handshakesecret, handshakesecretlen, tls_schedule_label_server_handshake_traffic, transcript_hash, transcript_hashlen);
}

qsc_tls_status qsc_tls_schedule_derive_client_application_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* mastersecret, size_t mastersecretlen, const uint8_t* transcript_hash, size_t transcript_hashlen)
{
	return qsc_tls_schedule_derive_secret_from_hash(hash, output, outlen, mastersecret, mastersecretlen, tls_schedule_label_client_application_traffic, transcript_hash, transcript_hashlen);
}

qsc_tls_status qsc_tls_schedule_derive_server_application_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* mastersecret, size_t mastersecretlen, const uint8_t* transcript_hash, size_t transcript_hashlen)
{
	return qsc_tls_schedule_derive_secret_from_hash(hash, output, outlen, mastersecret, mastersecretlen, tls_schedule_label_server_application_traffic, transcript_hash, transcript_hashlen);
}

qsc_tls_status qsc_tls_schedule_derive_record_key(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* trafficsecret, size_t trafficsecretlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(trafficsecret != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || trafficsecret == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_schedule_expand_label(hash, output, outlen, trafficsecret, trafficsecretlen, QSC_TLS_KEY_LABEL, NULL, 0U);
	}

	return status;
}

qsc_tls_status qsc_tls_schedule_derive_record_iv(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* trafficsecret, size_t trafficsecretlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(trafficsecret != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || trafficsecret == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		status = qsc_tls_schedule_expand_label(hash, output, outlen, trafficsecret, trafficsecretlen, QSC_TLS_IV_LABEL, NULL, 0U);
	}

	return status;
}

qsc_tls_status qsc_tls_schedule_update_application_traffic_secret(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* trafficsecret, size_t trafficsecretlen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(trafficsecret != NULL);

	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);

	if (output == NULL || trafficsecret == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (outlen < hlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		status = qsc_tls_schedule_expand_label(hash, output, hlen, trafficsecret, trafficsecretlen, QSC_TLS_KEY_UPDATE_LABEL, NULL, 0U);
	}

	return status;
}

qsc_tls_status qsc_tls_schedule_finished_key(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen, const uint8_t* basekey, size_t keylen)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(basekey != NULL);

	size_t hlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hlen = qsc_tls_transcript_hash_size(hash);

	if (output == NULL || basekey == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (outlen < hlen)
	{
		status = qsc_tls_status_buffer_too_small;
	}
	else
	{
		status = qsc_tls_schedule_expand_label(hash, output, hlen, basekey, keylen, QSC_TLS_FINISHED_LABEL, NULL, 0U);
	}

	return status;
}

qsc_tls_status qsc_tls_schedule_empty_hash(qsc_tls_hash_algorithm hash, uint8_t* output, size_t outlen)
{
	QSC_ASSERT(output != NULL);

	qsc_tls_status status;

	status = tls_schedule_hash_buffer(hash, output, outlen, NULL, 0U);

	return status;
}
