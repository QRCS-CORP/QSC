#include "tlsrecord.h"
#include "aes.h"
#include "chacha.h"
#include "intutils.h"
#include "memutils.h"
#include "tlsdefs.h"
#include "tlscodec.h"

static bool tls_record_content_type_is_valid(uint8_t type)
{
	bool res;

	res = false;

	switch ((qsc_tls_record_content_type)type)
	{
		case qsc_tls_record_content_change_cipher_spec:
		case qsc_tls_record_content_alert:
		case qsc_tls_record_content_handshake:
		case qsc_tls_record_content_application_data:
		{
			res = true;
			break;
		}
		default:
		{
			break;
		}
	}

	return res;
}

static bool tls_record_inner_content_type_is_valid(qsc_tls_record_content_type type)
{
	bool res;

	res = false;

	switch (type)
	{
		case qsc_tls_record_content_alert:
		case qsc_tls_record_content_handshake:
		case qsc_tls_record_content_application_data:
		{
			res = true;
			break;
		}
		default:
		{
			break;
		}
	}

	return res;
}

static size_t tls_record_find_inner_content_end_constant_time(const uint8_t* inner, size_t innerlen, uint8_t* innertype)
{
	size_t endpos;
	size_t i;
	size_t mask;
	uint8_t seen;
	uint8_t type;

	endpos = 0U;
	i = 0U;
	seen = 0U;
	type = 0U;

	while (i < innerlen)
	{
		uint8_t bte;
		size_t idx;
		uint8_t nz;
		uint8_t select;

		idx = innerlen - 1U - i;
		bte = inner[idx];
		nz = (uint8_t)((bte != 0U) ? 1U : 0U);
		select = (uint8_t)(nz & (uint8_t)(seen ^ 1U));
		mask = (size_t)0U - (size_t)select;
		endpos = (endpos & ~mask) | ((idx + 1U) & mask);
		type = (uint8_t)((type & (uint8_t)(~((uint8_t)mask))) | (bte & (uint8_t)mask));
		seen |= nz;
		++i;
	}

	if (innertype != NULL)
	{
		*innertype = type;
	}

	return endpos;
}

static void tls_record_build_nonce(const qsc_tls_record_state* state, uint8_t* nonce)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(nonce != NULL);

	uint8_t sq[8U] = { 0U };
	size_t i;

	qsc_memutils_copy(nonce, state->iv, QSC_TLS_GCM_NONCE_SIZE);
	qsc_intutils_be64to8(sq, state->sequence);

	for (i = 0U; i < sizeof(sq); ++i)
	{
		nonce[QSC_TLS_GCM_NONCE_SIZE - sizeof(sq) + i] ^= sq[i];
	}
}

static bool tls_record_write_limit_reached(const qsc_tls_record_state* state)
{
	bool res;

	res = true;

	if (state != NULL)
	{
		switch (state->suite)
		{
			case qsc_tls_cipher_suite_tls_aes_128_gcm_sha256:
			case qsc_tls_cipher_suite_tls_aes_256_gcm_sha384:
			{
				res = (state->sequence >= QSC_TLS_AES_GCM_KEY_USAGE_LIMIT);
				break;
			}
			case qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256:
			{
				res = (state->sequence == UINT64_MAX);
				break;
			}
			default:
			{
				break;
			}
		}
	}

	return res;
}

static size_t tls_record_suite_key_size(qsc_tls_cipher_suite suite)
{
	size_t res;

	res = 0U;

	switch (suite)
	{
		case qsc_tls_cipher_suite_tls_aes_128_gcm_sha256:
		{
			res = QSC_TLS_AES128_KEY_SIZE;
			break;
		}
		case qsc_tls_cipher_suite_tls_aes_256_gcm_sha384:
		case qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256:
		{
			res = QSC_TLS_AES256_KEY_SIZE;
			break;
		}
		default:
		{
			break;
		}
	}

	return res;
}

static qsc_tls_status tls_record_build_header(uint8_t* output, size_t outlen, size_t* written, qsc_tls_record_content_type type, size_t payloadlen)
{
	size_t offset;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;

	if (output == NULL || written == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (payloadlen > 65535U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_write_u8(output, outlen, &offset, (uint8_t)type);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, QSC_TLS_PROTOCOL_VERSION_12);
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_u16(output, outlen, &offset, (uint16_t)payloadlen);
		}
	}

	if (written != NULL)
	{
		*written = (status == qsc_tls_status_success) ? offset : 0U;
	}

	return status;
}

void qsc_tls_record_state_initialize(qsc_tls_record_state* state, qsc_tls_cipher_suite suite, const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen)
{
	QSC_ASSERT(state != NULL);

	if (state != NULL)
	{
		qsc_memutils_clear(state, sizeof(qsc_tls_record_state));

		if (key != NULL && iv != NULL && ivlen == QSC_TLS_GCM_NONCE_SIZE)
		{
			size_t ks;

			ks = tls_record_suite_key_size(suite);

			if (ks != 0U && keylen == ks)
			{
				state->suite = suite;
				state->keylen = ks;
				qsc_memutils_copy(state->key, key, ks);
				qsc_memutils_copy(state->iv, iv, QSC_TLS_GCM_NONCE_SIZE);
				state->initialized = true;
			}
		}
	}
}

void qsc_tls_record_state_dispose(qsc_tls_record_state* state)
{
	QSC_ASSERT(state != NULL);

	if (state != NULL)
	{
		qsc_memutils_secure_erase(state, sizeof(qsc_tls_record_state));
	}
}

qsc_tls_status qsc_tls_record_state_install_keys(qsc_tls_record_state* state, qsc_tls_cipher_suite suite, const uint8_t* key, size_t keylen, const uint8_t* iv, size_t ivlen)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(key != NULL);
	QSC_ASSERT(iv != NULL);

	qsc_tls_status status;
	size_t ks;

	status = qsc_tls_status_success;

	if (state == NULL || key == NULL || iv == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (ivlen != QSC_TLS_GCM_NONCE_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		ks = tls_record_suite_key_size(suite);

		if (ks == 0U || keylen != ks)
		{
			status = qsc_tls_status_not_supported;
		}
		else
		{
			/* zeroize any prior key material before reuse. */
			qsc_memutils_secure_erase(state, sizeof(qsc_tls_record_state));
			state->suite = suite;
			state->keylen = ks;
			qsc_memutils_copy(state->key, key, ks);
			qsc_memutils_copy(state->iv, iv, QSC_TLS_GCM_NONCE_SIZE);
			state->sequence = 0U;
			state->initialized = true;
		}
	}

	return status;
}

uint64_t qsc_tls_record_state_get_sequence(const qsc_tls_record_state* state)
{
	uint64_t res;

	if (state == NULL || state->initialized == false)
	{
		res = 0U;
	}
	else
	{
		res = state->sequence;
	}

	return res;
}

qsc_tls_status qsc_tls_record_encode_plaintext(uint8_t* output, size_t outlen, size_t* written, qsc_tls_record_content_type type, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(written != NULL);

	size_t hdrlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hdrlen = 0U;

	if (output == NULL || written == NULL || (input == NULL && inlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_record_content_type_is_valid((uint8_t)type) == false)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (inlen > QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (type == qsc_tls_record_content_handshake && inlen == 0U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (type == qsc_tls_record_content_alert && inlen != QSC_TLS_ALERT_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (type == qsc_tls_record_content_change_cipher_spec && (inlen != 1U || input == NULL || input[0U] != 0x01U))
	{
		status = qsc_tls_status_invalid_message;
	}
	else
	{
		status = tls_record_build_header(output, outlen, &hdrlen, type, inlen);

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_write_bytes(output, outlen, &hdrlen, input, inlen);
		}
	}

	if (written != NULL)
	{
		*written = (status == qsc_tls_status_success) ? hdrlen : 0U;
	}

	return status;
}

qsc_tls_status qsc_tls_record_decode_plaintext(const uint8_t* input, size_t inlen, qsc_tls_record_content_type* type, const uint8_t** payload, size_t* payloadlen)
{
	QSC_ASSERT(input != NULL);
	QSC_ASSERT(type != NULL);
	QSC_ASSERT(payload != NULL);

	size_t offset;
	uint16_t version;
	uint16_t length;
	uint8_t ctype;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	offset = 0U;
	ctype = 0U;
	version = 0U;
	length = 0U;

	if (type != NULL)
	{
		*type = qsc_tls_record_content_invalid;
	}

	if (payload != NULL)
	{
		*payload = NULL;
	}

	if (payloadlen != NULL)
	{
		*payloadlen = 0U;
	}

	if (input == NULL || type == NULL || payload == NULL || payloadlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (inlen < QSC_TLS_RECORD_HEADER_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		status = qsc_tls_codec_read_u8(input, inlen, &offset, &ctype);

		if (status == qsc_tls_status_success)
		{
			/* RFC 9846 Section 5.1: read the deprecated legacy version field; plaintext
			 * processing ignores its value. Protected records authenticate these bytes as AAD. */
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &version);
			(void)version;
		}

		if (status == qsc_tls_status_success)
		{
			status = qsc_tls_codec_read_u16(input, inlen, &offset, &length);
		}

		if (status == qsc_tls_status_success)
		{
			if (tls_record_content_type_is_valid(ctype) == false)
			{
				status = qsc_tls_status_invalid_input;
			}
			else if ((ctype == (uint8_t)qsc_tls_record_content_application_data &&
				length > QSC_TLS_RECORD_MAX_CIPHERTEXT_SIZE) ||
				(ctype != (uint8_t)qsc_tls_record_content_application_data &&
				length > QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE))
			{
				status = qsc_tls_status_record_overflow;
			}
			/* RFC 9846 Sections 5.1 and E.5: TLSPlaintext.legacy_record_version is
			 * deprecated and ignored on receipt. TLSCiphertext.legacy_record_version
			 * is authenticated as part of the AEAD additional data by qsc_tls_record_decrypt(). */
			else if ((inlen - offset) != length)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				*type = (qsc_tls_record_content_type)ctype;
				*payload = input + offset;
				*payloadlen = length;
			}
		}
	}

	return status;
}

qsc_tls_status qsc_tls_record_try_get_span_length(const uint8_t* input, size_t inlen, size_t* recordlen, bool* complete)
{
	QSC_ASSERT(recordlen != NULL);
	QSC_ASSERT(complete != NULL);

	size_t needed;
	qsc_tls_status status;
	uint16_t length;

	status = qsc_tls_status_success;
	needed = 0U;
	length = 0U;

	if (recordlen == NULL || complete == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		*recordlen = 0U;
		*complete = false;

		if (input == NULL)
		{
			status = qsc_tls_status_invalid_input;
		}
		else if (inlen < QSC_TLS_RECORD_HEADER_SIZE)
		{
			status = qsc_tls_status_success;
		}
		else
		{
			length = qsc_intutils_be8to16(input + 3U);
			needed = QSC_TLS_RECORD_HEADER_SIZE + (size_t)length;

			if (length > QSC_TLS_RECORD_MAX_CIPHERTEXT_SIZE)
			{
				status = qsc_tls_status_record_overflow;
			}
			else
			{
				*recordlen = needed;
				*complete = (inlen >= needed);
			}
		}
	}

	return status;
}

qsc_tls_status qsc_tls_record_encrypt(qsc_tls_record_state* state, uint8_t* output, size_t outlen, size_t* written, qsc_tls_record_content_type inner_type, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);

	qsc_aes_keyparams kp = { 0 };
	qsc_aes_gcm128_state gcm128 = { 0 };
	qsc_aes_gcm256_state gcm256 = { 0 };
	qsc_chacha_keyparams ckp = { 0 };
	qsc_chacha_poly1305_state cpoly = { 0 };
	uint8_t aad[QSC_TLS_RECORD_HEADER_SIZE] = { 0U };
	uint8_t nonce[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
	uint8_t* inner;
	size_t hdrlen;
	size_t innerlen;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hdrlen = 0U;
	innerlen = 0U;
	inner = NULL;

	if (written != NULL)
	{
		*written = 0U;
	}

	if (state == NULL || output == NULL || written == NULL || (input == NULL && inlen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (tls_record_inner_content_type_is_valid(inner_type) == false)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (inner_type == qsc_tls_record_content_handshake && inlen == 0U)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (inner_type == qsc_tls_record_content_alert && inlen != QSC_TLS_ALERT_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else if (state->initialized == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else if (inlen > QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE)
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		inner = (uint8_t*)qsc_memutils_malloc(QSC_TLS_RECORD_MAX_INNER_SIZE);

		if (inner == NULL)
		{
			status = qsc_tls_status_invalid_state;
		}
		else
		{
			qsc_memutils_clear(inner, QSC_TLS_RECORD_MAX_INNER_SIZE);

			if ((inlen + QSC_TLS_INNER_CONTENT_TYPE_SIZE) > QSC_TLS_RECORD_MAX_INNER_SIZE)
			{
				status = qsc_tls_status_invalid_length;
			}
			else
			{
				qsc_memutils_copy(inner, input, inlen);
				inner[inlen] = (uint8_t)inner_type;
				innerlen = inlen + QSC_TLS_INNER_CONTENT_TYPE_SIZE;

				status = tls_record_build_header(aad, sizeof(aad), &hdrlen, qsc_tls_record_content_application_data, innerlen + QSC_TLS_GCM_TAG_SIZE);

				if (status == qsc_tls_status_success)
				{
					status = tls_record_build_header(output, outlen, &hdrlen, qsc_tls_record_content_application_data, innerlen + QSC_TLS_GCM_TAG_SIZE);
				}

				if (status == qsc_tls_status_success)
				{
					/* Guard the full output range before any write: header + ciphertext + tag */
					if (outlen < QSC_TLS_RECORD_HEADER_SIZE + innerlen + QSC_TLS_GCM_TAG_SIZE)
					{
						status = qsc_tls_status_buffer_too_small;
					}
				}

				if (status == qsc_tls_status_success)
				{
					/* RFC 9846 Section 5.5: a sender MUST close or update keys before
					 * exceeding the AEAD usage limit. Count every AES-GCM record as
					 * full size, which is conservative for shorter records. */
					if (tls_record_write_limit_reached(state) == true)
					{
						qsc_tls_record_state_dispose(state);
						status = qsc_tls_status_authentication_failure;
					}
				}

				if (status == qsc_tls_status_success)
				{
					tls_record_build_nonce(state, nonce);

					switch (state->suite)
					{
						case qsc_tls_cipher_suite_tls_aes_128_gcm_sha256:
						{
							kp.key = state->key;
							kp.keylen = QSC_TLS_AES128_KEY_SIZE;
							kp.nonce = nonce;
							kp.noncelen = QSC_TLS_GCM_NONCE_SIZE;
							kp.info = NULL;
							kp.infolen = 0U;
							qsc_aes_gcm128_initialize(&gcm128, &kp, true);
							qsc_aes_gcm128_set_associated(&gcm128, aad, sizeof(aad));
							qsc_aes_gcm128_encrypt(&gcm128, output + QSC_TLS_RECORD_HEADER_SIZE, inner, innerlen);
							qsc_aes_gcm128_dispose(&gcm128);

							break;
						}
						case qsc_tls_cipher_suite_tls_aes_256_gcm_sha384:
						{
							kp.key = state->key;
							kp.keylen = QSC_TLS_AES256_KEY_SIZE;
							kp.nonce = nonce;
							kp.noncelen = QSC_TLS_GCM_NONCE_SIZE;
							kp.info = NULL;
							kp.infolen = 0U;
							qsc_aes_gcm256_initialize(&gcm256, &kp, true);
							qsc_aes_gcm256_set_associated(&gcm256, aad, sizeof(aad));
							qsc_aes_gcm256_encrypt(&gcm256, output + QSC_TLS_RECORD_HEADER_SIZE, inner, innerlen);
							qsc_aes_gcm256_dispose(&gcm256);

							break;
						}
						case qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256:
						{
							ckp.key = state->key;
							ckp.keylen = QSC_CHACHA_KEY256_SIZE;
							ckp.nonce = nonce;
							qsc_chacha_poly1305_initialize(&cpoly, &ckp);
							qsc_chacha_poly1305_set_associated(&cpoly, aad, sizeof(aad));
							qsc_chacha_poly1305_encrypt(&cpoly, output + QSC_TLS_RECORD_HEADER_SIZE, inner, innerlen);
							qsc_chacha_poly1305_dispose(&cpoly);

							break;
						}
						default:
						{
							status = qsc_tls_status_not_supported;
							break;
						}
					}

					if (status == qsc_tls_status_success)
					{
						state->sequence += 1U;
					}
				}
			}

			qsc_memutils_secure_erase(inner, QSC_TLS_RECORD_MAX_INNER_SIZE);
			qsc_memutils_alloc_free(inner);
			inner = NULL;
		}
	}

	if (written != NULL)
	{
		*written = (status == qsc_tls_status_success) ? (QSC_TLS_RECORD_HEADER_SIZE + innerlen + QSC_TLS_GCM_TAG_SIZE) : 0U;
	}

	qsc_memutils_secure_erase(aad, sizeof(aad));
	qsc_memutils_secure_erase(nonce, sizeof(nonce));
	qsc_memutils_secure_erase(&kp, sizeof(kp));
	qsc_memutils_secure_erase(&gcm128, sizeof(gcm128));
	qsc_memutils_secure_erase(&gcm256, sizeof(gcm256));
	qsc_memutils_secure_erase(&cpoly, sizeof(cpoly));
	qsc_memutils_secure_erase(&ckp, sizeof(ckp));

	return status;
}

qsc_tls_status qsc_tls_record_decrypt(qsc_tls_record_state* state, uint8_t* output, size_t outlen, size_t* written, qsc_tls_record_content_type* inner_type, const uint8_t* input, size_t inlen)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(written != NULL);

	qsc_aes_keyparams kp = { 0 };
	qsc_aes_gcm128_state gcm128 = { 0 };
	qsc_aes_gcm256_state gcm256 = { 0 };
	qsc_chacha_keyparams ckp = { 0 };
	qsc_chacha_poly1305_state cpoly = { 0 };
	uint8_t aad[QSC_TLS_RECORD_HEADER_SIZE] = { 0U };
	uint8_t nonce[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
	/* L3 fix: heap-allocate; see encrypt counterpart for full rationale. */
	uint8_t* inner;
	const uint8_t* payload;
	size_t payloadlen;
	size_t endpos;
	qsc_tls_record_content_type outer_type;
	bool decok;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	outer_type = qsc_tls_record_content_invalid;
	payload = NULL;
	payloadlen = 0U;
	endpos = 0U;
	decok = false;
	inner = NULL;

	if (written != NULL)
	{
		*written = 0U;
	}

	if (inner_type != NULL)
	{
		*inner_type = qsc_tls_record_content_invalid;
	}

	if (state == NULL || output == NULL || written == NULL || inner_type == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (state->initialized == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else if (inlen < (QSC_TLS_RECORD_HEADER_SIZE + QSC_TLS_GCM_TAG_SIZE + QSC_TLS_INNER_CONTENT_TYPE_SIZE))
	{
		status = qsc_tls_status_invalid_length;
	}
	else
	{
		inner = (uint8_t*)qsc_memutils_malloc(QSC_TLS_RECORD_MAX_INNER_SIZE);

		if (inner == NULL)
		{
			status = qsc_tls_status_invalid_state;
		}
		else
		{
			qsc_memutils_clear(inner, QSC_TLS_RECORD_MAX_INNER_SIZE);

			status = qsc_tls_record_decode_plaintext(input, inlen, &outer_type, &payload, &payloadlen);

			if (status == qsc_tls_status_success)
			{
				if (outer_type != qsc_tls_record_content_application_data)
				{
					status = qsc_tls_status_invalid_input;
				}
				else if (payloadlen > QSC_TLS_RECORD_MAX_CIPHERTEXT_SIZE)
				{
					status = qsc_tls_status_record_overflow;
				}
				else
				{
					if (state->sequence == UINT64_MAX)
					{
						qsc_tls_record_state_dispose(state);
						status = qsc_tls_status_authentication_failure;
					}
					else
					{
					qsc_memutils_copy(aad, input, QSC_TLS_RECORD_HEADER_SIZE);
					tls_record_build_nonce(state, nonce);

					switch (state->suite)
					{
						case qsc_tls_cipher_suite_tls_aes_128_gcm_sha256:
						{
							kp.key = state->key;
							kp.keylen = QSC_TLS_AES128_KEY_SIZE;
							kp.nonce = nonce;
							kp.noncelen = QSC_TLS_GCM_NONCE_SIZE;
							kp.info = NULL;
							kp.infolen = 0U;
							qsc_aes_gcm128_initialize(&gcm128, &kp, false);
							qsc_aes_gcm128_set_associated(&gcm128, aad, sizeof(aad));
							decok = qsc_aes_gcm128_decrypt(&gcm128, inner, payload, payloadlen);
							qsc_aes_gcm128_dispose(&gcm128);

							break;
						}
						case qsc_tls_cipher_suite_tls_aes_256_gcm_sha384:
						{
							kp.key = state->key;
							kp.keylen = QSC_TLS_AES256_KEY_SIZE;
							kp.nonce = nonce;
							kp.noncelen = QSC_TLS_GCM_NONCE_SIZE;
							kp.info = NULL;
							kp.infolen = 0U;
							qsc_aes_gcm256_initialize(&gcm256, &kp, false);
							qsc_aes_gcm256_set_associated(&gcm256, aad, sizeof(aad));
							decok = qsc_aes_gcm256_decrypt(&gcm256, inner, payload, payloadlen);
							qsc_aes_gcm256_dispose(&gcm256);

							break;
						}
						case qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256:
						{
							ckp.key = state->key;
							ckp.keylen = QSC_CHACHA_KEY256_SIZE;
							ckp.nonce = nonce;
							qsc_chacha_poly1305_initialize(&cpoly, &ckp);
							qsc_chacha_poly1305_set_associated(&cpoly, aad, sizeof(aad));
							decok = qsc_chacha_poly1305_decrypt(&cpoly, inner, payload, payloadlen);
							qsc_chacha_poly1305_dispose(&cpoly);

							break;
						}
						default:
						{
							status = qsc_tls_status_not_supported;
							decok = false;

							break;
						}
					}

					if (decok == false)
					{
						if (status == qsc_tls_status_success)
						{
							status = qsc_tls_status_authentication_failure;
						}
					}
					else
					{
						uint8_t contentbyte;

						contentbyte = 0U;
						endpos = tls_record_find_inner_content_end_constant_time(inner, payloadlen - QSC_TLS_GCM_TAG_SIZE, &contentbyte);

						if (endpos == 0U)
						{
							status = qsc_tls_status_invalid_length;
						}
						else
						{
							/* Preserve the received ContentType for the protocol layer.
							 * Sending remains restricted to TLS 1.3 legal protected types,
							 * while a received protected CCS or unknown type must be mapped
							 * to unexpected_message by the connection state machine. */
							*inner_type = (qsc_tls_record_content_type)contentbyte;
							endpos -= 1U;

							if (endpos > QSC_TLS_RECORD_MAX_PLAINTEXT_SIZE)
							{
								status = qsc_tls_status_record_overflow;
							}
							else if (endpos > outlen)
							{
								status = qsc_tls_status_buffer_too_small;
							}
							else
							{
								qsc_memutils_copy(output, inner, endpos);
								*written = endpos;
								state->sequence += 1U;
							}
						}
					}
				}
				} /* end sequence-check else */
			}

			qsc_memutils_secure_erase(inner, QSC_TLS_RECORD_MAX_INNER_SIZE);
			qsc_memutils_alloc_free(inner);
			inner = NULL;
		}
	}

	if (status != qsc_tls_status_success && written != NULL)
	{
		*written = 0U;
	}

	qsc_memutils_secure_erase(aad, sizeof(aad));
	qsc_memutils_secure_erase(nonce, sizeof(nonce));
	qsc_memutils_secure_erase(&kp, sizeof(kp));
	qsc_memutils_secure_erase(&gcm128, sizeof(gcm128));
	qsc_memutils_secure_erase(&gcm256, sizeof(gcm256));
	qsc_memutils_secure_erase(&cpoly, sizeof(cpoly));
	qsc_memutils_secure_erase(&ckp, sizeof(ckp));

	return status;
}
