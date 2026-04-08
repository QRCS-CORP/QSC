#include "tls_stage5_record_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlsdefs.h"
#include "tlserrors.h"
#include "tlsrecord.h"

static void tls_stage5_load_key_iv(uint8_t* key, size_t keylen, uint8_t* iv, size_t ivlen)
{
	size_t i;

	QSC_ASSERT(key != NULL);
	QSC_ASSERT(iv != NULL);

	if (key != NULL && iv != NULL)
	{
		for (i = 0U; i < keylen; ++i)
		{
			key[i] = (uint8_t)(0x10U + (uint8_t)i);
		}

		for (i = 0U; i < ivlen; ++i)
		{
			iv[i] = (uint8_t)(0xA0U + (uint8_t)i);
		}
	}
}

bool tls_stage5_record_state_lifecycle(void)
{
	qsc_tls_record_state state = { 0 };
	uint8_t key[QSC_TLS_AES256_KEY_SIZE] = { 0U };
	uint8_t iv[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
	bool res;

	tls_stage5_load_key_iv(key, sizeof(key), iv, sizeof(iv));
	res = true;

	qsc_tls_record_state_initialize(&state, key, sizeof(key), iv, sizeof(iv));

	if (state.initialized == false)
	{
		res = false;
	}

	if (res == true)
	{
		res = (state.sequence == 0U);
	}

	if (res == true)
	{
		res = (qsc_memutils_are_equal(state.key, key, sizeof(key)) == true);
	}

	if (res == true)
	{
		res = (qsc_memutils_are_equal(state.iv, iv, sizeof(iv)) == true);
	}

	if (res == true)
	{
		qsc_tls_record_state_dispose(&state);
		res = (state.initialized == false && state.sequence == 0U && qsc_memutils_are_equal(state.key, key, sizeof(key)) == false);
	}

	if (res == true)
	{
		qsc_memutils_clear(&state, sizeof(qsc_tls_record_state));
		qsc_tls_record_state_initialize(&state, key, sizeof(key) - 1U, iv, sizeof(iv));
		res = (state.initialized == false);
	}

	if (res == true)
	{
		qsc_memutils_clear(&state, sizeof(qsc_tls_record_state));
		qsc_tls_record_state_initialize(&state, key, sizeof(key), iv, sizeof(iv) - 1U);
		res = (state.initialized == false);
	}

	return res;
}

bool tls_stage5_record_plaintext_roundtrip(void)
{
	static const uint8_t msg[] =
	{
		0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU,
		0x10U, 0x32U, 0x54U, 0x76U, 0x98U, 0xBAU, 0xDCU, 0xFEU,
		0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU
	};

	uint8_t record[QSC_TLS_RECORD_HEADER_SIZE + sizeof(msg)] = { 0U };
	const uint8_t* payload;
	qsc_tls_record_content_type type;
	size_t payloadlen;
	size_t written;
	qsc_tls_status status;
	bool res;

	qsc_memutils_clear(record, sizeof(record));
	payload = NULL;
	type = qsc_tls_record_content_invalid;
	payloadlen = 0U;
	written = 0U;
	status = qsc_tls_record_encode_plaintext(record, sizeof(record), &written, qsc_tls_record_content_handshake, msg, sizeof(msg));
	res = (status == qsc_tls_status_success);

	if (res == true)
	{
		res = (written == (QSC_TLS_RECORD_HEADER_SIZE + sizeof(msg)));
	}

	if (res == true)
	{
		res = (record[0] == (uint8_t)qsc_tls_record_content_handshake);
	}

	if (res == true)
	{
		res = (record[1] == 0x03U && record[2] == 0x03U);
	}

	if (res == true)
	{
		status = qsc_tls_record_decode_plaintext(record, written, &type, &payload, &payloadlen);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (type == qsc_tls_record_content_handshake && payloadlen == sizeof(msg));
	}

	if (res == true)
	{
		res = (qsc_memutils_are_equal(payload, msg, sizeof(msg)) == true);
	}

	return res;
}

bool tls_stage5_record_protected_roundtrip(void)
{
	static const uint8_t msg[] =
	{
		0xDEU, 0xADU, 0xBEU, 0xEFU, 0x00U, 0x11U, 0x22U, 0x33U,
		0x44U, 0x55U, 0x66U, 0x77U, 0x88U, 0x99U, 0xAAU, 0xBBU,
		0xCCU, 0xDDU, 0xEEU, 0xFFU
	};

	qsc_tls_record_state sender = { 0 };
	qsc_tls_record_state receiver = { 0 };
	uint8_t key[QSC_TLS_AES256_KEY_SIZE] = { 0U };
	uint8_t iv[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
	uint8_t record[QSC_TLS_RECORD_HEADER_SIZE + sizeof(msg) + QSC_TLS_INNER_CONTENT_TYPE_SIZE + QSC_TLS_GCM_TAG_SIZE];
	uint8_t output[sizeof(msg)] = { 0U };
	qsc_tls_record_content_type inner_type;
	size_t written;
	size_t outlen;
	qsc_tls_status status;
	bool res;

	tls_stage5_load_key_iv(key, sizeof(key), iv, sizeof(iv));
	qsc_tls_record_state_initialize(&sender, key, sizeof(key), iv, sizeof(iv));
	qsc_tls_record_state_initialize(&receiver, key, sizeof(key), iv, sizeof(iv));
	inner_type = qsc_tls_record_content_invalid;
	written = 0U;
	outlen = 0U;
	status = qsc_tls_record_encrypt(&sender, record, sizeof(record), &written, qsc_tls_record_content_handshake, msg, sizeof(msg));
	res = (status == qsc_tls_status_success);

	if (res == true)
	{
		res = (record[0] == (uint8_t)qsc_tls_record_content_application_data);
	}

	if (res == true)
	{
		res = (sender.sequence == 1U && written == sizeof(record));
	}

	if (res == true)
	{
		status = qsc_tls_record_decrypt(&receiver, output, sizeof(output), &outlen, &inner_type, record, written);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (receiver.sequence == 1U && inner_type == qsc_tls_record_content_handshake);
	}

	if (res == true)
	{
		res = (outlen == sizeof(msg) && qsc_memutils_are_equal(output, msg, sizeof(msg)) == true);
	}

	qsc_tls_record_state_dispose(&sender);
	qsc_tls_record_state_dispose(&receiver);

	return res;
}

bool tls_stage5_record_sequence_nonces(void)
{
	static const uint8_t msg[] =
	{
		0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U,
		0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U
	};

	qsc_tls_record_state sender = { 0 };
	qsc_tls_record_state receiver = { 0 };
	uint8_t key[QSC_TLS_AES256_KEY_SIZE] = { 0U };
	uint8_t iv[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
	uint8_t recorda[QSC_TLS_RECORD_HEADER_SIZE + sizeof(msg) + QSC_TLS_INNER_CONTENT_TYPE_SIZE + QSC_TLS_GCM_TAG_SIZE] = { 0U };
	uint8_t recordb[QSC_TLS_RECORD_HEADER_SIZE + sizeof(msg) + QSC_TLS_INNER_CONTENT_TYPE_SIZE + QSC_TLS_GCM_TAG_SIZE] = { 0U };
	uint8_t output[sizeof(msg)] = { 0U };
	qsc_tls_record_content_type inner_type;
	size_t writtena;
	size_t writtenb;
	size_t outlen;
	qsc_tls_status status;
	bool res;

	tls_stage5_load_key_iv(key, sizeof(key), iv, sizeof(iv));
	qsc_tls_record_state_initialize(&sender, key, sizeof(key), iv, sizeof(iv));
	qsc_tls_record_state_initialize(&receiver, key, sizeof(key), iv, sizeof(iv));
	inner_type = qsc_tls_record_content_invalid;
	writtena = 0U;
	writtenb = 0U;
	outlen = 0U;

	status = qsc_tls_record_encrypt(&sender, recorda, sizeof(recorda), &writtena, qsc_tls_record_content_application_data, msg, sizeof(msg));
	res = (status == qsc_tls_status_success);

	if (res == true)
	{
		status = qsc_tls_record_encrypt(&sender, recordb, sizeof(recordb), &writtenb, qsc_tls_record_content_application_data, msg, sizeof(msg));
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (writtena == writtenb && qsc_memutils_are_equal(recorda, recordb, writtena) == false);
	}

	if (res == true)
	{
		status = qsc_tls_record_decrypt(&receiver, output, sizeof(output), &outlen, &inner_type, recorda, writtena);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (inner_type == qsc_tls_record_content_application_data && outlen == sizeof(msg));
	}

	if (res == true)
	{
		status = qsc_tls_record_decrypt(&receiver, output, sizeof(output), &outlen, &inner_type, recordb, writtenb);
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		res = (receiver.sequence == 2U && qsc_memutils_are_equal(output, msg, sizeof(msg)) == true);
	}

	qsc_tls_record_state_dispose(&sender);
	qsc_tls_record_state_dispose(&receiver);

	return res;
}

bool tls_stage5_record_negative_paths(void)
{
	static const uint8_t msg[] =
	{
		0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U
	};

	qsc_tls_record_state sender = { 0 };
	qsc_tls_record_state receiver = { 0 };
	uint8_t key[QSC_TLS_AES256_KEY_SIZE] = { 0U };
	uint8_t iv[QSC_TLS_GCM_NONCE_SIZE] = { 0U };
	uint8_t record[QSC_TLS_RECORD_HEADER_SIZE + sizeof(msg) + QSC_TLS_INNER_CONTENT_TYPE_SIZE + QSC_TLS_GCM_TAG_SIZE] = { 0U };
	uint8_t output[sizeof(msg)] = { 0U };
	qsc_tls_record_content_type type;
	const uint8_t* payload;
	size_t payloadlen;
	size_t written;
	size_t outlen;
	qsc_tls_status status;
	bool res;

	tls_stage5_load_key_iv(key, sizeof(key), iv, sizeof(iv));
	qsc_tls_record_state_initialize(&sender, key, sizeof(key), iv, sizeof(iv));
	qsc_tls_record_state_initialize(&receiver, key, sizeof(key), iv, sizeof(iv));
	payload = NULL;
	type = qsc_tls_record_content_invalid;
	payloadlen = 0U;
	written = 0U;
	outlen = 0U;
	res = true;

	status = qsc_tls_record_encode_plaintext(NULL, sizeof(record), &written, qsc_tls_record_content_handshake, msg, sizeof(msg));

	if (status != qsc_tls_status_invalid_input)
	{
		res = false;
	}

	if (res == true)
	{
		status = qsc_tls_record_decode_plaintext(record, QSC_TLS_RECORD_HEADER_SIZE - 1U, &type, &payload, &payloadlen);
		res = (status == qsc_tls_status_invalid_length);
	}

	if (res == true)
	{
		status = qsc_tls_record_encode_plaintext(record, sizeof(record), &written, qsc_tls_record_content_handshake, msg, sizeof(msg));
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		record[1U] = 0x03U;
		record[2U] = 0x04U;
		status = qsc_tls_record_decode_plaintext(record, written, &type, &payload, &payloadlen);
		res = (status == qsc_tls_status_invalid_input);
		record[1U] = 0x03U;
		record[2U] = 0x03U;
	}

	if (res == true)
	{
		record[3U] = 0x00U;
		record[4U] = 0x01U;
		status = qsc_tls_record_decode_plaintext(record, written, &type, &payload, &payloadlen);
		res = (status == qsc_tls_status_invalid_length);
		record[3U] = 0x00U;
		record[4U] = (uint8_t)sizeof(msg);
	}

	if (res == true)
	{
		qsc_tls_record_state_dispose(&sender);
		status = qsc_tls_record_encrypt(&sender, record, sizeof(record), &written, qsc_tls_record_content_handshake, msg, sizeof(msg));
		res = (status == qsc_tls_status_invalid_state);
		qsc_tls_record_state_initialize(&sender, key, sizeof(key), iv, sizeof(iv));
	}

	if (res == true)
	{
		status = qsc_tls_record_encrypt(&sender, record, sizeof(record), &written, qsc_tls_record_content_alert, msg, sizeof(msg));
		res = (status == qsc_tls_status_success);
	}

	if (res == true)
	{
		record[0U] = (uint8_t)qsc_tls_record_content_handshake;
		status = qsc_tls_record_decrypt(&receiver, output, sizeof(output), &outlen, &type, record, written);
		res = (status == qsc_tls_status_invalid_input);
		record[0U] = (uint8_t)qsc_tls_record_content_application_data;
	}

	if (res == true)
	{
		record[QSC_TLS_RECORD_HEADER_SIZE] ^= 0x01U;
		status = qsc_tls_record_decrypt(&receiver, output, sizeof(output), &outlen, &type, record, written);
		res = (status == qsc_tls_status_authentication_failure);
		record[QSC_TLS_RECORD_HEADER_SIZE] ^= 0x01U;
	}

	if (res == true)
	{
		status = qsc_tls_record_decrypt(&receiver, output, sizeof(output) - 1U, &outlen, &type, record, written);
		res = (status == qsc_tls_status_buffer_too_small);
	}

	qsc_tls_record_state_dispose(&sender);
	qsc_tls_record_state_dispose(&receiver);

	return res;
}

bool qsctest_tls_stage5_tests(void)
{
	bool res;

	res = true;

	if (tls_stage5_record_state_lifecycle() == true)
	{
		qsctest_print_safe("[PASS] TLS Stage 5 record state lifecycle test has succeeded.\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] TLS Stage 5 record state lifecycle has failed.\n");
		res = false;
	}

	if (tls_stage5_record_plaintext_roundtrip() == true)
	{
		qsctest_print_safe("[PASS] TLS Stage 5 record plaintext roundtrip test has succeeded.\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] TLS Stage 5 record plaintext roundtrip test has failed.\n");
		res = false;
	}

	if (tls_stage5_record_protected_roundtrip() == true)
	{
		qsctest_print_safe("[PASS] TLS Stage 5 record protected roundtrip test has succeeded.\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] TLS Stage 5 record protected roundtrip test has failed.\n");
		res = false;
	}

	if (tls_stage5_record_sequence_nonces() == true)
	{
		qsctest_print_safe("[PASS] TLS Stage 5 record sequence nonces test has succeeded.\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] TLS Stage 5 record sequence nonces test has failed.\n");
		res = false;
	}

	if (tls_stage5_record_negative_paths() == true)
	{
		qsctest_print_safe("[PASS] TLS Stage 5 record negative paths test has succeeded.\n");
	}
	else
	{
		qsctest_print_safe("[FAIL] TLS Stage 5 record negative paths test has failed.\n");
		res = false;
	}

	return res;
}
