#include "tlstranscript.h"
#include "memutils.h"

static void tls_transcript_snapshot_sha256(const qsc_tls_transcript_state* state, uint8_t* output)
{
	qsc_sha256_state ctx = { 0 };

	ctx = state->ctx.sha256;
	qsc_sha256_finalize(&ctx, output);
}

static void tls_transcript_snapshot_sha384(const qsc_tls_transcript_state* state, uint8_t* output)
{
	qsc_sha384_state ctx = { 0 };

	ctx = state->ctx.sha384;
	qsc_sha384_finalize(&ctx, output);
}

static void tls_transcript_snapshot_sha512(const qsc_tls_transcript_state* state, uint8_t* output)
{
	qsc_sha512_state ctx = { 0 };

	ctx = state->ctx.sha512;
	qsc_sha512_finalize(&ctx, output);
}

void qsc_tls_transcript_dispose(qsc_tls_transcript_state* state)
{
	QSC_ASSERT(state != NULL);

	if (state != NULL)
	{
		qsc_memutils_secure_erase(state, sizeof(qsc_tls_transcript_state));
	}
}

qsc_tls_status qsc_tls_transcript_initialize(qsc_tls_transcript_state* state, qsc_tls_hash_algorithm hash)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (state == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else
	{
		qsc_memutils_clear(state, sizeof(qsc_tls_transcript_state));

		switch (hash)
		{
		case qsc_tls_hash_sha256:
			qsc_sha256_initialize(&state->ctx.sha256);
			state->hash = hash;
			state->initialized = true;
			break;
		case qsc_tls_hash_sha384:
			qsc_sha384_initialize(&state->ctx.sha384);
			state->hash = hash;
			state->initialized = true;
			break;
		case qsc_tls_hash_sha512:
			qsc_sha512_initialize(&state->ctx.sha512);
			state->hash = hash;
			state->initialized = true;
			break;
		default:
			status = qsc_tls_status_not_supported;
			break;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_transcript_reset(qsc_tls_transcript_state* state)
{
	QSC_ASSERT(state != NULL);

	qsc_tls_hash_algorithm hash;
	qsc_tls_status status;

	status = qsc_tls_status_success;
	hash = qsc_tls_hash_none;

	if (state == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (state->initialized == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		hash = state->hash;
		status = qsc_tls_transcript_initialize(state, hash);
	}

	return status;
}

qsc_tls_status qsc_tls_transcript_append(qsc_tls_transcript_state* state, const uint8_t* message, size_t msglen)
{
	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (state == NULL || (message == NULL) && (msglen != 0U))
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (state->initialized == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else if (msglen != 0U)
	{
		switch (state->hash)
		{
		case qsc_tls_hash_sha256:
			qsc_sha256_update(&state->ctx.sha256, message, msglen);
			break;
		case qsc_tls_hash_sha384:
			qsc_sha384_update(&state->ctx.sha384, message, msglen);
			break;
		case qsc_tls_hash_sha512:
			qsc_sha512_update(&state->ctx.sha512, message, msglen);
			break;
		default:
			status = qsc_tls_status_not_supported;
			break;
		}
	}

	return status;
}

qsc_tls_status qsc_tls_transcript_snapshot(const qsc_tls_transcript_state* state, uint8_t* output, size_t outlen, size_t* hashlen)
{
	QSC_ASSERT(state != NULL);
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(hashlen != NULL);

	size_t hlen;
	qsc_tls_status status;

	hlen = 0U;
	status = qsc_tls_status_success;

	if (hashlen != NULL)
	{
		*hashlen = 0U;
	}

	if (state == NULL || output == NULL || hashlen == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (state->initialized == false)
	{
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		hlen = qsc_tls_transcript_hash_size(state->hash);

		if (outlen < hlen)
		{
			status = qsc_tls_status_buffer_too_small;
		}
		else
		{
			switch (state->hash)
			{
			case qsc_tls_hash_sha256:
				tls_transcript_snapshot_sha256(state, output);
				break;
			case qsc_tls_hash_sha384:
				tls_transcript_snapshot_sha384(state, output);
				break;
			case qsc_tls_hash_sha512:
				tls_transcript_snapshot_sha512(state, output);
				break;
			default:
				status = qsc_tls_status_not_supported;
				break;
			}
		}
	}

	if ((status == qsc_tls_status_success) && (hashlen != NULL))
	{
		*hashlen = hlen;
	}

	return status;
}

qsc_tls_status qsc_tls_transcript_clone(qsc_tls_transcript_state* output, const qsc_tls_transcript_state* input)
{
	QSC_ASSERT(output != NULL);
	QSC_ASSERT(input != NULL);

	qsc_tls_status status;

	status = qsc_tls_status_success;

	if (output == NULL || input == NULL)
	{
		status = qsc_tls_status_invalid_input;
	}
	else if (input->initialized == false)
	{
		qsc_memutils_clear(output, sizeof(qsc_tls_transcript_state));
		status = qsc_tls_status_invalid_state;
	}
	else
	{
		*output = *input;
	}

	return status;
}

size_t qsc_tls_transcript_hash_size(qsc_tls_hash_algorithm hash)
{
	size_t hlen;

	hlen = 0U;

	switch (hash)
	{
	case qsc_tls_hash_sha256:
		hlen = QSC_SHA2_256_HASH_SIZE;
		break;
	case qsc_tls_hash_sha384:
		hlen = QSC_SHA2_384_HASH_SIZE;
		break;
	case qsc_tls_hash_sha512:
		hlen = QSC_SHA2_512_HASH_SIZE;
		break;
	default:
		hlen = 0U;
		break;
	}

	return hlen;
}
