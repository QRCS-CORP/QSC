#include "tlstranscript.h"
#include "memutils.h"
#include "sha2.h"
#include "intutils.h"

qsc_tls_status qsc_tls_transcript_initialize(qsc_tls_transcript_state* state, qsc_tls_hash_algorithm hash)
{
    QSC_ASSERT(state != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_success;

    if (state != NULL)
    {
        qsc_memutils_clear(state, sizeof(*state));
        state->hash = hash;

        switch (hash)
        {
            case qsc_tls_hash_sha256:
            {
                qsc_sha256_initialize(&state->ctx.sha256);
                state->initialized = true;
                break;
            }
            case qsc_tls_hash_sha384:
            {
                qsc_sha384_initialize(&state->ctx.sha384);
                state->initialized = true;
                break;
            }
            case qsc_tls_hash_sha512:
            {
                qsc_sha512_initialize(&state->ctx.sha512);
                state->initialized = true;
                break;
            }
            default:
            {
                status = qsc_tls_status_not_supported;
                break;
            }
        }
    }
    else
    {
        status = qsc_tls_status_invalid_input;
    }

    return status;
}

void qsc_tls_transcript_dispose(qsc_tls_transcript_state* state)
{
    QSC_ASSERT(state != NULL);

    if (state != NULL)
    {
        qsc_memutils_secure_erase(state, sizeof(*state));
    }
}

qsc_tls_status qsc_tls_transcript_update(qsc_tls_transcript_state* state, const uint8_t* input, size_t inplen)
{
    QSC_ASSERT(state != NULL);
    QSC_ASSERT(input != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_success;

    if (state == NULL || (input == NULL && inplen != 0U))
    {
        status = qsc_tls_status_invalid_input;
    }
    else if (state->initialized == false)
    {
        status = qsc_tls_status_invalid_state;
    }
    else if (inplen != 0U)
    {
        switch (state->hash)
        {
            case qsc_tls_hash_sha256:
            {
                qsc_sha256_update(&state->ctx.sha256, input, inplen);
                break;
            }
            case qsc_tls_hash_sha384:
            {
                qsc_sha384_update(&state->ctx.sha384, input, inplen);
                break;
            }
            case qsc_tls_hash_sha512:
            {
                qsc_sha512_update(&state->ctx.sha512, input, inplen);
                break;
            }
            default:
            {
                status = qsc_tls_status_not_supported;
                break;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_transcript_snapshot(const qsc_tls_transcript_state* state, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(state != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);
    
    qsc_tls_transcript_state clone = { 0 };
    size_t digest;
    qsc_tls_status status;

    status = qsc_tls_status_success;

    if (written != NULL)
    {
        *written = 0U; 
    }

    if (state != NULL && output != NULL && written != NULL)
    {
        if (state->initialized == false)
        {
            status = qsc_tls_status_invalid_state;
        }
        else
        {
            digest = qsc_tls_transcript_digest_size(state->hash);

            if (outlen < digest)
            {
                status = qsc_tls_status_buffer_too_small;
            }
            else
            {
                /* clone the hash state so the caller's ongoing hash is undisturbed.
                 * SHA state structs are POD; byte copy reproduces the clone exactly. */
                qsc_memutils_copy(&clone, state, sizeof(clone));

                switch (state->hash)
                {
                    case qsc_tls_hash_sha256:
                    {
                        qsc_sha256_finalize(&clone.ctx.sha256, output);
                        break;
                    }
                    case qsc_tls_hash_sha384:
                    {
                        qsc_sha384_finalize(&clone.ctx.sha384, output);
                        break;
                    }
                    case qsc_tls_hash_sha512:
                    {
                        qsc_sha512_finalize(&clone.ctx.sha512, output);
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
                    *written = digest;
                }

                qsc_memutils_secure_erase(&clone, sizeof(clone));
            }
        }
    }
    else
    {
        status = qsc_tls_status_invalid_input;
    }

    return status;
}

qsc_tls_status qsc_tls_transcript_replace_with_message_hash(qsc_tls_transcript_state* state)
{
    QSC_ASSERT(state != NULL);

    uint8_t hash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t header[4U] = { 0U };
    size_t digest;
    size_t written;
    qsc_tls_status status;

    status = qsc_tls_status_success;

    if (state != NULL)
    {
        if (state->initialized == true)
        {
            digest = qsc_tls_transcript_digest_size(state->hash);
            status = qsc_tls_transcript_snapshot(state, hash, sizeof(hash), &written);

            if (status == qsc_tls_status_success && written == digest)
            {
                qsc_tls_hash_algorithm active;

                active = state->hash;
                qsc_memutils_clear(state, sizeof(*state));
                state->hash = active;

                switch (active)
                {
                    case qsc_tls_hash_sha256:
                    {
                        qsc_sha256_initialize(&state->ctx.sha256);
                        state->initialized = true;
                        break;
                    }
                    case qsc_tls_hash_sha384:
                    {
                        qsc_sha384_initialize(&state->ctx.sha384);
                        state->initialized = true;
                        break;
                    }
                    case qsc_tls_hash_sha512:
                    {
                        qsc_sha512_initialize(&state->ctx.sha512);
                        state->initialized = true;
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
                    /* synthetic handshake header: type=254 (message_hash), u24 length = digest. */
                    header[0U] = 254U;
                    header[1U] = 0U;
                    header[2U] = 0U;
                    header[3U] = (uint8_t)digest;
                    status = qsc_tls_transcript_update(state, header, 4U);

                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_transcript_update(state, hash, digest);
                    }
                }
            }
        }
        else
        {
            status = qsc_tls_status_invalid_state;
        }
    }
    else
    {
        status = qsc_tls_status_invalid_input;
    }

    qsc_memutils_secure_erase(hash, sizeof(hash));

    return status;
}

size_t qsc_tls_transcript_digest_size(qsc_tls_hash_algorithm hash)
{
    size_t res;

    switch (hash)
    {
        case qsc_tls_hash_sha256:
        {
            res = 32U;
            break;
        }
        case qsc_tls_hash_sha384:
        {
            res = 48U;
            break;
        }
        case qsc_tls_hash_sha512:
        {
            res = 64U;
            break;
        }
        default:
        {
            res = 0U;
            break;
        }
    }

    return res;
}
