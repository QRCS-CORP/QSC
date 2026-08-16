#include "tlskeyschedule.h"
#include "intutils.h"
#include "memutils.h"
#include "sha2.h"
#include "tlstranscript.h"

/* RFC 9846 Section 7.1: HkdfLabel.label is prefixed with the literal "tls13 " (6 bytes) */
static const char TLS13_LABEL_PREFIX[] = "tls13 ";

#define TLS13_LABEL_PREFIX_LEN 6U

static qsc_tls_status tls_keyschedule_extract(qsc_tls_hash_algorithm hash, const uint8_t* salt, size_t saltlen, const uint8_t* ikm, size_t ikmlen, uint8_t* output, size_t outlen)
{
    qsc_tls_status status;

    status = qsc_tls_status_success;

    switch (hash)
    {
        case qsc_tls_hash_sha256:
        {
            if (outlen < 32U)
            {
                status = qsc_tls_status_buffer_too_small;
            }
            else
            {
                qsc_hkdf256_extract(output, 32U, ikm, ikmlen, salt, saltlen);
            }

            break;
        }
        case qsc_tls_hash_sha384:
        {
            if (outlen < 48U) 
            { 
                status = qsc_tls_status_buffer_too_small; 
            }
            else 
            {
                qsc_hkdf384_extract(output, 48U, ikm, ikmlen, salt, saltlen); 
            }

            break;
        }
        case qsc_tls_hash_sha512:
        {
            if (outlen < 64U) 
            { 
                status = qsc_tls_status_buffer_too_small; 
            }
            else 
            { 
                qsc_hkdf512_extract(output, 64U, ikm, ikmlen, salt, saltlen);
            }

            break;
        }
        default:
        {
            status = qsc_tls_status_not_supported;
            break;
        }
    }

    return status;
}

static qsc_tls_status tls_keyschedule_expand(qsc_tls_hash_algorithm hash, const uint8_t* prk, size_t prklen, const uint8_t* info, size_t infolen, uint8_t* output, size_t outlen)
{
    qsc_tls_status status;

    status = qsc_tls_status_success;

    switch (hash)
    {
        case qsc_tls_hash_sha256:
        {
            qsc_hkdf256_expand(output, outlen, prk, prklen, info, infolen);
            break;
        }
        case qsc_tls_hash_sha384:
        {
            qsc_hkdf384_expand(output, outlen, prk, prklen, info, infolen);
            break;
        }
        case qsc_tls_hash_sha512:
        {
            qsc_hkdf512_expand(output, outlen, prk, prklen, info, infolen);
            break;
        }
        default:
        {
            status = qsc_tls_status_not_supported;
            break;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_hkdf_extract(qsc_tls_hash_algorithm hash, const uint8_t* salt, size_t saltlen, const uint8_t* ikm, size_t ikmlen, uint8_t* output, size_t outlen)
{
    QSC_ASSERT(output != NULL);

    uint8_t zeros[64U] = { 0U };
    size_t digest;
    qsc_tls_status status;

    digest = qsc_tls_transcript_digest_size(hash);

    if (output == NULL || outlen == 0U)
    {
        status = qsc_tls_status_invalid_input;
    }
    else if (digest == 0U)
    {
        status = qsc_tls_status_not_supported;
    }
    else
    {
        /* RFC 5869: salt optional; when absent use zeros of HashLen bytes */
        if (salt == NULL || saltlen == 0U)
        {
            salt = zeros;
            saltlen = digest;
        }

        /* RFC 5869: ikm may be empty */
        if (ikm == NULL)
        {
            ikm = zeros;
            ikmlen = 0U;
        }

        status = tls_keyschedule_extract(hash, salt, saltlen, ikm, ikmlen, output, outlen);
    }

    qsc_memutils_clear(zeros, sizeof(zeros));

    return status;
}

qsc_tls_status qsc_tls_keyschedule_hkdf_expand(qsc_tls_hash_algorithm hash, const uint8_t* prk, size_t prklen, const uint8_t* info, size_t infolen, uint8_t* output, size_t outlen)
{
    QSC_ASSERT(output != NULL);

    qsc_tls_status status;

    if (output == NULL || prk == NULL || (info == NULL && infolen != 0U) || outlen == 0U || prklen == 0U)
    {
        status = qsc_tls_status_invalid_input;
    }
    else if (qsc_tls_transcript_digest_size(hash) == 0U)
    {
        status = qsc_tls_status_not_supported;
    }
    else
    {
        status = tls_keyschedule_expand(hash, prk, prklen, info, infolen, output, outlen);
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_hkdf_expand_label(qsc_tls_hash_algorithm hash, const uint8_t* secret, size_t secretlen, const char* label, size_t labellen, const uint8_t* context, size_t contextlen, uint8_t* output, size_t outlen)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(secret != NULL);
    QSC_ASSERT(label != NULL);

    uint8_t info[2U + 1U + 255U + 1U + 255U] = { 0U };
    size_t off;
    size_t fulllabel;
    qsc_tls_status status;

    status = qsc_tls_status_success;

    if (output == NULL || secret == NULL || label == NULL || (context == NULL && contextlen != 0U))
    {
        status = qsc_tls_status_invalid_input;
    }
    else if (outlen == 0U || outlen > 0xFFFFU)
    {
        status = qsc_tls_status_invalid_length;
    }
    else if (labellen == 0U || labellen > (255U - TLS13_LABEL_PREFIX_LEN))
    {
        status = qsc_tls_status_invalid_length;
    }
    else if (contextlen > 255U)
    {
        status = qsc_tls_status_invalid_length;
    }
    else if (qsc_tls_transcript_digest_size(hash) == 0U)
    {
        status = qsc_tls_status_not_supported;
    }
    else
    {
        fulllabel = TLS13_LABEL_PREFIX_LEN + labellen;
        off = 0U;

        /* uint16 length, big-endian */
        qsc_intutils_be16to8(info + off, (uint16_t)outlen);
        off += 2U;
        /* label vector: u8 length prefix */
        info[off] = (uint8_t)fulllabel;
        off += 1U;
        qsc_memutils_copy(info + off, TLS13_LABEL_PREFIX, TLS13_LABEL_PREFIX_LEN);
        off += TLS13_LABEL_PREFIX_LEN;
        qsc_memutils_copy(info + off, label, labellen);
        off += labellen;
        /* context vector: u8 length prefix */
        info[off] = (uint8_t)contextlen;
        off += 1U;

        if (contextlen != 0U)
        {
            qsc_memutils_copy(info + off, context, contextlen);
            off += contextlen;
        }

        status = tls_keyschedule_expand(hash, secret, secretlen, info, off, output, outlen);
        qsc_memutils_secure_erase(info, sizeof(info));
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_secret_with_hash(qsc_tls_hash_algorithm hash, const uint8_t* secret, size_t secretlen, const char* label, size_t labellen, const uint8_t* transcripthash, size_t transcripthashlen, uint8_t* output, size_t outlen)
{
    size_t digest;
    qsc_tls_status status;

    digest = qsc_tls_transcript_digest_size(hash);

    if (digest == 0U)
    {
        status = qsc_tls_status_not_supported;
    }
    else if (transcripthash == NULL || transcripthashlen != digest)
    {
        status = qsc_tls_status_invalid_input;
    }
    else if (outlen != digest)
    {
        status = qsc_tls_status_invalid_length;
    }
    else
    {
        status = qsc_tls_keyschedule_hkdf_expand_label(hash, secret, secretlen, label, labellen, transcripthash, transcripthashlen, output, outlen);
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_secret_empty(qsc_tls_hash_algorithm hash, const uint8_t* secret, size_t secretlen, const char* label, size_t labellen, uint8_t* output, size_t outlen)
{
    uint8_t empty[64U] = { 0U };
    size_t digest;
    qsc_tls_status status;

    status = qsc_tls_status_success;
    digest = qsc_tls_transcript_digest_size(hash);

    if (digest == 0U)
    {
        status = qsc_tls_status_not_supported;
    }
    else if (outlen != digest)
    {
        status = qsc_tls_status_invalid_length;
    }
    else
    {
        switch (hash)
        {
            case qsc_tls_hash_sha256:
            {
                qsc_sha256_compute(empty, (const uint8_t*)"", 0U);
                break;
            }
            case qsc_tls_hash_sha384:
            {
                qsc_sha384_compute(empty, (const uint8_t*)"", 0U);
                break;
            }
            case qsc_tls_hash_sha512:
            {
                qsc_sha512_compute(empty, (const uint8_t*)"", 0U);
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
            status = qsc_tls_keyschedule_hkdf_expand_label(hash, secret, secretlen, label, labellen, empty, digest, output, outlen);
        }

        qsc_memutils_clear(empty, sizeof(empty));
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_build_certificate_verify_input(const char* contextstring, const uint8_t* transcripthash, size_t transcripthashlen, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);
    QSC_ASSERT(contextstring != NULL);
    QSC_ASSERT(transcripthash != NULL);

    size_t ctxlen;
    size_t i;
    size_t need;
    size_t off;
    qsc_tls_status status;

    status = qsc_tls_status_success;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (output != NULL && written != NULL && contextstring != NULL && transcripthash != NULL)
    {
        if (transcripthashlen != 0U && transcripthashlen <= QSC_TLS_HASH_MAX_SIZE)
        {
            ctxlen = 0U;

            while (contextstring[ctxlen] != '\0')
            {
                ctxlen += 1U;
            }

            if (ctxlen == 0U || ctxlen > 128U)
            {
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                need = 64U + ctxlen + 1U + transcripthashlen;

                if (outlen < need)
                {
                    status = qsc_tls_status_buffer_too_small;
                }
                else
                {
                    off = 0U;
                    for (i = 0U; i < 64U; ++i) { output[off + i] = 0x20U; }
                    off += 64U;
                    qsc_memutils_copy(output + off, (const uint8_t*)contextstring, ctxlen);
                    off += ctxlen;
                    output[off] = 0x00U;
                    off += 1U;
                    qsc_memutils_copy(output + off, transcripthash, transcripthashlen);
                    off += transcripthashlen;
                    *written = off;
                }
            }
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }
    else
    {
        status = qsc_tls_status_invalid_input;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_state_initialize(qsc_tls_key_schedule_state* state, qsc_tls_hash_algorithm hash)
{
    QSC_ASSERT(state != NULL);

    size_t ds;
    qsc_tls_status status;

    status = qsc_tls_status_success;

    if (state != NULL)
    {
        ds = qsc_tls_transcript_digest_size(hash);

        if (ds == 0U)
        {
            status = qsc_tls_status_not_supported;
        }
        else
        {
            qsc_memutils_clear(state, sizeof(*state));
            state->hash = hash;
            state->digestsize = ds;
            state->initialized = true;
        }
    }
    else
    {
        status = qsc_tls_status_invalid_input;
    }

    return status;
}

void qsc_tls_keyschedule_state_dispose(qsc_tls_key_schedule_state* state)
{
    QSC_ASSERT(state != NULL);

    if (state != NULL)
    {
        qsc_memutils_secure_erase(state, sizeof(*state));
    }
}

qsc_tls_status qsc_tls_keyschedule_extract_early_secret(qsc_tls_key_schedule_state* state, const uint8_t* psk, size_t psklen)
{
    QSC_ASSERT(state != NULL);

    uint8_t zerosalt[64U] = { 0 };
    uint8_t zeroikm[64U] = { 0 };
    qsc_tls_status status;

    if (state != NULL && state->initialized == true)
    {
        /* RFC 9846 Section 7.1: salt = 0, IKM = PSK (or 0-length zeros when no PSK) */
        if (psk == NULL || psklen == 0U)
        {
            psk = zeroikm;
            psklen = state->digestsize;
        }

        status = tls_keyschedule_extract(state->hash, zerosalt, state->digestsize, psk, psklen, state->earlysecret, state->digestsize);

        if (status == qsc_tls_status_success)
        {
            state->earlydone = true;
        }

        qsc_memutils_secure_erase(zerosalt, sizeof(zerosalt));
        qsc_memutils_secure_erase(zeroikm, sizeof(zeroikm));
    }
    else
    {
        status = qsc_tls_status_invalid_state;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_extract_handshake_secret(qsc_tls_key_schedule_state* state, const uint8_t* dhe, size_t dhelen)
{
    QSC_ASSERT(state != NULL);

    uint8_t derived[64U] = { 0U };
    qsc_tls_status status;

    if (state != NULL && state->initialized == true && state->earlydone == true)
    {
        if (dhe != NULL && dhelen != 0U)
        {
            /* salt = Derive-Secret(early, "derived", "") IKM = dhe */
            status = qsc_tls_keyschedule_derive_secret_empty(state->hash, state->earlysecret, state->digestsize, "derived", 7U, derived, state->digestsize);

            if (status == qsc_tls_status_success)
            {
                status = tls_keyschedule_extract(state->hash, derived, state->digestsize, dhe, dhelen, state->handshakesecret, state->digestsize);

                if (status == qsc_tls_status_success)
                {
                    state->handshakedone = true;
                }
            }

            qsc_memutils_secure_erase(derived, sizeof(derived));
        }
        else
        {
            status = qsc_tls_status_invalid_input;
        }
    }
    else
    {
        status = qsc_tls_status_invalid_state;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_extract_master_secret(qsc_tls_key_schedule_state* state)
{
    QSC_ASSERT(state != NULL);

    uint8_t derived[64U] = { 0U };
    uint8_t zeroikm[64U] = { 0U };
    qsc_tls_status status;

    if (state != NULL && state->initialized != false && state->handshakedone == true)
    {
        status = qsc_tls_keyschedule_derive_secret_empty(state->hash, state->handshakesecret, state->digestsize, "derived", 7U, derived, state->digestsize);

        if (status == qsc_tls_status_success)
        {
            status = tls_keyschedule_extract(state->hash, derived, state->digestsize, zeroikm, state->digestsize, state->mastersecret, state->digestsize);

            if (status == qsc_tls_status_success)
            {
                state->masterdone = true;
            }
        }

        qsc_memutils_secure_erase(derived, sizeof(derived));
        qsc_memutils_secure_erase(zeroikm, sizeof(zeroikm));
    }
    else
    {
        status = qsc_tls_status_invalid_state;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_handshake_traffic_secrets(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen)
{
    QSC_ASSERT(state != NULL);

    qsc_tls_status status;

    if (state != NULL && state->initialized == true && state->handshakedone == true)
    {
        status = qsc_tls_keyschedule_derive_secret_with_hash(state->hash, state->handshakesecret, state->digestsize, "c hs traffic", 12U, transcripthash, transcripthashlen, state->clienthandshaketrafficsecret, state->digestsize);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_keyschedule_derive_secret_with_hash(state->hash, state->handshakesecret, state->digestsize, "s hs traffic", 12U, transcripthash, transcripthashlen, state->serverhandshaketrafficsecret, state->digestsize);
        }
    }
    else
    {
        status = qsc_tls_status_invalid_state;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_application_traffic_secrets(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen)
{
    QSC_ASSERT(state != NULL);

    qsc_tls_status status;

    if (state != NULL && state->initialized == true && state->masterdone == true)
    {
        status = qsc_tls_keyschedule_derive_secret_with_hash(state->hash, state->mastersecret, state->digestsize, "c ap traffic", 12U, transcripthash, transcripthashlen, state->clientapplicationtrafficsecret, state->digestsize);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_keyschedule_derive_secret_with_hash(state->hash, state->mastersecret, state->digestsize, "s ap traffic", 12U, transcripthash, transcripthashlen, state->serverapplicationtrafficsecret, state->digestsize);
        }
    }
    else
    {
        status = qsc_tls_status_invalid_state;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_exporter_master_secret(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen)
{
    QSC_ASSERT(state != NULL);

    qsc_tls_status status;

    if (state != NULL && state->initialized == true && state->masterdone == true)
    {
        status = qsc_tls_keyschedule_derive_secret_with_hash(state->hash, state->mastersecret, state->digestsize, "exp master", 10U, transcripthash, transcripthashlen, state->exportermastersecret, state->digestsize);
    }
    else
    {
        status = qsc_tls_status_invalid_state;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_resumption_master_secret(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen)
{
    QSC_ASSERT(state != NULL);

    qsc_tls_status status;

    if (state != NULL && state->initialized == true && state->masterdone == true)
    {
        status = qsc_tls_keyschedule_derive_secret_with_hash(state->hash, state->mastersecret, state->digestsize, "res master", 10U, transcripthash, transcripthashlen, state->resumptionmastersecret, state->digestsize);
    }
    else
    {
        status = qsc_tls_status_invalid_state;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_traffic_keys(qsc_tls_hash_algorithm hash, const uint8_t* trafficsecret, size_t trafficsecretlen, size_t keylen, size_t ivlen, uint8_t* keyoutput, uint8_t* ivoutput)
{
    QSC_ASSERT(trafficsecret != NULL);
    QSC_ASSERT(keyoutput != NULL);
    QSC_ASSERT(ivoutput != NULL);

    qsc_tls_status status;

    if (trafficsecret != NULL && keyoutput != NULL && ivoutput != NULL)
    {
        status = qsc_tls_keyschedule_hkdf_expand_label(hash, trafficsecret, trafficsecretlen, "key", 3U, NULL, 0U, keyoutput, keylen);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_keyschedule_hkdf_expand_label(hash, trafficsecret, trafficsecretlen, "iv", 2U, NULL, 0U, ivoutput, ivlen);
        }
    }
    else
    {
        status = qsc_tls_status_invalid_state;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_advance_traffic_secret(qsc_tls_hash_algorithm hash, const uint8_t* currenttrafficsecret, size_t trafficsecretlen, uint8_t* nexttrafficsecret)
{
    return qsc_tls_keyschedule_hkdf_expand_label(hash, currenttrafficsecret, trafficsecretlen, "traffic upd", 11U, NULL, 0U, nexttrafficsecret, trafficsecretlen);
}

qsc_tls_status qsc_tls_keyschedule_compute_finished(qsc_tls_hash_algorithm hash, const uint8_t* basekey, size_t basekeylen, const uint8_t* transcripthash, size_t transcripthashlen, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);
    QSC_ASSERT(basekey != NULL);
    QSC_ASSERT(transcripthash != NULL);

    uint8_t finkey[64U] = { 0U };
    size_t digest;
    qsc_tls_status status;

    if (written != NULL) 
    { 
        *written = 0U; 
    }

    digest = qsc_tls_transcript_digest_size(hash);

    if (output != NULL && written != NULL && basekey != NULL && transcripthash != NULL)
    {
        if (digest == 0U)
        {
            status = qsc_tls_status_not_supported;
        }
        else if (outlen < digest)
        {
            status = qsc_tls_status_buffer_too_small;
        }
        else if (basekeylen != digest || transcripthashlen != digest)
        {
            status = qsc_tls_status_invalid_length;
        }
        else
        {
            status = qsc_tls_keyschedule_hkdf_expand_label(hash, basekey, basekeylen, "finished", 8U, NULL, 0U, finkey, digest);

            if (status == qsc_tls_status_success)
            {
                switch (hash)
                {
                    case qsc_tls_hash_sha256:
                    {
                        qsc_hmac256_compute(output, transcripthash, transcripthashlen, finkey, digest);
                        break;
                    }
                    case qsc_tls_hash_sha384:
                    {
                        qsc_hmac384_compute(output, transcripthash, transcripthashlen, finkey, digest);
                        break;
                    }
                    case qsc_tls_hash_sha512:
                    {
                        qsc_hmac512_compute(output, transcripthash, transcripthashlen, finkey, digest);
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
            }

            qsc_memutils_secure_erase(finkey, sizeof(finkey));
        }
    }
    else
    {
        status = qsc_tls_status_invalid_input;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_verify_finished(qsc_tls_hash_algorithm hash, const uint8_t* basekey, size_t basekeylen, const uint8_t* transcripthash, size_t transcripthashlen, const uint8_t* candidate, size_t candidatelen)
{
    QSC_ASSERT(candidate != NULL);

    uint8_t expected[64U] = { 0U };
    size_t written;
    size_t digest;
    qsc_tls_status status;

    digest = qsc_tls_transcript_digest_size(hash);

    if (candidate != NULL && candidatelen == digest)
    {
        status = qsc_tls_keyschedule_compute_finished(hash, basekey, basekeylen, transcripthash, transcripthashlen, expected, sizeof(expected), &written);

        if (status == qsc_tls_status_success)
        {
            if (qsc_intutils_verify(expected, candidate, digest) != 0)
            {
                status = qsc_tls_status_authentication_failure;
            }
        }

        qsc_memutils_secure_erase(expected, sizeof(expected));
    }
    else
    {
        status = qsc_tls_status_invalid_length;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_suite_record_sizes(qsc_tls_cipher_suite suite, size_t* keylen, size_t* ivlen)
{
    QSC_ASSERT(keylen != NULL);
    QSC_ASSERT(ivlen != NULL);

    qsc_tls_status status;

    if (keylen != NULL && ivlen != NULL)
    {
        *keylen = 0U;
        *ivlen = 0U;

        switch (suite)
        {
            case qsc_tls_cipher_suite_tls_aes_128_gcm_sha256:
            {
                status = qsc_tls_status_success;
                *keylen = 16U;
                *ivlen = 12U;
                break;
            }
            case qsc_tls_cipher_suite_tls_aes_256_gcm_sha384:
            {
                status = qsc_tls_status_success;
                *keylen = 32U;
                *ivlen = 12U;
                break;
            }
            case qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256:
            {
                status = qsc_tls_status_success;
                *keylen = 32U;
                *ivlen = 12U;
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

qsc_tls_hash_algorithm qsc_tls_keyschedule_suite_hash(qsc_tls_cipher_suite suite)
{
    qsc_tls_hash_algorithm h;

    switch (suite)
    {
        case qsc_tls_cipher_suite_tls_aes_128_gcm_sha256:
        case qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256:
        {
            h = qsc_tls_hash_sha256;
            break;
        }
        case qsc_tls_cipher_suite_tls_aes_256_gcm_sha384:
        {
            h = qsc_tls_hash_sha384;
            break;
        }
        default:
        {
            h = qsc_tls_hash_none;
            break;
        }
    }

    return h;
}

qsc_tls_status qsc_tls_keyschedule_derive_resumption_psk(const qsc_tls_key_schedule_state* state, const uint8_t* nonce, size_t noncelen, uint8_t* output, size_t outlen)
{
    QSC_ASSERT(state != NULL);
    QSC_ASSERT(output != NULL);

    qsc_tls_status status;

    /* RFC 9846 Section 4.7.1: PSK = HKDF-Expand-Label(resumption_secret, "resumption", ticket_nonce, Hash.length) */
    if (state != NULL && output != NULL && outlen != 0U && state->initialized == true && state->masterdone == true)
    {
        if ((nonce == NULL) && (noncelen != 0U))
        {
            return qsc_tls_status_invalid_input;
        }

        status = qsc_tls_keyschedule_hkdf_expand_label(state->hash, state->resumptionmastersecret, state->digestsize, "resumption", 10U, nonce, noncelen, output, outlen);
    }
    else
    {
        status = qsc_tls_status_invalid_state;
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_binder_key(qsc_tls_key_schedule_state* state, bool external)
{
    QSC_ASSERT(state != NULL);

    const char* label;
    size_t labellen;
    qsc_tls_status status;

    status = qsc_tls_status_invalid_state;

    if (state != NULL && state->initialized == true && state->earlydone == true)
    {
        /* RFC 9846 Section 7.1: binder_key uses "ext binder" for external PSK and "res binder" for resumption PSK */
        if (external)
        {
            label = "ext binder";
            labellen = 10U;
        }
        else
        {
            label = "res binder";
            labellen = 10U;
        }

        status = qsc_tls_keyschedule_derive_secret_empty(state->hash, state->earlysecret, state->digestsize, label, labellen, state->binderkey, state->digestsize);

        if (status == qsc_tls_status_success)
        {
            state->binderderived = true;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_client_early_traffic_secret(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen)
{
    QSC_ASSERT(state != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_state;

    if (state != NULL && state->initialized == true && state->earlydone == true)
    {
        status = qsc_tls_keyschedule_derive_secret_with_hash(state->hash, state->earlysecret, state->digestsize, "c e traffic", 11U, transcripthash, transcripthashlen, state->clientearlytrafficsecret, state->digestsize);

        if (status == qsc_tls_status_success)
        {
            state->earlytrafficderived = true;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_derive_early_exporter_secret(qsc_tls_key_schedule_state* state, const uint8_t* transcripthash, size_t transcripthashlen)
{
    QSC_ASSERT(state != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_state;

    if (state != NULL && state->initialized == true && state->earlydone == true)
    {
        status = qsc_tls_keyschedule_derive_secret_with_hash(state->hash, state->earlysecret, state->digestsize, "e exp master", 12U, transcripthash, transcripthashlen, state->earlyexportermastersecret, state->digestsize);
    }

    return status;
}

qsc_tls_status qsc_tls_keyschedule_compute_psk_binder(qsc_tls_hash_algorithm hash, const uint8_t* binderkey, size_t binderkeylen, const uint8_t* partialtranshash, size_t transcripthashlen, uint8_t* output, size_t outlen, size_t* written)
{
    /* PSK binder = HMAC(finished_key, partialtranshash)
     * where finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length).
     * Identical in shape to qsc_tls_keyschedule_compute_finished, with binder_key as the base */

    return qsc_tls_keyschedule_compute_finished(hash, binderkey, binderkeylen, partialtranshash, transcripthashlen, output, outlen, written);
}
