#include "tlsserver.h"
#include "tlsalert.h"
#include "csp.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "tlscodec.h"
#include "tlscert.h"
#include "tlsdefs.h"
#include "tlsextensions.h"
#include "tlssigalgs.h"
#include "tlshandshake.h"
#include "tlskeyschedule.h"
#include "tlsrecord.h"
#include "tlstranscript.h"
#include "tlssignerdefault.h"
#include "timestamp.h"
#include "x509cert.h"
#include "x509host.h"
#include "x509name.h"

static bool tls_server_local_certificate_sign(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, void* state);
static qsc_tls_status server_validate_client_certificate_chain(qsc_tls_server_state* state, const qsc_tls_certificate_view* chain, size_t chainlength);
static qsc_tls_status server_authorize_client_certificate_identity(qsc_tls_server_state* state);

/* Emit a HelloRetryRequest. RFC 9846 Section 4.2.4:
 * - Structurally a ServerHello with legacy_version=0x0303, the special HRR
 * random, echo of session_id, chosen cipher suite, null compression.
 * - extensions: supported_versions + key_share (containing only the selected
 * group id, no key material).
 * - Before updating the transcript with the HRR message, apply the
 * message_hash transform to replace the previous ClientHello with Hash(ClientHello1). */
static const uint8_t tls_hrr_special_random[32] = {
    0xCFU, 0x21U, 0xADU, 0x74U, 0xE5U, 0x9AU, 0x61U, 0x11U,
    0xBEU, 0x1DU, 0x8CU, 0x02U, 0x1EU, 0x65U, 0xB8U, 0x91U,
    0xC2U, 0xA2U, 0x11U, 0x16U, 0x7AU, 0xBBU, 0x8CU, 0x5EU,
    0x07U, 0x9EU, 0x09U, 0xE2U, 0xC8U, 0xA8U, 0x33U, 0x9CU
};


static qsc_tls_status server_install_handshake_keys(qsc_tls_server_state* state)
{
    uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t key[32U] = { 0U };
    uint8_t iv[12U] = { 0U };
    size_t keylen;
    size_t ivlen;
    size_t thashlen;
    qsc_tls_status st;

    keylen = 0U;
    ivlen = 0U;
    thashlen = 0U;

    st = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_keyschedule_derive_handshake_traffic_secrets(&state->keyschedule, thash, thashlen);
    }

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_keyschedule_suite_record_sizes(state->negotiatedsuite, &keylen, &ivlen);
    }

    /* server write = server_hs_traffic; server read = client_hs_traffic. */
    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.serverhandshaketrafficsecret, state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_record_state_install_keys(&state->writerecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clienthandshaketrafficsecret, state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_record_state_install_keys(&state->readrecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    qsc_memutils_secure_erase(thash, sizeof(thash));
    qsc_memutils_secure_erase(key, sizeof(key));
    qsc_memutils_secure_erase(iv, sizeof(iv));

    return st;
}

static qsc_tls_status server_emit_certificate_request(qsc_tls_server_state* state, uint8_t* output, size_t outlen, size_t* written)
{
    uint8_t body[3U + QSC_TLS_SIGNATURE_ALGORITHMS_EXTENSION_MAX_SIZE] = { 0U };
    uint8_t extensions[QSC_TLS_SIGNATURE_ALGORITHMS_EXTENSION_MAX_SIZE] = { 0U };
    uint8_t hs[4U + sizeof(body)] = { 0U };
    qsc_tls_signature_scheme schemes[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { qsc_tls_sig_none };
    size_t bodyoff;
    size_t extlen;
    size_t hsoff;
    size_t i;
    size_t schemecount;
    qsc_tls_status status;

    bodyoff = 0U;
    extlen = 0U;
    hsoff = 0U;
    schemecount = 0U;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && output != NULL && written != NULL)
    {
        *written = 0U;
        status = qsc_tls_status_success;

        for (i = 0U; i < state->config.sigschemepreferencecount && schemecount < QSC_TLS_MAX_SIGNATURE_SCHEMES; ++i)
        {
            if (qsc_tls_signature_scheme_is_supported(state->config.sigschemepreference[i]) == true &&
                qsc_tls_signature_scheme_is_certificate_verify_capable(state->config.sigschemepreference[i]) == true)
            {
                schemes[schemecount] = state->config.sigschemepreference[i];
                ++schemecount;
            }
        }

        if (schemecount == 0U)
        {
            state->lastalert = qsc_tls_alert_internal_error;
            status = qsc_tls_status_not_supported;
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_extensions_encode_signature_algorithms(extensions, sizeof(extensions), &extlen, schemes, schemecount);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_certificate_request_encode(NULL, 0U, extensions, extlen, body, sizeof(body), &bodyoff);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_certificate_request, bodyoff);
        }

        if (status == qsc_tls_status_success)
        {
            qsc_memutils_copy(hs + hsoff, body, bodyoff);
            hsoff += bodyoff;
            status = qsc_tls_transcript_update(&state->transcript, hs, hsoff);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_record_encrypt(&state->writerecord, output, outlen, written, qsc_tls_record_content_handshake, hs, hsoff);
        }
    }

    return status;
}

static qsc_tls_status server_emit_flight1(qsc_tls_server_state* state, uint8_t* output, size_t outlen, size_t* written)
{
    qsc_tls_status st;
    size_t off;

    off = 0U;

    /* ---- ServerHello ---- */
    {
        uint8_t body[QSC_TLS_SERVER_HELLO_BODY_MAX_SIZE] = { 0U };
        uint8_t hs[4 + QSC_TLS_SERVER_HELLO_BODY_MAX_SIZE] = { 0U };
        size_t boff;
        size_t exthdr;
        size_t hsoff;
        size_t recwritten;
        size_t suites_hdr_unused;

        boff = 0U;
        hsoff = 0U;
        recwritten = 0U;
        (void)suites_hdr_unused;

        st = qsc_tls_codec_write_u16(body, sizeof(body), &boff, QSC_TLS_PROTOCOL_VERSION_12);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        if (!qsc_csp_generate(state->serverrandom, 32U))
        {
            return qsc_tls_status_failure;
        }

        st = qsc_tls_codec_write_bytes(body, sizeof(body), &boff, state->serverrandom, 32U);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        /* RFC 9846 Section 4.2.3: ServerHello legacy_session_id_echo MUST equal the ClientHello legacy_session_id. */
        st = qsc_tls_codec_write_vector8(body, sizeof(body), &boff, state->legacy_session_id, state->legacy_session_id_len);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        st = qsc_tls_codec_write_u16(body, sizeof(body), &boff, (uint16_t)state->negotiatedsuite);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        st = qsc_tls_codec_write_u8(body, sizeof(body), &boff, 0U);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        /* extensions: supported_versions + key_share */
        st = qsc_tls_codec_vector_begin_u16(body, sizeof(body), &boff, &exthdr);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_extensions_encode_supported_versions_server(body, sizeof(body), &boff);
        }

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_extensions_encode_key_share_server(body, sizeof(body), &boff, state->negotiatedgroup, state->serverkeyshare, state->serverkeysharelen);
        }

        /* if we accepted a PSK, echo pre_shared_key(selected_identity) in ServerHello. */
        if (st == qsc_tls_status_success && state->pskaccepted)
        {
            st = qsc_tls_extensions_encode_pre_shared_key_server(body, sizeof(body), &boff, state->selectedpskidentity);
        }

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_codec_vector_end_u16(body, sizeof(body), &boff, exthdr);
        }

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        /* wrap in handshake header + plaintext record */

        st = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_server_hello, boff);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        qsc_memutils_copy(hs + hsoff, body, boff);
        hsoff += boff;

        st = qsc_tls_transcript_update(&state->transcript, hs, hsoff);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        st = qsc_tls_record_encode_plaintext(output + off, outlen - off, &recwritten, qsc_tls_record_content_handshake, hs, hsoff);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        off += recwritten;
    }

    /* install handshake keys now (transcript = CH..SH). */
    st = server_install_handshake_keys(state);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    /* ---- EncryptedExtensions ---- */
    {
        uint8_t body[4U + 4U + 2U + 1U + QSC_TLS_MAX_ALPN_SIZE] = { 0U };
        uint8_t hs[4U + 2U + sizeof(body)] = { 0U };
        size_t bodyoff;
        size_t hsoff;
        size_t recwritten;

        bodyoff = 0U;
        hsoff = 0U;
        recwritten = 0U;

        /* Build extensions vector body first, then emit. */
        if (state->alpnselected == true)
        {
            qsc_tls_alpn_protocols selectedalpn;

            qsc_memutils_clear(&selectedalpn, sizeof(selectedalpn));
            qsc_memutils_copy(selectedalpn.protocols[0U], state->selectedalpn, state->selectedalpnlen);
            selectedalpn.protocollens[0U] = state->selectedalpnlen;
            selectedalpn.protocolcount = 1U;
            selectedalpn.configured = true;
            st = qsc_tls_extensions_encode_alpn(body, sizeof(body), &bodyoff, &selectedalpn);
        }

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        st = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_encrypted_extensions, 2U + bodyoff);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        hs[hsoff] = (uint8_t)((bodyoff >> 8) & 0xFFU);
        ++hsoff;
        hs[hsoff] = (uint8_t)(bodyoff & 0xFFU);
        ++hsoff;

        for (size_t i = 0; i < bodyoff; ++i)
        {
            hs[hsoff] = body[i];
            ++hsoff;
        }

        st = qsc_tls_transcript_update(&state->transcript, hs, hsoff);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        st = qsc_tls_record_encrypt(&state->writerecord, output + off, outlen - off, &recwritten, qsc_tls_record_content_handshake, hs, hsoff);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        off += recwritten;
    }

    /* ---- CertificateRequest ---- */
    if (state->config.requestclientauth == true)
    {
        size_t recwritten;

        recwritten = 0U;
        st = server_emit_certificate_request(state, output + off, outlen - off, &recwritten);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        off += recwritten;
    }

    /* ---- certificate ---- (skipped on PSK resumption per RFC 9846 2.2) */
    if (!state->pskaccepted)
    {
        uint8_t body[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
        uint8_t* hs;
        size_t boff;
        size_t hsoff;

        boff = 0U;
        hsoff = 0U;

        st = qsc_tls_certificate_encode_message(NULL, 0U, state->config.localcert.chain, state->config.localcert.chainlength, body, sizeof(body), &boff);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        hs = (uint8_t*)qsc_memutils_malloc(4U + boff);

        if (hs == NULL)
        {
            return qsc_tls_status_failure;
        }

        st = qsc_tls_handshake_write_header(hs, 4U + boff, &hsoff, qsc_tls_handshake_type_certificate, boff);

        if (st == qsc_tls_status_success)
        {
            qsc_memutils_copy(hs + hsoff, body, boff);
            hsoff += boff;
            st = qsc_tls_transcript_update(&state->transcript, hs, hsoff);
        }

        if (st == qsc_tls_status_success)
        {
            size_t recwritten;

            recwritten = 0U;

            st = qsc_tls_record_encrypt(&state->writerecord, output + off, outlen - off, &recwritten, qsc_tls_record_content_handshake, hs, hsoff);

            if (st == qsc_tls_status_success)
            {
                off += recwritten;
            }
        }

        qsc_memutils_secure_erase(hs, 4U + boff);
        qsc_memutils_alloc_free(hs);

        if (st != qsc_tls_status_success)
        {
            return st;
        }
    }

    /* ---- CertificateVerify ---- (skipped on PSK resumption) */
    if (!state->pskaccepted)
    {
        uint8_t body[4U + QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE] = { 0U };
        uint8_t cvinput[256U] = { 0U };
        uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
        uint8_t sig[QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE] = { 0U };
        size_t boff;
        size_t cvinputlen;
        size_t siglen;
        size_t thashlen;
        bool ok;

        boff = 0U;
        cvinputlen = 0U;
        siglen = sizeof(sig);
        thashlen = 0U;

        st = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_keyschedule_build_certificate_verify_input("TLS 1.3, server CertificateVerify", thash, thashlen, cvinput, sizeof(cvinput), &cvinputlen);
        }

        if (st != qsc_tls_status_success)
        {
            qsc_memutils_secure_erase(thash, sizeof(thash));

            return st;
        }

        /* sign via the configured local signer callback. */
        if (state->config.localcert.signcallback == NULL)
        {
            qsc_memutils_secure_erase(thash, sizeof(thash));

            return qsc_tls_status_invalid_state;
        }

        ok = state->config.localcert.signcallback(state->negotiatedsigscheme, cvinput, cvinputlen, sig, &siglen, state->config.localcert.signstate);

        if (ok == false)
        {
            qsc_memutils_secure_erase(thash, sizeof(thash));
            qsc_memutils_secure_erase(cvinput, sizeof(cvinput)); return qsc_tls_status_failure;
        }

        /* CV body: scheme u16 + signature u16-vector */
        st = qsc_tls_handshake_encode_certificate_verify(body, sizeof(body), &boff, state->negotiatedsigscheme, sig, siglen);

        if (st == qsc_tls_status_success)
        {
            uint8_t* hs;

            hs = (uint8_t*)qsc_memutils_malloc(4U + boff);

            if (hs == NULL)
            {
                st = qsc_tls_status_failure;
            }
            else
            {
                size_t hsoff;

                hsoff = 0U;
                st = qsc_tls_handshake_write_header(hs, 4U + boff, &hsoff, qsc_tls_handshake_type_certificate_verify, boff);

                if (st == qsc_tls_status_success)
                {
                    qsc_memutils_copy(hs + hsoff, body, boff);
                    hsoff += boff;
                    st = qsc_tls_transcript_update(&state->transcript, hs, hsoff);
                }

                if (st == qsc_tls_status_success)
                {
                    size_t recwritten;

                    recwritten = 0U;

                    st = qsc_tls_record_encrypt(&state->writerecord, output + off, outlen - off, &recwritten, qsc_tls_record_content_handshake, hs, hsoff);

                    if (st == qsc_tls_status_success)
                    {
                        off += recwritten;
                    }
                }

                qsc_memutils_secure_erase(hs, 4U + boff);
                qsc_memutils_alloc_free(hs);
            }
        }

        qsc_memutils_secure_erase(thash, sizeof(thash));
        qsc_memutils_secure_erase(cvinput, sizeof(cvinput));
        qsc_memutils_secure_erase(sig, sizeof(sig));

        if (st != qsc_tls_status_success)
        {
            return st;
        }
    }

    /* ---- finished ---- */
    {
        uint8_t mac[QSC_TLS_HASH_MAX_SIZE] = { 0U };
        uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
        size_t maclen;
        size_t thashlen;

        maclen = 0U;
        thashlen = 0U;

        st = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_keyschedule_compute_finished(state->negotiatedhash, state->keyschedule.serverhandshaketrafficsecret, state->keyschedule.digestsize, thash, thashlen, mac, sizeof(mac), &maclen);
        }

        if (st == qsc_tls_status_success)
        {
            uint8_t hs[4U + QSC_TLS_HASH_MAX_SIZE] = { 0U };
            size_t hsoff;

            hsoff = 0U;
            st = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_finished, maclen);

            if (st == qsc_tls_status_success)
            {
                qsc_memutils_copy(hs + hsoff, mac, maclen);
                hsoff += maclen;
                st = qsc_tls_transcript_update(&state->transcript, hs, hsoff);
            }

            /* Application traffic secrets are derived from the transcript through server Finished.
             * Retain that boundary because subsequent client-authentication and EOED messages must
             * not alter the application-traffic-secret transcript input. */
            if (st == qsc_tls_status_success)
            {
                state->stashedserverfinhashlen = 0U;
                st = qsc_tls_transcript_snapshot(&state->transcript, state->stashedserverfinhash, sizeof(state->stashedserverfinhash), &state->stashedserverfinhashlen);
            }

            if (st == qsc_tls_status_success)
            {
                size_t recwritten;

                recwritten = 0U;
                st = qsc_tls_record_encrypt(&state->writerecord, output + off, outlen - off, &recwritten, qsc_tls_record_content_handshake, hs, hsoff);

                if (st == qsc_tls_status_success)
                {
                    off += recwritten;
                }
            }
        }

        qsc_memutils_secure_erase(thash, sizeof(thash));
        qsc_memutils_secure_erase(mac, sizeof(mac));

        if (st != qsc_tls_status_success)
        {
            return st;
        }
    }

    /* RFC 9846 Section 7.1: the Main Secret is derivable now. */
    st = qsc_tls_keyschedule_extract_master_secret(&state->keyschedule);
    *written = off;

    return st;
}

static bool server_signature_scheme_is_local_certificate_compatible(const qsc_tls_local_certificate_config* localcert, qsc_tls_signature_scheme scheme)
{
    bool res;

    res = false;

    if (localcert != NULL && localcert->configured == true)
    {
        if (qsc_tls_signature_scheme_is_supported(scheme) == true && qsc_tls_signature_scheme_is_certificate_verify_capable(scheme) == true)
        {
            if (localcert->verifyscheme != qsc_tls_sig_none)
            {
                res = (localcert->verifyscheme == scheme);
            }
            else
            {
                res = true;
            }
        }
    }

    return res;
}

static qsc_tls_signature_scheme server_select_signature_scheme(const qsc_tls_server_state* state)
{
    qsc_tls_signature_scheme scheme;

    scheme = qsc_tls_sig_none;

    if (state != NULL)
    {
        for (size_t i = 0U; i < state->config.sigschemepreferencecount && scheme == qsc_tls_sig_none; ++i)
        {
            if (server_signature_scheme_is_local_certificate_compatible(&state->config.localcert, state->config.sigschemepreference[i]) == true)
            {
                for (size_t j = 0U; j < state->clientcapabilities.sigschemecount; ++j)
                {
                    if (state->config.sigschemepreference[i] == state->clientcapabilities.sigschemes[j])
                    {
                        scheme = state->config.sigschemepreference[i];
                        break;
                    }
                }
            }
        }
    }

    return scheme;
}

static qsc_tls_status server_emit_hrr(qsc_tls_server_state* state, uint8_t* output, size_t outlen, size_t* written)
{
    uint8_t body[QSC_TLS_SERVER_HELLO_BODY_MAX_SIZE] = { 0U };
    uint8_t hs[4U + QSC_TLS_SERVER_HELLO_BODY_MAX_SIZE] = { 0U };
    size_t boff;
    size_t exthdr;
    size_t hsoff;
    size_t recwritten;
    qsc_tls_status status;

    boff = 0U;
    exthdr = 0U;
    hsoff = 0U;
    recwritten = 0U;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && output != NULL && written != NULL)
    {
        *written = 0U;

        if (qsc_csp_generate(state->hrrcookie, sizeof(state->hrrcookie)) == false)
        {
            status = qsc_tls_status_failure;
        }
        else
        {
            state->hrrcookielen = sizeof(state->hrrcookie);
            status = qsc_tls_transcript_replace_with_message_hash(&state->transcript);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u16(body, sizeof(body), &boff, QSC_TLS_PROTOCOL_VERSION_12);
        }

        if (status == qsc_tls_status_success)
        {
            qsc_memutils_copy(state->serverrandom, tls_hrr_special_random, sizeof(state->serverrandom));
            status = qsc_tls_codec_write_bytes(body, sizeof(body), &boff, state->serverrandom, sizeof(state->serverrandom));
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_vector8(body, sizeof(body), &boff, state->legacy_session_id, state->legacy_session_id_len);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u16(body, sizeof(body), &boff, (uint16_t)state->negotiatedsuite);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_u8(body, sizeof(body), &boff, 0U);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_begin_u16(body, sizeof(body), &boff, &exthdr);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_extensions_encode_supported_versions_server(body, sizeof(body), &boff);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_extensions_encode_key_share_hello_retry(body, sizeof(body), &boff, state->hrrgroup);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_extensions_encode_cookie(body, sizeof(body), &boff, state->hrrcookie, state->hrrcookielen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_end_u16(body, sizeof(body), &boff, exthdr);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_server_hello, boff);
        }

        if (status == qsc_tls_status_success)
        {
            qsc_memutils_copy(hs + hsoff, body, boff);
            hsoff += boff;
            status = qsc_tls_transcript_update(&state->transcript, hs, hsoff);
        }

        if (status == qsc_tls_status_success)
        {
            qsc_memutils_copy(&state->hrrtranscript, &state->transcript, sizeof(state->hrrtranscript));
            status = qsc_tls_record_encode_plaintext(output, outlen, &recwritten, qsc_tls_record_content_handshake, hs, hsoff);
        }

        if (status == qsc_tls_status_success)
        {
            *written = recwritten;
        }
    }

    return status;
}

static qsc_tls_status server_install_app_keys(qsc_tls_server_state* state, const uint8_t* thash_before_client_finished, size_t thashlen)
{
    uint8_t key[32U] = { 0U };
    uint8_t iv[12U] = { 0U };
    size_t keylen;
    size_t ivlen;
    qsc_tls_status st;

    ivlen = 0U;
    keylen = 0U;

    st = qsc_tls_keyschedule_derive_application_traffic_secrets(&state->keyschedule, thash_before_client_finished, thashlen);

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_keyschedule_suite_record_sizes(state->negotiatedsuite, &keylen, &ivlen);
    }

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.serverapplicationtrafficsecret, state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_record_state_install_keys(&state->writerecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clientapplicationtrafficsecret, state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_record_state_install_keys(&state->readrecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    qsc_memutils_secure_erase(key, sizeof(key));
    qsc_memutils_secure_erase(iv, sizeof(iv));

    return st;
}

static bool server_client_auth_signature_scheme_requested(const qsc_tls_server_state* state, qsc_tls_signature_scheme scheme)
{
    size_t i;
    bool found;

    found = false;

    if (state != NULL)
    {
        for (i = 0U; i < state->config.sigschemepreferencecount; ++i)
        {
            if (state->config.sigschemepreference[i] == scheme)
            {
                found = true;
                break;
            }
        }
    }

    return found;
}

static qsc_tls_status server_process_client_certificate(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen)
{
    qsc_tls_certificate_view chain[QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES] = { 0U };
    const uint8_t* requestcontext;
    size_t chainlength;
    size_t requestcontextlen;
    qsc_tls_status status;

    chainlength = 0U;
    requestcontext = NULL;
    requestcontextlen = 0U;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && msg != NULL)
    {
        state->clientcertificatelen = 0U;
        state->clientcertificatevalidationattempted = false;
        state->clientcertificatevalidated = false;
        state->clientauthenticated = false;
        qsc_memutils_clear(state->clientcertificate, sizeof(state->clientcertificate));
        status = qsc_tls_certificate_decode_message(msg, msglen, &requestcontext, &requestcontextlen, chain, QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES, &chainlength);

        if (status != qsc_tls_status_success)
        {
            state->lastalert = (status == qsc_tls_status_not_supported) ? qsc_tls_alert_unsupported_extension : qsc_tls_alert_decode_error;
        }
        else if (requestcontextlen != 0U)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }
        else if (chainlength == 0U)
        {
            if (state->config.requireclientauth == true)
            {
                state->lastalert = qsc_tls_alert_certificate_required;
                status = qsc_tls_status_authentication_failure;
            }
            else
            {
                state->phase = qsc_tls_server_phase_waiting_client_finished;
            }
        }
        else if (chain[0U].datalen > sizeof(state->clientcertificate))
        {
            state->lastalert = qsc_tls_alert_bad_certificate;
            status = qsc_tls_status_invalid_length;
        }
        else
        {
            status = server_validate_client_certificate_chain(state, chain, chainlength);

            if (status == qsc_tls_status_success)
            {
                qsc_memutils_copy(state->clientcertificate, chain[0U].data, chain[0U].datalen);
                state->clientcertificatelen = chain[0U].datalen;
                state->clientcertificatevalidated = true;
                state->phase = qsc_tls_server_phase_waiting_client_certificate_verify;
            }
        }
    }

    return status;
}

static qsc_tls_status server_process_client_certificate_verify(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen)
{
    uint8_t cvinput[256U] = { 0U };
    uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    qsc_tls_certificate_view signer;
    const uint8_t* signature;
    size_t cvinputlen;
    size_t signaturelen;
    size_t thashlen;
    qsc_tls_signature_scheme scheme;
    qsc_tls_status status;
    bool verified;

    cvinputlen = 0U;
    signature = NULL;
    signaturelen = 0U;
    thashlen = 0U;
    scheme = qsc_tls_sig_none;
    status = qsc_tls_status_invalid_input;
    verified = false;

    if (state != NULL && msg != NULL)
    {
        status = qsc_tls_handshake_decode_certificate_verify(msg, msglen, &scheme, &signature, &signaturelen);

        if (status != qsc_tls_status_success)
        {
            state->lastalert = qsc_tls_alert_decode_error;
        }
        else if (server_client_auth_signature_scheme_requested(state, scheme) == false ||
            qsc_tls_signature_scheme_is_supported(scheme) == false ||
            qsc_tls_signature_scheme_is_certificate_verify_capable(scheme) == false ||
            qsc_tls_signature_scheme_validate_signature_length(scheme, signaturelen) == false)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }
        else if (state->clientcertificatevalidated == false || state->clientcertificatelen == 0U ||
            state->config.clientcertinterface.verifycertificateverify == NULL)
        {
            state->lastalert = qsc_tls_alert_bad_certificate;
            status = qsc_tls_status_invalid_state;
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_keyschedule_build_certificate_verify_input("TLS 1.3, client CertificateVerify", thash, thashlen, cvinput, sizeof(cvinput), &cvinputlen);
        }

        if (status == qsc_tls_status_success)
        {
            signer.data = state->clientcertificate;
            signer.datalen = state->clientcertificatelen;
            verified = state->config.clientcertinterface.verifycertificateverify(scheme, cvinput, cvinputlen, signature, signaturelen, &signer, state->config.clientcertinterface.state);

            if (verified == false)
            {
                state->lastalert = qsc_tls_certificate_interface_get_last_alert(&state->config.clientcertinterface, true);
                status = qsc_tls_status_authentication_failure;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = server_authorize_client_certificate_identity(state);
        }

        if (status == qsc_tls_status_success)
        {
            state->clientauthenticated = true;
            state->phase = qsc_tls_server_phase_waiting_client_finished;
        }
    }

    qsc_memutils_secure_erase(thash, sizeof(thash));
    qsc_memutils_secure_erase(cvinput, sizeof(cvinput));

    return status;
}

static qsc_tls_status server_process_client_finished(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen)
{
    uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    size_t thashlen;
    qsc_tls_status st;

    thashlen = 0U;

    st = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_keyschedule_verify_finished(state->negotiatedhash, state->keyschedule.clienthandshaketrafficsecret, state->keyschedule.digestsize, thash, thashlen, msg, msglen);
    }

    qsc_memutils_secure_erase(thash, sizeof(thash));

    if (st != qsc_tls_status_success)
    {
        state->lastalert = qsc_tls_alert_decrypt_error;
    }

    return st;
}

typedef struct server_client_hello_context
{
    qsc_tls_alpn_protocols alpn;
    const uint8_t* clientkeyshare;
    const uint8_t* cookie;
    const uint8_t* pskextbody;
    size_t clientkeysharelen;
    size_t cookielen;
    size_t pskextabsbodyoffset;
    size_t pskextbodylen;
    qsc_tls_named_group clientgroup;
    bool earlydataoffered;
    bool hasalpn;
    bool pskdhemode;
} server_client_hello_context;


typedef struct server_client_hello_view
{
    const uint8_t* prefix;
    const uint8_t* extensions;
    size_t prefixlen;
    size_t extensionslen;
} server_client_hello_view;

typedef struct server_extension_view
{
    const uint8_t* data;
    size_t datalen;
    uint16_t type;
    bool present;
} server_extension_view;

static qsc_tls_status server_decode_client_hello_view(const uint8_t* msg, size_t msglen, server_client_hello_view* view)
{
    const uint8_t* span;
    size_t off;
    size_t spanlen;
    uint16_t legacyversion;
    qsc_tls_status status;

    span = NULL;
    off = 0U;
    spanlen = 0U;
    legacyversion = 0U;
    status = qsc_tls_status_invalid_input;

    if (msg != NULL && view != NULL)
    {
        qsc_memutils_clear(view, sizeof(*view));
        view->prefix = msg;
        status = qsc_tls_codec_read_u16(msg, msglen, &off, &legacyversion);

        if (status == qsc_tls_status_success)
        {
            if (off > msglen || 32U > (msglen - off))
            {
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                off += 32U;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector8_span(msg, msglen, &off, &span, &spanlen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector16_span(msg, msglen, &off, &span, &spanlen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector8_span(msg, msglen, &off, &span, &spanlen);
        }

        if (status == qsc_tls_status_success)
        {
            view->prefixlen = off;
            status = qsc_tls_codec_read_vector16_span(msg, msglen, &off, &view->extensions, &view->extensionslen);
        }

        if (status == qsc_tls_status_success && off != msglen)
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

static qsc_tls_status server_next_extension(const uint8_t* extensions, size_t extensionslen, size_t* offset, server_extension_view* view)
{
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (extensions != NULL && offset != NULL && view != NULL && *offset <= extensionslen)
    {
        qsc_memutils_clear(view, sizeof(*view));

        if (*offset == extensionslen)
        {
            status = qsc_tls_status_success;
        }
        else
        {
            status = qsc_tls_codec_read_u16(extensions, extensionslen, offset, &view->type);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_read_vector16_span(extensions, extensionslen, offset, &view->data, &view->datalen);
            }

            if (status == qsc_tls_status_success)
            {
                view->present = true;
            }
        }
    }

    return status;
}

static bool server_retry_extension_is_mutable(uint16_t type)
{
    return (type == (uint16_t)qsc_tls_extension_key_share ||
        type == (uint16_t)qsc_tls_extension_cookie ||
        type == (uint16_t)qsc_tls_extension_early_data ||
        type == (uint16_t)qsc_tls_extension_pre_shared_key ||
        type == 21U); /* padding */
}

static qsc_tls_status server_find_extension(const uint8_t* extensions, size_t extensionslen, uint16_t type, server_extension_view* found)
{
    server_extension_view current;
    size_t offset;
    qsc_tls_status status;

    qsc_memutils_clear(&current, sizeof(current));
    offset = 0U;
    status = qsc_tls_status_invalid_input;

    if (extensions != NULL && found != NULL)
    {
        qsc_memutils_clear(found, sizeof(*found));
        status = qsc_tls_status_success;

        while (offset < extensionslen && status == qsc_tls_status_success && found->present == false)
        {
            status = server_next_extension(extensions, extensionslen, &offset, &current);

            if (status == qsc_tls_status_success && current.present == true && current.type == type)
            {
                *found = current;
            }
        }
    }

    return status;
}

static qsc_tls_status server_compare_retry_psk(const qsc_tls_server_state* state, const server_extension_view* first, const server_extension_view* second)
{
    qsc_tls_psk_identity_view firstids[QSC_TLS_MAX_PSK_IDENTITIES] = { 0U };
    qsc_tls_psk_identity_view secondids[QSC_TLS_MAX_PSK_IDENTITIES] = { 0U };
    const uint8_t* firstbinders[QSC_TLS_MAX_PSK_IDENTITIES] = { 0U };
    const uint8_t* secondbinders[QSC_TLS_MAX_PSK_IDENTITIES] = { 0U };
    size_t firstbinderlens[QSC_TLS_MAX_PSK_IDENTITIES] = { 0U };
    size_t secondbinderlens[QSC_TLS_MAX_PSK_IDENTITIES] = { 0U };
    size_t digestlen;
    size_t firstcount;
    size_t firstoffset;
    size_t i;
    size_t j;
    size_t secondcount;
    size_t secondoffset;
    qsc_tls_status status;
    bool found;

    digestlen = 0U;
    firstcount = 0U;
    firstoffset = 0U;
    i = 0U;
    j = 0U;
    secondcount = 0U;
    secondoffset = 0U;
    status = qsc_tls_status_invalid_input;
    found = false;

    if (state != NULL && first != NULL && second != NULL)
    {
        if (first->present == false)
        {
            status = (second->present == false) ? qsc_tls_status_success : qsc_tls_status_invalid_message;
        }
        else
        {
            digestlen = qsc_tls_transcript_digest_size(state->negotiatedhash);

            if (digestlen == 0U)
            {
                status = qsc_tls_status_invalid_state;
            }
            else
            {
                status = qsc_tls_extensions_decode_pre_shared_key_offer(first->data, first->datalen, firstids, firstbinders, firstbinderlens, QSC_TLS_MAX_PSK_IDENTITIES, &firstcount, &firstoffset);

                if (status == qsc_tls_status_success && second->present == true)
                {
                    status = qsc_tls_extensions_decode_pre_shared_key_offer(second->data, second->datalen, secondids, secondbinders, secondbinderlens, QSC_TLS_MAX_PSK_IDENTITIES, &secondcount, &secondoffset);
                }

                if (status == qsc_tls_status_success && second->present == false)
                {
                    for (i = 0U; i < firstcount && status == qsc_tls_status_success; ++i)
                    {
                        if (firstbinderlens[i] == digestlen)
                        {
                            /* A PSK using the selected cipher-suite hash is compatible
                             * and therefore cannot be removed from ClientHello2. */
                            status = qsc_tls_status_invalid_message;
                        }
                    }
                }
                else if (status == qsc_tls_status_success)
                {
                    if (secondcount == 0U || secondcount > firstcount)
                    {
                        status = qsc_tls_status_invalid_message;
                    }

                    for (i = 0U; i < secondcount && status == qsc_tls_status_success; ++i)
                    {
                        found = false;

                        while (j < firstcount && found == false && status == qsc_tls_status_success)
                        {
                            if (firstids[j].identitylen == secondids[i].identitylen &&
                                firstbinderlens[j] == secondbinderlens[i] &&
                                qsc_memutils_are_equal(firstids[j].identity, secondids[i].identity, firstids[j].identitylen) == true)
                            {
                                found = true;
                            }
                            else if (firstbinderlens[j] == digestlen)
                            {
                                status = qsc_tls_status_invalid_message;
                            }

                            ++j;
                        }

                        if (status == qsc_tls_status_success && found == false)
                        {
                            status = qsc_tls_status_invalid_message;
                        }
                    }

                    while (j < firstcount && status == qsc_tls_status_success)
                    {
                        if (firstbinderlens[j] == digestlen)
                        {
                            status = qsc_tls_status_invalid_message;
                        }

                        ++j;
                    }
                }
            }
        }
    }

    return status;
}

static qsc_tls_status server_validate_retry_client_hello(const qsc_tls_server_state* state, const uint8_t* msg, size_t msglen)
{
    server_client_hello_view first;
    server_client_hello_view second;
    server_extension_view firstext;
    server_extension_view secondext;
    server_extension_view firstpsk;
    server_extension_view secondpsk;
    size_t firstoff;
    size_t secondoff;
    qsc_tls_status status;

    qsc_memutils_clear(&first, sizeof(first));
    qsc_memutils_clear(&second, sizeof(second));
    qsc_memutils_clear(&firstext, sizeof(firstext));
    qsc_memutils_clear(&secondext, sizeof(secondext));
    qsc_memutils_clear(&firstpsk, sizeof(firstpsk));
    qsc_memutils_clear(&secondpsk, sizeof(secondpsk));
    firstoff = 0U;
    secondoff = 0U;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && msg != NULL && state->clientcertificatelen != 0U)
    {
        status = server_decode_client_hello_view(state->clientcertificate, state->clientcertificatelen, &first);

        if (status == qsc_tls_status_success)
        {
            status = server_decode_client_hello_view(msg, msglen, &second);
        }

        if (status == qsc_tls_status_success && (first.prefixlen != second.prefixlen || qsc_memutils_are_equal(first.prefix, second.prefix, first.prefixlen) == false))
        {
            status = qsc_tls_status_invalid_message;
        }

        while (status == qsc_tls_status_success && firstoff < first.extensionslen)
        {
            status = server_next_extension(first.extensions, first.extensionslen, &firstoff, &firstext);

            if (status == qsc_tls_status_success && firstext.present == true && server_retry_extension_is_mutable(firstext.type) == false)
            {
                do
                {
                    status = server_next_extension(second.extensions, second.extensionslen, &secondoff, &secondext);
                }
                while (status == qsc_tls_status_success && secondext.present == true && server_retry_extension_is_mutable(secondext.type) == true);

                if (status == qsc_tls_status_success && (secondext.present == false || firstext.type != secondext.type ||
                    firstext.datalen != secondext.datalen ||
                    (firstext.datalen != 0U && qsc_memutils_are_equal(firstext.data, secondext.data, firstext.datalen) == false)))
                {
                    status = qsc_tls_status_invalid_message;
                }
            }
        }

        while (status == qsc_tls_status_success && secondoff < second.extensionslen)
        {
            status = server_next_extension(second.extensions, second.extensionslen, &secondoff, &secondext);

            if (status == qsc_tls_status_success && secondext.present == true && server_retry_extension_is_mutable(secondext.type) == false)
            {
                status = qsc_tls_status_invalid_message;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = server_find_extension(first.extensions, first.extensionslen, (uint16_t)qsc_tls_extension_pre_shared_key, &firstpsk);
        }

        if (status == qsc_tls_status_success)
        {
            status = server_find_extension(second.extensions, second.extensionslen, (uint16_t)qsc_tls_extension_pre_shared_key, &secondpsk);
        }

        if (status == qsc_tls_status_success)
        {
            status = server_compare_retry_psk(state, &firstpsk, &secondpsk);
        }
    }

    return status;
}

static qsc_tls_status server_parse_client_hello(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen, const uint8_t** suites, 
    size_t* suiteslen, const uint8_t** extblock, size_t* extblocklen)
{
    uint8_t clientrandom[32U] = { 0U };
    const uint8_t* comp;
    const uint8_t* sid;
    size_t complen;
    size_t off;
    size_t sidlen;
    uint16_t legacyversion;
    qsc_tls_status status;

    comp = NULL;
    sid = NULL;
    complen = 0U;
    off = 0U;
    sidlen = 0U;
    legacyversion = 0U;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && msg != NULL && suites != NULL && suiteslen != NULL && extblock != NULL && extblocklen != NULL)
    {
        *suites = NULL;
        *suiteslen = 0U;
        *extblock = NULL;
        *extblocklen = 0U;
        state->servernamelen = 0U;
        state->servernamereceived = false;
        state->servernameaccepted = false;
        qsc_memutils_clear(state->servername, sizeof(state->servername));

        status = qsc_tls_codec_read_u16(msg, msglen, &off, &legacyversion);

        if (status == qsc_tls_status_success && legacyversion != QSC_TLS_PROTOCOL_VERSION_12)
        {
            state->lastalert = qsc_tls_alert_protocol_version;
            status = qsc_tls_status_not_supported;
        }

        if (status == qsc_tls_status_success)
        {
            if (off > msglen || (msglen - off) < sizeof(clientrandom))
            {
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                qsc_memutils_copy(clientrandom, msg + off, sizeof(clientrandom));
                off += sizeof(clientrandom);
            }
        }

        if (status == qsc_tls_status_success)
        {
            if (state->helloretryrequestsent == true)
            {
                if (qsc_memutils_are_equal(clientrandom, state->clientrandom, sizeof(clientrandom)) == false)
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                    status = qsc_tls_status_invalid_message;
                }
            }
            else
            {
                qsc_memutils_copy(state->clientrandom, clientrandom, sizeof(state->clientrandom));
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector8_span(msg, msglen, &off, &sid, &sidlen);
        }

        if (status == qsc_tls_status_success && sidlen > sizeof(state->legacy_session_id))
        {
            status = qsc_tls_status_invalid_length;
        }

        if (status == qsc_tls_status_success)
        {
            if (state->helloretryrequestsent == true)
            {
                if (sidlen != state->legacy_session_id_len || (sidlen != 0U && qsc_memutils_are_equal(sid, state->legacy_session_id, sidlen) == false))
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                    status = qsc_tls_status_invalid_message;
                }
            }
            else
            {
                qsc_memutils_clear(state->legacy_session_id, sizeof(state->legacy_session_id));

                if (sidlen != 0U)
                {
                    qsc_memutils_copy(state->legacy_session_id, sid, sidlen);
                }

                state->legacy_session_id_len = sidlen;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector16_span(msg, msglen, &off, suites, suiteslen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector8_span(msg, msglen, &off, &comp, &complen);
        }

        if (status == qsc_tls_status_success && (complen != 1U || comp[0U] != 0U))
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector16_span(msg, msglen, &off, extblock, extblocklen);
        }

        if (status == qsc_tls_status_success && off != msglen)
        {
            state->lastalert = qsc_tls_alert_decode_error;
            status = qsc_tls_status_invalid_length;
        }
    }

    qsc_memutils_secure_erase(clientrandom, sizeof(clientrandom));

    return status;
}

static qsc_tls_status server_select_client_hello_cipher(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen, const uint8_t* suites, size_t suiteslen)
{
    uint8_t header[4U] = { 0U };
    qsc_tls_cipher_suite selected;
    qsc_tls_hash_algorithm hash;
    qsc_tls_status status;

    selected = qsc_tls_cipher_suite_none;
    hash = qsc_tls_hash_none;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && msg != NULL && suites != NULL && suiteslen != 0U)
    {
        status = qsc_tls_extensions_select_cipher_suite(suites, suiteslen, state->config.ciphersuitepreference,
            state->config.ciphersuitepreferencecount, &selected);

        if (status == qsc_tls_status_success && state->helloretryrequestsent == true && selected != state->negotiatedsuite)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            hash = qsc_tls_keyschedule_suite_hash(selected);

            if (hash == qsc_tls_hash_none)
            {
                status = qsc_tls_status_not_supported;
            }
        }

        if (status == qsc_tls_status_success && state->helloretryrequestsent == false && hash != state->negotiatedhash)
        {
            qsc_tls_transcript_dispose(&state->transcript);
            status = qsc_tls_transcript_initialize(&state->transcript, hash);

            if (status == qsc_tls_status_success)
            {
                header[0U] = (uint8_t)qsc_tls_handshake_type_client_hello;
                header[1U] = (uint8_t)((msglen >> 16) & 0xFFU);
                header[2U] = (uint8_t)((msglen >> 8) & 0xFFU);
                header[3U] = (uint8_t)(msglen & 0xFFU);
                status = qsc_tls_transcript_update(&state->transcript, header, sizeof(header));
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_transcript_update(&state->transcript, msg, msglen);
            }
        }

        if (status == qsc_tls_status_success)
        {
            state->negotiatedsuite = selected;
            state->negotiatedhash = hash;
        }
    }

    return status;
}

static qsc_tls_status server_validate_client_hello_extension_block(qsc_tls_server_state* state, const uint8_t* extblock, size_t extblocklen)
{
    uint8_t seen[8192U] = { 0U };
    const uint8_t* ebody;
    size_t eblen;
    size_t eoff;
    size_t index;
    uint16_t etype;
    uint8_t mask;
    qsc_tls_status status;

    ebody = NULL;
    eblen = 0U;
    eoff = 0U;
    index = 0U;
    etype = 0U;
    mask = 0U;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && extblock != NULL)
    {
        status = qsc_tls_status_success;

        while (eoff < extblocklen && status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_u16(extblock, extblocklen, &eoff, &etype);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_read_vector16_span(extblock, extblocklen, &eoff, &ebody, &eblen);
            }

            if (status == qsc_tls_status_success)
            {
                index = ((size_t)etype >> 3U);
                mask = (uint8_t)(1U << (etype & 7U));

                if ((seen[index] & mask) != 0U)
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    seen[index] |= mask;
                }
            }
        }

        if (status == qsc_tls_status_success && eoff != extblocklen)
        {
            state->lastalert = qsc_tls_alert_decode_error;
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

static qsc_tls_status server_decode_psk_key_exchange_modes(const uint8_t* input, size_t inplen, bool* pskdhemode)
{
    size_t i;
    size_t modecount;
    qsc_tls_status status;

    i = 0U;
    modecount = 0U;
    status = qsc_tls_status_invalid_input;

    if (input != NULL && pskdhemode != NULL)
    {
        *pskdhemode = false;

        if (inplen >= 2U)
        {
            modecount = (size_t)input[0U];

            if (modecount != 0U && modecount == (inplen - 1U))
            {
                status = qsc_tls_status_success;

                for (i = 0U; i < modecount; ++i)
                {
                    if (input[1U + i] == (uint8_t)qsc_tls_psk_key_exchange_mode_psk_dhe_ke)
                    {
                        *pskdhemode = true;
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
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

static qsc_tls_status server_decode_supported_groups(const uint8_t* input, size_t inplen, qsc_tls_named_group* groups, size_t capacity, size_t* count)
{
    const uint8_t* list;
    size_t i;
    size_t listlen;
    size_t n;
    size_t off;
    qsc_tls_named_group group;
    qsc_tls_status status;

    list = NULL;
    i = 0U;
    listlen = 0U;
    n = 0U;
    off = 0U;
    group = qsc_tls_group_none;
    status = qsc_tls_status_invalid_input;

    if (input != NULL && groups != NULL && count != NULL)
    {
        *count = 0U;
        status = qsc_tls_codec_read_vector16_span(input, inplen, &off, &list, &listlen);

        if (status == qsc_tls_status_success)
        {
            if (off != inplen || list == NULL || listlen < 2U || (listlen % 2U) != 0U)
            {
                status = qsc_tls_status_invalid_length;
            }
        }

        for (i = 0U; i < listlen && status == qsc_tls_status_success; i += 2U)
        {
            group = (qsc_tls_named_group)qsc_intutils_be8to16(list + i);

            if (qsc_tls_groups_is_supported(group) == true)
            {
                if (n < capacity)
                {
                    groups[n] = group;
                    ++n;
                }
                else
                {
                    status = qsc_tls_status_invalid_length;
                }
            }
        }

        if (status == qsc_tls_status_success)
        {
            *count = n;
        }
    }

    return status;
}

static qsc_tls_status server_decode_signature_algorithms(const uint8_t* input, size_t inplen, qsc_tls_signature_scheme* schemes, size_t capacity, size_t* count)
{
    const uint8_t* list;
    size_t i;
    size_t listlen;
    size_t n;
    size_t off;
    qsc_tls_signature_scheme scheme;
    qsc_tls_status status;

    list = NULL;
    i = 0U;
    listlen = 0U;
    n = 0U;
    off = 0U;
    scheme = qsc_tls_sig_none;
    status = qsc_tls_status_invalid_input;

    if (input != NULL && schemes != NULL && count != NULL)
    {
        *count = 0U;
        status = qsc_tls_codec_read_vector16_span(input, inplen, &off, &list, &listlen);

        if (status == qsc_tls_status_success)
        {
            if (off != inplen || list == NULL || listlen < 2U || (listlen % 2U) != 0U)
            {
                status = qsc_tls_status_invalid_length;
            }
        }

        for (i = 0U; i < listlen && status == qsc_tls_status_success; i += 2U)
        {
            scheme = (qsc_tls_signature_scheme)qsc_intutils_be8to16(list + i);

            if (qsc_tls_signature_scheme_is_supported(scheme) == true)
            {
                if (n < capacity)
                {
                    schemes[n] = scheme;
                    ++n;
                }
                else
                {
                    status = qsc_tls_status_invalid_length;
                }
            }
        }

        if (status == qsc_tls_status_success)
        {
            *count = n;
        }
    }

    return status;
}

static qsc_tls_status server_decode_key_share_client_hello(const uint8_t* input, size_t inplen, qsc_tls_named_group* groups, const uint8_t** shares, size_t* sharelens, size_t capacity, size_t* count)
{
    uint8_t seen[8192U] = { 0U };
    const uint8_t* list;
    size_t i;
    size_t index;
    size_t listlen;
    size_t n;
    size_t off;
    uint16_t gid;
    uint16_t sharelen;
    uint8_t mask;
    qsc_tls_named_group group;
    qsc_tls_status status;

    list = NULL;
    i = 0U;
    index = 0U;
    listlen = 0U;
    n = 0U;
    off = 0U;
    gid = 0U;
    sharelen = 0U;
    mask = 0U;
    group = qsc_tls_group_none;
    status = qsc_tls_status_invalid_input;

    if (input != NULL && groups != NULL && shares != NULL && sharelens != NULL && count != NULL)
    {
        *count = 0U;
        status = qsc_tls_codec_read_vector16_span(input, inplen, &off, &list, &listlen);

        if (status == qsc_tls_status_success && off != inplen)
        {
            status = qsc_tls_status_invalid_length;
        }

        while (status == qsc_tls_status_success && i < listlen)
        {
            if ((listlen - i) < 4U)
            {
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                gid = qsc_intutils_be8to16(list + i);
                i += 2U;
                sharelen = qsc_intutils_be8to16(list + i);
                i += 2U;

                if (sharelen == 0U || (size_t)sharelen > (listlen - i))
                {
                    status = qsc_tls_status_invalid_length;
                }
                else
                {
                    index = ((size_t)gid >> 3U);
                    mask = (uint8_t)(1U << (gid & 7U));

                    if ((seen[index] & mask) != 0U)
                    {
                        status = qsc_tls_status_invalid_message;
                    }
                    else
                    {
                        seen[index] |= mask;
                        group = (qsc_tls_named_group)gid;

                        if (qsc_tls_groups_is_supported(group) == true)
                        {
                            if (n < capacity)
                            {
                                groups[n] = group;
                                shares[n] = list + i;
                                sharelens[n] = (size_t)sharelen;
                                ++n;
                            }
                            else
                            {
                                status = qsc_tls_status_invalid_length;
                            }
                        }

                        i += (size_t)sharelen;
                    }
                }
            }
        }

        if (status == qsc_tls_status_success && i != listlen)
        {
            status = qsc_tls_status_invalid_length;
        }

        if (status == qsc_tls_status_success)
        {
            *count = n;
        }
    }

    return status;
}

static bool server_key_share_list_is_consistent(const qsc_tls_named_group* supportedgroups, size_t supportedgroupcount, const qsc_tls_named_group* keysharegroups, size_t keysharecount)
{
    size_t i;
    size_t j;
    size_t nextsupported;
    bool found;
    bool res;

    i = 0U;
    j = 0U;
    nextsupported = 0U;
    found = false;
    res = true;

    if ((supportedgroups == NULL && supportedgroupcount != 0U) || (keysharegroups == NULL && keysharecount != 0U))
    {
        res = false;
    }
    else
    {
        for (i = 0U; i < keysharecount && res == true; ++i)
        {
            for (j = 0U; j < i; ++j)
            {
                if (keysharegroups[j] == keysharegroups[i])
                {
                    res = false;
                    break;
                }
            }

            found = false;

            while (nextsupported < supportedgroupcount && res == true)
            {
                if (supportedgroups[nextsupported] == keysharegroups[i])
                {
                    found = true;
                    ++nextsupported;
                    break;
                }

                ++nextsupported;
            }

            if (found == false)
            {
                res = false;
            }
        }
    }

    return res;
}

static qsc_tls_status server_parse_client_hello_extensions(qsc_tls_server_state* state, const uint8_t* msg, const uint8_t* extblock, size_t extblocklen, server_client_hello_context* context)
{
    qsc_tls_named_group clientgroups[QSC_TLS_MAX_GROUPS] = { 0 };
    qsc_tls_named_group ksgroups[QSC_TLS_MAX_GROUPS] = { 0 };
    qsc_tls_signature_scheme clientsigs[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { 0 };
    qsc_tls_signature_scheme clientcertsigs[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { 0 };
    const uint8_t* ksshares[QSC_TLS_MAX_GROUPS] = { 0 };
    size_t kssharelens[QSC_TLS_MAX_GROUPS] = { 0 };
    const char* snihost;
    const uint8_t* ebody;
    size_t clientgroupcount;
    size_t clientsigcount;
    size_t clientcertsigcount;
    size_t eblen;
    size_t ebodyoffset;
    size_t eoff;
    size_t extblockabsoffset;
    size_t i;
    size_t j;
    size_t kscount;
    size_t snihostlen;
    uint16_t etype;
    bool acceptstls13;
    bool sawcookie;
    bool sawkeyshare;
    bool sawpre_shared_key;
    bool sawpskmodes;
    bool sawsignaturealgorithms;
    bool sawsignaturealgorithmscert;
    bool sawsupportedgroups;
    bool sawsupportedversions;
    qsc_tls_status status;

    snihost = NULL;
    ebody = NULL;
    clientgroupcount = 0U;
    clientsigcount = 0U;
    clientcertsigcount = 0U;
    eblen = 0U;
    ebodyoffset = 0U;
    eoff = 0U;
    extblockabsoffset = 0U;
    i = 0U;
    j = 0U;
    kscount = 0U;
    snihostlen = 0U;
    etype = 0U;
    acceptstls13 = false;
    sawcookie = false;
    sawkeyshare = false;
    sawpre_shared_key = false;
    sawpskmodes = false;
    sawsignaturealgorithms = false;
    sawsignaturealgorithmscert = false;
    sawsupportedgroups = false;
    sawsupportedversions = false;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && msg != NULL && extblock != NULL && context != NULL)
    {
        qsc_memutils_clear(context, sizeof(*context));
        context->clientgroup = qsc_tls_group_none;
        extblockabsoffset = (size_t)(extblock - msg);
        status = server_validate_client_hello_extension_block(state, extblock, extblocklen);

        while (eoff < extblocklen && status == qsc_tls_status_success)
        {
            ebody = NULL;
            eblen = 0U;
            ebodyoffset = 0U;
            etype = 0U;
            status = qsc_tls_codec_read_u16(extblock, extblocklen, &eoff, &etype);

            if (status == qsc_tls_status_success)
            {
                ebodyoffset = eoff + 2U;
                status = qsc_tls_codec_read_vector16_span(extblock, extblocklen, &eoff, &ebody, &eblen);
            }

            if (status == qsc_tls_status_success && etype == (uint16_t)qsc_tls_extension_pre_shared_key && eoff != extblocklen)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }

            if (status == qsc_tls_status_success)
            {
                if (etype == (uint16_t)qsc_tls_extension_supported_versions)
                {
                    status = qsc_tls_extensions_decode_supported_versions_client(ebody, eblen, &acceptstls13);

                    if (status == qsc_tls_status_success)
                    {
                        sawsupportedversions = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_supported_groups)
                {
                    status = server_decode_supported_groups(ebody, eblen, clientgroups, QSC_TLS_MAX_GROUPS, &clientgroupcount);

                    if (status == qsc_tls_status_success)
                    {
                        sawsupportedgroups = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_signature_algorithms)
                {
                    status = server_decode_signature_algorithms(ebody, eblen, clientsigs, QSC_TLS_MAX_SIGNATURE_SCHEMES, &clientsigcount);

                    if (status == qsc_tls_status_success)
                    {
                        sawsignaturealgorithms = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_signature_algorithms_cert)
                {
                    status = server_decode_signature_algorithms(ebody, eblen, clientcertsigs, QSC_TLS_MAX_SIGNATURE_SCHEMES, &clientcertsigcount);

                    if (status == qsc_tls_status_success)
                    {
                        sawsignaturealgorithmscert = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_key_share)
                {
                    status = server_decode_key_share_client_hello(ebody, eblen, ksgroups, ksshares, kssharelens, QSC_TLS_MAX_GROUPS, &kscount);

                    if (status == qsc_tls_status_success)
                    {
                        sawkeyshare = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_psk_key_exchange_modes)
                {
                    status = server_decode_psk_key_exchange_modes(ebody, eblen, &context->pskdhemode);

                    if (status == qsc_tls_status_success)
                    {
                        sawpskmodes = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_application_layer_protocol_negotiation)
                {
                    status = qsc_tls_extensions_decode_alpn(ebody, eblen, &context->alpn);

                    if (status == qsc_tls_status_success)
                    {
                        context->hasalpn = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_cookie)
                {
                    status = qsc_tls_extensions_decode_cookie(ebody, eblen, &context->cookie, &context->cookielen);

                    if (status == qsc_tls_status_success)
                    {
                        sawcookie = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_early_data)
                {
                    if (eblen == 0U)
                    {
                        context->earlydataoffered = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                        status = qsc_tls_status_invalid_length;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_pre_shared_key)
                {
                    sawpre_shared_key = true;
                    context->pskextbody = ebody;
                    context->pskextbodylen = eblen;

                    if (extblockabsoffset <= SIZE_MAX - ebodyoffset)
                    {
                        context->pskextabsbodyoffset = extblockabsoffset + ebodyoffset;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                        status = qsc_tls_status_invalid_length;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_server_name)
                {
                    status = qsc_tls_extensions_decode_server_name(ebody, eblen, &snihost, &snihostlen);

                    if (status == qsc_tls_status_success)
                    {
                        if (snihostlen == 0U || snihostlen > QSC_TLS_MAX_HOSTNAME_SIZE)
                        {
                            state->lastalert = qsc_tls_alert_unrecognized_name;
                            status = qsc_tls_status_invalid_length;
                        }
                        else
                        {
                            qsc_memutils_copy(state->servername, snihost, snihostlen);
                            state->servername[snihostlen] = '\0';
                            state->servernamelen = snihostlen;
                            state->servernamereceived = true;
                        }
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
            }
        }

        if (status == qsc_tls_status_success && (sawsupportedversions == false || acceptstls13 == false))
        {
            state->lastalert = qsc_tls_alert_protocol_version;
            status = qsc_tls_status_not_supported;
        }

        if (status == qsc_tls_status_success && sawpre_shared_key == false &&
            (sawsignaturealgorithms == false || sawsupportedgroups == false))
        {
            state->lastalert = qsc_tls_alert_missing_extension;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success && sawsupportedgroups != sawkeyshare)
        {
            state->lastalert = qsc_tls_alert_missing_extension;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success && sawpre_shared_key == true && sawpskmodes == false)
        {
            state->lastalert = qsc_tls_alert_missing_extension;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success && context->earlydataoffered == true && sawpre_shared_key == false)
        {
            state->lastalert = qsc_tls_alert_missing_extension;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success && state->helloretryrequestsent == false && sawcookie == true)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success && state->helloretryrequestsent == true)
        {
            if (context->earlydataoffered == true)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }
            else if (sawcookie == false || context->cookielen != state->hrrcookielen ||
                qsc_memutils_are_equal(context->cookie, state->hrrcookie, state->hrrcookielen) == false)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }
            else if (sawkeyshare == false || kscount != 1U || ksgroups[0U] != state->hrrgroup)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }
        }

        if (status == qsc_tls_status_success && sawkeyshare == true &&
            server_key_share_list_is_consistent(clientgroups, clientgroupcount, ksgroups, kscount) == false)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            state->clientcapabilities.groupcount = clientgroupcount;

            for (i = 0U; i < clientgroupcount; ++i)
            {
                state->clientcapabilities.groups[i] = clientgroups[i];
            }

            state->clientcapabilities.sigschemecount = clientsigcount;

            for (i = 0U; i < clientsigcount; ++i)
            {
                state->clientcapabilities.sigschemes[i] = clientsigs[i];
            }

            qsc_memutils_clear(state->clientcapabilities.certsigschemes, sizeof(state->clientcapabilities.certsigschemes));

            if (sawsignaturealgorithmscert == true)
            {
                state->clientcapabilities.certsigschemecount = clientcertsigcount;

                for (i = 0U; i < clientcertsigcount; ++i)
                {
                    state->clientcapabilities.certsigschemes[i] = clientcertsigs[i];
                }
            }
            else
            {
                state->clientcapabilities.certsigschemecount = clientsigcount;

                for (i = 0U; i < clientsigcount; ++i)
                {
                    state->clientcapabilities.certsigschemes[i] = clientsigs[i];
                }
            }

            for (i = 0U; i < state->config.groupspreferencecount && context->clientgroup == qsc_tls_group_none; ++i)
            {
                for (j = 0U; j < kscount; ++j)
                {
                    if (state->config.groupspreference[i] == ksgroups[j])
                    {
                        context->clientgroup = ksgroups[j];
                        context->clientkeyshare = ksshares[j];
                        context->clientkeysharelen = kssharelens[j];
                        break;
                    }
                }
            }
        }
    }

    return status;
}

static bool server_local_certificate_has_client_verify_scheme(const qsc_tls_server_state* state, const qsc_tls_local_certificate_config* localcert)
{
    size_t i;
    size_t j;
    bool res;

    i = 0U;
    j = 0U;
    res = false;

    if (state != NULL && localcert != NULL)
    {
        for (i = 0U; i < state->config.sigschemepreferencecount && res == false; ++i)
        {
            if (server_signature_scheme_is_local_certificate_compatible(localcert, state->config.sigschemepreference[i]) == true)
            {
                for (j = 0U; j < state->clientcapabilities.sigschemecount; ++j)
                {
                    if (state->config.sigschemepreference[i] == state->clientcapabilities.sigschemes[j])
                    {
                        res = true;
                        break;
                    }
                }
            }
        }
    }

    return res;
}

static bool server_certificate_signature_scheme_is_allowed(qsc_x509_signature_algorithm algorithm, const qsc_tls_signature_scheme* schemes, size_t schemecount)
{
    size_t i;
    bool res;

    i = 0U;
    res = false;

    if (schemes != NULL && schemecount != 0U)
    {
        for (i = 0U; i < schemecount; ++i)
        {
            if (qsc_tls_signature_scheme_matches_x509_algorithm(schemes[i], algorithm) == true)
            {
                res = true;
                break;
            }
        }
    }

    return res;
}

static bool server_certificate_chain_matches_client_certificate_schemes(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_signature_scheme* schemes, size_t schemecount)
{
    qsc_x509_certificate* certificate;
    size_t i;
    qsc_asn1_status xstatus;
    bool res;

    res = false;
    certificate = qsc_memutils_malloc(sizeof(qsc_x509_certificate));

    if (certificate != NULL)
    {
        qsc_memutils_clear(certificate, sizeof(qsc_x509_certificate));
        i = 0U;

        if (chain != NULL && chainlength != 0U && schemes != NULL && schemecount != 0U)
        {
            res = true;

            for (i = 0U; i < chainlength && res == true; ++i)
            {
                if (chain[i].data == NULL || chain[i].datalen == 0U)
                {
                    res = false;
                }
                else
                {
                    qsc_memutils_clear(certificate, sizeof(qsc_x509_certificate));
                    xstatus = qsc_x509_certificate_decode_der(chain[i].data, chain[i].datalen, certificate);

                    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
                    {
                        if (i + 1U == chainlength && qsc_x509_name_equals(&certificate->subject, &certificate->issuer) == true)
                        {
                            /* A self-issued trust anchor at the end of the transmitted path is not
                             * constrained by the peer's certificate signature-algorithm list. */
                        }
                        else if (server_certificate_signature_scheme_is_allowed(certificate->signaturealgorithm.signature, schemes, schemecount) == false)
                        {
                            res = false;
                        }
                    }

                    /* Certificate syntax and trust are enforced by the configured certificate
                     * interface. Preserve custom certificate callbacks by applying this X.509
                     * selection preference only to entries that decode as X.509. */
                    qsc_x509_certificate_clear(certificate);
                }
            }
        }

        qsc_x509_certificate_clear(certificate);
        qsc_memutils_alloc_free(certificate);
    }

    return res;
}

static qsc_tls_status server_apply_client_hello_policy(qsc_tls_server_state* state, const server_client_hello_context* context)
{
    size_t compatiblematch;
    size_t firstmatch;
    size_t firstverifymatch;
    size_t i;
    size_t selectedmatch;
    bool servernamematch;
    qsc_tls_status status;

    compatiblematch = 0U;
    firstmatch = 0U;
    firstverifymatch = 0U;
    i = 0U;
    selectedmatch = 0U;
    servernamematch = false;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && context != NULL)
    {
        status = qsc_tls_status_success;

        if (state->config.identitycount != 0U)
        {
            firstmatch = state->config.identitycount;
            firstverifymatch = state->config.identitycount;
            compatiblematch = state->config.identitycount;
            selectedmatch = state->config.identitycount;

            if (state->servernamereceived == true)
            {
                for (i = 0U; i < state->config.identitycount; ++i)
                {
                    if (state->config.identities[i].configured == true && qsc_x509_dns_name_match(state->config.identities[i].hostname, state->servername) == true)
                    {
                        if (firstmatch == state->config.identitycount)
                        {
                            firstmatch = i;
                        }

                        if (server_local_certificate_has_client_verify_scheme(state, &state->config.identities[i].localcert) == true)
                        {
                            if (firstverifymatch == state->config.identitycount)
                            {
                                firstverifymatch = i;
                            }

                            if (state->clientcapabilities.certsigschemecount != 0U &&
                                server_certificate_chain_matches_client_certificate_schemes(state->config.identities[i].localcert.chain,
                                state->config.identities[i].localcert.chainlength, state->clientcapabilities.certsigschemes,
                                state->clientcapabilities.certsigschemecount) == true)
                            {
                                compatiblematch = i;
                                break;
                            }
                        }
                    }
                }

                if (compatiblematch != state->config.identitycount)
                {
                    selectedmatch = compatiblematch;
                }
                else if (firstverifymatch != state->config.identitycount)
                {
                    /* RFC 9846 permits a fallback certificate chain when no chain
                     * can be produced using only the advertised certificate
                     * signature algorithms. CertificateVerify still requires a
                     * mutually supported signature scheme. */
                    selectedmatch = firstverifymatch;
                }
                else if (firstmatch != state->config.identitycount)
                {
                    selectedmatch = firstmatch;
                }

                if (selectedmatch != state->config.identitycount)
                {
                    state->config.localcert = state->config.identities[selectedmatch].localcert;
                    state->servernameaccepted = true;
                    servernamematch = true;
                }
            }

            if (state->config.requiresni == true && servernamematch == false)
            {
                state->lastalert = qsc_tls_alert_unrecognized_name;
                status = qsc_tls_status_not_supported;
            }
        }
        else if (state->config.requiresni == true && state->servernamereceived == false)
        {
            state->lastalert = qsc_tls_alert_unrecognized_name;
            status = qsc_tls_status_not_supported;
        }

        if (status == qsc_tls_status_success)
        {
            if (context->hasalpn == true)
            {
                state->clientalpncount = context->alpn.protocolcount;

                for (i = 0U; i < context->alpn.protocolcount; ++i)
                {
                    qsc_memutils_copy(state->clientalpn[i], context->alpn.protocols[i], context->alpn.protocollens[i]);
                    state->clientalpnlens[i] = context->alpn.protocollens[i];
                }

                if (state->config.alpn.configured == true)
                {
                    status = qsc_tls_extensions_select_alpn(&context->alpn, &state->config.alpn, state->selectedalpn, sizeof(state->selectedalpn), &state->selectedalpnlen);

                    if (status == qsc_tls_status_success)
                    {
                        state->alpnselected = true;
                    }
                    else if (state->config.alpn.required == true)
                    {
                        state->lastalert = qsc_tls_alert_no_application_protocol;
                    }
                    else
                    {
                        status = qsc_tls_status_success;
                    }
                }
            }
            else if (state->config.alpn.required == true)
            {
                state->lastalert = qsc_tls_alert_no_application_protocol;
                status = qsc_tls_status_not_supported;
            }
        }
    }

    return status;
}

static bool server_resumption_ticket_is_acceptable(const qsc_tls_server_state* state, const qsc_tls_psk_identity_view* identity, const qsc_tls_session_ticket* ticket, bool* agevalid)
{
    uint64_t elapsed;
    uint64_t maxage;
    uint64_t now;
    uint64_t ticketage;
    uint64_t difference;
    bool res;

    elapsed = 0ULL;
    maxage = 0ULL;
    now = 0ULL;
    ticketage = 0ULL;
    difference = 0ULL;
    res = false;

    if (agevalid != NULL)
    {
        *agevalid = false;
    }

    if (state != NULL && identity != NULL && ticket != NULL && agevalid != NULL)
    {
        if (ticket->protocolversion == QSC_TLS_PROTOCOL_VERSION_13 && ticket->lifetime != 0U &&
            ticket->lifetime <= QSC_TLS_SESSION_TICKET_LIFETIME_MAX && ticket->issuetimems != 0ULL &&
            ticket->ticketlen == identity->identitylen && ticket->ticketlen != 0U &&
            ticket->resumptionsecretlen == qsc_tls_transcript_digest_size(state->negotiatedhash) && ticket->resumptionsecretlen != 0U &&
            qsc_tls_keyschedule_suite_hash(ticket->suite) == state->negotiatedhash &&
            ticket->servernamelen == state->servernamelen &&
            (ticket->servernamelen == 0U || qsc_memutils_are_equal(ticket->servername, (const uint8_t*)state->servername, ticket->servernamelen) == true) &&
            qsc_memutils_are_equal(ticket->ticket, identity->identity, ticket->ticketlen) == true)
        {
            now = qsc_timestamp_epochtime_milliseconds();

            if (now >= ticket->issuetimems)
            {
                elapsed = now - ticket->issuetimems;
                maxage = (uint64_t)ticket->lifetime * 1000ULL;

                if (elapsed <= maxage)
                {
                    ticketage = (uint64_t)((uint32_t)(identity->obfuscatedticketage - ticket->ageadd));
                    difference = (elapsed >= ticketage) ? (elapsed - ticketage) : (ticketage - elapsed);
                    *agevalid = (difference <= QSC_TLS_SESSION_TICKET_AGE_TOLERANCE_MS);
                    res = true;
                }
            }
        }
    }

    return res;
}

static qsc_tls_status server_validate_client_psk_identity(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen,
    const server_client_hello_context* context, const qsc_tls_psk_identity_view* identity, const uint8_t* rxbinder,
    size_t rxbinderlen, size_t binderblockoff, size_t identityindex, bool* accepted)
{
    qsc_tls_key_schedule_state ksscratch = { 0 };
    qsc_tls_session_ticket ticket = { 0U };
    qsc_tls_transcript_state scratch = { 0 };
    uint8_t expectedbinder[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t header[4U] = { 0U };
    uint8_t trunchash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    size_t expectedbinderlen;
    size_t truncbodyoff;
    size_t trunchashlen;
    qsc_tls_status cryptostatus;
    qsc_tls_status status;
    bool agevalid;
    bool have;
    bool usable;

    expectedbinderlen = 0U;
    truncbodyoff = 0U;
    trunchashlen = 0U;
    cryptostatus = qsc_tls_status_failure;
    status = qsc_tls_status_invalid_input;
    agevalid = false;
    have = false;
    usable = false;

    if (accepted != NULL)
    {
        *accepted = false;
    }

    if (state != NULL && msg != NULL && context != NULL && identity != NULL && rxbinder != NULL && accepted != NULL)
    {
        status = qsc_tls_status_success;
        have = state->config.psklookup(identity->identity, identity->identitylen, &ticket, state->config.psklookupstate);

        if (have == true)
        {
            usable = server_resumption_ticket_is_acceptable(state, identity, &ticket, &agevalid);
        }

        if (usable == true && context->pskextabsbodyoffset <= msglen && binderblockoff <= (msglen - context->pskextabsbodyoffset))
        {
            truncbodyoff = context->pskextabsbodyoffset + binderblockoff;
            header[0U] = (uint8_t)qsc_tls_handshake_type_client_hello;
            header[1U] = (uint8_t)((msglen >> 16) & 0xFFU);
            header[2U] = (uint8_t)((msglen >> 8) & 0xFFU);
            header[3U] = (uint8_t)(msglen & 0xFFU);

            if (state->helloretryrequestsent == true)
            {
                if (state->hrrtranscript.initialized == true && state->hrrtranscript.hash == state->negotiatedhash)
                {
                    qsc_memutils_copy(&scratch, &state->hrrtranscript, sizeof(scratch));
                    cryptostatus = qsc_tls_status_success;
                }
                else
                {
                    cryptostatus = qsc_tls_status_invalid_state;
                }
            }
            else
            {
                cryptostatus = qsc_tls_transcript_initialize(&scratch, state->negotiatedhash);
            }

            if (cryptostatus == qsc_tls_status_success)
            {
                cryptostatus = qsc_tls_transcript_update(&scratch, header, sizeof(header));
            }

            if (cryptostatus == qsc_tls_status_success)
            {
                cryptostatus = qsc_tls_transcript_update(&scratch, msg, truncbodyoff);
            }

            if (cryptostatus == qsc_tls_status_success)
            {
                cryptostatus = qsc_tls_transcript_snapshot(&scratch, trunchash, sizeof(trunchash), &trunchashlen);
            }

            if (cryptostatus == qsc_tls_status_success)
            {
                cryptostatus = qsc_tls_keyschedule_state_initialize(&ksscratch, state->negotiatedhash);
            }

            if (cryptostatus == qsc_tls_status_success)
            {
                cryptostatus = qsc_tls_keyschedule_extract_early_secret(&ksscratch, ticket.resumptionsecret, ticket.resumptionsecretlen);
            }

            if (cryptostatus == qsc_tls_status_success)
            {
                cryptostatus = qsc_tls_keyschedule_derive_binder_key(&ksscratch, false);
            }

            if (cryptostatus == qsc_tls_status_success)
            {
                cryptostatus = qsc_tls_keyschedule_compute_psk_binder(state->negotiatedhash, ksscratch.binderkey, ksscratch.digestsize, trunchash, trunchashlen, expectedbinder, sizeof(expectedbinder), &expectedbinderlen);
            }

            if (cryptostatus != qsc_tls_status_success)
            {
                state->lastalert = qsc_tls_alert_internal_error;
                status = cryptostatus;
            }
            else if (rxbinderlen != expectedbinderlen || qsc_memutils_are_equal(expectedbinder, rxbinder, expectedbinderlen) == false)
            {
                state->lastalert = qsc_tls_alert_decrypt_error;
                status = qsc_tls_status_authentication_failure;
            }
            else
            {
                state->pskaccepted = true;
                state->pskticketagevalid = agevalid;
                state->selectedpskidentity = (uint16_t)identityindex;
                status = qsc_tls_keyschedule_state_initialize(&state->keyschedule, state->negotiatedhash);

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_keyschedule_extract_early_secret(&state->keyschedule, ticket.resumptionsecret, ticket.resumptionsecretlen);
                }

                if (status == qsc_tls_status_success)
                {
                    *accepted = true;
                }
                else
                {
                    state->lastalert = qsc_tls_alert_internal_error;
                }
            }
        }
    }

    qsc_tls_transcript_dispose(&scratch);
    qsc_tls_keyschedule_state_dispose(&ksscratch);
    qsc_tls_session_ticket_dispose(&ticket);
    qsc_memutils_secure_erase(expectedbinder, sizeof(expectedbinder));
    qsc_memutils_secure_erase(trunchash, sizeof(trunchash));

    return status;
}

static qsc_tls_status server_accept_client_psk(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen, const server_client_hello_context* context)
{
    qsc_tls_psk_identity_view identities[4U] = { 0U };
    const uint8_t* rxbinders[4U] = { 0U };
    size_t rxbinderlens[4U] = { 0U };
    size_t binderblockoff;
    size_t idcount;
    size_t i;
    bool accepted;
    qsc_tls_status status;

    binderblockoff = 0U;
    idcount = 0U;
    i = 0U;
    accepted = false;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && msg != NULL && context != NULL)
    {
        status = qsc_tls_status_success;

        if (context->pskextbody != NULL && state->config.psklookup != NULL && context->pskdhemode == true && state->config.requestclientauth == false)
        {
            status = qsc_tls_extensions_decode_pre_shared_key_offer(context->pskextbody, context->pskextbodylen, identities, rxbinders, rxbinderlens, 4U, &idcount, &binderblockoff);

            if (status == qsc_tls_status_success && (idcount == 0U || idcount > 4U))
            {
                status = qsc_tls_status_invalid_message;
            }

            for (i = 0U; i < idcount && accepted == false && status == qsc_tls_status_success; ++i)
            {
                status = server_validate_client_psk_identity(state, msg, msglen, context, &identities[i], rxbinders[i], rxbinderlens[i], binderblockoff, i, &accepted);
            }
        }
    }

    return status;
}

static void server_reset_hello_retry_psk_state(qsc_tls_server_state* state)
{
    if (state != NULL)
    {
        state->pskaccepted = false;
        state->pskticketagevalid = false;
        state->selectedpskidentity = 0U;
        state->stashedserverfinhashlen = 0U;
        qsc_memutils_secure_erase(state->stashedserverfinhash, sizeof(state->stashedserverfinhash));
        qsc_tls_record_state_dispose(&state->readrecord);
        qsc_tls_keyschedule_state_dispose(&state->keyschedule);
    }
}

static qsc_tls_status server_complete_client_key_exchange(qsc_tls_server_state* state, const server_client_hello_context* context)
{
    uint8_t sharedsecret[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
    const qsc_tls_group_descriptor* groupdesc;
    size_t i;
    size_t j;
    size_t sharedsecretlen;
    qsc_tls_named_group hrrtarget;
    qsc_tls_status status;

    groupdesc = NULL;
    i = 0U;
    j = 0U;
    sharedsecretlen = 0U;
    hrrtarget = qsc_tls_group_none;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && context != NULL)
    {
        status = qsc_tls_status_success;

        if (context->clientgroup == qsc_tls_group_none)
        {
            if (state->helloretryrequestsent == true)
            {
                state->lastalert = qsc_tls_alert_unexpected_message;
                status = qsc_tls_status_invalid_state;
            }
            else
            {
                for (i = 0U; i < state->config.groupspreferencecount && hrrtarget == qsc_tls_group_none; ++i)
                {
                    for (j = 0U; j < state->clientcapabilities.groupcount; ++j)
                    {
                        if (state->config.groupspreference[i] == state->clientcapabilities.groups[j])
                        {
                            hrrtarget = state->config.groupspreference[i];
                            break;
                        }
                    }
                }

                if (hrrtarget == qsc_tls_group_none)
                {
                    state->lastalert = qsc_tls_alert_handshake_failure;
                    status = qsc_tls_status_not_supported;
                }
                else
                {
                    server_reset_hello_retry_psk_state(state);
                    state->helloretryrequestsent = true;
                    state->hrrgroup = hrrtarget;
                    state->negotiatedgroup = hrrtarget;
                    state->negotiatedsigscheme = server_select_signature_scheme(state);

                    if (state->negotiatedsigscheme == qsc_tls_sig_none)
                    {
                        state->lastalert = qsc_tls_alert_handshake_failure;
                        status = qsc_tls_status_not_supported;
                    }
                }
            }
        }
        else
        {
            if (state->helloretryrequestsent == true && context->clientgroup != state->hrrgroup)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }
            else
            {
                state->negotiatedgroup = context->clientgroup;
                status = qsc_tls_groups_server_respond(context->clientgroup, context->clientkeyshare,
                    context->clientkeysharelen, state->serverkeyshare, sizeof(state->serverkeyshare),
                    &state->serverkeysharelen, sharedsecret, sizeof(sharedsecret), &sharedsecretlen);

                if (status != qsc_tls_status_success)
                {
                    groupdesc = qsc_tls_groups_descriptor_get(context->clientgroup);

                    if (groupdesc != NULL && groupdesc->iskem == true && status == qsc_tls_status_authentication_failure)
                    {
                        state->lastalert = qsc_tls_alert_internal_error;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_illegal_parameter;
                    }
                }

                if (status == qsc_tls_status_success && state->pskaccepted == false)
                {
                    status = qsc_tls_keyschedule_state_initialize(&state->keyschedule, state->negotiatedhash);

                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_keyschedule_extract_early_secret(&state->keyschedule, NULL, 0U);
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_keyschedule_extract_handshake_secret(&state->keyschedule, sharedsecret, sharedsecretlen);
                }

                if (status == qsc_tls_status_success)
                {
                    state->negotiatedsigscheme = server_select_signature_scheme(state);

                    if (state->negotiatedsigscheme == qsc_tls_sig_none)
                    {
                        state->lastalert = qsc_tls_alert_handshake_failure;
                        status = qsc_tls_status_not_supported;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    state->sharedsecretlen = 0U;
                }
            }
        }
    }

    qsc_memutils_secure_erase(sharedsecret, sizeof(sharedsecret));

    return status;
}

static qsc_tls_status server_process_client_hello(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen)
{
    server_client_hello_context context = { 0 };
    const uint8_t* extblock;
    const uint8_t* suites;
    size_t extblocklen;
    size_t suiteslen;
    qsc_tls_status status;

    status = qsc_tls_status_failure;
    extblock = NULL;
    suites = NULL;
    extblocklen = 0U;
    suiteslen = 0U;

    if (state != NULL && msg != NULL)
    {
        status = qsc_tls_status_success;

        if (state->helloretryrequestsent == true)
        {
            status = server_validate_retry_client_hello(state, msg, msglen);

            if (status != qsc_tls_status_success)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
            }
            else
            {
                qsc_memutils_secure_erase(state->clientcertificate, state->clientcertificatelen);
                state->clientcertificatelen = 0U;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = server_parse_client_hello(state, msg, msglen, &suites, &suiteslen, &extblock, &extblocklen);
        }

        if (status == qsc_tls_status_success)
        {
            status = server_select_client_hello_cipher(state, msg, msglen, suites, suiteslen);
        }

        if (status == qsc_tls_status_success)
        {
            status = server_parse_client_hello_extensions(state, msg, extblock, extblocklen, &context);
        }

        if (status == qsc_tls_status_success)
        {
            state->clientpskdhemodeoffered = context.pskdhemode;
            status = server_apply_client_hello_policy(state, &context);
        }

        if (status == qsc_tls_status_success)
        {
            status = server_accept_client_psk(state, msg, msglen, &context);
        }

        if (status == qsc_tls_status_success)
        {
            status = server_complete_client_key_exchange(state, &context);
        }

        if (status == qsc_tls_status_success && state->helloretryrequestsent == true && state->phase == qsc_tls_server_phase_waiting_client_hello)
        {
            if (msglen <= sizeof(state->clientcertificate))
            {
                qsc_memutils_copy(state->clientcertificate, msg, msglen);
                state->clientcertificatelen = msglen;
            }
            else
            {
                state->lastalert = qsc_tls_alert_internal_error;
                status = qsc_tls_status_buffer_too_small;
            }
        }
    }

    return status;
}

static bool tls_server_local_certificate_sign(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, void* state)
{
    qsc_tls_signer_default_context sctx;
    const qsc_tls_local_certificate_config* localcert;
    bool res;

    res = false;

    if (state != NULL)
    {
        localcert = (const qsc_tls_local_certificate_config*)state;

        if (localcert->signprivatekeylen != 0U)
        {
            sctx.scheme = scheme;
            sctx.privatekey = localcert->signprivatekey;
            sctx.privatekeylen = localcert->signprivatekeylen;
            res = qsc_tls_signer_default_sign(scheme, input, inputlen, signature, signaturelen, &sctx);
        }
    }

    return res;
}

static void tls_server_fill_authorization_info(qsc_tls_client_authorization_info* info, const qsc_tls_server_state* state, const qsc_tls_certificate_view* chain, size_t chainlength)
{
    const qsc_tls_qsc_x509_context* xctx;

    if (info != NULL)
    {
        qsc_memutils_clear(info, sizeof(*info));
        info->verifystatus = QSC_X509_VERIFY_STATUS_SUCCESS;
        info->chainvalid = true;

        if (chain != NULL && chainlength != 0U && chain[0U].data != NULL && chain[0U].datalen != 0U)
        {
            qsc_sha3_compute256(info->certificatefingerprint, chain[0U].data, chain[0U].datalen);
            info->certificatefingerprintlen = QSC_TLS_CERTIFICATE_FINGERPRINT_SIZE;
        }

        if (state != NULL && state->config.clientcertinterface.state != NULL &&
            state->config.clientcertinterface.validatechain == qsc_tls_x509_validate_chain &&
            state->config.clientcertinterface.verifycertificateverify == qsc_tls_x509_verify_certificate_verify)
        {
            xctx = (const qsc_tls_qsc_x509_context*)state->config.clientcertinterface.state;
            info->summary = xctx->peersummary;
            info->verifystatus = xctx->lastverifystatus;
            info->chainvalid = xctx->peersummary.chainvalid;
        }
    }
}

static qsc_tls_status server_validate_client_certificate_chain(qsc_tls_server_state* state, const qsc_tls_certificate_view* chain, size_t chainlength)
{
    qsc_tls_certificate_validation_context context;
    qsc_tls_status status;
    bool accepted;

    accepted = false;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && chain != NULL && chainlength != 0U && qsc_tls_certificate_interface_is_valid(&state->config.clientcertinterface) == true)
    {
        context.hostname = NULL;
        context.clientauth = true;
        context.requirepeercertificate = state->config.requireclientauth;
        state->clientcertificatevalidationattempted = true;
        accepted = state->config.clientcertinterface.validatechain(chain, chainlength, &context, state->config.clientcertinterface.state);

        if (accepted == true)
        {
            status = qsc_tls_status_success;
        }
        else
        {
            state->lastalert = qsc_tls_certificate_interface_get_last_alert(&state->config.clientcertinterface, false);
            status = qsc_tls_status_authentication_failure;
        }
    }

    return status;
}

static qsc_tls_status server_authorize_client_certificate_identity(qsc_tls_server_state* state)
{
    qsc_tls_client_authorization_info info;
    qsc_tls_certificate_view chain;
    qsc_tls_status status;
    bool accepted;

    accepted = false;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && state->clientcertificatevalidated == true && state->clientcertificatelen != 0U)
    {
        chain.data = state->clientcertificate;
        chain.datalen = state->clientcertificatelen;
        tls_server_fill_authorization_info(&info, state, &chain, 1U);

        if (state->config.clientauthcallback != NULL)
        {
            accepted = state->config.clientauthcallback(&info, state->config.clientauthstate);

            if (accepted == true)
            {
                status = qsc_tls_status_success;
            }
            else
            {
                state->lastalert = qsc_tls_alert_access_denied;
                status = qsc_tls_status_authentication_failure;
            }
        }
        else if (state->config.requireclientauthorization == true)
        {
            state->lastalert = qsc_tls_alert_access_denied;
            status = qsc_tls_status_authentication_failure;
        }
        else
        {
            status = qsc_tls_status_success;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_server_config_add_certificate_identity(qsc_tls_server_config* config, const char* hostname, const qsc_tls_local_certificate_config* localcert)
{
    qsc_tls_status status;
    size_t hostlen;

    status = qsc_tls_status_invalid_input;

    if (config != NULL && hostname != NULL && localcert != NULL && localcert->configured == true)
    {
        hostlen = 0U;

        while (hostname[hostlen] != '\0' && hostlen <= QSC_TLS_MAX_HOSTNAME_SIZE)
        {
            ++hostlen;
        }

        if (hostlen != 0U && hostlen <= QSC_TLS_MAX_HOSTNAME_SIZE && config->identitycount < QSC_TLS_MAX_SERVER_IDENTITIES)
        {
            qsc_memutils_clear(&config->identities[config->identitycount], sizeof(config->identities[config->identitycount]));
            qsc_memutils_copy(config->identities[config->identitycount].hostname, hostname, hostlen);
            config->identities[config->identitycount].hostname[hostlen] = '\0';
            config->identities[config->identitycount].localcert = *localcert;

            if (config->identities[config->identitycount].localcert.signprivatekeylen != 0U && config->identities[config->identitycount].localcert.signcallback != NULL)
            {
                config->identities[config->identitycount].localcert.signstate = &config->identities[config->identitycount].localcert;
            }

            config->identities[config->identitycount].configured = true;
            ++config->identitycount;
            status = qsc_tls_status_success;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_server_config_set_sni_required(qsc_tls_server_config* config, bool required)
{
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (config != NULL)
    {
        config->requiresni = required;
        status = qsc_tls_status_success;
    }

    return status;
}

qsc_tls_status qsc_tls_server_config_set_client_authorization(qsc_tls_server_config* config, qsc_tls_client_authorization_callback callback, void* state, bool required)
{
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (config != NULL && (callback != NULL || required == false))
    {
        config->clientauthcallback = callback;
        config->clientauthstate = state;
        config->requireclientauthorization = required;
        status = qsc_tls_status_success;
    }

    return status;
}

qsc_tls_status qsc_tls_server_authorize_client_certificate(qsc_tls_server_state* state, const qsc_tls_certificate_view* chain, size_t chainlength)
{
    qsc_tls_certificate_validation_context vctx;
    qsc_tls_client_authorization_info info;
    qsc_tls_status status;
    bool accepted;

    status = qsc_tls_status_invalid_input;
    accepted = false;

    if (state != NULL && chain != NULL && chainlength != 0U && qsc_tls_certificate_interface_is_valid(&state->config.clientcertinterface) == true)
    {
        vctx.hostname = NULL;
        vctx.clientauth = true;
        vctx.requirepeercertificate = state->config.requireclientauth;

        accepted = state->config.clientcertinterface.validatechain(chain, chainlength, &vctx, state->config.clientcertinterface.state);

        if (accepted == false)
        {
            state->lastalert = qsc_tls_certificate_interface_get_last_alert(&state->config.clientcertinterface, false);
            status = qsc_tls_status_authentication_failure;
        }
        else
        {
            tls_server_fill_authorization_info(&info, state, chain, chainlength);

            if (state->config.clientauthcallback != NULL)
            {
                accepted = state->config.clientauthcallback(&info, state->config.clientauthstate);

                if (accepted == true)
                {
                    status = qsc_tls_status_success;
                }
                else
                {
                    state->lastalert = qsc_tls_alert_access_denied;
                    status = qsc_tls_status_authentication_failure;
                }
            }
            else if (state->config.requireclientauthorization == true)
            {
                state->lastalert = qsc_tls_alert_access_denied;
                status = qsc_tls_status_authentication_failure;
            }
            else
            {
                status = qsc_tls_status_success;
            }
        }
    }

    return status;
}

qsc_tls_status qsc_tls_server_config_set_certificate_interface(qsc_tls_server_config* config, const qsc_tls_certificate_interface* iface, bool requestclientauth, bool requireclientauth)
{
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (config != NULL && ((requestclientauth == false && requireclientauth == false) || (iface != NULL && qsc_tls_certificate_interface_is_valid(iface) == true)))
    {
        if (iface != NULL)
        {
            config->clientcertinterface = *iface;
        }
        else
        {
            qsc_memutils_clear(&config->clientcertinterface, sizeof(config->clientcertinterface));
        }

        config->requestclientauth = (requestclientauth || requireclientauth);
        config->requireclientauth = requireclientauth;
        status = qsc_tls_status_success;
    }

    return status;
}

qsc_tls_status qsc_tls_server_config_set_local_certificate(qsc_tls_server_config* config, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, const uint8_t* privatekeydata, size_t privatekeylen)
{
    qsc_tls_status status;
    size_t i;

    status = qsc_tls_status_invalid_input;

    if (config != NULL && chain != NULL && chainlength != 0U && chainlength <= QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES &&
        privatekeydata != NULL && privatekeylen != 0U && privatekeylen <= QSC_TLS_MAX_SIGNING_PRIVATE_KEY_SIZE)
    {
        status = qsc_tls_status_success;

        for (i = 0U; i < chainlength; ++i)
        {
            if (chain[i].data == NULL || chain[i].datalen == 0U || chain[i].datalen > QSC_TLS_CERTIFICATE_MAX_SIZE)
            {
                status = qsc_tls_status_invalid_input;
                break;
            }
        }

        if (status == qsc_tls_status_success)
        {
            qsc_memutils_clear(&config->localcert, sizeof(config->localcert));

            for (i = 0U; i < chainlength; ++i)
            {
                config->localcert.chain[i] = chain[i];
            }

            config->localcert.chainlength = chainlength;
            config->localcert.verifyscheme = verifyscheme;
            config->localcert.signprivatekeylen = privatekeylen;
            qsc_memutils_copy(config->localcert.signprivatekey, privatekeydata, privatekeylen);
            config->localcert.signcallback = tls_server_local_certificate_sign;
            config->localcert.signstate = &config->localcert;
            config->localcert.configured = true;
            config->localcert.staticsignature = false;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_server_initialize(qsc_tls_server_state* state, const qsc_tls_server_config* config)
{
    qsc_tls_status status;

    if (state == NULL || config == NULL)
    {
        status = qsc_tls_status_invalid_input;
    }
    else if (config->acceptearlydata == true)
    {
        status = qsc_tls_status_not_supported;
    }
    else if (config->ciphersuitepreference == NULL || config->ciphersuitepreferencecount == 0U || config->groupspreference == NULL || 
        config->groupspreferencecount == 0U || config->sigschemepreference == NULL || config->sigschemepreferencecount == 0U ||
        ((config->requestclientauth == true || config->requireclientauth == true) &&
        qsc_tls_certificate_interface_is_valid(&config->clientcertinterface) == false) ||
        (config->requireclientauthorization == true && config->clientauthcallback == NULL))
    {
        status = qsc_tls_status_invalid_input;
    }
    else
    {
        qsc_memutils_clear(state, sizeof(*state));
        state->config = *config;
        state->config.requestclientauth = (state->config.requestclientauth || state->config.requireclientauth);

        if (state->config.clientcertinterface.state != NULL &&
            state->config.clientcertinterface.validatechain == qsc_tls_x509_validate_chain &&
            state->config.clientcertinterface.verifycertificateverify == qsc_tls_x509_verify_certificate_verify)
        {
            status = qsc_tls_x509_context_clone(&state->x509context, (const qsc_tls_qsc_x509_context*)state->config.clientcertinterface.state);

            if (status == qsc_tls_status_success)
            {
                state->config.clientcertinterface.state = &state->x509context;
            }
        }
        else
        {
            status = qsc_tls_status_success;
        }

        if (status == qsc_tls_status_success && state->config.localcert.signcallback == tls_server_local_certificate_sign)
        {
            state->config.localcert.signstate = &state->config.localcert;
        }

        if (status == qsc_tls_status_success)
        {
            state->phase = qsc_tls_server_phase_waiting_client_hello;
            state->negotiatedsuite = qsc_tls_cipher_suite_none;
            state->negotiatedhash = qsc_tls_hash_none;
            state->negotiatedgroup = qsc_tls_group_none;
            state->negotiatedsigscheme = qsc_tls_sig_none;
        }
    }

    return status;
}

void qsc_tls_server_dispose(qsc_tls_server_state* state)
{
    if (state != NULL)
    {
        qsc_tls_transcript_dispose(&state->transcript);
        qsc_tls_keyschedule_state_dispose(&state->keyschedule);
        qsc_tls_record_state_dispose(&state->readrecord);
        qsc_tls_record_state_dispose(&state->writerecord);
        qsc_memutils_secure_erase(state, sizeof(*state));
    }
}

qsc_tls_status qsc_tls_server_process_record(qsc_tls_server_state* state, const uint8_t* input, size_t inlen, size_t* consumed, uint8_t* output, size_t outlen, size_t* written)
{
    uint8_t decrypt_buf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    const uint8_t* payload;
    const uint8_t* plaintext;
    size_t paylen;
    size_t reclen;
    size_t decrypt_len = 0U;
    size_t plaintextlen;
    qsc_tls_record_content_type rtype;
    qsc_tls_status st;
    bool complete;
    bool protectedrecord;

    protectedrecord = false;

    if (consumed != NULL)
    {
        *consumed = 0U;
    }

    if (written != NULL)
    {
        *written = 0U;
    }

    if (state == NULL || input == NULL || consumed == NULL || written == NULL)
    {
        return qsc_tls_status_invalid_input;
    }

    st = qsc_tls_record_try_get_span_length(input, inlen, &reclen, &complete);

    if (st != qsc_tls_status_success)
    {
        if (st == qsc_tls_status_record_overflow)
        {
            state->lastalert = qsc_tls_alert_record_overflow;
            state->phase = qsc_tls_server_phase_failed;
        }

        return st;
    }

    if (!complete)
    {
        return qsc_tls_status_success;
    }

    st = qsc_tls_record_decode_plaintext(input, reclen, &rtype, &payload, &paylen);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    if (state->readrecord.initialized && rtype == qsc_tls_record_content_application_data)
    {
        qsc_tls_record_content_type inner;

        inner = qsc_tls_record_content_invalid;
        st = qsc_tls_record_decrypt(&state->readrecord, decrypt_buf, sizeof(decrypt_buf), &decrypt_len, &inner, input, reclen);

        if (st != qsc_tls_status_success)
        {
            if (st == qsc_tls_status_record_overflow)
            {
                state->lastalert = qsc_tls_alert_record_overflow;
                state->phase = qsc_tls_server_phase_failed;
                *consumed = reclen;
            }
            else if (st == qsc_tls_status_authentication_failure)
            {
                state->lastalert = qsc_tls_alert_bad_record_mac;
                state->phase = qsc_tls_server_phase_failed;
                *consumed = reclen;
            }

            return st;
        }

        plaintext = decrypt_buf;
        plaintextlen = decrypt_len;
        rtype = inner;
        protectedrecord = true;
    }
    else
    {
        plaintext = payload;
        plaintextlen = paylen;
    }

    if (state->handshakebufferlen != 0U && rtype != qsc_tls_record_content_handshake)
    {
        state->lastalert = qsc_tls_alert_unexpected_message;
        state->phase = qsc_tls_server_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_invalid_message;
    }

    if (rtype == qsc_tls_record_content_change_cipher_spec)
    {
        bool ccsallowed;

        ccsallowed = (state->phase == qsc_tls_server_phase_waiting_client_hello_2 ||
            state->phase == qsc_tls_server_phase_sending_flight1 ||
            state->phase == qsc_tls_server_phase_waiting_client_certificate ||
            state->phase == qsc_tls_server_phase_waiting_client_certificate_verify ||
            state->phase == qsc_tls_server_phase_waiting_client_finished);

        if (protectedrecord == true || ccsallowed == false || plaintextlen != 1U || plaintext[0U] != 0x01U)
        {
            state->lastalert = qsc_tls_alert_unexpected_message;
            state->phase = qsc_tls_server_phase_failed;
            *consumed = reclen;

            return qsc_tls_status_invalid_message;
        }

        state->changecipherspecreceived = true;
        *consumed = reclen;

        return qsc_tls_status_success;
    }

    if (rtype == qsc_tls_record_content_handshake && state->readrecord.initialized == true && protectedrecord == false)
    {
        state->lastalert = qsc_tls_alert_unexpected_message;
        state->phase = qsc_tls_server_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_invalid_message;
    }

    if (rtype == qsc_tls_record_content_alert)
    {
        qsc_tls_alert_description alert;

        if (protectedrecord == false && state->readrecord.initialized == true)
        {
            state->lastalert = qsc_tls_alert_unexpected_message;
            state->phase = qsc_tls_server_phase_failed;
            *consumed = reclen;

            return qsc_tls_status_invalid_message;
        }

        if (plaintextlen == 0U)
        {
            state->lastalert = qsc_tls_alert_unexpected_message;
            state->phase = qsc_tls_server_phase_failed;
            *consumed = reclen;

            return qsc_tls_status_invalid_message;
        }

        st = qsc_tls_alert_decode(plaintext, plaintextlen, &alert);

        if (st != qsc_tls_status_success)
        {
            state->lastalert = qsc_tls_alert_decode_error;
            state->phase = qsc_tls_server_phase_failed;
            *consumed = reclen;

            return st;
        }

        state->lastalert = alert;
        *consumed = reclen;

        if (alert == qsc_tls_alert_close_notify)
        {
            state->closenotifyreceived = true;
            state->phase = qsc_tls_server_phase_closed;

            return qsc_tls_status_success;
        }

        if (alert == qsc_tls_alert_user_canceled)
        {
            return qsc_tls_status_success;
        }

        state->phase = qsc_tls_server_phase_failed;

        return qsc_tls_status_failure;
    }

    if (rtype != qsc_tls_record_content_handshake)
    {
        return qsc_tls_status_invalid_message;
    }

    if (plaintextlen == 0U)
    {
        state->lastalert = qsc_tls_alert_unexpected_message;
        state->phase = qsc_tls_server_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_invalid_message;
    }

    if (plaintextlen > (sizeof(state->handshakebuffer) - state->handshakebufferlen))
    {
        state->lastalert = qsc_tls_alert_decode_error;
        state->phase = qsc_tls_server_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_invalid_length;
    }

    qsc_memutils_copy(state->handshakebuffer + state->handshakebufferlen, plaintext, plaintextlen);
    state->handshakebufferlen += plaintextlen;

    /* Process every complete handshake message and retain an incomplete tail for the next record. */
    size_t off = 0U;

    while ((state->handshakebufferlen - off) >= 4U)
    {
        qsc_tls_handshake_type type;
        size_t bodylen;
        size_t hdroff = off;

        st = qsc_tls_handshake_read_header(state->handshakebuffer, state->handshakebufferlen, &off, &type, &bodylen);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        if (bodylen > (state->handshakebufferlen - off))
        {
            off = hdroff;
            break;
        }

        const uint8_t* body = state->handshakebuffer + off;

        if ((type == qsc_tls_handshake_type_client_hello || type == qsc_tls_handshake_type_finished) &&
            (off + bodylen) != state->handshakebufferlen)
        {
            state->lastalert = qsc_tls_alert_unexpected_message;
            state->phase = qsc_tls_server_phase_failed;
            *consumed = reclen;

            return qsc_tls_status_invalid_message;
        }

        switch (type)
        {
        case qsc_tls_handshake_type_client_hello:
        {
            if (state->phase != qsc_tls_server_phase_waiting_client_hello && state->phase != qsc_tls_server_phase_waiting_client_hello_2)
            {
                return qsc_tls_status_invalid_state;
            }

            /* pick hash tentatively from first preferred suite so transcript is defined before
             * we know the real suite. Will reinitialize after suite negotiation. On CH2 the
             * transcript was already initialized and contains message_hash(CH1) + HRR. */
            if (state->phase == qsc_tls_server_phase_waiting_client_hello)
            {
                state->negotiatedhash = qsc_tls_keyschedule_suite_hash(state->config.ciphersuitepreference[0U]);

                if (state->negotiatedhash == qsc_tls_hash_none)
                {
                    return qsc_tls_status_not_supported;
                }

                st = qsc_tls_transcript_initialize(&state->transcript, state->negotiatedhash);

                if (st != qsc_tls_status_success)
                {
                    return st;
                }
            }

            st = qsc_tls_transcript_update(&state->transcript, state->handshakebuffer + hdroff, 4U + bodylen);

            if (st == qsc_tls_status_success)
            {
                st = server_process_client_hello(state, body, bodylen);
            }

            if (st == qsc_tls_status_success)
            {
                if (state->helloretryrequestsent && state->phase == qsc_tls_server_phase_waiting_client_hello)
                {
                    /* first CH triggered HRR: emit the retry and wait for CH2. */
                    st = server_emit_hrr(state, output, outlen, written);

                    if (st == qsc_tls_status_success)
                    {
                        state->phase = qsc_tls_server_phase_waiting_client_hello_2;
                    }
                }
                else
                {
                    /* either a first CH that matched directly, or a CH2 after HRR.
                     * either way, emit the full flight and advance to waiting-Finished. */
                    st = server_emit_flight1(state, output, outlen, written);

                    if (st == qsc_tls_status_success)
                    {
                        if (state->config.requestclientauth == true)
                        {
                            state->phase = qsc_tls_server_phase_waiting_client_certificate;
                        }
                        else
                        {
                            state->phase = qsc_tls_server_phase_waiting_client_finished;
                        }
                    }
                }
            }

            break;
        }
        case qsc_tls_handshake_type_certificate:
        {
            if (state->phase != qsc_tls_server_phase_waiting_client_certificate)
            {
                state->lastalert = qsc_tls_alert_unexpected_message;
                return qsc_tls_status_invalid_state;
            }

            st = server_process_client_certificate(state, body, bodylen);

            if (st == qsc_tls_status_success)
            {
                st = qsc_tls_transcript_update(&state->transcript, state->handshakebuffer + hdroff, 4U + bodylen);
            }

            break;
        }
        case qsc_tls_handshake_type_certificate_verify:
        {
            if (state->phase != qsc_tls_server_phase_waiting_client_certificate_verify)
            {
                state->lastalert = qsc_tls_alert_unexpected_message;
                return qsc_tls_status_invalid_state;
            }

            st = server_process_client_certificate_verify(state, body, bodylen);

            if (st == qsc_tls_status_success)
            {
                st = qsc_tls_transcript_update(&state->transcript, state->handshakebuffer + hdroff, 4U + bodylen);
            }

            break;
        }
        case qsc_tls_handshake_type_finished:
        {
            if (state->phase != qsc_tls_server_phase_waiting_client_finished)
            {
                state->lastalert = qsc_tls_alert_unexpected_message;
                return qsc_tls_status_invalid_state;
            }

            /* Verify client Finished over the complete handshake transcript preceding it. */
            st = server_process_client_finished(state, body, bodylen);

            if (st == qsc_tls_status_success)
            {
                st = qsc_tls_transcript_update(&state->transcript, state->handshakebuffer + hdroff, 4U + bodylen);
            }

            if (st == qsc_tls_status_success)
            {
                /* Application traffic secrets are bound to CH..server_Finished. Client
                 * Certificate, CertificateVerify, and Finished are later transcript
                 * messages and must not move that derivation boundary. */
                if (state->stashedserverfinhashlen > 0U)
                {
                    st = server_install_app_keys(state, state->stashedserverfinhash, state->stashedserverfinhashlen);
                }
                else
                {
                    state->lastalert = qsc_tls_alert_internal_error;
                    st = qsc_tls_status_invalid_state;
                }
            }

            if (st == qsc_tls_status_success)
            {
                /* derive resumption_master_secret now that transcript includes client Finished. */
                uint8_t thashrms[QSC_TLS_HASH_MAX_SIZE] = { 0U };
                size_t thashrmslen;

                thashrmslen = 0U;
                st = qsc_tls_transcript_snapshot(&state->transcript, thashrms, sizeof(thashrms), &thashrmslen);

                if (st == qsc_tls_status_success)
                {
                    st = qsc_tls_keyschedule_derive_resumption_master_secret(&state->keyschedule, thashrms, thashrmslen);
                }

                qsc_memutils_secure_erase(thashrms, sizeof(thashrms));
            }

            if (st == qsc_tls_status_success)
            {
                state->phase = qsc_tls_server_phase_established;
            }

            break;
        }
        default:
        {
            return qsc_tls_status_invalid_message;
        }
        }

        if (st != qsc_tls_status_success)
        {
            state->phase = qsc_tls_server_phase_failed;
            return st;
        }

        off += bodylen;
    }

    if (off != 0U)
    {
        const size_t remaining = state->handshakebufferlen - off;

        if (remaining != 0U)
        {
            qsc_memutils_move(state->handshakebuffer, state->handshakebuffer + off, remaining);
        }

        state->handshakebufferlen = remaining;
    }

    *consumed = reclen;

    return qsc_tls_status_success;
}

bool qsc_tls_server_is_handshake_complete(const qsc_tls_server_state* state)
{
    return (state != NULL && state->phase == qsc_tls_server_phase_established);
}

qsc_tls_cipher_suite qsc_tls_server_get_negotiated_cipher_suite(const qsc_tls_server_state* state)
{
    return (state != NULL) ? state->negotiatedsuite : qsc_tls_cipher_suite_none;
}
