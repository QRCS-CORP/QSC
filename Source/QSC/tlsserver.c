#include "tlsserver.h"
#include "csp.h"
#include "memutils.h"
#include "tlscodec.h"
#include "tlscert.h"
#include "tlsdefs.h"
#include "tlsextensions.h"
#include "tlshandshake.h"
#include "tlskeyschedule.h"
#include "tlsrecord.h"
#include "tlstranscript.h"
#include "tlssignerdefault.h"

static qsc_tls_status server_emit_flight1(qsc_tls_server_state* state, uint8_t* output, size_t outlen, size_t* written);
static qsc_tls_status server_emit_hrr(qsc_tls_server_state* state, uint8_t* output, size_t outlen, size_t* written);
static qsc_tls_status server_install_app_keys(qsc_tls_server_state* state, const uint8_t* thash_before_client_finished, size_t thashlen);
static qsc_tls_status server_install_handshake_keys(qsc_tls_server_state* state);
static qsc_tls_status server_process_client_finished(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen);
static qsc_tls_status server_process_client_hello(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen);

/* Emit a HelloRetryRequest. RFC 8446 4.1.4:
 *   - Structurally a ServerHello with legacy_version=0x0303, the special HRR
 *     random, echo of session_id, chosen cipher suite, null compression.
 *   - extensions: supported_versions + key_share (containing only the selected
 *     group id, no key material).
 *   - Before updating the transcript with the HRR message, apply the
 *     message_hash transform to replace the previous ClientHello with
 *     Hash(ClientHello1).
 */
static const uint8_t tls_hrr_special_random[32] = {
    0xCFU, 0x21U, 0xADU, 0x74U, 0xE5U, 0x9AU, 0x61U, 0x11U,
    0xBEU, 0x1DU, 0x8CU, 0x02U, 0x1EU, 0x65U, 0xB8U, 0x91U,
    0xC2U, 0xA2U, 0x11U, 0x16U, 0x7AU, 0xBBU, 0x8CU, 0x5EU,
    0x07U, 0x9EU, 0x09U, 0xE2U, 0xC8U, 0xA8U, 0x33U, 0x9CU
};

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

        config->requestclientauth = requestclientauth;
        config->requireclientauth = requireclientauth;
        status = qsc_tls_status_success;
    }

    return status;
}

qsc_tls_status qsc_tls_server_config_set_local_certificate(qsc_tls_server_config* config, const qsc_tls_certificate_view* chain, size_t chainlength, 
    qsc_tls_signature_scheme verifyscheme, const uint8_t* privatekeydata, size_t privatekeylen)
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
    else if (config->ciphersuitepreference == NULL || config->ciphersuitepreferencecount == 0U || config->groupspreference == NULL || 
        config->groupspreferencecount == 0U || config->sigschemepreference == NULL || config->sigschemepreferencecount == 0U)
    {
        status = qsc_tls_status_invalid_input;
    }
    else
    {
        qsc_memutils_clear(state, sizeof(*state));
        state->config = *config;

        if (state->config.localcert.signcallback == tls_server_local_certificate_sign)
        {
            state->config.localcert.signstate = &state->config.localcert;
        }

        state->phase = qsc_tls_server_phase_waiting_client_hello;
        state->negotiatedsuite = qsc_tls_cipher_suite_none;
        state->negotiatedhash = qsc_tls_hash_none;
        state->negotiatedgroup = qsc_tls_group_none;
        state->negotiatedsigscheme = qsc_tls_sig_none;
        status = qsc_tls_status_success;
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
            return st;
        }

        plaintext = decrypt_buf;
        plaintextlen = decrypt_len;
        rtype = inner;
    }
    else
    {
        plaintext = payload;
        plaintextlen = paylen;
    }

    if (rtype == qsc_tls_record_content_change_cipher_spec)
    {
        state->changecipherspecreceived = true;
        *consumed = reclen;

        return qsc_tls_status_success;
    }
    if (rtype == qsc_tls_record_content_alert)
    {
        if (plaintextlen >= 2U)
        {
            state->lastalert = (qsc_tls_alert_description)plaintext[1U];
        }

        state->phase = qsc_tls_server_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_failure;
    }

    if (rtype != qsc_tls_record_content_handshake)
    {
        return qsc_tls_status_invalid_message;
    }

    /* walk handshake messages inside this plaintext. */
    size_t off = 0U;

    while (off < plaintextlen)
    {
        qsc_tls_handshake_type type;
        size_t bodylen;
        size_t hdroff = off;

        st = qsc_tls_handshake_read_header(plaintext, plaintextlen, &off, &type, &bodylen);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        if (bodylen > plaintextlen - off)
        {
            return qsc_tls_status_invalid_length;
        }

        const uint8_t* body = plaintext + off;

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

            st = qsc_tls_transcript_update(&state->transcript, plaintext + hdroff, 4U + bodylen);

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
                        /* When 0-RTT was accepted the client sends early application data
                         * records followed by EndOfEarlyData under early keys; THEN sends
                         * Finished under handshake keys. Our read record is currently
                         * installed with the early traffic key (from CH processing).
                         * We'll switch it to the handshake traffic key on EOED receipt. */
                        state->phase = state->earlydataaccepted ? qsc_tls_server_phase_waiting_end_of_early_data : qsc_tls_server_phase_waiting_client_finished;
                    }
                }
            }

            break;
        }
        case qsc_tls_handshake_type_end_of_early_data:
        {
            if (state->phase != qsc_tls_server_phase_waiting_end_of_early_data)
            {
                state->lastalert = qsc_tls_alert_unexpected_message;
                return qsc_tls_status_invalid_state;
            }

            /* EOED body is empty per RFC 8446 4.5. Include in transcript, swap read key
             * from early_traffic to client_handshake_traffic, advance phase to waiting_finished. */
            if (bodylen != 0U) 
            {
                return qsc_tls_status_invalid_length; 
            }

            st = qsc_tls_transcript_update(&state->transcript, plaintext + hdroff, 4U + bodylen);

            if (st == qsc_tls_status_success)
            {
                uint8_t hiv[12U] = { 0U };
                uint8_t hkey[32U] = { 0U };
                size_t ilen;
                size_t klen;

                st = qsc_tls_keyschedule_suite_record_sizes(state->negotiatedsuite, &klen, &ilen);

                if (st == qsc_tls_status_success)
                {
                    st = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clienthandshaketrafficsecret, 
                        state->keyschedule.digestsize, klen, ilen, hkey, hiv);
                }

                if (st == qsc_tls_status_success)
                {
                    st = qsc_tls_record_state_install_keys(&state->readrecord, state->negotiatedsuite, hkey, klen, hiv, ilen);
                }

                qsc_memutils_secure_erase(hkey, sizeof(hkey));
                qsc_memutils_secure_erase(hiv, sizeof(hiv));
            }

            if (st == qsc_tls_status_success)
            {
                state->earlydatadone = true;
                state->phase = qsc_tls_server_phase_waiting_client_finished;
            }

            break;
        }
        case qsc_tls_handshake_type_finished:
        {
            if (state->phase != qsc_tls_server_phase_waiting_client_finished)
            {
                return qsc_tls_status_invalid_state;
            }

            /* snapshot the transcript BEFORE we include client Finished, this is the input to
             * application traffic secret derivation per RFC 8446 7.1. */
            {
                uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
                size_t thashlen;

                thashlen = 0U;
                st = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);

                if (st == qsc_tls_status_success)
                {
                    /* apply transcript including server's own previous Finished (already updated in flight1) and then
                     * compare client Finished against expected. But client computes its Finished over
                     * transcript CH..server Finished, which is exactly what we have right now. */
                    st = server_process_client_finished(state, body, bodylen);
                }

                if (st == qsc_tls_status_success)
                {
                    st = qsc_tls_transcript_update(&state->transcript, plaintext + hdroff, 4U + bodylen);
                }

                if (st == qsc_tls_status_success)
                {
                    /* on 0-RTT-accepted flow the transcript currently contains EOED past the
                     * server-Finished boundary. App keys must derive from CH..server_Finished
                     * which we stashed in flight1. Otherwise (normal flow) the live snapshot
                     * is the correct boundary. */
                    if (state->earlydataaccepted && state->stashedserverfinhashlen > 0U)
                    {
                        st = server_install_app_keys(state, state->stashedserverfinhash, state->stashedserverfinhashlen);
                    }
                    else
                    {
                        st = server_install_app_keys(state, thash, thashlen);
                    }
                }

                qsc_memutils_secure_erase(thash, sizeof(thash));
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

    *consumed = reclen;

    return qsc_tls_status_success;
}

static qsc_tls_status server_process_client_hello(qsc_tls_server_state* state, const uint8_t* msg, size_t msglen)
{
    const uint8_t* clientkeyshare;
    const uint8_t* comp;
    const uint8_t* extblock;
    const uint8_t* pskextbody = NULL;
    const uint8_t* sid;
    const uint8_t* suitesspan;
    size_t clientkeysharelen;
    size_t complen;
    size_t extblocklen;
    size_t off;
    size_t pskextbodylen;
    size_t pskextabsbodyoffset;
    size_t sidlen;
    size_t suiteslen;
    uint16_t legver;
    qsc_tls_named_group clientgroup;
    qsc_tls_status st;
    bool sawearlydataext;
    bool sawpskmodesdhe;

    clientkeyshare = NULL;
    clientkeysharelen = 0U;
    extblocklen = 0U;
    off = 0U;
    pskextbodylen = 0U;
    pskextabsbodyoffset = 0U;
    suiteslen = 0U;
    clientgroup = qsc_tls_group_none;
    sawearlydataext = false;
    sawpskmodesdhe = false;

    st = qsc_tls_codec_read_u16(msg, msglen, &off, &legver);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    if (off + 32U > msglen)
    {
        return qsc_tls_status_invalid_length;
    }

    qsc_memutils_copy(state->clientrandom, msg + off, 32U);
    off += 32U;

    st = qsc_tls_codec_read_vector8_span(msg, msglen, &off, &sid, &sidlen);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    if (sidlen > sizeof(state->legacy_session_id))
    {
        return qsc_tls_status_invalid_length;
    }

    if (sidlen != 0U)
    {
        qsc_memutils_copy(state->legacy_session_id, sid, sidlen);
    }

    state->legacy_session_id_len = sidlen;

    st = qsc_tls_codec_read_vector16_span(msg, msglen, &off, &suitesspan, &suiteslen);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    st = qsc_tls_codec_read_vector8_span(msg, msglen, &off, &comp, &complen);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    if (complen != 1U || comp[0U] != 0U)
    {
        return qsc_tls_status_invalid_message;
    }

    st = qsc_tls_codec_read_vector16_span(msg, msglen, &off, &extblock, &extblocklen);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    if (off != msglen)
    {
        return qsc_tls_status_invalid_length;
    }

    /* pick cipher suite. */
    st = qsc_tls_extensions_select_cipher_suite(suitesspan, suiteslen, state->config.ciphersuitepreference, state->config.ciphersuitepreferencecount, &state->negotiatedsuite);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    /* reset transcript with the actual suite's hash if different. */
    qsc_tls_hash_algorithm h = qsc_tls_keyschedule_suite_hash(state->negotiatedsuite);

    if (h != state->negotiatedhash)
    {
        qsc_tls_transcript_dispose(&state->transcript);
        st = qsc_tls_transcript_initialize(&state->transcript, h);

        if (st == qsc_tls_status_success)
        {
            /* re-feed the full ClientHello record including its handshake header. We need
             * the 4 header bytes; the caller passed only the body. Reconstruct them. */
            uint8_t hdr[4U] = { 0U };

            hdr[0U] = (uint8_t)qsc_tls_handshake_type_client_hello;
            hdr[1U] = (uint8_t)((msglen >> 16) & 0xFFU);
            hdr[2U] = (uint8_t)((msglen >> 8) & 0xFFU);
            hdr[3U] = (uint8_t)(msglen & 0xFFU);

            st = qsc_tls_transcript_update(&state->transcript, hdr, 4U);

            if (st == qsc_tls_status_success)
            {
                st = qsc_tls_transcript_update(&state->transcript, msg, msglen);
            }
        }

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        state->negotiatedhash = h;
    }

    /* walk extensions for supported_groups, signature_algorithms, key_share. */
    {
        qsc_tls_named_group clientgroups[QSC_TLS_MAX_GROUPS] = { 0 };
        qsc_tls_signature_scheme clientsigs[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { 0 };
        qsc_tls_named_group ksgroups[QSC_TLS_MAX_GROUPS] = { 0 };
        const uint8_t* ksshares[QSC_TLS_MAX_GROUPS] = { 0 };
        size_t kssharelens[QSC_TLS_MAX_GROUPS] = { 0 };
        size_t clientgroupcount;
        size_t clientsigcount;
        size_t eoff;
        size_t extblockabsoffset;
        size_t kscount;

        clientgroupcount = 0U;
        clientsigcount = 0U;
        eoff = 0U;
        kscount = 0U;

        /* Compute offset of extblock within msg: msg starts at legacy_version,
         * so absolute-within-msg offset = (extblock - msg). */
        extblockabsoffset = (size_t)(extblock - msg);

        while (eoff < extblocklen)
        {
            uint16_t etype;
            const uint8_t* ebody;
            size_t eblen;
            size_t ebodyeoffbefore;

            st = qsc_tls_codec_read_u16(extblock, extblocklen, &eoff, &etype);

            if (st != qsc_tls_status_success)
            {
                return st;
            }

            /* after reading 2-byte type + 2-byte length, eoff points at ebody. */
            ebodyeoffbefore = eoff + 2U;
            st = qsc_tls_codec_read_vector16_span(extblock, extblocklen, &eoff, &ebody, &eblen);

            if (st != qsc_tls_status_success)
            {
                return st;
            }

            if (etype == (uint16_t)qsc_tls_extension_supported_groups)
            {
                st = qsc_tls_extensions_decode_supported_groups(ebody, eblen, clientgroups, QSC_TLS_MAX_GROUPS, &clientgroupcount);

                if (st != qsc_tls_status_success)
                {
                    return st;
                }
            }
            else if (etype == (uint16_t)qsc_tls_extension_signature_algorithms)
            {
                st = qsc_tls_extensions_decode_signature_algorithms(ebody, eblen, clientsigs, QSC_TLS_MAX_SIGNATURE_SCHEMES, &clientsigcount);

                if (st != qsc_tls_status_success)
                {
                    return st;
                }
            }
            else if (etype == (uint16_t)qsc_tls_extension_key_share)
            {
                st = qsc_tls_extensions_decode_key_share_client_hello(ebody, eblen, ksgroups, ksshares, kssharelens, QSC_TLS_MAX_GROUPS, &kscount);

                if (st != qsc_tls_status_success)
                {
                    return st;
                }
            }
            else if (etype == (uint16_t)qsc_tls_extension_psk_key_exchange_modes)
            {
                /* body: opaque ke_modes<1..255>. We only support psk_dhe_ke = 0x01. */
                if (eblen >= 2U)
                {
                    uint8_t count;

                    count = ebody[0U];

                    for (size_t i = 0; i < count && 1U + i < eblen; ++i)
                    {
                        if (ebody[1U + i] == 0x01U) { sawpskmodesdhe = true; break; }
                    }
                }
            }
            else if (etype == (uint16_t)qsc_tls_extension_early_data)
            {
                sawearlydataext = true;
            }
            else if (etype == (uint16_t)qsc_tls_extension_pre_shared_key)
            {
                pskextbody = ebody;
                pskextbodylen = eblen;
                pskextabsbodyoffset = extblockabsoffset + ebodyeoffbefore;
            }
            /* supported_versions and server_name accepted but not recorded in MVP. */
        }

        /* record client capabilities. */
        state->clientcapabilities.groupcount = clientgroupcount;

        for (size_t i = 0; i < clientgroupcount; ++i)
        {
            state->clientcapabilities.groups[i] = clientgroups[i];
        }

        state->clientcapabilities.sigschemecount = clientsigcount;

        for (size_t i = 0; i < clientsigcount; ++i)
        {
            state->clientcapabilities.sigschemes[i] = clientsigs[i];
        }

        /* select a key_share we can service: first server preference that the client offered
         * AND has a matching key_share entry for. */
        for (size_t i = 0; i < state->config.groupspreferencecount && clientgroup == qsc_tls_group_none; ++i)
        {
            for (size_t j = 0; j < kscount; ++j)
            {
                if (state->config.groupspreference[i] == ksgroups[j])
                {
                    clientgroup = ksgroups[j];
                    clientkeyshare = ksshares[j];
                    clientkeysharelen = kssharelens[j];
                    break;
                }
            }
        }
    }

    /* ---- PSK resumption acceptance (RFC 8446 4.2.11) ----
     * If the client offered pre_shared_key AND we have a lookup callback AND the client
     * included psk_dhe_ke mode, attempt to accept the PSK.
     *
     * Binder validation:
     *   1. Compute transcript hash over truncated CH = 4-byte handshake header prefix +
     *      body[0 .. psk_ext_abs_body_offset + binder_block_offset_within_psk_ext].
     *   2. Look up the PSK via the config callback.
     *   3. Extract early_secret from the PSK, derive res binder_key.
     *   4. Compute expected binder and constant-time compare to the received binder.
     *   5. If match: set pskaccepted, selectedpskidentity, install early keys if 0-RTT.
     */
    if (pskextbody != NULL && state->config.psklookup != NULL && sawpskmodesdhe && !state->helloretryrequestsent)
    {
        qsc_tls_psk_identity_view ids[4U] = { 0U };
        const uint8_t* rxbinders[4U] = { 0U };
        size_t rxbinderlens[4U] = { 0U };
        size_t idcount;
        size_t binderblockoff;

        idcount = 0U;
        binderblockoff = 0U;

        st = qsc_tls_extensions_decode_pre_shared_key_offer(pskextbody, pskextbodylen, ids, rxbinders, rxbinderlens, 4U, &idcount, &binderblockoff);

        if (st != qsc_tls_status_success) 
        {
            return st; 
        }

        if (idcount == 0U) 
        {
            return qsc_tls_status_invalid_message; 
        }

        /* Walk each identity; accept first that validates. */
        for (size_t i = 0; i < idcount && !state->pskaccepted; ++i)
        {
            qsc_tls_key_schedule_state ksscratch = { 0 };
            qsc_tls_transcript_state scratch = { 0 };
            uint8_t expectedbinder[QSC_TLS_HASH_MAX_SIZE] = { 0U };
            size_t expectedbinderlen;
            uint8_t hdr[4U] = { 0U };
            uint8_t psk[QSC_TLS_HASH_MAX_SIZE] = { 0U };
            uint8_t trunchash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
            size_t psklen;
            size_t truncbodyoff;
            size_t trunchashlen;
            uint32_t maxearly;
            qsc_tls_cipher_suite ticketsuite;
            qsc_tls_status vst;
            bool have;

            expectedbinderlen = 0U;
            psklen = 0U;
            trunchashlen = 0U;
            ticketsuite = qsc_tls_cipher_suite_none;
            maxearly = 0U;

            have = state->config.psklookup(ids[i].identity, ids[i].identitylen, psk, sizeof(psk), &psklen, &ticketsuite, &maxearly, state->config.psklookupstate);
            
            if (!have) 
            { 
                continue; 
            }

            /* ticket-bound suite must match negotiated suite so the hash algorithm is consistent. */
            if (ticketsuite != state->negotiatedsuite)
            {
                qsc_memutils_secure_erase(psk, sizeof(psk));
                continue;
            }

            /* truncated-CH transcript hash. Truncation point within body: truncbodyoff = pskextabsbodyoffset + binderblockoff
             * total truncated bytes = 4-byte handshake header + body[0..truncbodyoff). */
            truncbodyoff = pskextabsbodyoffset + binderblockoff;

            if (truncbodyoff > msglen)
            {
                qsc_memutils_secure_erase(psk, sizeof(psk));
                continue;
            }

            hdr[0U] = (uint8_t)qsc_tls_handshake_type_client_hello;
            hdr[1U] = (uint8_t)((msglen >> 16) & 0xFFU);
            hdr[2U] = (uint8_t)((msglen >> 8) & 0xFFU);
            hdr[3U] = (uint8_t)(msglen & 0xFFU);

            vst = qsc_tls_transcript_initialize(&scratch, state->negotiatedhash);

            if (vst == qsc_tls_status_success)
            { 
                vst = qsc_tls_transcript_update(&scratch, hdr, 4U); 
            }

            if (vst == qsc_tls_status_success)
            {
                vst = qsc_tls_transcript_update(&scratch, msg, truncbodyoff); 
            }

            if (vst == qsc_tls_status_success)
            {
                vst = qsc_tls_transcript_snapshot(&scratch, trunchash, sizeof(trunchash), &trunchashlen);
            }

            /* derive expected binder. Uses key schedule scratch copy to avoid disturbing the main schedule. */
            
            if (vst == qsc_tls_status_success)
            {
                vst = qsc_tls_keyschedule_state_initialize(&ksscratch, state->negotiatedhash); 
            }

            if (vst == qsc_tls_status_success)
            {
                vst = qsc_tls_keyschedule_extract_early_secret(&ksscratch, psk, psklen);
            }

            if (vst == qsc_tls_status_success)
            {
                vst = qsc_tls_keyschedule_derive_binder_key(&ksscratch, false);
            }

            if (vst == qsc_tls_status_success)
            {
                vst = qsc_tls_keyschedule_compute_psk_binder(state->negotiatedhash, ksscratch.binderkey, ksscratch.digestsize,
                    trunchash, trunchashlen, expectedbinder, sizeof(expectedbinder), &expectedbinderlen);
            }

            if (vst == qsc_tls_status_success && rxbinderlens[i] == expectedbinderlen && qsc_memutils_are_equal(expectedbinder, rxbinders[i], expectedbinderlen))
            {
                state->pskaccepted = true;
                state->selectedpskidentity = (uint16_t)i;

                /* Extract early secret into the main schedule now so later stages can use it. */
                (void)qsc_tls_keyschedule_state_initialize(&state->keyschedule, state->negotiatedhash);
                (void)qsc_tls_keyschedule_extract_early_secret(&state->keyschedule, psk, psklen);

                /* if client offered early_data AND server accepts AND maxearly > 0:
                 * derive client_early_traffic_secret and install as READ key. After that we
                 * expect application-data records from the client until EndOfEarlyData. */
                if (sawearlydataext && state->config.acceptearlydata && maxearly > 0U)
                {
                    /* Full-CH transcript hash (main transcript was just populated at dispatcher level). */
                    uint8_t chhash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
                    size_t chhashlen;

                    chhashlen = 0U;

                    if (qsc_tls_transcript_snapshot(&state->transcript, chhash, sizeof(chhash), &chhashlen) == qsc_tls_status_success)
                    {
                        if (qsc_tls_keyschedule_derive_client_early_traffic_secret(&state->keyschedule, chhash, chhashlen) == qsc_tls_status_success)
                        {
                            uint8_t eiv[12U] = { 0U };
                            uint8_t ekey[32U] = { 0U };
                            size_t ilen;
                            size_t klen;

                            if (qsc_tls_keyschedule_suite_record_sizes(state->negotiatedsuite, &klen, &ilen) == qsc_tls_status_success && 
                               qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clientearlytrafficsecret, state->keyschedule.digestsize, klen, ilen, ekey, eiv) == qsc_tls_status_success && 
                               qsc_tls_record_state_install_keys(&state->readrecord, state->negotiatedsuite, ekey, klen, eiv, ilen) == qsc_tls_status_success)
                            {
                                state->earlydataaccepted = true;
                            }

                            qsc_memutils_secure_erase(ekey, sizeof(ekey));
                            qsc_memutils_secure_erase(eiv, sizeof(eiv));
                        }
                    }

                    qsc_memutils_secure_erase(chhash, sizeof(chhash));
                }
            }

            qsc_memutils_secure_erase(psk, sizeof(psk));
            qsc_memutils_secure_erase(expectedbinder, sizeof(expectedbinder));
            qsc_memutils_secure_erase(trunchash, sizeof(trunchash));
        }
    }

    if (clientgroup == qsc_tls_group_none)
    {
        qsc_tls_named_group hrrtarget;

        /* no matching key_share, check if HRR can rescue: find a group in the
         * client's supported_groups that matches server preference. If so, emit
         * HRR with that group. If the client already sent HRR once, refuse. */
        if (state->helloretryrequestsent)
        {
            state->lastalert = qsc_tls_alert_unexpected_message;
            return qsc_tls_status_invalid_state;
        }

        hrrtarget = qsc_tls_group_none;

        for (size_t i = 0; i < state->config.groupspreferencecount && hrrtarget == qsc_tls_group_none; ++i)
        {
            for (size_t j = 0; j < state->clientcapabilities.groupcount; ++j)
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
            return qsc_tls_status_not_supported;
        }

        /* record HRR target; the server_emit_flight1 wrapper checks this flag and
         * emits only the HRR message instead of the full flight. */
        state->helloretryrequestsent = true;
        state->hrrgroup = hrrtarget;
        state->negotiatedgroup = hrrtarget;

        /* still need to pick the signature scheme from what the client offered,
         * because HRR echoes the cipher suite and that requires the hash to match. */
        for (size_t i = 0U; i < state->config.sigschemepreferencecount; ++i)
        {
            for (size_t j = 0U; j < state->clientcapabilities.sigschemecount; ++j)
            {
                if (state->config.sigschemepreference[i] == state->clientcapabilities.sigschemes[j])
                {
                    state->negotiatedsigscheme = state->config.sigschemepreference[i];
                    goto hrr_sig_picked;
                }
            }
        }

    hrr_sig_picked:

        return qsc_tls_status_success;
    }

    state->negotiatedgroup = clientgroup;

    /* generate server key share + shared secret. */
    {
        uint8_t ss[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
        size_t sslen;

        sslen = 0U;

        st = qsc_tls_groups_server_respond(clientgroup, clientkeyshare, clientkeysharelen, state->serverkeyshare, sizeof(state->serverkeyshare),
            &state->serverkeysharelen, ss, sizeof(ss), &sslen);

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        /* key schedule through handshake secret.
         * when a PSK was accepted, the early_secret was already extracted from the PSK
         * during binder validation above. Only initialize + zero-extract for non-PSK flows. */
        if (!state->pskaccepted)
        {
            st = qsc_tls_keyschedule_state_initialize(&state->keyschedule, state->negotiatedhash);

            if (st == qsc_tls_status_success)
            {
                st = qsc_tls_keyschedule_extract_early_secret(&state->keyschedule, NULL, 0U);
            }
        }

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_keyschedule_extract_handshake_secret(&state->keyschedule, ss, sslen);
        }

        qsc_memutils_secure_erase(ss, sizeof(ss));

        if (st != qsc_tls_status_success)
        {
            return st;
        }

        /* pick signature scheme = first server preference that client accepted. */
        for (size_t i = 0U; i < state->config.sigschemepreferencecount; ++i)
        {
            for (size_t j = 0U; j < state->clientcapabilities.sigschemecount; ++j)
            {
                if (state->config.sigschemepreference[i] == state->clientcapabilities.sigschemes[j])
                {
                    state->negotiatedsigscheme = state->config.sigschemepreference[i];
                    goto sig_picked;
                }
            }
        }

    sig_picked:

        if (state->negotiatedsigscheme == qsc_tls_sig_none)
        {
            state->lastalert = qsc_tls_alert_handshake_failure;
            return qsc_tls_status_not_supported;
        }
    }

    state->sharedsecretlen = 0U;

    return qsc_tls_status_success;
}

static qsc_tls_status server_emit_hrr(qsc_tls_server_state* state, uint8_t* output, size_t outlen, size_t* written)
{
    uint8_t body[QSC_TLS_SERVER_HELLO_BODY_MAX_SIZE] = { 0U };
    uint8_t hs[4U + QSC_TLS_SERVER_HELLO_BODY_MAX_SIZE] = { 0U };
    size_t boff;
    size_t exthdr;
    size_t hsoff;
    size_t rec_written;
    qsc_tls_status st;

    boff = 0U;
    hsoff = 0U;
    rec_written = 0U;

    /* replace transcript with message_hash(ClientHello1) before HRR. */
    st = qsc_tls_transcript_replace_with_message_hash(&state->transcript);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    /* build HRR body (same format as ServerHello). */
    st = qsc_tls_codec_write_u16(body, sizeof(body), &boff, QSC_TLS_PROTOCOL_VERSION_12);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    qsc_memutils_copy(state->serverrandom, tls_hrr_special_random, 32U);
    st = qsc_tls_codec_write_bytes(body, sizeof(body), &boff, state->serverrandom, 32U);

    if (st != qsc_tls_status_success)
    {
        return st;
    }

    st = qsc_tls_codec_write_vector8(body, sizeof(body), &boff, (const uint8_t*)"", 0U);

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

    st = qsc_tls_codec_vector_begin_u16(body, sizeof(body), &boff, &exthdr);

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_extensions_encode_supported_versions_server(body, sizeof(body), &boff);
    }

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_extensions_encode_key_share_hello_retry(body, sizeof(body), &boff, state->hrrgroup);
    }

    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_codec_vector_end_u16(body, sizeof(body), &boff, exthdr);
    }

    if (st != qsc_tls_status_success)
    {
        return st;
    }

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

    st = qsc_tls_record_encode_plaintext(output, outlen, &rec_written, qsc_tls_record_content_handshake, hs, hsoff);

    if (st == qsc_tls_status_success)
    {
        *written = rec_written;
    }

    return st;
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

        /* RFC 8446: ServerHello legacy_session_id_echo MUST equal the ClientHello legacy_session_id. */
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

        /* If we accepted a PSK, echo pre_shared_key(selected_identity) in ServerHello. */
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
        uint8_t body[4U] = { 0U };
        uint8_t hs[4U + 2U + 4U] = { 0U };  /* 4-byte header + 2-byte len + up to 4 bytes early_data */
        size_t bodyoff;
        size_t hsoff;
        size_t recwritten;

        bodyoff = 0U;
        hsoff = 0U;
        recwritten = 0U;

        /* Build extensions vector body first, then emit. */
        if (state->earlydataaccepted)
        {
            /* early_data extension in EE context = empty body: type(2)+length(2)=0. */
            body[bodyoff] = 0x00U;
            ++bodyoff;
            body[bodyoff] = 0x2AU;  /* extension_type = early_data (42) */
            ++bodyoff;
            body[bodyoff] = 0x00U;
            ++bodyoff;
            body[bodyoff] = 0x00U;  /* zero-length body */
            ++bodyoff;
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

    /* ---- certificate ---- (skipped on PSK resumption per RFC 8446 2.2) */
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
            st = qsc_tls_keyschedule_compute_finished(state->negotiatedhash, state->keyschedule.serverhandshaketrafficsecret,
                state->keyschedule.digestsize, thash, thashlen, mac, sizeof(mac), &maclen);
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

            /* On 0-RTT-accepted flow we'll receive EOED before client Finished, and EOED
             * gets added to transcript. App-key derivation must use CH..server_Finished
             * snapshot it now while the transcript is at the correct boundary. */
            if (st == qsc_tls_status_success && state->earlydataaccepted)
            {
                state->stashedserverfinhashlen = 0U;
                st = qsc_tls_transcript_snapshot(&state->transcript,
                    state->stashedserverfinhash, sizeof(state->stashedserverfinhash),
                    &state->stashedserverfinhashlen);
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

    /* master secret is derivable now. */
    st = qsc_tls_keyschedule_extract_master_secret(&state->keyschedule);
    *written = off;

    return st;
}

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
        st = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.serverhandshaketrafficsecret,
            state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_record_state_install_keys(&state->writerecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    if (st == qsc_tls_status_success && !state->earlydataaccepted)
    {
        /* Normal flow: install client_hs_traffic as our READ key now.
         * On 0-RTT-accepted flow the read record holds the early_traffic key for
         * incoming 0-RTT app data and the EOED message; we swap to client_hs_traffic
         * inside the EOED handler. */
        st = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clienthandshaketrafficsecret, 
            state->keyschedule.digestsize, keylen, ivlen, key, iv);

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
        st = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.serverapplicationtrafficsecret,
            state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_record_state_install_keys(&state->writerecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }
    if (st == qsc_tls_status_success)
    {
        st = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clientapplicationtrafficsecret,
            state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (st == qsc_tls_status_success)
        {
            st = qsc_tls_record_state_install_keys(&state->readrecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    qsc_memutils_secure_erase(key, sizeof(key));
    qsc_memutils_secure_erase(iv, sizeof(iv));

    return st;
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
        st = qsc_tls_keyschedule_verify_finished(state->negotiatedhash, state->keyschedule.clienthandshaketrafficsecret,
            state->keyschedule.digestsize, thash, thashlen, msg, msglen);
    }

    qsc_memutils_secure_erase(thash, sizeof(thash));

    if (st == qsc_tls_status_success)
    {
        state->clientauthenticated = true;
    }
    else
    {
        state->lastalert = qsc_tls_alert_decrypt_error;
    }

    return st;
}

bool qsc_tls_server_is_handshake_complete(const qsc_tls_server_state* state)
{
    return (state != NULL && state->phase == qsc_tls_server_phase_established);
}

qsc_tls_cipher_suite qsc_tls_server_get_negotiated_cipher_suite(const qsc_tls_server_state* state)
{
    return (state != NULL) ? state->negotiatedsuite : qsc_tls_cipher_suite_none;
}
