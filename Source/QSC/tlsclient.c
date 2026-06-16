#include "tlsclient.h"
#include "csp.h"
#include "memutils.h"
#include "tlscodec.h"
#include "tlsdefs.h"
#include "tlsextensions.h"
#include "tlshandshake.h"
#include "tlskeyschedule.h"
#include "tlstranscript.h"
#include "tlsrecord.h"

/* RFC 8446 4.1.3 HelloRetryRequest magic random value. */
static const uint8_t tls_client_hrr_special_random[32U] = 
{
    0xCFU, 0x21U, 0xADU, 0x74U, 0xE5U, 0x9AU, 0x61U, 0x11U,
    0xBEU, 0x1DU, 0x8CU, 0x02U, 0x1EU, 0x65U, 0xB8U, 0x91U,
    0xC2U, 0xA2U, 0x11U, 0x16U, 0x7AU, 0xBBU, 0x8CU, 0x5EU,
    0x07U, 0x9EU, 0x09U, 0xE2U, 0xC8U, 0xA8U, 0x33U, 0x9CU
};

static bool client_cipher_suite_offered(const qsc_tls_client_state* state, qsc_tls_cipher_suite suite)
{
    bool res;

    res = false;

    if (state != NULL && state->config.ciphersuites != NULL)
    {
        size_t i;

        for (i = 0U; i < state->config.ciphersuitecount; ++i)
        {
            if (state->config.ciphersuites[i] == suite)
            {
                res = true;
                break;
            }
        }
    }

    return res;
}

static qsc_tls_status client_validate_selected_cipher_suite(qsc_tls_client_state* state, qsc_tls_cipher_suite suite)
{
    qsc_tls_status status;

    status = qsc_tls_status_success;

    if (client_cipher_suite_offered(state, suite) == false || qsc_tls_keyschedule_suite_hash(suite) == qsc_tls_hash_none)
    {
        state->lastalert = qsc_tls_alert_illegal_parameter;
        status = qsc_tls_status_invalid_message;
    }
    else if (state->helloretryrequestconsumed == true && state->negotiatedsuite != qsc_tls_cipher_suite_none && state->negotiatedsuite != suite)
    {
        state->lastalert = qsc_tls_alert_illegal_parameter;
        status = qsc_tls_status_invalid_message;
    }

    return status;
}

static qsc_tls_status client_build_clienthello(qsc_tls_client_state* state, uint8_t* body, size_t bodycap, size_t* bodylen, size_t* binder_offset_in_body_out, size_t* binder_len_out)
{
    size_t exthdr;
    size_t i;
    size_t off;
    size_t suiteshdr;
    qsc_tls_status status;

    if (binder_offset_in_body_out != NULL)
    {
        *binder_offset_in_body_out = 0U; 
    }

    if (binder_len_out != NULL)
    {
        *binder_len_out = 0U; 
    }

    off = 0U;

    /* legacy_version - TLS 1.2 */
    status = qsc_tls_codec_write_u16(body, bodycap, &off, QSC_TLS_PROTOCOL_VERSION_12);

    if (status == qsc_tls_status_success)
    {
        if (state->clientrandomgenerated == false)
        {
            state->clientrandomgenerated = qsc_csp_generate(state->clientrandom, 32U);
        }

        if (state->clientrandomgenerated == true)
        {
            status = qsc_tls_codec_write_bytes(body, bodycap, &off, state->clientrandom, 32U);

            if (status == qsc_tls_status_success)
            {
                /* legacy_session_id <0..32> - empty */
                status = qsc_tls_codec_write_vector8(body, bodycap, &off, (const uint8_t*)"", 0U);

                if (status == qsc_tls_status_success)
                {
                    /* cipher_suites<2..2^16-2> */
                    status = qsc_tls_codec_vector_begin_u16(body, bodycap, &off, &suiteshdr);

                    if (status == qsc_tls_status_success)
                    {
                        for (i = 0U; i < state->config.ciphersuitecount && status == qsc_tls_status_success; ++i)
                        {
                            status = qsc_tls_codec_write_u16(body, bodycap, &off, (uint16_t)state->config.ciphersuites[i]);
                        }

                        if (status == qsc_tls_status_success)
                        {
                            status = qsc_tls_codec_vector_end_u16(body, bodycap, &off, suiteshdr);

                            if (status == qsc_tls_status_success)
                            {
                                /* legacy_compression_methods<1..2^8-1> = [0] */
                                {
                                    const uint8_t compzero[1U] = { 0U };
                                    status = qsc_tls_codec_write_vector8(body, bodycap, &off, compzero, 1U);
                                }

                                if (status == qsc_tls_status_success)
                                {
                                    /* extensions<8..2^16-1> */
                                    status = qsc_tls_codec_vector_begin_u16(body, bodycap, &off, &exthdr);

                                    if (status == qsc_tls_status_success)
                                    {
                                        if (status == qsc_tls_status_success)
                                        {
                                            status = qsc_tls_extensions_encode_supported_versions_client(body, bodycap, &off);

                                            if (status == qsc_tls_status_success)
                                            {
                                                status = qsc_tls_extensions_encode_supported_groups(body, bodycap, &off, state->config.groups, state->config.groupcount);

                                                if (status == qsc_tls_status_success)
                                                {
                                                    status = qsc_tls_extensions_encode_signature_algorithms(body, bodycap, &off, state->config.sigschemes, state->config.sigschemecount);

                                                    if (status == qsc_tls_status_success && state->config.hostname != NULL)
                                                    {
                                                        status = qsc_tls_extensions_encode_server_name(body, bodycap, &off, state->config.hostname);
                                                    }

                                                    if (status == qsc_tls_status_success && state->config.alpn.configured == true)
                                                    {
                                                        status = qsc_tls_extensions_encode_alpn(body, bodycap, &off, &state->config.alpn);
                                                    }

                                                    if (status == qsc_tls_status_success)
                                                    {
                                                        status = qsc_tls_extensions_encode_key_share_client(body, bodycap, &off,
                                                            state->keyexchange.group, state->keyexchange.publicshare, state->keyexchange.publicsharelen);

                                                        /* psk resumption extensions (RFC 8446 4.2.11) */
                                                        if (status == qsc_tls_status_success && state->config.offeredticket != NULL)
                                                        {
                                                            /* psk_key_exchange_modes: we support psk_dhe_ke (0x01). */
                                                            const uint8_t psk_dhe_ke_modes[1U] = { 0x01U };

                                                            status = qsc_tls_extensions_encode_psk_key_exchange_modes(body, bodycap, &off, psk_dhe_ke_modes, 1U);

                                                            /* early_data (empty, requesting 0-RTT). Only when enableearlydata. */
                                                            if (status == qsc_tls_status_success && state->config.enableearlydata)
                                                            {
                                                                status = qsc_tls_extensions_encode_early_data_empty(body, bodycap, &off);

                                                                if (status == qsc_tls_status_success)
                                                                {
                                                                    state->earlydataoffered = true;
                                                                }
                                                            }

                                                            /* pre_shared_key - MUST be the final extension per RFC 8446 4.2.11. */
                                                            if (status == qsc_tls_status_success)
                                                            {
                                                                qsc_tls_psk_identity_view id_view;
                                                                size_t binder_offset_abs;
                                                                size_t binderlen;

                                                                binder_offset_abs = 0U;
                                                                binderlen = state->config.offeredticket->resumptionsecretlen;
                                                                id_view.identity = state->config.offeredticket->ticket;
                                                                id_view.identitylen = state->config.offeredticket->ticketlen;
                                                                /* Obfuscated ticket age: for test purposes use ageadd directly (age=0 + ageadd mod 2^32). */
                                                                id_view.obfuscatedticketage = state->config.offeredticket->ageadd;

                                                                status = qsc_tls_extensions_encode_pre_shared_key_offer(body, bodycap, &off,
                                                                    &id_view, 1U, binderlen, &binder_offset_abs);

                                                                if (status == qsc_tls_status_success)
                                                                {
                                                                    state->pskoffered = true;
                                                                    if (binder_offset_in_body_out != NULL) { *binder_offset_in_body_out = binder_offset_abs; }
                                                                    if (binder_len_out != NULL) { *binder_len_out = binderlen; }
                                                                }
                                                            }
                                                        }

                                                        if (status == qsc_tls_status_success)
                                                        {
                                                            status = qsc_tls_codec_vector_end_u16(body, bodycap, &off, exthdr);
                                                        }

                                                        if (status == qsc_tls_status_success)
                                                        {
                                                            *bodylen = off;
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        else
        {
            status = qsc_tls_status_failure;
        }
    }

    return status;
}

static bool client_server_hello_is_hrr(const uint8_t* body, size_t bodylen)
{
    bool res;

    res = false;

    /* body layout: u16 legacy_version + 32 bytes random + ... */
    if (body != NULL && bodylen >= 34U) 
    { 
        res = qsc_memutils_are_equal(body + 2U, tls_client_hrr_special_random, 32U);
    }

    return res;
}

static qsc_tls_status client_rebuild_transcript_for_server_hello(qsc_tls_client_state* state, const uint8_t* serverhello, size_t serverhellolen)
{
    qsc_tls_status status;

    QSC_ASSERT(state != NULL);
    QSC_ASSERT(serverhello != NULL);

    status = qsc_tls_status_invalid_input;

    if (state != NULL && serverhello != NULL && serverhellolen != 0U)
    {
        status = qsc_tls_transcript_initialize(&state->transcript, state->negotiatedhash);

        if (status == qsc_tls_status_success)
        {
            if (state->clienthellolen == 0U)
            {
                status = qsc_tls_status_invalid_state;
            }
            else
            {
                status = qsc_tls_transcript_update(&state->transcript, state->clienthello, state->clienthellolen);
            }
        }

        if (status == qsc_tls_status_success && state->helloretryrequestconsumed == true)
        {
            status = qsc_tls_transcript_replace_with_message_hash(&state->transcript);

            if (status == qsc_tls_status_success)
            {
                if (state->helloretryrequestlen == 0U || state->retryclienthellolen == 0U)
                {
                    status = qsc_tls_status_invalid_state;
                }
                else
                {
                    status = qsc_tls_transcript_update(&state->transcript, state->helloretryrequest, state->helloretryrequestlen);
                }
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_transcript_update(&state->transcript, state->retryclienthello, state->retryclienthellolen);
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_transcript_update(&state->transcript, serverhello, serverhellolen);
        }
    }

    return status;
}

static qsc_tls_status client_process_server_hello(qsc_tls_client_state* state, const uint8_t* msg, size_t msglen)
{
    const uint8_t* extblock;
    const uint8_t* serverkeyshare;
    const uint8_t* sid;
    size_t extblocklen;
    size_t off;
    size_t serverkeysharelen;
    size_t sidlen;
    uint16_t legver;
    uint16_t suiteraw;
    uint8_t compmethod;
    qsc_tls_named_group selgroup;
    qsc_tls_status status;

    compmethod = 0U;
    off = 0U;
    selgroup = qsc_tls_group_none;
    serverkeyshare = NULL;
    serverkeysharelen = 0U;

    /* legacy_version */
    status = qsc_tls_codec_read_u16(msg, msglen, &off, &legver);

    if (status == qsc_tls_status_success)
    {
        /* server_random */
        if (off + 32U <= msglen)
        {
            qsc_memutils_copy(state->serverrandom, msg + off, 32U);
            off += 32U;

            /* session_id echo */
            status = qsc_tls_codec_read_vector8_span(msg, msglen, &off, &sid, &sidlen);

            if (status == qsc_tls_status_success)
            {
                /* cipher_suite */
                status = qsc_tls_codec_read_u16(msg, msglen, &off, &suiteraw);

                if (status == qsc_tls_status_success)
                {
                    status = client_validate_selected_cipher_suite(state, (qsc_tls_cipher_suite)suiteraw);

                    if (status == qsc_tls_status_success)
                    {
                        state->negotiatedsuite = (qsc_tls_cipher_suite)suiteraw;
                    }

                    /* legacy_compression_method */
                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_codec_read_u8(msg, msglen, &off, &compmethod);
                    }

                    if (status == qsc_tls_status_success)
                    {
                        if (compmethod == 0U)
                        {
                            /* extensions */
                            status = qsc_tls_codec_read_vector16_span(msg, msglen, &off, &extblock, &extblocklen);

                            if (status == qsc_tls_status_success)
                            {
                                if (off == msglen)
                                {
                                    /* walk the extension block and extract key_share.
                                     * RFC 8446 s4.2.1: client MUST verify supported_versions == 0x0304.
                                     * RFC 8446 s4.2: unknown extensions in ServerHello MUST be rejected. */
                                    {
                                        size_t extoff;
                                        bool version13confirmed;

                                        extoff = 0U;
                                        version13confirmed = false;

                                        while (extoff < extblocklen)
                                        {
                                            uint16_t exttype;
                                            const uint8_t* extbody;
                                            size_t extbodylen;

                                            status = qsc_tls_codec_read_u16(extblock, extblocklen, &extoff, &exttype);

                                            if (status != qsc_tls_status_success)
                                            {
                                                return status;
                                            }

                                            status = qsc_tls_codec_read_vector16_span(extblock, extblocklen, &extoff, &extbody, &extbodylen);

                                            if (status != qsc_tls_status_success)
                                            {
                                                return status;
                                            }

                                            if (exttype == (uint16_t)qsc_tls_extension_supported_versions)
                                            {
                                                /* decode and verify the selected version is exactly TLS 1.3. */
                                                uint16_t selver;

                                                selver = 0U;
                                                status = qsc_tls_extensions_decode_supported_versions_server(extbody, extbodylen, &selver);

                                                if (status != qsc_tls_status_success)
                                                {
                                                    return status;
                                                }

                                                if (selver != QSC_TLS_PROTOCOL_VERSION_13)
                                                {
                                                    state->lastalert = qsc_tls_alert_illegal_parameter;
                                                    return qsc_tls_status_invalid_message;
                                                }

                                                version13confirmed = true;
                                            }
                                            else if (exttype == (uint16_t)qsc_tls_extension_key_share)
                                            {
                                                status = qsc_tls_extensions_decode_key_share_server_hello(extbody, extbodylen, &selgroup, &serverkeyshare, &serverkeysharelen);

                                                if (status != qsc_tls_status_success)
                                                {
                                                    return status;
                                                }
                                            }
                                            else if (exttype == (uint16_t)qsc_tls_extension_pre_shared_key)
                                            {
                                                uint16_t sel;

                                                sel = 0xFFFFU;
                                                status = qsc_tls_extensions_decode_pre_shared_key_server(extbody, extbodylen, &sel);

                                                if (status != qsc_tls_status_success)
                                                {
                                                    return status;
                                                }

                                                if (sel != 0U)
                                                {
                                                    state->lastalert = qsc_tls_alert_illegal_parameter;
                                                    return qsc_tls_status_invalid_message;
                                                }

                                                state->pskaccepted = true;
                                            }
                                            else
                                            {
                                                /* RFC 8446 s4.2: reject any extension not offered by the client. */
                                                state->lastalert = qsc_tls_alert_unsupported_extension;
                                                return qsc_tls_status_invalid_message;
                                            }
                                        }

                                        /* supported_versions MUST have been present and confirmed TLS 1.3. */
                                        if (!version13confirmed)
                                        {
                                            state->lastalert = qsc_tls_alert_missing_extension;
                                            return qsc_tls_status_invalid_message;
                                        }
                                    }

                                    if (selgroup == qsc_tls_group_none || selgroup != state->keyexchange.group)
                                    {
                                        return qsc_tls_status_not_supported;
                                    }

                                    /* derive the DHE shared secret. */
                                    {
                                        uint8_t ss[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
                                        size_t sslen;

                                        sslen = 0U;

                                        status = qsc_tls_groups_client_derive_shared_secret(&state->keyexchange, serverkeyshare, serverkeysharelen, ss, sizeof(ss), &sslen);

                                        if (status != qsc_tls_status_success)
                                        {
                                            qsc_memutils_secure_erase(ss, sizeof(ss));
                                            return status;
                                        }

                                        /* key schedule up through handshake secret */
                                        state->negotiatedhash = qsc_tls_keyschedule_suite_hash(state->negotiatedsuite);

                                        if (!state->pskaccepted)
                                        {
                                            status = qsc_tls_keyschedule_state_initialize(&state->keyschedule, state->negotiatedhash);

                                            if (status == qsc_tls_status_success)
                                            {
                                                status = qsc_tls_keyschedule_extract_early_secret(&state->keyschedule, NULL, 0U);
                                            }
                                        }

                                        if (status == qsc_tls_status_success)
                                        {
                                            status = qsc_tls_keyschedule_extract_handshake_secret(&state->keyschedule, ss, sslen);
                                        }

                                        qsc_memutils_secure_erase(ss, sizeof(ss));
                                    }

                                    state->negotiatedgroup = selgroup;
                                }
                                else
                                {
                                    status = qsc_tls_status_invalid_length;
                                }
                            }
                        }
                        else
                        {
                            status = qsc_tls_status_invalid_message;
                        }
                    }
                }
            }
        }
        else
        {
            status = qsc_tls_status_invalid_length;
        }
    }

    return status;
}

static qsc_tls_status client_process_hello_retry_request(qsc_tls_client_state* state, const uint8_t* hrr_msg, size_t hrr_msglen,
    const uint8_t* hrr_hdr_plus_body, size_t hrr_hdr_plus_body_len, uint8_t* output, size_t outlen, size_t* written)
{
    uint8_t body[QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE] = { 0U };
    uint8_t hs[4U + QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE] = { 0U };
    const uint8_t* extblock;
    const uint8_t* sid;
    size_t bodylen;
    size_t extblocklen;
    size_t hsoff;
    size_t off;
    size_t rec_written;
    size_t sidlen;
    uint16_t suiteraw;
    uint16_t legver;
    uint8_t compmethod;
    qsc_tls_named_group reqgroup;
    qsc_tls_status status;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (hrr_hdr_plus_body_len <= sizeof(state->helloretryrequest))
    {
        qsc_memutils_copy(state->helloretryrequest, hrr_hdr_plus_body, hrr_hdr_plus_body_len);
        state->helloretryrequestlen = hrr_hdr_plus_body_len;
    }
    else
    {
        return qsc_tls_status_buffer_too_small;
    }

    /* step 1: apply message_hash transform to transcript (CH1 -> Hash(CH1)) */
    status = qsc_tls_transcript_replace_with_message_hash(&state->transcript);

    if (status == qsc_tls_status_success)
    {
        /* step 2: update transcript with the HRR handshake message bytes */
        status = qsc_tls_transcript_update(&state->transcript, hrr_hdr_plus_body, hrr_hdr_plus_body_len);

        if (status == qsc_tls_status_success)
        {
            /* step 3: parse HRR body, pull the requested group from key_share extension */
            off = 0U;
            status = qsc_tls_codec_read_u16(hrr_msg, hrr_msglen, &off, &legver);

            if (status == qsc_tls_status_success)
            {
                /* skip the 32-byte HRR magic random (already matched by caller). */
                if (off + 32U <= hrr_msglen)
                {
                    off += 32U;

                    status = qsc_tls_codec_read_vector8_span(hrr_msg, hrr_msglen, &off, &sid, &sidlen);

                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_codec_read_u16(hrr_msg, hrr_msglen, &off, &suiteraw);

                        if (status == qsc_tls_status_success)
                        {
                            status = client_validate_selected_cipher_suite(state, (qsc_tls_cipher_suite)suiteraw);

                            if (status == qsc_tls_status_success)
                            {
                                /* lock in the selected suite; it determines the transcript hash going forward. */
                                state->negotiatedsuite = (qsc_tls_cipher_suite)suiteraw;
                                status = qsc_tls_codec_read_u8(hrr_msg, hrr_msglen, &off, &compmethod);
                            }

                            if (status == qsc_tls_status_success)
                            {
                                if (compmethod == 0U)
                                {
                                    status = qsc_tls_codec_read_vector16_span(hrr_msg, hrr_msglen, &off, &extblock, &extblocklen);

                                    if (status == qsc_tls_status_success)
                                    {
                                        /* walk extensions looking for key_share; that carries the requested group. */
                                        reqgroup = qsc_tls_group_none;

                                        {
                                            size_t eoff;

                                            eoff = 0U;

                                            while (eoff < extblocklen)
                                            {
                                                const uint8_t* ebody;
                                                size_t eblen;
                                                uint16_t etype;

                                                status = qsc_tls_codec_read_u16(extblock, extblocklen, &eoff, &etype);

                                                if (status != qsc_tls_status_success)
                                                {
                                                    return status;
                                                }

                                                status = qsc_tls_codec_read_vector16_span(extblock, extblocklen, &eoff, &ebody, &eblen);

                                                if (status != qsc_tls_status_success)
                                                {
                                                    return status;
                                                }

                                                if (etype == (uint16_t)qsc_tls_extension_key_share)
                                                {
                                                    status = qsc_tls_extensions_decode_key_share_hello_retry(ebody, eblen, &reqgroup);

                                                    if (status != qsc_tls_status_success)
                                                    {
                                                        return status;
                                                    }
                                                }
                                            }
                                        }

                                        if (reqgroup == qsc_tls_group_none)
                                        {
                                            state->lastalert = qsc_tls_alert_missing_extension;

                                            return qsc_tls_status_invalid_message;
                                        }

                                        /* confirm the requested group is one we offered in supported_groups per our config. */
                                        {
                                            bool acceptable;

                                            acceptable = false;

                                            for (size_t i = 0U; i < state->config.groupcount; ++i)
                                            {
                                                if (state->config.groups[i] == reqgroup)
                                                {
                                                    acceptable = true;
                                                    break;
                                                }
                                            }
                                            if (!acceptable)
                                            {
                                                state->lastalert = qsc_tls_alert_illegal_parameter;
                                                return qsc_tls_status_not_supported;
                                            }
                                        }

                                        /* step 4: dispose old keyexchange state, generate a fresh keypair for the requested group */
                                        qsc_tls_groups_key_exchange_state_dispose(&state->keyexchange);
                                        status = qsc_tls_groups_generate_client_keypair(&state->keyexchange, reqgroup);

                                        if (status != qsc_tls_status_success)
                                        {
                                            return status;
                                        }

                                        /* step 5: rebuild ClientHello2 with the same config/clientrandom but the new key_share */
                                        bodylen = 0U;
                                        status = client_build_clienthello(state, body, sizeof(body), &bodylen, NULL, NULL);

                                        if (status != qsc_tls_status_success)
                                        {
                                            return status;
                                        }

                                        hsoff = 0U;
                                        status = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_client_hello, bodylen);

                                        if (status != qsc_tls_status_success)
                                        {
                                            return status;
                                        }

                                        qsc_memutils_copy(hs + hsoff, body, bodylen);
                                        hsoff += bodylen;

                                        if (hsoff <= sizeof(state->retryclienthello))
                                        {
                                            qsc_memutils_copy(state->retryclienthello, hs, hsoff);
                                            state->retryclienthellolen = hsoff;
                                        }
                                        else
                                        {
                                            return qsc_tls_status_buffer_too_small;
                                        }

                                        /* update transcript with CH2. */
                                        status = qsc_tls_transcript_update(&state->transcript, hs, hsoff);

                                        if (status != qsc_tls_status_success)
                                        {
                                            return status;
                                        }

                                        /* Wrap in plaintext record and write to output. */
                                        rec_written = 0U;

                                        status = qsc_tls_record_encode_plaintext(output, outlen, &rec_written, qsc_tls_record_content_handshake, hs, hsoff);

                                        if (status != qsc_tls_status_success)
                                        {
                                            return status;
                                        }

                                        if (written != NULL)
                                        {
                                            *written = rec_written;
                                        }

                                        /* step 6: mark HRR consumed so a second HRR is rejected */
                                        state->helloretryrequestconsumed = true;
                                    }
                                }
                                else
                                {
                                    status = qsc_tls_status_invalid_message;
                                }
                            }
                        }
                    }
                }
                else
                {
                    status = qsc_tls_status_invalid_length;
                }
            }
        }
    }

    return status;
}

static qsc_tls_status client_install_handshake_keys(qsc_tls_client_state* state)
{
    uint8_t iv[12] = { 0U };
    uint8_t key[32] = { 0U };
    uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    size_t keylen;
    size_t ivlen;
    size_t thashlen;
    qsc_tls_status status;

    keylen = 0U;
    ivlen = 0U;
    thashlen = 0U;

    status = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_keyschedule_derive_handshake_traffic_secrets(&state->keyschedule, thash, thashlen);
    }

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_keyschedule_suite_record_sizes(state->negotiatedsuite, &keylen, &ivlen);
    }

    if (status == qsc_tls_status_success)
    {
        /* install read key (server_hs_traffic) first so we can decrypt the server's encrypted flight immediately. */
        status = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.serverhandshaketrafficsecret, state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_record_state_install_keys(&state->readrecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    if (status == qsc_tls_status_success && !state->earlydataoffered)
    {
        status = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clienthandshaketrafficsecret, state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_record_state_install_keys(&state->writerecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    qsc_memutils_secure_erase(thash, sizeof(thash));
    qsc_memutils_secure_erase(key, sizeof(key));
    qsc_memutils_secure_erase(iv, sizeof(iv));

    return status;
}

static qsc_tls_status client_process_certificate(qsc_tls_client_state* state, const uint8_t* msg, size_t msglen)
{
    qsc_tls_certificate_view chain[QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES] = { 0U };
    const uint8_t* rctx;
    size_t rctxlen;
    size_t chainlen;
    qsc_tls_status status;

    chainlen = 0U;
    rctx = NULL;
    rctxlen = 0U;

    status = qsc_tls_certificate_decode_message(msg, msglen, &rctx, &rctxlen, chain, QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES, &chainlen);

    if (status == qsc_tls_status_success)
    {
        if (chainlen != 0U)
        {
            qsc_tls_certificate_validation_context vctx;

            /* RFC 8446 requires the server certificate chain to be authenticated.
             * A NULL validation callback means that no trust-anchor, path, or
             * hostname verification can be performed by this client instance. */
            if (state->config.certinterface.validatechain == NULL)
            {
                state->lastalert = qsc_tls_alert_bad_certificate;
                status = qsc_tls_status_authentication_failure;
            }
            else
            {
                vctx.hostname = state->config.hostname;
                vctx.clientauth = false;
                vctx.requirepeercertificate = true;

                if (!state->config.certinterface.validatechain(chain, chainlen, &vctx, state->config.certinterface.state))
                {
                    state->lastalert = qsc_tls_alert_bad_certificate;
                    status = qsc_tls_status_authentication_failure;
                }
                else
                {
                    if (chain[0U].datalen <= sizeof(state->peercertificate))
                    {
                        qsc_memutils_copy(state->peercertificate, chain[0U].data, chain[0U].datalen);
                        state->peercertificatelen = chain[0U].datalen;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_bad_certificate;
                        status = qsc_tls_status_invalid_length;
                    }
                }
            }
        }
        else
        {
            state->lastalert = qsc_tls_alert_bad_certificate;
            status = qsc_tls_status_authentication_failure;
        }
    }

    return status;
}

static qsc_tls_status client_process_certificate_verify(qsc_tls_client_state* state, const uint8_t* msg, size_t msglen)
{
    uint8_t cvinput[256U] = { 0U };
    uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    const uint8_t* sig;
    size_t cvinputlen;
    size_t siglen;
    size_t thashlen;
    qsc_tls_signature_scheme scheme;
    qsc_tls_status status;

    cvinputlen = 0U;
    thashlen = 0U;

    status = qsc_tls_handshake_decode_certificate_verify(msg, msglen, &scheme, &sig, &siglen);

    if (status == qsc_tls_status_success)
    {
        state->negotiatedsigscheme = scheme;

        status = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_keyschedule_build_certificate_verify_input("TLS 1.3, server CertificateVerify", thash, thashlen, cvinput, sizeof(cvinput), &cvinputlen);

            if (status == qsc_tls_status_success)
            {
                /* RFC 8446 s4.4.3: CertificateVerify must be verified.
                 * A NULL callback means no signature check is possible; reject immediately. */
                if (state->config.certinterface.verifycertificateverify == NULL)
                {
                    state->lastalert = qsc_tls_alert_internal_error;
                    status = qsc_tls_status_invalid_state;
                }
                else
                {
                    qsc_tls_certificate_view view;
                    bool verifyres;

                    view.data = state->peercertificate;
                    view.datalen = state->peercertificatelen;

                    verifyres = state->config.certinterface.verifycertificateverify(scheme, cvinput, cvinputlen, sig, siglen, &view, state->config.certinterface.state);

                    if (verifyres == false)
                    {
                        state->lastalert = qsc_tls_alert_decrypt_error;
                        status = qsc_tls_status_authentication_failure;
                    }
                }

                qsc_memutils_secure_erase(thash, sizeof(thash));
                qsc_memutils_secure_erase(cvinput, sizeof(cvinput));
            }
        }
    }

    return status;
}

static qsc_tls_status client_process_finished(qsc_tls_client_state* state, const uint8_t* msg, size_t msglen)
{
    uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    size_t thashlen;
    qsc_tls_status status;

    thashlen = 0U;

    status = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_keyschedule_verify_finished(state->negotiatedhash, state->keyschedule.serverhandshaketrafficsecret, state->keyschedule.digestsize, thash, thashlen, msg, msglen);

        qsc_memutils_secure_erase(thash, sizeof(thash));

        if (status != qsc_tls_status_success)
        {
            state->lastalert = qsc_tls_alert_decrypt_error;
        }
        else
        {
            state->serverauthenticated = true;
        }
    }

    return status;
}

static qsc_tls_status client_emit_finished(qsc_tls_client_state* state, uint8_t* output, size_t outlen, size_t* written)
{
    uint8_t hs[4U + QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t mac[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    size_t hsoff;
    size_t maclen;
    size_t thashlen;
    qsc_tls_status status;

    hsoff = 0U;
    maclen = 0U;
    thashlen = 0U;

    if (written != NULL) 
    { 
        *written = 0U;
    }

    status = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);

    if (status == qsc_tls_status_success) 
    {
        status = qsc_tls_keyschedule_compute_finished(state->negotiatedhash, state->keyschedule.clienthandshaketrafficsecret, state->keyschedule.digestsize, thash, thashlen, mac, sizeof(mac), &maclen);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_finished, maclen);

            if (status == qsc_tls_status_success)
            {
                qsc_memutils_copy(hs + hsoff, mac, maclen);
            }

            hsoff += maclen;

            /* update transcript with our Finished for application-secret derivation. */
            status = qsc_tls_transcript_update(&state->transcript, hs, hsoff);

            if (status == qsc_tls_status_success)
            {
                /* encrypt as handshake payload with the client handshake traffic key. */
                status = qsc_tls_record_encrypt(&state->writerecord, output, outlen, written, qsc_tls_record_content_handshake, hs, hsoff);
            }
        }
    }

    qsc_memutils_secure_erase(thash, sizeof(thash));
    qsc_memutils_secure_erase(mac, sizeof(mac));
    qsc_memutils_secure_erase(hs, sizeof(hs));

    return status;
}

static qsc_tls_status client_install_app_keys(qsc_tls_client_state* state)
{
    uint8_t key[32U] = { 0U };
    uint8_t iv[12U] = { 0U };
    size_t keylen;
    size_t ivlen;
    qsc_tls_status status;

    keylen = 0U;
    ivlen = 0U;

    status = qsc_tls_keyschedule_suite_record_sizes(state->negotiatedsuite, &keylen, &ivlen);

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clientapplicationtrafficsecret, state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_record_state_install_keys(&state->writerecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.serverapplicationtrafficsecret, state->keyschedule.digestsize, keylen, ivlen, key, iv);

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_record_state_install_keys(&state->readrecord, state->negotiatedsuite, key, keylen, iv, ivlen);
        }
    }

    qsc_memutils_secure_erase(key, sizeof(key));
    qsc_memutils_secure_erase(iv, sizeof(iv));

    return status;
}

qsc_tls_status qsc_tls_client_config_set_certificate_interface(qsc_tls_client_config* config, const qsc_tls_certificate_interface* iface, const char* hostname)
{
    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (config != NULL && iface != NULL && qsc_tls_certificate_interface_is_valid(iface) == true)
    {
        config->certinterface = *iface;
        config->hostname = hostname;
        status = qsc_tls_status_success;
    }

    return status;
}

qsc_tls_status qsc_tls_client_initialize(qsc_tls_client_state* state, const qsc_tls_client_config* config)
{
    QSC_ASSERT(state != NULL);
    QSC_ASSERT(config != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (state != NULL && config != NULL && config->ciphersuites != NULL && config->ciphersuitecount != 0U &&
        config->groups != NULL && config->groupcount != 0U && config->sigschemes != NULL && config->sigschemecount != 0U)
    {
        qsc_memutils_clear(state, sizeof(*state));
        state->config = *config;
        state->phase = qsc_tls_client_phase_initial;
        state->negotiatedsuite = qsc_tls_cipher_suite_none;
        state->negotiatedhash = qsc_tls_hash_none;
        state->negotiatedgroup = qsc_tls_group_none;
        state->negotiatedsigscheme = qsc_tls_sig_none;

        status = qsc_tls_status_success;
    }

    return status;
}

void qsc_tls_client_dispose(qsc_tls_client_state* state)
{
    QSC_ASSERT(state != NULL);

    if (state != NULL)
    {
        qsc_tls_transcript_dispose(&state->transcript);
        qsc_tls_keyschedule_state_dispose(&state->keyschedule);
        qsc_tls_record_state_dispose(&state->readrecord);
        qsc_tls_record_state_dispose(&state->writerecord);
        qsc_tls_groups_key_exchange_state_dispose(&state->keyexchange);
        qsc_memutils_secure_erase(state, sizeof(*state));
    }
}

qsc_tls_status qsc_tls_client_send_hello(qsc_tls_client_state* state, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(state != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);

    uint8_t body[QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE] = { 0 };
    uint8_t hs[QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE + 4U] = { 0 };
    size_t bodylen;
    size_t hsoff;
    qsc_tls_status status;

    bodylen = 0U;
    hsoff = 0U;

    if (written != NULL) 
    { 
        *written = 0U; 
    }

    if (state != NULL && output != NULL && written != NULL)
    {
        size_t binderoffsetinbody;
        size_t binderlen;

        if (state->phase != qsc_tls_client_phase_initial)
        {
            return qsc_tls_status_invalid_state;
        }

        state->negotiatedhash = qsc_tls_keyschedule_suite_hash(state->config.ciphersuites[0]);

        if (state->negotiatedhash == qsc_tls_hash_none)
        {
            return qsc_tls_status_not_supported;
        }

        status = qsc_tls_transcript_initialize(&state->transcript, state->negotiatedhash);

        if (status != qsc_tls_status_success)
        {
            return status;
        }

        /* generate client key share for the first supported group. */
        status = qsc_tls_groups_generate_client_keypair(&state->keyexchange, state->config.groups[0U]);

        if (status != qsc_tls_status_success)
        {
            return status;
        }

        binderoffsetinbody = 0U;
        binderlen = 0U;

        status = client_build_clienthello(state, body, sizeof(body), &bodylen, &binderoffsetinbody, &binderlen);

        if (status != qsc_tls_status_success)
        {
            return status;
        }

        /* build handshake message: 4-byte header + body */
        status = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_client_hello, bodylen);

        if (status != qsc_tls_status_success)
        {
            return status;
        }

        qsc_memutils_copy(hs + hsoff, body, bodylen);
        hsoff += bodylen;

        if (state->pskoffered && state->config.offeredticket != NULL)
        {
            qsc_tls_transcript_state scratchts = { 0 };
            uint8_t truncatedhash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
            const size_t header_size = 4U;
            size_t truncatedhashlen;
            size_t truncoffsetinhs;

            truncatedhashlen = 0U;

            if (binderoffsetinbody < 3U)
            {
                return qsc_tls_status_invalid_state;
            }

            truncoffsetinhs = header_size + (binderoffsetinbody - 3U);

            /* set negotiatedhash from the offered PSK's suite + initialize keyschedule */
            state->negotiatedhash = qsc_tls_keyschedule_suite_hash(state->config.offeredticket->suite);

            if (state->negotiatedhash == qsc_tls_hash_none)
            {
                return qsc_tls_status_invalid_state;
            }

            status = qsc_tls_keyschedule_state_initialize(&state->keyschedule, state->negotiatedhash);

            if (status != qsc_tls_status_success) 
            { 
                return status; 
            }

            /* compute truncated transcript hash using a scratch hash state. */
            status = qsc_tls_transcript_initialize(&scratchts, state->negotiatedhash);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_transcript_update(&scratchts, hs, truncoffsetinhs);
            }

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_transcript_snapshot(&scratchts, truncatedhash, sizeof(truncatedhash), &truncatedhashlen);
            }

            /* extract early_secret from PSK */
            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_keyschedule_extract_early_secret(&state->keyschedule, state->config.offeredticket->resumptionsecret, state->config.offeredticket->resumptionsecretlen);
            }

            if (status == qsc_tls_status_success)
            {
                /* resumption binder */
                status = qsc_tls_keyschedule_derive_binder_key(&state->keyschedule, false);
            }

            /* compute binder and patch */
            if (status == qsc_tls_status_success)
            {
                uint8_t binderout[QSC_TLS_HASH_MAX_SIZE] = { 0U };
                size_t binderwritten;

                binderwritten = 0U;
                status = qsc_tls_keyschedule_compute_psk_binder(state->negotiatedhash, state->keyschedule.binderkey, state->keyschedule.digestsize, truncatedhash, truncatedhashlen, binderout, sizeof(binderout), &binderwritten);

                if (status == qsc_tls_status_success)
                {
                    if (binderwritten != binderlen)
                    {
                        status = qsc_tls_status_invalid_length;
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    qsc_memutils_copy(hs + header_size + binderoffsetinbody, binderout, binderlen);
                }

                qsc_memutils_secure_erase(binderout, sizeof(binderout));
            }

            qsc_memutils_secure_erase(truncatedhash, sizeof(truncatedhash));
        }

        if (hsoff <= sizeof(state->clienthello))
        {
            qsc_memutils_copy(state->clienthello, hs, hsoff);
            state->clienthellolen = hsoff;
        }
        else
        {
            return qsc_tls_status_buffer_too_small;
        }

        /* update transcript with the handshake message (excluding record header) */
        status = qsc_tls_transcript_update(&state->transcript, hs, hsoff);

        if (status != qsc_tls_status_success)
        {
            return status;
        }

        if (state->earlydataoffered)
        {
            uint8_t chhash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
            size_t chhashlen;

            chhashlen = 0U;
            status = qsc_tls_transcript_snapshot(&state->transcript, chhash, sizeof(chhash), &chhashlen);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_keyschedule_derive_client_early_traffic_secret(&state->keyschedule, chhash, chhashlen);
            }

            if (status == qsc_tls_status_success)
            {
                /* install the early traffic key into the write record. */
                uint8_t earlykey[32U] = { 0U };
                uint8_t earlyiv[12U] = { 0U };
                size_t ivlen;
                size_t keylen;

                status = qsc_tls_keyschedule_suite_record_sizes(state->config.ciphersuites[0], &keylen, &ivlen);

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clientearlytrafficsecret, state->keyschedule.digestsize, keylen, ivlen, earlykey, earlyiv);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_record_state_install_keys(&state->writerecord, state->config.ciphersuites[0], earlykey, keylen, earlyiv, ivlen);
                }

                qsc_memutils_secure_erase(earlykey, sizeof(earlykey));
                qsc_memutils_secure_erase(earlyiv, sizeof(earlyiv));
            }

            qsc_memutils_secure_erase(chhash, sizeof(chhash));

            if (status != qsc_tls_status_success) 
            {
                return status; 
            }
        }

        /* wrap in a plaintext TLSPlaintext record and emit. */
        status = qsc_tls_record_encode_plaintext(output, outlen, written, qsc_tls_record_content_handshake, hs, hsoff);

        if (status != qsc_tls_status_success)
        {
            return status;
        }

        state->phase = qsc_tls_client_phase_waiting_server_hello;
    }
    else
    {
        status = qsc_tls_status_invalid_input;
    }

    return status;
}

qsc_tls_status qsc_tls_client_process_record(qsc_tls_client_state* state, const uint8_t* input, size_t inlen, size_t* consumed, uint8_t* output, size_t outlen, size_t* written)
{
    QSC_ASSERT(state != NULL);
    QSC_ASSERT(input != NULL);
    QSC_ASSERT(consumed != NULL);
    QSC_ASSERT(output != NULL);
    QSC_ASSERT(written != NULL);

    uint8_t decrypt_buf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    const uint8_t* payload;
    uint8_t* ptext;
    size_t payloadlen;
    size_t reclen;
    size_t ptextlen;
    size_t declen;
    qsc_tls_record_content_type rtype;
    qsc_tls_status status;
    bool complete;

    ptext = NULL;
    ptextlen = 0U;
    declen = 0U;
    status = qsc_tls_status_invalid_input;

    if (consumed != NULL) 
    { 
        *consumed = 0U; 
    }

    if (written != NULL) 
    { 
        *written = 0U; 
    }

    if (state == NULL || input == NULL || consumed == NULL || (output == NULL && outlen != 0U) || written == NULL)
    {
        return qsc_tls_status_invalid_input;
    }

    status = qsc_tls_record_try_get_span_length(input, inlen, &reclen, &complete);

    if (status != qsc_tls_status_success) 
    { 
        return status; 
    }

    if (!complete) 
    { 
        /* partial record, wait for more */
        return qsc_tls_status_success; 
    }

    status = qsc_tls_record_decode_plaintext(input, reclen, &rtype, &payload, &payloadlen);

    if (status != qsc_tls_status_success) 
    { 
        return status; 
    }

    /* if we're past the ServerHello, inbound records after the first plaintext ServerHello are protected, decrypt them */
    if (state->readrecord.initialized && rtype == qsc_tls_record_content_application_data)
    {
        qsc_tls_record_content_type inner_type = qsc_tls_record_content_invalid;

        status = qsc_tls_record_decrypt(&state->readrecord, decrypt_buf, sizeof(decrypt_buf), &declen, &inner_type, input, reclen);

        if (status != qsc_tls_status_success)
        { 
            return status; 
        }

        ptext = decrypt_buf;
        ptextlen = declen;
        rtype = inner_type;
    }
    else
    {
        ptext = (uint8_t*)payload;
        ptextlen = payloadlen;
    }

    /* ignore the compatibility ChangeCipherSpec record the server may send */
    if (rtype == qsc_tls_record_content_change_cipher_spec)
    {
        state->changecipherspecreceived = true;
        *consumed = reclen;

        return qsc_tls_status_success;
    }

    if (rtype == qsc_tls_record_content_alert)
    {
        if (ptextlen >= 2U)
        {
            state->lastalert = (qsc_tls_alert_description)ptext[1U];
        }

        state->phase = qsc_tls_client_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_failure;
    }

    if (rtype != qsc_tls_record_content_handshake)
    {
        return qsc_tls_status_invalid_message;
    }

    /* walk handshake messages inside the record. */
    {
        size_t offset;

        offset = 0U;

        while (offset < ptextlen)
        {
            qsc_tls_handshake_type type;
            size_t bodylen;
            size_t hdroff;

            hdroff = offset;
            status = qsc_tls_handshake_read_header(ptext, ptextlen, &offset, &type, &bodylen);

            if (status != qsc_tls_status_success) 
            { 
                return status; 
            }

            if (bodylen > ptextlen - offset)
            { 
                return qsc_tls_status_invalid_length; 
            }

            const uint8_t* body = ptext + offset;

            switch (type)
            {
                case qsc_tls_handshake_type_server_hello:
                {
                    if (state->phase != qsc_tls_client_phase_waiting_server_hello)
                    {
                        return qsc_tls_status_invalid_state;
                    }

                    /* peek at the 32-byte random to decide: real ServerHello vs HelloRetryRequest */
                    if (client_server_hello_is_hrr(body, bodylen))
                    {
                        if (state->helloretryrequestconsumed)
                        {
                            /* second HRR - forbidden per RFC 8446 4.1.4 */
                            state->lastalert = qsc_tls_alert_unexpected_message;
                            return qsc_tls_status_invalid_state;
                        }
                        status = client_process_hello_retry_request(state, body, bodylen, ptext + hdroff, 4U + bodylen, output, outlen, written);
                        /* stay in waiting_server_hello: the real ServerHello comes after CH2 */
                    }
                    else
                    {
                        status = client_process_server_hello(state, body, bodylen);

                        if (status == qsc_tls_status_success)
                        {
                            status = client_rebuild_transcript_for_server_hello(state, ptext + hdroff, 4U + bodylen);
                        }

                        if (status == qsc_tls_status_success)
                        {
                            status = client_install_handshake_keys(state);
                        }

                        if (status == qsc_tls_status_success)
                        {
                            state->phase = qsc_tls_client_phase_waiting_encrypted_extensions;
                        }
                    }

                    break;
                }
                case qsc_tls_handshake_type_encrypted_extensions:
                {
                    if (state->phase != qsc_tls_client_phase_waiting_encrypted_extensions)
                    {
                        return qsc_tls_status_invalid_state;
                    }

                    status = qsc_tls_transcript_update(&state->transcript, ptext + hdroff, 4U + bodylen);

                    /* Scan EE extensions: watch for early_data acceptance and ALPN selection. */
                    if (status == qsc_tls_status_success && bodylen >= 2U)
                    {
                        uint16_t extveclen;
                        size_t eoff;

                        extveclen = ((uint16_t)body[0U] << 8) | body[1];
                        eoff = 2U;

                        if ((size_t)extveclen + 2U != bodylen)
                        {
                            state->lastalert = qsc_tls_alert_decode_error;
                            status = qsc_tls_status_invalid_length;
                        }

                        while (status == qsc_tls_status_success && eoff + 4U <= (size_t)(2U + extveclen))
                        {
                            qsc_tls_alpn_protocols peer_alpn;
                            uint16_t etype;
                            uint16_t elen;

                            etype = ((uint16_t)body[eoff] << 8) | body[eoff + 1U];
                            elen = ((uint16_t)body[eoff + 2U] << 8) | body[eoff + 3U];
                            eoff += 4U;

                            if ((size_t)elen > ((size_t)(2U + extveclen) - eoff))
                            {
                                state->lastalert = qsc_tls_alert_decode_error;
                                status = qsc_tls_status_invalid_length;
                                break;
                            }

                            if (etype == (uint16_t)qsc_tls_extension_early_data && elen == 0U)
                            {
                                state->earlydataaccepted = true;
                            }
                            else if (etype == (uint16_t)qsc_tls_extension_application_layer_protocol_negotiation)
                            {
                                status = qsc_tls_extensions_decode_alpn(body + eoff, elen, &peer_alpn);

                                if (status == qsc_tls_status_success)
                                {
                                    if (peer_alpn.protocolcount == 1U)
                                    {
                                        status = qsc_tls_extensions_select_alpn(&peer_alpn, &state->config.alpn,
                                            state->selectedalpn, sizeof(state->selectedalpn), &state->selectedalpnlen);

                                        if (status == qsc_tls_status_success)
                                        {
                                            state->alpnselected = true;
                                        }
                                        else
                                        {
                                            state->lastalert = qsc_tls_alert_no_application_protocol;
                                        }
                                    }
                                    else
                                    {
                                        state->lastalert = qsc_tls_alert_decode_error;
                                        status = qsc_tls_status_invalid_message;
                                    }
                                }
                                else
                                {
                                    state->lastalert = qsc_tls_alert_decode_error;
                                }
                            }

                            eoff += elen;
                        }
                    }

                    if (status == qsc_tls_status_success && state->config.alpn.required == true && state->alpnselected == false)
                    {
                        state->lastalert = qsc_tls_alert_no_application_protocol;
                        status = qsc_tls_status_not_supported;
                    }

                    /* if 0-RTT was offered but NOT accepted, install the deferred handshake write key now. 
                     * the write record currently holds the early_traffic key from CH
                     * emission; without this swap the Finished message would be encrypted under the early key and rejected by the server. */
                    if (status == qsc_tls_status_success && state->earlydataoffered && !state->earlydataaccepted)
                    {
                        uint8_t hiv[12U] = { 0U };
                        uint8_t hkey[32U] = { 0U };
                        size_t ilen;
                        size_t klen;

                        status = qsc_tls_keyschedule_suite_record_sizes(state->negotiatedsuite, &klen, &ilen);

                        if (status == qsc_tls_status_success)
                        {
                            status = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash, state->keyschedule.clienthandshaketrafficsecret, state->keyschedule.digestsize, klen, ilen, hkey, hiv);
                        }

                        if (status == qsc_tls_status_success)
                        {
                            status = qsc_tls_record_state_install_keys(&state->writerecord, state->negotiatedsuite, hkey, klen, hiv, ilen);
                        }

                        qsc_memutils_secure_erase(hkey, sizeof(hkey));
                        qsc_memutils_secure_erase(hiv, sizeof(hiv));
                    }

                    if (status == qsc_tls_status_success)
                    {
                        state->phase = state->pskaccepted ? qsc_tls_client_phase_waiting_finished : qsc_tls_client_phase_waiting_certificate;
                    }

                    break;
                }
                case qsc_tls_handshake_type_certificate:
                {
                    if (state->phase != qsc_tls_client_phase_waiting_certificate)
                    {
                        return qsc_tls_status_invalid_state;
                    }

                    status = qsc_tls_transcript_update(&state->transcript, ptext + hdroff, 4U + bodylen);

                    if (status == qsc_tls_status_success)
                    {
                        status = client_process_certificate(state, body, bodylen);
                    }

                    if (status == qsc_tls_status_success)
                    {
                        state->phase = qsc_tls_client_phase_waiting_certificate_verify;
                    }

                    break;
                }
                case qsc_tls_handshake_type_certificate_verify:
                {
                    if (state->phase != qsc_tls_client_phase_waiting_certificate_verify)
                    {
                        return qsc_tls_status_invalid_state;
                    }

                    /* verify FIRST with the transcript that ends at Certificate; THEN update with CV. */
                    status = client_process_certificate_verify(state, body, bodylen);

                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_transcript_update(&state->transcript, ptext + hdroff, 4U + bodylen);
                    }

                    if (status == qsc_tls_status_success)
                    {
                        state->phase = qsc_tls_client_phase_waiting_finished;
                    }

                    break;
                }
                case qsc_tls_handshake_type_finished:
                {
                    if (state->phase != qsc_tls_client_phase_waiting_finished)
                    {
                        return qsc_tls_status_invalid_state;
                    }

                    status = client_process_finished(state, body, bodylen);

                    if (status == qsc_tls_status_success)
                    {
                        /* transcript update with server Finished. */
                        status = qsc_tls_transcript_update(&state->transcript, ptext + hdroff, 4U + bodylen);
                    }

                    if (status == qsc_tls_status_success)
                    {
                        /* snapshot for app-secret derivation BEFORE client Finished is added
                         * per RFC 8446 7.1: c/s ap traffic = Derive-Secret(Master, "...", CH..server Finished) */
                        uint8_t thashapp[QSC_TLS_HASH_MAX_SIZE] = { 0U };
                        size_t thashapplen;

                        thashapplen = 0U;

                        status = qsc_tls_transcript_snapshot(&state->transcript, thashapp, sizeof(thashapp), &thashapplen);

                        if (status == qsc_tls_status_success)
                        {
                            status = qsc_tls_keyschedule_extract_master_secret(&state->keyschedule);
                        }

                        if (status == qsc_tls_status_success)
                        {
                            status = qsc_tls_keyschedule_derive_application_traffic_secrets(&state->keyschedule, thashapp, thashapplen);
                        }

                        if (status == qsc_tls_status_success)
                        {
                            if (state->earlydataaccepted)
                            {
                                uint8_t eoedhs[4U] = { 0U };
                                uint8_t eoedrec[64U] = { 0U };
                                size_t eoedoff;
                                size_t eoedreclen;

                                eoedoff = 0U;
                                eoedreclen = 0U;
                                status = qsc_tls_handshake_write_header(eoedhs, sizeof(eoedhs), &eoedoff, qsc_tls_handshake_type_end_of_early_data, 0U);

                                if (status == qsc_tls_status_success)
                                {
                                    status = qsc_tls_transcript_update(&state->transcript, eoedhs, eoedoff);
                                }

                                if (status == qsc_tls_status_success)
                                {
                                    status = qsc_tls_record_encrypt(&state->writerecord, eoedrec, sizeof(eoedrec), &eoedreclen, qsc_tls_record_content_handshake, eoedhs, eoedoff);
                                }

                                if (status == qsc_tls_status_success)
                                {
                                    /* copy EOED record into the caller's output buffer ahead of where Finished will be written next */
                                    if (eoedreclen > outlen) 
                                    { 
                                        status = qsc_tls_status_buffer_too_small; 
                                    }
                                    else
                                    {
                                        qsc_memutils_copy(output, eoedrec, eoedreclen);
                                        /* advance output pointer/outlen for the subsequent Finished emit */
                                        output += eoedreclen;
                                        outlen -= eoedreclen;

                                        if (written != NULL) 
                                        { 
                                            *written = eoedreclen; 
                                        }
                                    }
                                }

                                /* swap write record to client_handshake_traffic key */
                                if (status == qsc_tls_status_success)
                                {
                                    uint8_t hiv[12U] = { 0U };
                                    uint8_t hkey[32U] = { 0U };
                                    size_t ilen;
                                    size_t klen;

                                    status = qsc_tls_keyschedule_suite_record_sizes(state->negotiatedsuite, &klen, &ilen);

                                    if (status == qsc_tls_status_success)
                                    {
                                        status = qsc_tls_keyschedule_derive_traffic_keys(state->negotiatedhash,
                                            state->keyschedule.clienthandshaketrafficsecret, state->keyschedule.digestsize, klen, ilen, hkey, hiv);
                                    }

                                    if (status == qsc_tls_status_success)
                                    {
                                        status = qsc_tls_record_state_install_keys(&state->writerecord, state->negotiatedsuite, hkey, klen, hiv, ilen);
                                    }

                                    qsc_memutils_secure_erase(hkey, sizeof(hkey));
                                    qsc_memutils_secure_erase(hiv, sizeof(hiv));
                                }
                            }

                            /* emit client Finished encrypted under handshake write key */
                            size_t fin_written = 0U;
                            if (status == qsc_tls_status_success)
                            {
                                status = client_emit_finished(state, output, outlen, &fin_written);
                            }

                            if (status == qsc_tls_status_success && written != NULL)
                            {
                                *written += fin_written;
                            }
                        }

                        if (status == qsc_tls_status_success)
                        {
                            /* install application keys onto both directions */
                            status = client_install_app_keys(state);
                        }

                        qsc_memutils_secure_erase(thashapp, sizeof(thashapp));
                    }

                    if (status == qsc_tls_status_success)
                    {
                        /* derive resumption_master_secret now that transcript includes client Finished */
                        uint8_t thashrms[QSC_TLS_HASH_MAX_SIZE] = { 0U };
                        size_t thashrmslen;

                        thashrmslen = 0U;
                        status = qsc_tls_transcript_snapshot(&state->transcript, thashrms, sizeof(thashrms), &thashrmslen);

                        if (status == qsc_tls_status_success)
                        {
                            status = qsc_tls_keyschedule_derive_resumption_master_secret(&state->keyschedule, thashrms, thashrmslen);
                        }

                        qsc_memutils_secure_erase(thashrms, sizeof(thashrms));
                    }

                    if (status == qsc_tls_status_success)
                    {
                        state->phase = qsc_tls_client_phase_established;
                    }

                    break;
                }
                default:
                {
                    return qsc_tls_status_invalid_message;
                }
            }

            if (status != qsc_tls_status_success)
            {
                state->phase = qsc_tls_client_phase_failed;
                return status;
            }

            offset += bodylen;
        }
    }

    *consumed = reclen;

    return qsc_tls_status_success;
}

bool qsc_tls_client_is_handshake_complete(const qsc_tls_client_state* state)
{ 
    QSC_ASSERT(state != NULL);

    return (state != NULL && state->phase == qsc_tls_client_phase_established); 
}

qsc_tls_cipher_suite qsc_tls_client_get_negotiated_cipher_suite(const qsc_tls_client_state* state)
{ 
    QSC_ASSERT(state != NULL);

    return (state != NULL) ? state->negotiatedsuite : qsc_tls_cipher_suite_none; 
}
