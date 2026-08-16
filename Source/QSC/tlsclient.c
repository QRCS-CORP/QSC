#include "tlsclient.h"
#include "tlsalert.h"
#include "csp.h"
#include "memutils.h"
#include "intutils.h"
#include "tlscodec.h"
#include "tlsdefs.h"
#include "tlsextensions.h"
#include "tlsgroups.h"
#include "tlshandshake.h"
#include "tlskeyschedule.h"
#include "tlstranscript.h"
#include "tlsrecord.h"
#include "tlssigalgs.h"
#include "tlssignerdefault.h"
#include "stringutils.h"
#include "timestamp.h"

/* RFC 9846 4.2.4 HelloRetryRequest magic random value. */
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

static bool client_extension_is_known(uint16_t extensiontype)
{
    bool res;

    res = false;

    switch ((qsc_tls_extension_type)extensiontype)
    {
        case qsc_tls_extension_server_name:
        case qsc_tls_extension_supported_groups:
        case qsc_tls_extension_signature_algorithms:
        case qsc_tls_extension_application_layer_protocol_negotiation:
        case qsc_tls_extension_pre_shared_key:
        case qsc_tls_extension_early_data:
        case qsc_tls_extension_supported_versions:
        case qsc_tls_extension_cookie:
        case qsc_tls_extension_psk_key_exchange_modes:
        case qsc_tls_extension_signature_algorithms_cert:
        case qsc_tls_extension_key_share:
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

static bool client_signature_scheme_offered(const qsc_tls_client_state* state, qsc_tls_signature_scheme scheme)
{
    size_t i;
    bool res;

    i = 0U;
    res = false;

    if (state != NULL && state->config.sigschemes != NULL)
    {
        for (i = 0U; i < state->config.sigschemecount; ++i)
        {
            if (state->config.sigschemes[i] == scheme)
            {
                res = true;
                break;
            }
        }
    }

    return res;
}

static bool tls_client_local_certificate_sign(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, uint8_t* signature, size_t* signaturelen, void* state)
{
    qsc_tls_signer_default_context sctx;
    const qsc_tls_local_certificate_config* localcert;
    bool res;

    localcert = (const qsc_tls_local_certificate_config*)state;
    res = false;

    if (localcert != NULL && localcert->signprivatekeylen != 0U)
    {
        sctx.scheme = scheme;
        sctx.privatekey = localcert->signprivatekey;
        sctx.privatekeylen = localcert->signprivatekeylen;
        res = qsc_tls_signer_default_sign(scheme, input, inputlen, signature, signaturelen, &sctx);
    }

    return res;
}

static bool client_auth_signature_scheme_requested(const qsc_tls_client_state* state, qsc_tls_signature_scheme scheme)
{
    size_t i;
    bool res;

    i = 0U;
    res = false;

    if (state != NULL)
    {
        for (i = 0U; i < state->clientauthsigschemecount; ++i)
        {
            if (state->clientauthsigschemes[i] == scheme)
            {
                res = true;
                break;
            }
        }
    }

    return res;
}

static qsc_tls_status client_process_certificate_request(qsc_tls_client_state* state, const uint8_t* msg, size_t msglen)
{
    uint8_t seen[8192U] = { 0U };
    qsc_tls_signature_scheme sigschemes[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { 0U };
    qsc_tls_signature_scheme certsigschemes[QSC_TLS_MAX_SIGNATURE_SCHEMES] = { 0U };
    const uint8_t* extblock;
    const uint8_t* extbody;
    const uint8_t* requestcontext;
    size_t certsigschemecount;
    size_t extblocklen;
    size_t extbodylen;
    size_t extoff;
    size_t index;
    size_t requestcontextlen;
    size_t sigschemecount;
    uint16_t exttype;
    uint8_t mask;
    qsc_tls_status status;
    bool hassignaturealgorithms;
    bool hassignaturealgorithmscert;

    certsigschemecount = 0U;
    extblock = NULL;
    extbody = NULL;
    extblocklen = 0U;
    extbodylen = 0U;
    extoff = 0U;
    index = 0U;
    requestcontext = NULL;
    requestcontextlen = 0U;
    sigschemecount = 0U;
    exttype = 0U;
    mask = 0U;
    status = qsc_tls_status_invalid_input;
    hassignaturealgorithms = false;
    hassignaturealgorithmscert = false;

    if (state != NULL && msg != NULL)
    {
        status = qsc_tls_certificate_request_decode(msg, msglen, &requestcontext, &requestcontextlen, &extblock, &extblocklen);

        if (status != qsc_tls_status_success)
        {
            state->lastalert = qsc_tls_alert_decode_error;
        }
        else if (requestcontextlen != 0U)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        while (status == qsc_tls_status_success && extoff < extblocklen)
        {
            extbody = NULL;
            extbodylen = 0U;
            status = qsc_tls_codec_read_u16(extblock, extblocklen, &extoff, &exttype);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_read_vector16_span(extblock, extblocklen, &extoff, &extbody, &extbodylen);
            }

            if (status != qsc_tls_status_success)
            {
                state->lastalert = qsc_tls_alert_decode_error;
            }

            if (status == qsc_tls_status_success)
            {
                index = ((size_t)exttype >> 3U);
                mask = (uint8_t)(1U << (exttype & 7U));

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

            if (status == qsc_tls_status_success && client_extension_is_known(exttype) == true)
            {
                if (qsc_tls_extensions_is_permitted(qsc_tls_handshake_type_certificate_request, (qsc_tls_extension_type)exttype) == false)
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                    status = qsc_tls_status_invalid_message;
                }
                else if (exttype == (uint16_t)qsc_tls_extension_signature_algorithms)
                {
                    status = qsc_tls_extensions_decode_signature_algorithms(extbody, extbodylen, sigschemes, QSC_TLS_MAX_SIGNATURE_SCHEMES, &sigschemecount);

                    if (status == qsc_tls_status_success)
                    {
                        hassignaturealgorithms = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (exttype == (uint16_t)qsc_tls_extension_signature_algorithms_cert)
                {
                    status = qsc_tls_extensions_decode_signature_algorithms(extbody, extbodylen, certsigschemes, QSC_TLS_MAX_SIGNATURE_SCHEMES, &certsigschemecount);

                    if (status == qsc_tls_status_success)
                    {
                        hassignaturealgorithmscert = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
            }
        }

        if (status == qsc_tls_status_success && hassignaturealgorithms == false)
        {
            state->lastalert = qsc_tls_alert_missing_extension;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            qsc_memutils_clear(state->clientauthsigschemes, sizeof(state->clientauthsigschemes));
            qsc_memutils_copy(state->clientauthsigschemes, sigschemes, sigschemecount * sizeof(qsc_tls_signature_scheme));
            state->clientauthsigschemecount = sigschemecount;
            qsc_memutils_clear(state->peercapabilities.certsigschemes, sizeof(state->peercapabilities.certsigschemes));

            if (hassignaturealgorithmscert == true)
            {
                qsc_memutils_copy(state->peercapabilities.certsigschemes, certsigschemes, certsigschemecount * sizeof(qsc_tls_signature_scheme));
                state->peercapabilities.certsigschemecount = certsigschemecount;
            }
            else
            {
                qsc_memutils_copy(state->peercapabilities.certsigschemes, sigschemes, sigschemecount * sizeof(qsc_tls_signature_scheme));
                state->peercapabilities.certsigschemecount = sigschemecount;
            }

            state->clientauthrequested = true;
            state->clientcertificatesent = false;
        }
    }

    return status;
}

static qsc_tls_status client_decode_server_supported_groups(const uint8_t* input, size_t inplen, qsc_tls_named_group* groups, size_t capacity, size_t* count)
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


static bool client_resumption_ticket_is_usable(const qsc_tls_client_state* state, const qsc_tls_session_ticket* ticket, bool retry, uint32_t* obfuscatedage)
{
    uint64_t elapsedms;
    uint64_t lifetimems;
    uint64_t now;
    size_t hostlen;
    size_t i;
    qsc_tls_hash_algorithm hash;
    bool hashallowed;
    bool res;

    elapsedms = 0ULL;
    lifetimems = 0ULL;
    now = 0ULL;
    hostlen = 0U;
    hash = qsc_tls_hash_none;
    hashallowed = false;
    res = false;

    if (obfuscatedage != NULL)
    {
        *obfuscatedage = 0U;
    }

    if (state != NULL && ticket != NULL && obfuscatedage != NULL)
    {
        hash = qsc_tls_keyschedule_suite_hash(ticket->suite);

        if (hash != qsc_tls_hash_none && ticket->protocolversion == QSC_TLS_PROTOCOL_VERSION_13 &&
            ticket->lifetime > 0U && ticket->lifetime <= QSC_TLS_SESSION_TICKET_LIFETIME_MAX &&
            ticket->receipttimems != 0ULL && ticket->ticketlen > 0U && ticket->ticketlen <= QSC_TLS_TICKET_MAX_SIZE &&
            ticket->resumptionsecretlen == qsc_tls_transcript_digest_size(hash))
        {
            if (retry == true)
            {
                hashallowed = (hash == state->negotiatedhash);
            }
            else
            {
                for (i = 0U; i < state->config.ciphersuitecount && hashallowed == false; ++i)
                {
                    hashallowed = (qsc_tls_keyschedule_suite_hash(state->config.ciphersuites[i]) == hash);
                }
            }

            if (hashallowed == true)
            {
                if (state->config.hostname != NULL)
                {
                    hostlen = qsc_stringutils_string_size(state->config.hostname);
                    res = (hostlen > 0U && hostlen <= QSC_TLS_MAX_HOSTNAME_SIZE && ticket->servernamelen == hostlen &&
                        qsc_memutils_are_equal(ticket->servername, (const uint8_t*)state->config.hostname, hostlen) == true);
                }
                else
                {
                    res = (ticket->servernamelen == 0U);
                }
            }

            if (res == true)
            {
                now = qsc_timestamp_epochtime_milliseconds();
                lifetimems = (uint64_t)ticket->lifetime * 1000ULL;

                if (now >= ticket->receipttimems)
                {
                    elapsedms = now - ticket->receipttimems;

                    if (elapsedms <= lifetimems && elapsedms <= (uint64_t)UINT32_MAX)
                    {
                        *obfuscatedage = (uint32_t)elapsedms + ticket->ageadd;
                    }
                    else
                    {
                        res = false;
                    }
                }
                else
                {
                    res = false;
                }
            }
        }
    }

    return res;
}


static qsc_tls_status client_build_clienthello(qsc_tls_client_state* state, uint8_t* body, size_t bodycap, size_t* bodylen, 
    size_t* binderoffset, size_t* binderlen, const uint8_t* cookie, size_t cookielen, bool retry)
{
    qsc_tls_psk_identity_view identity;
    const uint8_t psk_dhe_ke_modes[1U] = { 0x01U };
    const uint8_t compzero[1U] = { 0U };
    size_t exthdr;
    size_t i;
    size_t off;
    size_t pskbinderoffset;
    size_t pskbinderlen;
    size_t suiteshdr;
    uint32_t obfuscatedage;
    bool offerpsk;
    qsc_tls_status status;

    exthdr = 0U;
    off = 0U;
    pskbinderoffset = 0U;
    pskbinderlen = 0U;
    suiteshdr = 0U;
    obfuscatedage = 0U;
    offerpsk = false;
    status = qsc_tls_status_invalid_input;

    if (bodylen != NULL)
    {
        *bodylen = 0U;
    }

    if (binderoffset != NULL)
    {
        *binderoffset = 0U;
    }

    if (binderlen != NULL)
    {
        *binderlen = 0U;
    }

    if (state != NULL && body != NULL && bodylen != NULL && (cookie != NULL || cookielen == 0U))
    {
        offerpsk = client_resumption_ticket_is_usable(state, state->config.offeredticket, retry, &obfuscatedage);

        state->pskoffered = offerpsk;
        status = qsc_tls_codec_write_u16(body, bodycap, &off, QSC_TLS_PROTOCOL_VERSION_12);

        if (status == qsc_tls_status_success && state->clientrandomgenerated == false)
        {
            state->clientrandomgenerated = qsc_csp_generate(state->clientrandom, sizeof(state->clientrandom));

            if (state->clientrandomgenerated == false)
            {
                status = qsc_tls_status_failure;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_bytes(body, bodycap, &off, state->clientrandom, sizeof(state->clientrandom));
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_vector8(body, bodycap, &off, (const uint8_t*)"", 0U);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_begin_u16(body, bodycap, &off, &suiteshdr);
        }

        for (i = 0U; i < state->config.ciphersuitecount && status == qsc_tls_status_success; ++i)
        {
            status = qsc_tls_codec_write_u16(body, bodycap, &off, (uint16_t)state->config.ciphersuites[i]);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_end_u16(body, bodycap, &off, suiteshdr);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_write_vector8(body, bodycap, &off, compzero, sizeof(compzero));
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_vector_begin_u16(body, bodycap, &off, &exthdr);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_extensions_encode_supported_versions_client(body, bodycap, &off);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_extensions_encode_supported_groups(body, bodycap, &off, state->config.groups, state->config.groupcount);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_extensions_encode_signature_algorithms(body, bodycap, &off, state->config.sigschemes, state->config.sigschemecount);
        }

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
            status = qsc_tls_extensions_encode_key_share_client(body, bodycap, &off, state->keyexchange.group, state->keyexchange.publicshare, state->keyexchange.publicsharelen);
        }

        if (status == qsc_tls_status_success && cookie != NULL && cookielen != 0U)
        {
            status = qsc_tls_extensions_encode_cookie(body, bodycap, &off, cookie, cookielen);
        }

        if (status == qsc_tls_status_success && (state->config.enableresumption == true || offerpsk == true))
        {
            status = qsc_tls_extensions_encode_psk_key_exchange_modes(body, bodycap, &off, psk_dhe_ke_modes, sizeof(psk_dhe_ke_modes));
        }

        if (status == qsc_tls_status_success && offerpsk == true)
        {
            pskbinderlen = state->config.offeredticket->resumptionsecretlen;
            identity.identity = state->config.offeredticket->ticket;
            identity.identitylen = state->config.offeredticket->ticketlen;
            identity.obfuscatedticketage = obfuscatedage;
            status = qsc_tls_extensions_encode_pre_shared_key_offer(body, bodycap, &off, &identity, 1U, pskbinderlen, &pskbinderoffset);

            if (status == qsc_tls_status_success)
            {
                if (binderoffset != NULL)
                {
                    *binderoffset = pskbinderoffset;
                }

                if (binderlen != NULL)
                {
                    *binderlen = pskbinderlen;
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

    return status;
}

static qsc_tls_status client_patch_psk_binder(qsc_tls_client_state* state, uint8_t* handshake, size_t handshakelen, size_t binderoffset, size_t binderlen, bool retry)
{
    qsc_tls_key_schedule_state ksscratch = { 0 };
    qsc_tls_transcript_state scratch = { 0 };
    uint8_t binder[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t truncatedhash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    size_t binderwritten;
    size_t truncatedhashlen;
    size_t truncateoffset;
    qsc_tls_hash_algorithm hash;
    qsc_tls_status status;

    binderwritten = 0U;
    truncatedhashlen = 0U;
    truncateoffset = 0U;
    hash = qsc_tls_hash_none;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && handshake != NULL && state->pskoffered == true && state->config.offeredticket != NULL && binderoffset >= 3U && binderlen != 0U)
    {
        hash = qsc_tls_keyschedule_suite_hash(state->config.offeredticket->suite);

        if (hash == qsc_tls_hash_none || 4U > SIZE_MAX - (binderoffset - 3U))
        {
            status = qsc_tls_status_invalid_state;
        }
        else
        {
            truncateoffset = 4U + (binderoffset - 3U);

            if (truncateoffset > handshakelen || binderoffset > SIZE_MAX - 4U ||
                (4U + binderoffset) > handshakelen || binderlen > (handshakelen - (4U + binderoffset)))
            {
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                if (retry == true)
                {
                    if (state->transcript.initialized == true && state->transcript.hash == hash)
                    {
                        qsc_memutils_copy(&scratch, &state->transcript, sizeof(scratch));
                        status = qsc_tls_status_success;
                    }
                    else
                    {
                        status = qsc_tls_status_invalid_state;
                    }
                }
                else
                {
                    status = qsc_tls_transcript_initialize(&scratch, hash);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_transcript_update(&scratch, handshake, truncateoffset);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_transcript_snapshot(&scratch, truncatedhash,
                        sizeof(truncatedhash), &truncatedhashlen);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_keyschedule_state_initialize(&ksscratch, hash);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_keyschedule_extract_early_secret(&ksscratch, state->config.offeredticket->resumptionsecret, state->config.offeredticket->resumptionsecretlen);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_keyschedule_derive_binder_key(&ksscratch, false);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_keyschedule_compute_psk_binder(hash, ksscratch.binderkey, ksscratch.digestsize, truncatedhash, truncatedhashlen, binder, sizeof(binder), &binderwritten);
                }

                if (status == qsc_tls_status_success && binderwritten != binderlen)
                {
                    status = qsc_tls_status_invalid_length;
                }

                if (status == qsc_tls_status_success)
                {
                    qsc_memutils_copy(handshake + 4U + binderoffset, binder, binderlen);

                    if (retry == false && state->transcript.hash != hash)
                    {
                        qsc_tls_transcript_dispose(&state->transcript);
                        status = qsc_tls_transcript_initialize(&state->transcript, hash);
                    }
                }

                if (status == qsc_tls_status_success)
                {
                    qsc_tls_keyschedule_state_dispose(&state->keyschedule);
                    status = qsc_tls_keyschedule_state_initialize(&state->keyschedule, hash);
                }

                if (status == qsc_tls_status_success)
                {
                    status = qsc_tls_keyschedule_extract_early_secret(&state->keyschedule, state->config.offeredticket->resumptionsecret, state->config.offeredticket->resumptionsecretlen);
                }

                state->negotiatedhash = hash;
            }
        }
    }
    else if (state != NULL && state->pskoffered == false)
    {
        status = qsc_tls_status_success;
    }

    qsc_tls_transcript_dispose(&scratch);
    qsc_tls_keyschedule_state_dispose(&ksscratch);
    qsc_memutils_secure_erase(binder, sizeof(binder));
    qsc_memutils_secure_erase(truncatedhash, sizeof(truncatedhash));

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
    uint8_t seen[8192U] = { 0U };
    uint8_t ss[QSC_TLS_MAX_SHARED_SECRET_SIZE] = { 0U };
    const uint8_t* extblock;
    const uint8_t* extbody;
    const uint8_t* keysharebody;
    const uint8_t* pskbody;
    const uint8_t* serverkeyshare;
    const uint8_t* sid;
    const uint8_t* versionsbody;
    size_t extblocklen;
    size_t extbodylen;
    size_t extoff;
    size_t index;
    size_t keysharebodylen;
    size_t off;
    size_t pskbodylen;
    size_t serverkeysharelen;
    size_t sidlen;
    size_t sslen;
    size_t versionsbodylen;
    uint16_t exttype;
    uint16_t legver;
    uint16_t selectedidentity;
    uint16_t selectedversion;
    uint16_t suiteraw;
    uint8_t compmethod;
    uint8_t mask;
    const qsc_tls_group_descriptor* groupdesc;
    qsc_tls_cipher_suite selectedsuite;
    qsc_tls_hash_algorithm selectedhash;
    qsc_tls_named_group selgroup;
    qsc_tls_status status;

    extblock = NULL;
    extbody = NULL;
    keysharebody = NULL;
    pskbody = NULL;
    serverkeyshare = NULL;
    sid = NULL;
    versionsbody = NULL;
    extblocklen = 0U;
    extbodylen = 0U;
    extoff = 0U;
    index = 0U;
    keysharebodylen = 0U;
    off = 0U;
    pskbodylen = 0U;
    serverkeysharelen = 0U;
    sidlen = 0U;
    sslen = 0U;
    versionsbodylen = 0U;
    exttype = 0U;
    legver = 0U;
    selectedidentity = 0xFFFFU;
    selectedversion = 0U;
    suiteraw = 0U;
    compmethod = 0U;
    mask = 0U;
    groupdesc = NULL;
    selectedsuite = qsc_tls_cipher_suite_none;
    selectedhash = qsc_tls_hash_none;
    selgroup = qsc_tls_group_none;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && msg != NULL)
    {
        status = qsc_tls_codec_read_u16(msg, msglen, &off, &legver);

        if (status == qsc_tls_status_success)
        {
            if (off > msglen || sizeof(state->serverrandom) > (msglen - off))
            {
                state->lastalert = qsc_tls_alert_decode_error;
                status = qsc_tls_status_invalid_length;
            }
            else
            {
                qsc_memutils_copy(state->serverrandom, msg + off, sizeof(state->serverrandom));
                off += sizeof(state->serverrandom);
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector8_span(msg, msglen, &off, &sid, &sidlen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_u16(msg, msglen, &off, &suiteraw);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_u8(msg, msglen, &off, &compmethod);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector16_span(msg, msglen, &off, &extblock, &extblocklen);
        }

        if (status == qsc_tls_status_success && off != msglen)
        {
            state->lastalert = qsc_tls_alert_decode_error;
            status = qsc_tls_status_invalid_length;
        }
        else if (status != qsc_tls_status_success)
        {
            state->lastalert = qsc_tls_alert_decode_error;
        }

        while (status == qsc_tls_status_success && extoff < extblocklen)
        {
            extbody = NULL;
            extbodylen = 0U;
            status = qsc_tls_codec_read_u16(extblock, extblocklen, &extoff, &exttype);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_read_vector16_span(extblock, extblocklen, &extoff, &extbody, &extbodylen);
            }

            if (status != qsc_tls_status_success)
            {
                state->lastalert = qsc_tls_alert_decode_error;
            }

            if (status == qsc_tls_status_success)
            {
                index = ((size_t)exttype >> 3U);
                mask = (uint8_t)(1U << (exttype & 7U));

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

            if (status == qsc_tls_status_success)
            {
                if (exttype == (uint16_t)qsc_tls_extension_supported_versions)
                {
                    versionsbody = extbody;
                    versionsbodylen = extbodylen;
                }
                else if (exttype == (uint16_t)qsc_tls_extension_key_share)
                {
                    keysharebody = extbody;
                    keysharebodylen = extbodylen;
                }
                else if (exttype == (uint16_t)qsc_tls_extension_pre_shared_key)
                {
                    pskbody = extbody;
                    pskbodylen = extbodylen;
                }
                else if (client_extension_is_known(exttype) == true)
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    state->lastalert = qsc_tls_alert_unsupported_extension;
                    status = qsc_tls_status_invalid_message;
                }
            }
        }

        if (status == qsc_tls_status_success && versionsbody == NULL)
        {
            state->lastalert = qsc_tls_alert_missing_extension;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_extensions_decode_supported_versions_server(versionsbody, versionsbodylen, &selectedversion);

            if (status != qsc_tls_status_success)
            {
                state->lastalert = qsc_tls_alert_decode_error;
            }
            else if (selectedversion != QSC_TLS_PROTOCOL_VERSION_13)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }
        }

        if (status == qsc_tls_status_success && legver != QSC_TLS_PROTOCOL_VERSION_12)
        {
            state->lastalert = qsc_tls_alert_protocol_version;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success && sidlen != 0U)
        {
            /* QSC emits an empty legacy_session_id; the server must echo it exactly. */
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success && compmethod != 0U)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            selectedsuite = (qsc_tls_cipher_suite)suiteraw;
            status = client_validate_selected_cipher_suite(state, selectedsuite);
        }

        if (status == qsc_tls_status_success)
        {
            selectedhash = qsc_tls_keyschedule_suite_hash(selectedsuite);
            state->negotiatedsuite = selectedsuite;
            state->negotiatedhash = selectedhash;
            state->pskaccepted = false;
        }

        if (status == qsc_tls_status_success && pskbody != NULL)
        {
            if (state->pskoffered == false || state->config.offeredticket == NULL)
            {
                state->lastalert = qsc_tls_alert_unsupported_extension;
                status = qsc_tls_status_invalid_message;
            }
            else
            {
                status = qsc_tls_extensions_decode_pre_shared_key_server(pskbody, pskbodylen, &selectedidentity);

                if (status != qsc_tls_status_success)
                {
                    state->lastalert = qsc_tls_alert_decode_error;
                }
                else if (selectedidentity != 0U ||
                    qsc_tls_keyschedule_suite_hash(state->config.offeredticket->suite) != selectedhash)
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                    status = qsc_tls_status_invalid_message;
                }
                else if (state->keyschedule.initialized == false || state->keyschedule.hash != selectedhash)
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                    status = qsc_tls_status_invalid_message;
                }
                else
                {
                    state->pskaccepted = true;
                }
            }
        }

        if (status == qsc_tls_status_success && keysharebody == NULL)
        {
            /* QSC offers only asymmetric key establishment and psk_dhe_ke. */
            state->lastalert = qsc_tls_alert_missing_extension;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_extensions_decode_key_share_server_hello(keysharebody, keysharebodylen, &selgroup, &serverkeyshare, &serverkeysharelen);

            if (status != qsc_tls_status_success)
            {
                state->lastalert = qsc_tls_alert_decode_error;
            }
            else if (serverkeyshare == NULL || serverkeysharelen == 0U || selgroup != state->keyexchange.group)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_groups_client_derive_shared_secret(&state->keyexchange, serverkeyshare, serverkeysharelen, ss, sizeof(ss), &sslen);

            if (status != qsc_tls_status_success)
            {
                groupdesc = qsc_tls_groups_descriptor_get(selgroup);

                if (groupdesc != NULL && groupdesc->iskem == true && status == qsc_tls_status_authentication_failure)
                {
                    state->lastalert = qsc_tls_alert_internal_error;
                }
                else
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                }
            }
        }

        if (status == qsc_tls_status_success && state->pskaccepted == false)
        {
            status = qsc_tls_keyschedule_state_initialize(&state->keyschedule, selectedhash);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_keyschedule_extract_early_secret(&state->keyschedule, NULL, 0U);
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_keyschedule_extract_handshake_secret(&state->keyschedule, ss, sslen);
        }

        if (status == qsc_tls_status_success)
        {
            state->negotiatedgroup = selgroup;
        }
    }

    qsc_memutils_secure_erase(ss, sizeof(ss));

    return status;
}

static qsc_tls_status client_process_hello_retry_request(qsc_tls_client_state* state, const uint8_t* hrr_msg, size_t hrr_msglen,
    const uint8_t* hrr_hdr_plus_body, size_t hrr_hdr_plus_body_len, uint8_t* output, size_t outlen, size_t* written)
{
    uint8_t seen[8192U] = { 0U };
    uint8_t body[QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE] = { 0U };
    uint8_t hs[4U + QSC_TLS_CLIENT_HELLO_BODY_MAX_SIZE] = { 0U };
    const uint8_t* cookie;
    const uint8_t* ebody;
    const uint8_t* extblock;
    const uint8_t* sid;
    size_t binderlen;
    size_t binderoffset;
    size_t bodylen;
    size_t cookielen;
    size_t eblen;
    size_t eoff;
    size_t extblocklen;
    size_t hsoff;
    size_t index;
    size_t off;
    size_t recwritten;
    size_t sidlen;
    uint16_t etype;
    uint16_t legver;
    uint16_t selectedversion;
    uint16_t suiteraw;
    uint8_t compmethod;
    uint8_t mask;
    qsc_tls_hash_algorithm selectedhash;
    qsc_tls_named_group reqgroup;
    qsc_tls_status status;
    bool sawcookie;
    bool sawkeyshare;
    bool sawsupportedversions;

    binderlen = 0U;
    binderoffset = 0U;
    bodylen = 0U;
    cookie = NULL;
    cookielen = 0U;
    ebody = NULL;
    eblen = 0U;
    eoff = 0U;
    extblock = NULL;
    extblocklen = 0U;
    hsoff = 0U;
    index = 0U;
    off = 0U;
    recwritten = 0U;
    sid = NULL;
    sidlen = 0U;
    etype = 0U;
    legver = 0U;
    selectedversion = 0U;
    suiteraw = 0U;
    compmethod = 0U;
    mask = 0U;
    selectedhash = qsc_tls_hash_none;
    reqgroup = qsc_tls_group_none;
    sawcookie = false;
    sawkeyshare = false;
    sawsupportedversions = false;
    status = qsc_tls_status_invalid_input;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (state != NULL && hrr_msg != NULL && hrr_hdr_plus_body != NULL && output != NULL &&
        written != NULL && state->helloretryrequestconsumed == false)
    {
        status = qsc_tls_codec_read_u16(hrr_msg, hrr_msglen, &off, &legver);

        if (status == qsc_tls_status_success && legver != QSC_TLS_PROTOCOL_VERSION_12)
        {
            state->lastalert = qsc_tls_alert_protocol_version;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            if (off > hrr_msglen || sizeof(tls_client_hrr_special_random) > (hrr_msglen - off) ||
                qsc_memutils_are_equal(hrr_msg + off, tls_client_hrr_special_random, sizeof(tls_client_hrr_special_random)) == false)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }
            else
            {
                off += sizeof(tls_client_hrr_special_random);
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector8_span(hrr_msg, hrr_msglen, &off, &sid, &sidlen);
        }

        if (status == qsc_tls_status_success && sidlen != 0U)
        {
            /* QSC emits a zero-length legacy_session_id and HRR must echo it exactly. */
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_u16(hrr_msg, hrr_msglen, &off, &suiteraw);
        }

        if (status == qsc_tls_status_success)
        {
            status = client_validate_selected_cipher_suite(state, (qsc_tls_cipher_suite)suiteraw);
        }

        if (status == qsc_tls_status_success)
        {
            selectedhash = qsc_tls_keyschedule_suite_hash((qsc_tls_cipher_suite)suiteraw);

            if (selectedhash == qsc_tls_hash_none)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }
            else
            {
                state->negotiatedsuite = (qsc_tls_cipher_suite)suiteraw;
                state->negotiatedhash = selectedhash;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_u8(hrr_msg, hrr_msglen, &off, &compmethod);
        }

        if (status == qsc_tls_status_success && compmethod != 0U)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_codec_read_vector16_span(hrr_msg, hrr_msglen, &off, &extblock, &extblocklen);
        }

        if (status == qsc_tls_status_success && off != hrr_msglen)
        {
            state->lastalert = qsc_tls_alert_decode_error;
            status = qsc_tls_status_invalid_length;
        }

        while (status == qsc_tls_status_success && eoff < extblocklen)
        {
            ebody = NULL;
            eblen = 0U;
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

            if (status == qsc_tls_status_success)
            {
                if (etype == (uint16_t)qsc_tls_extension_supported_versions)
                {
                    status = qsc_tls_extensions_decode_supported_versions_server(ebody, eblen, &selectedversion);

                    if (status == qsc_tls_status_success && selectedversion == QSC_TLS_PROTOCOL_VERSION_13)
                    {
                        sawsupportedversions = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_illegal_parameter;
                        status = qsc_tls_status_invalid_message;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_key_share)
                {
                    status = qsc_tls_extensions_decode_key_share_hello_retry(ebody, eblen, &reqgroup);

                    if (status == qsc_tls_status_success)
                    {
                        sawkeyshare = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (etype == (uint16_t)qsc_tls_extension_cookie)
                {
                    status = qsc_tls_extensions_decode_cookie(ebody, eblen, &cookie, &cookielen);

                    if (status == qsc_tls_status_success)
                    {
                        sawcookie = true;
                    }
                    else
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else
                {
                    state->lastalert = qsc_tls_alert_unsupported_extension;
                    status = qsc_tls_status_invalid_message;
                }
            }
        }

        if (status == qsc_tls_status_success && sawsupportedversions == false)
        {
            state->lastalert = qsc_tls_alert_missing_extension;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success && sawkeyshare == false && sawcookie == false)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }

        if (status == qsc_tls_status_success && sawkeyshare == true)
        {
            bool acceptable;
            size_t i;

            acceptable = false;
            i = 0U;

            if (reqgroup == state->keyexchange.group)
            {
                state->lastalert = qsc_tls_alert_illegal_parameter;
                status = qsc_tls_status_invalid_message;
            }
            else
            {
                for (i = 0U; i < state->config.groupcount; ++i)
                {
                    if (state->config.groups[i] == reqgroup)
                    {
                        acceptable = true;
                        break;
                    }
                }

                if (acceptable == false)
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                    status = qsc_tls_status_invalid_message;
                }
            }
        }

        if (status == qsc_tls_status_success && hrr_hdr_plus_body_len > sizeof(state->helloretryrequest))
        {
            status = qsc_tls_status_buffer_too_small;
        }

        if (status == qsc_tls_status_success)
        {
            qsc_memutils_copy(state->helloretryrequest, hrr_hdr_plus_body, hrr_hdr_plus_body_len);
            state->helloretryrequestlen = hrr_hdr_plus_body_len;

            /* Rebuild CH1 under the HRR-selected transcript hash before applying message_hash. */
            qsc_tls_transcript_dispose(&state->transcript);
            status = qsc_tls_transcript_initialize(&state->transcript, selectedhash);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_transcript_update(&state->transcript, state->clienthello, state->clienthellolen);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_transcript_replace_with_message_hash(&state->transcript);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_transcript_update(&state->transcript, hrr_hdr_plus_body, hrr_hdr_plus_body_len);
        }

        if (status == qsc_tls_status_success && sawkeyshare == true)
        {
            qsc_tls_groups_key_exchange_state_dispose(&state->keyexchange);
            status = qsc_tls_groups_generate_client_keypair(&state->keyexchange, reqgroup);
        }

        if (status == qsc_tls_status_success)
        {
            bodylen = 0U;
            binderoffset = 0U;
            binderlen = 0U;
            status = client_build_clienthello(state, body, sizeof(body), &bodylen, &binderoffset, &binderlen, cookie, cookielen, true);
        }

        if (status == qsc_tls_status_success)
        {
            hsoff = 0U;
            status = qsc_tls_handshake_write_header(hs, sizeof(hs), &hsoff, qsc_tls_handshake_type_client_hello, bodylen);
        }

        if (status == qsc_tls_status_success)
        {
            qsc_memutils_copy(hs + hsoff, body, bodylen);
            hsoff += bodylen;

            if (state->pskoffered == true)
            {
                status = client_patch_psk_binder(state, hs, hsoff, binderoffset, binderlen, true);
            }
        }

        if (status == qsc_tls_status_success)
        {
            if (hsoff <= sizeof(state->retryclienthello))
            {
                qsc_memutils_copy(state->retryclienthello, hs, hsoff);
                state->retryclienthellolen = hsoff;
            }
            else
            {
                status = qsc_tls_status_buffer_too_small;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_transcript_update(&state->transcript, hs, hsoff);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_record_encode_plaintext(output, outlen, &recwritten, qsc_tls_record_content_handshake, hs, hsoff);
        }

        if (status == qsc_tls_status_success)
        {
            *written = recwritten;
            state->helloretryrequestconsumed = true;
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

    if (status == qsc_tls_status_success)
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

static qsc_tls_status client_process_encrypted_extensions(qsc_tls_client_state* state, const uint8_t* msg, size_t msglen)
{
    uint8_t seen[8192U] = { 0U };
    qsc_tls_alpn_protocols peeralpn;
    const uint8_t* extblock;
    const uint8_t* extbody;
    size_t extblocklen;
    size_t extbodylen;
    size_t extoff;
    size_t index;
    size_t off;
    uint16_t exttype;
    uint8_t mask;
    qsc_tls_status status;

    qsc_memutils_clear(&peeralpn, sizeof(peeralpn));
    extblock = NULL;
    extbody = NULL;
    extblocklen = 0U;
    extbodylen = 0U;
    extoff = 0U;
    index = 0U;
    off = 0U;
    exttype = 0U;
    mask = 0U;
    status = qsc_tls_status_invalid_input;

    if (state != NULL && msg != NULL)
    {
        state->alpnselected = false;
        state->selectedalpnlen = 0U;
        qsc_memutils_clear(state->selectedalpn, sizeof(state->selectedalpn));
        state->peercapabilities.groupcount = 0U;

        status = qsc_tls_codec_read_vector16_span(msg, msglen, &off, &extblock, &extblocklen);

        if (status == qsc_tls_status_success && off != msglen)
        {
            state->lastalert = qsc_tls_alert_decode_error;
            status = qsc_tls_status_invalid_length;
        }
        else if (status != qsc_tls_status_success)
        {
            state->lastalert = qsc_tls_alert_decode_error;
        }

        while (status == qsc_tls_status_success && extoff < extblocklen)
        {
            extbody = NULL;
            extbodylen = 0U;
            status = qsc_tls_codec_read_u16(extblock, extblocklen, &extoff, &exttype);

            if (status == qsc_tls_status_success)
            {
                status = qsc_tls_codec_read_vector16_span(extblock, extblocklen, &extoff, &extbody, &extbodylen);
            }

            if (status != qsc_tls_status_success)
            {
                state->lastalert = qsc_tls_alert_decode_error;
            }

            if (status == qsc_tls_status_success)
            {
                index = ((size_t)exttype >> 3U);
                mask = (uint8_t)(1U << (exttype & 7U));

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

            if (status == qsc_tls_status_success)
            {
                if (client_extension_is_known(exttype) == false)
                {
                    /* QSC did not offer unknown extensions, so an unknown server response is unsolicited. */
                    state->lastalert = qsc_tls_alert_unsupported_extension;
                    status = qsc_tls_status_invalid_message;
                }
                else if (qsc_tls_extensions_is_permitted(qsc_tls_handshake_type_encrypted_extensions,
                    (qsc_tls_extension_type)exttype) == false)
                {
                    state->lastalert = qsc_tls_alert_illegal_parameter;
                    status = qsc_tls_status_invalid_message;
                }
                else if (exttype == (uint16_t)qsc_tls_extension_server_name)
                {
                    if (state->config.hostname == NULL)
                    {
                        state->lastalert = qsc_tls_alert_unsupported_extension;
                        status = qsc_tls_status_invalid_message;
                    }
                    else if (extbodylen != 0U)
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                        status = qsc_tls_status_invalid_length;
                    }
                }
                else if (exttype == (uint16_t)qsc_tls_extension_supported_groups)
                {
                    status = client_decode_server_supported_groups(extbody, extbodylen, state->peercapabilities.groups, QSC_TLS_MAX_GROUPS, &state->peercapabilities.groupcount);

                    if (status != qsc_tls_status_success)
                    {
                        state->lastalert = qsc_tls_alert_decode_error;
                    }
                }
                else if (exttype == (uint16_t)qsc_tls_extension_application_layer_protocol_negotiation)
                {
                    if (state->config.alpn.configured == false)
                    {
                        state->lastalert = qsc_tls_alert_unsupported_extension;
                        status = qsc_tls_status_invalid_message;
                    }
                    else
                    {
                        qsc_memutils_clear(&peeralpn, sizeof(peeralpn));
                        status = qsc_tls_extensions_decode_alpn(extbody, extbodylen, &peeralpn);

                        if (status == qsc_tls_status_success)
                        {
                            if (peeralpn.protocolcount != 1U)
                            {
                                state->lastalert = qsc_tls_alert_decode_error;
                                status = qsc_tls_status_invalid_message;
                            }
                            else
                            {
                                status = qsc_tls_extensions_select_alpn(&peeralpn, &state->config.alpn, state->selectedalpn, sizeof(state->selectedalpn), &state->selectedalpnlen);

                                if (status == qsc_tls_status_success)
                                {
                                    state->alpnselected = true;
                                }
                                else
                                {
                                    state->lastalert = qsc_tls_alert_no_application_protocol;
                                }
                            }
                        }
                        else
                        {
                            state->lastalert = qsc_tls_alert_decode_error;
                        }
                    }
                }
                else if (exttype == (uint16_t)qsc_tls_extension_early_data)
                {
                    /* QSC does not offer 0-RTT. An early_data response is therefore
                     * unsolicited and must be rejected as an unsupported extension. */
                    state->lastalert = qsc_tls_alert_unsupported_extension;
                    status = qsc_tls_status_invalid_message;
                }
            }
        }

        if (status == qsc_tls_status_success && state->config.alpn.required == true && state->alpnselected == false)
        {
            state->lastalert = qsc_tls_alert_no_application_protocol;
            status = qsc_tls_status_not_supported;
        }
    }

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

    if (status == qsc_tls_status_not_supported)
    {
        state->lastalert = qsc_tls_alert_unsupported_extension;
    }

    if (status == qsc_tls_status_success)
    {
        if (chainlen != 0U)
        {
            qsc_tls_certificate_validation_context vctx;

            /* RFC 9846 requires the server certificate chain to be authenticated.
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
                state->servercertificatevalidationattempted = true;

                if (!state->config.certinterface.validatechain(chain, chainlen, &vctx, state->config.certinterface.state))
                {
                    state->lastalert = qsc_tls_certificate_interface_get_last_alert(&state->config.certinterface, false);
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
    sig = NULL;
    siglen = 0U;
    thashlen = 0U;
    scheme = qsc_tls_sig_none;
    status = qsc_tls_handshake_decode_certificate_verify(msg, msglen, &scheme, &sig, &siglen);

    if (status != qsc_tls_status_success)
    {
        state->lastalert = qsc_tls_alert_decode_error;
    }

    if (status == qsc_tls_status_success)
    {
        if (client_signature_scheme_offered(state, scheme) == false ||
            qsc_tls_signature_scheme_is_supported(scheme) == false ||
            qsc_tls_signature_scheme_is_certificate_verify_capable(scheme) == false)
        {
            state->lastalert = qsc_tls_alert_illegal_parameter;
            status = qsc_tls_status_invalid_message;
        }
        else if (state->peercertificatelen == 0U)
        {
            state->lastalert = qsc_tls_alert_bad_certificate;
            status = qsc_tls_status_invalid_state;
        }
    }

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);
    }

    if (status == qsc_tls_status_success)
    {
        status = qsc_tls_keyschedule_build_certificate_verify_input("TLS 1.3, server CertificateVerify", thash, thashlen, cvinput, sizeof(cvinput), &cvinputlen);
    }

    if (status == qsc_tls_status_success)
    {
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
            else
            {
                state->negotiatedsigscheme = scheme;
            }
        }
    }

    qsc_memutils_secure_erase(thash, sizeof(thash));
    qsc_memutils_secure_erase(cvinput, sizeof(cvinput));

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

static bool client_local_certificate_is_usable(const qsc_tls_client_state* state)
{
    bool res;

    res = false;

    if (state != NULL && state->config.localcert.configured == true && state->config.localcert.chainlength != 0U &&
        state->config.localcert.signcallback != NULL && state->config.localcert.verifyscheme != qsc_tls_sig_none)
    {
        res = (qsc_tls_signature_scheme_is_supported(state->config.localcert.verifyscheme) == true &&
            qsc_tls_signature_scheme_is_certificate_verify_capable(state->config.localcert.verifyscheme) == true &&
            client_auth_signature_scheme_requested(state, state->config.localcert.verifyscheme) == true);
    }

    return res;
}

static qsc_tls_status client_emit_certificate_authentication(qsc_tls_client_state* state, uint8_t* output, size_t outlen, size_t* written)
{
    uint8_t body[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    uint8_t cvbody[4U + QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE] = { 0U };
    uint8_t cvinput[256U] = { 0U };
    uint8_t sig[QSC_TLS_CERTIFICATE_VERIFY_MAX_SIGNATURE_SIZE] = { 0U };
    uint8_t thash[QSC_TLS_HASH_MAX_SIZE] = { 0U };
    uint8_t* hs;
    const qsc_tls_certificate_view* chain;
    size_t bodyoff;
    size_t chainlength;
    size_t cvbodyoff;
    size_t cvinputlen;
    size_t hsoff;
    size_t off;
    size_t recwritten;
    size_t siglen;
    size_t thashlen;
    qsc_tls_status status;
    bool usecertificate;

    bodyoff = 0U;
    chain = NULL;
    chainlength = 0U;
    cvbodyoff = 0U;
    cvinputlen = 0U;
    hs = NULL;
    hsoff = 0U;
    off = 0U;
    recwritten = 0U;
    siglen = sizeof(sig);
    thashlen = 0U;
    status = qsc_tls_status_invalid_input;
    usecertificate = false;

    if (written != NULL)
    {
        *written = 0U;
    }

    if (state != NULL && output != NULL && written != NULL && state->clientauthrequested == true)
    {
        usecertificate = client_local_certificate_is_usable(state);

        if (usecertificate == true)
        {
            chain = state->config.localcert.chain;
            chainlength = state->config.localcert.chainlength;
        }

        status = qsc_tls_certificate_encode_message(NULL, 0U, chain, chainlength, body, sizeof(body), &bodyoff);

        if (status == qsc_tls_status_success)
        {
            hs = (uint8_t*)qsc_memutils_malloc(4U + bodyoff);

            if (hs == NULL)
            {
                status = qsc_tls_status_failure;
            }
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_handshake_write_header(hs, 4U + bodyoff, &hsoff, qsc_tls_handshake_type_certificate, bodyoff);
        }

        if (status == qsc_tls_status_success)
        {
            qsc_memutils_copy(hs + hsoff, body, bodyoff);
            hsoff += bodyoff;
            status = qsc_tls_transcript_update(&state->transcript, hs, hsoff);
        }

        if (status == qsc_tls_status_success)
        {
            status = qsc_tls_record_encrypt(&state->writerecord, output, outlen, &recwritten, qsc_tls_record_content_handshake, hs, hsoff);

            if (status == qsc_tls_status_success)
            {
                off += recwritten;
                state->clientcertificatesent = usecertificate;
            }
        }

        if (hs != NULL)
        {
            qsc_memutils_secure_erase(hs, 4U + bodyoff);
            qsc_memutils_alloc_free(hs);
            hs = NULL;
        }

        if (status == qsc_tls_status_success && usecertificate == true)
        {
            status = qsc_tls_transcript_snapshot(&state->transcript, thash, sizeof(thash), &thashlen);
        }

        if (status == qsc_tls_status_success && usecertificate == true)
        {
            status = qsc_tls_keyschedule_build_certificate_verify_input("TLS 1.3, client CertificateVerify",
                thash, thashlen, cvinput, sizeof(cvinput), &cvinputlen);
        }

        if (status == qsc_tls_status_success && usecertificate == true)
        {
            if (state->config.localcert.signcallback(state->config.localcert.verifyscheme, cvinput, cvinputlen,
                sig, &siglen, state->config.localcert.signstate) == false ||
                qsc_tls_signature_scheme_validate_signature_length(state->config.localcert.verifyscheme, siglen) == false)
            {
                state->lastalert = qsc_tls_alert_internal_error;
                status = qsc_tls_status_failure;
            }
        }

        if (status == qsc_tls_status_success && usecertificate == true)
        {
            status = qsc_tls_handshake_encode_certificate_verify(cvbody, sizeof(cvbody), &cvbodyoff,
                state->config.localcert.verifyscheme, sig, siglen);
        }

        if (status == qsc_tls_status_success && usecertificate == true)
        {
            hs = (uint8_t*)qsc_memutils_malloc(4U + cvbodyoff);

            if (hs == NULL)
            {
                status = qsc_tls_status_failure;
            }
            else
            {
                hsoff = 0U;
                status = qsc_tls_handshake_write_header(hs, 4U + cvbodyoff, &hsoff, qsc_tls_handshake_type_certificate_verify, cvbodyoff);
            }
        }

        if (status == qsc_tls_status_success && usecertificate == true)
        {
            qsc_memutils_copy(hs + hsoff, cvbody, cvbodyoff);
            hsoff += cvbodyoff;
            status = qsc_tls_transcript_update(&state->transcript, hs, hsoff);
        }

        if (status == qsc_tls_status_success && usecertificate == true)
        {
            recwritten = 0U;
            status = qsc_tls_record_encrypt(&state->writerecord, output + off, outlen - off, &recwritten, qsc_tls_record_content_handshake, hs, hsoff);

            if (status == qsc_tls_status_success)
            {
                off += recwritten;
            }
        }

        if (hs != NULL)
        {
            qsc_memutils_secure_erase(hs, 4U + cvbodyoff);
            qsc_memutils_alloc_free(hs);
        }

        if (status == qsc_tls_status_success)
        {
            *written = off;
        }
    }

    qsc_memutils_secure_erase(body, sizeof(body));
    qsc_memutils_secure_erase(cvbody, sizeof(cvbody));
    qsc_memutils_secure_erase(cvinput, sizeof(cvinput));
    qsc_memutils_secure_erase(sig, sizeof(sig));
    qsc_memutils_secure_erase(thash, sizeof(thash));

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

qsc_tls_status qsc_tls_client_config_set_local_certificate(qsc_tls_client_config* config, const qsc_tls_certificate_view* chain,
    size_t chainlength, qsc_tls_signature_scheme verifyscheme, const uint8_t* privatekeydata, size_t privatekeylen)
{
    qsc_tls_status status;
    size_t i;

    status = qsc_tls_status_invalid_input;

    if (config != NULL && chain != NULL && chainlength != 0U && chainlength <= QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES &&
        privatekeydata != NULL && privatekeylen != 0U && privatekeylen <= QSC_TLS_MAX_SIGNING_PRIVATE_KEY_SIZE &&
        qsc_tls_signature_scheme_is_supported(verifyscheme) == true &&
        qsc_tls_signature_scheme_is_certificate_verify_capable(verifyscheme) == true)
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
            config->localcert.signcallback = tls_client_local_certificate_sign;
            config->localcert.signstate = &config->localcert;
            config->localcert.configured = true;
            config->localcert.staticsignature = false;
        }
    }

    return status;
}

qsc_tls_status qsc_tls_client_initialize(qsc_tls_client_state* state, const qsc_tls_client_config* config)
{
    QSC_ASSERT(state != NULL);
    QSC_ASSERT(config != NULL);

    qsc_tls_status status;

    status = qsc_tls_status_invalid_input;

    if (state != NULL && config != NULL)
    {
        if (config->enableearlydata == true)
        {
            status = qsc_tls_status_not_supported;
        }
        else if (config->ciphersuites != NULL && config->ciphersuitecount != 0U &&
            config->groups != NULL && config->groupcount != 0U && config->sigschemes != NULL && config->sigschemecount != 0U)
        {
            qsc_memutils_clear(state, sizeof(*state));
            state->config = *config;

            if (state->config.certinterface.state != NULL &&
                state->config.certinterface.validatechain == qsc_tls_x509_validate_chain &&
                state->config.certinterface.verifycertificateverify == qsc_tls_x509_verify_certificate_verify)
            {
                status = qsc_tls_x509_context_clone(&state->x509context, (const qsc_tls_qsc_x509_context*)state->config.certinterface.state);

                if (status == qsc_tls_status_success)
                {
                    state->config.certinterface.state = &state->x509context;
                }
            }
            else
            {
                status = qsc_tls_status_success;
            }

            if (status == qsc_tls_status_success && state->config.localcert.signcallback == tls_client_local_certificate_sign)
            {
                state->config.localcert.signstate = &state->config.localcert;
            }

            if (status == qsc_tls_status_success)
            {
                state->phase = qsc_tls_client_phase_initial;
                state->negotiatedsuite = qsc_tls_cipher_suite_none;
                state->negotiatedhash = qsc_tls_hash_none;
                state->negotiatedgroup = qsc_tls_group_none;
                state->negotiatedsigscheme = qsc_tls_sig_none;
            }
        }
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

        status = client_build_clienthello(state, body, sizeof(body), &bodylen, &binderoffsetinbody, &binderlen, NULL, 0U, false);

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

        if (state->pskoffered == true)
        {
            status = client_patch_psk_binder(state, hs, hsoff, binderoffsetinbody, binderlen, false);

            if (status != qsc_tls_status_success)
            {
                return status;
            }
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

    uint8_t decbuf[QSC_TLS_MAX_RECORD_SIZE] = { 0U };
    const uint8_t* payload;
    uint8_t* ptext;
    size_t payloadlen;
    size_t reclen;
    size_t ptextlen;
    size_t declen;
    qsc_tls_record_content_type rtype;
    qsc_tls_status status;
    bool complete;
    bool protectedrecord;

    ptext = NULL;
    ptextlen = 0U;
    declen = 0U;
    status = qsc_tls_status_invalid_input;
    protectedrecord = false;

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
        if (status == qsc_tls_status_record_overflow)
        {
            state->lastalert = qsc_tls_alert_record_overflow;
            state->phase = qsc_tls_client_phase_failed;
        }

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

        status = qsc_tls_record_decrypt(&state->readrecord, decbuf, sizeof(decbuf), &declen, &inner_type, input, reclen);

        if (status != qsc_tls_status_success)
        {
            if (status == qsc_tls_status_record_overflow)
            {
                state->lastalert = qsc_tls_alert_record_overflow;
                state->phase = qsc_tls_client_phase_failed;
                *consumed = reclen;
            }
            else if (status == qsc_tls_status_authentication_failure)
            {
                state->lastalert = qsc_tls_alert_bad_record_mac;
                state->phase = qsc_tls_client_phase_failed;
                *consumed = reclen;
            }

            return status; 
        }

        ptext = decbuf;
        ptextlen = declen;
        rtype = inner_type;
        protectedrecord = true;
    }
    else
    {
        ptext = (uint8_t*)payload;
        ptextlen = payloadlen;
    }

    if (state->handshakebufferlen != 0U && rtype != qsc_tls_record_content_handshake)
    {
        state->lastalert = qsc_tls_alert_unexpected_message;
        state->phase = qsc_tls_client_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_invalid_message;
    }

    if (rtype == qsc_tls_record_content_change_cipher_spec)
    {
        bool ccsallowed;

        ccsallowed = (state->phase == qsc_tls_client_phase_waiting_server_hello ||
            state->phase == qsc_tls_client_phase_waiting_encrypted_extensions ||
            state->phase == qsc_tls_client_phase_waiting_certificate ||
            state->phase == qsc_tls_client_phase_waiting_certificate_verify ||
            state->phase == qsc_tls_client_phase_waiting_finished);

        if (protectedrecord == true || ccsallowed == false || ptextlen != 1U || ptext[0U] != 0x01U)
        {
            state->lastalert = qsc_tls_alert_unexpected_message;
            state->phase = qsc_tls_client_phase_failed;
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
        state->phase = qsc_tls_client_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_invalid_message;
    }

    if (rtype == qsc_tls_record_content_alert)
    {
        qsc_tls_alert_description alert;

        if (protectedrecord == false && state->readrecord.initialized == true)
        {
            state->lastalert = qsc_tls_alert_unexpected_message;
            state->phase = qsc_tls_client_phase_failed;
            *consumed = reclen;

            return qsc_tls_status_invalid_message;
        }

        if (ptextlen == 0U)
        {
            state->lastalert = qsc_tls_alert_unexpected_message;
            state->phase = qsc_tls_client_phase_failed;
            *consumed = reclen;

            return qsc_tls_status_invalid_message;
        }

        status = qsc_tls_alert_decode(ptext, ptextlen, &alert);

        if (status != qsc_tls_status_success)
        {
            state->lastalert = qsc_tls_alert_decode_error;
            state->phase = qsc_tls_client_phase_failed;
            *consumed = reclen;

            return status;
        }

        state->lastalert = alert;
        *consumed = reclen;

        if (alert == qsc_tls_alert_close_notify)
        {
            state->closenotifyreceived = true;
            state->phase = qsc_tls_client_phase_closed;

            return qsc_tls_status_success;
        }

        if (alert == qsc_tls_alert_user_canceled)
        {
            return qsc_tls_status_success;
        }

        state->phase = qsc_tls_client_phase_failed;

        return qsc_tls_status_failure;
    }

    if (rtype != qsc_tls_record_content_handshake)
    {
        return qsc_tls_status_invalid_message;
    }

    if (ptextlen == 0U)
    {
        state->lastalert = qsc_tls_alert_unexpected_message;
        state->phase = qsc_tls_client_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_invalid_message;
    }

    if (ptextlen > (sizeof(state->handshakebuffer) - state->handshakebufferlen))
    {
        state->lastalert = qsc_tls_alert_decode_error;
        state->phase = qsc_tls_client_phase_failed;
        *consumed = reclen;

        return qsc_tls_status_invalid_length;
    }

    qsc_memutils_copy(state->handshakebuffer + state->handshakebufferlen, ptext, ptextlen);
    state->handshakebufferlen += ptextlen;

    /* Process every complete handshake message and retain an incomplete tail for the next record. */
    {
        size_t offset;

        offset = 0U;

        while ((state->handshakebufferlen - offset) >= 4U)
        {
            qsc_tls_handshake_type type;
            size_t bodylen;
            size_t hdroff;

            hdroff = offset;
            status = qsc_tls_handshake_read_header(state->handshakebuffer, state->handshakebufferlen, &offset, &type, &bodylen);

            if (status != qsc_tls_status_success) 
            { 
                return status; 
            }

            if (bodylen > (state->handshakebufferlen - offset))
            {
                offset = hdroff;
                break;
            }

            const uint8_t* body = state->handshakebuffer + offset;

            if ((type == qsc_tls_handshake_type_server_hello || type == qsc_tls_handshake_type_finished) &&
                (offset + bodylen) != state->handshakebufferlen)
            {
                state->lastalert = qsc_tls_alert_unexpected_message;
                state->phase = qsc_tls_client_phase_failed;
                *consumed = reclen;

                return qsc_tls_status_invalid_message;
            }

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
                            /* second HRR - forbidden per RFC 9846 Section 4.2.4 */
                            state->lastalert = qsc_tls_alert_unexpected_message;
                            return qsc_tls_status_invalid_state;
                        }
                        status = client_process_hello_retry_request(state, body, bodylen, state->handshakebuffer + hdroff, 4U + bodylen, output, outlen, written);
                        /* stay in waiting_server_hello: the real ServerHello comes after CH2 */
                    }
                    else
                    {
                        status = client_process_server_hello(state, body, bodylen);

                        if (status == qsc_tls_status_success)
                        {
                            status = client_rebuild_transcript_for_server_hello(state, state->handshakebuffer + hdroff, 4U + bodylen);
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

                    status = client_process_encrypted_extensions(state, body, bodylen);

                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_transcript_update(&state->transcript, state->handshakebuffer + hdroff, 4U + bodylen);
                    }

                    if (status == qsc_tls_status_success)
                    {
                        state->phase = state->pskaccepted ? qsc_tls_client_phase_waiting_finished : qsc_tls_client_phase_waiting_certificate;
                    }

                    break;
                }
                case qsc_tls_handshake_type_certificate_request:
                {
                    if (state->phase != qsc_tls_client_phase_waiting_certificate || state->clientauthrequested == true || state->pskaccepted == true)
                    {
                        state->lastalert = qsc_tls_alert_unexpected_message;
                        return qsc_tls_status_invalid_state;
                    }

                    status = client_process_certificate_request(state, body, bodylen);

                    if (status == qsc_tls_status_success)
                    {
                        status = qsc_tls_transcript_update(&state->transcript, state->handshakebuffer + hdroff, 4U + bodylen);
                    }

                    break;
                }
                case qsc_tls_handshake_type_certificate:
                {
                    if (state->phase != qsc_tls_client_phase_waiting_certificate)
                    {
                        return qsc_tls_status_invalid_state;
                    }

                    status = qsc_tls_transcript_update(&state->transcript, state->handshakebuffer + hdroff, 4U + bodylen);

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
                        status = qsc_tls_transcript_update(&state->transcript, state->handshakebuffer + hdroff, 4U + bodylen);
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
                        status = qsc_tls_transcript_update(&state->transcript, state->handshakebuffer + hdroff, 4U + bodylen);
                    }

                    if (status == qsc_tls_status_success)
                    {
                        /* snapshot for app-secret derivation BEFORE client Finished is added
                         * per RFC 9846 Section 7.1: c/s ap traffic = Derive-Secret(Main Secret, "...", CH..server Finished) */
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
                            /* emit client Finished encrypted under handshake write key */
                            size_t fin_written = 0U;
                            if (status == qsc_tls_status_success)
                            {
                                if (state->clientauthrequested == true)
                                {
                                    size_t authwritten;

                                    authwritten = 0U;
                                    status = client_emit_certificate_authentication(state, output, outlen, &authwritten);

                                    if (status == qsc_tls_status_success)
                                    {
                                        output += authwritten;
                                        outlen -= authwritten;

                                        if (written != NULL)
                                        {
                                            *written += authwritten;
                                        }
                                    }
                                }
                            }

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
                    state->lastalert = qsc_tls_alert_unexpected_message;
                    state->phase = qsc_tls_client_phase_failed;
                    *consumed = reclen;

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

        if (offset != 0U)
        {
            const size_t remaining = state->handshakebufferlen - offset;

            if (remaining != 0U)
            {
                qsc_memutils_move(state->handshakebuffer, state->handshakebuffer + offset, remaining);
            }

            state->handshakebufferlen = remaining;
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
