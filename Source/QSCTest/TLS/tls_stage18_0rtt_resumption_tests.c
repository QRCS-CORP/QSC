/* End-to-end 0-RTT resumption gate. */
#include "tls_stage18_0rtt_resumption_tests.h"
#include "../testutils.h"
#include "acp.h"
#include "eddsa.h"
#include "memutils.h"
#include "secrand.h"
#include "tlsengine.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlssession.h"
#include "tlssignerdefault.h"

typedef struct psk_entry
{
    uint8_t id[64];
    size_t idlen;
    uint8_t psk[64];
    size_t psklen;
    qsc_tls_cipher_suite suite;
} psk_entry;

static psk_entry g_store;
static uint8_t g_server_pk[32U];
static uint8_t g_server_sk[64U];
static uint8_t g_server_cert[32U];

static bool psk_lookup_cb(const uint8_t* identity, size_t identitylen, uint8_t* psk_out, size_t pskcap, size_t* psk_len_out, qsc_tls_cipher_suite* suite_out, uint32_t* max_early_data_out, void* state)
{
    bool res;

    (void)state;
    res = false;

    if ((identitylen == g_store.idlen) && (qsc_memutils_are_equal(identity, g_store.id, identitylen) == true) && (g_store.psklen <= pskcap))
    {
        qsc_memutils_copy(psk_out, g_store.psk, g_store.psklen);
        *psk_len_out = g_store.psklen;
        *suite_out = g_store.suite;
        *max_early_data_out = 16384U;
        res = true;
    }

    return res;
}

static bool stub_validate(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* ctx, void* state)
{
    bool res;

    (void)ctx;
    (void)state;

    res = ((chainlength == 1U) && (chain[0].datalen == 32U));

    return res;
}

static bool stub_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    qsc_tls_certificate_view v;
    bool res;

    (void)signer;
    (void)state;

    v.data = g_server_pk;
    v.datalen = 32U;
    res = qsc_tls_signer_default_verify(scheme, input, inputlen, signature, signaturelen, &v, NULL);

    return res;
}

static bool do_handshake(qsc_tls_connection* c, qsc_tls_connection* s)
{
    uint8_t c2s[8192U];
    uint8_t s2c[32768U];
    uint8_t junk[128U];
    size_t c2s_len;
    size_t s2c_len;
    size_t consumed;
    size_t written;
    size_t off;
    size_t fin_len;
    size_t w;
    qsc_tls_status st;
    bool res;

    c2s_len = 0U;
    s2c_len = 0U;
    consumed = 0U;
    written = 0U;
    off = 0U;
    fin_len = 0U;
    w = 0U;
    res = true;

    st = qsc_tls_engine_handshake(c, NULL, 0U, &consumed, c2s, sizeof(c2s), &c2s_len);

    if ((st != qsc_tls_status_success) || (c2s_len == 0U))
    {
        res = false;
    }

    if (res == true)
    {
        st = qsc_tls_engine_handshake(s, c2s, c2s_len, &consumed, s2c, sizeof(s2c), &s2c_len);

        if (st != qsc_tls_status_success)
        {
            res = false;
        }
    }

    while ((res == true) && (off < s2c_len) && (qsc_tls_engine_is_handshake_complete(c) == false))
    {
        w = 0U;
        st = qsc_tls_engine_handshake(c, s2c + off, s2c_len - off, &consumed, c2s, sizeof(c2s), &w);

        if (st != qsc_tls_status_success)
        {
            res = false;
        }
        else
        {
            off += consumed;

            if (w > 0U)
            {
                fin_len = w;
            }
        }
    }

    if ((res == true) && (qsc_tls_engine_is_handshake_complete(c) == false))
    {
        res = false;
    }

    if (res == true)
    {
        st = qsc_tls_engine_handshake(s, c2s, fin_len, &consumed, junk, sizeof(junk), &written);

        if ((st != qsc_tls_status_success) || (qsc_tls_engine_is_handshake_complete(s) == false))
        {
            res = false;
        }
    }

    return res;
}

static void initialize_configs(qsc_tls_client_config* ccfg, qsc_tls_server_config* scfg, const qsc_tls_cipher_suite* suites, 
    const qsc_tls_named_group* groups, const qsc_tls_signature_scheme* sigs, qsc_tls_signer_default_context* signer_ctx)
{
    qsc_memutils_clear(ccfg, sizeof(*ccfg));
    ccfg->ciphersuites = suites;
    ccfg->ciphersuitecount = 1U;
    ccfg->groups = groups;
    ccfg->groupcount = 1U;
    ccfg->sigschemes = sigs;
    ccfg->sigschemecount = 1U;
    ccfg->hostname = "example.com";
    ccfg->certinterface.validatechain = stub_validate;
    ccfg->certinterface.verifycertificateverify = stub_verify;

    qsc_memutils_clear(scfg, sizeof(*scfg));
    scfg->ciphersuitepreference = suites;
    scfg->ciphersuitepreferencecount = 1U;
    scfg->groupspreference = groups;
    scfg->groupspreferencecount = 1U;
    scfg->sigschemepreference = sigs;
    scfg->sigschemepreferencecount = 1U;
    scfg->localcert.chain[0U].data = g_server_cert;
    scfg->localcert.chain[0U].datalen = 32U;
    scfg->localcert.chainlength = 1U;
    scfg->localcert.verifyscheme = qsc_tls_sig_ed25519;
    scfg->localcert.configured = true;
    scfg->localcert.signcallback = qsc_tls_signer_default_sign;
    scfg->localcert.signstate = signer_ctx;
}

static bool qsctest_tls_stage18_0rtt_resumption_test(void)
{
    const uint8_t early_payload[] = "ping-0rtt";
    const uint8_t late_c[] = "late-from-client";
    const uint8_t late_s[] = "late-from-server";
    uint8_t c_out[4096U] = { 0U };
    uint8_t ch_rec[4096U] = { 0U };
    uint8_t early_rec[256U] = { 0U };
    uint8_t nst[2048U] = { 0U };
    uint8_t plain[512U] = { 0U };
    uint8_t rec[512U] = { 0U };
    uint8_t rx_payload[256U] = { 0U };
    uint8_t rx_resp[256U] = { 0U };
    uint8_t seed[32U] = { 0U };
    uint8_t sh_flight[32768U] = { 0U };
    uint8_t srv_junk[256U] = { 0U };
    const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
    const qsc_tls_signature_scheme sigs[1U] = { qsc_tls_sig_ed25519 };
    qsc_tls_signer_default_context signer_ctx;
    qsc_tls_client_config ccfg1;
    qsc_tls_server_config scfg1;
    qsc_tls_connection c1;
    qsc_tls_connection s1;
    qsc_tls_session_ticket srv_ticket;
    qsc_tls_session_ticket cli_ticket;
    size_t c_out_len;
    size_t ch_rec_len;
    size_t cons;
    size_t consumed;
    size_t dummy;
    size_t early_rec_len;
    size_t fin_len;
    size_t nst_len;
    size_t off;
    size_t plen;
    size_t rlen;
    size_t rx_consumed;
    size_t rx_plainlen;
    size_t rx_resplen;
    size_t sh_flight_len;
    size_t srv_junk_len;
    size_t srv_off;
    size_t w;
    qsc_tls_status st;
    qsc_tls_client_config ccfg2;
    qsc_tls_server_config scfg2;
    qsc_tls_connection c2;
    qsc_tls_connection s2;
    bool c2_initialized;
    bool s2_initialized;
    bool res;
    bool tickets_initialized;

    nst_len = 0U;
    consumed = 0U;
    ch_rec_len = 0U;
    cons = 0U;
    early_rec_len = 0U;
    sh_flight_len = 0U;
    rx_consumed = 0U;
    rx_plainlen = 0U;
    rx_resplen = 0U;
    c_out_len = 0U;
    off = 0U;
    fin_len = 0U;
    w = 0U;
    srv_junk_len = 0U;
    srv_off = 0U;
    rlen = 0U;
    plen = 0U;
    dummy = 0U;
    tickets_initialized = false;
    c2_initialized = false;
    s2_initialized = false;
    res = true;

    qsc_acp_generate(seed, sizeof(seed));
    qsc_secrand_initialize(seed, sizeof(seed), NULL, 0U);
    qsc_eddsa_generate_keypair(g_server_pk, g_server_sk, qsc_secrand_generate);
    qsc_memutils_copy(g_server_cert, g_server_pk, 32U);

    signer_ctx.scheme = qsc_tls_sig_ed25519;
    signer_ctx.privatekey = g_server_sk;
    signer_ctx.privatekeylen = 64U;

    initialize_configs(&ccfg1, &scfg1, suites, groups, sigs, &signer_ctx);

    qsc_tls_engine_initialize_client(&c1, &ccfg1);
    qsc_tls_engine_initialize_server(&s1, &scfg1);

    if (do_handshake(&c1, &s1) == false)
    {
        res = false;
    }

    if (res == true)
    {
        st = qsc_tls_engine_emit_session_ticket(&s1, 7200U, nst, sizeof(nst), &nst_len, &srv_ticket);

        if (st != qsc_tls_status_success)
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_consume_session_ticket(&c1, nst, nst_len, &consumed, &cli_ticket);

        if ((st != qsc_tls_status_success) || (qsc_memutils_are_equal(srv_ticket.resumptionsecret, cli_ticket.resumptionsecret, srv_ticket.resumptionsecretlen) != true))
        {
            res = false;
        }
        else
        {
            tickets_initialized = true;
        }
    }

    if (res == true)
    {
        qsc_memutils_clear(&g_store, sizeof(g_store));
        g_store.idlen = srv_ticket.ticketlen;
        qsc_memutils_copy(g_store.id, srv_ticket.ticket, srv_ticket.ticketlen);
        g_store.psklen = srv_ticket.resumptionsecretlen;
        qsc_memutils_copy(g_store.psk, srv_ticket.resumptionsecret, srv_ticket.resumptionsecretlen);
        g_store.suite = srv_ticket.suite;
    }

    qsc_tls_engine_dispose(&c1);
    qsc_tls_engine_dispose(&s1);

    if (res == true)
    {
        ccfg2 = ccfg1;
        ccfg2.offeredticket = &cli_ticket;
        ccfg2.enableearlydata = true;

        scfg2 = scfg1;
        scfg2.psklookup = psk_lookup_cb;
        scfg2.psklookupstate = NULL;
        scfg2.acceptearlydata = true;

        qsc_tls_engine_initialize_client(&c2, &ccfg2);
        c2_initialized = true;
        qsc_tls_engine_initialize_server(&s2, &scfg2);
        s2_initialized = true;

        st = qsc_tls_engine_handshake(&c2, NULL, 0U, &cons, ch_rec, sizeof(ch_rec), &ch_rec_len);

        if ((st != qsc_tls_status_success) || (ch_rec_len == 0U) || (c2.state.client.pskoffered == false) || (c2.state.client.earlydataoffered == false))
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_write_application_data(&c2, early_payload, sizeof(early_payload) - 1U, early_rec, sizeof(early_rec), &early_rec_len);
        
        if ((st != qsc_tls_status_success) || (early_rec_len == 0U))
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_handshake(&s2, ch_rec, ch_rec_len, &cons, sh_flight, sizeof(sh_flight), &sh_flight_len);

        if ((st != qsc_tls_status_success) || (s2.state.server.pskaccepted == false) || (s2.state.server.earlydataaccepted == false))
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_read_application_data_ex(&s2, early_rec, early_rec_len, &rx_consumed, rx_payload, sizeof(rx_payload), &rx_plainlen, rx_resp, sizeof(rx_resp), &rx_resplen);

        if ((st != qsc_tls_status_success) || (rx_plainlen != (sizeof(early_payload) - 1U)) || (qsc_memutils_are_equal(rx_payload, early_payload, rx_plainlen) != true))
        {
            res = false;
        }
    }

    while ((res == true) && (off < sh_flight_len) && (qsc_tls_engine_is_handshake_complete(&c2) == false))
    {
        w = 0U;
        st = qsc_tls_engine_handshake(&c2, sh_flight + off, sh_flight_len - off, &cons, c_out, sizeof(c_out), &w);

        if (st != qsc_tls_status_success)
        {
            res = false;
        }
        else
        {
            off += cons;

            if (w > 0U)
            {
                c_out_len = w;
                fin_len = w;
            }
        }
    }

    if ((res == true) && ((qsc_tls_engine_is_handshake_complete(&c2) == false) ||
        (c2.state.client.pskaccepted == false) || (c2.state.client.earlydataaccepted == false) ||
        (c_out_len == 0U)))
    {
        res = false;
    }

    while ((res == true) && (srv_off < fin_len) && (qsc_tls_engine_is_handshake_complete(&s2) == false))
    {
        st = qsc_tls_engine_handshake(&s2, c_out + srv_off, fin_len - srv_off, &cons, srv_junk, sizeof(srv_junk), &srv_junk_len);

        if (st != qsc_tls_status_success)
        {
            res = false;
        }
        else
        {
            srv_off += cons;

            if (cons == 0U)
            {
                break;
            }
        }
    }

    if ((res == true) && (qsc_tls_engine_is_handshake_complete(&s2) == false))
    {
        res = false;
    }

    if (res == true)
    {
        st = qsc_tls_engine_write_application_data(&c2, late_c, sizeof(late_c) - 1U, rec, sizeof(rec), &rlen);

        if (st != qsc_tls_status_success)
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_read_application_data_ex(&s2, rec, rlen, &cons, plain, sizeof(plain), &plen, NULL, 0U, &dummy);

        if ((st != qsc_tls_status_success) || (plen != (sizeof(late_c) - 1U)) || (qsc_memutils_are_equal(plain, late_c, plen) != true))
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_write_application_data(&s2, late_s, sizeof(late_s) - 1U, rec, sizeof(rec), &rlen);

        if (st != qsc_tls_status_success)
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_read_application_data_ex(&c2, rec, rlen, &cons, plain, sizeof(plain), &plen, NULL, 0U, &dummy);

        if ((st != qsc_tls_status_success) || (plen != (sizeof(late_s) - 1U)) || (qsc_memutils_are_equal(plain, late_s, plen) != true))
        {
            res = false;
        }
    }

    if (tickets_initialized == true)
    {
        qsc_tls_session_ticket_dispose(&srv_ticket);
        qsc_tls_session_ticket_dispose(&cli_ticket);
    }

    if (c2_initialized == true)
    {
        qsc_tls_engine_dispose(&c2);
    }

    if (s2_initialized == true)
    {
        qsc_tls_engine_dispose(&s2);
    }

    return res;
}

bool qsctest_tls_stage18_tests(void)
{
    bool res;

    res = qsctest_tls_stage18_0rtt_resumption_test();

    if (res == true)
    {
        qsctest_print_line("[PASS] TLS Stage 18 0-RTT resumption test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 18 0-RTT resumption test.");
    }

    return res;
}
