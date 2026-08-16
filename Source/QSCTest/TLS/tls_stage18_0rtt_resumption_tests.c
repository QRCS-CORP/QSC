#include "tls_stage18_0rtt_resumption_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "eddsa.h"
#include "memutils.h"
#include "tlsengine.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlssession.h"
#include "tlssignerdefault.h"

static qsc_tls_session_ticket g_store;

static uint8_t g_server_pk[32U];
static uint8_t g_server_sk[64U];
static uint8_t g_server_cert[32U];

static bool psk_lookup_cb(const uint8_t* identity, size_t identitylen, qsc_tls_session_ticket* ticketout, void* state)
{
    const qsc_tls_session_ticket* ticket;
    bool res;

    ticket = (const qsc_tls_session_ticket*)state;
    res = false;

    if (ticket != NULL && ticketout != NULL && identity != NULL && identitylen != 0U && identitylen == ticket->ticketlen &&
        qsc_memutils_are_equal(identity, ticket->ticket, identitylen) == true)
    {
        *ticketout = *ticket;
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

static void initialize_configs(qsc_tls_client_config* ccfg, qsc_tls_server_config* scfg, const qsc_tls_cipher_suite* suites, const qsc_tls_named_group* groups, 
    const qsc_tls_signature_scheme* sigs, qsc_tls_signer_default_context* signer_ctx)
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
    ccfg->enableresumption = true;

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

static bool qsctest_tls_stage18_resumption_profile_test(void)
{
    const uint8_t clientmsg[] = "resumed-from-client";
    const uint8_t servermsg[] = "resumed-from-server";
    uint8_t nst[2048U] = { 0U };
    uint8_t plain[512U] = { 0U };
    uint8_t rec[512U] = { 0U };
    const qsc_tls_cipher_suite suites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    const qsc_tls_named_group groups[1U] = { qsc_tls_group_x25519 };
    const qsc_tls_signature_scheme sigs[1U] = { qsc_tls_sig_ed25519 };
    qsc_tls_signer_default_context signerctx;
    qsc_tls_client_config ccfg1;
    qsc_tls_client_config ccfg2;
    qsc_tls_client_config rejectccfg;
    qsc_tls_server_config* scfg1;
    qsc_tls_server_config* scfg2;
    qsc_tls_server_config* rejectscfg;
    qsc_tls_connection* c1;
    qsc_tls_connection* c2;
    qsc_tls_connection* rejected;
    qsc_tls_connection* s1;
    qsc_tls_connection* s2;
    qsc_tls_session_ticket cliticket;
    qsc_tls_session_ticket srvticket;
    size_t consumed;
    size_t nstlen;
    size_t plainlen;
    size_t reclen;
    qsc_tls_status status;
    bool c1initialized;
    bool c2initialized;
    bool res;
    bool s1initialized;
    bool s2initialized;

    c1 = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));
    c2 = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));
    rejected = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));
    s1 = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));
    s2 = (qsc_tls_connection*)qsc_memutils_malloc(sizeof(qsc_tls_connection));
    scfg1 = (qsc_tls_server_config*)qsc_memutils_malloc(sizeof(qsc_tls_server_config));
    scfg2 = (qsc_tls_server_config*)qsc_memutils_malloc(sizeof(qsc_tls_server_config));
    rejectscfg = (qsc_tls_server_config*)qsc_memutils_malloc(sizeof(qsc_tls_server_config));
    c1initialized = false;
    c2initialized = false;
    consumed = 0U;
    nstlen = 0U;
    plainlen = 0U;
    reclen = 0U;
    res = (c1 != NULL && c2 != NULL && rejected != NULL && s1 != NULL && s2 != NULL && scfg1 != NULL && scfg2 != NULL && rejectscfg != NULL);
    s1initialized = false;
    s2initialized = false;
    qsc_memutils_clear(&cliticket, sizeof(cliticket));
    qsc_memutils_clear(&srvticket, sizeof(srvticket));
    qsc_memutils_clear(&g_store, sizeof(g_store));

    if (res == true)
    {
        qsc_memutils_clear(c1, sizeof(qsc_tls_connection));
        qsc_memutils_clear(c2, sizeof(qsc_tls_connection));
        qsc_memutils_clear(rejected, sizeof(qsc_tls_connection));
        qsc_memutils_clear(s1, sizeof(qsc_tls_connection));
        qsc_memutils_clear(s2, sizeof(qsc_tls_connection));
        qsc_memutils_clear(scfg1, sizeof(qsc_tls_server_config));
        qsc_memutils_clear(scfg2, sizeof(qsc_tls_server_config));
        qsc_memutils_clear(rejectscfg, sizeof(qsc_tls_server_config));
        qsc_eddsa_generate_keypair(g_server_pk, g_server_sk, qsc_csp_generate);
        qsc_memutils_copy(g_server_cert, g_server_pk, sizeof(g_server_cert));
        signerctx.scheme = qsc_tls_sig_ed25519;
        signerctx.privatekey = g_server_sk;
        signerctx.privatekeylen = sizeof(g_server_sk);
        initialize_configs(&ccfg1, scfg1, suites, groups, sigs, &signerctx);

        status = qsc_tls_engine_initialize_client(c1, &ccfg1);
        res = (status == qsc_tls_status_success);
        c1initialized = res;
    }

    if (res == true)
    {
        status = qsc_tls_engine_initialize_server(s1, scfg1);
        res = (status == qsc_tls_status_success);
        s1initialized = res;
    }

    if (res == true)
    {
        res = do_handshake(c1, s1);
    }

    if (res == true)
    {
        status = qsc_tls_engine_emit_session_ticket(s1, 7200U, nst, sizeof(nst), &nstlen, &srvticket);
        res = (status == qsc_tls_status_success && nstlen != 0U && srvticket.maxearlydatasize == 0U);
    }

    if (res == true)
    {
        status = qsc_tls_engine_consume_session_ticket(c1, nst, nstlen, &consumed, &cliticket);
        res = (status == qsc_tls_status_success && consumed == nstlen && cliticket.maxearlydatasize == 0U &&
            cliticket.protocolversion == QSC_TLS_PROTOCOL_VERSION_13 && cliticket.receipttimems != 0ULL);
    }

    if (res == true)
    {
        res = (srvticket.resumptionsecretlen != 0U && srvticket.resumptionsecretlen == cliticket.resumptionsecretlen &&
            qsc_memutils_are_equal(srvticket.resumptionsecret, cliticket.resumptionsecret, srvticket.resumptionsecretlen) == true);
    }

    if (res == true)
    {
        g_store = srvticket;
    }

    if (c1initialized == true)
    {
        qsc_tls_engine_dispose(c1);
    }

    if (s1initialized == true)
    {
        qsc_tls_engine_dispose(s1);
    }

    if (res == true)
    {
        ccfg2 = ccfg1;
        ccfg2.offeredticket = &cliticket;
        ccfg2.enableearlydata = false;
        *scfg2 = *scfg1;
        scfg2->psklookup = psk_lookup_cb;
        scfg2->psklookupstate = &g_store;
        scfg2->acceptearlydata = false;
        status = qsc_tls_engine_initialize_client(c2, &ccfg2);
        res = (status == qsc_tls_status_success);
        c2initialized = res;
    }

    if (res == true)
    {
        status = qsc_tls_engine_initialize_server(s2, scfg2);
        res = (status == qsc_tls_status_success);
        s2initialized = res;
    }

    if (res == true)
    {
        res = do_handshake(c2, s2);
    }

    if (res == true)
    {
        res = (c2->state.client.pskoffered == true && c2->state.client.pskaccepted == true &&
            c2->state.client.earlydataoffered == false && c2->state.client.earlydataaccepted == false &&
            s2->state.server.pskaccepted == true && s2->state.server.earlydataaccepted == false);
    }

    if (res == true)
    {
        status = qsc_tls_engine_write_application_data(c2, clientmsg, sizeof(clientmsg) - 1U, rec, sizeof(rec), &reclen);
        res = (status == qsc_tls_status_success && reclen != 0U);
    }

    if (res == true)
    {
        consumed = 0U;
        plainlen = 0U;
        status = qsc_tls_engine_read_application_data(s2, rec, reclen, &consumed, plain, sizeof(plain), &plainlen);
        res = (status == qsc_tls_status_success && consumed == reclen && plainlen == (sizeof(clientmsg) - 1U) &&
            qsc_memutils_are_equal(plain, clientmsg, plainlen) == true);
    }

    if (res == true)
    {
        reclen = 0U;
        status = qsc_tls_engine_write_application_data(s2, servermsg, sizeof(servermsg) - 1U, rec, sizeof(rec), &reclen);
        res = (status == qsc_tls_status_success && reclen != 0U);
    }

    if (res == true)
    {
        consumed = 0U;
        plainlen = 0U;
        status = qsc_tls_engine_read_application_data(c2, rec, reclen, &consumed, plain, sizeof(plain), &plainlen);
        res = (status == qsc_tls_status_success && consumed == reclen && plainlen == (sizeof(servermsg) - 1U) &&
            qsc_memutils_are_equal(plain, servermsg, plainlen) == true);
    }

    if (c2initialized == true)
    {
        qsc_tls_engine_dispose(c2);
    }

    if (s2initialized == true)
    {
        qsc_tls_engine_dispose(s2);
    }

    if (res == true)
    {
        qsc_memutils_clear(rejected, sizeof(qsc_tls_connection));
        rejectccfg = ccfg1;
        rejectccfg.enableearlydata = true;
        status = qsc_tls_engine_initialize_client(rejected, &rejectccfg);
        res = (status == qsc_tls_status_not_supported);
    }

    if (res == true)
    {
        qsc_memutils_clear(rejected, sizeof(qsc_tls_connection));
        *rejectscfg = *scfg1;
        rejectscfg->acceptearlydata = true;
        status = qsc_tls_engine_initialize_server(rejected, rejectscfg);
        res = (status == qsc_tls_status_not_supported);
    }

    qsc_tls_session_ticket_dispose(&srvticket);
    qsc_tls_session_ticket_dispose(&cliticket);
    qsc_tls_session_ticket_dispose(&g_store);

    if (c1 != NULL)
    {
        qsc_memutils_secure_erase(c1, sizeof(qsc_tls_connection));
        qsc_memutils_alloc_free(c1);
    }

    if (c2 != NULL)
    {
        qsc_memutils_secure_erase(c2, sizeof(qsc_tls_connection));
        qsc_memutils_alloc_free(c2);
    }

    if (rejected != NULL)
    {
        qsc_memutils_secure_erase(rejected, sizeof(qsc_tls_connection));
        qsc_memutils_alloc_free(rejected);
    }

    if (s1 != NULL)
    {
        qsc_memutils_secure_erase(s1, sizeof(qsc_tls_connection));
        qsc_memutils_alloc_free(s1);
    }

    if (s2 != NULL)
    {
        qsc_memutils_secure_erase(s2, sizeof(qsc_tls_connection));
        qsc_memutils_alloc_free(s2);
    }

    if (scfg1 != NULL)
    {
        qsc_memutils_clear(scfg1, sizeof(qsc_tls_server_config));
        qsc_memutils_alloc_free(scfg1);
    }

    if (scfg2 != NULL)
    {
        qsc_memutils_clear(scfg2, sizeof(qsc_tls_server_config));
        qsc_memutils_alloc_free(scfg2);
    }

    if (rejectscfg != NULL)
    {
        qsc_memutils_clear(rejectscfg, sizeof(qsc_tls_server_config));
        qsc_memutils_alloc_free(rejectscfg);
    }

    return res;
}

bool qsctest_tls_stage18_tests(void)
{
    bool res;

    res = qsctest_tls_stage18_resumption_profile_test();

    if (res == true)
    {
        qsctest_print_line("[PASS] TLS Stage 18 1-RTT resumption and 0-RTT rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 18 1-RTT resumption and 0-RTT rejection test.");
    }

    return res;
}
