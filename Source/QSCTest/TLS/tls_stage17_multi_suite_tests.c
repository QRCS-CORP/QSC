#include "tls_stage17_multi_suite_tests.h"
#include "../testutils.h"
#include "acp.h"
#include "eddsa.h"
#include "memutils.h"
#include "secrand.h"
#include "tlsclient.h"
#include "tlsengine.h"
#include "tlsserver.h"
#include "tlssignerdefault.h"

static uint8_t g_server_pk[32U];
static uint8_t g_server_sk[64U];
static uint8_t g_server_cert[32U];

static bool stub_validate(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* ctx, void* state)
{
    bool res;

    (void)ctx;
    (void)state;
    res = ((chainlength == 1U) && (chain[0].datalen == 32U));

    return res;
}

static bool stub_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, 
    size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
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

static bool run_handshake_under_suite(qsc_tls_cipher_suite suite, const char* suite_name)
{
    const qsc_tls_cipher_suite suites[1] = { suite };
    const qsc_tls_named_group groups[1] = { qsc_tls_group_x25519 };
    const qsc_tls_signature_scheme sigs[1] = { qsc_tls_sig_ed25519 };
    qsc_tls_signer_default_context signer_ctx;
    qsc_tls_client_config ccfg;
    qsc_tls_server_config scfg;
    qsc_tls_connection c;
    qsc_tls_connection s;
    const uint8_t c2s_plain[] = "hello-from-client";
    const uint8_t s2c_plain[] = "ack-from-server";
    uint8_t ch[4096U] = { 0U };
    uint8_t cli_fin[1024U] = { 0U };
    uint8_t junk[256U] = { 0U };
    uint8_t plain[512U] = { 0U };
    uint8_t rec[512U] = { 0U };
    uint8_t srv_flight[32768U] = { 0U };
    size_t ch_len;
    size_t cli_fin_len;
    size_t cons;
    size_t dummy;
    size_t junk_len;
    size_t off;
    size_t plen;
    size_t reclen;
    size_t srv_flight_len;
    qsc_tls_status st;
    size_t w;
    bool res;

    (void)suite_name;
    ch_len = 0U;
    srv_flight_len = 0U;
    cli_fin_len = 0U;
    junk_len = 0U;
    cons = 0U;
    off = 0U;
    w = 0U;
    reclen = 0U;
    plen = 0U;
    dummy = 0U;
    res = true;

    signer_ctx.scheme = qsc_tls_sig_ed25519;
    signer_ctx.privatekey = g_server_sk;
    signer_ctx.privatekeylen = 64U;

    qsc_memutils_clear(&ccfg, sizeof(ccfg));
    ccfg.ciphersuites = suites;
    ccfg.ciphersuitecount = 1U;
    ccfg.groups = groups;
    ccfg.groupcount = 1U;
    ccfg.sigschemes = sigs;
    ccfg.sigschemecount = 1U;
    ccfg.hostname = "example.com";
    ccfg.certinterface.validatechain = stub_validate;
    ccfg.certinterface.verifycertificateverify = stub_verify;

    qsc_memutils_clear(&scfg, sizeof(scfg));
    scfg.ciphersuitepreference = suites;
    scfg.ciphersuitepreferencecount = 1U;
    scfg.groupspreference = groups;
    scfg.groupspreferencecount = 1U;
    scfg.sigschemepreference = sigs;
    scfg.sigschemepreferencecount = 1U;
    scfg.localcert.chain[0].data = g_server_cert;
    scfg.localcert.chain[0].datalen = 32U;
    scfg.localcert.chainlength = 1U;
    scfg.localcert.verifyscheme = qsc_tls_sig_ed25519;
    scfg.localcert.configured = true;
    scfg.localcert.signcallback = qsc_tls_signer_default_sign;
    scfg.localcert.signstate = &signer_ctx;

    qsc_tls_engine_initialize_client(&c, &ccfg);
    qsc_tls_engine_initialize_server(&s, &scfg);

    st = qsc_tls_engine_handshake(&c, NULL, 0U, &cons, ch, sizeof(ch), &ch_len);

    if ((st != qsc_tls_status_success) || (ch_len == 0U))
    {
        res = false;
    }

    if (res == true)
    {
        st = qsc_tls_engine_handshake(&s, ch, ch_len, &cons, srv_flight, sizeof(srv_flight), &srv_flight_len);

        if ((st != qsc_tls_status_success) || (srv_flight_len == 0U))
        {
            res = false;
        }
    }

    while ((res == true) && (off < srv_flight_len) && (qsc_tls_engine_is_handshake_complete(&c) == false))
    {
        w = 0U;
        st = qsc_tls_engine_handshake(&c, srv_flight + off, srv_flight_len - off, &cons, cli_fin, sizeof(cli_fin), &w);

        if (st != qsc_tls_status_success)
        {
            res = false;
        }
        else
        {
            off += cons;

            if (w > 0U)
            {
                cli_fin_len = w;
            }
            if (cons == 0U)
            {
                break;
            }
        }
    }

    if ((res == true) && ((qsc_tls_engine_is_handshake_complete(&c) == false) || (cli_fin_len == 0U) || (c.state.client.negotiatedsuite != suite)))
    {
        res = false;
    }

    if (res == true)
    {
        st = qsc_tls_engine_handshake(&s, cli_fin, cli_fin_len, &cons, junk, sizeof(junk), &junk_len);

        if ((st != qsc_tls_status_success) || (qsc_tls_engine_is_handshake_complete(&s) == false) || (s.state.server.negotiatedsuite != suite))
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_write_application_data(&c, c2s_plain, sizeof(c2s_plain) - 1U, rec, sizeof(rec), &reclen);

        if ((st != qsc_tls_status_success) || (reclen == 0U))
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_read_application_data_ex(&s, rec, reclen, &cons, plain, sizeof(plain), &plen, NULL, 0U, &dummy);

        if ((st != qsc_tls_status_success) || (plen != (sizeof(c2s_plain) - 1U)) || (qsc_memutils_are_equal(plain, c2s_plain, plen) != true))
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_write_application_data(&s, s2c_plain, sizeof(s2c_plain) - 1U, rec, sizeof(rec), &reclen);

        if ((st != qsc_tls_status_success) || (reclen == 0U))
        {
            res = false;
        }
    }

    if (res == true)
    {
        st = qsc_tls_engine_read_application_data_ex(&c, rec, reclen, &cons, plain, sizeof(plain), &plen, NULL, 0U, &dummy);

        if ((st != qsc_tls_status_success) || (plen != (sizeof(s2c_plain) - 1U)) || (qsc_memutils_are_equal(plain, s2c_plain, plen) != true))
        {
            res = false;
        }
    }

    qsc_tls_engine_dispose(&c);
    qsc_tls_engine_dispose(&s);

    return res;
}

static bool qsctest_tls_stage17_multi_suite_test(void)
{
    uint8_t seed[32U] = { 0U };
    bool res;

    res = true;

    qsc_acp_generate(seed, sizeof(seed));
    qsc_secrand_initialize(seed, sizeof(seed), NULL, 0U);
    qsc_eddsa_generate_keypair(g_server_pk, g_server_sk, qsc_secrand_generate);
    qsc_memutils_copy(g_server_cert, g_server_pk, 32U);

    if (run_handshake_under_suite(qsc_tls_cipher_suite_tls_aes_128_gcm_sha256, "TLS_AES_128_GCM_SHA256") == false)
    {
        res = false;
    }

    if (run_handshake_under_suite(qsc_tls_cipher_suite_tls_aes_256_gcm_sha384, "TLS_AES_256_GCM_SHA384") == false)
    {
        res = false;
    }

    if (run_handshake_under_suite(qsc_tls_cipher_suite_tls_chacha20_poly1305_sha256, "TLS_CHACHA20_POLY1305_SHA256") == false)
    {
        res = false;
    }

    return res;
}

bool qsctest_tls_stage17_tests(void)
{
    bool res;

    res = qsctest_tls_stage17_multi_suite_test();

    if (res == true)
    {
        qsctest_print_line("[PASS] TLS Stage 17 multi-suite end-to-end test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 17 multi-suite end-to-end test.");
    }

    return res;
}
