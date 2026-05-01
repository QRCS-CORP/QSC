#include "tls_stage7_hrr_tests.h"
#include "../testutils.h"
#include "tlsengine.h"
#include "tlsclient.h"
#include "tlsserver.h"
#include "tlssignerdefault.h"
#include "memutils.h"
#include "secrand.h"
#include "acp.h"
#include "eddsa.h"

static uint8_t qsctest_tls_stage7_server_pk[32U];
static uint8_t qsctest_tls_stage7_server_sk[64U];
static uint8_t qsctest_tls_stage7_server_cert[32U];

static bool qsctest_tls_stage7_validate(const qsc_tls_certificate_view* chain, size_t chainlength,
    const qsc_tls_certificate_validation_context* ctx, void* state)
{
    (void)ctx;
    (void)state;

    return (chain != NULL && chainlength == 1U && chain[0U].datalen == 32U);
}

static bool qsctest_tls_stage7_verify(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature,
    size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    qsc_tls_certificate_view view = { 0 };

    (void)signer;
    (void)state;

    view.data = qsctest_tls_stage7_server_pk;
    view.datalen = sizeof(qsctest_tls_stage7_server_pk);

    return qsc_tls_signer_default_verify(scheme, input, inputlen, signature, signaturelen, &view, NULL);
}

static bool qsctest_tls_stage7_hrr_handshake(bool* observed_hrr)
{
    qsc_tls_connection client = { 0 };
    qsc_tls_connection server = { 0 };
    qsc_tls_client_config ccfg = { 0 };
    qsc_tls_server_config scfg = { 0 };
    qsc_tls_signer_default_context signer_ctx = { 0 };
    uint8_t bufc2s[8192U] = { 0U };
    uint8_t bufs2c[32768U] = { 0U };
    uint8_t junk[128U] = { 0U };
    uint8_t seed[32U] = { 0U };
    const qsc_tls_cipher_suite csuites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    const qsc_tls_named_group cgroups[2U] = { qsc_tls_group_x25519, qsc_tls_group_secp256r1 };
    const qsc_tls_signature_scheme csigs[1U] = { qsc_tls_sig_ed25519 };
    const qsc_tls_cipher_suite ssuites[1U] = { qsc_tls_cipher_suite_tls_aes_128_gcm_sha256 };
    const qsc_tls_named_group sgroups[1U] = { qsc_tls_group_secp256r1 };
    const qsc_tls_signature_scheme ssigs[1U] = { qsc_tls_sig_ed25519 };
    size_t consumed;
    size_t written;
    size_t c2slen;
    size_t s2c_len;
    qsc_tls_status st;
    bool res;

    qsc_acp_generate(seed, sizeof(seed));
    qsc_secrand_initialize(seed, sizeof(seed), NULL, 0U);
    qsc_eddsa_generate_keypair(qsctest_tls_stage7_server_pk, qsctest_tls_stage7_server_sk, qsc_secrand_generate);
    qsc_memutils_copy(qsctest_tls_stage7_server_cert, qsctest_tls_stage7_server_pk, sizeof(qsctest_tls_stage7_server_cert));

    qsc_memutils_clear(&ccfg, sizeof(ccfg));
    ccfg.ciphersuites = csuites;
    ccfg.ciphersuitecount = 1U;
    ccfg.groups = cgroups;
    ccfg.groupcount = 2U;
    ccfg.sigschemes = csigs;
    ccfg.sigschemecount = 1U;
    ccfg.sigschemes = csigs;
    ccfg.sigschemecount = 1U;
    ccfg.hostname = "example.com";
    ccfg.certinterface.validatechain = qsctest_tls_stage7_validate;
    ccfg.certinterface.verifycertificateverify = qsctest_tls_stage7_verify;

    qsc_memutils_clear(&scfg, sizeof(scfg));
    scfg.ciphersuitepreference = ssuites;
    scfg.ciphersuitepreferencecount = 1U;
    scfg.groupspreference = sgroups;
    scfg.groupspreferencecount = 1U;
    scfg.sigschemepreference = ssigs;
    scfg.sigschemepreferencecount = 1U;
    scfg.localcert.chain[0].data = qsctest_tls_stage7_server_cert;
    scfg.localcert.chain[0].datalen = sizeof(qsctest_tls_stage7_server_cert);
    scfg.localcert.chainlength = 1U;
    scfg.localcert.verifyscheme = qsc_tls_sig_ed25519;
    scfg.localcert.configured = true;
    signer_ctx.scheme = qsc_tls_sig_ed25519;
    signer_ctx.privatekey = qsctest_tls_stage7_server_sk;
    signer_ctx.privatekeylen = sizeof(qsctest_tls_stage7_server_sk);
    scfg.localcert.signcallback = qsc_tls_signer_default_sign;
    scfg.localcert.signstate = &signer_ctx;

    qsc_tls_engine_initialize_client(&client, &ccfg);
    qsc_tls_engine_initialize_server(&server, &scfg);

    c2slen = 0U;
    st = qsc_tls_engine_handshake(&client, NULL, 0U, &consumed, bufc2s, sizeof(bufc2s), &c2slen);
    res = (st == qsc_tls_status_success && c2slen != 0U);

    if (res == true)
    {
        static const uint8_t hrr_magic[32U] = {
            0xCFU, 0x21U, 0xADU, 0x74U, 0xE5U, 0x9AU, 0x61U, 0x11U,
            0xBEU, 0x1DU, 0x8CU, 0x02U, 0x1EU, 0x65U, 0xB8U, 0x91U,
            0xC2U, 0xA2U, 0x11U, 0x16U, 0x7AU, 0xBBU, 0x8CU, 0x5EU,
            0x07U, 0x9EU, 0x09U, 0xE2U, 0xC8U, 0xA8U, 0x33U, 0x9CU };
        bool lookslikehrr = false;
        size_t offset;
        size_t clientfinlen;

        s2c_len = 0U;
        st = qsc_tls_engine_handshake(&server, bufc2s, c2slen, &consumed, bufs2c, sizeof(bufs2c), &s2c_len);
        res = (st == qsc_tls_status_success && s2c_len != 0U);

        if (res == true)
        {
            lookslikehrr = (s2c_len >= (11U + 32U));

            if (lookslikehrr == true)
            {
                lookslikehrr = qsc_memutils_are_equal(bufs2c + 11U, hrr_magic, sizeof(hrr_magic));
            }

            if (observed_hrr != NULL)
            {
                *observed_hrr = lookslikehrr;
            }

            res = (lookslikehrr == true);
            res = (res == true && server.state.server.helloretryrequestsent == true);
            res = (res == true && server.state.server.phase == qsc_tls_server_phase_waiting_client_hello_2);
        }

        if (res == true)
        {
            c2slen = 0U;
            st = qsc_tls_engine_handshake(&client, bufs2c, s2c_len, &consumed, bufc2s, sizeof(bufc2s), &c2slen);
            res = (st == qsc_tls_status_success && c2slen != 0U);
            res = (res == true && client.state.client.helloretryrequestconsumed == true);
        }

        if (res == true)
        {
            s2c_len = 0U;
            st = qsc_tls_engine_handshake(&server, bufc2s, c2slen, &consumed, bufs2c, sizeof(bufs2c), &s2c_len);
            res = (st == qsc_tls_status_success && s2c_len != 0U);
        }

        if (res == true)
        {
            offset = 0U;
            clientfinlen = 0U;

            while (offset < s2c_len && qsc_tls_engine_is_handshake_complete(&client) == false)
            {
                size_t w = 0U;
                st = qsc_tls_engine_handshake(&client, bufs2c + offset, s2c_len - offset, &consumed, bufc2s, sizeof(bufc2s), &w);

                if (st != qsc_tls_status_success)
                {
                    res = false;
                    break;
                }

                offset += consumed;

                if (w > 0U)
                {
                    clientfinlen = w;
                }
            }

            res = (res == true && qsc_tls_engine_is_handshake_complete(&client) == true);

            if (res == true)
            {
                st = qsc_tls_engine_handshake(&server, bufc2s, clientfinlen, &consumed, junk, sizeof(junk), &written);
                res = (st == qsc_tls_status_success);
                res = (res == true && qsc_tls_engine_is_handshake_complete(&server) == true);
                res = (res == true && client.state.client.negotiatedgroup == qsc_tls_group_secp256r1);
                res = (res == true && server.state.server.negotiatedgroup == qsc_tls_group_secp256r1);
            }
        }
    }

    qsc_tls_engine_dispose(&client);
    qsc_tls_engine_dispose(&server);

    return res;
}

bool qsctest_tls_stage7_tests(void)
{
    bool observed_hrr;
    bool res;

    res = true;
    observed_hrr = false;

    if (qsctest_tls_stage7_hrr_handshake(&observed_hrr) == true)
    {
        qsctest_print_line("[PASS] TLS Stage 7 HelloRetryRequest handshake test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 7 HelloRetryRequest handshake test.");
        res = false;
    }

    return res;
}
