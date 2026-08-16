#include "tls_stage22_mtls_authorization_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "sha3.h"
#include "tlscert.h"
#include "tlsserver.h"
#include "tlssocket.h"

#define STAGE22_CERTIFICATE_SIZE 24U

typedef struct stage22_mock_certificate_state
{
    bool validateaccept;
    bool validatecalled;
    bool verifycalled;
    bool sawclientauth;
    bool sawrequirepeer;
    size_t sawchainlength;
    size_t sawleaflength;
} stage22_mock_certificate_state;

typedef struct stage22_mock_authorization_state
{
    bool authorizeaccept;
    bool authorizecalled;
    bool sawchainvalid;
    bool sawverifysuccess;
    bool sawfingerprint;
    bool sawexpectedfingerprint;
    uint8_t expectedfingerprint[QSC_TLS_CERTIFICATE_FINGERPRINT_SIZE];
} stage22_mock_authorization_state;

static bool stage22_mock_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* context, void* state);

static bool stage22_mock_verify_certificate(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, 
    size_t signaturelen, const qsc_tls_certificate_view* signer, void* state);

static bool stage22_mock_authorize_client(const qsc_tls_client_authorization_info* info, void* state);

static void stage22_make_certificate_view(qsc_tls_certificate_view* view, const uint8_t* data, size_t datalen)
{
    if (view != NULL)
    {
        view->data = data;
        view->datalen = datalen;
    }
}

static void stage22_initialize_server_state(qsc_tls_server_state* state, stage22_mock_certificate_state* certstate, bool validateaccept, bool requireclientauth)
{
    qsc_tls_certificate_interface iface;

    if ((state != NULL) && (certstate != NULL))
    {
        qsc_memutils_clear(state, sizeof(*state));
        qsc_memutils_clear(certstate, sizeof(*certstate));
        certstate->validateaccept = validateaccept;
        qsc_tls_certificate_interface_initialize(&iface, stage22_mock_validate_chain, stage22_mock_verify_certificate, certstate);
        (void)qsc_tls_server_config_set_certificate_interface(&state->config, &iface, true, requireclientauth);
    }
}

static bool stage22_mock_validate_chain(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* context, void* state)
{
    stage22_mock_certificate_state* mstate;
    bool res;

    res = false;

    if (state != NULL)
    {
        mstate = (stage22_mock_certificate_state*)state;
        mstate->validatecalled = true;
        mstate->sawchainlength = chainlength;

        if ((chain != NULL) && (chainlength != 0U) && (chain[0U].data != NULL))
        {
            mstate->sawleaflength = chain[0U].datalen;
        }

        if (context != NULL)
        {
            mstate->sawclientauth = context->clientauth;
            mstate->sawrequirepeer = context->requirepeercertificate;
        }

        res = mstate->validateaccept;
    }

    return res;
}

static bool stage22_mock_verify_certificate(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, 
    size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    stage22_mock_certificate_state* mstate;

    (void)scheme;
    (void)input;
    (void)inputlen;
    (void)signature;
    (void)signaturelen;
    (void)signer;

    if (state != NULL)
    {
        mstate = (stage22_mock_certificate_state*)state;
        mstate->verifycalled = true;
    }

    return true;
}

static bool stage22_mock_authorize_client(const qsc_tls_client_authorization_info* info, void* state)
{
    stage22_mock_authorization_state* astate;
    bool res;

    res = false;

    if ((info != NULL) && (state != NULL))
    {
        astate = (stage22_mock_authorization_state*)state;
        astate->authorizecalled = true;
        astate->sawchainvalid = info->chainvalid;
        astate->sawverifysuccess = (info->verifystatus == QSC_X509_VERIFY_STATUS_SUCCESS);
        astate->sawfingerprint = (info->certificatefingerprintlen == QSC_TLS_CERTIFICATE_FINGERPRINT_SIZE);
        astate->sawexpectedfingerprint = qsc_memutils_are_equal(info->certificatefingerprint, astate->expectedfingerprint, QSC_TLS_CERTIFICATE_FINGERPRINT_SIZE);
        res = astate->authorizeaccept;
    }

    return res;
}

static bool stage22_server_config_client_auth_policy_test(void)
{
    qsc_tls_server_config config;
    qsc_tls_certificate_interface iface;
    stage22_mock_certificate_state certstate;
    bool res;

    res = false;
    qsc_memutils_clear(&config, sizeof(config));
    qsc_memutils_clear(&certstate, sizeof(certstate));
    qsc_tls_certificate_interface_initialize(&iface, stage22_mock_validate_chain, stage22_mock_verify_certificate, &certstate);

    if (qsc_tls_server_config_set_certificate_interface(&config, &iface, true, true) == qsc_tls_status_success)
    {
        if ((config.requestclientauth == true) && (config.requireclientauth == true) &&
            (qsc_tls_certificate_interface_is_valid(&config.clientcertinterface) == true))
        {
            if (qsc_tls_server_config_set_certificate_interface(&config, NULL, true, false) == qsc_tls_status_invalid_input)
            {
                if (qsc_tls_server_config_set_certificate_interface(&config, NULL, false, false) == qsc_tls_status_success)
                {
                    if ((config.requestclientauth == false) && (config.requireclientauth == false))
                    {
                        if (qsc_tls_server_config_set_client_authorization(&config, stage22_mock_authorize_client, &certstate, true) == qsc_tls_status_success)
                        {
                            if ((config.clientauthcallback == stage22_mock_authorize_client) && (config.clientauthstate == &certstate) &&
                                (config.requireclientauthorization == true))
                            {
                                if (qsc_tls_server_config_set_client_authorization(&config, NULL, NULL, true) == qsc_tls_status_invalid_input)
                                {
                                    if (qsc_tls_server_config_set_client_authorization(&config, NULL, NULL, false) == qsc_tls_status_success)
                                    {
                                        if ((config.clientauthcallback == NULL) && (config.clientauthstate == NULL) &&
                                            (config.requireclientauthorization == false))
                                        {
                                            res = true;
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

    return res;
}

static bool stage22_authorization_accept_test(void)
{
    static const uint8_t cert[STAGE22_CERTIFICATE_SIZE] = { 0x30U, 0x01U, 0x22U, 0xA0U, 0xA1U, 0xA2U, 0xA3U, 0xA4U,
        0xA5U, 0xA6U, 0xA7U, 0xA8U, 0xA9U, 0xAAU, 0xABU, 0xACU, 0xADU, 0xAEU, 0xAFU, 0xB0U, 0xB1U, 0xB2U, 0xB3U, 0xB4U };
    qsc_tls_server_state state;
    qsc_tls_certificate_view chain[1U];
    stage22_mock_certificate_state certstate;
    stage22_mock_authorization_state authstate;
    bool res;

    res = false;
    qsc_memutils_clear(&authstate, sizeof(authstate));
    authstate.authorizeaccept = true;
    qsc_sha3_compute256(authstate.expectedfingerprint, cert, sizeof(cert));
    stage22_make_certificate_view(&chain[0U], cert, sizeof(cert));
    stage22_initialize_server_state(&state, &certstate, true, true);

    if (qsc_tls_server_config_set_client_authorization(&state.config, stage22_mock_authorize_client, &authstate, true) == qsc_tls_status_success)
    {
        if (qsc_tls_server_authorize_client_certificate(&state, chain, 1U) == qsc_tls_status_success)
        {
            if ((certstate.validatecalled == true) && (certstate.verifycalled == false) && (certstate.sawclientauth == true) &&
                (certstate.sawrequirepeer == true) && (certstate.sawchainlength == 1U) && (certstate.sawleaflength == sizeof(cert)) &&
                (authstate.authorizecalled == true) && (authstate.sawchainvalid == true) && (authstate.sawverifysuccess == true) &&
                (authstate.sawfingerprint == true) && (authstate.sawexpectedfingerprint == true))
            {
                res = true;
            }
        }
    }

    return res;
}

static bool stage22_authorization_reject_test(void)
{
    static const uint8_t cert[STAGE22_CERTIFICATE_SIZE] = { 0x30U, 0x02U, 0x33U, 0xC0U, 0xC1U, 0xC2U, 0xC3U, 0xC4U,
        0xC5U, 0xC6U, 0xC7U, 0xC8U, 0xC9U, 0xCAU, 0xCBU, 0xCCU, 0xCDU, 0xCEU, 0xCFU, 0xD0U, 0xD1U, 0xD2U, 0xD3U, 0xD4U };
    qsc_tls_server_state state;
    qsc_tls_certificate_view chain[1U];
    stage22_mock_certificate_state certstate;
    stage22_mock_authorization_state authstate;
    bool res;

    res = false;
    qsc_memutils_clear(&authstate, sizeof(authstate));
    authstate.authorizeaccept = false;
    qsc_sha3_compute256(authstate.expectedfingerprint, cert, sizeof(cert));
    stage22_make_certificate_view(&chain[0U], cert, sizeof(cert));
    stage22_initialize_server_state(&state, &certstate, true, true);

    if (qsc_tls_server_config_set_client_authorization(&state.config, stage22_mock_authorize_client, &authstate, true) == qsc_tls_status_success)
    {
        if (qsc_tls_server_authorize_client_certificate(&state, chain, 1U) == qsc_tls_status_authentication_failure)
        {
            if ((state.lastalert == qsc_tls_alert_access_denied) && (certstate.validatecalled == true) &&
                (authstate.authorizecalled == true) && (authstate.sawexpectedfingerprint == true))
            {
                res = true;
            }
        }
    }

    return res;
}

static bool stage22_validation_failure_test(void)
{
    static const uint8_t cert[STAGE22_CERTIFICATE_SIZE] = { 0x30U, 0x03U, 0x44U, 0xE0U, 0xE1U, 0xE2U, 0xE3U, 0xE4U,
        0xE5U, 0xE6U, 0xE7U, 0xE8U, 0xE9U, 0xEAU, 0xEBU, 0xECU, 0xEDU, 0xEEU, 0xEFU, 0xF0U, 0xF1U, 0xF2U, 0xF3U, 0xF4U };
    qsc_tls_server_state state;
    qsc_tls_certificate_view chain[1U];
    stage22_mock_certificate_state certstate;
    stage22_mock_authorization_state authstate;
    bool res;

    res = false;
    qsc_memutils_clear(&authstate, sizeof(authstate));
    authstate.authorizeaccept = true;
    stage22_make_certificate_view(&chain[0U], cert, sizeof(cert));
    stage22_initialize_server_state(&state, &certstate, false, true);

    if (qsc_tls_server_config_set_client_authorization(&state.config, stage22_mock_authorize_client, &authstate, true) == qsc_tls_status_success)
    {
        if (qsc_tls_server_authorize_client_certificate(&state, chain, 1U) == qsc_tls_status_authentication_failure)
        {
            if ((state.lastalert == qsc_tls_alert_bad_certificate) && (certstate.validatecalled == true) &&
                (authstate.authorizecalled == false))
            {
                res = true;
            }
        }
    }

    return res;
}

static bool stage22_no_callback_policy_test(void)
{
    static const uint8_t cert[STAGE22_CERTIFICATE_SIZE] = { 0x30U, 0x04U, 0x55U, 0x90U, 0x91U, 0x92U, 0x93U, 0x94U,
        0x95U, 0x96U, 0x97U, 0x98U, 0x99U, 0x9AU, 0x9BU, 0x9CU, 0x9DU, 0x9EU, 0x9FU, 0xA0U, 0xA1U, 0xA2U, 0xA3U, 0xA4U };
    qsc_tls_server_state state;
    qsc_tls_certificate_view chain[1U];
    stage22_mock_certificate_state certstate;
    bool res;

    res = false;
    stage22_make_certificate_view(&chain[0U], cert, sizeof(cert));
    stage22_initialize_server_state(&state, &certstate, true, false);

    if (qsc_tls_server_config_set_client_authorization(&state.config, NULL, NULL, false) == qsc_tls_status_success)
    {
        if (qsc_tls_server_authorize_client_certificate(&state, chain, 1U) == qsc_tls_status_success)
        {
            state.config.requireclientauthorization = true;

            if (qsc_tls_server_authorize_client_certificate(&state, chain, 1U) == qsc_tls_status_authentication_failure)
            {
                if (state.lastalert == qsc_tls_alert_access_denied)
                {
                    res = true;
                }
            }
        }
    }

    return res;
}

static bool stage22_socket_context_client_authorization_test(void)
{
    qsc_tls_socket_context* ctx;
    stage22_mock_authorization_state authstate;
    bool res;

    res = false;
    qsc_memutils_clear(&authstate, sizeof(authstate));
    ctx = (qsc_tls_socket_context*)qsc_memutils_malloc(sizeof(qsc_tls_socket_context));

    if (ctx != NULL)
    {
        qsc_tls_socket_context_initialize(ctx);

        if (qsc_tls_socket_context_set_client_auth(ctx, false, true) == qsc_tls_socket_status_success)
        {
            if ((ctx->requestclientauth == true) && (ctx->requireclientauth == true))
            {
                if (qsc_tls_socket_context_set_client_authorization(ctx, stage22_mock_authorize_client, &authstate, true) == qsc_tls_socket_status_success)
                {
                    if ((ctx->clientauthcallback == stage22_mock_authorize_client) && (ctx->clientauthstate == &authstate) &&
                        (ctx->requireclientauthorization == true))
                    {
                        if (qsc_tls_socket_context_set_client_authorization(ctx, NULL, NULL, true) == qsc_tls_socket_status_invalid_input)
                        {
                            if (qsc_tls_socket_context_set_client_authorization(ctx, NULL, NULL, false) == qsc_tls_socket_status_success)
                            {
                                if ((ctx->clientauthcallback == NULL) && (ctx->clientauthstate == NULL) &&
                                    (ctx->requireclientauthorization == false))
                                {
                                    res = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        qsc_tls_socket_context_dispose(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

bool qsctest_tls_stage22_tests(void)
{
    bool res;

    res = true;

    if (stage22_server_config_client_auth_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 22 mTLS server configuration policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 22 mTLS server configuration policy test.");
        res = false;
    }

    if (stage22_authorization_accept_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 22 mTLS authorization accept callback test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 22 mTLS authorization accept callback test.");
        res = false;
    }

    if (stage22_authorization_reject_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 22 mTLS authorization reject callback test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 22 mTLS authorization reject callback test.");
        res = false;
    }

    if (stage22_validation_failure_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 22 mTLS validation failure test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 22 mTLS validation failure test.");
        res = false;
    }

    if (stage22_no_callback_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 22 mTLS no-callback policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 22 mTLS no-callback policy test.");
        res = false;
    }

    if (stage22_socket_context_client_authorization_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 22 mTLS socket context authorization test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 22 mTLS socket context authorization test.");
        res = false;
    }

    return res;
}
