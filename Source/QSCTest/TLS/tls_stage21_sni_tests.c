#include "tls_stage21_sni_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "tlsextensions.h"
#include "tlsserver.h"
#include "x509host.h"

static bool stage21_string_equals(const char* text, size_t textlen, const char* expected)
{
    size_t explen;
    bool res;

    res = false;

    if ((text != NULL) && (expected != NULL))
    {
        explen = qsc_stringutils_string_size(expected);

        if (textlen == explen)
        {
            res = qsc_memutils_are_equal((const uint8_t*)text, (const uint8_t*)expected, explen);
        }
    }

    return res;
}

static void stage21_make_certificate_view(qsc_tls_certificate_view* view, const uint8_t* data, size_t datalen)
{
    if (view != NULL)
    {
        view->data = data;
        view->datalen = datalen;
    }
}

static bool stage21_make_local_certificate(qsc_tls_server_config* config, const uint8_t* cert, size_t certlen, const uint8_t* key, size_t keylen,
    qsc_tls_signature_scheme scheme)
{
    qsc_tls_certificate_view chain[1U];
    bool res;

    res = false;

    if ((config != NULL) && (cert != NULL) && (key != NULL))
    {
        qsc_memutils_clear(config, sizeof(*config));
        stage21_make_certificate_view(&chain[0U], cert, certlen);

        if (qsc_tls_server_config_set_local_certificate(config, chain, 1U, scheme, key, keylen) == qsc_tls_status_success)
        {
            res = true;
        }
    }

    return res;
}

static bool stage21_sni_extension_codec_roundtrip_test(void)
{
    const char* host;
    uint8_t enc[96U];
    size_t hostlen;
    size_t off;
    size_t extlen;
    bool res;

    host = NULL;
    hostlen = 0U;
    off = 0U;
    res = false;
    qsc_memutils_clear(enc, sizeof(enc));

    if (qsc_tls_extensions_encode_server_name(enc, sizeof(enc), &off, "alpha.example.test") == qsc_tls_status_success)
    {
        if ((off == 27U) && (enc[0U] == 0x00U) && (enc[1U] == 0x00U))
        {
            extlen = ((size_t)enc[2U] << 8U) | (size_t)enc[3U];

            if (extlen == 23U)
            {
                if (qsc_tls_extensions_decode_server_name(enc + 4U, extlen, &host, &hostlen) == qsc_tls_status_success)
                {
                    if (stage21_string_equals(host, hostlen, "alpha.example.test") == true)
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

static bool stage21_sni_extension_negative_decode_test(void)
{
    const char* host;
    const uint8_t emptyname[] = { 0x00U, 0x03U, 0x00U, 0x00U, 0x00U };
    const uint8_t truncated[] = { 0x00U, 0x06U, 0x00U, 0x00U, 0x05U, 'h', 'o' };
    const uint8_t unsupported[] = { 0x00U, 0x06U, 0x01U, 0x00U, 0x03U, 'f', 'o', 'o' };
    uint8_t enc[QSC_TLS_MAX_HOSTNAME_SIZE + 16U];
    char longhost[QSC_TLS_MAX_HOSTNAME_SIZE + 2U];
    size_t hostlen;
    size_t off;
    size_t i;
    bool res;

    host = NULL;
    hostlen = 0U;
    off = 0U;
    res = false;
    qsc_memutils_clear(enc, sizeof(enc));

    for (i = 0U; i < sizeof(longhost); ++i)
    {
        longhost[i] = 'a';
    }

    longhost[QSC_TLS_MAX_HOSTNAME_SIZE + 1U] = '\0';

    if (qsc_tls_extensions_decode_server_name(emptyname, sizeof(emptyname), &host, &hostlen) == qsc_tls_status_invalid_length)
    {
        if (qsc_tls_extensions_decode_server_name(truncated, sizeof(truncated), &host, &hostlen) == qsc_tls_status_invalid_length)
        {
            if (qsc_tls_extensions_decode_server_name(unsupported, sizeof(unsupported), &host, &hostlen) == qsc_tls_status_not_supported)
            {
                if (qsc_tls_extensions_encode_server_name(enc, sizeof(enc), &off, "") == qsc_tls_status_invalid_length)
                {
                    if (qsc_tls_extensions_encode_server_name(enc, sizeof(enc), &off, longhost) == qsc_tls_status_invalid_length)
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

static bool stage21_server_config_sni_identity_policy_test(void)
{
    static const uint8_t certa[16U] = { 0x30U, 0x01U, 0x01U, 0xA1U, 0xA2U, 0xA3U, 0xA4U, 0xA5U, 0xA6U, 0xA7U, 0xA8U, 0xA9U, 0xAAU, 0xABU, 0xACU, 0xADU };
    static const uint8_t certb[16U] = { 0x30U, 0x02U, 0x02U, 0xB1U, 0xB2U, 0xB3U, 0xB4U, 0xB5U, 0xB6U, 0xB7U, 0xB8U, 0xB9U, 0xBAU, 0xBBU, 0xBCU, 0xBDU };
    static const uint8_t keya[32U] = { 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U, 0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU, 0x20U,
        0x21U, 0x22U, 0x23U, 0x24U, 0x25U, 0x26U, 0x27U, 0x28U, 0x29U, 0x2AU, 0x2BU, 0x2CU, 0x2DU, 0x2EU, 0x2FU, 0x30U };
    static const uint8_t keyb[32U] = { 0x31U, 0x32U, 0x33U, 0x34U, 0x35U, 0x36U, 0x37U, 0x38U, 0x39U, 0x3AU, 0x3BU, 0x3CU, 0x3DU, 0x3EU, 0x3FU, 0x40U,
        0x41U, 0x42U, 0x43U, 0x44U, 0x45U, 0x46U, 0x47U, 0x48U, 0x49U, 0x4AU, 0x4BU, 0x4CU, 0x4DU, 0x4EU, 0x4FU, 0x50U };
    qsc_tls_server_config base;
    qsc_tls_server_config alt;
    qsc_tls_server_config empty;
    bool res;

    res = false;
    qsc_memutils_clear(&base, sizeof(base));
    qsc_memutils_clear(&alt, sizeof(alt));
    qsc_memutils_clear(&empty, sizeof(empty));

    if (stage21_make_local_certificate(&base, certa, sizeof(certa), keya, sizeof(keya), qsc_tls_sig_ecdsa_secp256r1_sha256) == true)
    {
        if (stage21_make_local_certificate(&alt, certb, sizeof(certb), keyb, sizeof(keyb), qsc_tls_sig_ecdsa_secp384r1_sha384) == true)
        {
            if (qsc_tls_server_config_add_certificate_identity(&base, "alpha.example.test", &alt.localcert) == qsc_tls_status_success)
            {
                if ((base.identitycount == 1U) && (base.identities[0U].configured == true) &&
                    (stage21_string_equals(base.identities[0U].hostname, qsc_stringutils_string_size(base.identities[0U].hostname), "alpha.example.test") == true) &&
                    (base.identities[0U].localcert.verifyscheme == qsc_tls_sig_ecdsa_secp384r1_sha384) &&
                    (base.identities[0U].localcert.chain[0U].data == certb) &&
                    (base.identities[0U].localcert.signprivatekeylen == sizeof(keyb)))
                {
                    if (qsc_tls_server_config_set_sni_required(&base, true) == qsc_tls_status_success)
                    {
                        if (base.requiresni == true)
                        {
                            if (qsc_tls_server_config_add_certificate_identity(&base, "", &alt.localcert) == qsc_tls_status_invalid_input)
                            {
                                if (qsc_tls_server_config_add_certificate_identity(&base, "beta.example.test", &empty.localcert) == qsc_tls_status_invalid_input)
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

    return res;
}

static bool stage21_server_config_sni_capacity_test(void)
{
    static const uint8_t cert[16U] = { 0x30U, 0x03U, 0x03U, 0xC1U, 0xC2U, 0xC3U, 0xC4U, 0xC5U, 0xC6U, 0xC7U, 0xC8U, 0xC9U, 0xCAU, 0xCBU, 0xCCU, 0xCDU };
    static const uint8_t key[32U] = { 0x51U, 0x52U, 0x53U, 0x54U, 0x55U, 0x56U, 0x57U, 0x58U, 0x59U, 0x5AU, 0x5BU, 0x5CU, 0x5DU, 0x5EU, 0x5FU, 0x60U,
        0x61U, 0x62U, 0x63U, 0x64U, 0x65U, 0x66U, 0x67U, 0x68U, 0x69U, 0x6AU, 0x6BU, 0x6CU, 0x6DU, 0x6EU, 0x6FU, 0x70U };
    const char* hosts[QSC_TLS_MAX_SERVER_IDENTITIES] = { "one.example.test", "two.example.test", "three.example.test", "four.example.test" };
    qsc_tls_server_config config;
    qsc_tls_server_config ident;
    size_t i;
    bool res;

    res = false;
    qsc_memutils_clear(&config, sizeof(config));
    qsc_memutils_clear(&ident, sizeof(ident));

    if (stage21_make_local_certificate(&config, cert, sizeof(cert), key, sizeof(key), qsc_tls_sig_ecdsa_secp256r1_sha256) == true)
    {
        if (stage21_make_local_certificate(&ident, cert, sizeof(cert), key, sizeof(key), qsc_tls_sig_ecdsa_secp256r1_sha256) == true)
        {
            res = true;

            for (i = 0U; i < QSC_TLS_MAX_SERVER_IDENTITIES; ++i)
            {
                if (qsc_tls_server_config_add_certificate_identity(&config, hosts[i], &ident.localcert) != qsc_tls_status_success)
                {
                    res = false;
                    break;
                }
            }

            if (res == true)
            {
                if (config.identitycount == QSC_TLS_MAX_SERVER_IDENTITIES)
                {
                    if (qsc_tls_server_config_add_certificate_identity(&config, "overflow.example.test", &ident.localcert) != qsc_tls_status_invalid_input)
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

static bool stage21_server_config_sni_matching_test(void)
{
    static const uint8_t certa[16U] = { 0x30U, 0x04U, 0x04U, 0xD1U, 0xD2U, 0xD3U, 0xD4U, 0xD5U, 0xD6U, 0xD7U, 0xD8U, 0xD9U, 0xDAU, 0xDBU, 0xDCU, 0xDDU };
    static const uint8_t certb[16U] = { 0x30U, 0x05U, 0x05U, 0xE1U, 0xE2U, 0xE3U, 0xE4U, 0xE5U, 0xE6U, 0xE7U, 0xE8U, 0xE9U, 0xEAU, 0xEBU, 0xECU, 0xEDU };
    static const uint8_t key[32U] = { 0x71U, 0x72U, 0x73U, 0x74U, 0x75U, 0x76U, 0x77U, 0x78U, 0x79U, 0x7AU, 0x7BU, 0x7CU, 0x7DU, 0x7EU, 0x7FU, 0x80U,
        0x81U, 0x82U, 0x83U, 0x84U, 0x85U, 0x86U, 0x87U, 0x88U, 0x89U, 0x8AU, 0x8BU, 0x8CU, 0x8DU, 0x8EU, 0x8FU, 0x90U };
    qsc_tls_server_config config;
    qsc_tls_server_config exact;
    qsc_tls_server_config wildcard;
    size_t selected;
    size_t i;
    bool found;
    bool res;

    selected = 0U;
    found = false;
    res = false;
    qsc_memutils_clear(&config, sizeof(config));
    qsc_memutils_clear(&exact, sizeof(exact));
    qsc_memutils_clear(&wildcard, sizeof(wildcard));

    if (stage21_make_local_certificate(&config, certa, sizeof(certa), key, sizeof(key), qsc_tls_sig_ecdsa_secp256r1_sha256) == true)
    {
        if (stage21_make_local_certificate(&exact, certa, sizeof(certa), key, sizeof(key), qsc_tls_sig_ecdsa_secp256r1_sha256) == true)
        {
            if (stage21_make_local_certificate(&wildcard, certb, sizeof(certb), key, sizeof(key), qsc_tls_sig_ecdsa_secp384r1_sha384) == true)
            {
                if (qsc_tls_server_config_add_certificate_identity(&config, "alpha.example.test", &exact.localcert) == qsc_tls_status_success)
                {
                    if (qsc_tls_server_config_add_certificate_identity(&config, "*.service.example.test", &wildcard.localcert) == qsc_tls_status_success)
                    {
                        for (i = 0U; i < config.identitycount; ++i)
                        {
                            if ((config.identities[i].configured == true) &&
                                (qsc_x509_dns_name_match(config.identities[i].hostname, "api.service.example.test") == true))
                            {
                                selected = i;
                                found = true;
                                break;
                            }
                        }

                        if ((found == true) && (config.identities[selected].localcert.verifyscheme == qsc_tls_sig_ecdsa_secp384r1_sha384))
                        {
                            if (qsc_x509_dns_name_match(config.identities[0U].hostname, "alpha.example.test") == true)
                            {
                                if (qsc_x509_dns_name_match(config.identities[0U].hostname, "beta.example.test") == false)
                                {
                                    if (qsc_x509_dns_name_match(config.identities[1U].hostname, "deep.api.service.example.test") == false)
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

    return res;
}

bool qsctest_tls_stage21_tests(void)
{
    bool res;

    res = true;

    if (stage21_sni_extension_codec_roundtrip_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 21 SNI extension codec roundtrip test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 21 SNI extension codec roundtrip test.");
        res = false;
    }

    if (stage21_sni_extension_negative_decode_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 21 SNI extension negative decode test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 21 SNI extension negative decode test.");
        res = false;
    }

    if (stage21_server_config_sni_identity_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 21 SNI server identity policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 21 SNI server identity policy test.");
        res = false;
    }

    if (stage21_server_config_sni_capacity_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 21 SNI server identity capacity test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 21 SNI server identity capacity test.");
        res = false;
    }

    if (stage21_server_config_sni_matching_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 21 SNI multi-certificate matching test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 21 SNI multi-certificate matching test.");
        res = false;
    }

    return res;
}
