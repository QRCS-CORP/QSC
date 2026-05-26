#include "tls_stage20_alpn_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlsextensions.h"
#include "tlssocket.h"

static bool stage20_protocol_equals(const uint8_t* protocol, size_t protocollen, const char* expected)
{
    size_t explen;
    bool res;

    res = false;

    if ((protocol != NULL) && (expected != NULL))
    {
        explen = qsc_stringutils_string_size(expected);

        if (protocollen == explen)
        {
            res = qsc_memutils_are_equal(protocol, (const uint8_t*)expected, explen);
        }
    }

    return res;
}

static void stage20_alpn_add(qsc_tls_alpn_protocols* alpn, size_t index, const char* protocol)
{
    size_t plen;

    if ((alpn != NULL) && (protocol != NULL) && (index < QSC_TLS_MAX_ALPN_PROTOCOLS))
    {
        plen = qsc_stringutils_string_size(protocol);

        if ((plen != 0U) && (plen <= QSC_TLS_MAX_ALPN_SIZE))
        {
            qsc_memutils_copy(alpn->protocols[index], (const uint8_t*)protocol, plen);
            alpn->protocollens[index] = plen;

            if (alpn->protocolcount <= index)
            {
                alpn->protocolcount = index + 1U;
            }

            alpn->configured = true;
        }
    }
}

static bool stage20_socket_context_policy_test(void)
{
    qsc_tls_socket_context* ctx;
    const char* protocols[2U];
    const char* duplicate[2U];
    const char* empty[1U];
    const char* overlong[1U];
    char longproto[QSC_TLS_SOCKET_ALPN_SIZE_MAX + 2U];
    size_t i;
    bool res;

    res = false;
    ctx = (qsc_tls_socket_context*)qsc_memutils_malloc(sizeof(qsc_tls_socket_context));

    if (ctx != NULL)
    {
        qsc_tls_socket_context_initialize(ctx);

        for (i = 0U; i < sizeof(longproto); ++i)
        {
            longproto[i] = 'a';
        }

        longproto[QSC_TLS_SOCKET_ALPN_SIZE_MAX + 1U] = '\0';

        protocols[0U] = "h2";
        protocols[1U] = "http/1.1";
        duplicate[0U] = "h2";
        duplicate[1U] = "h2";
        empty[0U] = "";
        overlong[0U] = longproto;

        if (qsc_tls_socket_context_set_alpn_protocols(ctx, protocols, 2U, true) == qsc_tls_socket_status_success)
        {
            if ((ctx->alpn.configured == true) && (ctx->alpn.required == true) && (ctx->alpn.protocolcount == 2U))
            {
                if ((stage20_protocol_equals(ctx->alpn.protocols[0U], ctx->alpn.protocollens[0U], "h2") == true) &&
                    (stage20_protocol_equals(ctx->alpn.protocols[1U], ctx->alpn.protocollens[1U], "http/1.1") == true))
                {
                    if (qsc_tls_socket_context_clear_alpn_protocols(ctx) == qsc_tls_socket_status_success)
                    {
                        if ((ctx->alpn.configured == false) && (ctx->alpn.required == false) && (ctx->alpn.protocolcount == 0U))
                        {
                            if (qsc_tls_socket_context_set_alpn_protocols(ctx, protocols, 0U, false) == qsc_tls_socket_status_invalid_input)
                            {
                                if (qsc_tls_socket_context_set_alpn_protocols(ctx, duplicate, 2U, false) == qsc_tls_socket_status_invalid_input)
                                {
                                    if (qsc_tls_socket_context_set_alpn_protocols(ctx, empty, 1U, false) == qsc_tls_socket_status_invalid_input)
                                    {
                                        if (qsc_tls_socket_context_set_alpn_protocols(ctx, overlong, 1U, false) == qsc_tls_socket_status_invalid_input)
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

        qsc_tls_socket_context_dispose(ctx);
        qsc_memutils_alloc_free(ctx);
    }

    return res;
}

static bool stage20_extension_codec_roundtrip_test(void)
{
    qsc_tls_alpn_protocols alpn;
    qsc_tls_alpn_protocols decoded;
    uint8_t enc[64U];
    size_t off;
    size_t extlen;
    bool res;

    res = false;
    off = 0U;
    qsc_memutils_clear(&alpn, sizeof(alpn));
    qsc_memutils_clear(&decoded, sizeof(decoded));
    qsc_memutils_clear(enc, sizeof(enc));

    stage20_alpn_add(&alpn, 0U, "h2");
    stage20_alpn_add(&alpn, 1U, "http/1.1");
    alpn.required = true;

    if (qsc_tls_extensions_encode_alpn(enc, sizeof(enc), &off, &alpn) == qsc_tls_status_success)
    {
        if ((off == 18U) && (enc[0U] == 0x00U) && (enc[1U] == 0x10U))
        {
            extlen = ((size_t)enc[2U] << 8U) | (size_t)enc[3U];

            if (extlen == 14U)
            {
                if (qsc_tls_extensions_decode_alpn(enc + 4U, extlen, &decoded) == qsc_tls_status_success)
                {
                    if ((decoded.configured == true) && (decoded.protocolcount == 2U))
                    {
                        if ((stage20_protocol_equals(decoded.protocols[0U], decoded.protocollens[0U], "h2") == true) &&
                            (stage20_protocol_equals(decoded.protocols[1U], decoded.protocollens[1U], "http/1.1") == true))
                        {
                            res = true;
                        }
                    }
                }
            }
        }
    }

    return res;
}

static bool stage20_extension_negative_decode_test(void)
{
    qsc_tls_alpn_protocols decoded;
    const uint8_t emptyproto[] = { 0x00U, 0x01U, 0x00U };
    const uint8_t duplicate[] = { 0x00U, 0x06U, 0x02U, 'h', '2', 0x02U, 'h', '2' };
    const uint8_t truncated[] = { 0x00U, 0x03U, 0x02U, 'h' };
    uint8_t enc[16U];
    size_t off;
    bool res;

    res = false;
    off = 0U;
    qsc_memutils_clear(&decoded, sizeof(decoded));
    qsc_memutils_clear(enc, sizeof(enc));

    if (qsc_tls_extensions_decode_alpn(emptyproto, sizeof(emptyproto), &decoded) == qsc_tls_status_invalid_length)
    {
        if (qsc_tls_extensions_decode_alpn(duplicate, sizeof(duplicate), &decoded) == qsc_tls_status_invalid_message)
        {
            if (qsc_tls_extensions_decode_alpn(truncated, sizeof(truncated), &decoded) == qsc_tls_status_invalid_length)
            {
                if (qsc_tls_extensions_encode_alpn(enc, sizeof(enc), &off, &decoded) == qsc_tls_status_invalid_input)
                {
                    res = true;
                }
            }
        }
    }

    return res;
}

static bool stage20_extension_selection_test(void)
{
    qsc_tls_alpn_protocols client;
    qsc_tls_alpn_protocols server;
    qsc_tls_alpn_protocols nomatch;
    uint8_t selected[QSC_TLS_MAX_ALPN_SIZE];
    size_t selectedlen;
    bool res;

    res = false;
    selectedlen = 0U;
    qsc_memutils_clear(&client, sizeof(client));
    qsc_memutils_clear(&server, sizeof(server));
    qsc_memutils_clear(&nomatch, sizeof(nomatch));
    qsc_memutils_clear(selected, sizeof(selected));

    stage20_alpn_add(&client, 0U, "h2");
    stage20_alpn_add(&client, 1U, "http/1.1");
    stage20_alpn_add(&client, 2U, "qsc-test/1");
    stage20_alpn_add(&server, 0U, "qsc-test/1");
    stage20_alpn_add(&server, 1U, "http/1.1");
    stage20_alpn_add(&nomatch, 0U, "mqtt");

    if (qsc_tls_extensions_select_alpn(&client, &server, selected, sizeof(selected), &selectedlen) == qsc_tls_status_success)
    {
        if (stage20_protocol_equals(selected, selectedlen, "qsc-test/1") == true)
        {
            if (qsc_tls_extensions_select_alpn(&client, &nomatch, selected, sizeof(selected), &selectedlen) == qsc_tls_status_not_supported)
            {
                if (selectedlen == 0U)
                {
                    if (qsc_tls_extensions_select_alpn(&client, &server, selected, 2U, &selectedlen) == qsc_tls_status_invalid_length)
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

static bool stage20_socket_peer_selected_alpn_test(void)
{
    qsc_tls_socket_connection* conn;
    char protocol[QSC_TLS_SOCKET_ALPN_SIZE_MAX + 1U];
    size_t protocollen;
    bool res;

    res = false;
    protocollen = 0U;
    conn = (qsc_tls_socket_connection*)qsc_memutils_malloc(sizeof(qsc_tls_socket_connection));

    if (conn != NULL)
    {
        qsc_memutils_clear(protocol, sizeof(protocol));
        qsc_tls_socket_connection_initialize(conn);

        if (qsc_tls_socket_get_selected_alpn(conn, protocol, sizeof(protocol), &protocollen) == qsc_tls_socket_status_not_initialized)
        {
            if ((protocol[0U] == '\0') && (protocollen == 0U))
            {
                conn->peerinfo.alpn_selected = true;
                qsc_memutils_copy(conn->peerinfo.selected_alpn, "http/1.1", 9U);

                if (qsc_tls_socket_get_selected_alpn(conn, protocol, sizeof(protocol), &protocollen) == qsc_tls_socket_status_success)
                {
                    if ((protocollen == 8U) && (qsc_memutils_are_equal((const uint8_t*)protocol, (const uint8_t*)"http/1.1", 8U) == true) && (protocol[8U] == '\0'))
                    {
                        if (qsc_tls_socket_get_selected_alpn(conn, protocol, 4U, &protocollen) == qsc_tls_socket_status_invalid_input)
                        {
                            res = true;
                        }
                    }
                }
            }
        }

        qsc_tls_socket_connection_dispose(conn);
        qsc_memutils_alloc_free(conn);
    }

    return res;
}

bool qsctest_tls_stage20_tests(void)
{
    bool res;

    res = true;

    if (stage20_socket_context_policy_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 20 ALPN socket context policy test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 20 ALPN socket context policy test.");
        res = false;
    }

    if (stage20_extension_codec_roundtrip_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 20 ALPN extension codec roundtrip test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 20 ALPN extension codec roundtrip test.");
        res = false;
    }

    if (stage20_extension_negative_decode_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 20 ALPN extension negative decode test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 20 ALPN extension negative decode test.");
        res = false;
    }

    if (stage20_extension_selection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 20 ALPN extension selection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 20 ALPN extension selection test.");
        res = false;
    }

    if (stage20_socket_peer_selected_alpn_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 20 ALPN selected protocol accessor test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 20 ALPN selected protocol accessor test.");
        res = false;
    }

    return res;
}
