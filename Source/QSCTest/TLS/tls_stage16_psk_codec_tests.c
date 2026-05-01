#include "tls_stage16_psk_codec_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "tlsextensions.h"

static bool qsctest_tls_stage16_psk_codec_test(void)
{
    qsc_tls_psk_identity_view ids[2U];
    qsc_tls_psk_identity_view out_ids[4U];
    uint8_t id1[] = "ticket-id-one-very-long-bytes-32";
    uint8_t id2[] = "second-id";
    size_t out_binderlens[4U];
    const uint8_t* out_binders[4U];
    uint8_t buf[512U] = { 0U };
    uint8_t srv[16U] = { 0U };
    size_t binder_off;
    size_t off;
    size_t out_count;
    size_t out_binder_block_off;
    size_t srvoff;
    qsc_tls_status st;
    size_t i;
    uint16_t etype;
    uint16_t ebodylen;
    uint16_t selected;
    bool res;

    off = 0U;
    binder_off = 0U;
    out_count = 0U;
    out_binder_block_off = 0U;
    srvoff = 0U;
    selected = 0xFFFFU;
    res = true;

    ids[0U].identity = id1;
    ids[0U].identitylen = sizeof(id1) - 1U;
    ids[0U].obfuscatedticketage = 0x12345678U;
    ids[1U].identity = id2;
    ids[1U].identitylen = sizeof(id2) - 1U;
    ids[1U].obfuscatedticketage = 0xDEADBEEFU;

    st = qsc_tls_extensions_encode_pre_shared_key_offer(buf, sizeof(buf), &off, ids, 2U, 32U, &binder_off);

    if ((st != qsc_tls_status_success) || (off == 0U) || (binder_off == 0U) || (binder_off >= off))
    {
        res = false;
    }
    else
    {
        for (i = 0U; i < 32U; ++i)
        {
            buf[binder_off + i] = 0xAAU;
        }

        for (i = 0U; i < 32U; ++i)
        {
            buf[binder_off + 1U + 32U + i] = 0xBBU;
        }

        etype = ((uint16_t)buf[0] << 8) | buf[1];
        ebodylen = ((uint16_t)buf[2] << 8) | buf[3];

        if ((etype != qsc_tls_extension_pre_shared_key) || ((4U + ebodylen) != off))
        {
            res = false;
        }
        else
        {
            st = qsc_tls_extensions_decode_pre_shared_key_offer(buf + 4U, ebodylen, out_ids, out_binders, out_binderlens, 4U, &out_count, &out_binder_block_off);

            if ((st != qsc_tls_status_success) ||
                (out_count != 2U) ||
                (out_ids[0U].identitylen != ids[0U].identitylen) ||
                (qsc_memutils_are_equal(out_ids[0U].identity, ids[0U].identity, ids[0U].identitylen) != true) ||
                (out_ids[0U].obfuscatedticketage != 0x12345678U) ||
                (out_ids[1U].obfuscatedticketage != 0xDEADBEEFU) ||
                (out_binderlens[0U] != 32U) ||
                (out_binders[0U][0U] != 0xAAU) ||
                (out_binderlens[1U] != 32U) ||
                (out_binders[1U][0U] != 0xBBU))
            {
                res = false;
            }
        }
    }

    if (res == true)
    {
        st = qsc_tls_extensions_encode_pre_shared_key_server(srv, sizeof(srv), &srvoff, 0x0001U);

        if ((st != qsc_tls_status_success) || (srvoff != 6U))
        {
            res = false;
        }
        else
        {
            st = qsc_tls_extensions_decode_pre_shared_key_server(srv + 4U, 2U, &selected);

            if ((st != qsc_tls_status_success) || (selected != 0x0001U))
            {
                res = false;
            }
        }
    }

    return res;
}

bool qsctest_tls_stage16_tests(void)
{
    bool res;

    res = qsctest_tls_stage16_psk_codec_test();

    if (res == true)
    {
        qsctest_print_line("[PASS] TLS Stage 16 pre-shared-key codec test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 16 pre-shared-key codec test.");
    }

    return res;
}
