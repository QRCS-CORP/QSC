/* Trust-store integration gate. */
#include "tls_stage15_truststore_tests.h"
#include "../testutils.h"
#include "csp.h"
#include "asn1.h"
#include "eddsa.h"
#include "memutils.h"
#include "oid.h"
#include "timestamp.h"
#include "tlscertx509.h"
#include "tlslimits.h"
#include "tlscert.h"
#include "x509cert.h"
#include "x509certwrite.h"
#include "x509store.h"
#include "x509verify.h"
#include "x509types.h"
#include "x509name.h"
#include "x509ext.h"
#include "x509time.h"
#include "x509spki.h"
#include "x509sigver.h"

static uint8_t g_pk[32U];
static uint8_t g_sk[64U];

static qsc_asn1_status sign_cb(qsc_x509_signature_algorithm signaturealgorithm, const uint8_t* tbs, size_t tbslen, uint8_t* signature, size_t* signaturelen, void* context)
{
    uint8_t scratch[2048U] = { 0U };
    size_t scratchlen;
    qsc_asn1_status res;

    (void)context;
    scratchlen = sizeof(scratch);
    res = QSC_ASN1_STATUS_SUCCESS;

    if (signaturealgorithm != QSC_X509_SIGNATURE_ALGORITHM_ED25519)
    {
        res = QSC_ASN1_STATUS_UNSUPPORTED;
    }
    else if ((signature == NULL) || (signaturelen == NULL) || (*signaturelen < 64U))
    {
        res = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }
    else if ((tbslen + 64U) > sizeof(scratch))
    {
        res = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        qsc_eddsa_sign(scratch, &scratchlen, tbs, tbslen, g_sk);
        qsc_memutils_copy(signature, scratch, 64U);
        *signaturelen = 64U;
    }

    return res;
}

static void epoch_to_x509_time(qsc_x509_time* out, uint64_t epoch)
{
    uint64_t days;
    uint64_t sod;
    int64_t z;
    int64_t era;
    uint64_t doe;
    uint64_t yoe;
    int64_t y;
    uint64_t doy;
    uint64_t mp;
    uint32_t d;
    uint32_t m;

    days = epoch / 86400ULL;
    sod = epoch % 86400ULL;
    z = (int64_t)days + 719468;
    era = (z >= 0) ? (z / 146097) : ((z - 146096) / 146097);
    doe = (uint64_t)(z - (era * 146097));
    yoe = (doe - (doe / 1460U) + (doe / 36524U) - (doe / 146096U)) / 365U;
    y = (int64_t)yoe + (era * 400);
    doy = doe - ((365U * yoe) + (yoe / 4U) - (yoe / 100U));
    mp = ((5U * doy) + 2U) / 153U;
    d = (uint32_t)(doy - (((153U * mp) + 2U) / 5U) + 1U);
    m = (uint32_t)((mp < 10U) ? (mp + 3U) : (mp - 9U));

    if (m <= 2U)
    {
        ++y;
    }

    qsc_memutils_clear(out, sizeof(*out));
    out->year = (uint16_t)y;
    out->month = (uint8_t)m;
    out->day = (uint8_t)d;
    out->hour = (uint8_t)(sod / 3600ULL);
    out->minute = (uint8_t)((sod % 3600ULL) / 60ULL);
    out->second = (uint8_t)(sod % 60ULL);
    out->generalized = ((out->year >= 2050U) || (out->year < 1950U));
}

static void name_set_cn(qsc_x509_name* name, const char* cn)
{
    size_t len;

    len = strlen(cn);

    if (len > QSC_X509_NAME_ATTRIBUTE_STRING_MAX)
    {
        len = QSC_X509_NAME_ATTRIBUTE_STRING_MAX;
    }

    qsc_memutils_clear(name, sizeof(*name));
    name->count = 1U;
    name->attributes[0].type = QSC_X509_NAME_ATTRIBUTE_COMMON_NAME;
    name->attributes[0].oid = QSC_OID_ID_COMMON_NAME;
    qsc_oid_to_asn1(QSC_OID_ID_COMMON_NAME, &name->attributes[0].attribute_oid);
    name->attributes[0].string_tag = 0x0CU;
    name->attributes[0].rdn_index = 0U;
    qsc_memutils_copy(name->attributes[0].value, cn, len);
    name->attributes[0].length = len;
}

static size_t build_cert(uint8_t* out, size_t outcap, const char* cn)
{
    static const uint8_t serial[] = { 0x01U };
    qsc_x509_certificate_builder b;
    qsc_x509_name issuer;
    qsc_x509_name subject;
    qsc_x509_validity vd;
    qsc_x509_subject_public_key_info spki;
    qsc_x509_algorithm_identifier sigalg;
    uint64_t now;
    size_t outlen;
    qsc_asn1_status status;
    size_t res;

    res = 0U;
    outlen = outcap;

    qsc_x509_certificate_builder_initialize(&b);
    qsc_x509_certificate_builder_set_serial(&b, serial, sizeof(serial));

    name_set_cn(&issuer, cn);
    name_set_cn(&subject, cn);
    qsc_x509_certificate_builder_set_issuer(&b, &issuer);
    qsc_x509_certificate_builder_set_subject(&b, &subject);

    qsc_memutils_clear(&vd, sizeof(vd));
    now = qsc_timestamp_epochtime_seconds();
    epoch_to_x509_time(&vd.notbefore, now - 60U);
    epoch_to_x509_time(&vd.notafter, now + 31536000U);
    qsc_x509_certificate_builder_set_validity(&b, &vd);

    qsc_memutils_clear(&spki, sizeof(spki));
    spki.algorithm.oid = QSC_OID_ID_ED25519;
    spki.algorithm.publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519;
    spki.algorithm.signature = QSC_X509_SIGNATURE_ALGORITHM_ED25519;
    qsc_oid_to_asn1(QSC_OID_ID_ED25519, &spki.algorithm.algorithm_oid);
    spki.algorithm.parameters_present = false;
    spki.algorithm.parameters_null = false;
    qsc_memutils_copy(spki.publickey, g_pk, 32U);
    spki.publickeylen = 32U;
    spki.unusedbits = 0U;
    status = qsc_x509_certificate_builder_set_spki(&b, &spki);

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        qsc_memutils_clear(&sigalg, sizeof(sigalg));
        sigalg.oid = QSC_OID_ID_ED25519;
        sigalg.publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519;
        sigalg.signature = QSC_X509_SIGNATURE_ALGORITHM_ED25519;
        qsc_oid_to_asn1(QSC_OID_ID_ED25519, &sigalg.algorithm_oid);
        sigalg.parameters_present = false;
        sigalg.parameters_null = false;
        status = qsc_x509_certificate_builder_set_signature_algorithm(&b, &sigalg);
    }

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        qsc_x509_certificate_builder_add_subject_alt_name_dns(&b, cn, strlen(cn));
        status = qsc_x509_certificate_builder_apply_profile(&b, QSC_X509_CERT_PROFILE_TLS_SERVER);
    }

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        status = qsc_x509_certificate_builder_apply_generated_identifiers(&b, NULL);
    }

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        status = qsc_x509_certificate_builder_sign(&b, sign_cb, NULL, out, &outlen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            res = outlen;
        }
    }

    qsc_x509_certificate_builder_clear(&b);

    return res;
}

static bool qsctest_tls_stage15_no_store_override_rejected(const qsc_tls_certificate_view* chain, const qsc_tls_certificate_validation_context* ctx)
{
    qsc_tls_cert_x509_state s;
    qsc_tls_certificate_interface iface;
    bool ok;
    bool res;

    qsc_tls_cert_x509_state_initialize(&s, NULL);
    s.allowselfsigned = true;
    s.enforcehostname = true;
    s.enforcevalidityperiod = true;
    qsc_tls_cert_x509_bind(&iface, &s);
    ok = iface.validatechain(chain, 1U, ctx, iface.state);

    res = ((ok == false) &&
        (s.lastverifystatus == QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND) &&
        (s.lastalert == qsc_tls_alert_unknown_ca));

    return res;
}

static bool qsctest_tls_stage15_strict_no_store(const qsc_tls_certificate_view* chain, const qsc_tls_certificate_validation_context* ctx)
{
    qsc_tls_cert_x509_state s;
    qsc_tls_certificate_interface iface;
    bool ok;
    bool res;

    qsc_tls_cert_x509_state_initialize(&s, NULL);
    s.allowselfsigned = false;
    s.enforcehostname = true;
    s.enforcevalidityperiod = true;
    qsc_tls_cert_x509_bind(&iface, &s);
    ok = iface.validatechain(chain, 1U, ctx, iface.state);

    res = ((ok == false) &&
        (s.lastverifystatus == QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND) &&
        (s.lastalert == qsc_tls_alert_unknown_ca));

    return res;
}

static bool qsctest_tls_stage15_empty_store(const qsc_tls_certificate_view* chain, const qsc_tls_certificate_validation_context* ctx)
{
    qsc_x509_trust_anchor* anchors;
    qsc_x509_store store;
    qsc_tls_cert_x509_state s;
    qsc_tls_certificate_interface iface;
    bool ok;
    bool res;

    anchors = (qsc_x509_trust_anchor*)qsc_memutils_malloc(sizeof(qsc_x509_trust_anchor) * 4U);
    res = false;

    if (anchors != NULL)
    {
        qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * 4U);
        qsc_x509_store_initialize(&store, anchors, 4U);
        qsc_tls_cert_x509_state_initialize(&s, &store);
        s.enforcehostname = true;
        s.enforcevalidityperiod = true;
        qsc_tls_cert_x509_bind(&iface, &s);
        ok = iface.validatechain(chain, 1U, ctx, iface.state);
        res = ((ok == false) && (s.lastverifystatus != QSC_X509_VERIFY_STATUS_SUCCESS));
        qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * 4U);
        qsc_memutils_alloc_free(anchors);
    }

    return res;
}

static bool qsctest_tls_stage15_anchored(const qsc_tls_certificate_view* chain, const qsc_tls_certificate_validation_context* ctx, const uint8_t* der, size_t derlen)
{
    qsc_x509_certificate anchor;
    qsc_x509_trust_anchor* anchors;
    qsc_x509_store store;
    qsc_tls_cert_x509_state s;
    qsc_tls_certificate_interface iface;
    qsc_asn1_status status;
    bool ok;
    bool res;

    anchors = (qsc_x509_trust_anchor*)qsc_memutils_malloc(sizeof(qsc_x509_trust_anchor) * 4U);
    ok = false;
    res = (anchors != NULL);
    qsc_memutils_clear(&anchor, sizeof(anchor));

    if (res == true)
    {
        qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * 4U);
        status = qsc_x509_certificate_decode_der(der, derlen, &anchor);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            res = false;
        }
    }

    if (res == true)
    {
        qsc_x509_store_initialize(&store, anchors, 4U);
        status = qsc_x509_store_add_anchor(&store, &anchor, true);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            res = false;
        }
    }

    if (res == true)
    {
        qsc_tls_cert_x509_state_initialize(&s, &store);
        s.enforcehostname = true;
        s.enforcevalidityperiod = true;
        qsc_tls_cert_x509_bind(&iface, &s);
        ok = iface.validatechain(chain, 1U, ctx, iface.state);
        res = ((ok == true) && (s.lastverifystatus == QSC_X509_VERIFY_STATUS_SUCCESS));
    }

    qsc_x509_certificate_clear(&anchor);

    if (anchors != NULL)
    {
        qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * 4U);
        qsc_memutils_alloc_free(anchors);
    }

    return res;
}

static bool qsctest_tls_stage15_truststore_test(void)
{
    static uint8_t derbuf[4096U] = { 0U };
    size_t derlen;
    qsc_tls_certificate_view chain[1U];
    qsc_tls_certificate_validation_context ctx;
    bool res;

    res = true;

    qsc_eddsa_generate_keypair(g_pk, g_sk, qsc_csp_generate);

    derlen = build_cert(derbuf, sizeof(derbuf), "example.com");

    if (derlen == 0U)
    {
        res = false;
    }
    else
    {
        chain[0U].data = derbuf;
        chain[0U].datalen = derlen;

        ctx.hostname = "example.com";
        ctx.clientauth = false;
        ctx.requirepeercertificate = true;

        if (qsctest_tls_stage15_no_store_override_rejected(chain, &ctx) == false)
        {
            res = false;
        }

        if (qsctest_tls_stage15_strict_no_store(chain, &ctx) == false)
        {
            res = false;
        }

        if (qsctest_tls_stage15_empty_store(chain, &ctx) == false)
        {
            res = false;
        }

        if (qsctest_tls_stage15_anchored(chain, &ctx, derbuf, derlen) == false)
        {
            res = false;
        }
    }

    return res;
}

bool qsctest_tls_stage15_tests(void)
{
    bool res;

    res = qsctest_tls_stage15_truststore_test();

    if (res == true)
    {
        qsctest_print_line("[PASS] TLS Stage 15 trust-store integration test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 15 trust-store integration test.");
    }

    return res;
}
