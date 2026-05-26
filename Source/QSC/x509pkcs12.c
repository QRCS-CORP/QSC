#include "x509pkcs12.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "stringutils.h"
#include "sha2.h"

static const uint8_t OID_PKCS7_DATA[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x07U, 0x01U };
static const uint8_t OID_PKCS12_CERT_BAG[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x0CU, 0x0AU, 0x01U, 0x03U };
static const uint8_t OID_PKCS12_KEY_BAG[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x0CU, 0x0AU, 0x01U, 0x01U };
static const uint8_t OID_PKCS12_SHROUDED_KEY_BAG[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x0CU, 0x0AU, 0x01U, 0x02U };
static const uint8_t OID_PKCS9_X509_CERTIFICATE[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x09U, 0x16U, 0x01U };

static bool x509_asn1_is_octet_string(const qsc_encoding_ber_element* element)
{
    return (qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OCTET_STRING) == QSC_ASN1_STATUS_SUCCESS);
}

static bool x509_pkcs12_pbkdf2_hmac256(uint8_t* output, size_t outlen, const uint8_t* password, size_t passwordlen, const uint8_t* salt, size_t saltlen, uint64_t iterations)
{
    qsc_hmac256_state ctx = { 0 };
    uint8_t u[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t t[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t ctr[4U] = { 0U };
    size_t blockindex;
    size_t offset;
    size_t i;
    size_t j;
    bool res;

    res = false;

    if (output != NULL && iterations != 0U && iterations <= 1000000U)
    {
        offset = 0U;

        for (blockindex = 1U; offset < outlen; ++blockindex)
        {
            ctr[0U] = (uint8_t)((blockindex >> 24) & 0xFFU);
            ctr[1U] = (uint8_t)((blockindex >> 16) & 0xFFU);
            ctr[2U] = (uint8_t)((blockindex >> 8) & 0xFFU);
            ctr[3U] = (uint8_t)(blockindex & 0xFFU);

            qsc_hmac256_initialize(&ctx, password, passwordlen);

            if (saltlen != 0U)
            {
                qsc_hmac256_update(&ctx, salt, saltlen);
            }

            qsc_hmac256_update(&ctx, ctr, sizeof(ctr));
            qsc_hmac256_finalize(&ctx, u);
            qsc_memutils_copy(t, u, sizeof(t));

            for (i = 1U; i < (size_t)iterations; ++i)
            {
                qsc_hmac256_compute(u, u, sizeof(u), password, passwordlen);

                for (j = 0U; j < sizeof(t); ++j)
                {
                    t[j] ^= u[j];
                }
            }

            {
                const size_t cp = (outlen - offset < sizeof(t)) ? (outlen - offset) : sizeof(t);
                qsc_memutils_copy(output + offset, t, cp);
                offset += cp;
            }
        }

        qsc_memutils_secure_erase(u, sizeof(u));
        qsc_memutils_secure_erase(t, sizeof(t));
        qsc_hmac256_dispose(&ctx);
        res = true;
    }

    return res;
}

static bool x509_pkcs12_oid_equals(const qsc_asn1_oid* oid, const uint8_t* enc, size_t enclen)
{
    bool res;

    res = (oid != (const qsc_asn1_oid*)NULL && enc != (const uint8_t*)NULL && oid->length == enclen && qsc_memutils_are_equal(oid->data, enc, enclen));

    return res;
}

static bool x509_pkcs12_verify_mac(const qsc_encoding_ber_element* root, const qsc_encoding_ber_element* safes, const char* password)
{
    static const uint8_t OID_SHA256[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x01U };
    qsc_asn1_oid oid = { 0 };
    uint8_t key[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t mac[QSC_SHA2_256_HASH_SIZE] = { 0U };
    const qsc_encoding_ber_element* macdata;
    const qsc_encoding_ber_element* digestinfo;
    const qsc_encoding_ber_element* algseq;
    const qsc_encoding_ber_element* digestel;
    const qsc_encoding_ber_element* saltel;
    uint64_t iterations;
    size_t plen;
    bool res;

    res = false;

    if (root != (const qsc_encoding_ber_element*)NULL && safes != (const qsc_encoding_ber_element*)NULL && password != (const char*)NULL)
    {
        if (qsc_asn1_child_count(root) >= 3U)
        {
            macdata = qsc_asn1_get_child(root, 2U);

            if (qsc_asn1_require_sequence(macdata, 2U, 3U) == QSC_ASN1_STATUS_SUCCESS)
            {
                digestinfo = qsc_asn1_get_child(macdata, 0U);
                saltel = qsc_asn1_get_child(macdata, 1U);
                iterations = 1U;

                if (qsc_asn1_require_sequence(digestinfo, 2U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
                    qsc_asn1_require_sequence(qsc_asn1_get_child(digestinfo, 0U), 1U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
                    x509_asn1_is_octet_string(qsc_asn1_get_child(digestinfo, 1U)) == true &&
                    x509_asn1_is_octet_string(saltel) == true)
                {
                    algseq = qsc_asn1_get_child(digestinfo, 0U);
                    digestel = qsc_asn1_get_child(digestinfo, 1U);

                    if (qsc_asn1_decode_oid(qsc_asn1_get_child(algseq, 0U), &oid) == QSC_ASN1_STATUS_SUCCESS &&
                        x509_pkcs12_oid_equals(&oid, OID_SHA256, sizeof(OID_SHA256)) == true &&
                        digestel->length == QSC_SHA2_256_HASH_SIZE)
                    {
                        if (qsc_asn1_child_count(macdata) == 3U)
                        {
                            if (qsc_asn1_decode_integer_u64(qsc_asn1_get_child(macdata, 2U), &iterations) != QSC_ASN1_STATUS_SUCCESS)
                            {
                                iterations = 0U;
                            }
                        }

                        if (iterations != 0U)
                        {
                            plen = qsc_stringutils_string_size(password);

                            if (x509_pkcs12_pbkdf2_hmac256(key, sizeof(key), (const uint8_t*)password, plen, saltel->value, saltel->length, iterations) == true)
                            {
                                qsc_hmac256_compute(mac, safes->value, safes->length, key, sizeof(key));
                                res = qsc_memutils_are_equal(mac, digestel->value, sizeof(mac));
                            }
                        }
                    }
                }
            }
        }

        qsc_memutils_secure_erase(key, sizeof(key));
        qsc_memutils_secure_erase(mac, sizeof(mac));
    }

    return res;
}

void qsc_x509_pkcs12_initialize(qsc_x509_pkcs12_bundle* bundle)
{
    QSC_ASSERT(bundle != NULL);

    if (bundle != NULL)
    {
        qsc_memutils_clear((uint8_t*)bundle, sizeof(qsc_x509_pkcs12_bundle));
    }
}

static bool x509_pkcs12_add_certificate(qsc_x509_pkcs12_bundle* bundle, const uint8_t* der, size_t derlen)
{
    bool res;

    res = false;

    if (bundle != (qsc_x509_pkcs12_bundle*)NULL && der != (const uint8_t*)NULL && derlen != 0U)
    {
        if (bundle->certificatecount < QSC_X509_PKCS12_MAX_CERTIFICATES)
        {
            if (qsc_x509_certificate_decode_der(der, derlen, &bundle->certificates[bundle->certificatecount]) == QSC_ASN1_STATUS_SUCCESS)
            {
                ++bundle->certificatecount;
                res = true;
            }
        }
    }

    return res;
}

static bool x509_pkcs12_parse_safe_bag(const qsc_encoding_ber_element* bag, const char* password, qsc_x509_pkcs12_bundle* bundle)
{
    qsc_asn1_oid certoid = { 0 };
    qsc_asn1_oid oid = { 0 };
    uint8_t der[QSC_X509_PKCS12_DER_MAX] = { 0U };
    uint8_t pki[QSC_X509_PKCS12_DER_MAX] = { 0U };
    const qsc_encoding_ber_element* valuectx;
    const qsc_encoding_ber_element* value;
    const qsc_encoding_ber_element* certseq;
    const qsc_encoding_ber_element* certtype;
    const qsc_encoding_ber_element* certvalue;
    size_t derlen;
    size_t pkilen;
    bool res;

    res = false;

    if (bag != (const qsc_encoding_ber_element*)NULL && password != (const char*)NULL && bundle != (qsc_x509_pkcs12_bundle*)NULL)
    {
        if (qsc_asn1_require_sequence(bag, 2U, 3U) == QSC_ASN1_STATUS_SUCCESS)
        {
            if (qsc_asn1_decode_oid(qsc_asn1_get_child(bag, 0U), &oid) == QSC_ASN1_STATUS_SUCCESS)
            {
                valuectx = qsc_asn1_get_child(bag, 1U);
                value = (const qsc_encoding_ber_element*)NULL;

                if (qsc_asn1_get_explicit_child(valuectx, &value) == QSC_ASN1_STATUS_SUCCESS)
                {
                    if (x509_pkcs12_oid_equals(&oid, OID_PKCS12_CERT_BAG, sizeof(OID_PKCS12_CERT_BAG)) == true)
                    {
                        if (qsc_asn1_require_sequence(value, 2U, 2U) == QSC_ASN1_STATUS_SUCCESS)
                        {
                            certtype = qsc_asn1_get_child(value, 0U);
                            certvalue = qsc_asn1_get_child(value, 1U);

                            if (qsc_asn1_decode_oid(certtype, &certoid) == QSC_ASN1_STATUS_SUCCESS &&
                                x509_pkcs12_oid_equals(&certoid, OID_PKCS9_X509_CERTIFICATE, sizeof(OID_PKCS9_X509_CERTIFICATE)) == true)
                            {
                                if (qsc_asn1_get_explicit_child(certvalue, &certseq) == QSC_ASN1_STATUS_SUCCESS &&
                                    x509_asn1_is_octet_string(certseq) == true)
                                {
                                    res = x509_pkcs12_add_certificate(bundle, certseq->value, certseq->length);
                                }
                            }
                        }
                    }
                    else if (x509_pkcs12_oid_equals(&oid, OID_PKCS12_KEY_BAG, sizeof(OID_PKCS12_KEY_BAG)) == true)
                    {
                        derlen = qsc_encoding_der_encode_element((qsc_encoding_ber_element*)value, der, sizeof(der));

                        if (derlen != 0U)
                        {
                            if (qsc_x509_private_key_decode_pkcs8_der(der, derlen, &bundle->privatekey) == QSC_ASN1_STATUS_SUCCESS)
                            {
                                bundle->hasprivatekey = true;
                                res = true;
                            }
                        }
                    }
                    else if (x509_pkcs12_oid_equals(&oid, OID_PKCS12_SHROUDED_KEY_BAG, sizeof(OID_PKCS12_SHROUDED_KEY_BAG)) == true)
                    {
                        derlen = qsc_encoding_der_encode_element((qsc_encoding_ber_element*)value, der, sizeof(der));

                        if (derlen != 0U)
                        {
                            pkilen = sizeof(pki);

                            if (qsc_x509_pkcs12_decrypt_encrypted_private_key_info(der, derlen, password, pki, sizeof(pki), &pkilen) == true)
                            {
                                if (qsc_x509_private_key_decode_pkcs8_der(pki, pkilen, &bundle->privatekey) == QSC_ASN1_STATUS_SUCCESS)
                                {
                                    bundle->hasprivatekey = true;
                                    res = true;
                                }
                            }
                        }
                    }
                }
            }
        }

        qsc_memutils_secure_erase(der, sizeof(der));
        qsc_memutils_secure_erase(pki, sizeof(pki));
    }

    return res;
}

static bool x509_pkcs12_parse_safe_contents(const uint8_t* der, size_t derlen, const char* password, qsc_x509_pkcs12_bundle* bundle)
{
    qsc_encoding_ber_element* root;
    size_t consumed;
    bool res;
    size_t i;

    res = false;
    root = (qsc_encoding_ber_element*)NULL;

    if (der != (const uint8_t*)NULL && derlen != 0U && password != (const char*)NULL && bundle != (qsc_x509_pkcs12_bundle*)NULL)
    {
        consumed = 0U;
        root = qsc_encoding_ber_decode_element(der, derlen, &consumed);

        if (root != (qsc_encoding_ber_element*)NULL)
        {
            if (qsc_asn1_require_sequence(root, 0U, SIZE_MAX) == QSC_ASN1_STATUS_SUCCESS)
            {
                for (i = 0U; i < qsc_asn1_child_count(root); ++i)
                {
                    (void)x509_pkcs12_parse_safe_bag(qsc_asn1_get_child(root, i), password, bundle);
                }

                res = true;
            }

            qsc_encoding_ber_free_element(root);
        }
    }

    return res;
}

bool qsc_x509_pkcs12_parse(const uint8_t* data, size_t datalen, const char* password, qsc_x509_pkcs12_bundle* bundle)
{
    QSC_ASSERT(data != NULL);
    QSC_ASSERT(datalen != 0U);
    QSC_ASSERT(bundle != NULL);

    qsc_asn1_oid oid = { 0 };
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* authsafe;
    const qsc_encoding_ber_element* content;
    const qsc_encoding_ber_element* safes;
    uint64_t version;
    size_t consumed;
    const char* pwd;
    bool ok;
    bool res;

    res = false;
    ok = false;
    root = (qsc_encoding_ber_element*)NULL;
    pwd = "";

    if (data != (const uint8_t*)NULL && datalen != 0U && bundle != (qsc_x509_pkcs12_bundle*)NULL)
    {
        if (password != (const char*)NULL)
        {
            pwd = password;
        }

        qsc_x509_pkcs12_initialize(bundle);
        consumed = 0U;
        root = qsc_encoding_ber_decode_element(data, datalen, &consumed);

        if (root != (qsc_encoding_ber_element*)NULL)
        {
            if (qsc_asn1_require_sequence(root, 2U, 3U) == QSC_ASN1_STATUS_SUCCESS &&
                qsc_asn1_decode_integer_u64(qsc_asn1_get_child(root, 0U), &version) == QSC_ASN1_STATUS_SUCCESS &&
                version == 3U)
            {
                authsafe = qsc_asn1_get_child(root, 1U);

                if (qsc_asn1_require_sequence(authsafe, 2U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
                    qsc_asn1_decode_oid(qsc_asn1_get_child(authsafe, 0U), &oid) == QSC_ASN1_STATUS_SUCCESS &&
                    x509_pkcs12_oid_equals(&oid, OID_PKCS7_DATA, sizeof(OID_PKCS7_DATA)) == true)
                {
                    content = qsc_asn1_find_context_child(authsafe, 0U);

                    if (content != (const qsc_encoding_ber_element*)NULL &&
                        qsc_asn1_get_explicit_child(content, &safes) == QSC_ASN1_STATUS_SUCCESS &&
                        x509_asn1_is_octet_string(safes) == true &&
                        x509_pkcs12_verify_mac(root, safes, pwd) == true)
                    {
                        ok = x509_pkcs12_parse_safe_contents(safes->value, safes->length, pwd, bundle);
                    }
                }
            }

            qsc_encoding_ber_free_element(root);
        }

        res = (ok == true && (bundle->certificatecount != 0U || bundle->hasprivatekey == true));
    }

    return res;
}
