#include "x509pkcs12.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "stringutils.h"
#include "sha2.h"
#include "pbmac1.h"

static const uint8_t OID_PKCS7_DATA[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x07U, 0x01U };
static const uint8_t OID_PKCS12_CERT_BAG[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x0CU, 0x0AU, 0x01U, 0x03U };
static const uint8_t OID_PKCS12_KEY_BAG[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x0CU, 0x0AU, 0x01U, 0x01U };
static const uint8_t OID_PKCS12_SHROUDED_KEY_BAG[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x0CU, 0x0AU, 0x01U, 0x02U };
static const uint8_t OID_PKCS9_X509_CERTIFICATE[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x09U, 0x16U, 0x01U };

static const uint8_t OID_SHA256[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x01U };
static const uint8_t OID_SHA384[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x02U };
static const uint8_t OID_SHA512[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x03U };
static const uint8_t OID_PBKDF2[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x05U, 0x0CU };
static const uint8_t OID_PBMAC1[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x05U, 0x0EU };
static const uint8_t OID_HMAC_SHA256[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x02U, 0x09U };
static const uint8_t OID_HMAC_SHA384[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x02U, 0x0AU };
static const uint8_t OID_HMAC_SHA512[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x02U, 0x0BU };

#define X509_PKCS12_KDF_ID_MAC 3U
#define X509_PKCS12_MAC_ITERATION_MAX 10000000ULL
#define X509_PKCS12_PASSWORD_BMP_MAX 512U
#define X509_PKCS12_KDF_SCRATCH_MAX 8192U

typedef enum
{
    x509_pkcs12_hash_none = 0x00U,
    x509_pkcs12_hash_sha256 = 0x01U,
    x509_pkcs12_hash_sha384 = 0x02U,
    x509_pkcs12_hash_sha512 = 0x03U
} x509_pkcs12_hash_type;

static bool x509_asn1_is_octet_string(const qsc_encoding_ber_element* element)
{
    return (qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OCTET_STRING) == QSC_ASN1_STATUS_SUCCESS);
}

static bool x509_asn1_is_integer(const qsc_encoding_ber_element* element)
{
    return (qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_INTEGER) == QSC_ASN1_STATUS_SUCCESS);
}

static bool x509_pkcs12_oid_equals(const qsc_asn1_oid* oid, const uint8_t* enc, size_t enclen)
{
    bool res;

    res = (oid != (const qsc_asn1_oid*)NULL && enc != (const uint8_t*)NULL && oid->length == enclen && qsc_memutils_are_equal(oid->data, enc, enclen));

    return res;
}

static size_t x509_pkcs12_hash_size(x509_pkcs12_hash_type hash)
{
    size_t res;

    res = 0U;

    switch (hash)
    {
        case x509_pkcs12_hash_sha256:
        {
            res = QSC_SHA2_256_HASH_SIZE;
            break;
        }
        case x509_pkcs12_hash_sha384:
        {
            res = QSC_SHA2_384_HASH_SIZE;
            break;
        }
        case x509_pkcs12_hash_sha512:
        {
            res = QSC_SHA2_512_HASH_SIZE;
            break;
        }
        default:
        {
            break;
        }
    }

    return res;
}

static size_t x509_pkcs12_hash_block_size(x509_pkcs12_hash_type hash)
{
    size_t res;

    res = 0U;

    switch (hash)
    {
        case x509_pkcs12_hash_sha256:
        {
            res = QSC_SHA2_256_RATE;
            break;
        }
        case x509_pkcs12_hash_sha384:
        case x509_pkcs12_hash_sha512:
        {
            res = QSC_SHA2_512_RATE;
            break;
        }
        default:
        {
            break;
        }
    }

    return res;
}

static qsc_pbmac1_hash_type x509_pkcs12_to_pbmac1_hash(x509_pkcs12_hash_type hash)
{
    qsc_pbmac1_hash_type res;

    res = qsc_pbmac1_hash_none;

    switch (hash)
    {
        case x509_pkcs12_hash_sha256:
        {
            res = qsc_pbmac1_hash_sha256;
            break;
        }
        case x509_pkcs12_hash_sha384:
        {
            res = qsc_pbmac1_hash_sha384;
            break;
        }
        case x509_pkcs12_hash_sha512:
        {
            res = qsc_pbmac1_hash_sha512;
            break;
        }
        default:
        {
            break;
        }
    }

    return res;
}

static x509_pkcs12_hash_type x509_pkcs12_hash_from_digest_oid(const qsc_asn1_oid* oid)
{
    x509_pkcs12_hash_type res;

    res = x509_pkcs12_hash_none;

    if (x509_pkcs12_oid_equals(oid, OID_SHA256, sizeof(OID_SHA256)) == true)
    {
        res = x509_pkcs12_hash_sha256;
    }
    else if (x509_pkcs12_oid_equals(oid, OID_SHA384, sizeof(OID_SHA384)) == true)
    {
        res = x509_pkcs12_hash_sha384;
    }
    else if (x509_pkcs12_oid_equals(oid, OID_SHA512, sizeof(OID_SHA512)) == true)
    {
        res = x509_pkcs12_hash_sha512;
    }

    return res;
}

static x509_pkcs12_hash_type x509_pkcs12_hash_from_hmac_oid(const qsc_asn1_oid* oid)
{
    x509_pkcs12_hash_type res;

    res = x509_pkcs12_hash_none;

    if (x509_pkcs12_oid_equals(oid, OID_HMAC_SHA256, sizeof(OID_HMAC_SHA256)) == true)
    {
        res = x509_pkcs12_hash_sha256;
    }
    else if (x509_pkcs12_oid_equals(oid, OID_HMAC_SHA384, sizeof(OID_HMAC_SHA384)) == true)
    {
        res = x509_pkcs12_hash_sha384;
    }
    else if (x509_pkcs12_oid_equals(oid, OID_HMAC_SHA512, sizeof(OID_HMAC_SHA512)) == true)
    {
        res = x509_pkcs12_hash_sha512;
    }

    return res;
}

static void x509_pkcs12_hash_compute(x509_pkcs12_hash_type hash, uint8_t* output, const uint8_t* message, size_t msglen)
{
    switch (hash)
    {
        case x509_pkcs12_hash_sha256:
        {
            qsc_sha256_compute(output, message, msglen);
            break;
        }
        case x509_pkcs12_hash_sha384:
        {
            qsc_sha384_compute(output, message, msglen);
            break;
        }
        case x509_pkcs12_hash_sha512:
        {
            qsc_sha512_compute(output, message, msglen);
            break;
        }
        default:
        {
            break;
        }
    }
}

static void x509_pkcs12_hmac_compute(x509_pkcs12_hash_type hash, uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen)
{
    switch (hash)
    {
        case x509_pkcs12_hash_sha256:
        {
            qsc_hmac256_compute(output, message, msglen, key, keylen);
            break;
        }
        case x509_pkcs12_hash_sha384:
        {
            qsc_hmac384_compute(output, message, msglen, key, keylen);
            break;
        }
        case x509_pkcs12_hash_sha512:
        {
            qsc_hmac512_compute(output, message, msglen, key, keylen);
            break;
        }
        default:
        {
            break;
        }
    }
}

static bool x509_pkcs12_password_to_bmp(uint8_t* output, size_t outcap, size_t* outlen, const char* password)
{
    size_t plen;
    size_t i;
    bool res;

    res = false;

    if (output != (uint8_t*)NULL && outlen != (size_t*)NULL && password != (const char*)NULL)
    {
        plen = qsc_stringutils_string_size(password);

        if (((plen + 1U) * 2U) <= outcap)
        {
            for (i = 0U; i < plen; ++i)
            {
                output[i * 2U] = 0U;
                output[(i * 2U) + 1U] = (uint8_t)password[i];
            }

            output[plen * 2U] = 0U;
            output[(plen * 2U) + 1U] = 0U;
            *outlen = (plen + 1U) * 2U;
            res = true;
        }
    }

    return res;
}

static void x509_pkcs12_repeat_bytes(uint8_t* output, size_t outlen, const uint8_t* input, size_t inlen)
{
    size_t i;

    if (output != (uint8_t*)NULL && outlen != 0U)
    {
        for (i = 0U; i < outlen; ++i)
        {
            output[i] = input[i % inlen];
        }
    }
}

static void x509_pkcs12_adjust_block(uint8_t* block, size_t blocklen, const uint8_t* b)
{
    uint16_t carry;
    size_t pos;

    carry = 1U;
    pos = blocklen;

    while (pos != 0U)
    {
        --pos;
        carry = (uint16_t)block[pos] + (uint16_t)b[pos] + carry;
        block[pos] = (uint8_t)carry;
        carry >>= 8U;
    }
}

static bool x509_pkcs12_kdf_rfc7292(uint8_t* output, size_t outlen, const char* password, const uint8_t* salt, size_t saltlen, uint64_t iterations, uint8_t diversifier, x509_pkcs12_hash_type hash)
{
    uint8_t a[QSC_SHA2_512_HASH_SIZE] = { 0U };
    uint8_t b[QSC_SHA2_512_RATE] = { 0U };
    uint8_t d[QSC_SHA2_512_RATE] = { 0U };
    uint8_t pbuf[X509_PKCS12_PASSWORD_BMP_MAX] = { 0U };
    uint8_t* ibuf;
    uint8_t* msg;
    size_t plen;
    size_t slen;
    size_t ilen;
    size_t mlen;
    size_t hlen;
    size_t vlen;
    size_t offset;
    size_t cp;
    size_t i;
    size_t j;
    bool res;

    res = false;
    ilen = 0U;
    mlen = 0U;
    ibuf = (uint8_t*)NULL;
    msg = (uint8_t*)NULL;

    if (output != (uint8_t*)NULL && outlen != 0U && password != (const char*)NULL && iterations != 0U && iterations <= X509_PKCS12_MAC_ITERATION_MAX)
    {
        hlen = x509_pkcs12_hash_size(hash);
        vlen = x509_pkcs12_hash_block_size(hash);

        if (hlen != 0U && vlen != 0U && x509_pkcs12_password_to_bmp(pbuf, sizeof(pbuf), &plen, password) == true)
        {
            slen = (saltlen == 0U) ? 0U : (((saltlen + vlen - 1U) / vlen) * vlen);
            plen = (plen == 0U) ? 0U : (((plen + vlen - 1U) / vlen) * vlen);
            ilen = slen + plen;
            mlen = vlen + ilen;

            if (ilen <= X509_PKCS12_KDF_SCRATCH_MAX && mlen <= (X509_PKCS12_KDF_SCRATCH_MAX + QSC_SHA2_512_RATE))
            {
                ibuf = (uint8_t*)qsc_memutils_malloc(ilen == 0U ? 1U : ilen);
                msg = (uint8_t*)qsc_memutils_malloc(mlen);

                if (ibuf != (uint8_t*)NULL && msg != (uint8_t*)NULL)
                {
                    qsc_memutils_clear(ibuf, ilen == 0U ? 1U : ilen);
                    qsc_memutils_clear(msg, mlen);
                    qsc_memutils_clear(d, vlen);

                    for (i = 0U; i < vlen; ++i)
                    {
                        d[i] = diversifier;
                    }

                    if (slen != 0U)
                    {
                        x509_pkcs12_repeat_bytes(ibuf, slen, salt, saltlen);
                    }

                    if (plen != 0U)
                    {
                        x509_pkcs12_repeat_bytes(ibuf + slen, plen, pbuf, ((qsc_stringutils_string_size(password) + 1U) * 2U));
                    }

                    offset = 0U;

                    while (offset < outlen)
                    {
                        qsc_memutils_copy(msg, d, vlen);

                        if (ilen != 0U)
                        {
                            qsc_memutils_copy(msg + vlen, ibuf, ilen);
                        }

                        x509_pkcs12_hash_compute(hash, a, msg, mlen);

                        for (i = 1U; i < (size_t)iterations; ++i)
                        {
                            x509_pkcs12_hash_compute(hash, a, a, hlen);
                        }

                        for (i = 0U; i < vlen; ++i)
                        {
                            b[i] = a[i % hlen];
                        }

                        if (ilen != 0U)
                        {
                            for (j = 0U; j < ilen; j += vlen)
                            {
                                x509_pkcs12_adjust_block(ibuf + j, vlen, b);
                            }
                        }

                        cp = ((outlen - offset) < hlen) ? (outlen - offset) : hlen;
                        qsc_memutils_copy(output + offset, a, cp);
                        offset += cp;
                    }

                    res = true;
                }
            }
        }
    }

    if (ibuf != (uint8_t*)NULL)
    {
        qsc_memutils_secure_free(ibuf, ilen == 0U ? 1U : ilen);
    }

    if (msg != (uint8_t*)NULL)
    {
        qsc_memutils_secure_free(msg, mlen);
    }

    qsc_memutils_secure_erase(a, sizeof(a));
    qsc_memutils_secure_erase(b, sizeof(b));
    qsc_memutils_secure_erase(d, sizeof(d));
    qsc_memutils_secure_erase(pbuf, sizeof(pbuf));

    return res;
}

static bool x509_pkcs12_verify_classic_mac(const qsc_encoding_ber_element* digestinfo, const qsc_encoding_ber_element* saltel, uint64_t iterations, const qsc_encoding_ber_element* safes, const char* password)
{
    qsc_asn1_oid oid = { 0 };
    uint8_t key[QSC_SHA2_512_HASH_SIZE] = { 0U };
    uint8_t mac[QSC_SHA2_512_HASH_SIZE] = { 0U };
    const qsc_encoding_ber_element* algseq;
    const qsc_encoding_ber_element* digestel;
    x509_pkcs12_hash_type hash;
    size_t hlen;
    bool res;

    res = false;

    if (qsc_asn1_require_sequence(digestinfo, 2U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
        x509_asn1_is_octet_string(saltel) == true)
    {
        algseq = qsc_asn1_get_child(digestinfo, 0U);
        digestel = qsc_asn1_get_child(digestinfo, 1U);

        if (qsc_asn1_require_sequence(algseq, 1U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
            x509_asn1_is_octet_string(digestel) == true &&
            qsc_asn1_decode_oid(qsc_asn1_get_child(algseq, 0U), &oid) == QSC_ASN1_STATUS_SUCCESS)
        {
            hash = x509_pkcs12_hash_from_digest_oid(&oid);
            hlen = x509_pkcs12_hash_size(hash);

            if (hlen != 0U && digestel->length == hlen && iterations != 0U)
            {
                if (x509_pkcs12_kdf_rfc7292(key, hlen, password, saltel->value, saltel->length, iterations, X509_PKCS12_KDF_ID_MAC, hash) == true)
                {
                    x509_pkcs12_hmac_compute(hash, mac, safes->value, safes->length, key, hlen);
                    res = qsc_memutils_are_equal(mac, digestel->value, hlen);
                }
            }
        }
    }

    qsc_memutils_secure_erase(key, sizeof(key));
    qsc_memutils_secure_erase(mac, sizeof(mac));

    return res;
}

static bool x509_pkcs12_parse_pbkdf2_params(const qsc_encoding_ber_element* params, const uint8_t** salt, size_t* saltlen, uint64_t* iterations, size_t* keylen, x509_pkcs12_hash_type* prfhash)
{
    qsc_asn1_oid oid = { 0 };
    const qsc_encoding_ber_element* prf;
    size_t idx;
    uint64_t klen;
    bool res;

    res = false;
    idx = 2U;
    prf = (const qsc_encoding_ber_element*)NULL;
    klen = 0U;

    if (params != (const qsc_encoding_ber_element*)NULL && salt != (const uint8_t**)NULL && saltlen != (size_t*)NULL &&
        iterations != (uint64_t*)NULL && keylen != (size_t*)NULL && prfhash != (x509_pkcs12_hash_type*)NULL)
    {
        if (qsc_asn1_require_sequence(params, 2U, 4U) == QSC_ASN1_STATUS_SUCCESS &&
            x509_asn1_is_octet_string(qsc_asn1_get_child(params, 0U)) == true &&
            qsc_asn1_decode_integer_u64(qsc_asn1_get_child(params, 1U), iterations) == QSC_ASN1_STATUS_SUCCESS)
        {
            *salt = qsc_asn1_get_child(params, 0U)->value;
            *saltlen = qsc_asn1_get_child(params, 0U)->length;
            *keylen = 0U;
            *prfhash = x509_pkcs12_hash_none;

            if (qsc_asn1_child_count(params) > idx)
            {
                if (x509_asn1_is_integer(qsc_asn1_get_child(params, idx)) == true)
                {
                    if (qsc_asn1_decode_integer_u64(qsc_asn1_get_child(params, idx), &klen) == QSC_ASN1_STATUS_SUCCESS && klen <= QSC_PBMAC1_MAX_KEY_SIZE)
                    {
                        *keylen = (size_t)klen;
                    }
                    else
                    {
                        idx = SIZE_MAX;
                    }

                    if (idx != SIZE_MAX)
                    {
                        ++idx;
                    }
                }
            }

            if (idx != SIZE_MAX && qsc_asn1_child_count(params) > idx)
            {
                prf = qsc_asn1_get_child(params, idx);
            }

            if (prf != (const qsc_encoding_ber_element*)NULL)
            {
                if (qsc_asn1_require_sequence(prf, 1U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
                    qsc_asn1_decode_oid(qsc_asn1_get_child(prf, 0U), &oid) == QSC_ASN1_STATUS_SUCCESS)
                {
                    *prfhash = x509_pkcs12_hash_from_hmac_oid(&oid);
                }
            }

            res = (*iterations != 0U && *iterations <= X509_PKCS12_MAC_ITERATION_MAX && *salt != (const uint8_t*)NULL &&
                *keylen != 0U && *prfhash != x509_pkcs12_hash_none);
        }
    }

    return res;
}

static bool x509_pkcs12_verify_pbmac1_mac(const qsc_encoding_ber_element* digestinfo, const qsc_encoding_ber_element* safes, const char* password)
{
    qsc_asn1_oid oid = { 0 };
    qsc_asn1_oid kdf_oid = { 0 };
    qsc_asn1_oid mac_oid = { 0 };
    qsc_pbmac1_keyparams kp = { 0 };
    const uint8_t* salt;
    const qsc_encoding_ber_element* algseq;
    const qsc_encoding_ber_element* digestel;
    const qsc_encoding_ber_element* params;
    const qsc_encoding_ber_element* kdfalg;
    const qsc_encoding_ber_element* macalg;
    const qsc_encoding_ber_element* pbkdf2params;
    uint64_t iterations;
    size_t saltlen;
    size_t keylen;
    x509_pkcs12_hash_type prfhash;
    x509_pkcs12_hash_type machash;
    bool res;

    res = false;
    salt = (const uint8_t*)NULL;
    iterations = 0U;
    saltlen = 0U;
    keylen = 0U;
    prfhash = x509_pkcs12_hash_none;
    machash = x509_pkcs12_hash_none;

    if (qsc_asn1_require_sequence(digestinfo, 2U, 2U) == QSC_ASN1_STATUS_SUCCESS)
    {
        algseq = qsc_asn1_get_child(digestinfo, 0U);
        digestel = qsc_asn1_get_child(digestinfo, 1U);

        if (qsc_asn1_require_sequence(algseq, 2U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
            qsc_asn1_decode_oid(qsc_asn1_get_child(algseq, 0U), &oid) == QSC_ASN1_STATUS_SUCCESS &&
            x509_pkcs12_oid_equals(&oid, OID_PBMAC1, sizeof(OID_PBMAC1)) == true &&
            x509_asn1_is_octet_string(digestel) == true)
        {
            params = qsc_asn1_get_child(algseq, 1U);

            if (qsc_asn1_require_sequence(params, 2U, 2U) == QSC_ASN1_STATUS_SUCCESS)
            {
                kdfalg = qsc_asn1_get_child(params, 0U);
                macalg = qsc_asn1_get_child(params, 1U);

                if (qsc_asn1_require_sequence(kdfalg, 2U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
                    qsc_asn1_require_sequence(macalg, 1U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
                    qsc_asn1_decode_oid(qsc_asn1_get_child(kdfalg, 0U), &kdf_oid) == QSC_ASN1_STATUS_SUCCESS &&
                    qsc_asn1_decode_oid(qsc_asn1_get_child(macalg, 0U), &mac_oid) == QSC_ASN1_STATUS_SUCCESS &&
                    x509_pkcs12_oid_equals(&kdf_oid, OID_PBKDF2, sizeof(OID_PBKDF2)) == true)
                {
                    pbkdf2params = qsc_asn1_get_child(kdfalg, 1U);
                    machash = x509_pkcs12_hash_from_hmac_oid(&mac_oid);

                    if (machash != x509_pkcs12_hash_none && digestel->length == x509_pkcs12_hash_size(machash) &&
                        x509_pkcs12_parse_pbkdf2_params(pbkdf2params, &salt, &saltlen, &iterations, &keylen, &prfhash) == true &&
                        prfhash == machash)
                    {
                        kp.password = (const uint8_t*)password;
                        kp.passwordlen = qsc_stringutils_string_size(password);
                        kp.salt = salt;
                        kp.saltlen = saltlen;
                        kp.iterations = iterations;
                        kp.hash = x509_pkcs12_to_pbmac1_hash(machash);
                        kp.keylen = keylen;
                        res = qsc_pbmac1_verify(digestel->value, digestel->length, &kp, safes->value, safes->length);
                    }
                }
            }
        }
    }

    return res;
}

static bool x509_pkcs12_verify_mac(const qsc_encoding_ber_element* root, const qsc_encoding_ber_element* safes, const char* password)
{
    const qsc_encoding_ber_element* macdata;
    const qsc_encoding_ber_element* digestinfo;
    const qsc_encoding_ber_element* saltel;
    uint64_t iterations;
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

                if (qsc_asn1_child_count(macdata) == 3U)
                {
                    if (qsc_asn1_decode_integer_u64(qsc_asn1_get_child(macdata, 2U), &iterations) != QSC_ASN1_STATUS_SUCCESS)
                    {
                        iterations = 0U;
                    }
                }

                if (iterations != 0U)
                {
                    res = x509_pkcs12_verify_classic_mac(digestinfo, saltel, iterations, safes, password);

                    if (res == false)
                    {
                        res = x509_pkcs12_verify_pbmac1_mac(digestinfo, safes, password);
                    }
                }
            }
        }
    }

    return res;
}


typedef enum
{
    x509_pkcs12_mac_writer_classic_sha256 = 0x01U,
    x509_pkcs12_mac_writer_pbmac1_sha256 = 0x02U
} x509_pkcs12_mac_writer_mode;

static size_t x509_der_write_length(uint8_t* output, size_t outcap, size_t len)
{
    size_t res;

    res = 0U;

    if (output != (uint8_t*)NULL)
    {
        if (len < 128U)
        {
            if (outcap >= 1U)
            {
                output[0U] = (uint8_t)len;
                res = 1U;
            }
        }
        else if (len <= 0xFFU)
        {
            if (outcap >= 2U)
            {
                output[0U] = 0x81U;
                output[1U] = (uint8_t)len;
                res = 2U;
            }
        }
        else if (len <= 0xFFFFU)
        {
            if (outcap >= 3U)
            {
                output[0U] = 0x82U;
                output[1U] = (uint8_t)(len >> 8U);
                output[2U] = (uint8_t)len;
                res = 3U;
            }
        }
    }

    return res;
}

static size_t x509_der_write_tlv(uint8_t* output, size_t outcap, uint8_t tag, const uint8_t* value, size_t valuelen)
{
    size_t llen;
    size_t res;

    res = 0U;

    if (output != (uint8_t*)NULL && (value != (const uint8_t*)NULL || valuelen == 0U) && outcap != 0U)
    {
        output[0U] = tag;
        llen = x509_der_write_length(output + 1U, outcap - 1U, valuelen);

        if (llen != 0U && (1U + llen + valuelen) <= outcap)
        {
            if (valuelen != 0U)
            {
                qsc_memutils_copy(output + 1U + llen, value, valuelen);
            }

            res = 1U + llen + valuelen;
        }
    }

    return res;
}

static size_t x509_der_write_integer_u64(uint8_t* output, size_t outcap, uint64_t value)
{
    uint8_t enc[9U] = { 0U };
    size_t pos;
    size_t start;
    size_t len;

    pos = sizeof(enc);

    do
    {
        --pos;
        enc[pos] = (uint8_t)value;
        value >>= 8U;
    } while (value != 0U && pos != 0U);

    start = pos;

    if ((enc[start] & 0x80U) != 0U && start != 0U)
    {
        --start;
        enc[start] = 0U;
    }

    len = sizeof(enc) - start;

    return x509_der_write_tlv(output, outcap, BER_ASN1_INTEGER, enc + start, len);
}

static size_t x509_der_write_null(uint8_t* output, size_t outcap)
{
    return x509_der_write_tlv(output, outcap, BER_ASN1_NULL, NULL, 0U);
}

static size_t x509_der_write_oid(uint8_t* output, size_t outcap, const uint8_t* oid, size_t oidlen)
{
    return x509_der_write_tlv(output, outcap, BER_ASN1_OBJECT_IDENTIFIER, oid, oidlen);
}

static size_t x509_der_write_octet_string(uint8_t* output, size_t outcap, const uint8_t* value, size_t valuelen)
{
    return x509_der_write_tlv(output, outcap, BER_ASN1_OCTET_STRING, value, valuelen);
}

static size_t x509_der_write_sequence(uint8_t* output, size_t outcap, const uint8_t* value, size_t valuelen)
{
    return x509_der_write_tlv(output, outcap, BER_ASN1_SEQUENCE | 0x20U, value, valuelen);
}

static size_t x509_pkcs12_write_algid_sha256(uint8_t* output, size_t outcap)
{
    uint8_t tmp[32U] = { 0U };
    size_t pos;
    size_t len;

    pos = 0U;
    len = x509_der_write_oid(tmp + pos, sizeof(tmp) - pos, OID_SHA256, sizeof(OID_SHA256));
    if (len != 0U)
    {
        pos += len;
        len = x509_der_write_null(tmp + pos, sizeof(tmp) - pos);
        if (len != 0U)
        {
            pos += len;
            len = x509_der_write_sequence(output, outcap, tmp, pos);
        }
    }

    qsc_memutils_clear(tmp, sizeof(tmp));
    return len;
}

static size_t x509_pkcs12_write_algid_hmac_sha256(uint8_t* output, size_t outcap)
{
    uint8_t tmp[32U] = { 0U };
    size_t pos;
    size_t len;

    pos = 0U;
    len = x509_der_write_oid(tmp + pos, sizeof(tmp) - pos, OID_HMAC_SHA256, sizeof(OID_HMAC_SHA256));
    if (len != 0U)
    {
        pos += len;
        len = x509_der_write_null(tmp + pos, sizeof(tmp) - pos);
        if (len != 0U)
        {
            pos += len;
            len = x509_der_write_sequence(output, outcap, tmp, pos);
        }
    }

    qsc_memutils_clear(tmp, sizeof(tmp));
    return len;
}

static size_t x509_pkcs12_write_pbkdf2_algid(uint8_t* output, size_t outcap, const uint8_t* salt, size_t saltlen, uint64_t iterations)
{
    uint8_t tmp[256U] = { 0U };
    uint8_t params[224U] = { 0U };
    size_t pos;
    size_t ppos;
    size_t len;

    pos = 0U;
    ppos = 0U;
    len = x509_der_write_octet_string(params + ppos, sizeof(params) - ppos, salt, saltlen);
    if (len != 0U)
    {
        ppos += len;
        len = x509_der_write_integer_u64(params + ppos, sizeof(params) - ppos, iterations);
    }
    if (len != 0U)
    {
        ppos += len;
        len = x509_der_write_integer_u64(params + ppos, sizeof(params) - ppos, QSC_SHA2_256_HASH_SIZE);
    }
    if (len != 0U)
    {
        ppos += len;
        len = x509_pkcs12_write_algid_hmac_sha256(params + ppos, sizeof(params) - ppos);
    }
    if (len != 0U)
    {
        ppos += len;
        len = x509_der_write_oid(tmp + pos, sizeof(tmp) - pos, OID_PBKDF2, sizeof(OID_PBKDF2));
    }
    if (len != 0U)
    {
        pos += len;
        len = x509_der_write_sequence(tmp + pos, sizeof(tmp) - pos, params, ppos);
    }
    if (len != 0U)
    {
        pos += len;
        len = x509_der_write_sequence(output, outcap, tmp, pos);
    }

    qsc_memutils_clear(tmp, sizeof(tmp));
    qsc_memutils_clear(params, sizeof(params));
    return len;
}

static size_t x509_pkcs12_write_pbmac1_algid(uint8_t* output, size_t outcap, const uint8_t* salt, size_t saltlen, uint64_t iterations)
{
    uint8_t content[384U] = { 0U };
    uint8_t params[352U] = { 0U };
    size_t pos;
    size_t ppos;
    size_t len;

    pos = 0U;
    ppos = 0U;
    len = x509_pkcs12_write_pbkdf2_algid(params + ppos, sizeof(params) - ppos, salt, saltlen, iterations);
    if (len != 0U)
    {
        ppos += len;
        len = x509_pkcs12_write_algid_hmac_sha256(params + ppos, sizeof(params) - ppos);
    }
    if (len != 0U)
    {
        ppos += len;
        len = x509_der_write_oid(content + pos, sizeof(content) - pos, OID_PBMAC1, sizeof(OID_PBMAC1));
    }
    if (len != 0U)
    {
        pos += len;
        len = x509_der_write_sequence(content + pos, sizeof(content) - pos, params, ppos);
    }
    if (len != 0U)
    {
        pos += len;
        len = x509_der_write_sequence(output, outcap, content, pos);
    }

    qsc_memutils_clear(content, sizeof(content));
    qsc_memutils_clear(params, sizeof(params));
    return len;
}

static bool x509_pkcs12_compute_writer_mac(uint8_t* mac, const uint8_t* authsafe, size_t authsafelen, const char* password, const uint8_t* salt, size_t saltlen, uint64_t iterations, x509_pkcs12_mac_writer_mode mode)
{
    qsc_pbmac1_keyparams kp = { 0 };
    uint8_t key[QSC_SHA2_256_HASH_SIZE] = { 0U };
    bool res;

    res = false;

    if (mode == x509_pkcs12_mac_writer_classic_sha256)
    {
        if (x509_pkcs12_kdf_rfc7292(key, sizeof(key), password, salt, saltlen, iterations, X509_PKCS12_KDF_ID_MAC, x509_pkcs12_hash_sha256) == true)
        {
            qsc_hmac256_compute(mac, authsafe, authsafelen, key, sizeof(key));
            res = true;
        }
    }
    else if (mode == x509_pkcs12_mac_writer_pbmac1_sha256)
    {
        kp.password = (const uint8_t*)password;
        kp.passwordlen = qsc_stringutils_string_size(password);
        kp.salt = salt;
        kp.saltlen = saltlen;
        kp.iterations = iterations;
        kp.hash = qsc_pbmac1_hash_sha256;
        kp.keylen = QSC_SHA2_256_HASH_SIZE;
        res = qsc_pbmac1_compute(mac, &kp, authsafe, authsafelen);
    }

    qsc_memutils_secure_erase(key, sizeof(key));

    return res;
}

static bool x509_pkcs12_encode_mac_data_internal(uint8_t* output, size_t outcap, size_t* outlen, const uint8_t* authsafe, size_t authsafelen, const char* password, const uint8_t* salt, size_t saltlen, uint64_t iterations, x509_pkcs12_mac_writer_mode mode)
{
    uint8_t content[512U] = { 0U };
    uint8_t dinfo[448U] = { 0U };
    uint8_t mac[QSC_SHA2_256_HASH_SIZE] = { 0U };
    size_t pos;
    size_t dpos;
    size_t len;
    bool res;

    res = false;
    pos = 0U;
    dpos = 0U;

    if (output != (uint8_t*)NULL && outlen != (size_t*)NULL && authsafe != (const uint8_t*)NULL && password != (const char*)NULL &&
        salt != (const uint8_t*)NULL && saltlen != 0U && iterations != 0U && iterations <= X509_PKCS12_MAC_ITERATION_MAX)
    {
        if (x509_pkcs12_compute_writer_mac(mac, authsafe, authsafelen, password, salt, saltlen, iterations, mode) == true)
        {
            if (mode == x509_pkcs12_mac_writer_classic_sha256)
            {
                len = x509_pkcs12_write_algid_sha256(dinfo + dpos, sizeof(dinfo) - dpos);
            }
            else
            {
                len = x509_pkcs12_write_pbmac1_algid(dinfo + dpos, sizeof(dinfo) - dpos, salt, saltlen, iterations);
            }

            if (len != 0U)
            {
                dpos += len;
                len = x509_der_write_octet_string(dinfo + dpos, sizeof(dinfo) - dpos, mac, sizeof(mac));
            }
            if (len != 0U)
            {
                dpos += len;
                len = x509_der_write_sequence(content + pos, sizeof(content) - pos, dinfo, dpos);
            }
            if (len != 0U)
            {
                pos += len;
                len = x509_der_write_octet_string(content + pos, sizeof(content) - pos, salt, saltlen);
            }
            if (len != 0U)
            {
                pos += len;
                len = x509_der_write_integer_u64(content + pos, sizeof(content) - pos, iterations);
            }
            if (len != 0U)
            {
                pos += len;
                len = x509_der_write_sequence(output, outcap, content, pos);

                if (len != 0U)
                {
                    *outlen = len;
                    res = true;
                }
            }
        }
    }

    qsc_memutils_secure_erase(content, sizeof(content));
    qsc_memutils_secure_erase(dinfo, sizeof(dinfo));
    qsc_memutils_secure_erase(mac, sizeof(mac));

    return res;
}

bool qsc_x509_pkcs12_encode_mac_data_der(uint8_t* output, size_t outcap, size_t* outlen, const uint8_t* authsafe, size_t authsafelen, const char* password, const uint8_t* salt, size_t saltlen, uint64_t iterations, bool usepbmac1)
{
    x509_pkcs12_mac_writer_mode mode;

    mode = (usepbmac1 == true) ? x509_pkcs12_mac_writer_pbmac1_sha256 : x509_pkcs12_mac_writer_classic_sha256;

    return x509_pkcs12_encode_mac_data_internal(output, outcap, outlen, authsafe, authsafelen, password, salt, saltlen, iterations, mode);
}


bool qsc_x509_pkcs12_verify_mac_data(const uint8_t* data, size_t datalen, const char* password)
{
    qsc_asn1_oid oid = { 0 };
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* authsafe;
    const qsc_encoding_ber_element* content;
    const qsc_encoding_ber_element* safes;
    uint64_t version;
    size_t consumed;
    const char* pwd;
    bool res;

    res = false;
    root = (qsc_encoding_ber_element*)NULL;
    pwd = "";

    if (data != (const uint8_t*)NULL && datalen != 0U)
    {
        if (password != (const char*)NULL)
        {
            pwd = password;
        }

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
                        x509_asn1_is_octet_string(safes) == true)
                    {
                        res = x509_pkcs12_verify_mac(root, safes, pwd);
                    }
                }
            }

            qsc_encoding_ber_free_element(root);
        }
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
