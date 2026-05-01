#include "x509pkcs12.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "sha2.h"
#include "sha3.h"
#include "stringutils.h"
#if defined(QSC_X509_PKCS12_USE_AES)
#   include "aes.h"
#elif defined(QSC_X509_PKCS12_USE_RCS)
#   include "rcs.h"
#endif

#define X509_PKCS12_AES256_CBC_KEY_SIZE 32U
#define X509_PKCS12_AES128_CBC_KEY_SIZE 16U
#define X509_PKCS12_AES_BLOCK_SIZE 16U
#define X509_PKCS12_RCS256_KEY_SIZE 32U
#define X509_PKCS12_RCS512_KEY_SIZE 64U
#define X509_PKCS12_RCS_NONCE_SIZE 32U

static const uint8_t OID_PBES2[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x05U, 0x0DU };
static const uint8_t OID_PBKDF2[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x05U, 0x0CU };
static const uint8_t OID_AES128_CBC[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x01U, 0x02U };
static const uint8_t OID_AES256_CBC[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x01U, 0x2AU };

static bool x509_asn1_is_octet_string(const qsc_encoding_ber_element* element)
{
    return (qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OCTET_STRING) == QSC_ASN1_STATUS_SUCCESS);
}

static bool x509_pkcs12_oid_equals(const qsc_asn1_oid* oid, const uint8_t* enc, size_t enclen)
{
    bool res;

    if (oid != NULL && enc != NULL && oid->length == enclen)
    {
        res = qsc_memutils_are_equal(oid->data, enc, enclen);
    }
    else
    {
        res = false;
    }

    return res;
}

static bool x509_pkcs12_parse_pbkdf2_params(const qsc_encoding_ber_element* params, uint8_t* salt, size_t saltcap, size_t* saltlen, uint64_t* iterations, uint64_t* keylength)
{
    const qsc_encoding_ber_element* child;
    bool res;

    res = false;

    if (qsc_asn1_require_sequence(params, 2U, 4U) == QSC_ASN1_STATUS_SUCCESS)
    {
        child = qsc_asn1_get_child(params, 0U);

        if (x509_asn1_is_octet_string(child) == true || child->length <= saltcap)
        {
            qsc_memutils_copy(salt, child->value, child->length);
            *saltlen = child->length;

            if (qsc_asn1_decode_integer_u64(qsc_asn1_get_child(params, 1U), iterations) == QSC_ASN1_STATUS_SUCCESS)
            {
                *keylength = 0U;

                if (qsc_asn1_child_count(params) >= 3U && qsc_asn1_is_integer(qsc_asn1_get_child(params, 2U)) == true)
                {
                    if (qsc_asn1_decode_integer_u64(qsc_asn1_get_child(params, 2U), keylength) == QSC_ASN1_STATUS_SUCCESS)
                    {
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

static bool x509_pkcs12_pbkdf2_hmac256(uint8_t* output, size_t outlen, const uint8_t* password, size_t passwordlen, const uint8_t* salt, size_t saltlen, uint64_t iterations)
{
    qsc_hmac256_state ctx = { 0 };
    uint8_t u[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t t[QSC_SHA2_256_HASH_SIZE] = { 0U };
    uint8_t ctr[4U] = { 0U };
    size_t offset;
    bool res;

    if (output == NULL || (outlen != 0U && password == (const uint8_t*)NULL) ||
        (salt == (const uint8_t*)NULL && saltlen != 0U) || iterations == 0U || iterations > 1000000U)
    {
        res = false;
    }
    else
    {
        offset = 0U;

        for (size_t idx = 1U; offset < outlen; ++idx)
        {
            ctr[0U] = (uint8_t)((idx >> 24) & 0xFFU);
            ctr[1U] = (uint8_t)((idx >> 16) & 0xFFU);
            ctr[2U] = (uint8_t)((idx >> 8) & 0xFFU);
            ctr[3U] = (uint8_t)(idx & 0xFFU);

            qsc_hmac256_initialize(&ctx, password, passwordlen);

            if (saltlen != 0U)
            {
                qsc_hmac256_update(&ctx, salt, saltlen);
            }

            qsc_hmac256_update(&ctx, ctr, sizeof(ctr));
            qsc_hmac256_finalize(&ctx, u);
            qsc_memutils_copy(t, u, sizeof(t));

            for (size_t i = 1U; i < (size_t)iterations; ++i)
            {
                qsc_hmac256_compute(u, u, sizeof(u), password, passwordlen);
                for (size_t j = 0U; j < sizeof(t); ++j)
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

static bool x509_pkcs12_decrypt_cbc(const uint8_t* enc, size_t enclen, const uint8_t* iv, size_t ivlen, const uint8_t* key, size_t keylen, uint8_t* out, size_t* outlen)
{
#if defined(QSC_X509_PKCS12_USE_AES)

    qsc_aes_state state = { 0 };
    qsc_aes_keyparams kp = { 0 };
    uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0U };
    size_t plen;
    bool res;

    if ((keylen != QSC_AES128_KEY_SIZE && keylen != QSC_AES256_KEY_SIZE) || ivlen != QSC_AES_BLOCK_SIZE)
    {
        res = false;
    }
    else
    {
        qsc_memutils_copy(nonce, iv, ivlen);
        kp.key = key;
        kp.keylen = keylen;
        kp.nonce = nonce;
        kp.noncelen = ivlen;
        kp.info = (const uint8_t*)NULL;
        kp.infolen = 0U;
        qsc_aes_initialize(&state, &kp, false, (keylen == QSC_AES256_KEY_SIZE) ? qsc_aes_cipher_256 : qsc_aes_cipher_128);
        plen = *outlen;
        qsc_aes_cbc_decrypt(&state, out, &plen, enc, enclen);
        qsc_aes_dispose(&state);
        *outlen = plen;
        res = true;
    }

    return res;

#elif defined(QSC_X509_PKCS12_USE_RCS)

    qsc_rcs_state state = { 0 };
    qsc_rcs_keyparams kp = { 0 };
    uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0U };
    bool res;

    if (ivlen > sizeof(nonce) || (keylen != QSC_RCS256_KEY_SIZE && keylen != QSC_RCS512_KEY_SIZE) || enclen > *outlen)
    {
        res = false;
    }
    else
    {
        qsc_memutils_clear(nonce, sizeof(nonce));
        qsc_memutils_copy(nonce, iv, ivlen);
        kp.key = key;
        kp.keylen = keylen;
        kp.nonce = nonce;
        kp.info = (const uint8_t*)NULL;
        kp.infolen = 0U;
        qsc_rcs_initialize(&state, &kp, false);

        res = qsc_rcs_transform(&state, out, enc, enclen);
        qsc_rcs_dispose(&state);

        if (res == true)
        {
            *outlen = enclen;
        }
    }

    return res;

#else
    (void)enc;
    (void)enclen;
    (void)iv;
    (void)ivlen;
    (void)key;
    (void)keylen;
    (void)out;
    (void)outlen;
    return false;
#endif
}

bool qsc_x509_pkcs12_decrypt_encrypted_private_key_info(const uint8_t* data, size_t datalen, const char* password, uint8_t* privatekeyinfo, size_t privatekeyinfocapacity, size_t* privatekeyinfolen)
{
    QSC_ASSERT(data != NULL);
    QSC_ASSERT(password != NULL);
    QSC_ASSERT(privatekeyinfo != NULL);
    QSC_ASSERT(privatekeyinfolen != NULL);

    qsc_asn1_oid oid = { 0 };
    uint8_t key[64U] = { 0U };
    uint8_t salt[64U] = { 0U };
    qsc_encoding_ber_element* root;
    const qsc_encoding_ber_element* algseq;
    const qsc_encoding_ber_element* params;
    const qsc_encoding_ber_element* kdfseq;
    const qsc_encoding_ber_element* kdfparams;
    const qsc_encoding_ber_element* encseq;
    const qsc_encoding_ber_element* ivel;
    const qsc_encoding_ber_element* ctel;
    uint64_t iterations;
    uint64_t keylength;
    size_t consumed;
    size_t outlen;
    size_t saltlen;
    qsc_asn1_status status;

    ctel = NULL;
    encseq = NULL;
    ivel = NULL;
    kdfseq = NULL;
    params = NULL;
    saltlen = 0U;
    iterations = 0U;
    keylength = 0U;
    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (data != NULL && password != NULL && privatekeyinfo != NULL && privatekeyinfolen != NULL)
    {
        consumed = 0U;
        root = qsc_encoding_ber_decode_element(data, datalen, &consumed);

        if (root != NULL)
        {
            status = qsc_asn1_require_sequence(root, 2U, 2U);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                algseq = qsc_asn1_get_child(root, 0U);
                ctel = qsc_asn1_get_child(root, 1U);
                status = qsc_asn1_require_sequence(algseq, 2U, 2U);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    status = qsc_asn1_decode_oid(qsc_asn1_get_child(algseq, 0U), &oid);
                }

                if (status == QSC_ASN1_STATUS_SUCCESS && x509_pkcs12_oid_equals(&oid, OID_PBES2, sizeof(OID_PBES2)) == true)
                {
                    params = qsc_asn1_get_child(algseq, 1U);
                    status = qsc_asn1_require_sequence(params, 2U, 2U);
                }
                else
                {
                    status = QSC_ASN1_STATUS_UNSUPPORTED;
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                kdfseq = qsc_asn1_get_child(params, 0U);
                encseq = qsc_asn1_get_child(params, 1U);
                status = qsc_asn1_require_sequence(kdfseq, 2U, 2U);
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_asn1_decode_oid(qsc_asn1_get_child(kdfseq, 0U), &oid);

                if (status == QSC_ASN1_STATUS_SUCCESS && x509_pkcs12_oid_equals(&oid, OID_PBKDF2, sizeof(OID_PBKDF2)) == true)
                {
                    kdfparams = qsc_asn1_get_child(kdfseq, 1U);
                    saltlen = 0U;
                    iterations = 0U;
                    keylength = 0U;

                    if (x509_pkcs12_parse_pbkdf2_params(kdfparams, salt, sizeof(salt), &saltlen, &iterations, &keylength) == false)
                    {
                        status = QSC_ASN1_STATUS_FAILURE;
                    }
                }
                else
                {
                    status = QSC_ASN1_STATUS_UNSUPPORTED;
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_asn1_require_sequence(encseq, 2U, 2U);
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_asn1_decode_oid(qsc_asn1_get_child(encseq, 0U), &oid);
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                ivel = qsc_asn1_get_child(encseq, 1U);

                if (x509_asn1_is_octet_string(ivel) == false || x509_asn1_is_octet_string(ctel) == false)
                {
                    status = QSC_ASN1_STATUS_FAILURE;
                }
                else if (x509_pkcs12_oid_equals(&oid, OID_AES256_CBC, sizeof(OID_AES256_CBC)) == true)
                {
                    if (keylength == 0U)
                    {
                        keylength = X509_PKCS12_AES256_CBC_KEY_SIZE;
                    }
                }
                else if (x509_pkcs12_oid_equals(&oid, OID_AES128_CBC, sizeof(OID_AES128_CBC)) == true)
                {
                    if (keylength == 0U)
                    {
                        keylength = X509_PKCS12_AES128_CBC_KEY_SIZE;
                    }
                }
                else
                {
                    status = QSC_ASN1_STATUS_UNSUPPORTED;
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                if (keylength > sizeof(key) || keylength == 0U)
                {
                    status = QSC_ASN1_STATUS_INVALID_LENGTH;
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                if (x509_pkcs12_pbkdf2_hmac256(key, (size_t)keylength, (const uint8_t*)password, qsc_stringutils_string_size(password), salt, saltlen, iterations) == false)
                {
                    status = QSC_ASN1_STATUS_OUT_OF_RANGE;
                }
                else
                {
                    outlen = privatekeyinfocapacity;

                    if (x509_pkcs12_decrypt_cbc(ctel->value, ctel->length, ivel->value, ivel->length, key, (size_t)keylength, privatekeyinfo, &outlen) == false)
                    {
                        status = QSC_ASN1_STATUS_UNSUPPORTED;
                    }
                    else
                    {
                        *privatekeyinfolen = outlen;
                    }

                    qsc_memutils_secure_erase(key, sizeof(key));
                }
            }

            qsc_encoding_ber_free_element(root);
        }
    }

    return (status == QSC_ASN1_STATUS_SUCCESS);
}
