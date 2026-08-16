#include "x509pkcs12.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "pbmac1.h"
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
static const uint8_t OID_HMAC_SHA256[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x02U, 0x09U };
static const uint8_t OID_HMAC_SHA384[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x02U, 0x0AU };
static const uint8_t OID_HMAC_SHA512[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x02U, 0x0BU };

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

static qsc_pbmac1_hash_type x509_pkcs12_prf_from_oid(const qsc_asn1_oid* oid)
{
    qsc_pbmac1_hash_type res;

    res = qsc_pbmac1_hash_none;

    if (x509_pkcs12_oid_equals(oid, OID_HMAC_SHA256, sizeof(OID_HMAC_SHA256)) == true)
    {
        res = qsc_pbmac1_hash_sha256;
    }
    else if (x509_pkcs12_oid_equals(oid, OID_HMAC_SHA384, sizeof(OID_HMAC_SHA384)) == true)
    {
        res = qsc_pbmac1_hash_sha384;
    }
    else if (x509_pkcs12_oid_equals(oid, OID_HMAC_SHA512, sizeof(OID_HMAC_SHA512)) == true)
    {
        res = qsc_pbmac1_hash_sha512;
    }

    return res;
}

static bool x509_pkcs12_parse_pbkdf2_params(const qsc_encoding_ber_element* params, uint8_t* salt, size_t saltcap, size_t* saltlen,
    uint64_t* iterations, uint64_t* keylength, qsc_pbmac1_hash_type* prfhash)
{
    qsc_asn1_oid oid = { 0 };
    const qsc_encoding_ber_element* child;
    const qsc_encoding_ber_element* prf;
    size_t count;
    size_t idx;
    bool res;

    res = false;

    if (params != (const qsc_encoding_ber_element*)NULL && salt != (uint8_t*)NULL && saltlen != (size_t*)NULL &&
        iterations != (uint64_t*)NULL && keylength != (uint64_t*)NULL && prfhash != (qsc_pbmac1_hash_type*)NULL &&
        qsc_asn1_require_sequence(params, 2U, 4U) == QSC_ASN1_STATUS_SUCCESS)
    {
        child = qsc_asn1_get_child(params, 0U);
        count = qsc_asn1_child_count(params);

        if (x509_asn1_is_octet_string(child) == true && child->length != 0U && child->length <= saltcap &&
            qsc_asn1_decode_integer_u64(qsc_asn1_get_child(params, 1U), iterations) == QSC_ASN1_STATUS_SUCCESS &&
            *iterations != 0U && *iterations <= QSC_PBMAC1_MAX_ITERATIONS)
        {
            qsc_memutils_copy(salt, child->value, child->length);
            *saltlen = child->length;
            *keylength = 0U;
            *prfhash = qsc_pbmac1_hash_none;
            idx = 2U;

            if (idx < count && qsc_asn1_is_integer(qsc_asn1_get_child(params, idx)) == true)
            {
                if (qsc_asn1_decode_integer_u64(qsc_asn1_get_child(params, idx), keylength) == QSC_ASN1_STATUS_SUCCESS &&
                    *keylength != 0U && *keylength <= QSC_PBMAC1_MAX_KEY_SIZE)
                {
                    ++idx;
                }
                else
                {
                    idx = SIZE_MAX;
                }
            }

            if (idx != SIZE_MAX && idx < count)
            {
                prf = qsc_asn1_get_child(params, idx);

                if (qsc_asn1_require_sequence(prf, 1U, 2U) == QSC_ASN1_STATUS_SUCCESS &&
                    qsc_asn1_decode_oid(qsc_asn1_get_child(prf, 0U), &oid) == QSC_ASN1_STATUS_SUCCESS)
                {
                    *prfhash = x509_pkcs12_prf_from_oid(&oid);

                    if (*prfhash != qsc_pbmac1_hash_none &&
                        (qsc_asn1_child_count(prf) == 1U || qsc_asn1_decode_null(qsc_asn1_get_child(prf, 1U)) == QSC_ASN1_STATUS_SUCCESS))
                    {
                        ++idx;
                    }
                    else
                    {
                        idx = SIZE_MAX;
                    }
                }
            }

            /* RFC 8018 defaults an omitted PBKDF2 PRF to HMAC-SHA-1. QSC's
             * PKCS #12 profile intentionally supports SHA-2 PRFs only, so an
             * omitted PRF is unsupported rather than being guessed as SHA-256. */
            res = (idx == count && *prfhash != qsc_pbmac1_hash_none);
        }
    }

    return res;
}

static bool x509_pkcs12_pbkdf2(uint8_t* output, size_t outlen, const uint8_t* password, size_t passwordlen,
    const uint8_t* salt, size_t saltlen, uint64_t iterations, qsc_pbmac1_hash_type prfhash)
{
    qsc_pbmac1_keyparams kp = { 0 };
    bool res;

    res = false;

    if (output != (uint8_t*)NULL && outlen != 0U && outlen <= QSC_PBMAC1_MAX_KEY_SIZE &&
        (password != (const uint8_t*)NULL || passwordlen == 0U) && salt != (const uint8_t*)NULL && saltlen != 0U &&
        iterations != 0U && iterations <= QSC_PBMAC1_MAX_ITERATIONS && prfhash != qsc_pbmac1_hash_none)
    {
        kp.password = password;
        kp.passwordlen = passwordlen;
        kp.salt = salt;
        kp.saltlen = saltlen;
        kp.iterations = iterations;
        kp.hash = prfhash;
        kp.keylen = outlen;
        res = qsc_pbmac1_derive_key(output, outlen, &kp);
    }

    return res;
}

#if defined(QSC_X509_PKCS12_USE_AES)
static bool x509_pkcs12_pkcs7_unpad(const uint8_t* data, size_t datalen, size_t* plaintextlen)
{
    size_t padlen;
    size_t i;
    uint8_t bad;
    uint8_t mask;
    bool res;

    padlen = 0U;
    bad = 0U;
    res = false;

    if (data != (const uint8_t*)NULL && plaintextlen != (size_t*)NULL && datalen >= QSC_AES_BLOCK_SIZE &&
        (datalen % QSC_AES_BLOCK_SIZE) == 0U)
    {
        padlen = (size_t)data[datalen - 1U];
        bad = (uint8_t)((padlen == 0U || padlen > QSC_AES_BLOCK_SIZE) ? 1U : 0U);

        for (i = 0U; i < QSC_AES_BLOCK_SIZE; ++i)
        {
            mask = (uint8_t)(0U - (uint8_t)(i < padlen));
            bad |= (uint8_t)((data[datalen - 1U - i] ^ (uint8_t)padlen) & mask);
        }

        if (bad == 0U)
        {
            *plaintextlen = datalen - padlen;
            res = true;
        }
    }

    return res;
}
#endif

static bool x509_pkcs12_decrypt_cbc(const uint8_t* enc, size_t enclen, const uint8_t* iv, size_t ivlen, const uint8_t* key, size_t keylen, uint8_t* out, size_t* outlen)
{
#if defined(QSC_X509_PKCS12_USE_AES)

    qsc_aes_state state = { 0 };
    qsc_aes_keyparams kp = { 0 };
    uint8_t nonce[QSC_AES_BLOCK_SIZE] = { 0U };
    size_t capacity;
    size_t offset;
    size_t plaintextlen;
    bool res;

    capacity = 0U;
    offset = 0U;
    plaintextlen = 0U;
    res = false;

    if (outlen != (size_t*)NULL)
    {
        capacity = *outlen;
        *outlen = 0U;
    }

    if (enc != (const uint8_t*)NULL && iv != (const uint8_t*)NULL && key != (const uint8_t*)NULL &&
        out != (uint8_t*)NULL && outlen != (size_t*)NULL && enclen != 0U &&
        (enclen % QSC_AES_BLOCK_SIZE) == 0U && enclen <= capacity &&
        (keylen == QSC_AES128_KEY_SIZE || keylen == QSC_AES256_KEY_SIZE) && ivlen == QSC_AES_BLOCK_SIZE)
    {
        qsc_memutils_copy(nonce, iv, ivlen);
        kp.key = key;
        kp.keylen = keylen;
        kp.nonce = nonce;
        kp.noncelen = ivlen;
        kp.info = (const uint8_t*)NULL;
        kp.infolen = 0U;

        qsc_aes_initialize(&state, &kp, false, (keylen == QSC_AES256_KEY_SIZE) ? qsc_aes_cipher_256 : qsc_aes_cipher_128);

        while (offset < enclen)
        {
            qsc_aes_cbc_decrypt_block(&state, out + offset, enc + offset);
            offset += QSC_AES_BLOCK_SIZE;
        }

        qsc_aes_dispose(&state);

        if (x509_pkcs12_pkcs7_unpad(out, enclen, &plaintextlen) == true)
        {
            *outlen = plaintextlen;
            res = true;
        }
        else
        {
            qsc_memutils_secure_erase(out, enclen);
        }
    }

    qsc_memutils_secure_erase(nonce, sizeof(nonce));

    return res;

#elif defined(QSC_X509_PKCS12_USE_RCS)

    qsc_rcs_state state = { 0 };
    qsc_rcs_keyparams kp = { 0 };
    uint8_t nonce[QSC_RCS_NONCE_SIZE] = { 0U };
    size_t capacity;
    bool res;

    capacity = 0U;
    res = false;

    if (outlen != (size_t*)NULL)
    {
        capacity = *outlen;
        *outlen = 0U;
    }

    if (enc != (const uint8_t*)NULL && iv != (const uint8_t*)NULL && key != (const uint8_t*)NULL &&
        out != (uint8_t*)NULL && outlen != (size_t*)NULL && enclen != 0U && enclen <= capacity &&
        ivlen <= sizeof(nonce) && (keylen == QSC_RCS256_KEY_SIZE || keylen == QSC_RCS512_KEY_SIZE))
    {
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
        else
        {
            qsc_memutils_secure_erase(out, enclen);
        }
    }

    qsc_memutils_secure_erase(nonce, sizeof(nonce));

    return res;

#else

    if (outlen != (size_t*)NULL)
    {
        *outlen = 0U;
    }

    (void)enc;
    (void)enclen;
    (void)iv;
    (void)ivlen;
    (void)key;
    (void)keylen;
    (void)out;

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
    qsc_pbmac1_hash_type prfhash;
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
    prfhash = qsc_pbmac1_hash_none;
    status = QSC_ASN1_STATUS_INVALID_INPUT;

    if (privatekeyinfolen != (size_t*)NULL)
    {
        *privatekeyinfolen = 0U;
    }

    if (data != NULL && datalen != 0U && password != NULL && privatekeyinfo != NULL && privatekeyinfolen != NULL)
    {
        consumed = 0U;
        root = qsc_encoding_ber_decode_element(data, datalen, &consumed);

        if (root != NULL)
        {
            if (consumed == datalen)
            {
                status = qsc_asn1_require_sequence(root, 2U, 2U);
            }
            else
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }

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

                    if (x509_pkcs12_parse_pbkdf2_params(kdfparams, salt, sizeof(salt), &saltlen, &iterations, &keylength, &prfhash) == false)
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
                if (x509_pkcs12_pbkdf2(key, (size_t)keylength, (const uint8_t*)password, qsc_stringutils_string_size(password), salt, saltlen, iterations, prfhash) == false)
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

                }
            }

            qsc_encoding_ber_free_element(root);
        }
    }

    qsc_memutils_secure_erase(key, sizeof(key));
    qsc_memutils_secure_erase(salt, sizeof(salt));

    return (status == QSC_ASN1_STATUS_SUCCESS);
}
