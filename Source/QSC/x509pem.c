#include "x509pem.h"
#include "encoding.h"
#include "memutils.h"
#include "x509keywrite.h"
#include "x509verify.h"
#include "x509sigver.h"
#include "stringutils.h"

#define QSC_X509_PEM_CSR_BEGIN "-----BEGIN CERTIFICATE REQUEST-----"
#define QSC_X509_PEM_CSR_END "-----END CERTIFICATE REQUEST-----"

#define QSC_X509_PEM_CERT_BEGIN "-----BEGIN CERTIFICATE-----"
#define QSC_X509_PEM_CERT_END "-----END CERTIFICATE-----"
#define QSC_X509_PEM_CRL_BEGIN "-----BEGIN X509 CRL-----"
#define QSC_X509_PEM_CRL_END "-----END X509 CRL-----"
#define QSC_X509_PEM_PKCS8_BEGIN "-----BEGIN PRIVATE KEY-----"
#define QSC_X509_PEM_PKCS8_END "-----END PRIVATE KEY-----"
#define QSC_X509_PEM_MLDSA_PKCS8_BEGIN "-----BEGIN ML-DSA PRIVATE KEY-----"
#define QSC_X509_PEM_MLDSA_PKCS8_END "-----END ML-DSA PRIVATE KEY-----"
#define QSC_X509_PEM_MLKEM_PKCS8_BEGIN "-----BEGIN ML-KEM PRIVATE KEY-----"
#define QSC_X509_PEM_MLKEM_PKCS8_END "-----END ML-KEM PRIVATE KEY-----"
#define QSC_X509_PEM_SEC1_BEGIN "-----BEGIN EC PRIVATE KEY-----"
#define QSC_X509_PEM_SEC1_END "-----END EC PRIVATE KEY-----"
#define QSC_X509_PEM_LABEL_PREFIX "-----BEGIN "

static const char* x509_mem_find(const char* data, size_t datalen, const char* token)
{
    const char* ret;
    size_t toklen;

    ret = NULL;
    toklen = 0U;

    if ((data != NULL) && (token != NULL))
    {
        toklen = qsc_stringutils_string_size(token);

        if ((toklen != 0U) && (toklen <= datalen))
        {
            for (size_t i = 0U; i <= (datalen - toklen); ++i)
            {
                if (qsc_memutils_are_equal((const uint8_t*)(data + i), (const uint8_t*)token, toklen) == true)
                {
                    ret = data + i;
                    break;
                }
            }
        }
    }

    return ret;
}

static bool x509_pem_region_has_nested_begin(const char* begin, size_t regionlen)
{
    const char* next;
    const char* search;
    size_t remain;

    if ((begin == NULL) || (regionlen == 0U))
    {
        return false;
    }

    if (regionlen <= qsc_stringutils_string_size(QSC_X509_PEM_LABEL_PREFIX))
    {
        return false;
    }

    search = begin + qsc_stringutils_string_size(QSC_X509_PEM_LABEL_PREFIX);
    remain = regionlen - qsc_stringutils_string_size(QSC_X509_PEM_LABEL_PREFIX);
    next = x509_mem_find(search, remain, QSC_X509_PEM_LABEL_PREFIX);

    return (next != NULL);
}


static const char* x509_find_begin_label(const char* pem, size_t pemlen, const char* label)
{
    return x509_mem_find(pem, pemlen, label);
}

static const char* x509_find_end_label(const char* pem, size_t pemlen, const char* label)
{
    return x509_mem_find(pem, pemlen, label);
}

static qsc_asn1_status x509_decode_pem_region_der(const char* begin, size_t length, uint8_t* der, size_t dercapacity, size_t* derlen)
{
    char* region;
    qsc_asn1_status status;

    if (begin == NULL || der == NULL || derlen == NULL || length == 0U)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if ((length == SIZE_MAX) || (dercapacity == 0U))
    {
        return QSC_ASN1_STATUS_OUT_OF_RANGE;
    }

    if (x509_pem_region_has_nested_begin(begin, length) == true)
    {
        return QSC_ASN1_STATUS_INVALID_ENCODING;
    }

    region = (char*)qsc_memutils_malloc(length + 1U);

    if (region == NULL)
    {
        return QSC_ASN1_STATUS_FAILURE;
    }

    qsc_memutils_copy(region, begin, length);
    region[length] = '\0';
    *derlen = 0U;
    status = qsc_encoding_pem_decode(region, length + 1U, der, dercapacity, derlen) ? QSC_ASN1_STATUS_SUCCESS : QSC_ASN1_STATUS_INVALID_ENCODING;
    qsc_memutils_secure_erase((uint8_t*)region, length + 1U);
    qsc_memutils_alloc_free(region);

    return status;
}

static qsc_asn1_status x509_find_pem_region(const char* pem, size_t pemlen, const char* beginlabel, const char* endlabel, const char** begin, size_t* regionlen)
{
    const char* b;
    const char* e;
    size_t beginlen;
    size_t endlen;
    size_t remain;
    size_t total;

    if (pem == NULL || beginlabel == NULL || endlabel == NULL || begin == NULL || regionlen == NULL || pemlen == 0U)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    beginlen = qsc_stringutils_string_size(beginlabel);
    endlen = qsc_stringutils_string_size(endlabel);

    if ((beginlen == 0U) || (endlen == 0U) || (beginlen > pemlen))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    b = x509_find_begin_label(pem, pemlen, beginlabel);

    if (b == NULL)
    {
        return QSC_ASN1_STATUS_NOT_FOUND;
    }

    remain = pemlen - (size_t)(b - pem);
    e = x509_find_end_label(b, remain, endlabel);

    if ((e == NULL) || (e < b) || ((size_t)(e - b) > remain) || (endlen > (remain - (size_t)(e - b))))
    {
        return QSC_ASN1_STATUS_INVALID_ENCODING;
    }

    total = (size_t)(e - b) + endlen;

    if ((total == 0U) || (total > remain))
    {
        return QSC_ASN1_STATUS_INVALID_ENCODING;
    }

    if (x509_pem_region_has_nested_begin(b, total) == true)
    {
        return QSC_ASN1_STATUS_INVALID_ENCODING;
    }

    *begin = b;
    *regionlen = total;

    return QSC_ASN1_STATUS_SUCCESS;
}

static qsc_asn1_status x509_find_private_key_region(const char* pem, size_t pemlen, const char** begin, size_t* regionlen)
{
    qsc_asn1_status status;

    status = x509_find_pem_region(pem, pemlen, QSC_X509_PEM_PKCS8_BEGIN, QSC_X509_PEM_PKCS8_END, begin, regionlen);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        status = x509_find_pem_region(pem, pemlen, QSC_X509_PEM_MLDSA_PKCS8_BEGIN, QSC_X509_PEM_MLDSA_PKCS8_END, begin, regionlen);
    }

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        status = x509_find_pem_region(pem, pemlen, QSC_X509_PEM_MLKEM_PKCS8_BEGIN, QSC_X509_PEM_MLKEM_PKCS8_END, begin, regionlen);
    }

    return status;
}

static qsc_asn1_status x509_decode_pem_region(const char* begin, size_t length, qsc_x509_certificate* certificate)
{
    qsc_asn1_status status;
    uint8_t* der;
    size_t derlen;

    if ((begin == NULL) || (certificate == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    der = (uint8_t*)qsc_memutils_malloc(QSC_X509_PEM_DER_MAX);

    if (der == NULL)
    {
        return QSC_ASN1_STATUS_FAILURE;
    }

    qsc_memutils_clear(der, QSC_X509_PEM_DER_MAX);
    derlen = 0U;
    status = x509_decode_pem_region_der(begin, length, der, QSC_X509_PEM_DER_MAX, &derlen);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        qsc_memutils_secure_erase(der, QSC_X509_PEM_DER_MAX);
        qsc_memutils_alloc_free(der);
        return status;
    }

    if ((derlen == 0U) || (derlen > QSC_X509_PEM_DER_MAX))
    {
        qsc_memutils_secure_erase(der, QSC_X509_PEM_DER_MAX);
        qsc_memutils_alloc_free(der);
        return QSC_ASN1_STATUS_INVALID_ENCODING;
    }

    status = qsc_x509_certificate_decode_der(der, derlen, certificate);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        qsc_memutils_secure_erase(der, QSC_X509_PEM_DER_MAX);
        qsc_memutils_alloc_free(der);
    }
    else
    {
        certificate->derowned = true;
    }

    return status;
}

static qsc_asn1_status x509_encode_pem_label(const char* label, const uint8_t* der, size_t derlen, char* pem, size_t* pemlen)
{
    size_t required = 0U;

    if (((der == NULL) && (derlen != 0U)) || (label == NULL) || (pemlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if ((pem == NULL) || (*pemlen == 0U))
    {
        if (qsc_encoding_pem_encode(label, NULL, 0U, der, derlen) == false)
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        /* the encoding module does not expose a pure sizing API.
         * use a conservative upper bound: PEM header/footer plus base64 expansion and line breaks. */
        {
            const size_t b64len = (((derlen + 2U) / 3U) * 4U);
            const size_t linebreaks = (b64len + 63U) / 64U;
            required = (qsc_stringutils_string_size(label) * 2U) + b64len + linebreaks + 68U;
        }
        *pemlen = required;
        return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    if (qsc_encoding_pem_encode(label, pem, *pemlen, der, derlen) == false)
    {
        {
            const size_t b64len = (((derlen + 2U) / 3U) * 4U);
            const size_t linebreaks = (b64len + 63U) / 64U;
            required = (qsc_stringutils_string_size(label) * 2U) + b64len + linebreaks + 68U;
        }
        *pemlen = required;
        return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    *pemlen = qsc_stringutils_string_size(pem) + 1U;
    return QSC_ASN1_STATUS_SUCCESS;
}

qsc_asn1_status qsc_x509_certificate_decode_pem(const char* pem, size_t pemlen, qsc_x509_certificate* certificate)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(certificate != NULL);

    const char* begin = NULL;
    const char* end = NULL;
    size_t regionlen = 0U;

    if ((pem == NULL) || (certificate == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    begin = x509_find_begin_label(pem, pemlen, QSC_X509_PEM_CERT_BEGIN);
    end = x509_find_end_label(pem, pemlen, QSC_X509_PEM_CERT_END);

    if ((begin == NULL) || (end == NULL) || (end <= begin))
    {
        return QSC_ASN1_STATUS_NOT_FOUND;
    }

    regionlen = (size_t)((end - begin) + qsc_stringutils_string_size(QSC_X509_PEM_CERT_END));

    if (((size_t)(begin - pem) >= pemlen) || (regionlen > (pemlen - (size_t)(begin - pem))))
    {
        return QSC_ASN1_STATUS_INVALID_ENCODING;
    }

    return x509_decode_pem_region(begin, regionlen, certificate);
}

qsc_asn1_status qsc_x509_chain_decode_pem_bundle(const char* pem, size_t pemlen, qsc_x509_certificate* certificates, size_t certcount, qsc_x509_chain* chain)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(certificates != NULL);
    QSC_ASSERT(chain != NULL);

    const char* cur = NULL;
    size_t count = 0U;
    qsc_asn1_status status = QSC_ASN1_STATUS_NOT_FOUND;

    if ((pem == NULL) || (certificates == NULL) || (chain == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    chain->certificates = certificates;
    chain->count = 0U;
    cur = pem;

    while (cur < (pem + pemlen))
    {
        const char* begin = NULL;
        const char* end = NULL;
        size_t regionlen = 0U;

        begin = x509_find_begin_label(cur, (size_t)((pem + pemlen) - cur), QSC_X509_PEM_CERT_BEGIN);

        if (begin == NULL)
        {
            break;
        }

        end = x509_find_end_label(begin, (size_t)((pem + pemlen) - begin), QSC_X509_PEM_CERT_END);

        if (end == NULL)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
            break;
        }

        if (count >= certcount)
        {
            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            break;
        }

        regionlen = (size_t)((end - begin) + qsc_stringutils_string_size(QSC_X509_PEM_CERT_END));

        if (regionlen > (size_t)((pem + pemlen) - begin))
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
            break;
        }

        status = x509_decode_pem_region(begin, regionlen, &certificates[count]);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            break;
        }

        count += 1U;
        cur = end + qsc_stringutils_string_size(QSC_X509_PEM_CERT_END);
    }

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        size_t i;

        for (i = 0U; i < count; ++i)
        {
            qsc_x509_certificate_free(&certificates[i]);
        }

        chain->count = 0U;
        return status;
    }

    chain->count = count;
    return (count == 0U) ? QSC_ASN1_STATUS_NOT_FOUND : QSC_ASN1_STATUS_SUCCESS;
}

qsc_asn1_status qsc_x509_store_load_pem_bundle(const char* pem, size_t pemlen, qsc_x509_trust_anchor* anchors, size_t anchorcount, qsc_x509_store* store)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(anchors != NULL);
    QSC_ASSERT(store != NULL);

    qsc_x509_chain chain;
    size_t i = 0U;
    qsc_asn1_status status = QSC_ASN1_STATUS_SUCCESS;

    if ((pem == NULL) || (anchors == NULL) || (store == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    chain.certificates = (qsc_x509_certificate*)anchors;
    chain.count = 0U;
    status = qsc_x509_chain_decode_pem_bundle(pem, pemlen, (qsc_x509_certificate*)anchors, anchorcount, &chain);

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        for (i = 0U; i < chain.count; ++i)
        {
            qsc_x509_verify_state verifystate;
            uint8_t verifybuffer[QSC_X509_CERTIFICATE_WRITE_MAX];

            qsc_x509_qsc_verify_state_initialize(&verifystate, verifybuffer, sizeof(verifybuffer));
            anchors[i].selfsigned = qsc_x509_certificate_is_self_signed(&anchors[i].certificate, qsc_x509_qsc_signature_verify, &verifystate);
        }

        store->anchors = anchors;
        store->count = chain.count;
    }

    return status;
}

qsc_asn1_status qsc_x509_crl_decode_pem(const char* pem, size_t pemlen, qsc_x509_crl* crl)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(crl != NULL);

    const char* begin;
    size_t regionlen;
    uint8_t* der;
    size_t derlen;
    qsc_asn1_status status;

    if (pem == NULL || crl == NULL)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    status = x509_find_pem_region(pem, pemlen, QSC_X509_PEM_CRL_BEGIN, QSC_X509_PEM_CRL_END, &begin, &regionlen);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    der = (uint8_t*)qsc_memutils_malloc(QSC_X509_PEM_DER_MAX);

    if (der == NULL)
    {
        return QSC_ASN1_STATUS_FAILURE;
    }

    qsc_memutils_clear(der, QSC_X509_PEM_DER_MAX);
    derlen = 0U;
    status = x509_decode_pem_region_der(begin, regionlen, der, QSC_X509_PEM_DER_MAX, &derlen);

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        status = qsc_x509_crl_decode_der(der, derlen, crl);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            /* Preserve the decoded DER backing store so crl->der and crl->tbsdata
             * remain valid for later signature verification. */
            crl->der = der;
            crl->derlen = derlen;
            return status;
        }
    }

    qsc_memutils_secure_erase(der, QSC_X509_PEM_DER_MAX);
    qsc_memutils_alloc_free(der);
    return status;
}

void qsc_x509_chain_free(qsc_x509_chain* chain)
{
    QSC_ASSERT(chain != NULL);

    size_t i;

    if (chain != (qsc_x509_chain*)NULL && chain->certificates != (qsc_x509_certificate*)NULL)
    {
        for (i = 0U; i < chain->count; ++i)
        {
            qsc_x509_certificate_free(&chain->certificates[i]);
        }

        chain->count = 0U;
    }
}

void qsc_x509_store_free(qsc_x509_store* store)
{
    QSC_ASSERT(store != NULL);

    size_t i;

    if (store != (qsc_x509_store*)NULL && store->anchors != (qsc_x509_trust_anchor*)NULL)
    {
        for (i = 0U; i < store->count; ++i)
        {
            qsc_x509_certificate_free(&store->anchors[i].certificate);
            store->anchors[i].selfsigned = false;
        }

        store->count = 0U;
    }
}

qsc_asn1_status qsc_x509_pem_encode_certificate(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen)
{
    return x509_encode_pem_label("CERTIFICATE", der, derlen, pem, pemlen);
}

qsc_asn1_status qsc_x509_pem_encode_crl(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen)
{
    return x509_encode_pem_label("X509 CRL", der, derlen, pem, pemlen);
}

qsc_asn1_status qsc_x509_csr_decode_pem_from_bundle(const char* pem, size_t pemlen, qsc_x509_csr* csr)
{
    return qsc_x509_csr_decode_pem(csr, pem, pemlen);
}

qsc_asn1_status qsc_x509_pem_encode_csr(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen)
{
    return qsc_x509_csr_encode_pem(der, derlen, pem, pemlen);
}

qsc_asn1_status qsc_x509_private_key_decode_sec1_pem_from_bundle(const char* pem, size_t pemlen, qsc_x509_private_key* key)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(key != NULL);

    char region[(QSC_X509_PEM_DER_MAX * 3U) + 256U] = { 0 };
    const char* begin;
    size_t regionlen;

    if (pem == NULL || key == NULL)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (x509_find_pem_region(pem, pemlen, QSC_X509_PEM_SEC1_BEGIN, QSC_X509_PEM_SEC1_END, &begin, &regionlen) != QSC_ASN1_STATUS_SUCCESS)
    {
        return QSC_ASN1_STATUS_NOT_FOUND;
    }

    if (regionlen >= sizeof(region))
    {
        return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    qsc_memutils_clear(region, sizeof(region));
    qsc_memutils_copy(region, begin, regionlen);
    {
        qsc_asn1_status status;

        status = qsc_x509_private_key_decode_sec1_pem(region, regionlen + 1U, key);
        qsc_memutils_secure_erase((uint8_t*)region, sizeof(region));
        return status;
    }
}

qsc_asn1_status qsc_x509_private_key_decode_pkcs8_pem_from_bundle(const char* pem, size_t pemlen, qsc_x509_private_key* key)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(key != NULL);

    char region[(QSC_X509_PEM_DER_MAX * 3U) + 256U] = { 0 };
    const char* begin;
    size_t regionlen;

    if (pem == NULL || key == NULL)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (x509_find_private_key_region(pem, pemlen, &begin, &regionlen) != QSC_ASN1_STATUS_SUCCESS)
    {
        return QSC_ASN1_STATUS_NOT_FOUND;
    }

    if (regionlen >= sizeof(region))
    {
        return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    qsc_memutils_clear(region, sizeof(region));
    qsc_memutils_copy(region, begin, regionlen);

    {
        qsc_asn1_status status;

        status = qsc_x509_private_key_decode_pkcs8_pem(region, regionlen + 1U, key);
        qsc_memutils_secure_erase((uint8_t*)region, sizeof(region));
        return status;
    }
}

qsc_asn1_status qsc_x509_private_key_decode_pem_from_bundle(const char* pem, size_t pemlen, qsc_x509_private_key* key)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(key != NULL);

    qsc_asn1_status status;

    status = qsc_x509_private_key_decode_pkcs8_pem_from_bundle(pem, pemlen, key);

    if (status == QSC_ASN1_STATUS_NOT_FOUND)
    {
        status = qsc_x509_private_key_decode_sec1_pem_from_bundle(pem, pemlen, key);
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_decode_pkcs8_pem_ex_from_bundle(const char* pem, size_t pemlen, qsc_x509_algorithm_identifier* algorithm, uint8_t* privatekey, 
    size_t privatekeycapacity, size_t* privatekeylen, uint8_t* publickey, size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(algorithm != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(privatekeylen != NULL);

    char region[(QSC_X509_PEM_DER_MAX * 3U) + 256U] = { 0 };
    const char* begin;
    size_t regionlen;

    if (pem == NULL || algorithm == NULL || privatekey == NULL || privatekeylen == NULL)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (x509_find_private_key_region(pem, pemlen, &begin, &regionlen) != QSC_ASN1_STATUS_SUCCESS)
    {
        return QSC_ASN1_STATUS_NOT_FOUND;
    }

    if (regionlen >= sizeof(region))
    {
        return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }

    qsc_memutils_clear(region, sizeof(region));
    qsc_memutils_copy(region, begin, regionlen);
    {
        qsc_asn1_status status;

        status = qsc_x509_private_key_decode_pkcs8_pem_ex(region, regionlen + 1U, algorithm, privatekey, privatekeycapacity, privatekeylen, publickey, publickeycapacity, publickeylen, publickeypresent);
        qsc_memutils_secure_erase((uint8_t*)region, sizeof(region));
        return status;
    }
}

qsc_asn1_status qsc_x509_pem_encode_private_key_pkcs8(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen)
{
    return x509_encode_pem_label("PRIVATE KEY", der, derlen, pem, pemlen);
}

qsc_asn1_status qsc_x509_pem_encode_private_key_sec1(const uint8_t* der, size_t derlen, char* pem, size_t* pemlen)
{
    return x509_encode_pem_label("EC PRIVATE KEY", der, derlen, pem, pemlen);
}

qsc_asn1_status qsc_x509_pem_encode_private_key_pkcs8_from_key(const qsc_x509_private_key* key, bool includepublickey, char* pem, size_t* pemlen)
{
    return qsc_x509_private_key_encode_pkcs8_pem(key, includepublickey, pem, pemlen);
}

qsc_asn1_status qsc_x509_pem_encode_private_key_sec1_from_key(const qsc_x509_private_key* key, bool includeparameters, bool includepublickey, char* pem, size_t* pemlen)
{
    return qsc_x509_private_key_encode_sec1_pem(key, includeparameters, includepublickey, pem, pemlen);
}
