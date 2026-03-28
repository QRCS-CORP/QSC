#include "x509key.h"
#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "x509keywrite.h"
#include "x509pem.h"
#include "x509spki.h"
#include "ecdsap256base.h"
#include "ecdsap384base.h"
#include "ecdsap521base.h"

#define X509_CERTIFICATE_KEY_MATCH 66U

static size_t x509_curve_scalar_size(qsc_x509_named_curve curve)
{
    size_t res = 0U;

    if (curve == QSC_X509_NAMED_CURVE_PRIME256V1)
    {
        res = 32U;
    }
    else if (curve == QSC_X509_NAMED_CURVE_SECP384R1)
    {
        res = 48U;
    }
    else if (curve == QSC_X509_NAMED_CURVE_SECP521R1)
    {
        res = 66U;
    }

    return res;
}

static size_t x509_curve_public_key_size(qsc_x509_named_curve curve)
{
    size_t res = 0U;

    if (curve == QSC_X509_NAMED_CURVE_PRIME256V1)
    {
        res = 64U;
    }
    else if (curve == QSC_X509_NAMED_CURVE_SECP384R1)
    {
        res = 96U;
    }
    else if (curve == QSC_X509_NAMED_CURVE_SECP521R1)
    {
        res = 132U;
    }

    return res;
}

static qsc_asn1_status x509_decode_curve_from_explicit_parameters(const qsc_encoding_ber_element* element, qsc_x509_named_curve* curve)
{
    qsc_asn1_oid oid = { 0 };
    const qsc_encoding_ber_element* child;
    qsc_oid_id oidid;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    child = (const qsc_encoding_ber_element*)NULL;
    oidid = QSC_OID_ID_NONE;

    if (element == (const qsc_encoding_ber_element*)NULL || curve == (qsc_x509_named_curve*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 0U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_asn1_get_explicit_child(element, &child);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_asn1_decode_oid(child, &oid);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    oidid = qsc_oid_identify(&oid);
                    *curve = QSC_X509_NAMED_CURVE_NONE;

                    if (oidid == QSC_OID_ID_PRIME256V1)
                    {
                        *curve = QSC_X509_NAMED_CURVE_PRIME256V1;
                    }
                    else if (oidid == QSC_OID_ID_SECP384R1)
                    {
                        *curve = QSC_X509_NAMED_CURVE_SECP384R1;
                    }
                    else if (oidid == QSC_OID_ID_SECP521R1)
                    {
                        *curve = QSC_X509_NAMED_CURVE_SECP521R1;
                    }
                    else
                    {
                        status = QSC_ASN1_STATUS_UNSUPPORTED;
                    }
                }
            }
        }
    }

    return status;
}

static qsc_asn1_status x509_decode_public_key_from_explicit_bit_string(const qsc_encoding_ber_element* element, qsc_x509_private_key* key)
{
    qsc_asn1_bit_string bitstr = { 0 };
    const qsc_encoding_ber_element* child;
    size_t explen;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    child = (const qsc_encoding_ber_element*)NULL;
    explen = 0U;

    if (element == (const qsc_encoding_ber_element*)NULL || key == (qsc_x509_private_key*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        status = qsc_asn1_require_tag(element, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 1U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_asn1_get_explicit_child(element, &child);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_asn1_decode_bit_string(child, &bitstr);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    explen = qsc_x509_named_curve_public_key_size(key->algorithm.curve);

                    if (bitstr.unused != 0U || bitstr.length != explen || explen < 1U || bitstr.data[0U] != 0x04U)
                    {
                        status = QSC_ASN1_STATUS_INVALID_ENCODING;
                    }
                    else if ((bitstr.length - 1U) > sizeof(key->publickey))
                    {
                        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                    }
                    else
                    {
                        qsc_memutils_copy(key->publickey, bitstr.data + 1U, bitstr.length - 1U);
                        key->publickeylen = bitstr.length - 1U;
                        key->publickey_present = true;
                    }
                }
            }
        }
    }

    return status;
}

static qsc_asn1_status x509_decode_ec_private_key_element(const qsc_encoding_ber_element* element, qsc_x509_named_curve expected_curve, qsc_x509_private_key* key)
{
    uint8_t scalar[QSC_X509_PRIVATE_KEY_MAX] = { 0U };
    const qsc_encoding_ber_element* child;
    uint64_t version;
    size_t scalarlen;
    size_t explen;
    size_t i;
    qsc_x509_named_curve inner_curve;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    child = (const qsc_encoding_ber_element*)NULL;
    version = 0U;
    scalarlen = 0U;
    explen = 0U;
    inner_curve = QSC_X509_NAMED_CURVE_NONE;

    if (element == (const qsc_encoding_ber_element*)NULL || key == (qsc_x509_private_key*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        status = qsc_asn1_require_sequence(element, 2U, 4U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, 0U);

            if (child == (const qsc_encoding_ber_element*)NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                status = qsc_asn1_decode_integer_u64(child, &version);
            }

            if (status == QSC_ASN1_STATUS_SUCCESS && version != 1U)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                child = qsc_asn1_get_child(element, 1U);

                if (child == (const qsc_encoding_ber_element*)NULL)
                {
                    status = QSC_ASN1_STATUS_NOT_FOUND;
                }
                else
                {
                    status = qsc_asn1_decode_octet_string(child, scalar, sizeof(scalar), &scalarlen);
                }
            }

            for (i = 2U; status == QSC_ASN1_STATUS_SUCCESS && i < qsc_asn1_child_count(element); ++i)
            {
                child = qsc_asn1_get_child(element, i);

                if (child != (const qsc_encoding_ber_element*)NULL)
                {
                    if (qsc_asn1_element_is_tag(child, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 0U) == true)
                    {
                        status = x509_decode_curve_from_explicit_parameters(child, &inner_curve);
                    }
                    else if (qsc_asn1_element_is_tag(child, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 1U) == true)
                    {
                        if (key->algorithm.curve == QSC_X509_NAMED_CURVE_NONE)
                        {
                            if (inner_curve != QSC_X509_NAMED_CURVE_NONE)
                            {
                                key->algorithm.curve = inner_curve;
                            }
                            else if (expected_curve != QSC_X509_NAMED_CURVE_NONE)
                            {
                                key->algorithm.curve = expected_curve;
                            }
                        }

                        status = x509_decode_public_key_from_explicit_bit_string(child, key);
                    }
                    else
                    {
                        status = QSC_ASN1_STATUS_UNSUPPORTED;
                    }
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                if (expected_curve != QSC_X509_NAMED_CURVE_NONE && inner_curve != QSC_X509_NAMED_CURVE_NONE && expected_curve != inner_curve)
                {
                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                }
                else if (inner_curve != QSC_X509_NAMED_CURVE_NONE)
                {
                    key->algorithm.curve = inner_curve;
                }
                else if (expected_curve != QSC_X509_NAMED_CURVE_NONE)
                {
                    key->algorithm.curve = expected_curve;
                }
                else
                {
                    status = QSC_ASN1_STATUS_NOT_FOUND;
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                key->algorithm.publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_EC;
                key->algorithm.oid = QSC_OID_ID_EC_PUBLIC_KEY;
                key->algorithm.parameters_present = true;
                key->algorithm.parameters_null = false;
                key->algorithm.parameters_oid = true;
                explen = x509_curve_scalar_size(key->algorithm.curve);

                if (explen == 0U)
                {
                    status = QSC_ASN1_STATUS_UNSUPPORTED;
                }
                else if (scalarlen != explen)
                {
                    status = QSC_ASN1_STATUS_INVALID_LENGTH;
                }
                else
                {
                    qsc_memutils_copy(key->privatekey, scalar, explen);
                    key->privatekeylen = explen;
                }
            }
        }
    }

    qsc_memutils_secure_erase(scalar, sizeof(scalar));
    return status;
}

static qsc_asn1_status x509_private_key_decode_pkcs8_root_ex(const qsc_encoding_ber_element* root, qsc_x509_algorithm_identifier* algorithm, uint8_t* privatekey, 
    size_t privatekeycapacity, size_t* privatekeylen, uint8_t* publickey, size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent)
{
    uint8_t* octets;
    const qsc_encoding_ber_element* child;
    qsc_encoding_ber_element* inner;
    uint64_t version;
    size_t octetlen;
    size_t consumed;
    size_t i;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    octets = (uint8_t*)NULL;
    child = (const qsc_encoding_ber_element*)NULL;
    inner = (qsc_encoding_ber_element*)NULL;
    version = 0U;
    octetlen = 0U;
    consumed = 0U;

    if (algorithm == (qsc_x509_algorithm_identifier*)NULL || privatekey == (uint8_t*)NULL || privatekeylen == (size_t*)NULL)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    *privatekeylen = 0U;

    if (publickeylen != (size_t*)NULL)
    {
        *publickeylen = 0U;
    }

    if (publickeypresent != (bool*)NULL)
    {
        *publickeypresent = false;
    }

    octets = (uint8_t*)qsc_memutils_malloc(QSC_X509_KEY_WRITE_MAX);

    if (octets == (uint8_t*)NULL)
    {
        return QSC_ASN1_STATUS_FAILURE;
    }

    qsc_memutils_clear(octets, QSC_X509_KEY_WRITE_MAX);
    status = qsc_asn1_require_sequence(root, 3U, 5U);

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        child = qsc_asn1_get_child(root, 0U);
        status = (child == (const qsc_encoding_ber_element*)NULL) ? QSC_ASN1_STATUS_NOT_FOUND : qsc_asn1_decode_integer_u64(child, &version);
    }

    if (status == QSC_ASN1_STATUS_SUCCESS && version != 0U && version != 1U)
    {
        status = QSC_ASN1_STATUS_INVALID_ENCODING;
    }

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        child = qsc_asn1_get_child(root, 1U);
        status = (child == (const qsc_encoding_ber_element*)NULL) ? QSC_ASN1_STATUS_NOT_FOUND : qsc_x509_algorithm_identifier_decode(child, algorithm);
    }

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        child = qsc_asn1_get_child(root, 2U);
        status = (child == (const qsc_encoding_ber_element*)NULL) ? QSC_ASN1_STATUS_NOT_FOUND : qsc_asn1_decode_octet_string(child, octets, QSC_X509_KEY_WRITE_MAX, &octetlen);
    }

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC)
        {
            qsc_x509_private_key tmpkey = { 0 };

            inner = qsc_encoding_der_decode_element(octets, octetlen, &consumed);

            if (inner == (qsc_encoding_ber_element*)NULL || consumed != octetlen)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else
            {
                status = x509_decode_ec_private_key_element(inner, algorithm->curve, &tmpkey);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    if (privatekeycapacity < tmpkey.privatekeylen)
                    {
                        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                    }
                    else
                    {
                        qsc_memutils_copy(privatekey, tmpkey.privatekey, tmpkey.privatekeylen);
                        *privatekeylen = tmpkey.privatekeylen;
                    }

                    if (status == QSC_ASN1_STATUS_SUCCESS && publickey != (uint8_t*)NULL && publickeylen != (size_t*)NULL && tmpkey.publickey_present == true)
                    {
                        if (publickeycapacity < tmpkey.publickeylen)
                        {
                            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                        }
                        else
                        {
                            qsc_memutils_copy(publickey, tmpkey.publickey, tmpkey.publickeylen);
                            *publickeylen = tmpkey.publickeylen;
                            if (publickeypresent != (bool*)NULL)
                            {
                                *publickeypresent = true;
                            }
                        }
                    }
                }
            }

            qsc_memutils_secure_erase((uint8_t*)&tmpkey, sizeof(qsc_x509_private_key));
        }
        else
        {
            if (privatekeycapacity < octetlen)
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                qsc_memutils_copy(privatekey, octets, octetlen);
                *privatekeylen = octetlen;
                status = QSC_ASN1_STATUS_SUCCESS;
            }

            for (i = 3U; status == QSC_ASN1_STATUS_SUCCESS && i < qsc_asn1_child_count(root); ++i)
            {
                qsc_asn1_bit_string bitstr = { 0 };
                const qsc_encoding_ber_element* opt = qsc_asn1_get_child(root, i);

                if (opt != (const qsc_encoding_ber_element*)NULL && qsc_asn1_element_is_tag(opt, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, true, 1U) == true && publickey != (uint8_t*)NULL && publickeylen != (size_t*)NULL)
                {
                    const qsc_encoding_ber_element* exchild = (const qsc_encoding_ber_element*)NULL;
                    status = qsc_asn1_get_explicit_child(opt, &exchild);

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        status = qsc_asn1_decode_bit_string(exchild, &bitstr);
                    }

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        if (bitstr.unused != 0U)
                        {
                            status = QSC_ASN1_STATUS_INVALID_ENCODING;
                        }
                        else if (publickeycapacity < bitstr.length)
                        {
                            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                        }
                        else
                        {
                            qsc_memutils_copy(publickey, bitstr.data, bitstr.length);
                            *publickeylen = bitstr.length;
                            if (publickeypresent != (bool*)NULL)
                            {
                                *publickeypresent = true;
                            }
                        }
                    }
                }
            }
        }
    }

    if (inner != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(inner);
    }

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        bool haspublickey;

        haspublickey = ((publickeypresent != (bool*)NULL) && (*publickeypresent == true));

        if ((version == 0U) && (haspublickey == true))
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if ((version == 1U) && (haspublickey == false))
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }

    if (octets != (uint8_t*)NULL)
    {
        qsc_memutils_secure_erase(octets, QSC_X509_KEY_WRITE_MAX);
        qsc_memutils_alloc_free(octets);
    }

    return status;
}

static qsc_asn1_status x509_private_key_decode_pkcs8_root(const qsc_encoding_ber_element* root, qsc_x509_private_key* key)
{
    size_t privatekeylen;
    size_t publickeylen;
    qsc_asn1_status status;
    bool publickeypresent;

    if ((root == (const qsc_encoding_ber_element*)NULL) || (key == (qsc_x509_private_key*)NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_x509_private_key_initialize(key);
        privatekeylen = 0U;
        publickeylen = 0U;
        publickeypresent = false;

        status = x509_private_key_decode_pkcs8_root_ex(root, &key->algorithm,
            key->privatekey, sizeof(key->privatekey), &privatekeylen,
            key->publickey, sizeof(key->publickey), &publickeylen, &publickeypresent);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            key->privatekeylen = privatekeylen;
            key->publickeylen = publickeylen;
            key->publickey_present = publickeypresent;
            status = qsc_x509_private_key_validate(key);
        }
    }

    return status;
}

static qsc_asn1_status x509_private_key_decode_pem_generic(const char* pem, size_t pemlen, qsc_x509_private_key* key, bool pkcs8)
{
    qsc_asn1_status status;
    uint8_t* der;
    size_t derlen;

    status = QSC_ASN1_STATUS_FAILURE;
    der = (uint8_t*)NULL;
    derlen = 0U;

    if (pem == (const char*)NULL || key == (qsc_x509_private_key*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        der = (uint8_t*)qsc_memutils_malloc(QSC_X509_PEM_DER_MAX);

        if (der == (uint8_t*)NULL)
        {
            status = QSC_ASN1_STATUS_FAILURE;
        }
        else if (qsc_encoding_pem_decode(pem, pemlen, der, QSC_X509_PEM_DER_MAX, &derlen) == false)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if (pkcs8 == true)
        {
            status = qsc_x509_private_key_decode_pkcs8_der(der, derlen, key);
        }
        else
        {
            status = qsc_x509_private_key_decode_sec1_der(der, derlen, key);
        }
    }

    if (der != (uint8_t*)NULL)
    {
        qsc_memutils_secure_erase(der, QSC_X509_PEM_DER_MAX);
        qsc_memutils_alloc_free(der);
    }

    return status;
}

static bool x509_private_key_derive_public(uint8_t* publickey, qsc_x509_named_curve curve, const uint8_t* privatekey)
{
    bool res;

    res = false;

    if (publickey != (uint8_t*)NULL && privatekey != (const uint8_t*)NULL)
    {
        if (curve == QSC_X509_NAMED_CURVE_PRIME256V1)
        {
            res = (qsc_p256_publickey_from_privatekey(publickey, privatekey) == 0);
        }
        else if (curve == QSC_X509_NAMED_CURVE_SECP384R1)
        {
            res = (qsc_p384_publickey_from_privatekey(publickey, privatekey) == 0);
        }
        else if (curve == QSC_X509_NAMED_CURVE_SECP521R1)
        {
            res = (qsc_p521_publickey_from_privatekey(publickey, privatekey) == 0);
        }
    }

    return res;
}

qsc_asn1_status qsc_x509_private_key_validate(const qsc_x509_private_key* key)
{
    qsc_asn1_status status;
    size_t expectedpriv;
    size_t expectedpub;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    expectedpriv = 0U;
    expectedpub = 0U;

    if (key != (const qsc_x509_private_key*)NULL)
    {
        status = qsc_x509_algorithm_identifier_validate(&key->algorithm);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            expectedpriv = qsc_x509_private_key_expected_private_size(&key->algorithm);

            if ((expectedpriv == 0U) || (key->privatekeylen != expectedpriv))
            {
                status = (expectedpriv == 0U) ? QSC_ASN1_STATUS_UNSUPPORTED : QSC_ASN1_STATUS_INVALID_LENGTH;
            }
        }

        if ((status == QSC_ASN1_STATUS_SUCCESS) && (key->publickey_present == true))
        {
            expectedpub = qsc_x509_private_key_expected_public_size(&key->algorithm);

            if ((expectedpub == 0U) || (key->publickeylen != expectedpub))
            {
                status = (expectedpub == 0U) ? QSC_ASN1_STATUS_UNSUPPORTED : QSC_ASN1_STATUS_INVALID_LENGTH;
            }
        }
    }

    return status;
}

size_t qsc_x509_private_key_expected_private_size(const qsc_x509_algorithm_identifier* algorithm)
{
    QSC_ASSERT(algorithm != NULL);

    size_t klen;

    klen = 0U;

    if (algorithm == (const qsc_x509_algorithm_identifier*)NULL)
    {
        klen = 0U;
    }
    else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC)
    {
        klen = x509_curve_scalar_size(algorithm->curve);
    }
    else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA)
    {
        switch (algorithm->pqcparameter)
        {
            case QSC_X509_PQC_PARAMETER_SET_ML_DSA_44:
                klen = QSC_X509_ML_DSA_44_PRIVATEKEY_SIZE;
                break;
            case QSC_X509_PQC_PARAMETER_SET_ML_DSA_65:
                klen = QSC_X509_ML_DSA_65_PRIVATEKEY_SIZE;
                break;
            case QSC_X509_PQC_PARAMETER_SET_ML_DSA_87:
                klen = QSC_X509_ML_DSA_87_PRIVATEKEY_SIZE;
                break;
            default:
                klen = 0U;
        }
    }
    else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM)
    {
        switch (algorithm->pqcparameter)
        {
            case QSC_X509_PQC_PARAMETER_SET_ML_KEM_512:
                klen = QSC_X509_ML_KEM_512_PRIVATEKEY_SIZE;
                break;
            case QSC_X509_PQC_PARAMETER_SET_ML_KEM_768:
                klen = QSC_X509_ML_KEM_768_PRIVATEKEY_SIZE;
                break;
            case QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024:
                klen = QSC_X509_ML_KEM_1024_PRIVATEKEY_SIZE;
                break;
            default:
                klen = 0U;
        }
    }

    return klen;
}

size_t qsc_x509_private_key_expected_public_size(const qsc_x509_algorithm_identifier* algorithm)
{
    QSC_ASSERT(algorithm != NULL);

    size_t klen;

    klen = 0U;

    if (algorithm == (const qsc_x509_algorithm_identifier*)NULL)
    {
        klen = 0U;
    }
    else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC)
    {
        klen = x509_curve_public_key_size(algorithm->curve);
    }
    else
    {
        if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA)
        {
            switch (algorithm->pqcparameter)
            {
            case QSC_X509_PQC_PARAMETER_SET_ML_DSA_44:
                klen = QSC_X509_ML_DSA_44_PUBLICKEY_SIZE;
                break;
            case QSC_X509_PQC_PARAMETER_SET_ML_DSA_65:
                klen = QSC_X509_ML_DSA_65_PUBLICKEY_SIZE;
                break;
            case QSC_X509_PQC_PARAMETER_SET_ML_DSA_87:
                klen = QSC_X509_ML_DSA_87_PUBLICKEY_SIZE;
                break;
            default:
                klen = 0U;
            }
        }
        else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM)
        {
            switch (algorithm->pqcparameter)
            {
            case QSC_X509_PQC_PARAMETER_SET_ML_KEM_512:
                klen = QSC_X509_ML_KEM_512_PUBLICKEY_SIZE;
                break;
            case QSC_X509_PQC_PARAMETER_SET_ML_KEM_768:
                klen = QSC_X509_ML_KEM_768_PUBLICKEY_SIZE;
                break;
            case QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024:
                klen = QSC_X509_ML_KEM_1024_PUBLICKEY_SIZE;
                break;
            default:
                klen = 0U;
            }
        }
    }

    return klen;
}

qsc_asn1_status qsc_x509_private_key_decode_pkcs8_der_ex(const uint8_t* data, size_t datalen, qsc_x509_algorithm_identifier* algorithm, uint8_t* privatekey, 
    size_t privatekeycapacity, size_t* privatekeylen, uint8_t* publickey, size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent)
{
    QSC_ASSERT(data != NULL);
    QSC_ASSERT(algorithm != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(privatekeylen != NULL);

    qsc_encoding_ber_element* root;
    size_t consumed;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    root = (qsc_encoding_ber_element*)NULL;
    consumed = 0U;

    if ((data == (const uint8_t*)NULL) || (datalen == 0U) || (algorithm == (qsc_x509_algorithm_identifier*)NULL) ||
        (privatekey == (uint8_t*)NULL) || (privatekeylen == (size_t*)NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_memutils_clear((uint8_t*)algorithm, sizeof(qsc_x509_algorithm_identifier));
        *privatekeylen = 0U;

        if (publickeylen != (size_t*)NULL)
        {
            *publickeylen = 0U;
        }

        if (publickeypresent != (bool*)NULL)
        {
            *publickeypresent = false;
        }

        root = qsc_encoding_der_decode_element(data, datalen, &consumed);

        if ((root == (qsc_encoding_ber_element*)NULL) || (consumed != datalen))
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else
        {
            status = x509_private_key_decode_pkcs8_root_ex(root, algorithm, privatekey, privatekeycapacity, privatekeylen,
                publickey, publickeycapacity, publickeylen, publickeypresent);
        }

        if (root != (qsc_encoding_ber_element*)NULL)
        {
            qsc_encoding_ber_free_element(root);
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_decode_pkcs8_pem_ex(const char* pem, size_t pemlen, qsc_x509_algorithm_identifier* algorithm, uint8_t* privatekey, 
    size_t privatekeycapacity, size_t* privatekeylen, uint8_t* publickey, size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(algorithm != NULL);
    QSC_ASSERT(privatekey != NULL);
    QSC_ASSERT(privatekeylen != NULL);

    uint8_t* der;
    size_t derlen;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    der = (uint8_t*)NULL;
    derlen = 0U;

    if (pem == (const char*)NULL || algorithm == (qsc_x509_algorithm_identifier*)NULL || privatekey == (uint8_t*)NULL || privatekeylen == (size_t*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        der = (uint8_t*)qsc_memutils_malloc(QSC_X509_PEM_DER_MAX);

        if (der == (uint8_t*)NULL)
        {
            status = QSC_ASN1_STATUS_FAILURE;
        }
        else if (qsc_encoding_pem_decode(pem, pemlen, der, QSC_X509_PEM_DER_MAX, &derlen) == false)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else
        {
            status = qsc_x509_private_key_decode_pkcs8_der_ex(der, derlen, algorithm, privatekey, privatekeycapacity, privatekeylen, publickey, publickeycapacity, publickeylen, publickeypresent);
        }
    }

    if (der != (uint8_t*)NULL)
    {
        qsc_memutils_secure_erase(der, QSC_X509_PEM_DER_MAX);
        qsc_memutils_alloc_free(der);
    }

    return status;
}

void qsc_x509_private_key_initialize(qsc_x509_private_key* key)
{
    QSC_ASSERT(key != NULL);

    if (key != (qsc_x509_private_key*)NULL)
    {
        qsc_memutils_clear((uint8_t*)key, sizeof(qsc_x509_private_key));
    }
}

qsc_asn1_status qsc_x509_private_key_decode_sec1_der(const uint8_t* data, size_t datalen, qsc_x509_private_key* key)
{
    QSC_ASSERT(data != NULL);
    QSC_ASSERT(key != NULL);

    qsc_encoding_ber_element* root;
    size_t consumed;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    root = (qsc_encoding_ber_element*)NULL;
    consumed = 0U;

    if (data == (const uint8_t*)NULL || datalen == 0U || key == (qsc_x509_private_key*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_x509_private_key_initialize(key);
        root = qsc_encoding_der_decode_element(data, datalen, &consumed);

        if (root == (qsc_encoding_ber_element*)NULL || consumed != datalen)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else
        {
            status = x509_decode_ec_private_key_element(root, QSC_X509_NAMED_CURVE_NONE, key);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_x509_private_key_validate(key);
            }
        }
    }

    if (root != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(root);
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_decode_sec1_pem(const char* pem, size_t pemlen, qsc_x509_private_key* key)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(key != NULL);

    qsc_asn1_status status;

    if ((pem != NULL) && (key != NULL))
    {
        status = x509_private_key_decode_pem_generic(pem, pemlen, key, false);
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_decode_pkcs8_der(const uint8_t* data, size_t datalen, qsc_x509_private_key* key)
{
    QSC_ASSERT(data != NULL);
    QSC_ASSERT(key != NULL);

    qsc_encoding_ber_element* root;
    size_t consumed;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    root = (qsc_encoding_ber_element*)NULL;
    consumed = 0U;

    if (data == (const uint8_t*)NULL || datalen == 0U || key == (qsc_x509_private_key*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_x509_private_key_initialize(key);
        root = qsc_encoding_der_decode_element(data, datalen, &consumed);

        if (root == (qsc_encoding_ber_element*)NULL || consumed != datalen)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else
        {
            status = x509_private_key_decode_pkcs8_root(root, key);
        }
    }

    if (root != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(root);
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_decode_pkcs8_pem(const char* pem, size_t pemlen, qsc_x509_private_key* key)
{
    QSC_ASSERT(pem != NULL);
    QSC_ASSERT(key != NULL);

    qsc_asn1_status status;

    if ((pem != NULL) && (key != NULL))
    {
        status = x509_private_key_decode_pem_generic(pem, pemlen, key, true);
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

bool qsc_x509_certificate_key_match(const qsc_x509_certificate* certificate, const qsc_x509_private_key* key)
{
    QSC_ASSERT(certificate != NULL);
    QSC_ASSERT(key != NULL);

    uint8_t certx[X509_CERTIFICATE_KEY_MATCH] = { 0U };
    uint8_t certy[X509_CERTIFICATE_KEY_MATCH] = { 0U };
    uint8_t derived[QSC_X509_PRIVATE_KEY_PUBLIC_MAX] = { 0U };
    const qsc_x509_subject_public_key_info* spki;
    size_t expectedpub;
    size_t flen;
    bool res;

    spki = (const qsc_x509_subject_public_key_info*)NULL;
    expectedpub = 0U;
    flen = 0U;
    res = false;

    if ((certificate != (const qsc_x509_certificate*)NULL) && (key != (const qsc_x509_private_key*)NULL))
    {
        spki = &certificate->subjectpublickeyinfo;

        if ((spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC) &&
            (key->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC) &&
            (spki->algorithm.curve == key->algorithm.curve))
        {
            flen = qsc_x509_named_curve_coordinate_size(key->algorithm.curve);

            if ((flen != 0U) &&
                (key->privatekeylen == x509_curve_scalar_size(key->algorithm.curve)) &&
                (qsc_x509_spki_get_ec_coordinates(spki, certx, sizeof(certx), certy, sizeof(certy)) == QSC_ASN1_STATUS_SUCCESS) &&
                (x509_private_key_derive_public(derived, key->algorithm.curve, key->privatekey) == true) &&
                (qsc_memutils_are_equal(derived, certx, flen) == true) &&
                (qsc_memutils_are_equal(derived + flen, certy, flen) == true))
            {
                res = true;
            }
        }
        else if ((spki->algorithm.publickey == key->algorithm.publickey) &&
                 ((spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) ||
                  (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM)) &&
                 (spki->algorithm.pqcparameter == key->algorithm.pqcparameter) &&
                 (key->publickey_present == true))
        {
            expectedpub = qsc_x509_private_key_expected_public_size(&key->algorithm);

            if ((expectedpub != 0U) && (spki->publickeylen == expectedpub) && (key->publickeylen == expectedpub) &&
                (qsc_memutils_are_equal(spki->publickey, key->publickey, expectedpub) == true))
            {
                res = true;
            }
        }
    }

    qsc_memutils_secure_erase(derived, sizeof(derived));

    return res;
}
