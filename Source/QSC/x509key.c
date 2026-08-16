#include "x509key.h"
#include "asn1.h"
#include "dilithium.h"
#include "eddsa.h"
#include "kyber.h"
#include "encoding.h"
#include "memutils.h"
#include "sha3.h"
#include "x509keywrite.h"
#include "x509pem.h"
#include "x509spki.h"
#include "ecdsap256base.h"
#include "ecdsap384base.h"
#include "ecdsap521base.h"

#define X509_CERTIFICATE_KEY_MATCH 66U


static bool x509_mldsa_parameter_is_active(qsc_x509_pqc_parameter_set parameter)
{
    bool res;

#if defined(QSC_DILITHIUM_S1P44)
    res = (parameter == QSC_X509_PQC_PARAMETER_SET_ML_DSA_44);
#elif defined(QSC_DILITHIUM_S3P65)
    res = (parameter == QSC_X509_PQC_PARAMETER_SET_ML_DSA_65);
#else
    res = (parameter == QSC_X509_PQC_PARAMETER_SET_ML_DSA_87);
#endif

    return res;
}

static bool x509_mlkem_parameter_is_active(qsc_x509_pqc_parameter_set parameter)
{
    bool res;

#if defined(QSC_KYBER_S1K2P512)
    res = (parameter == QSC_X509_PQC_PARAMETER_SET_ML_KEM_512);
#elif defined(QSC_KYBER_S3K3P768)
    res = (parameter == QSC_X509_PQC_PARAMETER_SET_ML_KEM_768);
#elif defined(QSC_KYBER_S5K4P1024)
    res = (parameter == QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024);
#else
    res = false;
#endif

    return res;
}

static qsc_asn1_status x509_validate_mlkem_expanded_private(const uint8_t* privatekey, size_t privatekeylen, size_t publickeylen, const uint8_t** embeddedpublic)
{
    uint8_t digest[QSC_SHA3_256_HASH_SIZE] = { 0U };
    const uint8_t* storedhash;
    size_t privatecomponentlen;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_INVALID_ENCODING;
    storedhash = (const uint8_t*)NULL;
    privatecomponentlen = 0U;

    if ((privatekey == (const uint8_t*)NULL) || (embeddedpublic == (const uint8_t**)NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((publickeylen == 0U) || (privatekeylen <= (publickeylen + (2U * QSC_KYBER_SEED_SIZE))))
    {
        status = QSC_ASN1_STATUS_INVALID_LENGTH;
    }
    else
    {
        privatecomponentlen = privatekeylen - publickeylen - (2U * QSC_KYBER_SEED_SIZE);
        *embeddedpublic = privatekey + privatecomponentlen;
        storedhash = *embeddedpublic + publickeylen;
        qsc_sha3_compute256(digest, *embeddedpublic, publickeylen);

        if (qsc_memutils_are_equal(digest, storedhash, sizeof(digest)) == true)
        {
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    qsc_memutils_secure_erase(digest, sizeof(digest));

    return status;
}

static qsc_asn1_status x509_decode_pkcs8_mldsa_private(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* octets, size_t octetlen, uint8_t* privatekey,
    size_t privatekeycapacity, size_t* privatekeylen, uint8_t* publickey, size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent)
{
    uint8_t generatedprivate[QSC_DILITHIUM_PRIVATEKEY_SIZE] = { 0U };
    uint8_t generatedpublic[QSC_DILITHIUM_PUBLICKEY_SIZE] = { 0U };
    uint8_t seed[QSC_DILITHIUM_GENERATE_SEED_SIZE] = { 0U };
    qsc_encoding_ber_element* inner;
    const qsc_encoding_ber_element* child;
    size_t expectedprivate;
    size_t expectedpublic;
    size_t generatedlen;
    size_t seedlen;
    size_t consumed;
    qsc_asn1_status status;

    inner = (qsc_encoding_ber_element*)NULL;
    child = (const qsc_encoding_ber_element*)NULL;
    expectedprivate = qsc_x509_private_key_expected_private_size(algorithm);
    expectedpublic = qsc_x509_private_key_expected_public_size(algorithm);
    generatedlen = 0U;
    seedlen = 0U;
    consumed = 0U;
    status = QSC_ASN1_STATUS_INVALID_ENCODING;

    if ((algorithm == (const qsc_x509_algorithm_identifier*)NULL) || (octets == (const uint8_t*)NULL) || (privatekey == (uint8_t*)NULL) || (privatekeylen == (size_t*)NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((expectedprivate == 0U) || (expectedpublic == 0U))
    {
        status = QSC_ASN1_STATUS_UNSUPPORTED;
    }
    else
    {
        inner = qsc_encoding_der_decode_element(octets, octetlen, &consumed);

        if ((inner == (qsc_encoding_ber_element*)NULL) || (consumed != octetlen))
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if (qsc_asn1_element_is_tag(inner, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 0U) == true)
        {
            if ((inner->length != QSC_DILITHIUM_GENERATE_SEED_SIZE) || (x509_mldsa_parameter_is_active(algorithm->pqcparameter) == false))
            {
                status = (inner->length != QSC_DILITHIUM_GENERATE_SEED_SIZE) ? QSC_ASN1_STATUS_INVALID_LENGTH : QSC_ASN1_STATUS_UNSUPPORTED;
            }
            else if ((privatekeycapacity < expectedprivate) || ((publickey != (uint8_t*)NULL) && (publickeycapacity < expectedpublic)))
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                qsc_memutils_copy(seed, inner->value, sizeof(seed));
                qsc_dilithium_seeded_generate_keypair(generatedpublic, generatedprivate, seed);
                qsc_memutils_copy(privatekey, generatedprivate, expectedprivate);
                *privatekeylen = expectedprivate;

                if ((publickey != (uint8_t*)NULL) && (publickeylen != (size_t*)NULL))
                {
                    qsc_memutils_copy(publickey, generatedpublic, expectedpublic);
                    *publickeylen = expectedpublic;

                    if (publickeypresent != (bool*)NULL)
                    {
                        *publickeypresent = true;
                    }
                }

                status = QSC_ASN1_STATUS_SUCCESS;
            }
        }
        else if (qsc_asn1_element_is_tag(inner, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OCTET_STRING) == true)
        {
            if (privatekeycapacity < expectedprivate)
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                status = qsc_asn1_decode_octet_string(inner, privatekey, privatekeycapacity, &generatedlen);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    if (generatedlen != expectedprivate)
                    {
                        qsc_memutils_secure_erase(privatekey, generatedlen);
                        status = QSC_ASN1_STATUS_INVALID_LENGTH;
                    }
                    else
                    {
                        *privatekeylen = generatedlen;
                    }
                }
            }
        }
        else if (qsc_asn1_element_is_tag(inner, QSC_ENCODING_BER_CLASS_UNIVERSAL, true, BER_ASN1_SEQUENCE) == true)
        {
            status = qsc_asn1_require_sequence(inner, 2U, 2U);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                child = qsc_asn1_get_child(inner, 0U);
                status = (child == (const qsc_encoding_ber_element*)NULL) ? QSC_ASN1_STATUS_NOT_FOUND : qsc_asn1_decode_octet_string(child, seed, sizeof(seed), &seedlen);
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (seedlen != QSC_DILITHIUM_GENERATE_SEED_SIZE))
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (x509_mldsa_parameter_is_active(algorithm->pqcparameter) == false))
            {
                status = QSC_ASN1_STATUS_UNSUPPORTED;
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                child = qsc_asn1_get_child(inner, 1U);
                status = (child == (const qsc_encoding_ber_element*)NULL) ? QSC_ASN1_STATUS_NOT_FOUND : qsc_asn1_decode_octet_string(child, privatekey, privatekeycapacity, &generatedlen);
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (generatedlen != expectedprivate))
            {
                qsc_memutils_secure_erase(privatekey, generatedlen);
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                qsc_dilithium_seeded_generate_keypair(generatedpublic, generatedprivate, seed);

                if (qsc_memutils_are_equal(privatekey, generatedprivate, expectedprivate) == false)
                {
                    qsc_memutils_secure_erase(privatekey, generatedlen);
                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                }
                else
                {
                    *privatekeylen = generatedlen;

                    if ((publickey != (uint8_t*)NULL) && (publickeylen != (size_t*)NULL))
                    {
                        if (publickeycapacity < expectedpublic)
                        {
                            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                        }
                        else
                        {
                            qsc_memutils_copy(publickey, generatedpublic, expectedpublic);
                            *publickeylen = expectedpublic;

                            if (publickeypresent != (bool*)NULL)
                            {
                                *publickeypresent = true;
                            }
                        }
                    }
                }
            }
        }
        else
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }

    if (inner != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(inner);
    }

    qsc_memutils_secure_erase(generatedprivate, sizeof(generatedprivate));
    qsc_memutils_secure_erase(generatedpublic, sizeof(generatedpublic));
    qsc_memutils_secure_erase(seed, sizeof(seed));

    return status;
}

static qsc_asn1_status x509_decode_pkcs8_mlkem_private(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* octets, size_t octetlen, uint8_t* privatekey,
    size_t privatekeycapacity, size_t* privatekeylen, uint8_t* publickey, size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent)
{
    uint8_t generatedprivate[QSC_KYBER_PRIVATEKEY_SIZE] = { 0U };
    uint8_t generatedpublic[QSC_KYBER_PUBLICKEY_SIZE] = { 0U };
    uint8_t seed[2U * QSC_KYBER_SEED_SIZE] = { 0U };
    qsc_encoding_ber_element* inner;
    const qsc_encoding_ber_element* child;
    const uint8_t* embeddedpublic;
    size_t expectedprivate;
    size_t expectedpublic;
    size_t generatedlen;
    size_t seedlen;
    size_t consumed;
    qsc_asn1_status status;

    inner = (qsc_encoding_ber_element*)NULL;
    child = (const qsc_encoding_ber_element*)NULL;
    embeddedpublic = (const uint8_t*)NULL;
    expectedprivate = qsc_x509_private_key_expected_private_size(algorithm);
    expectedpublic = qsc_x509_private_key_expected_public_size(algorithm);
    generatedlen = 0U;
    seedlen = 0U;
    consumed = 0U;
    status = QSC_ASN1_STATUS_INVALID_ENCODING;

    if ((algorithm == (const qsc_x509_algorithm_identifier*)NULL) || (octets == (const uint8_t*)NULL) || (privatekey == (uint8_t*)NULL) || (privatekeylen == (size_t*)NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((expectedprivate == 0U) || (expectedpublic == 0U))
    {
        status = QSC_ASN1_STATUS_UNSUPPORTED;
    }
    else
    {
        inner = qsc_encoding_der_decode_element(octets, octetlen, &consumed);

        if ((inner == (qsc_encoding_ber_element*)NULL) || (consumed != octetlen))
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if (qsc_asn1_element_is_tag(inner, QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC, false, 0U) == true)
        {
            if ((inner->length != sizeof(seed)) || (x509_mlkem_parameter_is_active(algorithm->pqcparameter) == false))
            {
                status = (inner->length != sizeof(seed)) ? QSC_ASN1_STATUS_INVALID_LENGTH : QSC_ASN1_STATUS_UNSUPPORTED;
            }
            else if ((privatekeycapacity < expectedprivate) || ((publickey != (uint8_t*)NULL) && (publickeycapacity < expectedpublic)))
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                qsc_memutils_copy(seed, inner->value, sizeof(seed));
                qsc_kyber_generate_seeded_keypair(generatedpublic, generatedprivate, seed, seed + QSC_KYBER_SEED_SIZE);
                qsc_memutils_copy(privatekey, generatedprivate, expectedprivate);
                *privatekeylen = expectedprivate;

                if ((publickey != (uint8_t*)NULL) && (publickeylen != (size_t*)NULL))
                {
                    qsc_memutils_copy(publickey, generatedpublic, expectedpublic);
                    *publickeylen = expectedpublic;

                    if (publickeypresent != (bool*)NULL)
                    {
                        *publickeypresent = true;
                    }
                }

                status = QSC_ASN1_STATUS_SUCCESS;
            }
        }
        else if (qsc_asn1_element_is_tag(inner, QSC_ENCODING_BER_CLASS_UNIVERSAL, false, BER_ASN1_OCTET_STRING) == true)
        {
            if (privatekeycapacity < expectedprivate)
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                status = qsc_asn1_decode_octet_string(inner, privatekey, privatekeycapacity, &generatedlen);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    if (generatedlen != expectedprivate)
                    {
                        qsc_memutils_secure_erase(privatekey, generatedlen);
                        status = QSC_ASN1_STATUS_INVALID_LENGTH;
                    }
                    else
                    {
                        status = x509_validate_mlkem_expanded_private(privatekey, generatedlen, expectedpublic, &embeddedpublic);

                        if (status != QSC_ASN1_STATUS_SUCCESS)
                        {
                            qsc_memutils_secure_erase(privatekey, generatedlen);
                        }
                    }
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    *privatekeylen = generatedlen;

                    if ((publickey != (uint8_t*)NULL) && (publickeylen != (size_t*)NULL))
                    {
                        if (publickeycapacity < expectedpublic)
                        {
                            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                        }
                        else
                        {
                            qsc_memutils_copy(publickey, embeddedpublic, expectedpublic);
                            *publickeylen = expectedpublic;

                            if (publickeypresent != (bool*)NULL)
                            {
                                *publickeypresent = true;
                            }
                        }
                    }
                }
            }
        }
        else if (qsc_asn1_element_is_tag(inner, QSC_ENCODING_BER_CLASS_UNIVERSAL, true, BER_ASN1_SEQUENCE) == true)
        {
            status = qsc_asn1_require_sequence(inner, 2U, 2U);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                child = qsc_asn1_get_child(inner, 0U);
                status = (child == (const qsc_encoding_ber_element*)NULL) ? QSC_ASN1_STATUS_NOT_FOUND : qsc_asn1_decode_octet_string(child, seed, sizeof(seed), &seedlen);
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (seedlen != sizeof(seed)))
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (x509_mlkem_parameter_is_active(algorithm->pqcparameter) == false))
            {
                status = QSC_ASN1_STATUS_UNSUPPORTED;
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                child = qsc_asn1_get_child(inner, 1U);
                status = (child == (const qsc_encoding_ber_element*)NULL) ? QSC_ASN1_STATUS_NOT_FOUND : qsc_asn1_decode_octet_string(child, privatekey, privatekeycapacity, &generatedlen);
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (generatedlen != expectedprivate))
            {
                qsc_memutils_secure_erase(privatekey, generatedlen);
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = x509_validate_mlkem_expanded_private(privatekey, generatedlen, expectedpublic, &embeddedpublic);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    qsc_memutils_secure_erase(privatekey, generatedlen);
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                qsc_kyber_generate_seeded_keypair(generatedpublic, generatedprivate, seed, seed + QSC_KYBER_SEED_SIZE);

                if (qsc_memutils_are_equal(privatekey, generatedprivate, expectedprivate) == false)
                {
                    qsc_memutils_secure_erase(privatekey, generatedlen);
                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                }
                else
                {
                    *privatekeylen = generatedlen;

                    if ((publickey != (uint8_t*)NULL) && (publickeylen != (size_t*)NULL))
                    {
                        if (publickeycapacity < expectedpublic)
                        {
                            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                        }
                        else
                        {
                            qsc_memutils_copy(publickey, generatedpublic, expectedpublic);
                            *publickeylen = expectedpublic;

                            if (publickeypresent != (bool*)NULL)
                            {
                                *publickeypresent = true;
                            }
                        }
                    }
                }
            }
        }
        else
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }

    if (inner != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(inner);
    }

    qsc_memutils_secure_erase(generatedprivate, sizeof(generatedprivate));
    qsc_memutils_secure_erase(generatedpublic, sizeof(generatedpublic));
    qsc_memutils_secure_erase(seed, sizeof(seed));

    return status;
}

static qsc_asn1_status x509_decode_pkcs8_optional_public_key(const qsc_encoding_ber_element* root, const qsc_x509_algorithm_identifier* algorithm, uint8_t* publickey,
    size_t publickeycapacity, size_t* publickeylen, bool* publickeypresent, bool* encodedpublicpresent)
{
    const qsc_encoding_ber_element* child;
    const qsc_encoding_ber_element* exchild;
    const uint8_t* keydata;
    qsc_asn1_bit_string bitstr;
    size_t expectedpublic;
    size_t keylen;
    size_t i;
    qsc_asn1_status status;

    child = (const qsc_encoding_ber_element*)NULL;
    exchild = (const qsc_encoding_ber_element*)NULL;
    keydata = (const uint8_t*)NULL;
    qsc_memutils_clear((uint8_t*)&bitstr, sizeof(qsc_asn1_bit_string));
    expectedpublic = qsc_x509_private_key_expected_public_size(algorithm);
    keylen = 0U;
    status = QSC_ASN1_STATUS_SUCCESS;

    for (i = 3U; status == QSC_ASN1_STATUS_SUCCESS && i < qsc_asn1_child_count(root); ++i)
    {
        child = qsc_asn1_get_child(root, i);

        if ((child != (const qsc_encoding_ber_element*)NULL) && (child->tagclass == QSC_ENCODING_BER_CLASS_CONTEXT_SPECIFIC) && (child->tagnumber == 1U))
        {
            if ((encodedpublicpresent != (bool*)NULL) && (*encodedpublicpresent == true))
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else if (child->constructed == false)
            {
                if ((child->value == (uint8_t*)NULL) || (child->length < 1U) || (child->value[0U] != 0U))
                {
                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                }
                else
                {
                    keydata = child->value + 1U;
                    keylen = child->length - 1U;
                }
            }
            else
            {
                status = qsc_asn1_get_explicit_child(child, &exchild);

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
                    else
                    {
                        keydata = bitstr.data;
                        keylen = bitstr.length;
                    }
                }
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (expectedpublic != 0U) && (keylen != expectedpublic))
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (publickey != (uint8_t*)NULL) && (publickeylen != (size_t*)NULL))
            {
                if (publickeycapacity < keylen)
                {
                    status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                }
                else if ((publickeypresent != (bool*)NULL) && (*publickeypresent == true))
                {
                    if ((*publickeylen != keylen) || (qsc_memutils_are_equal(publickey, keydata, keylen) == false))
                    {
                        status = QSC_ASN1_STATUS_INVALID_ENCODING;
                    }
                }
                else
                {
                    qsc_memutils_copy(publickey, keydata, keylen);
                    *publickeylen = keylen;

                    if (publickeypresent != (bool*)NULL)
                    {
                        *publickeypresent = true;
                    }
                }
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (encodedpublicpresent != (bool*)NULL))
            {
                *encodedpublicpresent = true;
            }
        }
    }

    return status;
}

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

static qsc_asn1_status x509_decode_pkcs8_eddsa_seed_octets(const uint8_t* octets, size_t octetlen, uint8_t* privatekey, size_t privatekeycapacity, size_t* privatekeylen)
{
    qsc_encoding_ber_element* inner;
    size_t consumed;
    size_t seedlen;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    inner = (qsc_encoding_ber_element*)NULL;
    consumed = 0U;
    seedlen = 0U;

    if ((octets == (const uint8_t*)NULL) || (privatekey == (uint8_t*)NULL) || (privatekeylen == (size_t*)NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    *privatekeylen = 0U;

    /*
     * RFC 8410 PKCS#8 stores CurvePrivateKey inside the outer PrivateKey OCTET STRING.
     * For Ed25519 this is normally:
     *   privateKey OCTET STRING -> inner OCTET STRING -> 32-byte seed
     *
     * Accept the standard wrapped form, and also tolerate a raw 32-byte seed form.
     */
    inner = qsc_encoding_der_decode_element(octets, octetlen, &consumed);

    if ((inner != (qsc_encoding_ber_element*)NULL) && (consumed == octetlen))
    {
        status = qsc_asn1_decode_octet_string(inner, privatekey, privatekeycapacity, &seedlen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (seedlen != QSC_X509_EDDSA_SEED_SIZE)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else
            {
                *privatekeylen = seedlen;
            }
        }

        qsc_encoding_ber_free_element(inner);
        inner = (qsc_encoding_ber_element*)NULL;
    }
    else
    {
        /* Interop tolerance: some implementations expose the raw seed directly. */
        if (octetlen != QSC_X509_EDDSA_SEED_SIZE)
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
        else if (privatekeycapacity < QSC_X509_EDDSA_SEED_SIZE)
        {
            status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            qsc_memutils_copy(privatekey, octets, QSC_X509_EDDSA_SEED_SIZE);
            *privatekeylen = QSC_X509_EDDSA_SEED_SIZE;
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

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
    bool encodedpublicpresent;
    qsc_asn1_status status;

    status = QSC_ASN1_STATUS_FAILURE;
    octets = (uint8_t*)NULL;
    child = (const qsc_encoding_ber_element*)NULL;
    inner = (qsc_encoding_ber_element*)NULL;
    version = 0U;
    octetlen = 0U;
    consumed = 0U;
    encodedpublicpresent = false;

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
        else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519)
        {
            status = x509_decode_pkcs8_eddsa_seed_octets(octets, octetlen, privatekey, privatekeycapacity, privatekeylen);
        }
        else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA)
        {
            status = x509_decode_pkcs8_mldsa_private(algorithm, octets, octetlen, privatekey, privatekeycapacity, privatekeylen, publickey, publickeycapacity, publickeylen, publickeypresent);
        }
        else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM)
        {
            status = x509_decode_pkcs8_mlkem_private(algorithm, octets, octetlen, privatekey, privatekeycapacity, privatekeylen, publickey, publickeycapacity, publickeylen, publickeypresent);
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
        }

        if ((status == QSC_ASN1_STATUS_SUCCESS) && (algorithm->publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_EC))
        {
            status = x509_decode_pkcs8_optional_public_key(root, algorithm, publickey, publickeycapacity, publickeylen, publickeypresent, &encodedpublicpresent);
        }
    }

    if (inner != (qsc_encoding_ber_element*)NULL)
    {
        qsc_encoding_ber_free_element(inner);
    }

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        if ((version == 0U) && (encodedpublicpresent == true))
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else if ((version == 1U) && (encodedpublicpresent == false))
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
    else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519)
    {
        /* RFC 8410 PKCS#8 carries the 32-byte private seed. */
        klen = QSC_X509_EDDSA_SEED_SIZE;
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
    else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519)
    {
        klen = QSC_X509_EDDSA_PUBLIC_KEY_SIZE;
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
            status = x509_private_key_decode_pkcs8_root_ex(root, algorithm, privatekey, privatekeycapacity, privatekeylen, publickey, publickeycapacity, publickeylen, publickeypresent);
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
    uint8_t edpub[QSC_X509_EDDSA_PUBLIC_KEY_SIZE] = { 0U };
    uint8_t edpriv[QSC_EDDSA_PRIVATEKEY_SIZE] = { 0U };
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
        else if ((spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519) &&
            (key->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519) &&
            (spki->algorithm.parameters_present == false) &&
            (key->algorithm.parameters_present == false) &&
            (spki->publickeylen == QSC_X509_EDDSA_PUBLIC_KEY_SIZE))
        {
            if ((key->publickey_present == true) && (key->publickeylen == QSC_X509_EDDSA_PUBLIC_KEY_SIZE))
            {
                if (qsc_memutils_are_equal(spki->publickey, key->publickey, QSC_X509_EDDSA_PUBLIC_KEY_SIZE) == true)
                {
                    res = true;
                }
            }
            else if (key->privatekeylen == QSC_X509_EDDSA_SEED_SIZE)
            {
                qsc_memutils_clear(edpub, sizeof(edpub));
                qsc_memutils_clear(edpriv, sizeof(edpriv));

                qsc_eddsa_generate_seeded_keypair(edpub, edpriv, key->privatekey);

                if (qsc_memutils_are_equal(spki->publickey, edpub, QSC_X509_EDDSA_PUBLIC_KEY_SIZE) == true)
                {
                    res = true;
                }
            }
            else if (key->privatekeylen == QSC_EDDSA_PRIVATEKEY_SIZE)
            {
                if (qsc_memutils_are_equal(spki->publickey,
                    key->privatekey + QSC_X509_EDDSA_SEED_SIZE,
                    QSC_X509_EDDSA_PUBLIC_KEY_SIZE) == true)
                {
                    res = true;
                }
            }
        }
        else if ((spki->algorithm.publickey == key->algorithm.publickey) &&
            ((spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) || (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM)) &&
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
    qsc_memutils_secure_erase(edpub, sizeof(edpub));
    qsc_memutils_secure_erase(edpriv, sizeof(edpriv));

    return res;
}
