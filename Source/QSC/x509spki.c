#include "x509spki.h"
#include "memutils.h"

static void x509_algorithm_identifier_initialize(qsc_x509_algorithm_identifier* algorithm)
{
    qsc_memutils_clear((uint8_t*)algorithm, sizeof(qsc_x509_algorithm_identifier));
}

static void x509_spki_initialize(qsc_x509_subject_public_key_info* spki)
{
    qsc_memutils_clear((uint8_t*)spki, sizeof(qsc_x509_subject_public_key_info));
}

static qsc_x509_public_key_algorithm x509_map_public_key_algorithm(qsc_oid_id oid)
{
    qsc_x509_public_key_algorithm alg;

    alg = QSC_X509_PUBLIC_KEY_ALGORITHM_NONE;

    if (oid == QSC_OID_ID_RSA_ENCRYPTION)
    {
        alg = QSC_X509_PUBLIC_KEY_ALGORITHM_RSA;
    }
    else if (oid == QSC_OID_ID_EC_PUBLIC_KEY)
    {
        alg = QSC_X509_PUBLIC_KEY_ALGORITHM_EC;
    }

    return alg;
}

static qsc_x509_signature_algorithm x509_map_signature_algorithm(qsc_oid_id oid)
{
    qsc_x509_signature_algorithm alg;

    alg = QSC_X509_SIGNATURE_ALGORITHM_NONE;

    if (oid == QSC_OID_ID_MD5_WITH_RSA_ENCRYPTION)
    {
        alg = QSC_X509_SIGNATURE_ALGORITHM_RSA_MD5;
    }
    else if (oid == QSC_OID_ID_SHA1_WITH_RSA_ENCRYPTION)
    {
        alg = QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA1;
    }
    else if (oid == QSC_OID_ID_SHA256_WITH_RSA_ENCRYPTION)
    {
        alg = QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA256;
    }
    else if (oid == QSC_OID_ID_SHA384_WITH_RSA_ENCRYPTION)
    {
        alg = QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA384;
    }
    else if (oid == QSC_OID_ID_SHA512_WITH_RSA_ENCRYPTION)
    {
        alg = QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA512;
    }
    else if (oid == QSC_OID_ID_ECDSA_WITH_SHA1)
    {
        alg = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA1;
    }
    else if (oid == QSC_OID_ID_ECDSA_WITH_SHA256)
    {
        alg = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256;
    }
    else if (oid == QSC_OID_ID_ECDSA_WITH_SHA384)
    {
        alg = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384;
    }
    else if (oid == QSC_OID_ID_ECDSA_WITH_SHA512)
    {
        alg = QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512;
    }

    return alg;
}

static qsc_x509_hash_algorithm x509_map_hash_algorithm(qsc_oid_id oid)
{
    qsc_x509_hash_algorithm halg;

    halg = QSC_X509_HASH_ALGORITHM_NONE;

    if (oid == QSC_OID_ID_MD5_WITH_RSA_ENCRYPTION)
    {
        halg = QSC_X509_HASH_ALGORITHM_MD5;
    }
    else if (oid == QSC_OID_ID_SHA1_WITH_RSA_ENCRYPTION || oid == QSC_OID_ID_ECDSA_WITH_SHA1 || oid == QSC_OID_ID_SHA1)
    {
        halg = QSC_X509_HASH_ALGORITHM_SHA1;
    }
    else if (oid == QSC_OID_ID_SHA224)
    {
        halg = QSC_X509_HASH_ALGORITHM_SHA224;
    }
    else if (oid == QSC_OID_ID_SHA256_WITH_RSA_ENCRYPTION || oid == QSC_OID_ID_ECDSA_WITH_SHA256 || oid == QSC_OID_ID_SHA256)
    {
        halg = QSC_X509_HASH_ALGORITHM_SHA256;
    }
    else if (oid == QSC_OID_ID_SHA384_WITH_RSA_ENCRYPTION || oid == QSC_OID_ID_ECDSA_WITH_SHA384 || oid == QSC_OID_ID_SHA384)
    {
        halg = QSC_X509_HASH_ALGORITHM_SHA384;
    }
    else if (oid == QSC_OID_ID_SHA512_WITH_RSA_ENCRYPTION || oid == QSC_OID_ID_ECDSA_WITH_SHA512 || oid == QSC_OID_ID_SHA512)
    {
        halg = QSC_X509_HASH_ALGORITHM_SHA512;
    }

    return halg;
}

static qsc_x509_named_curve x509_map_named_curve(qsc_oid_id oid)
{
    qsc_x509_named_curve curve;

    curve = QSC_X509_NAMED_CURVE_NONE;

    if (oid == QSC_OID_ID_PRIME256V1)
    {
        curve = QSC_X509_NAMED_CURVE_PRIME256V1;
    }
    else if (oid == QSC_OID_ID_SECP384R1)
    {
        curve = QSC_X509_NAMED_CURVE_SECP384R1;
    }
    else if (oid == QSC_OID_ID_SECP521R1)
    {
        curve = QSC_X509_NAMED_CURVE_SECP521R1;
    }

    return curve;
}

qsc_asn1_status qsc_x509_algorithm_identifier_decode(const qsc_encoding_ber_element* element, qsc_x509_algorithm_identifier* algorithm)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(algorithm != NULL);

    qsc_asn1_status status;
    const qsc_encoding_ber_element* child;
    qsc_oid_id oid;

    status = QSC_ASN1_STATUS_FAILURE;
    child = (const qsc_encoding_ber_element*)NULL;
    oid = QSC_OID_ID_NONE;

    if (element == (const qsc_encoding_ber_element*)NULL || algorithm == (qsc_x509_algorithm_identifier*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        x509_algorithm_identifier_initialize(algorithm);
        status = qsc_asn1_require_sequence(element, 1U, 2U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, 0U);

            if (child == (const qsc_encoding_ber_element*)NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                status = qsc_asn1_decode_oid(child, &algorithm->algorithm_oid);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    oid = qsc_oid_identify(&algorithm->algorithm_oid);
                    algorithm->oid = oid;
                    algorithm->publickey = x509_map_public_key_algorithm(oid);
                    algorithm->signature = x509_map_signature_algorithm(oid);
                    algorithm->hash = x509_map_hash_algorithm(oid);

                    if (element->ccount > 1U)
                    {
                        child = qsc_asn1_get_child(element, 1U);

                        if (child == (const qsc_encoding_ber_element*)NULL)
                        {
                            status = QSC_ASN1_STATUS_NOT_FOUND;
                        }
                        else
                        {
                            algorithm->parameters_present = true;

                            if (qsc_asn1_is_null(child) == true)
                            {
                                algorithm->parameters_null = true;
                            }
                            else if (qsc_asn1_is_oid(child) == true)
                            {
                                status = qsc_asn1_decode_oid(child, &algorithm->parameter_oid);

                                if (status == QSC_ASN1_STATUS_SUCCESS)
                                {
                                    algorithm->parameters_oid = true;
                                    oid = qsc_oid_identify(&algorithm->parameter_oid);
                                    algorithm->curve = x509_map_named_curve(oid);
                                }
                            }
                            else
                            {
                                status = QSC_ASN1_STATUS_UNSUPPORTED;
                            }

                            if (algorithm->parameters_present == true &&
                                algorithm->parameters_null == true)
                            {
                                if (algorithm->signature == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256 ||
                                    algorithm->signature == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384 ||
                                    algorithm->signature == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512)
                                {
                                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                                }
                            }
                        }
                    }

                    if (status == QSC_ASN1_STATUS_SUCCESS && algorithm->curve == QSC_X509_NAMED_CURVE_NONE && algorithm->parameters_oid == true)
                    {
                        status = QSC_ASN1_STATUS_UNSUPPORTED;
                    }
                }
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_subject_public_key_info_decode(const qsc_encoding_ber_element* element, qsc_x509_subject_public_key_info* spki)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(spki != NULL);

    qsc_asn1_status status;
    const qsc_encoding_ber_element* child;
    qsc_asn1_bit_string bitstr;

    status = QSC_ASN1_STATUS_FAILURE;
    child = (const qsc_encoding_ber_element*)NULL;

    if (element == (const qsc_encoding_ber_element*)NULL || spki == (qsc_x509_subject_public_key_info*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        x509_spki_initialize(spki);
        qsc_memutils_clear((uint8_t*)&bitstr, sizeof(qsc_asn1_bit_string));
        status = qsc_asn1_require_sequence(element, 2U, 2U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, 0U);

            if (child == (const qsc_encoding_ber_element*)NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                status = qsc_x509_algorithm_identifier_decode(child, &spki->algorithm);

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    child = qsc_asn1_get_child(element, 1U);

                    if (child == (const qsc_encoding_ber_element*)NULL)
                    {
                        status = QSC_ASN1_STATUS_NOT_FOUND;
                    }
                    else
                    {
                        status = qsc_asn1_decode_bit_string(child, &bitstr);

                        if (status == QSC_ASN1_STATUS_SUCCESS)
                        {
                            if (bitstr.length > sizeof(spki->publickey))
                            {
                                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                            }
                            else
                            {
                                qsc_memutils_copy(spki->publickey, bitstr.data, bitstr.length);
                                spki->publickeylen = bitstr.length;
                                spki->unusedbits = bitstr.unused;
                            }
                        }
                    }
                }
            }
        }
    }

    return status;
}

bool qsc_x509_spki_is_uncompressed_ec_point(const qsc_x509_subject_public_key_info* spki)
{
    QSC_ASSERT(spki != NULL);

    bool res;

    res = false;

    if (spki != (const qsc_x509_subject_public_key_info*)NULL &&
        spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC &&
        spki->publickeylen > 0U &&
        spki->unusedbits == 0U &&
        spki->publickey[0U] == 0x04U)
    {
        res = true;
    }

    return res;
}

size_t qsc_x509_named_curve_coordinate_size(qsc_x509_named_curve curve)
{
    size_t size;

    size = 0U;

    if (curve == QSC_X509_NAMED_CURVE_PRIME256V1)
    {
        size = 32U;
    }
    else if (curve == QSC_X509_NAMED_CURVE_SECP384R1)
    {
        size = 48U;
    }
    else if (curve == QSC_X509_NAMED_CURVE_SECP521R1)
    {
        size = 66U;
    }

    return size;
}

qsc_asn1_status qsc_x509_spki_get_ec_coordinates(const qsc_x509_subject_public_key_info* spki, uint8_t* x, size_t xlen, uint8_t* y, size_t ylen)
{
    QSC_ASSERT(spki != NULL);
    QSC_ASSERT(x != NULL);
    QSC_ASSERT(y != NULL);

    qsc_asn1_status status;
    size_t flen;
    size_t elen;

    status = QSC_ASN1_STATUS_FAILURE;
    flen = 0U;
    elen = 0U;

    if (spki == (const qsc_x509_subject_public_key_info*)NULL || x == (uint8_t*)NULL || y == (uint8_t*)NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if (qsc_x509_spki_is_uncompressed_ec_point(spki) == false)
    {
        status = QSC_ASN1_STATUS_INVALID_ENCODING;
    }
    else
    {
        flen = qsc_x509_named_curve_coordinate_size(spki->algorithm.curve);

        if (flen == 0U)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else
        {
            elen = (2U * flen) + 1U;

            if (spki->publickeylen != elen)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else if (xlen < flen || ylen < flen)
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                qsc_memutils_copy(x, spki->publickey + 1U, flen);
                qsc_memutils_copy(y, spki->publickey + 1U + flen, flen);
                status = QSC_ASN1_STATUS_SUCCESS;
            }
        }
    }

    return status;
}
