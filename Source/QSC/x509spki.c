#include "x509spki.h"
#include "memutils.h"
#include "oid.h"
#include "dilithium.h"
#include "kyber.h"

static qsc_x509_pqc_parameter_set x509_spki_active_mldsa_parameter_set(void)
{
#if defined(QSC_DILITHIUM_S1P44)
    return QSC_X509_PQC_PARAMETER_SET_ML_DSA_44;
#elif defined(QSC_DILITHIUM_S3P65)
    return QSC_X509_PQC_PARAMETER_SET_ML_DSA_65;
#elif defined(QSC_DILITHIUM_S5P87)
    return QSC_X509_PQC_PARAMETER_SET_ML_DSA_87;
#else
    return QSC_X509_PQC_PARAMETER_SET_NONE;
#endif
}

static qsc_x509_pqc_parameter_set x509_spki_active_mlkem_parameter_set(void)
{
#if defined(QSC_KYBER_PUBLICKEY_SIZE)
    if (QSC_KYBER_PUBLICKEY_SIZE == 800U)
    {
        return QSC_X509_PQC_PARAMETER_SET_ML_KEM_512;
    }
    else if (QSC_KYBER_PUBLICKEY_SIZE == 1184U)
    {
        return QSC_X509_PQC_PARAMETER_SET_ML_KEM_768;
    }
    else if (QSC_KYBER_PUBLICKEY_SIZE == 1568U)
    {
        return QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024;
    }
#endif
    return QSC_X509_PQC_PARAMETER_SET_NONE;
}

static bool x509_spki_mldsa_parameter_set_matches_build(qsc_x509_pqc_parameter_set parameterset)
{
    qsc_x509_pqc_parameter_set active = x509_spki_active_mldsa_parameter_set();
    return (active != QSC_X509_PQC_PARAMETER_SET_NONE) && (parameterset == active);
}

static bool x509_spki_mlkem_parameter_set_matches_build(qsc_x509_pqc_parameter_set parameterset)
{
    qsc_x509_pqc_parameter_set active = x509_spki_active_mlkem_parameter_set();
    return (active != QSC_X509_PQC_PARAMETER_SET_NONE) && (parameterset == active);
}

static qsc_x509_public_key_algorithm x509_map_public_key_algorithm(qsc_oid_id oid)
{
    if (oid == QSC_OID_ID_RSA_ENCRYPTION)
    {
        return QSC_X509_PUBLIC_KEY_ALGORITHM_RSA;
    }
    else if (oid == QSC_OID_ID_EC_PUBLIC_KEY)
    {
        return QSC_X509_PUBLIC_KEY_ALGORITHM_EC;
    }
    else if ((oid == QSC_OID_ID_ML_DSA_44) ||
             (oid == QSC_OID_ID_ML_DSA_65) ||
             (oid == QSC_OID_ID_ML_DSA_87))
    {
        return QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA;
    }
    else if ((oid == QSC_OID_ID_ML_KEM_512) ||
             (oid == QSC_OID_ID_ML_KEM_768) ||
             (oid == QSC_OID_ID_ML_KEM_1024))
    {
        return QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM;
    }

    return QSC_X509_PUBLIC_KEY_ALGORITHM_NONE;
}

static qsc_x509_signature_algorithm x509_map_signature_algorithm(qsc_oid_id oid)
{
    if (oid == QSC_OID_ID_MD5_WITH_RSA_ENCRYPTION)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_RSA_MD5;
    }
    else if (oid == QSC_OID_ID_SHA1_WITH_RSA_ENCRYPTION)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA1;
    }
    else if (oid == QSC_OID_ID_SHA256_WITH_RSA_ENCRYPTION)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA256;
    }
    else if (oid == QSC_OID_ID_SHA384_WITH_RSA_ENCRYPTION)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA384;
    }
    else if (oid == QSC_OID_ID_SHA512_WITH_RSA_ENCRYPTION)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA512;
    }
    else if (oid == QSC_OID_ID_ECDSA_WITH_SHA1)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA1;
    }
    else if (oid == QSC_OID_ID_ECDSA_WITH_SHA256)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256;
    }
    else if (oid == QSC_OID_ID_ECDSA_WITH_SHA384)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384;
    }
    else if (oid == QSC_OID_ID_ECDSA_WITH_SHA512)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512;
    }
    else if (oid == QSC_OID_ID_ML_DSA_44)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44;
    }
    else if (oid == QSC_OID_ID_ML_DSA_65)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65;
    }
    else if (oid == QSC_OID_ID_ML_DSA_87)
    {
        return QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87;
    }

    return QSC_X509_SIGNATURE_ALGORITHM_NONE;
}

static qsc_x509_hash_algorithm x509_map_hash_algorithm(qsc_oid_id oid)
{
    if (oid == QSC_OID_ID_MD5_WITH_RSA_ENCRYPTION)
    {
        return QSC_X509_HASH_ALGORITHM_MD5;
    }
    else if ((oid == QSC_OID_ID_SHA1_WITH_RSA_ENCRYPTION) || (oid == QSC_OID_ID_ECDSA_WITH_SHA1) || (oid == QSC_OID_ID_SHA1))
    {
        return QSC_X509_HASH_ALGORITHM_SHA1;
    }
    else if (oid == QSC_OID_ID_SHA224)
    {
        return QSC_X509_HASH_ALGORITHM_SHA224;
    }
    else if ((oid == QSC_OID_ID_SHA256_WITH_RSA_ENCRYPTION) || (oid == QSC_OID_ID_ECDSA_WITH_SHA256) || (oid == QSC_OID_ID_SHA256))
    {
        return QSC_X509_HASH_ALGORITHM_SHA256;
    }
    else if ((oid == QSC_OID_ID_SHA384_WITH_RSA_ENCRYPTION) || (oid == QSC_OID_ID_ECDSA_WITH_SHA384) || (oid == QSC_OID_ID_SHA384))
    {
        return QSC_X509_HASH_ALGORITHM_SHA384;
    }
    else if ((oid == QSC_OID_ID_SHA512_WITH_RSA_ENCRYPTION) || (oid == QSC_OID_ID_ECDSA_WITH_SHA512) || (oid == QSC_OID_ID_SHA512))
    {
        return QSC_X509_HASH_ALGORITHM_SHA512;
    }

    return QSC_X509_HASH_ALGORITHM_NONE;
}

static qsc_x509_named_curve x509_map_named_curve(qsc_oid_id oid)
{
    if (oid == QSC_OID_ID_PRIME256V1)
    {
        return QSC_X509_NAMED_CURVE_PRIME256V1;
    }
    else if (oid == QSC_OID_ID_SECP384R1)
    {
        return QSC_X509_NAMED_CURVE_SECP384R1;
    }
    else if (oid == QSC_OID_ID_SECP521R1)
    {
        return QSC_X509_NAMED_CURVE_SECP521R1;
    }

    return QSC_X509_NAMED_CURVE_NONE;
}

static qsc_x509_pqc_parameter_set x509_map_pqc_parameter_set(qsc_oid_id oid)
{
    switch (oid)
    {
        case QSC_OID_ID_ML_DSA_44:
            return QSC_X509_PQC_PARAMETER_SET_ML_DSA_44;
        case QSC_OID_ID_ML_DSA_65:
            return QSC_X509_PQC_PARAMETER_SET_ML_DSA_65;
        case QSC_OID_ID_ML_DSA_87:
            return QSC_X509_PQC_PARAMETER_SET_ML_DSA_87;
        case QSC_OID_ID_ML_KEM_512:
            return QSC_X509_PQC_PARAMETER_SET_ML_KEM_512;
        case QSC_OID_ID_ML_KEM_768:
            return QSC_X509_PQC_PARAMETER_SET_ML_KEM_768;
        case QSC_OID_ID_ML_KEM_1024:
            return QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024;
        default:
            return QSC_X509_PQC_PARAMETER_SET_NONE;
    }
}

static qsc_oid_id x509_mldsa_parameter_set_to_oid_id(qsc_x509_pqc_parameter_set parameterset)
{
    switch (parameterset)
    {
        case QSC_X509_PQC_PARAMETER_SET_ML_DSA_44:
            return QSC_OID_ID_ML_DSA_44;
        case QSC_X509_PQC_PARAMETER_SET_ML_DSA_65:
            return QSC_OID_ID_ML_DSA_65;
        case QSC_X509_PQC_PARAMETER_SET_ML_DSA_87:
            return QSC_OID_ID_ML_DSA_87;
        default:
            return QSC_OID_ID_NONE;
    }
}

static qsc_oid_id x509_mlkem_parameter_set_to_oid_id(qsc_x509_pqc_parameter_set parameterset)
{
    switch (parameterset)
    {
        case QSC_X509_PQC_PARAMETER_SET_ML_KEM_512:
            return QSC_OID_ID_ML_KEM_512;
        case QSC_X509_PQC_PARAMETER_SET_ML_KEM_768:
            return QSC_OID_ID_ML_KEM_768;
        case QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024:
            return QSC_OID_ID_ML_KEM_1024;
        default:
            return QSC_OID_ID_NONE;
    }
}

static bool x509_is_ecdsa_signature_oid(qsc_oid_id oid)
{
    return (oid == QSC_OID_ID_ECDSA_WITH_SHA1) ||
           (oid == QSC_OID_ID_ECDSA_WITH_SHA256) ||
           (oid == QSC_OID_ID_ECDSA_WITH_SHA384) ||
           (oid == QSC_OID_ID_ECDSA_WITH_SHA512);
}

static bool x509_is_digest_oid(qsc_oid_id oid)
{
    return (oid == QSC_OID_ID_SHA1) ||
           (oid == QSC_OID_ID_SHA224) ||
           (oid == QSC_OID_ID_SHA256) ||
           (oid == QSC_OID_ID_SHA384) ||
           (oid == QSC_OID_ID_SHA512);
}

static bool x509_is_mldsa_parameter_set(qsc_x509_pqc_parameter_set parameterset)
{
    return (parameterset == QSC_X509_PQC_PARAMETER_SET_ML_DSA_44) ||
           (parameterset == QSC_X509_PQC_PARAMETER_SET_ML_DSA_65) ||
           (parameterset == QSC_X509_PQC_PARAMETER_SET_ML_DSA_87);
}

static bool x509_is_mlkem_parameter_set(qsc_x509_pqc_parameter_set parameterset)
{
    return (parameterset == QSC_X509_PQC_PARAMETER_SET_ML_KEM_512) ||
           (parameterset == QSC_X509_PQC_PARAMETER_SET_ML_KEM_768) ||
           (parameterset == QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024);
}

qsc_asn1_status qsc_x509_algorithm_identifier_validate(const qsc_x509_algorithm_identifier* algorithm)
{
    if (algorithm == NULL)
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC)
    {
        if ((algorithm->oid != QSC_OID_ID_EC_PUBLIC_KEY) ||
            (algorithm->signature != QSC_X509_SIGNATURE_ALGORITHM_NONE) ||
            (algorithm->hash != QSC_X509_HASH_ALGORITHM_NONE) ||
            (algorithm->pqcparameter != QSC_X509_PQC_PARAMETER_SET_NONE))
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        if ((algorithm->parameters_present == false) ||
            (algorithm->parameters_null == true) ||
            (algorithm->parameters_oid == false) ||
            (algorithm->curve == QSC_X509_NAMED_CURVE_NONE))
        {
            return (algorithm->curve == QSC_X509_NAMED_CURVE_NONE) ? QSC_ASN1_STATUS_UNSUPPORTED : QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }
    else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA)
    {
        if ((algorithm->signature != QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44) &&
            (algorithm->signature != QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65) &&
            (algorithm->signature != QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87))
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        if ((algorithm->curve != QSC_X509_NAMED_CURVE_NONE) ||
            (algorithm->hash != QSC_X509_HASH_ALGORITHM_NONE) ||
            (x509_is_mldsa_parameter_set(algorithm->pqcparameter) == false) ||
            (algorithm->parameters_present == true))
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }
    else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM)
    {
        if ((algorithm->signature != QSC_X509_SIGNATURE_ALGORITHM_NONE) ||
            (algorithm->curve != QSC_X509_NAMED_CURVE_NONE) ||
            (algorithm->hash != QSC_X509_HASH_ALGORITHM_NONE) ||
            (x509_is_mlkem_parameter_set(algorithm->pqcparameter) == false) ||
            (algorithm->parameters_present == true))
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }
    else if (x509_is_ecdsa_signature_oid(algorithm->oid) == true)
    {
        if ((algorithm->publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_NONE) ||
            (algorithm->curve != QSC_X509_NAMED_CURVE_NONE) ||
            (algorithm->pqcparameter != QSC_X509_PQC_PARAMETER_SET_NONE) ||
            (algorithm->parameters_present == true))
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }
    }
    else if (x509_is_digest_oid(algorithm->oid) == true)
    {
        if ((algorithm->publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_NONE) ||
            (algorithm->signature != QSC_X509_SIGNATURE_ALGORITHM_NONE) ||
            (algorithm->curve != QSC_X509_NAMED_CURVE_NONE) ||
            (algorithm->pqcparameter != QSC_X509_PQC_PARAMETER_SET_NONE))
        {
            return QSC_ASN1_STATUS_INVALID_ENCODING;
        }

        if ((algorithm->parameters_present == true) && (algorithm->parameters_null == false))
        {
            return QSC_ASN1_STATUS_UNSUPPORTED;
        }
    }
    else
    {
        if ((algorithm->parameters_present == true) &&
            (algorithm->parameters_null == false) &&
            (algorithm->parameters_oid == false))
        {
            return QSC_ASN1_STATUS_UNSUPPORTED;
        }
    }

    return QSC_ASN1_STATUS_SUCCESS;
}

void qsc_x509_algorithm_identifier_initialize(qsc_x509_algorithm_identifier* algorithm)
{
    QSC_ASSERT(algorithm != NULL);

    if (algorithm != NULL)
    {
        qsc_memutils_clear((uint8_t*)algorithm, sizeof(qsc_x509_algorithm_identifier));
    }
}

void qsc_x509_subject_public_key_info_initialize(qsc_x509_subject_public_key_info* spki)
{
    QSC_ASSERT(spki != NULL);

    if (spki != NULL)
    {
        qsc_memutils_clear((uint8_t*)spki, sizeof(qsc_x509_subject_public_key_info));
    }
}

size_t qsc_x509_pqc_public_key_size(qsc_x509_pqc_parameter_set parameterset)
{
    switch (parameterset)
    {
        case QSC_X509_PQC_PARAMETER_SET_ML_DSA_44:
#if defined(QSC_DILITHIUM_S1P44)
            return QSC_DILITHIUM_PUBLICKEY_SIZE;
#else
            return 1312U;
#endif
        case QSC_X509_PQC_PARAMETER_SET_ML_DSA_65:
#if defined(QSC_DILITHIUM_S3P65)
            return QSC_DILITHIUM_PUBLICKEY_SIZE;
#else
            return 1952U;
#endif
        case QSC_X509_PQC_PARAMETER_SET_ML_DSA_87:
#if defined(QSC_DILITHIUM_S5P87)
            return QSC_DILITHIUM_PUBLICKEY_SIZE;
#else
            return 2592U;
#endif
        case QSC_X509_PQC_PARAMETER_SET_ML_KEM_512:
#if defined(QSC_KYBER_PUBLICKEY_SIZE)
            if (QSC_KYBER_PUBLICKEY_SIZE == 800U)
            {
                return QSC_KYBER_PUBLICKEY_SIZE;
            }
#endif
            return 800U;
        case QSC_X509_PQC_PARAMETER_SET_ML_KEM_768:
#if defined(QSC_KYBER_PUBLICKEY_SIZE)
            if (QSC_KYBER_PUBLICKEY_SIZE == 1184U)
            {
                return QSC_KYBER_PUBLICKEY_SIZE;
            }
#endif
            return 1184U;
        case QSC_X509_PQC_PARAMETER_SET_ML_KEM_1024:
#if defined(QSC_KYBER_PUBLICKEY_SIZE)
            if (QSC_KYBER_PUBLICKEY_SIZE == 1568U)
            {
                return QSC_KYBER_PUBLICKEY_SIZE;
            }
#endif
            return 1568U;
        default:
            return 0U;
    }
}

bool qsc_x509_algorithm_identifier_is_mldsa(const qsc_x509_algorithm_identifier* algorithm)
{
    QSC_ASSERT(algorithm != NULL);

    bool res;

    res = false;

    if (algorithm != NULL)
    {
        res = (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) ||
            (algorithm->signature == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44) ||
            (algorithm->signature == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65) ||
            (algorithm->signature == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87);
    }

    return res;
}

bool qsc_x509_algorithm_identifier_is_mlkem(const qsc_x509_algorithm_identifier* algorithm)
{
    QSC_ASSERT(algorithm != NULL);

    bool res;

    res = false;

    if (algorithm != NULL)
    {
        res = (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM);
    }

    return res;
}

qsc_asn1_status qsc_x509_algorithm_identifier_initialize_mldsa(qsc_x509_algorithm_identifier* algorithm, qsc_x509_pqc_parameter_set parameterset)
{
    QSC_ASSERT(algorithm != NULL);

    qsc_asn1_status status;
    qsc_oid_id oid;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    oid = QSC_OID_ID_NONE;

    if (algorithm != NULL)
    {
        oid = x509_mldsa_parameter_set_to_oid_id(parameterset);

        if (oid == QSC_OID_ID_NONE)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else
        {
            qsc_x509_algorithm_identifier_initialize(algorithm);

            if (qsc_oid_to_asn1(oid, &algorithm->algorithm_oid) == false)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                algorithm->oid = oid;
                algorithm->publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA;
                algorithm->pqcparameter = parameterset;
                algorithm->signature = x509_map_signature_algorithm(oid);
                status = QSC_ASN1_STATUS_SUCCESS;
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_algorithm_identifier_initialize_mlkem(qsc_x509_algorithm_identifier* algorithm, qsc_x509_pqc_parameter_set parameterset)
{
    QSC_ASSERT(algorithm != NULL);

    qsc_asn1_status status;
    qsc_oid_id oid;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    oid = QSC_OID_ID_NONE;

    if (algorithm != NULL)
    {
        oid = x509_mlkem_parameter_set_to_oid_id(parameterset);

        if (oid == QSC_OID_ID_NONE)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else
        {
            qsc_x509_algorithm_identifier_initialize(algorithm);

            if (qsc_oid_to_asn1(oid, &algorithm->algorithm_oid) == false)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                algorithm->oid = oid;
                algorithm->publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM;
                algorithm->pqcparameter = parameterset;
                status = QSC_ASN1_STATUS_SUCCESS;
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_algorithm_identifier_decode(const qsc_encoding_ber_element* element, qsc_x509_algorithm_identifier* algorithm)
{
    QSC_ASSERT(element != NULL);
    QSC_ASSERT(algorithm != NULL);

    qsc_asn1_status status;
    const qsc_encoding_ber_element* child;
    qsc_oid_id oid;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    child = (const qsc_encoding_ber_element*)NULL;
    oid = QSC_OID_ID_NONE;

    if ((element != NULL) && (algorithm != NULL))
    {
        qsc_x509_algorithm_identifier_initialize(algorithm);
        status = qsc_asn1_require_sequence(element, 1U, 2U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, 0U);

            if (child == NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                status = qsc_asn1_decode_oid(child, &algorithm->algorithm_oid);
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            oid = qsc_oid_identify(&algorithm->algorithm_oid);
            algorithm->oid = oid;
            algorithm->publickey = x509_map_public_key_algorithm(oid);
            algorithm->signature = x509_map_signature_algorithm(oid);
            algorithm->hash = x509_map_hash_algorithm(oid);
            algorithm->pqcparameter = x509_map_pqc_parameter_set(oid);

            if (element->ccount > 1U)
            {
                child = qsc_asn1_get_child(element, 1U);

                if (child == NULL)
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
                }
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = qsc_x509_algorithm_identifier_validate(algorithm);
        }
    }

    return status;
}

size_t qsc_x509_named_curve_coordinate_size(qsc_x509_named_curve curve)
{
    size_t res;

    res = 0U;

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

size_t qsc_x509_named_curve_public_key_size(qsc_x509_named_curve curve)
{
    size_t flen;
    size_t res;

    flen = qsc_x509_named_curve_coordinate_size(curve);
    res = 0U;

    if (flen != 0U)
    {
        res = (2U * flen) + 1U;
    }

    return res;
}

bool qsc_x509_spki_is_uncompressed_ec_point(const qsc_x509_subject_public_key_info* spki)
{
    QSC_ASSERT(spki != NULL);

    bool res;

    res = false;

    if (spki != NULL)
    {
        res = (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC) &&
            (spki->publickeylen > 0U) &&
            (spki->unusedbits == 0U) &&
            (spki->publickey[0U] == 0x04U);
    }

    return res;
}

qsc_asn1_status qsc_x509_spki_validate(const qsc_x509_subject_public_key_info* spki)
{
    QSC_ASSERT(spki != NULL);

    qsc_asn1_status status;
    size_t explen;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    explen = 0U;

    if (spki != NULL)
    {
        status = qsc_x509_algorithm_identifier_validate(&spki->algorithm);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (spki->publickeylen == 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else if (spki->unusedbits != 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_ENCODING;
            }
            else if (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC)
            {
                if (qsc_x509_spki_is_uncompressed_ec_point(spki) == false)
                {
                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                }
                else
                {
                    explen = qsc_x509_named_curve_public_key_size(spki->algorithm.curve);

                    if (explen == 0U)
                    {
                        status = QSC_ASN1_STATUS_UNSUPPORTED;
                    }
                    else if (spki->publickeylen != explen)
                    {
                        status = QSC_ASN1_STATUS_INVALID_LENGTH;
                    }
                }
            }
            else if ((spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) ||
                (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM))
            {
                explen = qsc_x509_pqc_public_key_size(spki->algorithm.pqcparameter);

                if (explen == 0U)
                {
                    status = QSC_ASN1_STATUS_UNSUPPORTED;
                }
                else if (spki->unusedbits != 0U)
                {
                    status = QSC_ASN1_STATUS_INVALID_ENCODING;
                }
                else if (spki->publickeylen != explen)
                {
                    status = QSC_ASN1_STATUS_INVALID_LENGTH;
                }
#if defined(QSC_DILITHIUM_PUBLICKEY_SIZE)
                else if ((spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA) &&
                    (x509_spki_mldsa_parameter_set_matches_build(spki->algorithm.pqcparameter) == true) &&
                    (spki->publickeylen != QSC_DILITHIUM_PUBLICKEY_SIZE))
                {
                    status = QSC_ASN1_STATUS_INVALID_LENGTH;
                }
#endif
#if defined(QSC_KYBER_PUBLICKEY_SIZE)
                else if ((spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM) &&
                    (x509_spki_mlkem_parameter_set_matches_build(spki->algorithm.pqcparameter) == true) &&
                    (spki->publickeylen != QSC_KYBER_PUBLICKEY_SIZE))
                {
                    status = QSC_ASN1_STATUS_INVALID_LENGTH;
                }
#endif
                else
                {
                    status = QSC_ASN1_STATUS_SUCCESS;
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

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    child = (const qsc_encoding_ber_element*)NULL;
    qsc_memutils_clear((uint8_t*)&bitstr, sizeof(qsc_asn1_bit_string));

    if ((element != NULL) && (spki != NULL))
    {
        qsc_x509_subject_public_key_info_initialize(spki);
        status = qsc_asn1_require_sequence(element, 2U, 2U);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, 0U);

            if (child == NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                status = qsc_x509_algorithm_identifier_decode(child, &spki->algorithm);
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            child = qsc_asn1_get_child(element, 1U);

            if (child == NULL)
            {
                status = QSC_ASN1_STATUS_NOT_FOUND;
            }
            else
            {
                status = qsc_asn1_decode_bit_string(child, &bitstr);
            }
        }

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            if (bitstr.length == 0U)
            {
                status = QSC_ASN1_STATUS_INVALID_LENGTH;
            }
            else if (bitstr.length > sizeof(spki->publickey))
            {
                status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
            }
            else
            {
                qsc_memutils_copy(spki->publickey, bitstr.data, bitstr.length);
                spki->publickeylen = bitstr.length;
                spki->unusedbits = bitstr.unused;
                status = qsc_x509_spki_validate(spki);
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_spki_get_ec_coordinates(const qsc_x509_subject_public_key_info* spki, uint8_t* x, size_t xlen, uint8_t* y, size_t ylen)
{
    QSC_ASSERT(spki != NULL);
    QSC_ASSERT(x != NULL);
    QSC_ASSERT(y != NULL);

    qsc_asn1_status status;
    size_t flen;
    size_t elen;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    flen = 0U;
    elen = 0U;

    if ((spki != NULL) && (x != NULL) && (y != NULL))
    {
        if (qsc_x509_spki_is_uncompressed_ec_point(spki) == false)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else
        {
            flen = qsc_x509_named_curve_coordinate_size(spki->algorithm.curve);
            elen = qsc_x509_named_curve_public_key_size(spki->algorithm.curve);

            if ((flen == 0U) || (elen == 0U))
            {
                status = QSC_ASN1_STATUS_UNSUPPORTED;
            }
            else if ((xlen < flen) || (ylen < flen) || (spki->publickeylen != elen))
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

qsc_asn1_status qsc_x509_spki_initialize_ec(qsc_x509_subject_public_key_info* spki, qsc_x509_named_curve curve, const uint8_t* publickey, size_t publickeylen)
{
    QSC_ASSERT(spki != NULL);
    QSC_ASSERT(publickey != NULL);

    qsc_asn1_status status;
    size_t expected;
    qsc_oid_id curveoid;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    expected = 0U;
    curveoid = QSC_OID_ID_NONE;

    if ((spki != NULL) && (publickey != NULL))
    {
        expected = qsc_x509_named_curve_public_key_size(curve);

        if (expected == 0U)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else if ((publickeylen != expected) || (publickeylen > sizeof(spki->publickey)))
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
        else if (publickey[0U] != 0x04U)
        {
            status = QSC_ASN1_STATUS_INVALID_ENCODING;
        }
        else
        {
            if (curve == QSC_X509_NAMED_CURVE_PRIME256V1)
            {
                curveoid = QSC_OID_ID_PRIME256V1;
            }
            else if (curve == QSC_X509_NAMED_CURVE_SECP384R1)
            {
                curveoid = QSC_OID_ID_SECP384R1;
            }
            else if (curve == QSC_X509_NAMED_CURVE_SECP521R1)
            {
                curveoid = QSC_OID_ID_SECP521R1;
            }

            if (curveoid == QSC_OID_ID_NONE)
            {
                status = QSC_ASN1_STATUS_UNSUPPORTED;
            }
            else
            {
                qsc_x509_subject_public_key_info_initialize(spki);
                spki->algorithm.publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_EC;
                spki->algorithm.curve = curve;
                spki->algorithm.oid = QSC_OID_ID_EC_PUBLIC_KEY;
                spki->algorithm.parameters_present = true;
                spki->algorithm.parameters_oid = true;

                if (qsc_oid_to_asn1(QSC_OID_ID_EC_PUBLIC_KEY, &spki->algorithm.algorithm_oid) == false)
                {
                    status = QSC_ASN1_STATUS_NOT_FOUND;
                }
                else if (qsc_oid_to_asn1(curveoid, &spki->algorithm.parameter_oid) == false)
                {
                    status = QSC_ASN1_STATUS_NOT_FOUND;
                }
                else
                {
                    qsc_memutils_copy(spki->publickey, publickey, publickeylen);
                    spki->publickeylen = publickeylen;
                    spki->unusedbits = 0U;
                    status = qsc_x509_spki_validate(spki);
                }
            }
        }
    }

    return status;
}
qsc_asn1_status qsc_x509_spki_initialize_ml_dsa(qsc_x509_subject_public_key_info* spki, qsc_x509_pqc_parameter_set parameterset, const uint8_t* publickey, size_t publickeylen)
{
    QSC_ASSERT(spki != NULL);
    QSC_ASSERT(publickey != NULL);

    qsc_asn1_status status;
    size_t expected;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    expected = 0U;

    if ((spki != NULL) && (publickey != NULL))
    {
        expected = qsc_x509_pqc_public_key_size(parameterset);

        if (expected == 0U)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else if (x509_spki_mldsa_parameter_set_matches_build(parameterset) == false)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else if ((publickeylen != expected) || (publickeylen > sizeof(spki->publickey)))
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
#if defined(QSC_DILITHIUM_PUBLICKEY_SIZE)
        else if ((publickeylen != QSC_DILITHIUM_PUBLICKEY_SIZE) || (expected != QSC_DILITHIUM_PUBLICKEY_SIZE))
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
#endif
        else
        {
            qsc_x509_subject_public_key_info_initialize(spki);
            status = qsc_x509_algorithm_identifier_initialize_mldsa(&spki->algorithm, parameterset);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                qsc_memutils_copy(spki->publickey, publickey, publickeylen);
                spki->publickeylen = publickeylen;
                spki->unusedbits = 0U;
                status = qsc_x509_spki_validate(spki);
            }
        }
    }

    return status;
}

qsc_asn1_status qsc_x509_spki_initialize_ml_kem(qsc_x509_subject_public_key_info* spki, qsc_x509_pqc_parameter_set parameterset, const uint8_t* publickey, size_t publickeylen)
{
    QSC_ASSERT(spki != NULL);
    QSC_ASSERT(publickey != NULL);

    qsc_asn1_status status;
    size_t expected;

    status = QSC_ASN1_STATUS_INVALID_INPUT;
    expected = 0U;

    if ((spki != NULL) && (publickey != NULL))
    {
        expected = qsc_x509_pqc_public_key_size(parameterset);

        if (expected == 0U)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else if (x509_spki_mlkem_parameter_set_matches_build(parameterset) == false)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else if ((publickeylen != expected) || (publickeylen > sizeof(spki->publickey)))
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
#if defined(QSC_KYBER_PUBLICKEY_SIZE)
        else if ((publickeylen != QSC_KYBER_PUBLICKEY_SIZE) || (expected != QSC_KYBER_PUBLICKEY_SIZE))
        {
            status = QSC_ASN1_STATUS_INVALID_LENGTH;
        }
#endif
        else
        {
            qsc_x509_subject_public_key_info_initialize(spki);
            status = qsc_x509_algorithm_identifier_initialize_mlkem(&spki->algorithm, parameterset);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                qsc_memutils_copy(spki->publickey, publickey, publickeylen);
                spki->publickeylen = publickeylen;
                spki->unusedbits = 0U;
                status = qsc_x509_spki_validate(spki);
            }
        }
    }

    return status;
}
