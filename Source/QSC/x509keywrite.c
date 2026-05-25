#include "x509keywrite.h"
#include "encoding.h"
#include "memutils.h"
#include "stringutils.h"
#include "x509write.h"

#define QSC_X509_PEM_PKCS8_LABEL "PRIVATE KEY"
#define QSC_X509_PEM_SEC1_LABEL "EC PRIVATE KEY"

static size_t x509_keywrite_ml_dsa_private_size(qsc_x509_pqc_parameter_set parameter)
{
    size_t klen;

    switch (parameter)
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

    return klen;
}

static size_t x509_keywrite_ml_dsa_public_size(qsc_x509_pqc_parameter_set parameter)
{
    size_t klen;

    switch (parameter)
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

    return klen;
}

static size_t x509_keywrite_ml_kem_private_size(qsc_x509_pqc_parameter_set parameter)
{
    size_t klen;

    switch (parameter)
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

    return klen;
}

static size_t x509_keywrite_ml_kem_public_size(qsc_x509_pqc_parameter_set parameter)
{
    size_t klen;

    switch (parameter)
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

    return klen;
}

static qsc_asn1_status x509_keywrite_validate_ml_dsa_material(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* privatekey, 
    size_t privatekeylen, const uint8_t* publickey, size_t publickeylen, bool publickeypresent)
{
    const size_t expectedpriv = (algorithm == NULL) ? 0U : x509_keywrite_ml_dsa_private_size(algorithm->pqcparameter);
    const size_t expectedpub = (algorithm == NULL) ? 0U : x509_keywrite_ml_dsa_public_size(algorithm->pqcparameter);
    qsc_asn1_status status;

    if ((algorithm == NULL) || (privatekey == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((expectedpriv == 0U) || (expectedpub == 0U))
    {
        status = QSC_ASN1_STATUS_UNSUPPORTED;
    }
    else if (privatekeylen != expectedpriv)
    {
        status = QSC_ASN1_STATUS_INVALID_LENGTH;
    }
    else if ((publickeypresent == true) && ((publickey == NULL) || (publickeylen != expectedpub)))
    {
        status = QSC_ASN1_STATUS_INVALID_LENGTH;
    }
    else
    {
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

static qsc_asn1_status x509_keywrite_validate_ml_kem_material(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* privatekey, 
    size_t privatekeylen, const uint8_t* publickey, size_t publickeylen, bool publickeypresent)
{
    const size_t expectedpriv = (algorithm == NULL) ? 0U : x509_keywrite_ml_kem_private_size(algorithm->pqcparameter);
    const size_t expectedpub = (algorithm == NULL) ? 0U : x509_keywrite_ml_kem_public_size(algorithm->pqcparameter);
    qsc_asn1_status status;

    if ((algorithm == NULL) || (privatekey == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((expectedpriv == 0U) || (expectedpub == 0U))
    {
        status = QSC_ASN1_STATUS_UNSUPPORTED;
    }
    else if (privatekeylen != expectedpriv)
    {
        status = QSC_ASN1_STATUS_INVALID_LENGTH;
    }
    else if ((publickeypresent == true) && ((publickey == NULL) || (publickeylen != expectedpub)))
    {
        status = QSC_ASN1_STATUS_INVALID_LENGTH;
    }
    else
    {
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

static size_t x509_keywrite_curve_scalar_size(qsc_x509_named_curve curve)
{
    size_t res;

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
    else
    {
        res = 0U;
    }

    return res;
}

static size_t x509_keywrite_curve_public_key_size(qsc_x509_named_curve curve)
{
    size_t res;

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
    else
    {
        res = 0U;
    }

    return res;
}

static qsc_asn1_status x509_keywrite_build_curve_oid(qsc_x509_named_curve curve, qsc_asn1_oid* oid)
{
    qsc_asn1_status status;

    if (oid == NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_memutils_clear((uint8_t*)oid, sizeof(qsc_asn1_oid));

        switch (curve)
        {
        case QSC_X509_NAMED_CURVE_PRIME256V1:
        {
            static const uint32_t arcs[] = { 1U, 2U, 840U, 10045U, 3U, 1U, 7U };
            static const uint8_t data[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U };
            oid->arcscount = sizeof(arcs) / sizeof(arcs[0]);
            oid->length = sizeof(data);
            qsc_memutils_copy((uint8_t*)oid->arcs, (const uint8_t*)arcs, sizeof(arcs));
            qsc_memutils_copy(oid->data, data, sizeof(data));
            status = QSC_ASN1_STATUS_SUCCESS;
            break;
        }
        case QSC_X509_NAMED_CURVE_SECP384R1:
        {
            static const uint32_t arcs[] = { 1U, 3U, 132U, 0U, 34U };
            static const uint8_t data[] = { 0x2BU, 0x81U, 0x04U, 0x00U, 0x22U };
            oid->arcscount = sizeof(arcs) / sizeof(arcs[0]);
            oid->length = sizeof(data);
            qsc_memutils_copy((uint8_t*)oid->arcs, (const uint8_t*)arcs, sizeof(arcs));
            qsc_memutils_copy(oid->data, data, sizeof(data));
            status = QSC_ASN1_STATUS_SUCCESS;
            break;
        }
        case QSC_X509_NAMED_CURVE_SECP521R1:
        {
            static const uint32_t arcs[] = { 1U, 3U, 132U, 0U, 35U };
            static const uint8_t data[] = { 0x2BU, 0x81U, 0x04U, 0x00U, 0x23U };
            oid->arcscount = sizeof(arcs) / sizeof(arcs[0]);
            oid->length = sizeof(data);
            qsc_memutils_copy((uint8_t*)oid->arcs, (const uint8_t*)arcs, sizeof(arcs));
            qsc_memutils_copy(oid->data, data, sizeof(data));
            status = QSC_ASN1_STATUS_SUCCESS;
            break;
        }
        default:
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        }
    }

    return status;
}

static qsc_asn1_status x509_keywrite_build_ec_algorithm(qsc_x509_named_curve curve, qsc_x509_algorithm_identifier* algorithm)
{
    qsc_asn1_oid algoid = { 0 };
    qsc_asn1_oid paramoid = { 0 };
    qsc_asn1_status status;

    if (algorithm == NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_memutils_clear((uint8_t*)algorithm, sizeof(qsc_x509_algorithm_identifier));

        algoid.arcscount = 6U;
        algoid.length = 7U;
        algoid.arcs[0U] = 1U;
        algoid.arcs[1U] = 2U;
        algoid.arcs[2U] = 840U;
        algoid.arcs[3U] = 10045U;
        algoid.arcs[4U] = 2U;
        algoid.arcs[5U] = 1U;
        algoid.data[0U] = 0x2AU;
        algoid.data[1U] = 0x86U;
        algoid.data[2U] = 0x48U;
        algoid.data[3U] = 0xCEU;
        algoid.data[4U] = 0x3DU;
        algoid.data[5U] = 0x02U;
        algoid.data[6U] = 0x01U;

        if (x509_keywrite_build_curve_oid(curve, &paramoid) != QSC_ASN1_STATUS_SUCCESS)
        {
            status = QSC_ASN1_STATUS_UNSUPPORTED;
        }
        else
        {
            algorithm->oid = QSC_OID_ID_EC_PUBLIC_KEY;
            algorithm->publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_EC;
            algorithm->curve = curve;
            algorithm->pqcparameter = QSC_X509_PQC_PARAMETER_SET_NONE;
            algorithm->algorithm_oid = algoid;
            algorithm->parameter_oid = paramoid;
            algorithm->parameters_present = true;
            algorithm->parameters_null = false;
            algorithm->parameters_oid = true;
            status = QSC_ASN1_STATUS_SUCCESS;
        }
    }

    return status;
}

static qsc_asn1_status x509_keywrite_encode_pem_label(const char* label, const uint8_t* der, size_t derlen, char* output, size_t* outputlen)
{
    qsc_asn1_status status;

    if (((der == NULL) && (derlen != 0U)) || (label == NULL) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else if ((output == NULL) || (*outputlen == 0U))
    {
        *outputlen = ((derlen + 2U) / 3U) * 4U + 128U;
        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }
    else if (qsc_encoding_pem_encode(label, output, *outputlen, der, derlen) == false)
    {
        *outputlen = ((derlen + 2U) / 3U) * 4U + 128U;
        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        *outputlen = qsc_stringutils_string_size(output) + 1U;
        status = QSC_ASN1_STATUS_SUCCESS;
    }

    return status;
}

static qsc_asn1_status x509_keywrite_encode_ec_private_key_der(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* privatekey, size_t privatekeylen,
    const uint8_t* publickey, size_t publickeylen, bool includeparameters, bool includepublickey, uint8_t* output, size_t* outputlen)
{
    uint8_t content[QSC_X509_KEY_WRITE_MAX] = { 0U };
    uint8_t tmp[QSC_X509_KEY_WRITE_MAX] = { 0U };
    qsc_asn1_oid curveoid;
    size_t expectedpriv;
    size_t expectedpub;
    size_t len;
    size_t pos;
    uint8_t version[1U] = { 0x01U };
    qsc_asn1_status status;

    if ((algorithm == NULL) || ((privatekey == NULL) && (privatekeylen != 0U)) || (outputlen == NULL))
    {
        return QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if ((algorithm->publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_EC) || (algorithm->curve == QSC_X509_NAMED_CURVE_NONE))
    {
        return QSC_ASN1_STATUS_UNSUPPORTED;
    }

    expectedpriv = x509_keywrite_curve_scalar_size(algorithm->curve);
    expectedpub = x509_keywrite_curve_public_key_size(algorithm->curve);

    if ((expectedpriv == 0U) || (privatekeylen != expectedpriv))
    {
        return QSC_ASN1_STATUS_INVALID_LENGTH;
    }

    if ((includepublickey == true) && ((publickey == NULL) || (publickeylen != expectedpub)))
    {
        return QSC_ASN1_STATUS_INVALID_LENGTH;
    }

    qsc_memutils_clear((uint8_t*)&curveoid, sizeof(qsc_asn1_oid));
    status = x509_keywrite_build_curve_oid(algorithm->curve, &curveoid);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        return status;
    }

    pos = 0U;
    len = sizeof(content) - pos;
    status = qsc_x509_write_integer(version, sizeof(version), content + pos, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        qsc_memutils_secure_erase(tmp, sizeof(tmp));
        return status;
    }

    pos += len;
    len = sizeof(content) - pos;
    status = qsc_x509_write_octet_string(privatekey, privatekeylen, content + pos, &len);

    if (status != QSC_ASN1_STATUS_SUCCESS)
    {
        qsc_memutils_secure_erase(tmp, sizeof(tmp));
        return status;
    }

    pos += len;

    if (includeparameters == true)
    {
        len = sizeof(tmp);
        status = qsc_x509_write_oid(&curveoid, tmp, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_memutils_secure_erase(tmp, sizeof(tmp));
            return status;
        }

        if ((sizeof(content) - pos) < (len + 8U))
        {
            qsc_memutils_secure_erase(tmp, sizeof(tmp));
            return QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
        }

        {
            size_t explen = sizeof(content) - pos;
            status = qsc_x509_write_explicit(0U, tmp, len, content + pos, &explen);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                qsc_memutils_secure_erase(tmp, sizeof(tmp));
                return status;
            }

            pos += explen;
        }
    }

    if (includepublickey == true)
    {
        len = sizeof(tmp);
        status = qsc_x509_write_bit_string(publickey, publickeylen, 0U, tmp, &len);

        if (status != QSC_ASN1_STATUS_SUCCESS)
        {
            qsc_memutils_secure_erase(tmp, sizeof(tmp));
            return status;
        }

        {
            size_t explen = sizeof(content) - pos;
            status = qsc_x509_write_explicit(1U, tmp, len, content + pos, &explen);

            if (status != QSC_ASN1_STATUS_SUCCESS)
            {
                qsc_memutils_secure_erase(tmp, sizeof(tmp));
                return status;
            }

            pos += explen;
        }
    }

    status = qsc_x509_write_sequence(content, pos, output, outputlen);
    qsc_memutils_secure_erase(tmp, sizeof(tmp));

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_sec1_der(const qsc_x509_private_key* key, bool includeparameters, bool includepublickey, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(key != NULL);
    QSC_ASSERT(outputlen != NULL);

    qsc_asn1_status status;

    if ((key != NULL) && (outputlen != NULL))
    {
        status = x509_keywrite_encode_ec_private_key_der(&key->algorithm,
            key->privatekey, key->privatekeylen,
            key->publickey, key->publickeylen,
            includeparameters,
            (includepublickey == true && key->publickey_present == true),
            output, outputlen);
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_sec1_pem(const qsc_x509_private_key* key, bool includeparameters, bool includepublickey, char* output, size_t* outputlen)
{
    QSC_ASSERT(key != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t der[QSC_X509_KEY_WRITE_MAX] = { 0U };
    size_t derlen;
    qsc_asn1_status status;

    if ((key != NULL) && (outputlen != NULL))
    {
        derlen = sizeof(der);
        status = qsc_x509_private_key_encode_sec1_der(key, includeparameters, includepublickey, der, &derlen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = x509_keywrite_encode_pem_label(QSC_X509_PEM_SEC1_LABEL, der, derlen, output, outputlen);
        }

        qsc_memutils_secure_erase(der, sizeof(der));
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_pkcs8_der(const qsc_x509_private_key* key, bool includepublickey, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(key != NULL);
    QSC_ASSERT(outputlen != NULL);

    qsc_asn1_status status;

    if ((key != NULL) && (outputlen != NULL))
    {
        status = qsc_x509_private_key_encode_pkcs8_der_ex(&key->algorithm,
            key->privatekey, key->privatekeylen,
            key->publickey, key->publickeylen,
            (includepublickey == true && key->publickey_present == true),
            output, outputlen);
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_pkcs8_pem(const qsc_x509_private_key* key, bool includepublickey, char* output, size_t* outputlen)
{
    QSC_ASSERT(key != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t der[QSC_X509_KEY_WRITE_MAX] = { 0U };
    size_t derlen;
    qsc_asn1_status status;

    if ((key != NULL) && (outputlen != NULL))
    {
        derlen = sizeof(der);
        status = qsc_x509_private_key_encode_pkcs8_der(key, includepublickey, der, &derlen);

        if (status == QSC_ASN1_STATUS_SUCCESS)
        {
            status = x509_keywrite_encode_pem_label(QSC_X509_PEM_PKCS8_LABEL, der, derlen, output, outputlen);
        }

        qsc_memutils_secure_erase(der, sizeof(der));
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_pkcs8_der_ex(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* privatekey, size_t privatekeylen,
    const uint8_t* publickey, size_t publickeylen, bool publickeypresent, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(algorithm != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t algbuf[256U] = { 0U };
    uint8_t version[1U] = { 0x00U };
    uint8_t* content;
    uint8_t* explicitfield;
    uint8_t* bitstr;
    uint8_t* inner;
    qsc_x509_algorithm_identifier localalg;
    const qsc_x509_algorithm_identifier* encalg;
    size_t alglen;
    size_t innerlen;
    size_t len;
    size_t pos;
    qsc_asn1_status status;

    qsc_memutils_clear((uint8_t*)&localalg, sizeof(qsc_x509_algorithm_identifier));
    content = (uint8_t*)NULL;
    explicitfield = (uint8_t*)NULL;
    bitstr = (uint8_t*)NULL;
    inner = (uint8_t*)NULL;
    encalg = algorithm;
    alglen = 0U;
    innerlen = 0U;
    len = 0U;
    pos = 0U;
    status = QSC_ASN1_STATUS_FAILURE;

    if ((algorithm == NULL) || ((privatekey == NULL) && (privatekeylen != 0U)) || (outputlen == NULL))
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        inner = (uint8_t*)qsc_memutils_malloc(QSC_X509_KEY_WRITE_MAX);
        content = (uint8_t*)qsc_memutils_malloc(QSC_X509_KEY_WRITE_MAX);

        if ((inner == (uint8_t*)NULL) || (content == (uint8_t*)NULL))
        {
            status = QSC_ASN1_STATUS_FAILURE;
        }
        else
        {
            qsc_memutils_clear(inner, QSC_X509_KEY_WRITE_MAX);
            qsc_memutils_clear(content, QSC_X509_KEY_WRITE_MAX);

            if ((publickeypresent == true) && (algorithm->publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_EC))
            {
                version[0U] = 0x01U;
            }

            if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC)
            {
                localalg = *algorithm;
                encalg = &localalg;

                if ((localalg.parameters_oid == false) || (localalg.parameters_present == false) || (localalg.curve == QSC_X509_NAMED_CURVE_NONE))
                {
                    status = x509_keywrite_build_ec_algorithm(algorithm->curve, &localalg);
                }
                else
                {
                    status = QSC_ASN1_STATUS_SUCCESS;
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    innerlen = QSC_X509_KEY_WRITE_MAX;
                    status = x509_keywrite_encode_ec_private_key_der(encalg,
                        privatekey, privatekeylen,
                        publickey, publickeylen,
                        true,
                        publickeypresent,
                        inner, &innerlen);
                }
            }
            else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA)
            {
                status = x509_keywrite_validate_ml_dsa_material(algorithm, privatekey, privatekeylen, publickey, publickeylen, publickeypresent);

                if ((status == QSC_ASN1_STATUS_SUCCESS) && (privatekeylen > QSC_X509_KEY_WRITE_MAX))
                {
                    status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    qsc_memutils_copy(inner, privatekey, privatekeylen);
                    innerlen = privatekeylen;
                }
            }
            else if (algorithm->publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM)
            {
                status = x509_keywrite_validate_ml_kem_material(algorithm, privatekey, privatekeylen, publickey, publickeylen, publickeypresent);

                if ((status == QSC_ASN1_STATUS_SUCCESS) && (privatekeylen > QSC_X509_KEY_WRITE_MAX))
                {
                    status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                }

                if (status == QSC_ASN1_STATUS_SUCCESS)
                {
                    qsc_memutils_copy(inner, privatekey, privatekeylen);
                    innerlen = privatekeylen;
                }
            }
            else
            {
                status = QSC_ASN1_STATUS_UNSUPPORTED;
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                alglen = sizeof(algbuf);
                status = qsc_x509_write_algorithm_identifier(encalg, algbuf, &alglen);
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                len = QSC_X509_KEY_WRITE_MAX - pos;
                status = qsc_x509_write_integer(version, sizeof(version), content + pos, &len);
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                pos += len;

                if ((QSC_X509_KEY_WRITE_MAX - pos) < alglen)
                {
                    status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                }
                else
                {
                    qsc_memutils_copy(content + pos, algbuf, alglen);
                    pos += alglen;
                    len = QSC_X509_KEY_WRITE_MAX - pos;
                    status = qsc_x509_write_octet_string(inner, innerlen, content + pos, &len);
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                pos += len;
            }

            if ((status == QSC_ASN1_STATUS_SUCCESS) && (publickeypresent == true) && (algorithm->publickey != QSC_X509_PUBLIC_KEY_ALGORITHM_EC))
            {
                size_t bitstrlen;
                size_t explicitlen;

                bitstr = (uint8_t*)qsc_memutils_malloc(QSC_X509_KEY_WRITE_MAX);
                explicitfield = (uint8_t*)qsc_memutils_malloc(QSC_X509_KEY_WRITE_MAX);

                if ((bitstr == (uint8_t*)NULL) || (explicitfield == (uint8_t*)NULL))
                {
                    status = QSC_ASN1_STATUS_FAILURE;
                }
                else
                {
                    qsc_memutils_clear(bitstr, QSC_X509_KEY_WRITE_MAX);
                    qsc_memutils_clear(explicitfield, QSC_X509_KEY_WRITE_MAX);
                    bitstrlen = QSC_X509_KEY_WRITE_MAX;
                    explicitlen = QSC_X509_KEY_WRITE_MAX;

                    status = qsc_x509_write_bit_string(publickey, publickeylen, 0U, bitstr, &bitstrlen);

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        status = qsc_x509_write_explicit(1U, bitstr, bitstrlen, explicitfield, &explicitlen);
                    }

                    if ((status == QSC_ASN1_STATUS_SUCCESS) && ((QSC_X509_KEY_WRITE_MAX - pos) < explicitlen))
                    {
                        status = QSC_ASN1_STATUS_BUFFER_TOO_SMALL;
                    }

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        qsc_memutils_copy(content + pos, explicitfield, explicitlen);
                        pos += explicitlen;
                    }
                }
            }

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = qsc_x509_write_sequence(content, pos, output, outputlen);
            }
        }
    }

    if (bitstr != (uint8_t*)NULL)
    {
        qsc_memutils_secure_erase(bitstr, QSC_X509_KEY_WRITE_MAX);
        qsc_memutils_alloc_free(bitstr);
    }

    if (explicitfield != (uint8_t*)NULL)
    {
        qsc_memutils_secure_erase(explicitfield, QSC_X509_KEY_WRITE_MAX);
        qsc_memutils_alloc_free(explicitfield);
    }

    if (inner != (uint8_t*)NULL)
    {
        qsc_memutils_secure_erase(inner, QSC_X509_KEY_WRITE_MAX);
        qsc_memutils_alloc_free(inner);
    }

    if (content != (uint8_t*)NULL)
    {
        qsc_memutils_secure_erase(content, QSC_X509_KEY_WRITE_MAX);
        qsc_memutils_alloc_free(content);
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_pkcs8_pem_ex(const qsc_x509_algorithm_identifier* algorithm, const uint8_t* privatekey, size_t privatekeylen,
    const uint8_t* publickey, size_t publickeylen, bool publickeypresent, char* output, size_t* outputlen)
{
    QSC_ASSERT(algorithm != NULL);
    QSC_ASSERT(outputlen != NULL);

    uint8_t* der;
    size_t derlen;
    qsc_asn1_status status;

    der = (uint8_t*)NULL;

    if ((algorithm != NULL) && (outputlen != NULL))
    {
        der = (uint8_t*)qsc_memutils_malloc(QSC_X509_KEY_WRITE_MAX);

        if (der == (uint8_t*)NULL)
        {
            status = QSC_ASN1_STATUS_FAILURE;
        }
        else
        {
            qsc_memutils_clear(der, QSC_X509_KEY_WRITE_MAX);
            derlen = QSC_X509_KEY_WRITE_MAX;
            status = qsc_x509_private_key_encode_pkcs8_der_ex(algorithm, privatekey, privatekeylen, publickey, publickeylen, publickeypresent, der, &derlen);

            if (status == QSC_ASN1_STATUS_SUCCESS)
            {
                status = x509_keywrite_encode_pem_label(QSC_X509_PEM_PKCS8_LABEL, der, derlen, output, outputlen);
            }
        }
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    if (der != (uint8_t*)NULL)
    {
        qsc_memutils_secure_erase(der, QSC_X509_KEY_WRITE_MAX);
        qsc_memutils_alloc_free(der);
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_pkcs8_ml_dsa_der(qsc_x509_pqc_parameter_set parameter, const uint8_t* privatekey, size_t privatekeylen,
    const uint8_t* publickey, size_t publickeylen, bool publickeypresent, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    qsc_x509_algorithm_identifier algorithm = { 0 };
    qsc_asn1_status status;

    if (outputlen != NULL)
    {
        algorithm.publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA;
        algorithm.pqcparameter = parameter;

        status = qsc_x509_private_key_encode_pkcs8_der_ex(&algorithm, privatekey, privatekeylen, publickey,
            publickeylen, publickeypresent, output, outputlen);
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_pkcs8_ml_dsa_pem(qsc_x509_pqc_parameter_set parameter, const uint8_t* privatekey, size_t privatekeylen,
    const uint8_t* publickey, size_t publickeylen, bool publickeypresent, char* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    qsc_x509_algorithm_identifier algorithm = { 0 };
    qsc_asn1_status status;

    if (outputlen != NULL)
    {
        algorithm.publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA;
        algorithm.pqcparameter = parameter;

        status = qsc_x509_private_key_encode_pkcs8_pem_ex(&algorithm, privatekey, privatekeylen, publickey, publickeylen, publickeypresent, output, outputlen);
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_pkcs8_ml_kem_der(qsc_x509_pqc_parameter_set parameter, const uint8_t* privatekey, size_t privatekeylen,
    const uint8_t* publickey, size_t publickeylen, bool publickeypresent, uint8_t* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    qsc_x509_algorithm_identifier algorithm = { 0 };
    qsc_asn1_status status;

    if (outputlen != NULL)
    {
        algorithm.publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM;
        algorithm.pqcparameter = parameter;

        status = qsc_x509_private_key_encode_pkcs8_der_ex(&algorithm, privatekey, privatekeylen, publickey,
            publickeylen, publickeypresent, output, outputlen);
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}

qsc_asn1_status qsc_x509_private_key_encode_pkcs8_ml_kem_pem(qsc_x509_pqc_parameter_set parameter, const uint8_t* privatekey, size_t privatekeylen,
    const uint8_t* publickey, size_t publickeylen, bool publickeypresent, char* output, size_t* outputlen)
{
    QSC_ASSERT(outputlen != NULL);

    qsc_x509_algorithm_identifier algorithm = { 0 };
    qsc_asn1_status status;

    if (outputlen != NULL)
    {
        algorithm.publickey = QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM;
        algorithm.pqcparameter = parameter;
        status = qsc_x509_private_key_encode_pkcs8_pem_ex(&algorithm, privatekey, privatekeylen, publickey, publickeylen, publickeypresent, output, outputlen);
    }
    else
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }

    return status;
}
