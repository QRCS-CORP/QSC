#include "x509verify.h"
#include "memutils.h"
#include "x509cert.h"
#include "x509name.h"
#include "x509sig.h"
#include "x509host.h"
#include "x509store.h"

static bool x509_time_is_zero(const qsc_asn1_time* time)
{
    bool res;

    res = false;

    if (time != (const qsc_asn1_time*)NULL)
    {
        res = (time->year == 0U && time->month == 0U && time->day == 0U &&
            time->hour == 0U && time->minute == 0U && time->second == 0U);
    }

    return res;
}

static qsc_x509_verify_status x509_check_certificate_minimal(const qsc_x509_certificate* certificate)
{
    qsc_x509_verify_status status;

    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (certificate == (const qsc_x509_certificate*)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else if (certificate->version < 1U || certificate->version > 3U)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
    }
    else if (certificate->serialnumberlen == 0U)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
    }
    else if (certificate->tbsdata == (const uint8_t*)NULL || certificate->tbsdatalen == 0U)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
    }
    else if (certificate->signaturelen == 0U)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
    }
    else if (certificate->subjectpublickeyinfo.publickeylen == 0U)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
    }

    return status;
}

static bool x509_key_identifier_matches(const qsc_x509_subject_key_identifier* ski, const qsc_x509_authority_key_identifier* aki)
{
    bool res;

    res = true;

    if (ski != (const qsc_x509_subject_key_identifier*)NULL &&
        aki != (const qsc_x509_authority_key_identifier*)NULL &&
        ski->present == true && aki->present == true && aki->keyidentifierlen != 0U)
    {
        if (ski->identifierlen != aki->keyidentifierlen)
        {
            res = false;
        }
        else
        {
            res = qsc_memutils_are_equal((uint8_t*)ski->identifier, (uint8_t*)aki->keyidentifier, ski->identifierlen);
        }
    }

    return res;
}

static bool x509_name_present(const qsc_x509_name* name)
{
    bool res;

    res = false;

    if (name != (const qsc_x509_name*)NULL)
    {
        res = (name->count != 0U);
    }

    return res;
}

static bool x509_usage_has_cert_sign(const qsc_x509_certificate* certificate)
{
    bool res;

    res = true;

    if (certificate != (const qsc_x509_certificate*)NULL && certificate->extensions.keyusage.present == true)
    {
        res = ((certificate->extensions.keyusage.bits & QSC_X509_KEY_USAGE_KEY_CERT_SIGN) != 0U);
    }

    return res;
}

static bool x509_spki_is_signature_capable(const qsc_x509_subject_public_key_info* spki)
{
    bool res;

    res = false;

    if (spki != (const qsc_x509_subject_public_key_info*)NULL)
    {
        res = (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_RSA ||
            spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_EC ||
            spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA);
    }

    return res;
}

static bool x509_spki_is_kem_only(const qsc_x509_subject_public_key_info* spki)
{
    bool res;

    res = false;

    if (spki != (const qsc_x509_subject_public_key_info*)NULL)
    {
        res = (spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_KEM);
    }

    return res;
}

static bool x509_extension_is_verification_supported(qsc_x509_extension_type type)
{
    bool res;

    res = false;

    if (type == QSC_X509_EXTENSION_BASIC_CONSTRAINTS ||
        type == QSC_X509_EXTENSION_KEY_USAGE ||
        type == QSC_X509_EXTENSION_SUBJECT_KEY_IDENTIFIER ||
        type == QSC_X509_EXTENSION_AUTHORITY_KEY_IDENTIFIER ||
        type == QSC_X509_EXTENSION_SUBJECT_ALT_NAME ||
        type == QSC_X509_EXTENSION_ISSUER_ALT_NAME ||
        type == QSC_X509_EXTENSION_EXTENDED_KEY_USAGE)
    {
        res = true;
    }

    return res;
}

static bool x509_signature_can_be_verified_by_issuer(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer)
{
    bool res;

    res = false;

    if ((certificate != (const qsc_x509_certificate*)NULL) && (issuer != (const qsc_x509_certificate*)NULL))
    {
        res = qsc_x509_signature_algorithm_matches_spki(certificate->signaturealgorithm.signature, &issuer->subjectpublickeyinfo);
    }

    return res;
}

static qsc_x509_verify_status x509_check_signature_encoding_constraints(const qsc_x509_certificate* certificate)
{
    qsc_x509_verify_status status;
    size_t explen;

    status = QSC_X509_VERIFY_STATUS_SUCCESS;
    explen = 0U;

    if (certificate == (const qsc_x509_certificate*)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else if (certificate->signaturelen == 0U)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
    }
    else if (certificate->signatureunusedbits != 0U)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
    }
    else if ((certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_44) ||
             (certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_65) ||
             (certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ML_DSA_87))
    {
        explen = qsc_x509_signature_expected_size(certificate->signaturealgorithm.signature, QSC_X509_NAMED_CURVE_NONE);

        if ((explen == 0U) || (certificate->signaturelen != explen))
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
        }
    }

    return status;
}

static qsc_x509_verify_status x509_check_subject_public_key_usage(const qsc_x509_certificate* certificate)
{
    uint16_t bits;

    if (certificate == (const qsc_x509_certificate*)NULL)
    {
        return QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }

    if (x509_spki_is_kem_only(&certificate->subjectpublickeyinfo) == true &&
        certificate->extensions.basicconstraints.present == true && certificate->extensions.basicconstraints.ca == true)
    {
        return QSC_X509_VERIFY_STATUS_NOT_CA;
    }

    if (certificate->extensions.keyusage.present == false)
    {
        return QSC_X509_VERIFY_STATUS_SUCCESS;
    }

    bits = certificate->extensions.keyusage.bits;

    if (x509_spki_is_kem_only(&certificate->subjectpublickeyinfo) == true)
    {
        if ((bits & QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT) == 0U ||
            (bits & (QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE | QSC_X509_KEY_USAGE_KEY_CERT_SIGN | QSC_X509_KEY_USAGE_CRL_SIGN)) != 0U)
        {
            return QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED;
        }
    }
    else if (certificate->subjectpublickeyinfo.algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA)
    {
        if ((bits & (QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT | QSC_X509_KEY_USAGE_DATA_ENCIPHERMENT |
                     QSC_X509_KEY_USAGE_KEY_AGREEMENT | QSC_X509_KEY_USAGE_ENCIPHER_ONLY |
                     QSC_X509_KEY_USAGE_DECIPHER_ONLY)) != 0U)
        {
            return QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED;
        }
    }

    return QSC_X509_VERIFY_STATUS_SUCCESS;
}

static qsc_x509_verify_status x509_check_critical_extensions(const qsc_x509_certificate* certificate, bool strictreject)
{
    qsc_x509_verify_status status;
    size_t i;

    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (certificate == (const qsc_x509_certificate*)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else if (strictreject == true)
    {
        for (i = 0U; i < certificate->extensions.count; ++i)
        {
            if (certificate->extensions.entries[i].critical == true &&
                x509_extension_is_verification_supported(certificate->extensions.entries[i].type) == false)
            {
                status = QSC_X509_VERIFY_STATUS_UNSUPPORTED_CRITICAL_EXTENSION;
                break;
            }
        }
    }

    return status;
}

static qsc_x509_verify_status x509_authority_cert_issuer_matches(const qsc_x509_certificate* issuer, const qsc_x509_authority_key_identifier* aki)
{
    qsc_x509_verify_status status;

    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (issuer != (const qsc_x509_certificate*)NULL && aki != (const qsc_x509_authority_key_identifier*)NULL &&
        aki->present == true && aki->issuer_present == true)
    {
        if (aki->issuername_present == false)
        {
            status = QSC_X509_VERIFY_STATUS_UNSUPPORTED;
        }
        else if (x509_name_present(&issuer->subject) == false || x509_name_present(&aki->issuername) == false)
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
        }
        else if (qsc_x509_name_equals(&issuer->subject, &aki->issuername) == false)
        {
            status = QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH;
        }
    }

    return status;
}

static bool x509_authority_serial_matches(const qsc_x509_certificate* issuer, const qsc_x509_authority_key_identifier* aki)
{
    const uint8_t* serial;
    size_t seriallen;
    size_t ofs;
    bool res;

    res = true;
    serial = (const uint8_t*)NULL;
    seriallen = 0U;
    ofs = 0U;

    if (issuer != (const qsc_x509_certificate*)NULL && aki != (const qsc_x509_authority_key_identifier*)NULL &&
        aki->present == true && aki->serial_present == true)
    {
        if (aki->seriallen == 0U || (aki->serial[0U] & 0x80U) != 0U)
        {
            res = false;
        }
        else
        {
            while (ofs + 1U < aki->seriallen && aki->serial[ofs] == 0x00U)
            {
                ofs += 1U;
            }

            while (seriallen < issuer->serialnumberlen && seriallen + 1U < issuer->serialnumberlen && issuer->serialnumber[seriallen] == 0x00U)
            {
                seriallen += 1U;
            }

            serial = aki->serial + ofs;
            seriallen = aki->seriallen - ofs;

            while (issuer->serialnumberlen > 1U && issuer->serialnumber[0U] == 0x00U)
            {
                break;
            }

            if (seriallen == 0U)
            {
                res = false;
            }
            else
            {
                size_t issuerofs = 0U;

                while (issuerofs + 1U < issuer->serialnumberlen && issuer->serialnumber[issuerofs] == 0x00U)
                {
                    issuerofs += 1U;
                }

                if ((issuer->serialnumberlen - issuerofs) != seriallen)
                {
                    res = false;
                }
                else
                {
                    res = qsc_memutils_are_equal((uint8_t*)issuer->serialnumber + issuerofs, (uint8_t*)serial, seriallen);
                }
            }
        }
    }

    return res;
}

static qsc_x509_verify_status x509_check_trust_anchor_match(const qsc_x509_trust_anchor* anchor, const qsc_x509_certificate* subject)
{
    const qsc_x509_certificate* issuer;
    qsc_x509_verify_status status;

    issuer = (const qsc_x509_certificate*)NULL;
    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (anchor == (const qsc_x509_trust_anchor*)NULL || subject == (const qsc_x509_certificate*)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else
    {
        issuer = &anchor->certificate;

        if (x509_name_present(&issuer->subject) == false || x509_name_present(&subject->issuer) == false)
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
        }
        else if (qsc_x509_name_equals(&issuer->subject, &subject->issuer) == false)
        {
            status = QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH;
        }
        else
        {
            status = x509_authority_cert_issuer_matches(issuer, &subject->extensions.authoritykeyidentifier);

            if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
                x509_key_identifier_matches(&issuer->extensions.subjectkeyidentifier, &subject->extensions.authoritykeyidentifier) == false)
            {
                status = QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH;
            }

            if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
                x509_authority_serial_matches(issuer, &subject->extensions.authoritykeyidentifier) == false)
            {
                status = QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH;
            }
        }
    }

    return status;
}

static qsc_x509_verify_status x509_check_trust_anchor_minimal(const qsc_x509_trust_anchor* anchor)
{
    const qsc_x509_certificate* certificate;
    qsc_x509_verify_status status;

    certificate = (const qsc_x509_certificate*)NULL;
    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (anchor == (const qsc_x509_trust_anchor*)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else
    {
        certificate = &anchor->certificate;

        if (x509_name_present(&certificate->subject) == false || certificate->subjectpublickeyinfo.publickeylen == 0U)
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
        }
    }

    return status;
}

static size_t x509_count_non_self_issued_intermediates_below(const qsc_x509_chain* chain, size_t lastindexinclusive)
{
    const qsc_x509_certificate* certificate;
    size_t count;
    size_t i;

    count = 0U;
    certificate = (const qsc_x509_certificate*)NULL;

    if (chain != (const qsc_x509_chain*)NULL && chain->certificates != (const qsc_x509_certificate*)NULL)
    {
        for (i = 1U; i <= lastindexinclusive && i < chain->count; ++i)
        {
            certificate = &chain->certificates[i];

            if (qsc_x509_certificate_is_ca(certificate) == true && qsc_x509_certificate_is_self_issued(certificate) == false)
            {
                count += 1U;
            }
        }
    }

    return count;
}

static bool x509_certificate_equal(const qsc_x509_certificate* left, const qsc_x509_certificate* right)
{
    bool res;

    res = false;

    if (left != (const qsc_x509_certificate*)NULL && right != (const qsc_x509_certificate*)NULL)
    {
        if (left->der != (const uint8_t*)NULL && right->der != (const uint8_t*)NULL && left->derlen == right->derlen)
        {
            res = qsc_memutils_are_equal((uint8_t*)left->der, (uint8_t*)right->der, left->derlen);
        }
        else if (left->serialnumberlen == right->serialnumberlen &&
            qsc_memutils_are_equal((uint8_t*)left->serialnumber, (uint8_t*)right->serialnumber, left->serialnumberlen) == true &&
            qsc_x509_name_equals(&left->issuer, &right->issuer) == true &&
            qsc_x509_name_equals(&left->subject, &right->subject) == true)
        {
            res = true;
        }
    }

    return res;
}

static qsc_x509_verify_status x509_map_revocation_status(qsc_x509_revocation_status status, qsc_x509_revocation_mode mode)
{
    qsc_x509_verify_status res;

    res = QSC_X509_VERIFY_STATUS_SUCCESS;

    switch (status)
    {
        case QSC_X509_REVOCATION_STATUS_GOOD:
        case QSC_X509_REVOCATION_STATUS_UNCHECKED:
        {
            res = QSC_X509_VERIFY_STATUS_SUCCESS;
            break;
        }
        case QSC_X509_REVOCATION_STATUS_REVOKED:
        {
            res = QSC_X509_VERIFY_STATUS_REVOKED;
            break;
        }
        case QSC_X509_REVOCATION_STATUS_CRL_NOT_FOUND:
        case QSC_X509_REVOCATION_STATUS_CRL_INVALID:
        case QSC_X509_REVOCATION_STATUS_CRL_EXPIRED:
        case QSC_X509_REVOCATION_STATUS_ISSUER_MISMATCH:
        case QSC_X509_REVOCATION_STATUS_ERROR:
        default:
        {
            res = (mode == QSC_X509_REVOCATION_MODE_REQUIRE_VALID_CRL) ?
                QSC_X509_VERIFY_STATUS_REVOCATION_UNKNOWN : QSC_X509_VERIFY_STATUS_SUCCESS;
            break;
        }
    }

    return res;
}

static bool x509_subject_alt_name_has_entries(const qsc_x509_subject_alt_name* san)
{
    return (san != (const qsc_x509_subject_alt_name*)NULL && san->present == true && san->count != 0U);
}

void qsc_x509_verify_options_initialize(qsc_x509_verify_options* options)
{
    QSC_ASSERT(options != NULL);

    if (options != (qsc_x509_verify_options*)NULL)
    {
        qsc_memutils_clear((uint8_t*)options, sizeof(qsc_x509_verify_options));
        options->purpose = QSC_X509_VERIFY_PURPOSE_GENERIC;
        options->rejectunsupportedcriticalextensions = true;
    }
}

bool qsc_x509_certificate_is_self_issued(const qsc_x509_certificate* certificate)
{
    QSC_ASSERT(certificate != NULL);

    bool res;

    res = false;

    if (certificate != (const qsc_x509_certificate*)NULL)
    {
        if (x509_name_present(&certificate->issuer) == true && x509_name_present(&certificate->subject) == true)
        {
            res = qsc_x509_name_equals(&certificate->issuer, &certificate->subject);
        }
    }

    return res;
}

bool qsc_x509_certificate_is_self_signed(const qsc_x509_certificate* certificate, qsc_x509_signature_verify_callback callback, void* state)
{
    QSC_ASSERT(certificate != NULL);

    bool res;

    res = false;

    if (certificate != (const qsc_x509_certificate*)NULL && callback != (qsc_x509_signature_verify_callback)NULL)
    {
        if (qsc_x509_certificate_is_self_issued(certificate) == true &&
            qsc_x509_certificate_check_algorithms(certificate) == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            res = callback(certificate, certificate, state);
        }
    }

    return res;
}

bool qsc_x509_certificate_is_ca(const qsc_x509_certificate* certificate)
{
    QSC_ASSERT(certificate != NULL);

    bool res;

    res = false;

    if (certificate != (const qsc_x509_certificate*)NULL)
    {
        if (certificate->extensions.basicconstraints.present == true && certificate->extensions.basicconstraints.ca == true &&
            x509_spki_is_signature_capable(&certificate->subjectpublickeyinfo) == true)
        {
            res = true;

            if (certificate->extensions.keyusage.present == true)
            {
                res = ((certificate->extensions.keyusage.bits & QSC_X509_KEY_USAGE_KEY_CERT_SIGN) != 0U);
            }
        }
    }

    return res;
}

bool qsc_x509_certificate_allows_server_auth(const qsc_x509_certificate* certificate)
{
    QSC_ASSERT(certificate != NULL);

    uint32_t bits;
    bool res;

    res = false;
    bits = 0U;

    if (certificate != (const qsc_x509_certificate*)NULL)
    {
        res = true;

        if (certificate->extensions.extendedkeyusage.present == true)
        {
            bits = certificate->extensions.extendedkeyusage.bits;
            res = ((bits & QSC_X509_EXTENDED_KEY_USAGE_ANY) != 0U ||
                (bits & QSC_X509_EXTENDED_KEY_USAGE_SERVER_AUTH) != 0U);
        }

        if (res == true && certificate->extensions.keyusage.present == true)
        {
            bits = certificate->extensions.keyusage.bits;
            res = ((bits & QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE) != 0U ||
                (bits & QSC_X509_KEY_USAGE_KEY_ENCIPHERMENT) != 0U ||
                (bits & QSC_X509_KEY_USAGE_KEY_AGREEMENT) != 0U);
        }
    }

    return res;
}

bool qsc_x509_certificate_allows_client_auth(const qsc_x509_certificate* certificate)
{
    QSC_ASSERT(certificate != NULL);

    uint32_t bits;
    bool res;

    res = false;
    bits = 0U;

    if (certificate != (const qsc_x509_certificate*)NULL)
    {
        res = true;

        if (certificate->extensions.extendedkeyusage.present == true)
        {
            bits = certificate->extensions.extendedkeyusage.bits;
            res = ((bits & QSC_X509_EXTENDED_KEY_USAGE_ANY) != 0U ||
                (bits & QSC_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH) != 0U);
        }

        if (res == true && certificate->extensions.keyusage.present == true)
        {
            bits = certificate->extensions.keyusage.bits;
            res = ((bits & QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE) != 0U ||
                (bits & QSC_X509_KEY_USAGE_KEY_AGREEMENT) != 0U);
        }
    }

    return res;
}

qsc_x509_verify_status qsc_x509_certificate_check_structure(const qsc_x509_certificate* certificate)
{
    qsc_x509_verify_status status;

    QSC_ASSERT(certificate != NULL);

    status = x509_check_certificate_minimal(certificate);

    if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
    {
        if (certificate->version == 1U)
        {
            if (certificate->issueruniqueid_present == true || certificate->subjectuniqueid_present == true ||
                certificate->extensions.count != 0U || certificate->extensions.decoded == true)
            {
                status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
            }
        }
        else if (certificate->version == 2U)
        {
            if (certificate->extensions.count != 0U || certificate->extensions.decoded == true)
            {
                status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
            }
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS && x509_name_present(&certificate->subject) == false)
        {
            if (certificate->extensions.subjectaltname.present == false ||
                certificate->extensions.subjectaltname.critical == false ||
                x509_subject_alt_name_has_entries(&certificate->extensions.subjectaltname) == false)
            {
                status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
            }
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
            certificate->extensions.basicconstraints.present == true &&
            certificate->extensions.basicconstraints.ca == true)
        {
            if (x509_spki_is_kem_only(&certificate->subjectpublickeyinfo) == true ||
                x509_spki_is_signature_capable(&certificate->subjectpublickeyinfo) == false)
            {
                status = QSC_X509_VERIFY_STATUS_NOT_CA;
            }
            else if (certificate->extensions.keyusage.present == true &&
                (certificate->extensions.keyusage.bits & QSC_X509_KEY_USAGE_KEY_CERT_SIGN) == 0U)
            {
                status = QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED;
            }
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = x509_check_subject_public_key_usage(certificate);
        }
    }

    return status;
}

qsc_x509_verify_status qsc_x509_certificate_check_algorithms(const qsc_x509_certificate* certificate)
{
    QSC_ASSERT(certificate != NULL);

    qsc_x509_verify_status status;

    status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;

    if (certificate != (const qsc_x509_certificate*)NULL)
    {
        status = qsc_x509_certificate_check_structure(certificate);

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            if (qsc_x509_signature_algorithm_equal(&certificate->tbsignature, &certificate->signaturealgorithm) == false)
            {
                status = QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH;
            }
            else if (certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_NONE ||
                     certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_MD5 ||
                     certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA1 ||
                     certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA1)
            {
                status = QSC_X509_VERIFY_STATUS_UNSUPPORTED;
            }
            else
            {
                status = x509_check_signature_encoding_constraints(certificate);
            }
        }
    }

    return status;
}

qsc_x509_verify_status qsc_x509_certificate_check_validity(const qsc_x509_certificate* certificate, const qsc_asn1_time* ascnow)
{
    QSC_ASSERT(certificate != NULL);

    int32_t cmpna;
    int32_t cmpnb;
    qsc_x509_verify_status status;

    cmpna = 0;
    cmpnb = 0;
    status = x509_check_certificate_minimal(certificate);

    if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
    {
        if (ascnow == (const qsc_asn1_time*)NULL || x509_time_is_zero(ascnow) == true)
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
        }
        else if (qsc_x509_time_is_valid(&certificate->validity.notbefore) == false ||
                 qsc_x509_time_is_valid(&certificate->validity.notafter) == false)
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
        }
        else if (qsc_x509_time_compare(&certificate->validity.notbefore, &certificate->validity.notafter) > 0)
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
        }
        else
        {
            cmpnb = qsc_x509_time_compare(ascnow, &certificate->validity.notbefore);
            cmpna = qsc_x509_time_compare(ascnow, &certificate->validity.notafter);

            if (cmpnb < 0)
            {
                status = QSC_X509_VERIFY_STATUS_NOT_YET_VALID;
            }
            else if (cmpna > 0)
            {
                status = QSC_X509_VERIFY_STATUS_EXPIRED;
            }
        }
    }

    return status;
}

qsc_x509_verify_status qsc_x509_certificate_check_purpose(const qsc_x509_certificate* certificate, qsc_x509_verify_purpose purpose)
{
    qsc_x509_verify_status status;

    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (certificate == (const qsc_x509_certificate*)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else if (purpose == QSC_X509_VERIFY_PURPOSE_TLS_SERVER)
    {
        if ((certificate->extensions.basicconstraints.present == true && certificate->extensions.basicconstraints.ca == true) ||
            qsc_x509_certificate_is_ca(certificate) == true)
        {
            status = QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED;
        }
        else if (qsc_x509_certificate_allows_server_auth(certificate) == false)
        {
            status = QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED;
        }
    }
    else if (purpose == QSC_X509_VERIFY_PURPOSE_TLS_CLIENT)
    {
        if ((certificate->extensions.basicconstraints.present == true && certificate->extensions.basicconstraints.ca == true) ||
            qsc_x509_certificate_is_ca(certificate) == true)
        {
            status = QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED;
        }
        else if (qsc_x509_certificate_allows_client_auth(certificate) == false)
        {
            status = QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED;
        }
    }

    return status;
}

qsc_x509_verify_status qsc_x509_certificate_check_hostname(const qsc_x509_certificate* certificate, const char* hostname)
{
    if (certificate == (const qsc_x509_certificate*)NULL || hostname == (const char*)NULL || hostname[0] == '\0')
    {
        return QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }

    return (qsc_x509_certificate_match_hostname(certificate, hostname) == true) ?
        QSC_X509_VERIFY_STATUS_SUCCESS : QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
}

qsc_x509_verify_status qsc_x509_certificate_check_ip_address(const qsc_x509_certificate* certificate, const uint8_t* address, size_t addresslen)
{
    if (certificate == (const qsc_x509_certificate*)NULL || address == (const uint8_t*)NULL || addresslen == 0U)
    {
        return QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }

    return (qsc_x509_certificate_match_ip_address(certificate, address, addresslen) == true) ?
        QSC_X509_VERIFY_STATUS_SUCCESS : QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
}

qsc_x509_verify_status qsc_x509_certificate_check_issuer(const qsc_x509_certificate* issuer, const qsc_x509_certificate* subject, size_t remainingdepth)
{
    qsc_x509_verify_status status;

    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (issuer == (const qsc_x509_certificate*)NULL || subject == (const qsc_x509_certificate*)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else if (x509_name_present(&issuer->subject) == false || x509_name_present(&subject->issuer) == false)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
    }
    else if (qsc_x509_name_equals(&issuer->subject, &subject->issuer) == false)
    {
        status = QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH;
    }
    else
    {
        status = x509_authority_cert_issuer_matches(issuer, &subject->extensions.authoritykeyidentifier);

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
            x509_key_identifier_matches(&issuer->extensions.subjectkeyidentifier, &subject->extensions.authoritykeyidentifier) == false)
        {
            status = QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH;
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
            x509_authority_serial_matches(issuer, &subject->extensions.authoritykeyidentifier) == false)
        {
            status = QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH;
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS && qsc_x509_certificate_is_ca(issuer) == false)
        {
            status = QSC_X509_VERIFY_STATUS_NOT_CA;
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS && x509_spki_is_signature_capable(&issuer->subjectpublickeyinfo) == false)
        {
            status = QSC_X509_VERIFY_STATUS_NOT_CA;
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS && x509_usage_has_cert_sign(issuer) == false)
        {
            status = QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED;
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS && issuer->extensions.basicconstraints.present == true &&
            issuer->extensions.basicconstraints.pathlen_present == true &&
            remainingdepth > issuer->extensions.basicconstraints.pathlen)
        {
            status = QSC_X509_VERIFY_STATUS_PATH_LENGTH_EXCEEDED;
        }
    }

    return status;
}

qsc_x509_verify_status qsc_x509_certificate_verify_ex(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer,
    const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state, const qsc_x509_verify_options* options)
{
    qsc_x509_revocation_status revstatus;
    qsc_x509_verify_status status;

    revstatus = QSC_X509_REVOCATION_STATUS_UNCHECKED;
    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (callback == (qsc_x509_signature_verify_callback)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else
    {
        status = x509_check_certificate_minimal(certificate);

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = x509_check_certificate_minimal(issuer);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = qsc_x509_certificate_check_algorithms(certificate);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = qsc_x509_certificate_check_algorithms(issuer);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = qsc_x509_certificate_check_validity(certificate, now);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = qsc_x509_certificate_check_validity(issuer, now);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = x509_check_critical_extensions(certificate,
                (options == (const qsc_x509_verify_options*)NULL) ? true : options->rejectunsupportedcriticalextensions);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = x509_check_critical_extensions(issuer,
                (options == (const qsc_x509_verify_options*)NULL) ? true : options->rejectunsupportedcriticalextensions);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = qsc_x509_certificate_check_structure(certificate);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = qsc_x509_certificate_check_structure(issuer);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = qsc_x509_certificate_check_issuer(issuer, certificate, 0U);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS && x509_signature_can_be_verified_by_issuer(certificate, issuer) == false)
        {
            status = QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH;
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS && options != (const qsc_x509_verify_options*)NULL)
        {
            status = qsc_x509_certificate_check_purpose(certificate, options->purpose);
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            if (callback(certificate, issuer, state) == false)
            {
                status = QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED;
            }
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS && options != (const qsc_x509_verify_options*)NULL &&
            options->revocation != (const qsc_x509_revocation_options*)NULL)
        {
            revstatus = qsc_x509_certificate_check_revocation(certificate, issuer, options->revocation, now);
            status = x509_map_revocation_status(revstatus, options->revocation->mode);
        }
    }

    return status;
}

qsc_x509_verify_status qsc_x509_chain_verify_ex(const qsc_x509_chain* chain, const qsc_x509_store* store,
    const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state, const qsc_x509_verify_options* options)
{
    const qsc_x509_certificate* anchor;
    const qsc_x509_certificate* issuer;
    const qsc_x509_certificate* subject;
    bool anchorfound;
    qsc_x509_revocation_status revstatus;
    qsc_x509_verify_status status;
    size_t i;
    size_t j;
    size_t remainingdepth;

    anchor = (const qsc_x509_certificate*)NULL;
    issuer = (const qsc_x509_certificate*)NULL;
    subject = (const qsc_x509_certificate*)NULL;
    anchorfound = false;
    revstatus = QSC_X509_REVOCATION_STATUS_UNCHECKED;
    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (chain == (const qsc_x509_chain*)NULL || store == (const qsc_x509_store*)NULL || now == (const qsc_asn1_time*)NULL ||
        callback == (qsc_x509_signature_verify_callback)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else if (chain->certificates == (qsc_x509_certificate*)NULL || chain->count == 0U ||
        store->anchors == (qsc_x509_trust_anchor*)NULL || store->count == 0U)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else
    {
        for (i = 0U; i < chain->count && status == QSC_X509_VERIFY_STATUS_SUCCESS; ++i)
        {
            status = qsc_x509_certificate_check_algorithms(&chain->certificates[i]);

            if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
            {
                status = qsc_x509_certificate_check_validity(&chain->certificates[i], now);
            }

            if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
            {
                status = x509_check_critical_extensions(&chain->certificates[i],
                    (options == (const qsc_x509_verify_options*)NULL) ? true : options->rejectunsupportedcriticalextensions);
            }

            if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
            {
                status = qsc_x509_certificate_check_structure(&chain->certificates[i]);
            }

            for (j = i + 1U; j < chain->count && status == QSC_X509_VERIFY_STATUS_SUCCESS; ++j)
            {
                if (x509_certificate_equal(&chain->certificates[i], &chain->certificates[j]) == true)
                {
                    status = QSC_X509_VERIFY_STATUS_CHAIN_LOOP;
                }
            }
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS && options != (const qsc_x509_verify_options*)NULL)
        {
            status = qsc_x509_certificate_check_purpose(&chain->certificates[0], options->purpose);
        }

        for (i = 0U; status == QSC_X509_VERIFY_STATUS_SUCCESS && (i + 1U) < chain->count; ++i)
        {
            subject = &chain->certificates[i];
            issuer = &chain->certificates[i + 1U];
            remainingdepth = x509_count_non_self_issued_intermediates_below(chain, i);

            status = qsc_x509_certificate_check_issuer(issuer, subject, remainingdepth);

            if (status == QSC_X509_VERIFY_STATUS_SUCCESS && x509_signature_can_be_verified_by_issuer(subject, issuer) == false)
            {
                status = QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH;
            }

            if (status == QSC_X509_VERIFY_STATUS_SUCCESS && callback(subject, issuer, state) == false)
            {
                status = QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED;
            }

            if (status == QSC_X509_VERIFY_STATUS_SUCCESS && options != (const qsc_x509_verify_options*)NULL &&
                options->revocation != (const qsc_x509_revocation_options*)NULL)
            {
                revstatus = qsc_x509_certificate_check_revocation(subject, issuer, options->revocation, now);
                status = x509_map_revocation_status(revstatus, options->revocation->mode);
            }
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            subject = &chain->certificates[chain->count - 1U];

            if (qsc_x509_store_contains_anchor(store, subject) == true)
            {
                anchorfound = true;
                status = QSC_X509_VERIFY_STATUS_SUCCESS;
            }
            else
            {
                qsc_x509_verify_status anchorstatus = QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND;

                for (i = 0U; i < store->count && anchorfound == false; ++i)
                {
                    if (x509_check_trust_anchor_minimal(&store->anchors[i]) != QSC_X509_VERIFY_STATUS_SUCCESS)
                    {
                        continue;
                    }

                    if (x509_check_trust_anchor_match(&store->anchors[i], subject) != QSC_X509_VERIFY_STATUS_SUCCESS)
                    {
                        continue;
                    }

                    anchor = &store->anchors[i].certificate;

                    if (x509_signature_can_be_verified_by_issuer(subject, anchor) == false)
                    {
                        anchorstatus = QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH;
                        continue;
                    }

                    if (callback(subject, anchor, state) == false)
                    {
                        anchorstatus = QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED;
                        continue;
                    }

                    anchorfound = true;
                    anchorstatus = QSC_X509_VERIFY_STATUS_SUCCESS;

                    if (options != (const qsc_x509_verify_options*)NULL && options->revocation != (const qsc_x509_revocation_options*)NULL)
                    {
                        revstatus = qsc_x509_certificate_check_revocation(subject, anchor, options->revocation, now);
                        anchorstatus = x509_map_revocation_status(revstatus, options->revocation->mode);
                        if (anchorstatus != QSC_X509_VERIFY_STATUS_SUCCESS)
                        {
                            anchorfound = false;
                            continue;
                        }
                    }

                    break;
                }

                status = anchorstatus;
            }
        }
    }

    return status;
}

bool qsc_x509_chain_is_anchored(const qsc_x509_chain* chain, const qsc_x509_store* store)
{
    size_t i;

    if (chain == (const qsc_x509_chain*)NULL || store == (const qsc_x509_store*)NULL ||
        chain->certificates == (const qsc_x509_certificate*)NULL || chain->count == 0U ||
        store->anchors == (const qsc_x509_trust_anchor*)NULL || store->count == 0U)
    {
        return false;
    }

    for (i = 0U; i < store->count; ++i)
    {
        if (x509_certificate_equal(&store->anchors[i].certificate, &chain->certificates[chain->count - 1U]) == true)
        {
            return true;
        }
    }

    return false;
}

qsc_x509_verify_status qsc_x509_certificate_verify(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer,
    const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state)
{
    return qsc_x509_certificate_verify_ex(certificate, issuer, now, callback, state, (const qsc_x509_verify_options*)NULL);
}

qsc_x509_verify_status qsc_x509_chain_verify(const qsc_x509_chain* chain, const qsc_x509_store* store,
    const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state)
{
    return qsc_x509_chain_verify_ex(chain, store, now, callback, state, (const qsc_x509_verify_options*)NULL);
}
