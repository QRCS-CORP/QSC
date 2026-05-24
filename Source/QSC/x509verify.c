#include "x509verify.h"
#include "memutils.h"
#include "x509cert.h"
#include "x509name.h"
#include "x509sig.h"
#include "x509host.h"
#include "x509store.h"

/*
 * Maximum number of permitted or excluded subtrees that will be
 * processed per NameConstraints extension.  Values beyond this limit
 * are silently ignored (conservative: additional constraints are not
 * applied, which is safe for excluded subtrees but overly permissive
 * for permitted subtrees — the limit is set high enough that it will
 * not be hit in practice for conforming certificates).
 */
#define X509_NC_SUBTREES_MAX (32U)

 /*
  * Internal tag constants used by the inline DER parser.
  * Avoids a dependency on the encoding module internals.
  */
#define X509_NC_TAG_SEQUENCE     (0x30U)
#define X509_NC_TAG_CONTEXT_P(n) ((uint8_t)(0x80U | (uint8_t)(n)))
#define X509_NC_TAG_CONTEXT_C(n) ((uint8_t)(0xA0U | (uint8_t)(n)))

typedef enum x509_nc_name_type_t
{
    X509_NC_TYPE_NONE = 0,
    X509_NC_TYPE_DNS = 1,       /* dNSName [2] */
    X509_NC_TYPE_EMAIL = 2,     /* rfc822Name [1] */
    X509_NC_TYPE_URI = 3,       /* uniformResourceIdentifier [6] */
    X509_NC_TYPE_IP4 = 4,       /* iPAddress [7] IPv4: 8-byte addr||mask */
    X509_NC_TYPE_IP6 = 5,       /* iPAddress [7] IPv6: 32-byte addr||mask */
    X509_NC_TYPE_DIR = 6,       /* directoryName [4] EXPLICIT */
    X509_NC_TYPE_UNKNOWN = 7    /* recognised tag but unsupported name form */
} x509_nc_name_type;

typedef struct x509_nc_subtree_t
{
    x509_nc_name_type type;
    /* For DNS, email, URI: NUL-terminated ASCII string in str[].
       For IP:              raw address||mask octets in ip[].
       DIR entries are counted but not decoded (fail-closed policy). */
    char str[QSC_X509_NAME_ATTRIBUTE_STRING_MAX + 1U];
    uint8_t ip[32U];
    size_t iplen;  /* 8 for IPv4, 32 for IPv6 */
} x509_nc_subtree;

typedef struct x509_nc_subtrees_t
{
    x509_nc_subtree entries[X509_NC_SUBTREES_MAX];
    size_t          count;
} x509_nc_subtrees;

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

static bool x509_key_identifier_matches(const qsc_x509_subject_key_identifier* ski, const qsc_x509_authority_key_identifier* aki, bool strict)
{
    bool res;

    if (ski == (const qsc_x509_subject_key_identifier*)NULL ||
        aki == (const qsc_x509_authority_key_identifier*)NULL ||
        ski->present == false ||
        aki->present == false ||
        aki->keyidentifierlen == 0U)
    {
        res = (strict == false);
    }
    else if (ski->identifierlen != aki->keyidentifierlen)
    {
        res = false;
    }
    else
    {
        res = qsc_memutils_are_equal((uint8_t*)ski->identifier, (uint8_t*)aki->keyidentifier, ski->identifierlen);
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
            spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ML_DSA ||
            spki->algorithm.publickey == QSC_X509_PUBLIC_KEY_ALGORITHM_ED25519);
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
    else if ((certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA256) ||
             (certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA384) ||
             (certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA512))
    {
        if (certificate->signaturelen < 8U || certificate->signaturelen > 139U)
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
        }
        else if (certificate->signature[0U] != 0x30U)
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
        }
        else
        {
            /* Length within bounds and tag correct */
        }
    }
    else if (certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ED25519)
    {
        if (certificate->signaturelen != 64U)
        {
            status = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
        }
    }
    else
    {
        /* Other algorithm types pass length pre-screening here;
         * algorithm acceptance/rejection is handled by check_algorithms. */
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
                x509_key_identifier_matches(&issuer->extensions.subjectkeyidentifier, &subject->extensions.authoritykeyidentifier, false) == false)
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
        if (left->der != (const uint8_t*)NULL && right->der != (const uint8_t*)NULL)
        {
            if (left->derlen == right->derlen)
            {
                res = qsc_memutils_are_equal((uint8_t*)left->der, (uint8_t*)right->der, left->derlen);
            }
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

static size_t x509_nc_decode_length(const uint8_t* p, size_t avail, size_t* outlen)
{
    size_t nb;
    size_t len;
    size_t i;
    size_t consumed;

    consumed = 0U;
    len = 0U;

    if (p != (const uint8_t*)NULL && avail != 0U && outlen != (size_t*)NULL)
    {
        if ((*p & 0x80U) == 0U)
        {
            /* short form */
            *outlen = (size_t)*p;
            consumed = 1U;
        }
        else
        {
            nb = (size_t)(*p & 0x7FU);

            if (nb == 0U || nb > 4U || nb >= avail)
            {
                consumed = 0U;
            }
            else
            {
                for (i = 1U; i <= nb; ++i)
                {
                    len = (len << 8) | (size_t)p[i];
                }

                *outlen = len;
                consumed = nb + 1U;
            }
        }
    }

    return consumed;
}

static size_t x509_nc_copy_str(char* dst, size_t dstlen, const uint8_t* src, size_t srclen)
{
    size_t n;
    size_t i;

    n = srclen;

    if (n >= dstlen)
    {
        n = dstlen - 1U;
    }

    for (i = 0U; i < n; ++i)
    {
        dst[i] = (char)src[i];
    }

    dst[n] = '\0';
    return n;
}

static size_t x509_nc_copy_bytes(uint8_t* dst, size_t dstlen, const uint8_t* src, size_t srclen)
{
    size_t n;
    size_t i;

    n = srclen;

    if (n > dstlen)
    {
        n = dstlen;
    }

    for (i = 0U; i < n; ++i)
    {
        dst[i] = src[i];
    }

    return n;
}

static int32_t x509_nc_tolower(int32_t c)
{
    int32_t res;

    res = c;

    if (c >= (int32_t)'A' && c <= (int32_t)'Z')
    {
        res = c + 32;
    }

    return res;
}

static size_t x509_nc_strlen(const char* s)
{
    size_t n;

    n = 0U;

    if (s != (const char*)NULL)
    {
        while (s[n] != '\0')
        {
            ++n;
        }
    }

    return n;
}

static bool x509_nc_ascii_eq_n(const char* a, const char* b, size_t len)
{
    size_t i;
    bool   res;

    res = true;

    for (i = 0U; i < len; ++i)
    {
        if (a[i] == '\0' || b[i] == '\0')
        {
            res = false;
            break;
        }

        if (x509_nc_tolower((uint8_t)a[i]) != x509_nc_tolower((uint8_t)b[i]))
        {
            res = false;
            break;
        }
    }

    return res;
}

static bool x509_nc_parse_subtrees(const uint8_t* der, size_t derlen, x509_nc_subtrees* out)
{
    const uint8_t* p;
    const uint8_t* end;
    size_t consumed;
    size_t seqlen;
    size_t gslen;
    size_t gnlen;
    uint8_t tag;
    bool res;

    res = false;

    if (der == (const uint8_t*)NULL || derlen == 0U || out == (x509_nc_subtrees*)NULL)
    {
        return false;
    }

    out->count = 0U;
    p = der;
    end = der + derlen;

    /* outer SEQUENCE OF GeneralSubtree */
    if (p >= end || *p != X509_NC_TAG_SEQUENCE)
    {
        return false;
    }

    p++;
    consumed = x509_nc_decode_length(p, (size_t)(end - p), &seqlen);

    if (consumed == 0U || seqlen > (size_t)(end - p - consumed))
    {
        return false;
    }

    p += consumed;
    end = p + seqlen;
    res = true;

    while (p < end && out->count < X509_NC_SUBTREES_MAX)
    {
        /* each GeneralSubtree is a SEQUENCE */
        if (*p != X509_NC_TAG_SEQUENCE)
        {
            res = false;
            break;
        }

        p++;
        consumed = x509_nc_decode_length(p, (size_t)(end - p), &gslen);

        if (consumed == 0U || gslen > (size_t)(end - p - consumed))
        {
            res = false;
            break;
        }

        p += consumed;

        {
            const uint8_t* gsend;

            gsend = p + gslen;

            if (gsend > end)
            {
                res = false;
                break;
            }

            /* GeneralName is the first (required) field of GeneralSubtree */
            if (p < gsend)
            {
                tag = *p;
                p++;
                consumed = x509_nc_decode_length(p, (size_t)(gsend - p), &gnlen);

                if (consumed == 0U || gnlen > (size_t)(gsend - p - consumed))
                {
                    res = false;
                    break;
                }

                p += consumed;

                {
                    x509_nc_subtree* entry;

                    entry = &out->entries[out->count];
                    entry->type = X509_NC_TYPE_NONE;
                    entry->iplen = 0U;
                    entry->str[0] = '\0';

                    switch (tag)
                    {
                    case 0x81U:  /* rfc822Name [1] IMPLICIT IA5String */
                    {
                        if (gnlen <= QSC_X509_NAME_ATTRIBUTE_STRING_MAX)
                        {
                            (void)x509_nc_copy_str(entry->str, sizeof(entry->str), p, gnlen);
                            entry->type = X509_NC_TYPE_EMAIL;
                        }
                        break;
                    }
                    case 0x82U:  /* dNSName [2] IMPLICIT IA5String */
                    {
                        if (gnlen <= QSC_X509_NAME_ATTRIBUTE_STRING_MAX)
                        {
                            (void)x509_nc_copy_str(entry->str, sizeof(entry->str), p, gnlen);
                            entry->type = X509_NC_TYPE_DNS;
                        }
                        break;
                    }
                    case 0x86U:  /* uniformResourceIdentifier [6] IMPLICIT IA5String */
                    {
                        if (gnlen <= QSC_X509_NAME_ATTRIBUTE_STRING_MAX)
                        {
                            (void)x509_nc_copy_str(entry->str, sizeof(entry->str), p, gnlen);
                            entry->type = X509_NC_TYPE_URI;
                        }
                        break;
                    }
                    case 0x87U:  /* iPAddress [7] IMPLICIT OCTET STRING */
                    {
                        if (gnlen == 8U)
                        {
                            (void)x509_nc_copy_bytes(entry->ip, sizeof(entry->ip), p, gnlen);
                            entry->iplen = gnlen;
                            entry->type = X509_NC_TYPE_IP4;
                        }
                        else if (gnlen == 32U)
                        {
                            (void)x509_nc_copy_bytes(entry->ip, sizeof(entry->ip), p, gnlen);
                            entry->iplen = gnlen;
                            entry->type = X509_NC_TYPE_IP6;
                        }
                        else
                        {
                            entry->type = X509_NC_TYPE_UNKNOWN;
                        }
                        break;
                    }
                    case 0xA4U:  /* directoryName [4] EXPLICIT */
                    {
                        /* Counted but not decoded — fail-closed when evaluating */
                        entry->type = X509_NC_TYPE_DIR;
                        break;
                    }
                    default:
                    {
                        entry->type = X509_NC_TYPE_UNKNOWN;
                        break;
                    }
                    }

                    out->count++;
                }

                p += gnlen;
            }

            /* Skip minimum/maximum fields of GeneralSubtree (not used in PKIX) */
            p = gsend;
        }
    }

    return res;
}

static bool x509_nc_dns_in_subtree(const char* hostname, const char* subtree)
{
    /* RFC 5280 4.2.1.10 DNS name constraint membership test.
     * A constraint of "" matches any name (treat as unconstrained).
     * A constraint of ".example.com" requires a sub-domain: "a.example.com" matches, "example.com" does not.
     * A constraint of "example.com" (no leading dot) matches the domain itself and all sub-domains: "example.com", "a.example.com". */

    size_t hlen;
    size_t slen;
    bool res;

    res = false;

    if (hostname != (const char*)NULL && subtree != (const char*)NULL)
    {
        hlen = x509_nc_strlen(hostname);
        slen = x509_nc_strlen(subtree);

        if (slen == 0U)
        {
            res = true;   /* empty constraint = unconstrained */
        }
        else if (hlen == 0U)
        {
            res = false;
        }
        else if (slen == hlen)
        {
            res = x509_nc_ascii_eq_n(hostname, subtree, hlen);
        }
        else if (subtree[0] == '.')
        {
            /* leading-dot form: hostname must end with ".subtree" and be strictly longer */
            if (hlen > slen)
            {
                res = x509_nc_ascii_eq_n(hostname + (hlen - slen), subtree, slen);
            }
        }
        else if (hlen > slen && hostname[hlen - slen - 1U] == '.')
        {
            /* no leading dot: "example.com" matches "a.example.com" */
            res = x509_nc_ascii_eq_n(hostname + (hlen - slen), subtree, slen);
        }
        else
        {
            res = false;
        }
    }

    return res;
}

static bool x509_nc_email_in_subtree(const char* email, const char* subtree)
{
    /* RFC 5280 4.2.1.10 email constraint membership test.
     * if the constraint contains '@': require an exact match.
     * If the constraint has no '@': it is a domain constraint and the 
     * email's domain must match or be a sub-domain of the constraint. */

    const char* atem;
    const char* domain;
    size_t dlen;
    size_t elen;
    size_t slen;
    bool res;

    res = false;

    if (email != (const char*)NULL && subtree != (const char*)NULL)
    {
        elen = x509_nc_strlen(email);
        slen = x509_nc_strlen(subtree);
        atem = (const char*)NULL;

        {
            size_t k;

            for (k = 0U; k < elen; ++k)
            {
                if (email[k] == '@')
                {
                    atem = email + k;
                    break;
                }
            }
        }

        if (slen == 0U)
        {
            res = true;   /* unconstrained */
        }
        else if (elen == 0U || atem == (const char*)NULL)
        {
            res = false;
        }
        else
        {
            {
                bool has_at;
                size_t j;

                has_at = false;

                for (j = 0U; j < slen; ++j)
                {
                    if (subtree[j] == '@')
                    {
                        has_at = true;
                        break;
                    }
                }

                if (has_at == true)
                {
                    /* exact email match */
                    if (elen == slen)
                    {
                        res = x509_nc_ascii_eq_n(email, subtree, elen);
                    }
                }
                else
                {
                    /* domain constraint */
                    domain = atem + 1U;
                    dlen = x509_nc_strlen(domain);

                    if (dlen == slen)
                    {
                        res = x509_nc_ascii_eq_n(domain, subtree, dlen);
                    }
                    else if (dlen > slen && domain[dlen - slen - 1U] == '.')
                    {
                        res = x509_nc_ascii_eq_n(domain + (dlen - slen), subtree, slen);
                    }
                    else
                    {
                        res = false;
                    }
                }
            }
        }
    }

    return res;
}

static bool x509_nc_ip_in_subtree(const uint8_t* addr, size_t addrlen, const uint8_t* subtree_ip, size_t subtree_iplen)
{
    /* RFC 5280 4.2.1.10 IP address constraint membership test.
     * The subtree entry is (address || mask): 8 bytes for IPv4, 32 for IPv6.
     * The subject SAN iPAddress is the raw address: 4 bytes IPv4, 16 bytes IPv6.
     * Membership: (addr[i] & mask[i]) == (constraint_addr[i] & mask[i]) for all i. */

    const uint8_t* mask;
    size_t half;
    size_t i;
    bool res;

    res = false;

    if (addr != (const uint8_t*)NULL && subtree_ip != (const uint8_t*)NULL)
    {
        half = subtree_iplen / 2U;  /* 4 for IPv4, 16 for IPv6 */

        if (addrlen == half)
        {
            mask = subtree_ip + half;
            res = true;

            for (i = 0U; i < half; ++i)
            {
                if ((addr[i] & mask[i]) != (subtree_ip[i] & mask[i]))
                {
                    res = false;
                    break;
                }
            }
        }
    }

    return res;
}

static qsc_x509_verify_status x509_nc_check_one_name(const x509_nc_subtrees* permitted, const x509_nc_subtrees* excluded, const qsc_x509_general_name* gn, bool nc_critical)
{
    size_t j;
    bool inexcluded;
    bool hasperm;
    bool inpermitted;
    qsc_x509_verify_status status;

    status = QSC_X509_VERIFY_STATUS_SUCCESS;
    inexcluded = false;
    hasperm = false;
    inpermitted = false;

    if (gn->type == QSC_X509_GENERAL_NAME_DNS_NAME)
    {
        const char* hostname;

        hostname = (const char*)gn->data;

        for (j = 0U; j < excluded->count && inexcluded == false; ++j)
        {
            if (excluded->entries[j].type == X509_NC_TYPE_DNS)
            {
                if (x509_nc_dns_in_subtree(hostname, excluded->entries[j].str) == true)
                {
                    inexcluded = true;
                }
            }
        }

        if (inexcluded == true)
        {
            status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
        }
        else
        {
            for (j = 0U; j < permitted->count; ++j)
            {
                if (permitted->entries[j].type == X509_NC_TYPE_DNS)
                {
                    hasperm = true;

                    if (x509_nc_dns_in_subtree(hostname, permitted->entries[j].str) == true)
                    {
                        inpermitted = true;
                        break;
                    }
                }
            }

            if (hasperm == true && inpermitted == false)
            {
                status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
            }
        }
    }
    else if (gn->type == QSC_X509_GENERAL_NAME_RFC822_NAME)
    {
        const char* email;

        email = (const char*)gn->data;

        for (j = 0U; j < excluded->count && inexcluded == false; ++j)
        {
            if (excluded->entries[j].type == X509_NC_TYPE_EMAIL)
            {
                if (x509_nc_email_in_subtree(email, excluded->entries[j].str) == true)
                {
                    inexcluded = true;
                }
            }
        }

        if (inexcluded == true)
        {
            status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
        }
        else
        {
            for (j = 0U; j < permitted->count; ++j)
            {
                if (permitted->entries[j].type == X509_NC_TYPE_EMAIL)
                {
                    hasperm = true;

                    if (x509_nc_email_in_subtree(email, permitted->entries[j].str) == true)
                    {
                        inpermitted = true;
                        break;
                    }
                }
            }

            if (hasperm == true && inpermitted == false)
            {
                status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
            }
        }
    }
    else if (gn->type == QSC_X509_GENERAL_NAME_IP_ADDRESS)
    {
        for (j = 0U; j < excluded->count && inexcluded == false; ++j)
        {
            if (excluded->entries[j].type == X509_NC_TYPE_IP4 ||
                excluded->entries[j].type == X509_NC_TYPE_IP6)
            {
                if (x509_nc_ip_in_subtree(gn->data, gn->length,
                    excluded->entries[j].ip, excluded->entries[j].iplen) == true)
                {
                    inexcluded = true;
                }
            }
        }

        if (inexcluded == true)
        {
            status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
        }
        else
        {
            for (j = 0U; j < permitted->count; ++j)
            {
                if (permitted->entries[j].type == X509_NC_TYPE_IP4 ||
                    permitted->entries[j].type == X509_NC_TYPE_IP6)
                {
                    hasperm = true;

                    if (x509_nc_ip_in_subtree(gn->data, gn->length,
                        permitted->entries[j].ip, permitted->entries[j].iplen) == true)
                    {
                        inpermitted = true;
                        break;
                    }
                }
            }

            if (hasperm == true && inpermitted == false)
            {
                status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
            }
        }
    }
    else if (gn->type == QSC_X509_GENERAL_NAME_DIRECTORY_NAME)
    {
        /* directoryName constraints require a DN-prefix comparison that is
         * outside the scope of this function.  
         * we fail closed: if any directoryName constraint exists, reject. */

        for (j = 0U; j < excluded->count; ++j)
        {
            if (excluded->entries[j].type == X509_NC_TYPE_DIR)
            {
                status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
                break;
            }
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            for (j = 0U; j < permitted->count; ++j)
            {
                if (permitted->entries[j].type == X509_NC_TYPE_DIR)
                {
                    status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
                    break;
                }
            }
        }
    }
    else
    {
        /* unrecognised name type in a critical extension — fail closed
         * per RFC 5280 6.1.3(d) if any unknown constraint exists. */

        if (nc_critical == true)
        {
            for (j = 0U; j < permitted->count; ++j)
            {
                if (permitted->entries[j].type == X509_NC_TYPE_UNKNOWN)
                {
                    status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
                    break;
                }
            }
        }
    }

    return status;
}

static size_t x509_nc_wrap_sequence(uint8_t* buf, size_t buflen, const uint8_t* inner, size_t innerlen)
{
    size_t hlen;
    size_t i;

    hlen = 0U;

    if (buf != (uint8_t*)NULL && inner != (const uint8_t*)NULL && innerlen <= buflen)
    {
        buf[hlen] = X509_NC_TAG_SEQUENCE;
        ++hlen;

        if (innerlen < 0x80U)
        {
            buf[hlen] = (uint8_t)innerlen;
            ++hlen;
        }
        else if (innerlen <= 0xFFU)
        {
            buf[hlen] = 0x81U;
            ++hlen;
            buf[hlen] = (uint8_t)innerlen;
            ++hlen;
        }
        else
        {
            buf[hlen] = 0x82U;
            ++hlen;
            buf[hlen] = (uint8_t)((innerlen >> 8) & 0xFFU);
            ++hlen;
            buf[hlen] = (uint8_t)(innerlen & 0xFFU);
            ++hlen;
        }

        if ((hlen + innerlen) <= buflen)
        {
            for (i = 0U; i < innerlen; ++i)
            {
                buf[hlen + i] = inner[i];
            }

            hlen += innerlen;
        }
        else
        {
            hlen = 0U;
        }
    }

    return hlen;
}

static qsc_x509_verify_status x509_check_name_constraints(const uint8_t* nc_der, size_t nc_derlen, bool nc_critical, const qsc_x509_certificate* subject)
{
    uint8_t tmpbuf[4U + (X509_NC_SUBTREES_MAX * (QSC_X509_NAME_ATTRIBUTE_STRING_MAX + 16U))] = { 0U };
    const uint8_t* p;
    const uint8_t* outer_end;
    x509_nc_subtrees permitted;
    x509_nc_subtrees excluded;
    size_t consumed;
    size_t outerlen;
    size_t set_len;
    size_t tmplen;
    size_t i;
    qsc_x509_verify_status status;
    uint8_t tag;
    bool haspermitted;
    bool hasexcluded;

    status = QSC_X509_VERIFY_STATUS_SUCCESS;
    haspermitted = false;
    hasexcluded = false;

    if (nc_der == (const uint8_t*)NULL || nc_derlen == 0U || subject == (const qsc_x509_certificate*)NULL)
    {
        return QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }

    /* zero-initialise subtree tables without memset */
    qsc_memutils_clear((void*)&permitted, sizeof(permitted));
    qsc_memutils_clear((void*)&excluded, sizeof(excluded));

    p = nc_der;
    outer_end = nc_der + nc_derlen;

    /*
     * NameConstraints ::= SEQUENCE {
     *     permittedSubtrees [0] GeneralSubtrees OPTIONAL,
     *     excludedSubtrees  [1] GeneralSubtrees OPTIONAL
     * }
     * GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
     */
    if (p >= outer_end || *p != X509_NC_TAG_SEQUENCE)
    {
        return QSC_X509_VERIFY_STATUS_SUCCESS;
    }

    p++;
    consumed = x509_nc_decode_length(p, (size_t)(outer_end - p), &outerlen);

    if (consumed == 0U || outerlen > (size_t)(outer_end - p - consumed))
    {
        return QSC_X509_VERIFY_STATUS_SUCCESS;
    }

    p += consumed;
    outer_end = p + outerlen;

    while (p < outer_end && status == QSC_X509_VERIFY_STATUS_SUCCESS)
    {
        tag = *p;
        p++;
        consumed = x509_nc_decode_length(p, (size_t)(outer_end - p), &set_len);

        if (consumed == 0U || set_len > (size_t)(outer_end - p - consumed))
        {
            break;
        }

        p += consumed;

        if (tag == X509_NC_TAG_CONTEXT_C(0U))
        {
            /*
             * permittedSubtrees [0] IMPLICIT GeneralSubtrees
             *
             * X.690 IMPLICIT tagging for a CONSTRUCTED type:
             *   GeneralSubtrees is SEQUENCE OF GeneralSubtree.
             *   Under IMPLICIT tagging, the [0] tag replaces the SEQUENCE
             *   tag.  So [0]'s value bytes are the interior of the SEQUENCE
             *   (the concatenation of GeneralSubtree items), NOT a nested
             *   SEQUENCE.
             *
             *   However, many implementations (including OpenSSL) encode the
             *   NameConstraints with the SEQUENCE still present inside [0],
             *   making [0]'s content begin with 0x30 (SEQUENCE tag).
             *
             * We detect which form is present:
             *   - If content[0] == 0x30  →  the SEQUENCE is present verbatim;
             *     pass content directly to x509_nc_parse_subtrees (no wrapping).
             *   - Otherwise              →  content is raw GeneralSubtree items;
             *     wrap in a synthetic SEQUENCE before passing.
             */
            if (set_len > 0U && p[0U] == X509_NC_TAG_SEQUENCE)
            {
                /* content already begins with the SEQUENCE tag of GeneralSubtrees */
                haspermitted = x509_nc_parse_subtrees(p, set_len, &permitted);
            }
            else
            {
                tmplen = x509_nc_wrap_sequence(tmpbuf, sizeof(tmpbuf), p, set_len);

                if (tmplen != 0U)
                {
                    haspermitted = x509_nc_parse_subtrees(tmpbuf, tmplen, &permitted);
                }
            }
        }
        else if (tag == X509_NC_TAG_CONTEXT_C(1U))
        {
            /* excludedSubtrees [1] IMPLICIT GeneralSubtrees — same encoding */
            if (set_len > 0U && p[0U] == X509_NC_TAG_SEQUENCE)
            {
                hasexcluded = x509_nc_parse_subtrees(p, set_len, &excluded);
            }
            else
            {
                tmplen = x509_nc_wrap_sequence(tmpbuf, sizeof(tmpbuf), p, set_len);

                if (tmplen != 0U)
                {
                    hasexcluded = x509_nc_parse_subtrees(tmpbuf, tmplen, &excluded);
                }
            }
        }
        else
        {
            /* unknown field inside NameConstraints — skip */
        }

        p += set_len;
    }

    if (haspermitted == false && hasexcluded == false)
    {
        return QSC_X509_VERIFY_STATUS_SUCCESS;
    }

    /* check each SAN entry against the parsed constraints */
    if (subject->extensions.subjectaltname.present == true)
    {
        for (i = 0U; i < subject->extensions.subjectaltname.count && status == QSC_X509_VERIFY_STATUS_SUCCESS; ++i)
        {
            status = x509_nc_check_one_name(&permitted, &excluded,
                &subject->extensions.subjectaltname.entries[i], nc_critical);
        }
    }

    /* if no SAN is present the subject DN is the only identity.  We
     * check for directoryName constraints as a fail-closed measure;
     * DNS/email/IP constraints on a DN-only certificate are not
     * evaluated here (the name type mismatch means no constraint fires). */
    if (status == QSC_X509_VERIFY_STATUS_SUCCESS &&
        (subject->extensions.subjectaltname.present == false ||
            subject->extensions.subjectaltname.count == 0U))
    {
        size_t j;

        for (j = 0U; j < excluded.count; ++j)
        {
            if (excluded.entries[j].type == X509_NC_TYPE_DIR)
            {
                status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
                break;
            }
        }

        if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            for (j = 0U; j < permitted.count; ++j)
            {
                if (permitted.entries[j].type == X509_NC_TYPE_DIR)
                {
                    status = QSC_X509_VERIFY_STATUS_NAME_MISMATCH;
                    break;
                }
            }
        }
    }

    return status;
}

static qsc_x509_verify_status x509_evaluate_name_constraints(const qsc_x509_certificate* issuer, const qsc_x509_certificate* subject)
{
    qsc_x509_verify_status status;
    size_t i;

    status = QSC_X509_VERIFY_STATUS_SUCCESS;

    if (issuer == (const qsc_x509_certificate*)NULL || subject == (const qsc_x509_certificate*)NULL)
    {
        status = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
    }
    else
    {
        for (i = 0U; i < issuer->extensions.count && status == QSC_X509_VERIFY_STATUS_SUCCESS; ++i)
        {
            const qsc_x509_extension* ext;

            ext = &issuer->extensions.entries[i];

            if (ext->type == QSC_X509_EXTENSION_NAME_CONSTRAINTS && ext->decoded == true)
            {
                if (ext->rawextnvalue.data != (const uint8_t*)NULL && ext->rawextnvalue.length > 0U)
                {
                    status = x509_check_name_constraints(
                        ext->rawextnvalue.data,
                        ext->rawextnvalue.length,
                        ext->critical,
                        subject);
                }

                /* RFC 5280 4.2 prohibits duplicate extensions */
                break;
            }
        }
    }

    return status;
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
                     certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_ECDSA_SHA1 ||
                     certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA256 ||
                     certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA384 ||
                     certificate->signaturealgorithm.signature == QSC_X509_SIGNATURE_ALGORITHM_RSA_SHA512)
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
            x509_key_identifier_matches(&issuer->extensions.subjectkeyidentifier, &subject->extensions.authoritykeyidentifier, false) == false)
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

            if (status == QSC_X509_VERIFY_STATUS_SUCCESS)
            {
                status = x509_evaluate_name_constraints(issuer, subject);
            }

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

                    {
                        qsc_x509_verify_status anchor_validity;

                        anchor_validity = qsc_x509_certificate_check_validity(&store->anchors[i].certificate, now);

                        if (anchor_validity != QSC_X509_VERIFY_STATUS_SUCCESS)
                        {
                            anchorstatus = anchor_validity;
                            continue;
                        }
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
