#include "oid.h"
#include "memutils.h"

static const uint8_t OID_RSA_ENCRYPTION[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x01U };
static const uint8_t OID_MD5_WITH_RSA_ENCRYPTION[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x04U };
static const uint8_t OID_SHA1_WITH_RSA_ENCRYPTION[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x05U };
static const uint8_t OID_SHA256_WITH_RSA_ENCRYPTION[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0BU };
static const uint8_t OID_SHA384_WITH_RSA_ENCRYPTION[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0CU };
static const uint8_t OID_SHA512_WITH_RSA_ENCRYPTION[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0DU };

static const uint8_t OID_ML_DSA_44[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x03U, 0x11U };
static const uint8_t OID_ML_DSA_65[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x03U, 0x12U };
static const uint8_t OID_ML_DSA_87[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x03U, 0x13U };

static const uint8_t OID_ML_KEM_512[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x04U, 0x01U };
static const uint8_t OID_ML_KEM_768[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x04U, 0x02U };
static const uint8_t OID_ML_KEM_1024[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x04U, 0x03U };

static const uint8_t OID_EC_PUBLIC_KEY[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x02U, 0x01U };
static const uint8_t OID_PRIME256V1[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U };
static const uint8_t OID_SECP384R1[] = { 0x2BU, 0x81U, 0x04U, 0x00U, 0x22U };
static const uint8_t OID_SECP521R1[] = { 0x2BU, 0x81U, 0x04U, 0x00U, 0x23U };
static const uint8_t OID_ECDSA_WITH_SHA1[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x01U };
static const uint8_t OID_ECDSA_WITH_SHA256[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x02U };
static const uint8_t OID_ECDSA_WITH_SHA384[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x03U };
static const uint8_t OID_ECDSA_WITH_SHA512[] = { 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x04U };

static const uint8_t OID_SHA1[] = { 0x2BU, 0x0EU, 0x03U, 0x02U, 0x1AU };
static const uint8_t OID_SHA224[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x04U };
static const uint8_t OID_SHA256[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x01U };
static const uint8_t OID_SHA384[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x02U };
static const uint8_t OID_SHA512[] = { 0x60U, 0x86U, 0x48U, 0x01U, 0x65U, 0x03U, 0x04U, 0x02U, 0x03U };

static const uint8_t OID_COMMON_NAME[] = { 0x55U, 0x04U, 0x03U };
static const uint8_t OID_SURNAME[] = { 0x55U, 0x04U, 0x04U };
static const uint8_t OID_SERIAL_NUMBER[] = { 0x55U, 0x04U, 0x05U };
static const uint8_t OID_COUNTRY_NAME[] = { 0x55U, 0x04U, 0x06U };
static const uint8_t OID_LOCALITY_NAME[] = { 0x55U, 0x04U, 0x07U };
static const uint8_t OID_STATE_OR_PROVINCE_NAME[] = { 0x55U, 0x04U, 0x08U };
static const uint8_t OID_STREET_ADDRESS[] = { 0x55U, 0x04U, 0x09U };
static const uint8_t OID_ORGANIZATION_NAME[] = { 0x55U, 0x04U, 0x0AU };
static const uint8_t OID_ORGANIZATIONAL_UNIT_NAME[] = { 0x55U, 0x04U, 0x0BU };
static const uint8_t OID_TITLE[] = { 0x55U, 0x04U, 0x0CU };
static const uint8_t OID_DESCRIPTION[] = { 0x55U, 0x04U, 0x0DU };
static const uint8_t OID_GIVEN_NAME[] = { 0x55U, 0x04U, 0x2AU };
static const uint8_t OID_INITIALS[] = { 0x55U, 0x04U, 0x2BU };
static const uint8_t OID_GENERATION_QUALIFIER[] = { 0x55U, 0x04U, 0x2CU };
static const uint8_t OID_DN_QUALIFIER[] = { 0x55U, 0x04U, 0x2EU };
static const uint8_t OID_PSEUDONYM[] = { 0x55U, 0x04U, 0x41U };
static const uint8_t OID_DOMAIN_COMPONENT[] = { 0x09U, 0x92U, 0x26U, 0x89U, 0x93U, 0xF2U, 0x2CU, 0x64U, 0x01U, 0x19U };
static const uint8_t OID_EMAIL_ADDRESS[] = { 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x09U, 0x01U };

static const uint8_t OID_SUBJECT_KEY_IDENTIFIER[] = { 0x55U, 0x1DU, 0x0EU };
static const uint8_t OID_KEY_USAGE[] = { 0x55U, 0x1DU, 0x0FU };
static const uint8_t OID_SUBJECT_ALT_NAME[] = { 0x55U, 0x1DU, 0x11U };
static const uint8_t OID_ISSUER_ALT_NAME[] = { 0x55U, 0x1DU, 0x12U };
static const uint8_t OID_BASIC_CONSTRAINTS[] = { 0x55U, 0x1DU, 0x13U };
static const uint8_t OID_NAME_CONSTRAINTS[] = { 0x55U, 0x1DU, 0x1EU };
static const uint8_t OID_CRL_DISTRIBUTION_POINTS[] = { 0x55U, 0x1DU, 0x1FU };
static const uint8_t OID_CERTIFICATE_POLICIES[] = { 0x55U, 0x1DU, 0x20U };
static const uint8_t OID_CRL_NUMBER[] = { 0x55U, 0x1DU, 0x14U };
static const uint8_t OID_AUTHORITY_KEY_IDENTIFIER[] = { 0x55U, 0x1DU, 0x23U };
static const uint8_t OID_EXTENDED_KEY_USAGE[] = { 0x55U, 0x1DU, 0x25U };
static const uint8_t OID_AUTHORITY_INFO_ACCESS[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x01U, 0x01U };
static const uint8_t OID_SUBJECT_INFO_ACCESS[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x01U, 0x0BU };

static const uint8_t OID_ANY_EXTENDED_KEY_USAGE[] = { 0x55U, 0x1DU, 0x25U, 0x00U };
static const uint8_t OID_SERVER_AUTH[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x01U };
static const uint8_t OID_CLIENT_AUTH[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x02U };
static const uint8_t OID_CODE_SIGNING[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x03U };
static const uint8_t OID_EMAIL_PROTECTION[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x04U };
static const uint8_t OID_TIME_STAMPING[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x08U };
static const uint8_t OID_OCSP_SIGNING[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x03U, 0x09U };

static const uint8_t OID_OCSP[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x30U, 0x01U };
static const uint8_t OID_CA_ISSUERS[] = { 0x2BU, 0x06U, 0x01U, 0x05U, 0x05U, 0x07U, 0x30U, 0x02U };

static const qsc_oid_entry OID_REGISTRY[] =
{
    { QSC_OID_ID_RSA_ENCRYPTION, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION), "1.2.840.113549.1.1.1", "rsaEncryption" },
    { QSC_OID_ID_MD5_WITH_RSA_ENCRYPTION, OID_MD5_WITH_RSA_ENCRYPTION, sizeof(OID_MD5_WITH_RSA_ENCRYPTION), "1.2.840.113549.1.1.4", "md5WithRSAEncryption" },
    { QSC_OID_ID_SHA1_WITH_RSA_ENCRYPTION, OID_SHA1_WITH_RSA_ENCRYPTION, sizeof(OID_SHA1_WITH_RSA_ENCRYPTION), "1.2.840.113549.1.1.5", "sha1WithRSAEncryption" },
    { QSC_OID_ID_SHA256_WITH_RSA_ENCRYPTION, OID_SHA256_WITH_RSA_ENCRYPTION, sizeof(OID_SHA256_WITH_RSA_ENCRYPTION), "1.2.840.113549.1.1.11", "sha256WithRSAEncryption" },
    { QSC_OID_ID_SHA384_WITH_RSA_ENCRYPTION, OID_SHA384_WITH_RSA_ENCRYPTION, sizeof(OID_SHA384_WITH_RSA_ENCRYPTION), "1.2.840.113549.1.1.12", "sha384WithRSAEncryption" },
    { QSC_OID_ID_SHA512_WITH_RSA_ENCRYPTION, OID_SHA512_WITH_RSA_ENCRYPTION, sizeof(OID_SHA512_WITH_RSA_ENCRYPTION), "1.2.840.113549.1.1.13", "sha512WithRSAEncryption" },

    { QSC_OID_ID_ML_DSA_44, OID_ML_DSA_44, sizeof(OID_ML_DSA_44), "2.16.840.1.101.3.4.3.17", "id-ml-dsa-44" },
    { QSC_OID_ID_ML_DSA_65, OID_ML_DSA_65, sizeof(OID_ML_DSA_65), "2.16.840.1.101.3.4.3.18", "id-ml-dsa-65" },
    { QSC_OID_ID_ML_DSA_87, OID_ML_DSA_87, sizeof(OID_ML_DSA_87), "2.16.840.1.101.3.4.3.19", "id-ml-dsa-87" },

    { QSC_OID_ID_ML_KEM_512, OID_ML_KEM_512, sizeof(OID_ML_KEM_512), "2.16.840.1.101.3.4.4.1", "id-alg-ml-kem-512" },
    { QSC_OID_ID_ML_KEM_768, OID_ML_KEM_768, sizeof(OID_ML_KEM_768), "2.16.840.1.101.3.4.4.2", "id-alg-ml-kem-768" },
    { QSC_OID_ID_ML_KEM_1024, OID_ML_KEM_1024, sizeof(OID_ML_KEM_1024), "2.16.840.1.101.3.4.4.3", "id-alg-ml-kem-1024" },

    { QSC_OID_ID_EC_PUBLIC_KEY, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY), "1.2.840.10045.2.1", "id-ecPublicKey" },
    { QSC_OID_ID_PRIME256V1, OID_PRIME256V1, sizeof(OID_PRIME256V1), "1.2.840.10045.3.1.7", "prime256v1" },
    { QSC_OID_ID_SECP384R1, OID_SECP384R1, sizeof(OID_SECP384R1), "1.3.132.0.34", "secp384r1" },
    { QSC_OID_ID_SECP521R1, OID_SECP521R1, sizeof(OID_SECP521R1), "1.3.132.0.35", "secp521r1" },
    { QSC_OID_ID_ECDSA_WITH_SHA1, OID_ECDSA_WITH_SHA1, sizeof(OID_ECDSA_WITH_SHA1), "1.2.840.10045.4.1", "ecdsa-with-SHA1" },
    { QSC_OID_ID_ECDSA_WITH_SHA256, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256), "1.2.840.10045.4.3.2", "ecdsa-with-SHA256" },
    { QSC_OID_ID_ECDSA_WITH_SHA384, OID_ECDSA_WITH_SHA384, sizeof(OID_ECDSA_WITH_SHA384), "1.2.840.10045.4.3.3", "ecdsa-with-SHA384" },
    { QSC_OID_ID_ECDSA_WITH_SHA512, OID_ECDSA_WITH_SHA512, sizeof(OID_ECDSA_WITH_SHA512), "1.2.840.10045.4.3.4", "ecdsa-with-SHA512" },

    { QSC_OID_ID_SHA1, OID_SHA1, sizeof(OID_SHA1), "1.3.14.3.2.26", "id-sha1" },
    { QSC_OID_ID_SHA224, OID_SHA224, sizeof(OID_SHA224), "2.16.840.1.101.3.4.2.4", "id-sha224" },
    { QSC_OID_ID_SHA256, OID_SHA256, sizeof(OID_SHA256), "2.16.840.1.101.3.4.2.1", "id-sha256" },
    { QSC_OID_ID_SHA384, OID_SHA384, sizeof(OID_SHA384), "2.16.840.1.101.3.4.2.2", "id-sha384" },
    { QSC_OID_ID_SHA512, OID_SHA512, sizeof(OID_SHA512), "2.16.840.1.101.3.4.2.3", "id-sha512" },

    { QSC_OID_ID_COMMON_NAME, OID_COMMON_NAME, sizeof(OID_COMMON_NAME), "2.5.4.3", "commonName" },
    { QSC_OID_ID_SURNAME, OID_SURNAME, sizeof(OID_SURNAME), "2.5.4.4", "surname" },
    { QSC_OID_ID_SERIAL_NUMBER, OID_SERIAL_NUMBER, sizeof(OID_SERIAL_NUMBER), "2.5.4.5", "serialNumber" },
    { QSC_OID_ID_COUNTRY_NAME, OID_COUNTRY_NAME, sizeof(OID_COUNTRY_NAME), "2.5.4.6", "countryName" },
    { QSC_OID_ID_LOCALITY_NAME, OID_LOCALITY_NAME, sizeof(OID_LOCALITY_NAME), "2.5.4.7", "localityName" },
    { QSC_OID_ID_STATE_OR_PROVINCE_NAME, OID_STATE_OR_PROVINCE_NAME, sizeof(OID_STATE_OR_PROVINCE_NAME), "2.5.4.8", "stateOrProvinceName" },
    { QSC_OID_ID_STREET_ADDRESS, OID_STREET_ADDRESS, sizeof(OID_STREET_ADDRESS), "2.5.4.9", "streetAddress" },
    { QSC_OID_ID_ORGANIZATION_NAME, OID_ORGANIZATION_NAME, sizeof(OID_ORGANIZATION_NAME), "2.5.4.10", "organizationName" },
    { QSC_OID_ID_ORGANIZATIONAL_UNIT_NAME, OID_ORGANIZATIONAL_UNIT_NAME, sizeof(OID_ORGANIZATIONAL_UNIT_NAME), "2.5.4.11", "organizationalUnitName" },
    { QSC_OID_ID_TITLE, OID_TITLE, sizeof(OID_TITLE), "2.5.4.12", "title" },
    { QSC_OID_ID_DESCRIPTION, OID_DESCRIPTION, sizeof(OID_DESCRIPTION), "2.5.4.13", "description" },
    { QSC_OID_ID_GIVEN_NAME, OID_GIVEN_NAME, sizeof(OID_GIVEN_NAME), "2.5.4.42", "givenName" },
    { QSC_OID_ID_INITIALS, OID_INITIALS, sizeof(OID_INITIALS), "2.5.4.43", "initials" },
    { QSC_OID_ID_GENERATION_QUALIFIER, OID_GENERATION_QUALIFIER, sizeof(OID_GENERATION_QUALIFIER), "2.5.4.44", "generationQualifier" },
    { QSC_OID_ID_DN_QUALIFIER, OID_DN_QUALIFIER, sizeof(OID_DN_QUALIFIER), "2.5.4.46", "dnQualifier" },
    { QSC_OID_ID_PSEUDONYM, OID_PSEUDONYM, sizeof(OID_PSEUDONYM), "2.5.4.65", "pseudonym" },
    { QSC_OID_ID_DOMAIN_COMPONENT, OID_DOMAIN_COMPONENT, sizeof(OID_DOMAIN_COMPONENT), "0.9.2342.19200300.100.1.25", "domainComponent" },
    { QSC_OID_ID_EMAIL_ADDRESS, OID_EMAIL_ADDRESS, sizeof(OID_EMAIL_ADDRESS), "1.2.840.113549.1.9.1", "emailAddress" },

    { QSC_OID_ID_SUBJECT_KEY_IDENTIFIER, OID_SUBJECT_KEY_IDENTIFIER, sizeof(OID_SUBJECT_KEY_IDENTIFIER), "2.5.29.14", "subjectKeyIdentifier" },
    { QSC_OID_ID_KEY_USAGE, OID_KEY_USAGE, sizeof(OID_KEY_USAGE), "2.5.29.15", "keyUsage" },
    { QSC_OID_ID_SUBJECT_ALT_NAME, OID_SUBJECT_ALT_NAME, sizeof(OID_SUBJECT_ALT_NAME), "2.5.29.17", "subjectAltName" },
    { QSC_OID_ID_ISSUER_ALT_NAME, OID_ISSUER_ALT_NAME, sizeof(OID_ISSUER_ALT_NAME), "2.5.29.18", "issuerAltName" },
    { QSC_OID_ID_BASIC_CONSTRAINTS, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS), "2.5.29.19", "basicConstraints" },
    { QSC_OID_ID_NAME_CONSTRAINTS, OID_NAME_CONSTRAINTS, sizeof(OID_NAME_CONSTRAINTS), "2.5.29.30", "nameConstraints" },
    { QSC_OID_ID_CRL_DISTRIBUTION_POINTS, OID_CRL_DISTRIBUTION_POINTS, sizeof(OID_CRL_DISTRIBUTION_POINTS), "2.5.29.31", "cRLDistributionPoints" },
    { QSC_OID_ID_CERTIFICATE_POLICIES, OID_CERTIFICATE_POLICIES, sizeof(OID_CERTIFICATE_POLICIES), "2.5.29.32", "certificatePolicies" },
    { QSC_OID_ID_CRL_NUMBER, OID_CRL_NUMBER, sizeof(OID_CRL_NUMBER), "2.5.29.20", "cRLNumber" },
    { QSC_OID_ID_AUTHORITY_KEY_IDENTIFIER, OID_AUTHORITY_KEY_IDENTIFIER, sizeof(OID_AUTHORITY_KEY_IDENTIFIER), "2.5.29.35", "authorityKeyIdentifier" },
    { QSC_OID_ID_EXTENDED_KEY_USAGE, OID_EXTENDED_KEY_USAGE, sizeof(OID_EXTENDED_KEY_USAGE), "2.5.29.37", "extKeyUsage" },
    { QSC_OID_ID_AUTHORITY_INFO_ACCESS, OID_AUTHORITY_INFO_ACCESS, sizeof(OID_AUTHORITY_INFO_ACCESS), "1.3.6.1.5.5.7.1.1", "authorityInfoAccess" },
    { QSC_OID_ID_SUBJECT_INFO_ACCESS, OID_SUBJECT_INFO_ACCESS, sizeof(OID_SUBJECT_INFO_ACCESS), "1.3.6.1.5.5.7.1.11", "subjectInfoAccess" },

    { QSC_OID_ID_ANY_EXTENDED_KEY_USAGE, OID_ANY_EXTENDED_KEY_USAGE, sizeof(OID_ANY_EXTENDED_KEY_USAGE), "2.5.29.37.0", "anyExtendedKeyUsage" },
    { QSC_OID_ID_SERVER_AUTH, OID_SERVER_AUTH, sizeof(OID_SERVER_AUTH), "1.3.6.1.5.5.7.3.1", "id-kp-serverAuth" },
    { QSC_OID_ID_CLIENT_AUTH, OID_CLIENT_AUTH, sizeof(OID_CLIENT_AUTH), "1.3.6.1.5.5.7.3.2", "id-kp-clientAuth" },
    { QSC_OID_ID_CODE_SIGNING, OID_CODE_SIGNING, sizeof(OID_CODE_SIGNING), "1.3.6.1.5.5.7.3.3", "id-kp-codeSigning" },
    { QSC_OID_ID_EMAIL_PROTECTION, OID_EMAIL_PROTECTION, sizeof(OID_EMAIL_PROTECTION), "1.3.6.1.5.5.7.3.4", "id-kp-emailProtection" },
    { QSC_OID_ID_TIME_STAMPING, OID_TIME_STAMPING, sizeof(OID_TIME_STAMPING), "1.3.6.1.5.5.7.3.8", "id-kp-timeStamping" },
    { QSC_OID_ID_OCSP_SIGNING, OID_OCSP_SIGNING, sizeof(OID_OCSP_SIGNING), "1.3.6.1.5.5.7.3.9", "id-kp-OCSPSigning" },

    { QSC_OID_ID_OCSP, OID_OCSP, sizeof(OID_OCSP), "1.3.6.1.5.5.7.48.1", "id-ad-ocsp" },
    { QSC_OID_ID_CA_ISSUERS, OID_CA_ISSUERS, sizeof(OID_CA_ISSUERS), "1.3.6.1.5.5.7.48.2", "id-ad-caIssuers" }
};

static bool oid_decode_base128(const uint8_t* data, size_t length, qsc_asn1_oid* oid)
{
    size_t i;
    size_t arcidx;
    uint32_t value;
    bool firstarc;
    bool res;

    res = false;

    if (data != NULL && length != 0U && oid != NULL && length <= QSC_ASN1_OID_MAX_SIZE)
    {
        qsc_memutils_clear(oid, sizeof(qsc_asn1_oid));
        qsc_memutils_copy(oid->data, data, length);
        oid->length = length;
        firstarc = true;
        arcidx = 0U;
        value = 0U;

        for (i = 0U; i < length; ++i)
        {
            if ((value & 0xFE000000U) != 0U)
            {
                arcidx = 0U;
                break;
            }

            value = (value << 7) | (uint32_t)(data[i] & 0x7FU);

            if ((data[i] & 0x80U) == 0U)
            {
                if (firstarc == true)
                {
                    uint32_t arc0;
                    uint32_t arc1;

                    if (value < 40U)
                    {
                        arc0 = 0U;
                        arc1 = value;
                    }
                    else if (value < 80U)
                    {
                        arc0 = 1U;
                        arc1 = value - 40U;
                    }
                    else
                    {
                        arc0 = 2U;
                        arc1 = value - 80U;
                    }

#if (QSC_ASN1_OID_MAX_ARCS < 2U)
                        arcidx = 0U;
                        break;
#endif

                    oid->arcs[0U] = arc0;
                    oid->arcs[1U] = arc1;
                    arcidx = 2U;
                    firstarc = false;
                }
                else
                {
                    if (arcidx >= QSC_ASN1_OID_MAX_ARCS)
                    {
                        arcidx = 0U;
                        break;
                    }

                    oid->arcs[arcidx] = value;
                    ++arcidx;
                }

                value = 0U;
            }
        }

        if (arcidx >= 2U && (length == 0U || (data[length - 1U] & 0x80U) == 0U))
        {
            oid->arcscount = arcidx;
            res = true;
        }
        else
        {
            qsc_memutils_clear(oid, sizeof(qsc_asn1_oid));
        }
    }

    return res;
}

size_t qsc_oid_registry_count(void)
{
    return (sizeof(OID_REGISTRY) / sizeof(OID_REGISTRY[0U]));
}

const qsc_oid_entry* qsc_oid_registry_at(size_t index)
{
    const qsc_oid_entry* entry;

    entry = NULL;

    if (index < qsc_oid_registry_count())
    {
        entry = &OID_REGISTRY[index];
    }

    return entry;
}

const qsc_oid_entry* qsc_oid_get_entry(qsc_oid_id id)
{
    const qsc_oid_entry* entry;
    size_t i;

    entry = NULL;

    for (i = 0U; i < qsc_oid_registry_count(); ++i)
    {
        if (OID_REGISTRY[i].id == id)
        {
            entry = &OID_REGISTRY[i];
            break;
        }
    }

    return entry;
}

qsc_oid_id qsc_oid_identify(const qsc_asn1_oid* oid)
{
    QSC_ASSERT(oid != NULL);

    qsc_oid_id id;
    size_t i;

    id = QSC_OID_ID_NONE;

    if (oid != NULL)
    {
        for (i = 0U; i < qsc_oid_registry_count(); ++i)
        {
            if (oid->length == OID_REGISTRY[i].length &&
                qsc_memutils_are_equal(oid->data, OID_REGISTRY[i].data, oid->length) == true)
            {
                id = OID_REGISTRY[i].id;
                break;
            }
        }
    }

    return id;
}

bool qsc_oid_equals_id(const qsc_asn1_oid* oid, qsc_oid_id id)
{
    QSC_ASSERT(oid != NULL);

    bool res;

    res = false;

    if (oid != NULL && id != QSC_OID_ID_NONE)
    {
        res = (qsc_oid_identify(oid) == id);
    }

    return res;
}

bool qsc_oid_get_encoded(qsc_oid_id id, const uint8_t** data, size_t* length)
{
    QSC_ASSERT(data != NULL);
    QSC_ASSERT(length != NULL);

    const qsc_oid_entry* entry;
    bool res;

    res = false;

    if (data != NULL && length != NULL)
    {
        entry = qsc_oid_get_entry(id);

        if (entry != NULL)
        {
            *data = entry->data;
            *length = entry->length;
            res = true;
        }
    }

    return res;
}

bool qsc_oid_to_asn1(qsc_oid_id id, qsc_asn1_oid* oid)
{
    QSC_ASSERT(oid != NULL);

    const qsc_oid_entry* entry;
    bool res;

    res = false;

    if (oid != NULL)
    {
        entry = qsc_oid_get_entry(id);

        if (entry != NULL)
        {
            res = oid_decode_base128(entry->data, entry->length, oid);
        }
    }

    return res;
}

const char* qsc_oid_get_dotted(qsc_oid_id id)
{
    const qsc_oid_entry* entry;
    const char* text;

    entry = qsc_oid_get_entry(id);
    text = NULL;

    if (entry != NULL)
    {
        text = entry->dotted;
    }

    return text;
}

const char* qsc_oid_get_name(qsc_oid_id id)
{
    const qsc_oid_entry* entry;
    const char* text;

    entry = qsc_oid_get_entry(id);
    text = NULL;

    if (entry != NULL)
    {
        text = entry->name;
    }

    return text;
}

const char* qsc_oid_get_name_from_oid(const qsc_asn1_oid* oid)
{
    QSC_ASSERT(oid != NULL);

    const char* res;

    if (oid != NULL)
    {
        res = qsc_oid_get_name(qsc_oid_identify(oid));
    }
    else
    {
        res = NULL;
    }

    return res;
}
