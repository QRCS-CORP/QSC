#include "x509wrap.h"
#include "fileutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "x509name.h"
#include "timestamp.h"
#include "x509certwrite.h"
#include "x509keywrite.h"
#include "tlserrors.h"

/*
 * qsc_x509w is intentionally offline-only. Network retrieval helpers are excluded
 * from this translation unit so certificate processing, validation, and TLS bridge
 * integration remain deterministic and non-blocking.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>

extern void qsc_tls_client_set_certificate_interface(qsc_tls_client* client, const qsc_tls_certificate_interface* iface, const char* hostname, bool requirepeercertificate);
extern void qsc_tls_server_set_certificate_interface(qsc_tls_server* server, const qsc_tls_certificate_interface* iface, const char* hostname, bool requirepeercertificate);
extern qsc_tls_status qsc_tls_server_set_local_certificate(qsc_tls_server* server, const qsc_tls_certificate_view* chain, size_t chainlength, qsc_tls_signature_scheme verifyscheme, const uint8_t* verifysignature, size_t verifysignaturelen);

static void x509w_result_set_message(qsc_x509w_result* result, const char* message)
{
    if (result != NULL && message != NULL)
    {
        qsc_memutils_clear(result->message, sizeof(result->message));
        qsc_stringutils_copy_string(result->message, sizeof(result->message), message);
    }
}

static void x509w_result_set_status(qsc_x509w_result* result, qsc_x509w_status status, qsc_x509w_stage stage, const char* message)
{
    if (result != NULL)
    {
        result->status = status;
        result->stage = stage;
        x509w_result_set_message(result, message);
    }
}

static void x509w_result_apply_verify_status(qsc_x509w_result* result, qsc_x509_verify_status vstatus)
{
    if (result != NULL)
    {
        result->verifystatus = vstatus;

        switch (vstatus)
        {
            case QSC_X509_VERIFY_STATUS_EXPIRED:
            case QSC_X509_VERIFY_STATUS_NOT_YET_VALID:
            {
                result->timevalid = false;
                break;
            }
            case QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED:
            case QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED:
            {
                result->purposevalid = false;
                break;
            }
            default:
            {
                break;
            }
        }
    }
}

static bool x509w_profile_revocation_uses_local_crl(const qsc_x509w_profile* profile)
{
    bool result;

    result = false;

    if (profile != NULL)
    {
        result = (profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_IF_PRESENT ||
            profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_REQUIRED ||
            profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_OR_OCSP_REQUIRED ||
            profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_AND_OCSP_REQUIRED);
    }

    return result;
}

static bool x509w_profile_requires_supported_revocation(const qsc_x509w_profile* profile)
{
    bool result;

    result = false;

    if (profile != NULL)
    {
        result = (profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_REQUIRED);
    }

    return result;
}

static bool x509w_profile_requires_future_network_revocation(const qsc_x509w_profile* profile)
{
    bool result;

    result = false;

    if (profile != NULL)
    {
        result = (profile->revocationmode == QSC_X509W_REVOCATION_MODE_OCSP_IF_PRESENT ||
            profile->revocationmode == QSC_X509W_REVOCATION_MODE_OCSP_REQUIRED ||
            profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_OR_OCSP_REQUIRED ||
            profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_AND_OCSP_REQUIRED ||
            profile->aiaissuerpolicy != QSC_X509W_LOCATOR_POLICY_DISABLED ||
            profile->ocsppolicy != QSC_X509W_LOCATOR_POLICY_DISABLED);
    }

    return result;
}

static qsc_x509w_status x509w_read_file(const char* path, uint8_t* data, size_t datacapacity, size_t* datalen)
{
    size_t length;
    qsc_x509w_status status;

    length = 0U;
    status = QSC_X509W_STATUS_SUCCESS;

    if (path == NULL || data == NULL || datalen == NULL || datacapacity == 0U)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else if (qsc_fileutils_exists(path) == false)
    {
        status = QSC_X509W_STATUS_NOT_FOUND;
    }
    else
    {
        length = qsc_fileutils_get_size(path);

        if (length == 0U)
        {
            status = QSC_X509W_STATUS_IO_ERROR;
        }
        else if (length > datacapacity)
        {
            status = QSC_X509W_STATUS_BUFFER_TOO_SMALL;
        }
        else
        {
            length = qsc_fileutils_copy_file_to_object(path, data, length);
            if (length == 0U)
            {
                status = QSC_X509W_STATUS_IO_ERROR;
            }
            else
            {
                *datalen = length;
            }
        }
    }

    return status;
}

static bool x509w_is_pem(const uint8_t* data, size_t datalen)
{
    return (data != NULL && datalen >= 10U && memcmp(data, "-----BEGIN", 10U) == 0);
}

static qsc_x509w_status x509w_map_asn1_status(qsc_asn1_status status)
{
    qsc_x509w_status res;

    res = QSC_X509W_STATUS_DECODE_ERROR;

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        res = QSC_X509W_STATUS_SUCCESS;
    }
    else if (status == QSC_ASN1_STATUS_INVALID_INPUT)
    {
        res = QSC_X509W_STATUS_INVALID_INPUT;
    }

    return res;
}

static qsc_x509w_status x509w_map_verify_status(qsc_x509_verify_status status)
{
    qsc_x509w_status res;

    res = QSC_X509W_STATUS_VERIFY_ERROR;

    switch (status)
    {
        case QSC_X509_VERIFY_STATUS_SUCCESS:
        {
            res = QSC_X509W_STATUS_SUCCESS;
            break;
        }
        case QSC_X509_VERIFY_STATUS_INVALID_INPUT:
        {
            res = QSC_X509W_STATUS_INVALID_INPUT;
            break;
        }
        case QSC_X509_VERIFY_STATUS_NAME_MISMATCH:
        {
            res = QSC_X509W_STATUS_HOSTNAME_MISMATCH;
            break;
        }
        case QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED:
        {
            res = QSC_X509W_STATUS_PURPOSE_REJECTED;
            break;
        }
        default:
        {
            break;
        }
    }

    return res;
}

static qsc_x509w_status x509w_map_encode_status(qsc_asn1_status status)
{
    qsc_x509w_status res;

    res = QSC_X509W_STATUS_ENCODING_ERROR;

    if (status == QSC_ASN1_STATUS_SUCCESS)
    {
        res = QSC_X509W_STATUS_SUCCESS;
    }
    else if (status == QSC_ASN1_STATUS_INVALID_INPUT)
    {
        res = QSC_X509W_STATUS_INVALID_INPUT;
    }

    return res;
}

static qsc_x509w_status x509w_current_utc_time_internal(qsc_x509_time* currenttime)
{
    qsc_x509w_status status;
    time_t now;

    status = QSC_X509W_STATUS_SUCCESS;
    now = 0;

    if (currenttime == NULL)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_memutils_clear(currenttime, sizeof(qsc_x509_time));
        now = time(NULL);

        if (now == (time_t)-1)
        {
            status = QSC_X509W_STATUS_IO_ERROR;
        }
        else
        {
#if defined(QSC_SYSTEM_OS_WINDOWS)
            struct tm tmnow;
            errno_t err;

            err = _gmtime64_s(&tmnow, &now);
            if (err != 0)
            {
                status = QSC_X509W_STATUS_IO_ERROR;
            }
            else
            {
                currenttime->year = (uint16_t)(tmnow.tm_year + 1900);
                currenttime->month = (uint8_t)(tmnow.tm_mon + 1);
                currenttime->day = (uint8_t)tmnow.tm_mday;
                currenttime->hour = (uint8_t)tmnow.tm_hour;
                currenttime->minute = (uint8_t)tmnow.tm_min;
                currenttime->second = (uint8_t)tmnow.tm_sec;
            }
#else
            struct tm tmnow;
            struct tm* ptm;

            ptm = gmtime_r(&now, &tmnow);
            if (ptm == NULL)
            {
                status = QSC_X509W_STATUS_IO_ERROR;
            }
            else
            {
                currenttime->year = (uint16_t)(tmnow.tm_year + 1900);
                currenttime->month = (uint8_t)(tmnow.tm_mon + 1);
                currenttime->day = (uint8_t)tmnow.tm_mday;
                currenttime->hour = (uint8_t)tmnow.tm_hour;
                currenttime->minute = (uint8_t)tmnow.tm_min;
                currenttime->second = (uint8_t)tmnow.tm_sec;
            }
#endif
        }
    }

    return status;
}

static qsc_asn1_status x509w_resolve_crl(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, qsc_x509_crl* crl, void* context)
{
    const qsc_x509w_trust_store* store;
    size_t i;
    qsc_asn1_status status;

    QSC_ASSERT(certificate != NULL);
    QSC_ASSERT(issuer != NULL);
    QSC_ASSERT(crl != NULL);

    (void)certificate;
    store = (const qsc_x509w_trust_store*)context;
    status = QSC_ASN1_STATUS_NOT_FOUND;

    if (issuer == NULL || crl == NULL || store == NULL)
    {
        status = QSC_ASN1_STATUS_INVALID_INPUT;
    }
    else
    {
        for (i = 0U; i < store->crlcount; ++i)
        {
            if (qsc_x509_name_equals(&store->crls[i].issuer, &issuer->subject) == true)
            {
                qsc_memutils_copy(crl, &store->crls[i], sizeof(qsc_x509_crl));
                status = QSC_ASN1_STATUS_SUCCESS;
                break;
            }
        }
    }

    return status;
}

static qsc_x509w_status x509w_verify_chain_internal(const qsc_x509_certificate* certificates, size_t certificatecount,
    const qsc_x509w_trust_store* store, const qsc_x509w_profile* profile, qsc_x509w_result* result)
{
    qsc_x509_certificate built[QSC_X509W_CHAIN_MAX];
    qsc_x509_chain chain;
    qsc_x509_verify_options options;
    qsc_x509_revocation_options revocation;
    qsc_x509_verify_state verifystate;
    qsc_x509_verify_status vstatus;
    qsc_x509w_status status;
    qsc_x509_time currenttime;
    const qsc_x509_time* validationtime;
    uint8_t verifybuffer[QSC_X509W_VERIFY_BUFFER_SIZE];

    qsc_memutils_clear(built, sizeof(built));
    qsc_memutils_clear(&chain, sizeof(chain));
    qsc_memutils_clear(&options, sizeof(options));
    qsc_memutils_clear(&revocation, sizeof(revocation));
    qsc_memutils_clear(&verifystate, sizeof(verifystate));
    qsc_memutils_clear(&currenttime, sizeof(currenttime));
    qsc_memutils_clear(verifybuffer, sizeof(verifybuffer));

    status = QSC_X509W_STATUS_SUCCESS;
    validationtime = NULL;
    vstatus = QSC_X509_VERIFY_STATUS_INVALID_INPUT;

    if (result != NULL)
    {
        qsc_x509w_result_initialize(result);
    }

    if (certificates == NULL || certificatecount == 0U || certificatecount > QSC_X509W_CHAIN_MAX || store == NULL || profile == NULL)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else
    {
        if (profile->validationtime != NULL)
        {
            validationtime = profile->validationtime;
        }
        else
        {
            status = x509w_current_utc_time_internal(&currenttime);
            validationtime = &currenttime;
        }
    }

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        vstatus = qsc_x509_chain_build(&certificates[0],
            (certificatecount > 1U) ? &certificates[1] : NULL,
            (certificatecount > 1U) ? (certificatecount - 1U) : 0U,
            &store->store,
            built,
            QSC_X509W_CHAIN_MAX,
            &chain);

        if (vstatus != QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = QSC_X509W_STATUS_CHAIN_BUILD_ERROR;
            if (result != NULL)
            {
                result->failuredepth = 0U;
                x509w_result_apply_verify_status(result, vstatus);
                x509w_result_set_status(result, status, QSC_X509W_STAGE_CHAIN_BUILD, "certificate chain build failed");
            }
        }
        else if (result != NULL)
        {
            result->chainbuilt = true;
        }
    }

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        qsc_x509_verify_options_initialize(&options);
        options.purpose = profile->purpose;
        options.rejectunsupportedcriticalextensions = profile->rejectunsupportedcriticalextensions;

        if (result != NULL)
        {
            result->aiaavailability = QSC_X509W_AVAILABILITY_UNCHECKED;
            result->ocspavailability = QSC_X509W_AVAILABILITY_UNCHECKED;
            result->aiahintpresent = (profile->aiaissuerpolicy != QSC_X509W_LOCATOR_POLICY_DISABLED);
            result->ocsphintpresent = (profile->ocsppolicy != QSC_X509W_LOCATOR_POLICY_DISABLED ||
                profile->revocationmode == QSC_X509W_REVOCATION_MODE_OCSP_IF_PRESENT ||
                profile->revocationmode == QSC_X509W_REVOCATION_MODE_OCSP_REQUIRED ||
                profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_OR_OCSP_REQUIRED ||
                profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_AND_OCSP_REQUIRED);
        }

        if (x509w_profile_revocation_uses_local_crl(profile) == true && store->crlcount != 0U)
        {
            qsc_x509_revocation_options_initialize(&revocation);
            revocation.mode = (profile->revocationmode == QSC_X509W_REVOCATION_MODE_CRL_IF_PRESENT) ?
                QSC_X509_REVOCATION_MODE_BEST_EFFORT : QSC_X509_REVOCATION_MODE_REQUIRE_VALID_CRL;
            revocation.resolver = x509w_resolve_crl;
            revocation.verifycallback = qsc_x509_qsc_crl_signature_verify;
            revocation.resolvercontext = (void*)store;
            revocation.verifycontext = &verifystate;
            options.revocation = &revocation;

            if (result != NULL)
            {
                result->revocationsource = QSC_X509W_REVOCATION_SOURCE_CRL;
                result->revocationstatus = QSC_X509_REVOCATION_STATUS_UNCHECKED;
                result->aiaavailability = (profile->aiaissuerpolicy == QSC_X509W_LOCATOR_POLICY_DISABLED) ? QSC_X509W_AVAILABILITY_UNCHECKED : QSC_X509W_AVAILABILITY_UNAVAILABLE;
                result->ocspavailability = (profile->ocsppolicy == QSC_X509W_LOCATOR_POLICY_DISABLED) ? QSC_X509W_AVAILABILITY_UNCHECKED : QSC_X509W_AVAILABILITY_UNAVAILABLE;
            }
        }
        else if (x509w_profile_requires_supported_revocation(profile) == true)
        {
            status = QSC_X509W_STATUS_VERIFY_ERROR;

            if (result != NULL)
            {
                result->revocationstatus = QSC_X509_REVOCATION_STATUS_UNCHECKED;
                result->revocationsource = QSC_X509W_REVOCATION_SOURCE_NONE;
                x509w_result_set_status(result, status, QSC_X509W_STAGE_REVOCATION, "required CRL revocation data is unavailable");
            }
        }
        else if (x509w_profile_requires_future_network_revocation(profile) == true && result != NULL)
        {
            result->aiaavailability = (profile->aiaissuerpolicy == QSC_X509W_LOCATOR_POLICY_DISABLED) ? QSC_X509W_AVAILABILITY_UNCHECKED : QSC_X509W_AVAILABILITY_UNAVAILABLE;
            result->ocspavailability = (profile->ocsppolicy == QSC_X509W_LOCATOR_POLICY_DISABLED &&
                profile->revocationmode != QSC_X509W_REVOCATION_MODE_OCSP_IF_PRESENT &&
                profile->revocationmode != QSC_X509W_REVOCATION_MODE_OCSP_REQUIRED &&
                profile->revocationmode != QSC_X509W_REVOCATION_MODE_CRL_OR_OCSP_REQUIRED &&
                profile->revocationmode != QSC_X509W_REVOCATION_MODE_CRL_AND_OCSP_REQUIRED) ?
                QSC_X509W_AVAILABILITY_UNCHECKED : QSC_X509W_AVAILABILITY_UNAVAILABLE;
        }

        qsc_x509_qsc_verify_state_initialize(&verifystate, verifybuffer, sizeof(verifybuffer));
        vstatus = qsc_x509_chain_verify_ex(&chain, &store->store, validationtime, qsc_x509_qsc_signature_verify, &verifystate, &options);
        status = x509w_map_verify_status(vstatus);

        if (result != NULL)
        {
            result->chainlength = chain.count;
            result->revocationstatus = (vstatus == QSC_X509_VERIFY_STATUS_REVOKED) ? QSC_X509_REVOCATION_STATUS_REVOKED : ((vstatus == QSC_X509_VERIFY_STATUS_REVOCATION_UNKNOWN) ? QSC_X509_REVOCATION_STATUS_ERROR : QSC_X509_REVOCATION_STATUS_GOOD);
            if (options.revocation != NULL)
            {
                result->revocationsource = QSC_X509W_REVOCATION_SOURCE_CRL;
                result->aiaavailability = QSC_X509W_AVAILABILITY_UNCHECKED;
                result->ocspavailability = QSC_X509W_AVAILABILITY_UNCHECKED;
            }
            x509w_result_apply_verify_status(result, vstatus);

            if (status != QSC_X509W_STATUS_SUCCESS)
            {
                if (vstatus == QSC_X509_VERIFY_STATUS_EXPIRED || vstatus == QSC_X509_VERIFY_STATUS_NOT_YET_VALID)
                {
                    x509w_result_set_status(result, status, QSC_X509W_STAGE_TIME, "certificate validity interval rejected");
                }
                else if (vstatus == QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED || vstatus == QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED)
                {
                    x509w_result_set_status(result, status, QSC_X509W_STAGE_PURPOSE, "certificate purpose rejected");
                }
                else if (vstatus == QSC_X509_VERIFY_STATUS_REVOKED || vstatus == QSC_X509_VERIFY_STATUS_REVOCATION_UNKNOWN)
                {
                    x509w_result_set_status(result, status, QSC_X509W_STAGE_REVOCATION, "certificate revocation check failed");
                }
                else if (vstatus == QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND)
                {
                    x509w_result_set_status(result, status, QSC_X509W_STAGE_TRUST, "no trust anchor found");
                }
                else
                {
                    x509w_result_set_status(result, status, QSC_X509W_STAGE_CHAIN_BUILD, "certificate chain verification failed");
                }
            }
        }
    }

    if (status == QSC_X509W_STATUS_SUCCESS && profile->hostname != NULL)
    {
        qsc_x509_verify_status hstatus;

        hstatus = qsc_x509_certificate_check_hostname(&chain.certificates[0], profile->hostname);

        if (result != NULL)
        {
            result->hostnamechecked = true;
            result->hostnamevalid = (hstatus == QSC_X509_VERIFY_STATUS_SUCCESS);
        }

        if (hstatus != QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = x509w_map_verify_status(hstatus);
            vstatus = hstatus;
        }
    }
    else if (result != NULL)
    {
        result->hostnamechecked = false;
        result->hostnamevalid = false;
    }

    if (result != NULL)
    {
        result->status = status;
        result->verifystatus = vstatus;
        result->chainlength = chain.count;
        if (result->revocationsource == QSC_X509W_REVOCATION_SOURCE_NONE)
        {
            result->revocationstatus = (status == QSC_X509W_STATUS_SUCCESS) ? QSC_X509_REVOCATION_STATUS_GOOD : QSC_X509_REVOCATION_STATUS_UNCHECKED;
        }
    }

    return status;
}

static void x509w_profile_apply_tls_server_defaults(qsc_x509w_profile* profile)
{
    qsc_memutils_clear(profile, sizeof(qsc_x509w_profile));
    profile->purpose = QSC_X509_VERIFY_PURPOSE_TLS_SERVER;
    profile->rejectunsupportedcriticalextensions = true;
    profile->requirehostname = true;
    profile->revocationmode = QSC_X509W_REVOCATION_MODE_NONE;
    profile->aiaissuerpolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
    profile->ocsppolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
}

static void x509w_profile_apply_tls_client_defaults(qsc_x509w_profile* profile)
{
    qsc_memutils_clear(profile, sizeof(qsc_x509w_profile));
    profile->purpose = QSC_X509_VERIFY_PURPOSE_TLS_CLIENT;
    profile->rejectunsupportedcriticalextensions = true;
    profile->requirehostname = false;
    profile->revocationmode = QSC_X509W_REVOCATION_MODE_NONE;
    profile->aiaissuerpolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
    profile->ocsppolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
}

static void x509w_profile_apply_ca_defaults(qsc_x509w_profile* profile)
{
    qsc_memutils_clear(profile, sizeof(qsc_x509w_profile));
    profile->purpose = QSC_X509_VERIFY_PURPOSE_GENERIC;
    profile->rejectunsupportedcriticalextensions = true;
    profile->requirehostname = false;
    profile->revocationmode = QSC_X509W_REVOCATION_MODE_NONE;
    profile->aiaissuerpolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
    profile->ocsppolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
}

static void x509w_profile_apply_strict_revocation_defaults(qsc_x509w_profile* profile)
{
    x509w_profile_apply_tls_server_defaults(profile);
    profile->revocationmode = QSC_X509W_REVOCATION_MODE_CRL_REQUIRED;
    profile->aiaissuerpolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
    profile->ocsppolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
}

static void x509w_profile_apply_development_defaults(qsc_x509w_profile* profile)
{
    qsc_memutils_clear(profile, sizeof(qsc_x509w_profile));
    profile->purpose = QSC_X509_VERIFY_PURPOSE_TLS_SERVER;
    profile->rejectunsupportedcriticalextensions = false;
    profile->requirehostname = false;
    profile->revocationmode = QSC_X509W_REVOCATION_MODE_NONE;
    profile->aiaissuerpolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
    profile->ocsppolicy = QSC_X509W_LOCATOR_POLICY_DISABLED;
}

void qsc_x509w_profile_initialize(qsc_x509w_profile* profile)
{
    QSC_ASSERT(profile != NULL);

    if (profile != NULL)
    {
        x509w_profile_apply_tls_server_defaults(profile);
    }
}

void qsc_x509w_profile_apply_preset(qsc_x509w_profile* profile, qsc_x509w_profile_preset preset)
{
    QSC_ASSERT(profile != NULL);

    if (profile != NULL)
    {
        switch (preset)
        {
            case QSC_X509W_PROFILE_PRESET_TLS_CLIENT:
            {
                x509w_profile_apply_tls_client_defaults(profile);
                break;
            }
            case QSC_X509W_PROFILE_PRESET_CA:
            {
                x509w_profile_apply_ca_defaults(profile);
                break;
            }
            case QSC_X509W_PROFILE_PRESET_STRICT_REVOCATION:
            {
                x509w_profile_apply_strict_revocation_defaults(profile);
                break;
            }
            case QSC_X509W_PROFILE_PRESET_DEVELOPMENT:
            {
                x509w_profile_apply_development_defaults(profile);
                break;
            }
            case QSC_X509W_PROFILE_PRESET_TLS_SERVER:
            default:
            {
                x509w_profile_apply_tls_server_defaults(profile);
                break;
            }
        }
    }
}

void qsc_x509w_profile_set_tls_server_defaults(qsc_x509w_profile* profile)
{
    QSC_ASSERT(profile != NULL);

    if (profile != NULL)
    {
        x509w_profile_apply_tls_server_defaults(profile);
    }
}

void qsc_x509w_profile_set_tls_client_defaults(qsc_x509w_profile* profile)
{
    QSC_ASSERT(profile != NULL);

    if (profile != NULL)
    {
        x509w_profile_apply_tls_client_defaults(profile);
    }
}

void qsc_x509w_profile_set_ca_defaults(qsc_x509w_profile* profile)
{
    QSC_ASSERT(profile != NULL);

    if (profile != NULL)
    {
        x509w_profile_apply_ca_defaults(profile);
    }
}

void qsc_x509w_profile_set_strict_revocation_defaults(qsc_x509w_profile* profile)
{
    QSC_ASSERT(profile != NULL);

    if (profile != NULL)
    {
        x509w_profile_apply_strict_revocation_defaults(profile);
    }
}

void qsc_x509w_profile_set_development_defaults(qsc_x509w_profile* profile)
{
    QSC_ASSERT(profile != NULL);

    if (profile != NULL)
    {
        x509w_profile_apply_development_defaults(profile);
    }
}

void qsc_x509w_result_initialize(qsc_x509w_result* result)
{
    QSC_ASSERT(result != NULL);

    if (result != NULL)
    {
        qsc_memutils_clear(result, sizeof(qsc_x509w_result));
        result->status = QSC_X509W_STATUS_SUCCESS;
        result->verifystatus = QSC_X509_VERIFY_STATUS_SUCCESS;
        result->revocationstatus = QSC_X509_REVOCATION_STATUS_UNCHECKED;
        result->revocationsource = QSC_X509W_REVOCATION_SOURCE_NONE;
        result->aiaavailability = QSC_X509W_AVAILABILITY_UNCHECKED;
        result->ocspavailability = QSC_X509W_AVAILABILITY_UNCHECKED;
    }
}

void qsc_x509w_trust_store_initialize(qsc_x509w_trust_store* store)
{
    QSC_ASSERT(store != NULL);

    if (store != NULL)
    {
        qsc_memutils_clear(store, sizeof(qsc_x509w_trust_store));
        qsc_x509_store_initialize(&store->store, store->anchors, QSC_X509W_ANCHOR_MAX);
    }
}

void qsc_x509w_trust_store_clear(qsc_x509w_trust_store* store)
{
    size_t i;

    QSC_ASSERT(store != NULL);

    if (store != NULL)
    {
        for (i = 0U; i < store->store.count; ++i)
        {
            qsc_x509_certificate_free(&store->anchors[i].certificate);
        }

        for (i = 0U; i < store->crlcount; ++i)
        {
            qsc_x509_crl_clear(&store->crls[i]);
        }

        qsc_memutils_clear(store, sizeof(qsc_x509w_trust_store));
        qsc_x509_store_initialize(&store->store, store->anchors, QSC_X509W_ANCHOR_MAX);
    }
}

void qsc_x509w_server_identity_initialize(qsc_x509w_server_identity* identity)
{
    QSC_ASSERT(identity != NULL);

    if (identity != NULL)
    {
        qsc_memutils_clear(identity, sizeof(qsc_x509w_server_identity));
        qsc_x509_private_key_initialize(&identity->privatekey);
    }
}

void qsc_x509w_server_identity_clear(qsc_x509w_server_identity* identity)
{
    size_t i;

    QSC_ASSERT(identity != NULL);

    if (identity != NULL)
    {
        qsc_x509_certificate_free(&identity->leaf);

        for (i = 0U; i < identity->intermediatecount; ++i)
        {
            qsc_x509_certificate_free(&identity->intermediates[i]);
        }

        qsc_memutils_clear(identity, sizeof(qsc_x509w_server_identity));
    }
}

qsc_x509w_status qsc_x509w_current_utc_time(qsc_x509_time* currenttime)
{
    return x509w_current_utc_time_internal(currenttime);
}

qsc_x509w_status qsc_x509w_certificate_load_memory(const uint8_t* data, size_t datalen, qsc_x509_certificate* certificate)
{
    qsc_asn1_status xstatus;

    xstatus = QSC_ASN1_STATUS_SUCCESS;

    if (data == NULL || datalen == 0U || certificate == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    qsc_x509_certificate_clear(certificate);

    if (x509w_is_pem(data, datalen) == true)
    {
        xstatus = qsc_x509_certificate_decode_pem((const char*)data, datalen, certificate);
    }
    else
    {
        xstatus = qsc_x509_certificate_decode_der(data, datalen, certificate);
    }

    return x509w_map_asn1_status(xstatus);
}

qsc_x509w_status qsc_x509w_certificate_load_file(const char* path, qsc_x509_certificate* certificate)
{
    uint8_t data[QSC_X509_PEM_DER_MAX];
    size_t datalen;
    qsc_x509w_status status;

    qsc_memutils_clear(data, sizeof(data));
    datalen = 0U;
    status = x509w_read_file(path, data, sizeof(data), &datalen);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_certificate_load_memory(data, datalen, certificate);
    }

    return status;
}

qsc_x509w_status qsc_x509w_certificate_chain_load_memory(const uint8_t* data, size_t datalen, qsc_x509_certificate* certificates, size_t certificatecount, qsc_x509_chain* chain)
{
    qsc_asn1_status xstatus;
    qsc_x509w_status status;

    xstatus = QSC_ASN1_STATUS_SUCCESS;
    status = QSC_X509W_STATUS_SUCCESS;

    if (data == NULL || datalen == 0U || certificates == NULL || certificatecount == 0U || chain == NULL)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else if (x509w_is_pem(data, datalen) == true)
    {
        xstatus = qsc_x509_chain_decode_pem_bundle((const char*)data, datalen, certificates, certificatecount, chain);
        status = x509w_map_asn1_status(xstatus);
    }
    else
    {
        status = qsc_x509w_certificate_load_memory(data, datalen, &certificates[0]);

        if (status == QSC_X509W_STATUS_SUCCESS)
        {
            chain->certificates = certificates;
            chain->count = 1U;
        }
    }

    return status;
}

qsc_x509w_status qsc_x509w_certificate_chain_load_file(const char* path, qsc_x509_certificate* certificates, size_t certificatecount, qsc_x509_chain* chain)
{
    uint8_t data[QSC_X509_PEM_DER_MAX];
    size_t datalen;
    qsc_x509w_status status;

    qsc_memutils_clear(data, sizeof(data));
    datalen = 0U;
    status = x509w_read_file(path, data, sizeof(data), &datalen);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_certificate_chain_load_memory(data, datalen, certificates, certificatecount, chain);
    }

    return status;
}

qsc_x509w_status qsc_x509w_private_key_load_file(const char* path, qsc_x509_private_key* privatekey)
{
    uint8_t data[QSC_X509_PEM_DER_MAX];
    size_t datalen;
    qsc_x509w_status status;

    qsc_memutils_clear(data, sizeof(data));
    datalen = 0U;
    status = x509w_read_file(path, data, sizeof(data), &datalen);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_private_key_load_memory(data, datalen, privatekey);
    }

    return status;
}

qsc_x509w_status qsc_x509w_crl_load_file(const char* path, qsc_x509_crl* crl)
{
    uint8_t data[QSC_X509_PEM_DER_MAX];
    size_t datalen;
    qsc_x509w_status status;

    qsc_memutils_clear(data, sizeof(data));
    datalen = 0U;
    status = x509w_read_file(path, data, sizeof(data), &datalen);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_crl_load_memory(data, datalen, crl);
    }

    return status;
}

qsc_x509w_status qsc_x509w_private_key_load_memory(const uint8_t* data, size_t datalen, qsc_x509_private_key* privatekey)
{
    qsc_asn1_status xstatus;

    xstatus = QSC_ASN1_STATUS_SUCCESS;

    if (data == NULL || datalen == 0U || privatekey == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    qsc_x509_private_key_initialize(privatekey);

    if (x509w_is_pem(data, datalen) == true)
    {
        xstatus = qsc_x509_private_key_decode_pem_from_bundle((const char*)data, datalen, privatekey);
    }
    else
    {
        xstatus = qsc_x509_private_key_decode_pkcs8_der(data, datalen, privatekey);

        if (xstatus != QSC_ASN1_STATUS_SUCCESS)
        {
            xstatus = qsc_x509_private_key_decode_sec1_der(data, datalen, privatekey);
        }
    }

    return x509w_map_asn1_status(xstatus);
}

qsc_x509w_status qsc_x509w_crl_load_memory(const uint8_t* data, size_t datalen, qsc_x509_crl* crl)
{
    qsc_asn1_status xstatus;

    xstatus = QSC_ASN1_STATUS_SUCCESS;

    if (data == NULL || datalen == 0U || crl == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    qsc_x509_crl_clear(crl);

    if (x509w_is_pem(data, datalen) == true)
    {
        xstatus = qsc_x509_crl_decode_pem((const char*)data, datalen, crl);
    }
    else
    {
        xstatus = qsc_x509_crl_decode_der(data, datalen, crl);
    }

    return x509w_map_asn1_status(xstatus);
}

qsc_x509w_status qsc_x509w_csr_load_memory(const uint8_t* data, size_t datalen, qsc_x509_csr* csr)
{
    qsc_asn1_status xstatus;

    xstatus = QSC_ASN1_STATUS_SUCCESS;

    if (data == NULL || datalen == 0U || csr == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    qsc_x509_csr_clear(csr);

    if (x509w_is_pem(data, datalen) == true)
    {
        xstatus = qsc_x509_csr_decode_pem(csr, (const char*)data, datalen);
    }
    else
    {
        xstatus = qsc_x509_csr_decode_der(csr, data, datalen);
    }

    return x509w_map_asn1_status(xstatus);
}

qsc_x509w_status qsc_x509w_csr_load_file(const char* path, qsc_x509_csr* csr)
{
    uint8_t data[QSC_X509_PEM_DER_MAX];
    size_t datalen;
    qsc_x509w_status status;

    qsc_memutils_clear(data, sizeof(data));
    datalen = 0U;
    status = x509w_read_file(path, data, sizeof(data), &datalen);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_csr_load_memory(data, datalen, csr);
    }

    return status;
}

qsc_x509w_status qsc_x509w_trust_store_add_anchor(qsc_x509w_trust_store* store, const qsc_x509_certificate* certificate, bool selfsigned)
{
    qsc_asn1_status xstatus;
    size_t index;

    xstatus = QSC_ASN1_STATUS_SUCCESS;

    if (store == NULL || certificate == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }
    else if (store->store.count >= store->store.capacity)
    {
        return QSC_X509W_STATUS_STORE_FULL;
    }

    index = store->store.count;
    qsc_memutils_copy(&store->anchors[index].certificate, certificate, sizeof(qsc_x509_certificate));
    xstatus = qsc_x509_store_add_anchor(&store->store, &store->anchors[index].certificate, selfsigned);

    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        store->anchors[store->store.count - 1U].selfsigned = selfsigned;
    }
    else
    {
        qsc_memutils_clear(&store->anchors[index], sizeof(qsc_x509_trust_anchor));
    }

    return x509w_map_asn1_status(xstatus);
}

qsc_x509w_status qsc_x509w_trust_store_add_anchor_bundle_memory(qsc_x509w_trust_store* store, const uint8_t* data, size_t datalen, bool selfsigned)
{
    qsc_x509_certificate certificates[QSC_X509W_CHAIN_MAX];
    qsc_x509_chain chain;
    qsc_x509w_status status;
    size_t i;

    qsc_memutils_clear(certificates, sizeof(certificates));
    qsc_memutils_clear(&chain, sizeof(chain));
    status = qsc_x509w_certificate_chain_load_memory(data, datalen, certificates, QSC_X509W_CHAIN_MAX, &chain);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        for (i = 0U; i < chain.count && status == QSC_X509W_STATUS_SUCCESS; ++i)
        {
            status = qsc_x509w_trust_store_add_anchor(store, &certificates[i], selfsigned);
        }
    }

    return status;
}

qsc_x509w_status qsc_x509w_trust_store_add_anchor_bundle_file(qsc_x509w_trust_store* store, const char* path, bool selfsigned)
{
    uint8_t data[QSC_X509_PEM_DER_MAX];
    size_t datalen;
    qsc_x509w_status status;

    qsc_memutils_clear(data, sizeof(data));
    datalen = 0U;
    status = x509w_read_file(path, data, sizeof(data), &datalen);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_trust_store_add_anchor_bundle_memory(store, data, datalen, selfsigned);
    }

    return status;
}

qsc_x509w_status qsc_x509w_trust_store_add_anchor_memory(qsc_x509w_trust_store* store, const uint8_t* data, size_t datalen, bool selfsigned)
{
    qsc_x509_certificate certificate;
    qsc_x509w_status status;

    qsc_memutils_clear(&certificate, sizeof(qsc_x509_certificate));
    status = qsc_x509w_certificate_load_memory(data, datalen, &certificate);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_trust_store_add_anchor(store, &certificate, selfsigned);
    }

    return status;
}

qsc_x509w_status qsc_x509w_trust_store_add_crl(qsc_x509w_trust_store* store, const qsc_x509_crl* crl)
{
    if (store == NULL || crl == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }
    else if (store->crlcount >= QSC_X509W_CRL_MAX)
    {
        return QSC_X509W_STATUS_STORE_FULL;
    }

    qsc_memutils_copy(&store->crls[store->crlcount], crl, sizeof(qsc_x509_crl));
    ++store->crlcount;

    return QSC_X509W_STATUS_SUCCESS;
}

qsc_x509w_status qsc_x509w_trust_store_add_crl_memory(qsc_x509w_trust_store* store, const uint8_t* data, size_t datalen)
{
    qsc_x509_crl crl;
    qsc_x509w_status status;

    qsc_memutils_clear(&crl, sizeof(qsc_x509_crl));
    status = qsc_x509w_crl_load_memory(data, datalen, &crl);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_trust_store_add_crl(store, &crl);
    }

    return status;
}

qsc_x509w_status qsc_x509w_trust_store_add_anchor_file(qsc_x509w_trust_store* store, const char* path, bool selfsigned)
{
    qsc_x509_certificate certificate;
    qsc_x509w_status status;

    qsc_memutils_clear(&certificate, sizeof(qsc_x509_certificate));
    status = qsc_x509w_certificate_load_file(path, &certificate);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_trust_store_add_anchor(store, &certificate, selfsigned);
    }

    return status;
}

qsc_x509w_status qsc_x509w_trust_store_add_crl_file(qsc_x509w_trust_store* store, const char* path)
{
    qsc_x509_crl crl;
    qsc_x509w_status status;

    qsc_memutils_clear(&crl, sizeof(qsc_x509_crl));
    status = qsc_x509w_crl_load_file(path, &crl);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = qsc_x509w_trust_store_add_crl(store, &crl);
    }

    return status;
}

qsc_x509w_status qsc_x509w_server_identity_load_files(qsc_x509w_server_identity* identity, const char* certificatechainpath, const char* privatekeypath)
{
    qsc_x509_chain chain;
    qsc_x509w_status status;

    qsc_memutils_clear(&chain, sizeof(chain));
    status = QSC_X509W_STATUS_SUCCESS;

    if (identity == NULL || certificatechainpath == NULL || privatekeypath == NULL)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_x509w_server_identity_clear(identity);
        qsc_x509w_server_identity_initialize(identity);
        status = qsc_x509w_certificate_chain_load_file(certificatechainpath, &identity->leaf, QSC_X509W_CHAIN_MAX, &chain);

        if (status == QSC_X509W_STATUS_SUCCESS)
        {
            if (chain.count == 0U)
            {
                status = QSC_X509W_STATUS_DECODE_ERROR;
            }
            else
            {
                identity->intermediatecount = (chain.count > 1U) ? (chain.count - 1U) : 0U;
            }
        }

        if (status == QSC_X509W_STATUS_SUCCESS)
        {
            status = qsc_x509w_private_key_load_file(privatekeypath, &identity->privatekey);
        }
    }

    return status;
}

qsc_x509w_status qsc_x509w_server_identity_load_configuration(qsc_x509w_server_identity* identity, const qsc_x509w_deployment_config* config, qsc_x509w_result* result)
{
    qsc_x509w_status status;

    if (result != NULL)
    {
        qsc_x509w_result_initialize(result);
    }

    if (identity == NULL || config == NULL || config->certificatechainpath == NULL || config->privatekeypath == NULL)
    {
        if (result != NULL)
        {
            x509w_result_set_status(result, QSC_X509W_STATUS_INVALID_INPUT, QSC_X509W_STAGE_CONFIGURATION, "deployment configuration is incomplete");
        }

        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    status = qsc_x509w_server_identity_load_files(identity, config->certificatechainpath, config->privatekeypath);

    if (result != NULL)
    {
        if (status == QSC_X509W_STATUS_SUCCESS)
        {
            x509w_result_set_status(result, status, QSC_X509W_STAGE_NONE, "success");
        }
        else
        {
            x509w_result_set_status(result, status, QSC_X509W_STAGE_LOAD, "server identity load failed");
        }
    }

    return status;
}

qsc_x509w_status qsc_x509w_trust_store_load_configuration(qsc_x509w_trust_store* store, const qsc_x509w_deployment_config* config, qsc_x509w_result* result)
{
    qsc_x509w_status status;

    if (result != NULL)
    {
        qsc_x509w_result_initialize(result);
    }

    if (store == NULL || config == NULL)
    {
        if (result != NULL)
        {
            x509w_result_set_status(result, QSC_X509W_STATUS_INVALID_INPUT, QSC_X509W_STAGE_CONFIGURATION, "deployment configuration is incomplete");
        }

        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    qsc_x509w_trust_store_initialize(store);
    status = QSC_X509W_STATUS_SUCCESS;

    if (config->loadtrustanchors == true && config->trustanchorpath != NULL)
    {
        status = qsc_x509w_trust_store_add_anchor_bundle_file(store, config->trustanchorpath, true);
    }

    if (status == QSC_X509W_STATUS_SUCCESS && config->loadcrls == true && config->crlpath != NULL)
    {
        status = qsc_x509w_trust_store_add_crl_file(store, config->crlpath);
    }

    if (result != NULL)
    {
        if (status == QSC_X509W_STATUS_SUCCESS)
        {
            x509w_result_set_status(result, status, QSC_X509W_STAGE_NONE, "success");
        }
        else
        {
            x509w_result_set_status(result, status, QSC_X509W_STAGE_LOAD, "trust store load failed");
        }
    }

    return status;
}

qsc_x509w_status qsc_x509w_server_identity_validate(const qsc_x509w_server_identity* identity, const qsc_x509w_profile* profile, qsc_x509w_result* result)
{
    qsc_x509_verify_status vstatus;
    qsc_x509w_status status;
    bool keymatch;

    if (result != NULL)
    {
        qsc_x509w_result_initialize(result);
    }

    if (identity == NULL || profile == NULL)
    {
        if (result != NULL)
        {
            x509w_result_set_status(result, QSC_X509W_STATUS_INVALID_INPUT, QSC_X509W_STAGE_CONFIGURATION, "server identity validation input is invalid");
        }

        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    status = QSC_X509W_STATUS_SUCCESS;
    vstatus = qsc_x509_certificate_check_purpose(&identity->leaf, profile->purpose);
    keymatch = qsc_x509_certificate_key_match(&identity->leaf, &identity->privatekey);

    if (result != NULL)
    {
        result->keymatch = keymatch;
        result->purposevalid = (vstatus == QSC_X509_VERIFY_STATUS_SUCCESS);
        result->chainlength = 1U + identity->intermediatecount;
        x509w_result_apply_verify_status(result, vstatus);
    }

    if (keymatch == false)
    {
        status = QSC_X509W_STATUS_KEY_MISMATCH;

        if (result != NULL)
        {
            x509w_result_set_status(result, status, QSC_X509W_STAGE_KEY_MATCH, "private key does not match certificate");
        }
    }
    else if (vstatus != QSC_X509_VERIFY_STATUS_SUCCESS)
    {
        status = x509w_map_verify_status(vstatus);

        if (result != NULL)
        {
            x509w_result_set_status(result, status, QSC_X509W_STAGE_PURPOSE, "certificate purpose rejected");
        }
    }
    else if (profile->hostname != NULL)
    {
        vstatus = qsc_x509_certificate_check_hostname(&identity->leaf, profile->hostname);
        if (vstatus != QSC_X509_VERIFY_STATUS_SUCCESS)
        {
            status = x509w_map_verify_status(vstatus);

            if (result != NULL)
            {
                result->hostnamechecked = true;
                result->hostnamevalid = false;
                x509w_result_apply_verify_status(result, vstatus);
                x509w_result_set_status(result, status, QSC_X509W_STAGE_HOSTNAME, "certificate hostname mismatch");
            }
        }
        else if (result != NULL)
        {
            result->hostnamechecked = true;
            result->hostnamevalid = true;
        }
    }

    if (result != NULL && status == QSC_X509W_STATUS_SUCCESS)
    {
        result->verifystatus = vstatus;
        x509w_result_set_status(result, status, QSC_X509W_STAGE_NONE, "success");
    }

    return status;
}

qsc_x509w_status qsc_x509w_verify_peer_certificates(const qsc_x509_certificate* certificates, size_t certificatecount,
    const qsc_x509w_trust_store* store, const qsc_x509w_profile* profile, qsc_x509w_result* result)
{
    return x509w_verify_chain_internal(certificates, certificatecount, store, profile, result);
}

static qsc_x509w_status x509w_copy_text_value(const uint8_t* data, size_t datalen, char* output, size_t outputlen, size_t* written)
{
    qsc_x509w_status status;

    status = QSC_X509W_STATUS_SUCCESS;

    if (data == NULL || output == NULL || written == NULL || outputlen == 0U)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else if (datalen >= outputlen)
    {
        status = QSC_X509W_STATUS_BUFFER_TOO_SMALL;
    }
    else
    {
        qsc_memutils_copy((uint8_t*)output, data, datalen);
        output[datalen] = '\0';
        *written = datalen;
    }

    return status;
}

qsc_x509w_status qsc_x509w_name_string(const qsc_x509_name* name, char* output, size_t outputlen, size_t* written)
{
    if (name == NULL || output == NULL || written == NULL || outputlen == 0U)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    return x509w_map_asn1_status(qsc_x509_name_to_string(name, output, outputlen, written));
}

qsc_x509w_status qsc_x509w_name_get_attribute_first(const qsc_x509_name* name, qsc_x509_name_attribute_type type, char* output, size_t outputlen, size_t* written)
{
    const qsc_x509_name_attribute* attr;

    if (name == NULL || output == NULL || written == NULL || outputlen == 0U)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    attr = qsc_x509_name_find_first(name, type);

    if (attr == NULL)
    {
        return QSC_X509W_STATUS_NOT_FOUND;
    }

    return x509w_copy_text_value(attr->value, attr->length, output, outputlen, written);
}

qsc_x509w_status qsc_x509w_certificate_subject_string(const qsc_x509_certificate* certificate, char* output, size_t outputlen, size_t* written)
{
    if (certificate == NULL || output == NULL || written == NULL || outputlen == 0U)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    return qsc_x509w_name_string(&certificate->subject, output, outputlen, written);
}

qsc_x509w_status qsc_x509w_certificate_issuer_string(const qsc_x509_certificate* certificate, char* output, size_t outputlen, size_t* written)
{
    if (certificate == NULL || output == NULL || written == NULL || outputlen == 0U)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    return qsc_x509w_name_string(&certificate->issuer, output, outputlen, written);
}

qsc_x509w_status qsc_x509w_certificate_subject_common_name(const qsc_x509_certificate* certificate, char* output, size_t outputlen, size_t* written)
{
    if (certificate == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    return qsc_x509w_name_get_attribute_first(&certificate->subject, QSC_X509_NAME_ATTRIBUTE_COMMON_NAME, output, outputlen, written);
}

size_t qsc_x509w_certificate_subject_dns_name_count(const qsc_x509_certificate* certificate)
{
    size_t i;
    size_t count;

    count = 0U;

    if (certificate != NULL && certificate->extensions.subjectaltname.present == true)
    {
        for (i = 0U; i < certificate->extensions.subjectaltname.count; ++i)
        {
            if (certificate->extensions.subjectaltname.entries[i].type == QSC_X509_GENERAL_NAME_DNS_NAME)
            {
                ++count;
            }
        }
    }

    return count;
}

qsc_x509w_status qsc_x509w_certificate_subject_dns_name(const qsc_x509_certificate* certificate, size_t index, char* output, size_t outputlen, size_t* written)
{
    size_t i;
    size_t count;
    const qsc_x509_general_name* entry;

    if (certificate == NULL || output == NULL || written == NULL || outputlen == 0U)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    if (certificate->extensions.subjectaltname.present == false)
    {
        return QSC_X509W_STATUS_NOT_FOUND;
    }

    count = 0U;

    for (i = 0U; i < certificate->extensions.subjectaltname.count; ++i)
    {
        entry = &certificate->extensions.subjectaltname.entries[i];

        if (entry->type == QSC_X509_GENERAL_NAME_DNS_NAME)
        {
            if (count == index)
            {
                return x509w_copy_text_value(entry->data, entry->length, output, outputlen, written);
            }

            ++count;
        }
    }

    return QSC_X509W_STATUS_NOT_FOUND;
}

const char* qsc_x509w_revocation_mode_string(qsc_x509w_revocation_mode mode)
{
    const char* text;

    text = "unknown";

    switch (mode)
    {
        case QSC_X509W_REVOCATION_MODE_NONE: text = "none"; break;
        case QSC_X509W_REVOCATION_MODE_CRL_IF_PRESENT: text = "crl-if-present"; break;
        case QSC_X509W_REVOCATION_MODE_CRL_REQUIRED: text = "crl-required"; break;
        case QSC_X509W_REVOCATION_MODE_OCSP_IF_PRESENT: text = "ocsp-if-present"; break;
        case QSC_X509W_REVOCATION_MODE_OCSP_REQUIRED: text = "ocsp-required"; break;
        case QSC_X509W_REVOCATION_MODE_CRL_OR_OCSP_REQUIRED: text = "crl-or-ocsp-required"; break;
        case QSC_X509W_REVOCATION_MODE_CRL_AND_OCSP_REQUIRED: text = "crl-and-ocsp-required"; break;
        default: break;
    }

    return text;
}

const char* qsc_x509w_locator_policy_string(qsc_x509w_locator_policy policy)
{
    const char* text;

    text = "unknown";

    switch (policy)
    {
        case QSC_X509W_LOCATOR_POLICY_DISABLED: text = "disabled"; break;
        case QSC_X509W_LOCATOR_POLICY_ALLOW_EMBEDDED: text = "allow-embedded"; break;
        case QSC_X509W_LOCATOR_POLICY_REQUIRE_EMBEDDED: text = "require-embedded"; break;
        default: break;
    }

    return text;
}

const char* qsc_x509w_revocation_source_string(qsc_x509w_revocation_source source)
{
    const char* text;

    text = "unknown";

    switch (source)
    {
        case QSC_X509W_REVOCATION_SOURCE_NONE: text = "none"; break;
        case QSC_X509W_REVOCATION_SOURCE_CRL: text = "crl"; break;
        case QSC_X509W_REVOCATION_SOURCE_OCSP: text = "ocsp"; break;
        default: break;
    }

    return text;
}

const char* qsc_x509w_availability_string(qsc_x509w_availability availability)
{
    const char* text;

    text = "unknown";

    switch (availability)
    {
        case QSC_X509W_AVAILABILITY_UNSPECIFIED: text = "unspecified"; break;
        case QSC_X509W_AVAILABILITY_UNCHECKED: text = "unchecked"; break;
        case QSC_X509W_AVAILABILITY_AVAILABLE: text = "available"; break;
        case QSC_X509W_AVAILABILITY_UNAVAILABLE: text = "unavailable"; break;
        default: break;
    }

    return text;
}

const char* qsc_x509w_status_string(qsc_x509w_status status)
{
    switch (status)
    {
        case QSC_X509W_STATUS_SUCCESS: return "success";
        case QSC_X509W_STATUS_INVALID_INPUT: return "invalid input";
        case QSC_X509W_STATUS_IO_ERROR: return "I/O error";
        case QSC_X509W_STATUS_DECODE_ERROR: return "decode error";
        case QSC_X509W_STATUS_CHAIN_BUILD_ERROR: return "chain build error";
        case QSC_X509W_STATUS_VERIFY_ERROR: return "verification error";
        case QSC_X509W_STATUS_HOSTNAME_MISMATCH: return "hostname mismatch";
        case QSC_X509W_STATUS_KEY_MISMATCH: return "key mismatch";
        case QSC_X509W_STATUS_PURPOSE_REJECTED: return "purpose rejected";
        case QSC_X509W_STATUS_STORE_FULL: return "store full";
        case QSC_X509W_STATUS_BUFFER_TOO_SMALL: return "buffer too small";
        case QSC_X509W_STATUS_NETWORK_ERROR: return "network error";
        case QSC_X509W_STATUS_UNSUPPORTED: return "unsupported";
        case QSC_X509W_STATUS_NOT_FOUND: return "not found";
        case QSC_X509W_STATUS_ENCODING_ERROR: return "encoding error";
        case QSC_X509W_STATUS_PROFILE_ERROR: return "profile error";
        case QSC_X509W_STATUS_CALLBACK_ERROR: return "callback error";
        default: return "unknown status";
    }
}

const char* qsc_x509w_stage_string(qsc_x509w_stage stage)
{
    switch (stage)
    {
        case QSC_X509W_STAGE_NONE: return "none";
        case QSC_X509W_STAGE_LOAD: return "load";
        case QSC_X509W_STAGE_PARSE: return "parse";
        case QSC_X509W_STAGE_CHAIN_BUILD: return "chain_build";
        case QSC_X509W_STAGE_TIME: return "time";
        case QSC_X509W_STAGE_PURPOSE: return "purpose";
        case QSC_X509W_STAGE_HOSTNAME: return "hostname";
        case QSC_X509W_STAGE_KEY_MATCH: return "key_match";
        case QSC_X509W_STAGE_REVOCATION: return "revocation";
        case QSC_X509W_STAGE_TRUST: return "trust";
        case QSC_X509W_STAGE_EXPORT: return "export";
        case QSC_X509W_STAGE_CONFIGURATION: return "configuration";
        default: return "unknown_stage";
    }
}

const char* qsc_x509w_verify_status_string(qsc_x509_verify_status status)
{
    switch (status)
    {
        case QSC_X509_VERIFY_STATUS_SUCCESS: return "success";
        case QSC_X509_VERIFY_STATUS_INVALID_INPUT: return "invalid_input";
        case QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE: return "invalid_certificate";
        case QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH: return "algorithm_mismatch";
        case QSC_X509_VERIFY_STATUS_EXPIRED: return "expired";
        case QSC_X509_VERIFY_STATUS_NOT_YET_VALID: return "not_yet_valid";
        case QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH: return "issuer_mismatch";
        case QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH: return "key_identifier_mismatch";
        case QSC_X509_VERIFY_STATUS_NOT_CA: return "not_ca";
        case QSC_X509_VERIFY_STATUS_PATH_LENGTH_EXCEEDED: return "path_length_exceeded";
        case QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED: return "key_usage_rejected";
        case QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED: return "signature_rejected";
        case QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND: return "trust_not_found";
        case QSC_X509_VERIFY_STATUS_UNSUPPORTED: return "unsupported";
        case QSC_X509_VERIFY_STATUS_CALLBACK_FAILURE: return "callback_failure";
        case QSC_X509_VERIFY_STATUS_UNSUPPORTED_CRITICAL_EXTENSION: return "unsupported_critical_extension";
        case QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED: return "purpose_rejected";
        case QSC_X509_VERIFY_STATUS_REVOKED: return "revoked";
        case QSC_X509_VERIFY_STATUS_REVOCATION_UNKNOWN: return "revocation_unknown";
        case QSC_X509_VERIFY_STATUS_CHAIN_LOOP: return "chain_loop";
        case QSC_X509_VERIFY_STATUS_NAME_MISMATCH: return "name_mismatch";
        default: return "unknown_verify_status";
    }
}

const char* qsc_x509w_result_message(const qsc_x509w_result* result)
{
    if (result == NULL)
    {
        return "invalid result";
    }

    return result->message;
}

qsc_x509w_status qsc_x509w_certificate_check_role(const qsc_x509_certificate* certificate, qsc_x509w_certificate_role role,
    const char* hostname, qsc_x509w_result* result)
{
    qsc_x509_verify_status vstatus;
    qsc_x509w_status status;

    if (result != NULL)
    {
        qsc_x509w_result_initialize(result);
    }

    if (certificate == NULL)
    {
        if (result != NULL)
        {
            x509w_result_set_status(result, QSC_X509W_STATUS_INVALID_INPUT, QSC_X509W_STAGE_CONFIGURATION, "certificate role check input is invalid");
        }

        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    vstatus = QSC_X509_VERIFY_STATUS_SUCCESS;
    status = QSC_X509W_STATUS_SUCCESS;

    switch (role)
    {
        case QSC_X509W_CERTIFICATE_ROLE_TLS_SERVER:
        {
            vstatus = qsc_x509_certificate_check_purpose(certificate, QSC_X509_VERIFY_PURPOSE_TLS_SERVER);
            break;
        }
        case QSC_X509W_CERTIFICATE_ROLE_TLS_CLIENT:
        {
            vstatus = qsc_x509_certificate_check_purpose(certificate, QSC_X509_VERIFY_PURPOSE_TLS_CLIENT);
            break;
        }
        case QSC_X509W_CERTIFICATE_ROLE_CA:
        case QSC_X509W_CERTIFICATE_ROLE_TRUST_ANCHOR:
        {
            if (qsc_x509_certificate_is_ca(certificate) == false)
            {
                vstatus = QSC_X509_VERIFY_STATUS_NOT_CA;
            }
            break;
        }
        default:
        {
            vstatus = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
            break;
        }
    }

    status = x509w_map_verify_status(vstatus);

    if (result != NULL)
    {
        result->purposevalid = (vstatus == QSC_X509_VERIFY_STATUS_SUCCESS);
        x509w_result_apply_verify_status(result, vstatus);
    }

    if (status == QSC_X509W_STATUS_SUCCESS && hostname != NULL && role == QSC_X509W_CERTIFICATE_ROLE_TLS_SERVER)
    {
        vstatus = qsc_x509_certificate_check_hostname(certificate, hostname);
        status = x509w_map_verify_status(vstatus);

        if (result != NULL)
        {
            result->hostnamechecked = true;
            result->hostnamevalid = (vstatus == QSC_X509_VERIFY_STATUS_SUCCESS);
            x509w_result_apply_verify_status(result, vstatus);
        }
    }

    if (result != NULL)
    {
        if (status == QSC_X509W_STATUS_SUCCESS)
        {
            x509w_result_set_status(result, status, QSC_X509W_STAGE_NONE, "success");
        }
        else if (status == QSC_X509W_STATUS_HOSTNAME_MISMATCH)
        {
            x509w_result_set_status(result, status, QSC_X509W_STAGE_HOSTNAME, "certificate hostname mismatch");
        }
        else
        {
            x509w_result_set_status(result, status, QSC_X509W_STAGE_PURPOSE, "certificate role suitability check failed");
        }
    }

    return status;
}

qsc_x509w_status qsc_x509w_server_identity_get_chain(const qsc_x509w_server_identity* identity, qsc_x509_chain* chain)
{
    if (identity == NULL || chain == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    chain->certificates = (qsc_x509_certificate*)&identity->leaf;
    chain->count = 1U + identity->intermediatecount;

    return QSC_X509W_STATUS_SUCCESS;
}

qsc_x509w_status qsc_x509w_server_identity_verify(const qsc_x509w_server_identity* identity, const qsc_x509w_trust_store* store,
    const qsc_x509w_profile* profile, qsc_x509w_result* result)
{
    if (identity == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    return qsc_x509w_verify_peer_certificates(&identity->leaf, 1U + identity->intermediatecount, store, profile, result);
}

qsc_x509w_status qsc_x509w_certificate_export_der(const qsc_x509_certificate* certificate, uint8_t* output, size_t outputlen, size_t* written)
{
    if (certificate == NULL || output == NULL || written == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }
    else if (certificate->der == NULL || certificate->derlen == 0U)
    {
        return QSC_X509W_STATUS_UNSUPPORTED;
    }
    else if (outputlen < certificate->derlen)
    {
        return QSC_X509W_STATUS_BUFFER_TOO_SMALL;
    }

    qsc_memutils_copy(output, certificate->der, certificate->derlen);
    *written = certificate->derlen;

    return QSC_X509W_STATUS_SUCCESS;
}

qsc_x509w_status qsc_x509w_certificate_export_pem(const qsc_x509_certificate* certificate, char* output, size_t outputlen, size_t* written)
{
    qsc_asn1_status xstatus;
    size_t outlen;

    if (certificate == NULL || output == NULL || written == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }
    else if (certificate->der == NULL || certificate->derlen == 0U)
    {
        return QSC_X509W_STATUS_UNSUPPORTED;
    }

    outlen = outputlen;
    xstatus = qsc_x509_certificate_encode_pem(certificate->der, certificate->derlen, output, &outlen);
    *written = outlen;

    return x509w_map_encode_status(xstatus);
}

qsc_x509w_status qsc_x509w_private_key_export_pkcs8_der(const qsc_x509_private_key* privatekey, bool includepublickey, uint8_t* output, size_t outputlen, size_t* written)
{
    qsc_asn1_status xstatus;
    size_t outlen;

    if (privatekey == NULL || output == NULL || written == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    outlen = outputlen;
    xstatus = qsc_x509_private_key_encode_pkcs8_der(privatekey, includepublickey, output, &outlen);
    *written = outlen;

    return x509w_map_encode_status(xstatus);
}

qsc_x509w_status qsc_x509w_private_key_export_pkcs8_pem(const qsc_x509_private_key* privatekey, bool includepublickey, char* output, size_t outputlen, size_t* written)
{
    qsc_asn1_status xstatus;
    size_t outlen;

    if (privatekey == NULL || output == NULL || written == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    outlen = outputlen;
    xstatus = qsc_x509_private_key_encode_pkcs8_pem(privatekey, includepublickey, output, &outlen);
    *written = outlen;

    return x509w_map_encode_status(xstatus);
}

qsc_x509w_status qsc_x509w_csr_export_der(const qsc_x509_csr* csr, uint8_t* output, size_t outputlen, size_t* written)
{
    if (csr == NULL || output == NULL || written == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }
    else if (csr->der == NULL || csr->derlen == 0U)
    {
        return QSC_X509W_STATUS_UNSUPPORTED;
    }
    else if (outputlen < csr->derlen)
    {
        return QSC_X509W_STATUS_BUFFER_TOO_SMALL;
    }

    qsc_memutils_copy(output, csr->der, csr->derlen);
    *written = csr->derlen;

    return QSC_X509W_STATUS_SUCCESS;
}

qsc_x509w_status qsc_x509w_csr_export_pem(const qsc_x509_csr* csr, char* output, size_t outputlen, size_t* written)
{
    qsc_asn1_status xstatus;
    size_t outlen;

    if (csr == NULL || output == NULL || written == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }
    else if (csr->der == NULL || csr->derlen == 0U)
    {
        return QSC_X509W_STATUS_UNSUPPORTED;
    }

    outlen = outputlen;
    xstatus = qsc_x509_csr_encode_pem(csr->der, csr->derlen, output, &outlen);
    *written = outlen;

    return x509w_map_encode_status(xstatus);
}

qsc_x509w_status qsc_x509w_csr_create(qsc_x509_csr* csr, const qsc_x509_name* subject,
    const qsc_x509_subject_public_key_info* spki, const qsc_x509_algorithm_identifier* signaturealgorithm)
{
    qsc_asn1_status xstatus;

    if (csr == NULL || subject == NULL || spki == NULL || signaturealgorithm == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    qsc_x509_csr_initialize(csr);
    xstatus = qsc_x509_csr_set_subject(csr, subject);

    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_csr_set_spki(csr, spki);
    }

    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_csr_set_signature_algorithm(csr, signaturealgorithm);
    }

    return x509w_map_asn1_status(xstatus);
}

qsc_x509w_status qsc_x509w_csr_add_dns_name(qsc_x509_csr* csr, const char* dnsname)
{
    if (csr == NULL || dnsname == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    return x509w_map_asn1_status(qsc_x509_csr_add_san_dns(csr, dnsname, strlen(dnsname)));
}

qsc_x509w_status qsc_x509w_csr_sign_der(const qsc_x509_csr* csr, qsc_x509_certificate_sign_callback signcallback,
    void* context, uint8_t* output, size_t* outputlen)
{
    if (csr == NULL || signcallback == NULL || output == NULL || outputlen == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    return x509w_map_encode_status(qsc_x509_csr_sign(csr, signcallback, context, output, outputlen));
}

qsc_x509w_status qsc_x509w_csr_sign_pem(const qsc_x509_csr* csr, qsc_x509_certificate_sign_callback signcallback,
    void* context, char* output, size_t* outputlen)
{
    qsc_x509w_status status;
    uint8_t der[QSC_X509_CSR_WRITE_MAX];
    size_t derlen;

    qsc_memutils_clear(der, sizeof(der));
    derlen = sizeof(der);
    status = qsc_x509w_csr_sign_der(csr, signcallback, context, der, &derlen);

    if (status == QSC_X509W_STATUS_SUCCESS)
    {
        status = x509w_map_encode_status(qsc_x509_csr_encode_pem(der, derlen, output, outputlen));
    }

    return status;
}

qsc_x509w_status qsc_x509w_csr_verify(const qsc_x509_csr* csr)
{
    if (csr == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    return (qsc_x509_csr_verify(csr) == true) ? QSC_X509W_STATUS_SUCCESS : QSC_X509W_STATUS_VERIFY_ERROR;
}

qsc_x509w_status qsc_x509w_certificate_issue_from_csr(const qsc_x509_csr* csr, const qsc_x509_certificate* issuer,
    const qsc_x509_algorithm_identifier* signaturealgorithm, const uint8_t* serialnumber, size_t serialnumberlen,
    const qsc_x509_validity* validity, uint32_t profile, uint32_t policyflags,
    qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen)
{
    qsc_asn1_status xstatus;
    qsc_x509_certificate_builder builder;

    if (csr == NULL || issuer == NULL || signaturealgorithm == NULL || serialnumber == NULL || serialnumberlen == 0U ||
        validity == NULL || signcallback == NULL || output == NULL || outputlen == NULL)
    {
        return QSC_X509W_STATUS_INVALID_INPUT;
    }

    qsc_x509_certificate_builder_initialize(&builder);
    xstatus = qsc_x509_cert_issuance_validate_csr(csr);

    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_certificate_builder_set_serial(&builder, serialnumber, serialnumberlen);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_certificate_builder_set_issuer_from_certificate(&builder, issuer);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_certificate_builder_set_subject(&builder, &csr->subject);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_certificate_builder_set_validity(&builder, validity);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_certificate_builder_set_spki(&builder, &csr->spki);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_certificate_builder_set_signature_algorithm(&builder, signaturealgorithm);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS && profile != QSC_X509_CERT_PROFILE_NONE)
    {
        xstatus = qsc_x509_certificate_builder_apply_profile(&builder, profile);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_cert_issuance_apply_csr_extensions(&builder, csr, policyflags);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_certificate_builder_apply_generated_identifiers(&builder, issuer);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS && profile != QSC_X509_CERT_PROFILE_NONE)
    {
        xstatus = qsc_x509_certificate_builder_validate_profile(&builder, issuer, profile);
    }
    if (xstatus == QSC_ASN1_STATUS_SUCCESS)
    {
        xstatus = qsc_x509_certificate_builder_sign(&builder, signcallback, context, output, outputlen);
    }

    qsc_x509_certificate_builder_clear(&builder);

    if (xstatus != QSC_ASN1_STATUS_SUCCESS)
    {
        if (xstatus == QSC_ASN1_STATUS_INVALID_INPUT)
        {
            return QSC_X509W_STATUS_INVALID_INPUT;
        }

        return (profile != QSC_X509_CERT_PROFILE_NONE) ? QSC_X509W_STATUS_PROFILE_ERROR : QSC_X509W_STATUS_ENCODING_ERROR;
    }

    return QSC_X509W_STATUS_SUCCESS;
}


void qsc_x509w_tls_bridge_initialize(qsc_x509w_tls_bridge* bridge)
{
    if (bridge != NULL)
    {
        qsc_memutils_clear(bridge, sizeof(qsc_x509w_tls_bridge));
        qsc_x509w_profile_initialize(&bridge->profile);
    }
}

void qsc_x509w_tls_local_certificate_initialize(qsc_x509w_tls_local_certificate* localcert)
{
    if (localcert != NULL)
    {
        qsc_memutils_clear(localcert, sizeof(qsc_x509w_tls_local_certificate));
        localcert->verifyscheme = qsc_tls_sig_none;
    }
}

bool qsc_x509w_tls_bridge_is_ready(const qsc_x509w_tls_bridge* bridge)
{
    bool res;

    res = false;

    if (bridge != NULL)
    {
        res = bridge->initialized;
    }

    return res;
}

const qsc_tls_certificate_interface* qsc_x509w_tls_bridge_get_interface(const qsc_x509w_tls_bridge* bridge)
{
    const qsc_tls_certificate_interface* iface;

    iface = NULL;

    if (bridge != NULL && bridge->initialized == true)
    {
        iface = &bridge->iface;
    }

    return iface;
}

bool qsc_x509w_tls_local_certificate_is_ready(const qsc_x509w_tls_local_certificate* localcert)
{
    bool res;

    res = false;

    if (localcert != NULL)
    {
        res = (localcert->chainlength != 0U);
    }

    return res;
}

static qsc_x509w_status x509w_map_tls_status(qsc_tls_status status)
{
    qsc_x509w_status res;

    res = QSC_X509W_STATUS_CALLBACK_ERROR;

    switch (status)
    {
        case qsc_tls_status_success:
        {
            res = QSC_X509W_STATUS_SUCCESS;
            break;
        }
        case qsc_tls_status_invalid_input:
        {
            res = QSC_X509W_STATUS_INVALID_INPUT;
            break;
        }
        case qsc_tls_status_buffer_too_small:
        case qsc_tls_status_invalid_length:
        {
            res = QSC_X509W_STATUS_BUFFER_TOO_SMALL;
            break;
        }
        default:
        {
            break;
        }
    }

    return res;
}

qsc_x509w_status qsc_x509w_tls_bridge_configure(qsc_x509w_tls_bridge* bridge, const qsc_x509w_trust_store* store,
    const qsc_x509w_profile* profile)
{
    qsc_tls_status tstatus;
    qsc_x509w_status status;

    tstatus = qsc_tls_status_success;
    status = QSC_X509W_STATUS_SUCCESS;

    if (bridge == NULL || store == NULL || profile == NULL)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_x509w_tls_bridge_initialize(bridge);
        bridge->profile = *profile;
        bridge->truststore = store;

        if (bridge->profile.validationtime == NULL)
        {
            status = x509w_current_utc_time_internal(&bridge->currenttime);
            if (status == QSC_X509W_STATUS_SUCCESS)
            {
                bridge->profile.validationtime = &bridge->currenttime;
            }
        }

        if (status == QSC_X509W_STATUS_SUCCESS)
        {
            qsc_tls_qsc_x509_context_initialize(&bridge->context, &store->store, NULL, 0U, bridge->profile.validationtime,
                bridge->verifybuffer, sizeof(bridge->verifybuffer));
            bridge->context.rejectunsupportedcriticalextensions = bridge->profile.rejectunsupportedcriticalextensions;
            tstatus = qsc_tls_certificate_interface_initialize_qsc_x509(&bridge->iface, &bridge->context);
            status = x509w_map_tls_status(tstatus);

            if (status == QSC_X509W_STATUS_SUCCESS)
            {
                bridge->initialized = true;
            }
        }
    }

    return status;
}

qsc_x509w_status qsc_x509w_tls_bridge_attach_client_validation(qsc_tls_client* client, const qsc_x509w_tls_bridge* bridge,
    const char* hostname, bool requirepeercertificate)
{
    qsc_x509w_status status;
    const qsc_tls_certificate_interface* iface;

    status = QSC_X509W_STATUS_SUCCESS;
    iface = qsc_x509w_tls_bridge_get_interface(bridge);

    if (client == NULL || iface == NULL)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_tls_client_set_certificate_interface(client, iface, hostname, requirepeercertificate);
    }

    return status;
}

qsc_x509w_status qsc_x509w_tls_bridge_attach_server_validation(qsc_tls_server* server, const qsc_x509w_tls_bridge* bridge,
    const char* hostname, bool requirepeercertificate)
{
    qsc_x509w_status status;
    const qsc_tls_certificate_interface* iface;

    status = QSC_X509W_STATUS_SUCCESS;
    iface = qsc_x509w_tls_bridge_get_interface(bridge);

    if (server == NULL || iface == NULL)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_tls_server_set_certificate_interface(server, iface, hostname, requirepeercertificate);
    }

    return status;
}

qsc_x509w_status qsc_x509w_tls_bridge_set_client(qsc_tls_client* client, qsc_x509w_tls_bridge* bridge,
    const char* hostname, bool requirepeercertificate)
{
    return qsc_x509w_tls_bridge_attach_client_validation(client, bridge, hostname, requirepeercertificate);
}

qsc_x509w_status qsc_x509w_tls_bridge_set_server_validation(qsc_tls_server* server, qsc_x509w_tls_bridge* bridge,
    const char* hostname, bool requirepeercertificate)
{
    return qsc_x509w_tls_bridge_attach_server_validation(server, bridge, hostname, requirepeercertificate);
}

qsc_x509w_status qsc_x509w_tls_local_certificate_from_identity(const qsc_x509w_server_identity* identity,
    qsc_tls_signature_scheme verifyscheme, const uint8_t* verifysignature, size_t verifysignaturelen,
    qsc_x509w_tls_local_certificate* localcert)
{
    qsc_x509w_status status;
    size_t i;
    size_t written;

    status = QSC_X509W_STATUS_SUCCESS;
    i = 0U;
    written = 0U;

    if (identity == NULL || localcert == NULL || identity->intermediatecount >= QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES ||
        (verifysignature == NULL && verifysignaturelen != 0U) ||
        verifysignaturelen > sizeof(localcert->verifysignature))
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else
    {
        qsc_x509w_tls_local_certificate_initialize(localcert);
        status = qsc_x509w_certificate_export_der(&identity->leaf, localcert->chainder[0], sizeof(localcert->chainder[0]), &written);

        if (status == QSC_X509W_STATUS_SUCCESS)
        {
            localcert->chain[0].data = localcert->chainder[0];
            localcert->chain[0].datalen = written;
            localcert->chainlength = 1U;
        }

        while (status == QSC_X509W_STATUS_SUCCESS && i < identity->intermediatecount)
        {
            written = 0U;
            status = qsc_x509w_certificate_export_der(&identity->intermediates[i], localcert->chainder[i + 1U], sizeof(localcert->chainder[i + 1U]), &written);

            if (status == QSC_X509W_STATUS_SUCCESS)
            {
                localcert->chain[i + 1U].data = localcert->chainder[i + 1U];
                localcert->chain[i + 1U].datalen = written;
                localcert->chainlength = i + 2U;
            }

            ++i;
        }

        if (status == QSC_X509W_STATUS_SUCCESS)
        {
            localcert->verifyscheme = verifyscheme;
            localcert->verifysignaturelen = verifysignaturelen;
            if (verifysignaturelen != 0U)
            {
                qsc_memutils_copy(localcert->verifysignature, verifysignature, verifysignaturelen);
            }
        }
    }

    return status;
}

qsc_x509w_status qsc_x509w_tls_server_set_local_certificate(qsc_tls_server* server,
    const qsc_x509w_tls_local_certificate* localcert)
{
    qsc_tls_status tstatus;
    qsc_x509w_status status;

    tstatus = qsc_tls_status_success;
    status = QSC_X509W_STATUS_SUCCESS;

    if (server == NULL || localcert == NULL || localcert->chainlength == 0U)
    {
        status = QSC_X509W_STATUS_INVALID_INPUT;
    }
    else
    {
        tstatus = qsc_tls_server_set_local_certificate(server, localcert->chain, localcert->chainlength,
            localcert->verifyscheme, localcert->verifysignature, localcert->verifysignaturelen);
        status = x509w_map_tls_status(tstatus);
    }

    return status;
}
