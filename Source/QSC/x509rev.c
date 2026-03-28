#include "x509rev.h"
#include "memutils.h"
#include "x509name.h"

static qsc_x509_revocation_status x509_map_crl_verify_status(qsc_x509_crl_verify_status status)
{
    qsc_x509_revocation_status res;

    switch (status)
    {
        case QSC_X509_CRL_VERIFY_STATUS_SUCCESS:
        {
            res = QSC_X509_REVOCATION_STATUS_GOOD;
            break;
        }
        case QSC_X509_CRL_VERIFY_STATUS_ISSUER_MISMATCH:
        {
            res = QSC_X509_REVOCATION_STATUS_ISSUER_MISMATCH;
            break;
        }
        case QSC_X509_CRL_VERIFY_STATUS_EXPIRED:
        case QSC_X509_CRL_VERIFY_STATUS_NOT_YET_VALID:
        {
            res = QSC_X509_REVOCATION_STATUS_CRL_EXPIRED;
            break;
        }
        case QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT:
        case QSC_X509_CRL_VERIFY_STATUS_INVALID_CRL:
        case QSC_X509_CRL_VERIFY_STATUS_ALGORITHM_MISMATCH:
        case QSC_X509_CRL_VERIFY_STATUS_KEY_USAGE_REJECTED:
        case QSC_X509_CRL_VERIFY_STATUS_SIGNATURE_REJECTED:
        case QSC_X509_CRL_VERIFY_STATUS_CALLBACK_FAILURE:
        case QSC_X509_CRL_VERIFY_STATUS_UNSUPPORTED:
        default:
        {
            res = QSC_X509_REVOCATION_STATUS_CRL_INVALID;
            break;
        }
    }

    return res;
}

static qsc_x509_revocation_status x509_check_crl_baseline(const qsc_x509_crl* crl, const qsc_x509_certificate* issuer, const qsc_x509_time* validationtime)
{
    qsc_x509_revocation_status res;

    res = QSC_X509_REVOCATION_STATUS_GOOD;

    if (crl == (const qsc_x509_crl*)NULL || issuer == (const qsc_x509_certificate*)NULL)
    {
        res = QSC_X509_REVOCATION_STATUS_ERROR;
    }
    else if (qsc_x509_crl_check_algorithms(crl) != QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
    {
        res = QSC_X509_REVOCATION_STATUS_CRL_INVALID;
    }
    else if (qsc_x509_name_equals(&crl->issuer, &issuer->subject) == false)
    {
        res = QSC_X509_REVOCATION_STATUS_ISSUER_MISMATCH;
    }
    else if (issuer->extensions.keyusage.present == true && (issuer->extensions.keyusage.bits & QSC_X509_KEY_USAGE_CRL_SIGN) == 0U)
    {
        res = QSC_X509_REVOCATION_STATUS_CRL_INVALID;
    }
    else if (validationtime != (const qsc_x509_time*)NULL)
    {
        if (qsc_x509_time_compare(validationtime, &crl->thisupdate) < 0)
        {
            res = QSC_X509_REVOCATION_STATUS_CRL_EXPIRED;
        }
        else if (crl->nextupdate_present == true && qsc_x509_time_compare(validationtime, &crl->nextupdate) > 0)
        {
            res = QSC_X509_REVOCATION_STATUS_CRL_EXPIRED;
        }
    }

    return res;
}

void qsc_x509_revocation_options_initialize(qsc_x509_revocation_options* options)
{
    if (options != (qsc_x509_revocation_options*)NULL)
    {
        qsc_memutils_clear((uint8_t*)options, sizeof(qsc_x509_revocation_options));
        options->mode = QSC_X509_REVOCATION_MODE_NONE;
    }
}

qsc_x509_revocation_status qsc_x509_certificate_check_revocation_with_crl(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, 
    const qsc_x509_crl* crl, qsc_x509_crl_signature_verify_callback verifycallback, void* verifycontext, const qsc_x509_time* validationtime)
{
    qsc_x509_revocation_status revstatus;
    qsc_x509_crl_verify_status vstatus;

    revstatus = QSC_X509_REVOCATION_STATUS_ERROR;
    vstatus = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;

    if (certificate == NULL || issuer == NULL)
    {
        revstatus = QSC_X509_REVOCATION_STATUS_ERROR;
    }
    else if (crl == NULL)
    {
        revstatus = QSC_X509_REVOCATION_STATUS_CRL_NOT_FOUND;
    }
    else
    {
        revstatus = x509_check_crl_baseline(crl, issuer, validationtime);

        if (revstatus == QSC_X509_REVOCATION_STATUS_GOOD && verifycallback != (qsc_x509_crl_signature_verify_callback)NULL)
        {
            vstatus = qsc_x509_crl_verify(crl, issuer, validationtime, verifycallback, verifycontext);
            revstatus = x509_map_crl_verify_status(vstatus);
        }

        if (revstatus == QSC_X509_REVOCATION_STATUS_GOOD)
        {
            if (qsc_x509_certificate_is_revoked_by_crl(certificate, crl) == true)
            {
                revstatus = QSC_X509_REVOCATION_STATUS_REVOKED;
            }
        }
    }

    return revstatus;
}

qsc_x509_revocation_status qsc_x509_certificate_check_revocation(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, 
    const qsc_x509_revocation_options* options, const qsc_x509_time* validationtime)
{
    qsc_x509_crl* basecrl;
    qsc_x509_crl* deltacrl;
    qsc_x509_crl* mergedcrl;
    qsc_asn1_status status;
    qsc_x509_crl_verify_status mstatus;
    qsc_x509_revocation_status revstatus;
    bool deltaavailable;

    basecrl = (qsc_x509_crl*)NULL;
    deltacrl = (qsc_x509_crl*)NULL;
    mergedcrl = (qsc_x509_crl*)NULL;
    deltaavailable = false;
    revstatus = QSC_X509_REVOCATION_STATUS_ERROR;
    status = QSC_ASN1_STATUS_FAILURE;
    mstatus = QSC_X509_CRL_VERIFY_STATUS_INVALID_INPUT;

    if (certificate == (const qsc_x509_certificate*)NULL || issuer == (const qsc_x509_certificate*)NULL)
    {
        revstatus = QSC_X509_REVOCATION_STATUS_ERROR;
    }
    else if (options == (const qsc_x509_revocation_options*)NULL || options->mode == QSC_X509_REVOCATION_MODE_NONE)
    {
        revstatus = QSC_X509_REVOCATION_STATUS_UNCHECKED;
    }
    else
    {
        basecrl = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));

        if (basecrl == (qsc_x509_crl*)NULL)
        {
            revstatus = QSC_X509_REVOCATION_STATUS_ERROR;
        }
        else
        {
            qsc_memutils_clear((uint8_t*)basecrl, sizeof(qsc_x509_crl));

            if (options->deltaresolver != (qsc_x509_delta_crl_resolver_callback)NULL)
            {
                deltacrl = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));
                mergedcrl = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));

                if (deltacrl != (qsc_x509_crl*)NULL && mergedcrl != (qsc_x509_crl*)NULL)
                {
                    qsc_memutils_clear((uint8_t*)deltacrl, sizeof(qsc_x509_crl));
                    qsc_memutils_clear((uint8_t*)mergedcrl, sizeof(qsc_x509_crl));
                    status = options->deltaresolver(certificate, issuer, basecrl, deltacrl, &deltaavailable, options->deltaresolvercontext);

                    if (status == QSC_ASN1_STATUS_SUCCESS)
                    {
                        if (deltaavailable == true)
                        {
                            mstatus = qsc_x509_apply_delta_crl(mergedcrl, basecrl, deltacrl, issuer, validationtime, options->verifycallback, options->verifycontext);

                            if (mstatus == QSC_X509_CRL_VERIFY_STATUS_SUCCESS)
                            {
                                revstatus = qsc_x509_certificate_check_revocation_with_crl(certificate, issuer, mergedcrl,
                                    options->verifycallback, options->verifycontext, validationtime);
                            }
                            else
                            {
                                revstatus = x509_map_crl_verify_status(mstatus);
                            }
                        }
                        else
                        {
                            revstatus = qsc_x509_certificate_check_revocation_with_crl(certificate, issuer, basecrl,
                                options->verifycallback, options->verifycontext, validationtime);
                        }
                    }
                }
            }

            if (revstatus == QSC_X509_REVOCATION_STATUS_ERROR && options->resolver != (qsc_x509_crl_resolver_callback)NULL)
            {
                status = options->resolver(certificate, issuer, basecrl, options->resolvercontext);

                if (status != QSC_ASN1_STATUS_SUCCESS)
                {
                    revstatus = QSC_X509_REVOCATION_STATUS_CRL_NOT_FOUND;
                }
                else
                {
                    revstatus = qsc_x509_certificate_check_revocation_with_crl(certificate, issuer, basecrl,
                        options->verifycallback, options->verifycontext, validationtime);
                }
            }
            else if (revstatus == QSC_X509_REVOCATION_STATUS_ERROR)
            {
                revstatus = QSC_X509_REVOCATION_STATUS_CRL_NOT_FOUND;
            }
        }
    }

    if (mergedcrl != (qsc_x509_crl*)NULL)
    {
        qsc_x509_crl_clear(mergedcrl);
        qsc_memutils_alloc_free(mergedcrl);
    }

    if (deltacrl != (qsc_x509_crl*)NULL)
    {
        qsc_x509_crl_clear(deltacrl);
        qsc_memutils_alloc_free(deltacrl);
    }

    if (basecrl != (qsc_x509_crl*)NULL)
    {
        qsc_x509_crl_clear(basecrl);
        qsc_memutils_alloc_free(basecrl);
    }

    return revstatus;
}
