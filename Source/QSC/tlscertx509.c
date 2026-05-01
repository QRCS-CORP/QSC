#include "tlscertx509.h"
#include "tlslimits.h"
#include "tlssignerdefault.h"
#include "tlssigalgs.h"
#include "memutils.h"
#include "timestamp.h"
#include "x509cert.h"
#include "x509verify.h"
#include "x509sigver.h"
#include "x509time.h"
#include "x509store.h"

/* tlscertx509.c default X.509-backed TLS certificate interface.
 * Full RFC 5280 path validation (trust-store walk, intermediate signatures,
 * AKI/SKI threading, revocation) is available through the existing
 * qsc_x509_chain_verify API; wiring it through this interface requires
 * constructing a qsc_x509_chain from the TLS views and supplying a per-chain
 * signature-verify callback. That's a larger integration and is left to a
 * later iteration; this MVP covers the leaf-centric cases that account for
 * the vast majority of TLS deployments (pinned leaves, self-signed test
 * certs, and stacks that delegate path validation to OS trust stores).
 */

static void tls_cert_x509_time_now_from_epoch(qsc_x509_time* out)
{
    /* build a qsc_x509_time (aliased to qsc_asn1_time) from the current UTC epoch. */
    uint64_t epoch;
    uint64_t secs_per_day;
    uint64_t days;
    uint64_t secs_in_day;
    uint32_t year;
    uint32_t month;
    uint32_t day;
    uint32_t hour;
    uint32_t minute;
    uint32_t second;
    uint32_t days_in_month;
    bool leap;

    qsc_memutils_clear(out, sizeof(*out));

    epoch = (uint64_t)qsc_timestamp_epochtime_seconds();
    secs_per_day = 86400ULL;
    days = epoch / secs_per_day;
    secs_in_day = epoch % secs_per_day;

    hour = (uint32_t)(secs_in_day / 3600ULL);
    minute = (uint32_t)((secs_in_day % 3600ULL) / 60ULL);
    second = (uint32_t)(secs_in_day % 60ULL);

    /* civil-from-days algorithm (Howard Hinnant, public domain), adapted and
     * rounded to the Gregorian year range. Epoch 1970-01-01 is civil days 0. */
    {
        int64_t z = (int64_t)days + 719468;
        int64_t era = (z >= 0 ? z : z - 146096) / 146097;
        uint64_t doe = (uint64_t)(z - era * 146097);
        uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        int64_t y = (int64_t)yoe + era * 400;
        uint64_t doy = doe - (365U * yoe + yoe / 4U - yoe / 100U);
        uint64_t mp  = (5U * doy + 2U) / 153U;
        uint32_t d   = (uint32_t)(doy - (153U*mp + 2U) / 5U + 1U);
        uint32_t m   = (uint32_t)(mp < 10U ? mp + 3U : mp - 9U);
        y += (m <= 2U) ? 1 : 0;
        year = (uint32_t)y;
        month = m;
        day = d;
    }

    (void)days_in_month;
    (void)leap;

    out->year = (uint16_t)year;
    out->month = (uint8_t)month;
    out->day = (uint8_t)day;
    out->hour = (uint8_t)hour;
    out->minute = (uint8_t)minute;
    out->second = (uint8_t)second;
    out->generalized = (year >= 2050U || year < 1950U);
}


static bool tls_cert_x509_spki_to_signer_key(const qsc_x509_subject_public_key_info* spki, qsc_tls_signature_scheme scheme, const uint8_t** outkey, size_t* outkeylen)
{
    /* map a raw SPKI BIT STRING payload to the effective public key bytes the signer expects for a given TLS scheme. */
    bool res;

    res = false;

    if (spki != NULL && spki->publickeylen != 0U && outkey != NULL && outkeylen != NULL)
    {
        switch (scheme)
        {
            case qsc_tls_sig_ed25519:
            {
                if (spki->publickeylen == 32U)
                {
                    *outkey = spki->publickey;
                    *outkeylen = 32U;
                    res = true;
                }

                break;
            }
            case qsc_tls_sig_ecdsa_secp256r1_sha256:
            {
                /* uncompressed EC point: 0x04 || X(32) || Y(32). Signer wants X||Y. */
                if (spki->publickeylen == 65U && spki->publickey[0U] == 0x04U)
                {
                    *outkey = spki->publickey + 1U;
                    *outkeylen = 64U;
                    res = true;
                }

                break;
            }
            case qsc_tls_sig_ecdsa_secp384r1_sha384:
            {
                if (spki->publickeylen == 97U && spki->publickey[0U] == 0x04U)
                {
                    *outkey = spki->publickey + 1U;
                    *outkeylen = 96U;
                    res = true;
                }

                break;
            }
            case qsc_tls_sig_mldsa44:
            case qsc_tls_sig_mldsa65:
            case qsc_tls_sig_mldsa87:
            {
                /* ML-DSA public key is the BIT STRING payload verbatim. */
                *outkey = spki->publickey;
                *outkeylen = spki->publickeylen;
                res = true;

                break;
            }
            default:
            {
                res = false;
                break;
            }
        }
    }

    return res;
}

static bool tls_cert_x509_validate_chain_cb(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* context, void* state)
{
    bool res;
    qsc_tls_cert_x509_state* xstate;
    qsc_x509_certificate leaf;
    qsc_x509_verify_status vs;

    xstate = (qsc_tls_cert_x509_state*)state;
    res = false;

    if (xstate == NULL || chain == NULL || chainlength == 0U || chain[0U].data == NULL)
    {
        if (xstate != NULL)
        {
            xstate->lastverifystatus = QSC_X509_VERIFY_STATUS_INVALID_INPUT;
            xstate->lastalert = qsc_tls_alert_bad_certificate;
        }
    }
    else
    {
        qsc_memutils_clear(&leaf, sizeof(leaf));

        if (qsc_x509_certificate_decode_der(chain[0U].data, chain[0U].datalen, &leaf) != QSC_ASN1_STATUS_SUCCESS)
        {
            xstate->lastverifystatus = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
            xstate->lastalert = qsc_tls_alert_bad_certificate;
        }
        else
        {
            res = true;

            /* structural check. */
            vs = qsc_x509_certificate_check_structure(&leaf);

            if (vs != QSC_X509_VERIFY_STATUS_SUCCESS)
            {
                xstate->lastverifystatus = vs;
                xstate->lastalert = qsc_tls_alert_bad_certificate;
                res = false;
            }

            /* validity period. */
            if (res && xstate->enforcevalidityperiod)
            {
                qsc_x509_time now;
                tls_cert_x509_time_now_from_epoch(&now);
                vs = qsc_x509_certificate_check_validity(&leaf, &now);

                if (vs != QSC_X509_VERIFY_STATUS_SUCCESS)
                {
                    xstate->lastverifystatus = vs;
                    xstate->lastalert = (vs == QSC_X509_VERIFY_STATUS_EXPIRED)
                        ? qsc_tls_alert_certificate_expired
                        : qsc_tls_alert_bad_certificate;

                    res = false;
                }
            }

            /* hostname match. */
            if (res && xstate->enforcehostname && context != NULL && context->hostname != NULL)
            {
                vs = qsc_x509_certificate_check_hostname(&leaf, context->hostname);
                if (vs != QSC_X509_VERIFY_STATUS_SUCCESS)
                {
                    xstate->lastverifystatus = vs;
                    xstate->lastalert = qsc_tls_alert_bad_certificate;
                    res = false;
                }
            }

            /* Trust anchor / chain validation.
             *
             *   - No trust store + allowselfsigned: pinned-key/test mode (legacy MVP).
             *   - No trust store + !allowselfsigned: refuse (unknown_ca).
             *   - Trust store provided: run RFC 5280 chain validation via
             *     qsc_x509_chain_verify, including signatures, validity,
             *     issuer linkage, key identifiers, and termination at a
             *     configured trust anchor. The leaf hostname/validity have
             *     already been checked above; the chain walk re-checks them
             *     against each link.
             */
            if (res)
            {
                if (xstate->truststore == NULL)
                {
                    if (xstate->allowselfsigned)
                    {
                        xstate->lastverifystatus = QSC_X509_VERIFY_STATUS_SUCCESS;
                    }
                    else
                    {
                        xstate->lastverifystatus = QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND;
                        xstate->lastalert = qsc_tls_alert_unknown_ca;
                        res = false;
                    }
                }
                else
                {
                    /* build a qsc_x509_chain from the TLS views by decoding each
                     * DER blob in chainlen-order. The leaf is index 0; intermediates
                     * follow. We allocate the certificate array on stack with a small
                     * upper bound; the TLS interface caps chainlength at
                     * QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES. */
                    qsc_x509_certificate xchain[QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES] = { 0 };
                    size_t decoded;
                    bool decodeok;

                    decoded = 0U;
                    decodeok = true;

                    for (size_t i = 0U; i < chainlength && i < QSC_TLS_CERTIFICATE_LIST_MAX_ENTRIES; ++i)
                    {
                        qsc_memutils_clear(&xchain[i], sizeof(xchain[i]));
                        qsc_asn1_status as = qsc_x509_certificate_decode_der(chain[i].data, chain[i].datalen, &xchain[i]);
                        if (as != QSC_ASN1_STATUS_SUCCESS)
                        {
                            decodeok = false;
                            break;
                        }

                        ++decoded;
                    }

                    if (decodeok == false)
                    {
                        xstate->lastverifystatus = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
                        xstate->lastalert = qsc_tls_alert_bad_certificate;
                        res = false;
                    }
                    else
                    {
                        qsc_x509_chain xc;
                        qsc_x509_time now;

                        xc.certificates = xchain;
                        xc.count = decoded;
                        tls_cert_x509_time_now_from_epoch(&now);

                        /* qsc_x509_signature_verify is QSC's ready-made callback that
                         * dispatches signature verification on the issuer's SPKI for ed25519,
                         * ecdsa-p256/384, dilithium, etc. State buffer is unused (NULL). */
                        qsc_x509_verify_status vchain = qsc_x509_chain_verify(&xc, xstate->truststore, &now, qsc_x509_qsc_signature_verify, NULL);

                        xstate->lastverifystatus = vchain;
                        if (vchain == QSC_X509_VERIFY_STATUS_SUCCESS)
                        {
                            /* res stays true */
                        }
                        else
                        {
                            res = false;
                            switch (vchain)
                            {
                                case QSC_X509_VERIFY_STATUS_EXPIRED:
                                case QSC_X509_VERIFY_STATUS_NOT_YET_VALID:
                                {
                                    xstate->lastalert = qsc_tls_alert_certificate_expired;
                                    break;
                                }
                                case QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND:
                                case QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH:
                                case QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH:
                                case QSC_X509_VERIFY_STATUS_NOT_CA:
                                case QSC_X509_VERIFY_STATUS_PATH_LENGTH_EXCEEDED:
                                case QSC_X509_VERIFY_STATUS_CHAIN_LOOP:
                                {
                                    xstate->lastalert = qsc_tls_alert_unknown_ca;
                                    break;
                                }
                                case QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED:
                                {
                                    xstate->lastalert = qsc_tls_alert_decrypt_error;
                                    break;
                                }
                                case QSC_X509_VERIFY_STATUS_REVOKED:
                                {
                                    xstate->lastalert = qsc_tls_alert_certificate_revoked;
                                    break;
                                }
                                case QSC_X509_VERIFY_STATUS_NAME_MISMATCH:
                                case QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED:
                                case QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED:
                                {
                                    xstate->lastalert = qsc_tls_alert_bad_certificate;
                                    break;
                                }
                                case QSC_X509_VERIFY_STATUS_UNSUPPORTED:
                                case QSC_X509_VERIFY_STATUS_UNSUPPORTED_CRITICAL_EXTENSION:
                                case QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH:
                                {
                                    xstate->lastalert = qsc_tls_alert_unsupported_certificate;
                                    break;
                                }
                                default:
                                {
                                    xstate->lastalert = qsc_tls_alert_bad_certificate;
                                    break;
                                }
                            }
                        }

                        for (size_t i = 0U; i < decoded; ++i)
                        {
                            qsc_x509_certificate_clear(&xchain[i]);
                        }
                    }
                }
            }
        }

        qsc_x509_certificate_clear(&leaf);
    }

    return res;
}

static bool tls_cert_x509_verify_cv_cb(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, 
    size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    qsc_x509_certificate leaf = { 0 };
    qsc_tls_certificate_view view;
    qsc_tls_cert_x509_state* xstate;
    const uint8_t* pubkey;
    size_t pubkeylen;
    bool res;

    xstate = (qsc_tls_cert_x509_state*)state;
    res = false;

    if (signer != NULL && signer->data != NULL && signer->datalen != 0U && input != NULL && signature != NULL)
    {
        qsc_memutils_clear(&leaf, sizeof(leaf));

        if (qsc_x509_certificate_decode_der(signer->data, signer->datalen, &leaf) != QSC_ASN1_STATUS_SUCCESS)
        {
            if (xstate != NULL)
            {
                xstate->lastverifystatus = QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE;
                xstate->lastalert = qsc_tls_alert_bad_certificate;
            }
        }
        else
        {
            pubkey = NULL;
            pubkeylen = 0U;

            if (tls_cert_x509_spki_to_signer_key(&leaf.subjectpublickeyinfo, scheme, &pubkey, &pubkeylen))
            {
                view.data = pubkey;
                view.datalen = pubkeylen;

                res = qsc_tls_signer_default_verify(scheme, input, inputlen, signature, signaturelen, &view, NULL);

                if (!res && xstate != NULL)
                {
                    xstate->lastverifystatus = QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED;
                    xstate->lastalert = qsc_tls_alert_decrypt_error;
                }
            }
            else if (xstate != NULL)
            {
                xstate->lastverifystatus = QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH;
                xstate->lastalert = qsc_tls_alert_unsupported_certificate;
            }

            qsc_x509_certificate_clear(&leaf);
        }
    }

    return res;
}

void qsc_tls_cert_x509_state_initialize(qsc_tls_cert_x509_state* state, const qsc_x509_store* truststore)
{
    QSC_ASSERT(state != NULL);

    if (state != NULL)
    {
        qsc_memutils_clear(state, sizeof(*state));

        state->truststore = truststore;
        state->allowselfsigned = (truststore == NULL);
        state->enforcehostname = true;
        state->enforcevalidityperiod = true;
        state->lastverifystatus = QSC_X509_VERIFY_STATUS_SUCCESS;
        state->lastalert = qsc_tls_alert_close_notify; /* sentinel: no alert pending */
    }
}

void qsc_tls_cert_x509_bind(qsc_tls_certificate_interface* iface, qsc_tls_cert_x509_state* state)
{
    QSC_ASSERT(iface != NULL);
    QSC_ASSERT(state != NULL);

    if (iface != NULL && state != NULL)
    {
        iface->validatechain = tls_cert_x509_validate_chain_cb;
        iface->verifycertificateverify = tls_cert_x509_verify_cv_cb;
        iface->state = state;
    }
}
