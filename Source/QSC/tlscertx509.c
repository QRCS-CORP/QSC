#include "tlscertx509.h"
#include "memutils.h"
#include "timestamp.h"

/* tlscertx509.c compatibility adapter for the canonical QSC X.509 TLS bridge.
 * RFC 5280 path validation and TLS CertificateVerify verification are delegated
 * to tlscert.c so trust policy and signature handling have one implementation.
 * A missing trust store fails closed. */

static void tls_cert_x509_time_now_from_epoch(qsc_x509_time* output)
{
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

    qsc_memutils_clear(output, sizeof(*output));

    epoch = (uint64_t)qsc_timestamp_epochtime_seconds();
    secs_per_day = 86400ULL;
    days = epoch / secs_per_day;
    secs_in_day = epoch % secs_per_day;

    hour = (uint32_t)(secs_in_day / 3600ULL);
    minute = (uint32_t)((secs_in_day % 3600ULL) / 60ULL);
    second = (uint32_t)(secs_in_day % 60ULL);

    {
        int64_t z = (int64_t)days + 719468;
        int64_t era = (z >= 0 ? z : z - 146096) / 146097;
        uint64_t doe = (uint64_t)(z - era * 146097);
        uint64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        int64_t y = (int64_t)yoe + era * 400;
        uint64_t doy = doe - (365U * yoe + yoe / 4U - yoe / 100U);
        uint64_t mp = (5U * doy + 2U) / 153U;
        uint32_t d = (uint32_t)(doy - (153U * mp + 2U) / 5U + 1U);
        uint32_t m = (uint32_t)(mp < 10U ? mp + 3U : mp - 9U);
        y += (m <= 2U) ? 1 : 0;
        year = (uint32_t)y;
        month = m;
        day = d;
    }

    (void)days_in_month;
    (void)leap;

    output->year = (uint16_t)year;
    output->month = (uint8_t)month;
    output->day = (uint8_t)day;
    output->hour = (uint8_t)hour;
    output->minute = (uint8_t)minute;
    output->second = (uint8_t)second;
    output->generalized = (year >= 2050U || year < 1950U);
}

static void tls_cert_x509_copy_result(qsc_tls_cert_x509_state* state, const qsc_tls_qsc_x509_context* bridge)
{
    if (state != NULL && bridge != NULL)
    {
        state->lastverifystatus = bridge->lastverifystatus;
        state->lastalert = bridge->lastalert;
    }
}

static bool tls_cert_x509_validate_chain_cb(const qsc_tls_certificate_view* chain, size_t chainlength, const qsc_tls_certificate_validation_context* context, void* state)
{
    qsc_tls_certificate_validation_context validationcontext;
    qsc_tls_qsc_x509_context bridge;
    qsc_tls_cert_x509_state* xstate;
    qsc_x509_time now;
    qsc_tls_status status;
    bool res;

    xstate = (qsc_tls_cert_x509_state*)state;
    qsc_memutils_clear(&validationcontext, sizeof(validationcontext));
    qsc_memutils_clear(&bridge, sizeof(bridge));
    qsc_memutils_clear(&now, sizeof(now));
    status = qsc_tls_status_invalid_input;
    res = false;

    if (xstate != NULL && chain != NULL && chainlength != 0U && xstate->truststore != NULL)
    {
        if (context != NULL)
        {
            validationcontext = *context;
        }

        if (xstate->enforcehostname == false)
        {
            validationcontext.hostname = NULL;
        }

        tls_cert_x509_time_now_from_epoch(&now);
        status = qsc_tls_x509_context_initialize(&bridge, xstate->truststore, NULL, 0U, &now, NULL, 0U);

        if (status == qsc_tls_status_success)
        {
            res = qsc_tls_x509_validate_chain(chain, chainlength, &validationcontext, &bridge);
            tls_cert_x509_copy_result(xstate, &bridge);
        }
    }
    else if (xstate != NULL)
    {
        xstate->lastverifystatus = (xstate->truststore == NULL) ? QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND : QSC_X509_VERIFY_STATUS_INVALID_INPUT;
        xstate->lastalert = (xstate->truststore == NULL) ? qsc_tls_alert_unknown_ca : qsc_tls_alert_bad_certificate;
    }

    return res;
}

static bool tls_cert_x509_verify_cv_cb(qsc_tls_signature_scheme scheme, const uint8_t* input, size_t inputlen, const uint8_t* signature, size_t signaturelen, const qsc_tls_certificate_view* signer, void* state)
{
    qsc_tls_qsc_x509_context bridge;
    qsc_tls_cert_x509_state* xstate;
    qsc_x509_time now;
    qsc_tls_status status;
    bool res;

    xstate = (qsc_tls_cert_x509_state*)state;
    qsc_memutils_clear(&bridge, sizeof(bridge));
    qsc_memutils_clear(&now, sizeof(now));
    status = qsc_tls_status_invalid_input;
    res = false;

    if (xstate != NULL)
    {
        tls_cert_x509_time_now_from_epoch(&now);
        status = qsc_tls_x509_context_initialize(&bridge, xstate->truststore, NULL, 0U, &now, NULL, 0U);

        if (status == qsc_tls_status_success)
        {
            res = qsc_tls_x509_verify_certificate_verify(scheme, input, inputlen, signature, signaturelen, signer, &bridge);
            tls_cert_x509_copy_result(xstate, &bridge);
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
        state->allowselfsigned = false;
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
