#include "tls_stage29_negative_x509_tests.h"
#include "../testutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "x509host.h"
#include "x509types.h"
#include "x509verify.h"

static void stage29_set_dns_name(qsc_x509_general_name* name, const char* dnsname)
{
    size_t nlen;

    qsc_memutils_clear(name, sizeof(qsc_x509_general_name));
    nlen = qsc_stringutils_string_size(dnsname);

    name->type = QSC_X509_GENERAL_NAME_DNS_NAME;
    name->length = nlen;
    qsc_memutils_copy(name->data, (const uint8_t*)dnsname, nlen);
    name->data[nlen] = 0U;
}

static void stage29_set_common_name(qsc_x509_certificate* cert, const char* commonname)
{
    size_t nlen;

    nlen = qsc_stringutils_string_size(commonname);
    cert->subject.count = 1U;
    cert->subject.attributes[0U].type = QSC_X509_NAME_ATTRIBUTE_COMMON_NAME;
    cert->subject.attributes[0U].length = nlen;
    qsc_memutils_copy(cert->subject.attributes[0U].value, commonname, nlen);
    cert->subject.attributes[0U].value[nlen] = '\0';
}

static void stage29_make_server_leaf(qsc_x509_certificate* cert)
{
    qsc_memutils_clear(cert, sizeof(qsc_x509_certificate));

    cert->version = 3U;
    cert->extensions.decoded = true;
    cert->extensions.basicconstraints.present = true;
    cert->extensions.basicconstraints.critical = true;
    cert->extensions.basicconstraints.ca = false;
    cert->extensions.keyusage.present = true;
    cert->extensions.keyusage.critical = true;
    cert->extensions.keyusage.bits = QSC_X509_KEY_USAGE_DIGITAL_SIGNATURE;
    cert->extensions.extendedkeyusage.present = true;
    cert->extensions.extendedkeyusage.bits = QSC_X509_EXTENDED_KEY_USAGE_SERVER_AUTH;
    cert->extensions.subjectaltname.present = true;
    cert->extensions.subjectaltname.count = 1U;
    stage29_set_dns_name(&cert->extensions.subjectaltname.entries[0U], "localhost");
    stage29_set_common_name(cert, "unused.example.test");
}

static bool stage29_valid_server_leaf_purpose_test(void)
{
    qsc_x509_certificate cert;
    bool res;

    stage29_make_server_leaf(&cert);

    res = (qsc_x509_certificate_check_purpose(&cert, QSC_X509_VERIFY_PURPOSE_TLS_SERVER) == QSC_X509_VERIFY_STATUS_SUCCESS);
    res = (res == true && qsc_x509_certificate_allows_server_auth(&cert) == true);
    res = (res == true && qsc_x509_certificate_check_hostname(&cert, "localhost") == QSC_X509_VERIFY_STATUS_SUCCESS);

    return res;
}

static bool stage29_leaf_ca_true_rejection_test(void)
{
    qsc_x509_certificate cert;
    bool res;

    stage29_make_server_leaf(&cert);
    cert.extensions.basicconstraints.ca = true;

    res = (qsc_x509_certificate_check_purpose(&cert, QSC_X509_VERIFY_PURPOSE_TLS_SERVER) == QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED);
    res = (res == true && qsc_x509_certificate_check_purpose(&cert, QSC_X509_VERIFY_PURPOSE_TLS_CLIENT) == QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED);

    return res;
}

static bool stage29_server_eku_rejection_test(void)
{
    qsc_x509_certificate cert;
    bool res;

    stage29_make_server_leaf(&cert);
    cert.extensions.extendedkeyusage.bits = QSC_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH;

    res = (qsc_x509_certificate_allows_server_auth(&cert) == false);
    res = (res == true && qsc_x509_certificate_check_purpose(&cert, QSC_X509_VERIFY_PURPOSE_TLS_SERVER) == QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED);
    res = (res == true && qsc_x509_certificate_check_purpose(&cert, QSC_X509_VERIFY_PURPOSE_TLS_CLIENT) == QSC_X509_VERIFY_STATUS_SUCCESS);

    return res;
}

static bool stage29_client_eku_rejection_test(void)
{
    qsc_x509_certificate cert;
    bool res;

    stage29_make_server_leaf(&cert);

    res = (qsc_x509_certificate_allows_client_auth(&cert) == false);
    res = (res == true && qsc_x509_certificate_check_purpose(&cert, QSC_X509_VERIFY_PURPOSE_TLS_CLIENT) == QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED);

    return res;
}

static bool stage29_key_usage_rejection_test(void)
{
    qsc_x509_certificate cert;
    bool res;

    stage29_make_server_leaf(&cert);
    cert.extensions.keyusage.bits = QSC_X509_KEY_USAGE_CRL_SIGN;

    res = (qsc_x509_certificate_allows_server_auth(&cert) == false);
    res = (res == true && qsc_x509_certificate_check_purpose(&cert, QSC_X509_VERIFY_PURPOSE_TLS_SERVER) == QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED);

    cert.extensions.extendedkeyusage.bits = QSC_X509_EXTENDED_KEY_USAGE_CLIENT_AUTH;
    res = (res == true && qsc_x509_certificate_allows_client_auth(&cert) == false);
    res = (res == true && qsc_x509_certificate_check_purpose(&cert, QSC_X509_VERIFY_PURPOSE_TLS_CLIENT) == QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED);

    return res;
}

static bool stage29_hostname_mismatch_test(void)
{
    qsc_x509_certificate cert;
    bool res;

    stage29_make_server_leaf(&cert);

    res = (qsc_x509_certificate_check_hostname(&cert, "localhost") == QSC_X509_VERIFY_STATUS_SUCCESS);
    res = (res == true && qsc_x509_certificate_check_hostname(&cert, "example.com") == QSC_X509_VERIFY_STATUS_NAME_MISMATCH);

    return res;
}

static bool stage29_san_precedence_over_common_name_test(void)
{
    qsc_x509_certificate cert;
    bool res;

    stage29_make_server_leaf(&cert);
    stage29_set_common_name(&cert, "example.com");

    res = (qsc_x509_certificate_check_hostname(&cert, "localhost") == QSC_X509_VERIFY_STATUS_SUCCESS);
    res = (res == true && qsc_x509_certificate_check_hostname(&cert, "example.com") == QSC_X509_VERIFY_STATUS_NAME_MISMATCH);

    cert.extensions.subjectaltname.present = false;
    cert.extensions.subjectaltname.count = 0U;
    res = (res == true && qsc_x509_certificate_check_hostname(&cert, "example.com") == QSC_X509_VERIFY_STATUS_NAME_MISMATCH);

    return res;
}

static bool stage29_invalid_input_rejection_test(void)
{
    qsc_x509_certificate cert;
    bool res;

    stage29_make_server_leaf(&cert);

    res = (qsc_x509_certificate_check_purpose(NULL, QSC_X509_VERIFY_PURPOSE_TLS_SERVER) == QSC_X509_VERIFY_STATUS_INVALID_INPUT);
    res = (res == true && qsc_x509_certificate_check_hostname(NULL, "localhost") == QSC_X509_VERIFY_STATUS_INVALID_INPUT);
    res = (res == true && qsc_x509_certificate_check_hostname(&cert, NULL) == QSC_X509_VERIFY_STATUS_INVALID_INPUT);
    res = (res == true && qsc_x509_certificate_check_hostname(&cert, "") == QSC_X509_VERIFY_STATUS_INVALID_INPUT);

    return res;
}

bool qsctest_tls_stage29_tests(void)
{
    bool res;

    res = true;

    if (stage29_valid_server_leaf_purpose_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 29 valid server leaf purpose test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 29 valid server leaf purpose test.");
        res = false;
    }

    if (stage29_leaf_ca_true_rejection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 29 leaf CA true rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 29 leaf CA true rejection test.");
        res = false;
    }

    if (stage29_server_eku_rejection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 29 server EKU rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 29 server EKU rejection test.");
        res = false;
    }

    if (stage29_client_eku_rejection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 29 client EKU rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 29 client EKU rejection test.");
        res = false;
    }

    if (stage29_key_usage_rejection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 29 key-usage rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 29 key-usage rejection test.");
        res = false;
    }

    if (stage29_hostname_mismatch_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 29 hostname mismatch test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 29 hostname mismatch test.");
        res = false;
    }

    if (stage29_san_precedence_over_common_name_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 29 SAN precedence over common-name test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 29 SAN precedence over common-name test.");
        res = false;
    }

    if (stage29_invalid_input_rejection_test() == true)
    {
        qsctest_print_line("[PASS] TLS Stage 29 invalid-input rejection test.");
    }
    else
    {
        qsctest_print_line("[FAIL] TLS Stage 29 invalid-input rejection test.");
        res = false;
    }

    return res;
}
