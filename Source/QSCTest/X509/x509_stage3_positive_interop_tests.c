#include "x509_stage3_positive_interop_tests.h"
#include "../testutils.h"
#include "x509_test_helper.h"
#include "fileutils.h"
#include "memutils.h"
#include "timestamp.h"
#include "x509pem.h"
#include "x509store.h"
#include "x509verify.h"
#include "x509sigver.h"
#include "x509csr.h"
#include "x509crl.h"
#include "x509time.h"

#define QSCTEST_X509_STAGE3_VECTOR_DIR QSCTEST_X509_VECTOR_ROOT "/Stage3"
#define TESTBUF 32768U
#define MAX_CHAIN_CERTS 8U
#define MAX_ANCHORS 8U

static const char CCHAIN_PEM_PATH[] = "X509/Vectors/Stage3/openssl_client_chain.pem";
static const char GCRL_PEM_PATH[] = "X509/Vectors/Stage3/interop_good.crl.pem";
static const char IROOT_PEM_PATH[] = "X509/Vectors/Stage3/interop_root.cert.pem";
static const char SCERT_DER_PATH[] = "X509/Vectors/Stage3/interop_server.cert.der";
static const char SCHAIN_PEM_PATH[] = "X509/Vectors/Stage3/openssl_server_chain.pem";
static const char TROOTS_PEM_PATH[] = "X509/Vectors/Stage3/openssl_trust_roots.pem";
static const char VALID_CSR_PATH[] = "X509/Vectors/Stage3/interop_valid.csr.pem";

static bool load_chain_and_store(const char* chain_path, const char* store_path,
	qsc_x509_certificate* certs, qsc_x509_chain* chain, qsc_x509_trust_anchor* anchors, qsc_x509_store* store)
{
	char* chain_pem;
	char* store_pem;
	size_t chain_len;
	size_t store_len;
	bool res;

	res = false;
	chain_pem = qsctest_x509_read_text_file(chain_path, &chain_len);
	store_pem = qsctest_x509_read_text_file(store_path, &store_len);

	if (chain_pem != NULL && store_pem != NULL)
	{
		if (qsc_x509_chain_decode_pem_bundle(chain_pem, chain_len, certs, MAX_CHAIN_CERTS, chain) == QSC_ASN1_STATUS_SUCCESS)
		{
			res = (qsc_x509_store_load_pem_bundle(store_pem, store_len, anchors, MAX_ANCHORS, store) == QSC_ASN1_STATUS_SUCCESS);
		}

		qsc_memutils_alloc_free(chain_pem);
		qsc_memutils_alloc_free(store_pem);
	}

	return res;
}

static qsc_x509_verify_status run_verify(const char* chain_path, const char* trust_path,
	qsc_x509_verify_purpose purpose, const char* hostname)
{
	qsc_x509_certificate certs[MAX_CHAIN_CERTS] = { 0 };
	qsc_x509_trust_anchor anchors[MAX_ANCHORS] = { 0 };
	qsc_x509_chain chain = { 0 };
	qsc_x509_store store = { 0 };
	qsc_x509_verify_state vstate = { 0 };
	qsc_asn1_time tnow = { 0 };
	qsc_x509_verify_options options = { 0 };
	uint8_t verifybuf[TESTBUF] = { 0 };
	qsc_x509_verify_status st;

	st = QSC_X509_VERIFY_STATUS_INVALID_INPUT;

	if (load_chain_and_store(chain_path, trust_path, certs, &chain, anchors, &store) == true)
	{
		qsctest_x509_current_time(&tnow);
		qsc_x509_qsc_verify_state_initialize(&vstate, verifybuf, sizeof(verifybuf));
		qsc_x509_verify_options_initialize(&options);
		options.purpose = purpose;
		options.rejectunsupportedcriticalextensions = true;

		st = qsc_x509_chain_verify_ex(&chain, &store, &tnow, qsc_x509_qsc_signature_verify, &vstate, &options);

		if (st == QSC_X509_VERIFY_STATUS_SUCCESS && hostname != NULL)
		{
			st = qsc_x509_certificate_check_hostname(&chain.certificates[0], hostname);
		}
	}

	return st;
}

bool x509_stage3_openssl_server_chain_ok(void)
{
	qsc_x509_verify_status st = run_verify(SCHAIN_PEM_PATH,
		TROOTS_PEM_PATH,
		QSC_X509_VERIFY_PURPOSE_TLS_SERVER,
		"interop.example.test");

	return (st == QSC_X509_VERIFY_STATUS_SUCCESS);
}

bool x509_stage3_openssl_client_chain_ok(void)
{
	qsc_x509_verify_status st = run_verify(
		CCHAIN_PEM_PATH,
		TROOTS_PEM_PATH,
		QSC_X509_VERIFY_PURPOSE_TLS_CLIENT,
		"client.interop.example.test");

	return (st == QSC_X509_VERIFY_STATUS_SUCCESS);
}

bool x509_stage3_rfc5280_utctime_decode(void)
{
	qsc_asn1_time t;
	const uint8_t s[] = "491231235959Z";
	bool res;

	res = false;
	qsc_memutils_clear(&t, sizeof(t));

	if (qsc_x509_time_parse_utctime((const char*)s, sizeof(s) - 1U, &t) == true)
	{
		res = (t.year == 2049U && t.month == 12U && t.day == 31U &&
			t.hour == 23U && t.minute == 59U && t.second == 59U);
	}

	return res;
}

bool x509_stage3_rfc5280_generalizedtime_decode(void)
{
	qsc_asn1_time t;
	const uint8_t s[] = "20500101000000Z";
	bool res;

	res = false;
	qsc_memutils_clear(&t, sizeof(t));

	if (qsc_x509_time_parse_generalizedtime((const char*)s, sizeof(s) - 1U, &t) == true)
	{
		res = (t.year == 2050U && t.month == 1U && t.day == 1U &&
			t.hour == 0U && t.minute == 0U && t.second == 0U);
	}

	return res;
}

bool x509_stage3_csr_verify_known_good(void)
{
	qsc_x509_csr csr = { 0 };
	char* pem;
	size_t pemlen;
	bool res;

	res = false;
	pem = qsctest_x509_read_text_file(VALID_CSR_PATH, &pemlen);

	if (pem != NULL)
	{
		if (qsc_x509_csr_decode_pem(&csr, pem, pemlen) == QSC_ASN1_STATUS_SUCCESS)
		{
			res = qsc_x509_csr_verify(&csr);
		}

		qsc_memutils_alloc_free(pem);
	}

	return res;
}

bool x509_stage3_crl_verify_known_good(void)
{
	qsc_x509_crl crl = { 0 };
	qsc_x509_certificate issuer = { 0 };
	qsc_x509_verify_state vstate = { 0 };
	qsc_asn1_time now = { 0 };
	uint8_t verifybuf[TESTBUF] = { 0 };
	char* crlpem;
	char* issuerpem;
	size_t crlpemlen;
	size_t issuerpemlen;
	bool res;

	res = false;
	crlpem = qsctest_x509_read_text_file(GCRL_PEM_PATH, &crlpemlen);
	issuerpem = qsctest_x509_read_text_file(IROOT_PEM_PATH, &issuerpemlen);

	if (crlpem != NULL && issuerpem != NULL)
	{
		if (qsc_x509_crl_decode_pem(crlpem, crlpemlen, &crl) == QSC_ASN1_STATUS_SUCCESS &&
			qsc_x509_certificate_decode_pem(issuerpem, issuerpemlen, &issuer) == QSC_ASN1_STATUS_SUCCESS)
		{
			qsctest_x509_current_time(&now);
			qsc_x509_qsc_verify_state_initialize(&vstate, verifybuf, sizeof(verifybuf));

			/* NOTE: for the test ONLY, the test certificate could be expired, so we change the date/time to now */
			crl.nextupdate = now;

			res = (qsc_x509_crl_verify(&crl, &issuer, &now, qsc_x509_qsc_crl_signature_verify, &vstate) == QSC_X509_CRL_VERIFY_STATUS_SUCCESS);
		}

		qsc_memutils_alloc_free(crlpem);
		qsc_memutils_alloc_free(issuerpem);
	}

	return res;
}

bool x509_stage3_der_certificate_decode_known_good(void)
{
	qsc_x509_certificate cert = { 0 };
	uint8_t* der;
	size_t derlen;
	bool res;

	res = false;
	der = qsctest_x509_read_binary_file(SCERT_DER_PATH, &derlen);

	if (der != NULL)
	{
		res = (qsc_x509_certificate_decode_der(der, derlen, &cert) == QSC_ASN1_STATUS_SUCCESS);
		qsc_memutils_alloc_free(der);
	}

	return res;
}

bool qsctest_x509_stage3_positive_interop_tests(void)
{
	bool res;

	res = true;

	if (x509_stage3_openssl_server_chain_ok() == true)
	{
		qsctest_print_line("[PASS] OpenSSL server chain validation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] OpenSSL server chain validation test.");
		res = false;
	}

	if (x509_stage3_openssl_client_chain_ok() == true)
	{
		qsctest_print_line("[PASS] OpenSSL certificate chain validation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] OpenSSL certificate chain validation test.");
		res = false;
	}

	if (x509_stage3_rfc5280_utctime_decode() == true)
	{
		qsctest_print_line("[PASS] UTC time fields validation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] UTC time fields validation test.");
		res = false;
	}

	if (x509_stage3_rfc5280_generalizedtime_decode() == true)
	{
		qsctest_print_line("[PASS] Generalized time decode test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Generalized time decode test.");
		res = false;
	}

	if (x509_stage3_csr_verify_known_good() == true)
	{
		qsctest_print_line("[PASS] CSR known good certificate validation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSR known good certificate validation test.");
		res = false;
	}

	if (x509_stage3_crl_verify_known_good() == true)
	{
		qsctest_print_line("[PASS] CSR known good certificate revocation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSR known good certificate revocation test.");
		res = false;
	}

	if (x509_stage3_der_certificate_decode_known_good() == true)
	{
		qsctest_print_line("[PASS] DER known good validation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] DER known good validation test.");
		res = false;
	}

	return res;
}
