#include "x509_stage1_tests.h"
#include "../testutils.h"
#include "x509_test_helper.h"
#include "encoding.h"
#include "fileutils.h"
#include "memutils.h"
#include "timestamp.h"
#include "x509pem.h"
#include "x509store.h"
#include "x509verify.h"
#include "x509host.h"
#include "x509sigver.h"
#include "x509crl.h"
#include "x509rev.h"

#define TESTBUF 32768U
#define PEMBUF QSC_X509_PEM_DER_MAX
#define MAX_CHAIN_CERTS 8U
#define MAX_ANCHORS 8U

static const char CLIENT_CHAIN_PATH[] = "X509/Vectors/Stage1/client_chain.pem";
static const char SERVER_CHAIN_PATH[] = "X509/Vectors/Stage1/server_chain.pem";
static const char SERVER_ROOTS_PATH[] = "X509/Vectors/Stage1/trust_roots.pem";
static const char SERVER_INTMD_PATH[] = "X509/Vectors/Stage1/intermediate.crl.pem";
static const char RCHAIN_PEM_PATH[] = "X509/Vectors/Stage1/revoked_chain.pem";

static int32_t load_chain_and_store(const char* chain_path, const char* store_path,
	qsc_x509_certificate* certs, qsc_x509_chain* chain, qsc_x509_trust_anchor* anchors, qsc_x509_store* store)
{
	char* chain_pem;
	char* store_pem;
	size_t chain_len;
	size_t store_len;
	int32_t res;

	res = 0;
	chain_pem = qsctest_x509_read_text_file(chain_path, &chain_len);
	store_pem = qsctest_x509_read_text_file(store_path, &store_len);

	if (chain_pem != NULL && store_pem != NULL)
	{
		if (qsc_x509_chain_decode_pem_bundle(chain_pem, chain_len, certs, MAX_CHAIN_CERTS, chain) == QSC_ASN1_STATUS_SUCCESS)
		{
			if (qsc_x509_store_load_pem_bundle(store_pem, store_len, anchors, MAX_ANCHORS, store) == QSC_ASN1_STATUS_SUCCESS)
			{
				res = 1;
			}
		}
	}

	qsc_memutils_alloc_free(chain_pem);
	qsc_memutils_alloc_free(store_pem);

	return res;
}

static int32_t load_crl_pem(const char* crl_path, qsc_x509_crl* crl)
{
	uint8_t der[PEMBUF] = { 0U };
	char* pem;
	size_t derlen;
	size_t pemlen;
	int32_t res;

	res = 0;
	pem = qsctest_x509_read_text_file(crl_path, &pemlen);

	if (pem != NULL)
	{
		derlen = 0U;

		if (qsc_encoding_pem_decode(pem, pemlen, der, sizeof(der), &derlen) == true)
		{
			res = (qsc_x509_crl_decode_der(der, derlen, crl) == QSC_ASN1_STATUS_SUCCESS);
		}
	}

	qsc_memutils_alloc_free(pem);

	return res;
}

bool x509_stage1_dns_matcher(void)
{
	const char* name = "x509_stage1_dns_matcher";
	bool res;

	res = false;

	if (qsc_x509_dns_name_match("*.example.com", "www.example.com") == true)
	{
		if (qsc_x509_dns_name_match("*.example.com", "a.b.example.com") == false)
		{
			if (qsc_x509_dns_name_match("*.xn--example.com", "www.xn--example.com") == true)
			{
				res = true;
			}
		}
	}

	return res;
}

bool x509_stage1_server_chain_verify(void)
{
	const char* name = "x509_stage1_server_chain_verify";
	qsc_x509_certificate* certs;
	qsc_x509_trust_anchor* anchors;
	qsc_x509_chain chain = { 0 };
	qsc_x509_store store = { 0 };
	qsc_x509_verify_state vstate = { 0 };
	qsc_asn1_time now = { 0 };
	qsc_x509_verify_options options = { 0 };
	uint8_t verifybuf[TESTBUF] = { 0U };
	qsc_x509_verify_status st;
	bool res;

	res = false;
	certs = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
	anchors = (qsc_x509_trust_anchor*)qsc_memutils_malloc(sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);

	if (certs != NULL && anchors != NULL)
	{
		qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);

		if (load_chain_and_store(SERVER_CHAIN_PATH, SERVER_ROOTS_PATH, certs, &chain, anchors, &store) != 0)
		{
			qsctest_x509_current_time(&now);
			qsc_x509_qsc_verify_state_initialize(&vstate, verifybuf, sizeof(verifybuf));
			qsc_x509_verify_options_initialize(&options);
			options.purpose = QSC_X509_VERIFY_PURPOSE_TLS_SERVER;
			options.rejectunsupportedcriticalextensions = true;

			st = qsc_x509_chain_verify_ex(&chain, &store, &now, qsc_x509_qsc_signature_verify, &vstate, &options);

			if (st == QSC_X509_VERIFY_STATUS_SUCCESS)
			{
				st = qsc_x509_certificate_check_hostname(&chain.certificates[0], "server.example.test");

				if (st == QSC_X509_VERIFY_STATUS_SUCCESS)
				{
					st = qsc_x509_certificate_check_hostname(&chain.certificates[0], "wrong.example.test");

					if (st == QSC_X509_VERIFY_STATUS_NAME_MISMATCH)
					{
						res = true;
					}
				}
			}
		}
	}

	qsc_x509_chain_free(&chain);
	qsc_x509_store_free(&store);

	if (certs != NULL)
	{
		qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
		qsc_memutils_alloc_free(certs);
	}

	if (anchors != NULL)
	{
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);
		qsc_memutils_alloc_free(anchors);
	}

	return res;
}

bool x509_stage1_client_purpose_rejection(void)
{
	const char* name = "x509_stage1_client_purpose_rejection";
	qsc_x509_certificate* certs;
	qsc_x509_trust_anchor* anchors;
	qsc_x509_chain chain = { 0 };
	qsc_x509_store store = { 0 };
	qsc_x509_verify_state vstate = { 0 };
	qsc_asn1_time tnow = { 0 };
	qsc_x509_verify_options options = { 0 };
	uint8_t verifybuf[TESTBUF] = { 0U };
	qsc_x509_verify_status st;
	bool res;

	res = false;
	certs = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
	anchors = (qsc_x509_trust_anchor*)qsc_memutils_malloc(sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);

	if (certs != NULL && anchors != NULL)
	{
		qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);

		if (load_chain_and_store(CLIENT_CHAIN_PATH, SERVER_ROOTS_PATH, certs, &chain, anchors, &store) != 0)
		{
			qsctest_x509_current_time(&tnow);
			qsc_x509_qsc_verify_state_initialize(&vstate, verifybuf, sizeof(verifybuf));
			qsc_x509_verify_options_initialize(&options);
			options.purpose = QSC_X509_VERIFY_PURPOSE_TLS_SERVER;
			options.rejectunsupportedcriticalextensions = true;

			st = qsc_x509_chain_verify_ex(&chain, &store, &tnow, qsc_x509_qsc_signature_verify, &vstate, &options);

			if (st == QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED)
			{
				res = true;
			}
		}
	}

	qsc_x509_chain_free(&chain);
	qsc_x509_store_free(&store);

	if (certs != NULL)
	{
		qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
		qsc_memutils_alloc_free(certs);
	}

	if (anchors != NULL)
	{
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);
		qsc_memutils_alloc_free(anchors);
	}

	return res;
}

bool x509_stage1_crl_revocation(void)
{
	const char* name = "x509_stage1_crl_revocation";
	qsc_x509_certificate* certs;
	qsc_x509_trust_anchor* anchors;
	qsc_x509_crl* crl;
	qsc_x509_chain chain = { 0 };
	qsc_x509_store store = { 0 };
	qsc_asn1_time tnow = { 0 };
	qsc_x509_revocation_status rst = { 0 };
	qsc_x509_verify_state vstate = { 0 };
	uint8_t verifybuf[TESTBUF] = { 0U };
	bool res;

	res = false;
	certs = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
	anchors = (qsc_x509_trust_anchor*)qsc_memutils_malloc(sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);
	crl = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));

	if (certs != NULL && anchors != NULL && crl != NULL)
	{
		qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));

		if (load_chain_and_store(RCHAIN_PEM_PATH, SERVER_ROOTS_PATH, certs, &chain, anchors, &store) != 0)
		{
			if (load_crl_pem(SERVER_INTMD_PATH, crl) != 0)
			{
				qsctest_x509_current_time(&tnow);
				qsc_x509_qsc_verify_state_initialize(&vstate, verifybuf, sizeof(verifybuf));

				if (chain.certificates != NULL)
				{
					rst = qsc_x509_certificate_check_revocation_with_crl(&chain.certificates[0], &chain.certificates[1], crl,
						qsc_x509_qsc_crl_signature_verify, &vstate, &tnow);

					if (rst == QSC_X509_REVOCATION_STATUS_REVOKED)
					{
						res = true;
					}
				}
			}
		}
	}

	if (crl != NULL)
	{
		qsc_x509_crl_clear(crl);
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));
		qsc_memutils_alloc_free(crl);
	}

	qsc_x509_chain_free(&chain);
	qsc_x509_store_free(&store);

	if (certs != NULL)
	{
		qsc_memutils_clear(certs, sizeof(qsc_x509_certificate) * MAX_CHAIN_CERTS);
		qsc_memutils_alloc_free(certs);
	}

	if (anchors != NULL)
	{
		qsc_memutils_clear(anchors, sizeof(qsc_x509_trust_anchor) * MAX_ANCHORS);
		qsc_memutils_alloc_free(anchors);
	}

	return res;
}

bool qsctest_x509_stage1_tests(void)
{
	bool res;

	res = true;

	if (x509_stage1_dns_matcher() == true)
	{
		qsctest_print_line("[PASS] DNS matching test.");
	}
	else
	{
		qsctest_print_line("[FAIL] DNS matching test.");
		res = false;
	}

	if (x509_stage1_server_chain_verify() == true)
	{
		qsctest_print_line("[PASS] Server chain test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Server chain test.");
		res = false;
	}

	if (x509_stage1_client_purpose_rejection() == true)
	{
		qsctest_print_line("[PASS] Client rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Client rejection test.");
		res = false;
	}

	return res;
}
