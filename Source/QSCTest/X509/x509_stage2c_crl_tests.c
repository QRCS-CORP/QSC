#include "x509_stage2c_crl_tests.h"
#include "../testutils.h"
#include "x509_test_helper.h"
#include "fileutils.h"
#include "memutils.h"
#include "x509cert.h"
#include "x509crl.h"
#include "x509crlwrite.h"
#include "x509pem.h"

static const char RCRL_DER_PATH[] = "X509/Vectors/Stage2C/revocation.crl.der";
static const char RCRL_PEM_PATH[] = "X509/Vectors/Stage2C/revocation.crl.pem";
static const char RCERT_PEM_PATH[] = "X509/Vectors/Stage2C/revoked.cert.pem";
static const char GCERT_PEM_PATH[] = "X509/Vectors/Stage2C/good.cert.pem";

static bool load_crl_pem(const char* path, qsc_x509_crl* crl)
{
	char* pem;
	size_t pemlen;
	bool res;

	res = false;
	pem = qsctest_x509_read_text_file(path, &pemlen);

	if (pem != NULL)
	{
		res = (qsc_x509_crl_decode_pem(pem, pemlen, crl) == QSC_ASN1_STATUS_SUCCESS);
		qsc_memutils_alloc_free(pem);
	}

	return res;
}

static bool load_crl_der(const char* path, qsc_x509_crl* crl)
{
	uint8_t* der;
	size_t derlen;
	bool res;

	res = false;
	der = qsctest_x509_read_binary_file(path, &derlen);

	if (der != NULL)
	{
		res = (qsc_x509_crl_decode_der(der, derlen, crl) == QSC_ASN1_STATUS_SUCCESS);
		qsc_memutils_alloc_free(der);
	}

	return res;
}

static bool load_cert_pem(const char* path, qsc_x509_certificate* cert)
{
	char* pem;
	size_t pemlen;
	bool res;

	res = false;
	pem = qsctest_x509_read_text_file(path, &pemlen);

	if (pem != NULL)
	{
		res = (qsc_x509_certificate_decode_pem(pem, pemlen, cert) == QSC_ASN1_STATUS_SUCCESS);
		qsc_memutils_alloc_free(pem);
	}

	return res;
}

bool x509_stage2c_crl_pem_decode(void)
{
	qsc_x509_crl* crl;
	bool res;

	crl = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));
	res = false;

	if (crl != NULL)
	{
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));
		res = load_crl_pem(RCRL_PEM_PATH, crl);
		qsc_x509_crl_clear(crl);
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));
		qsc_memutils_alloc_free(crl);
	}

	return res;
}

bool x509_stage2c_crl_der_decode(void)
{
	qsc_x509_crl* crl;
	bool res;

	crl = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));
	res = false;

	if (crl != NULL)
	{
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));
		res = load_crl_der(RCRL_DER_PATH, crl);
		qsc_x509_crl_clear(crl);
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));
		qsc_memutils_alloc_free(crl);
	}

	return res;
}

bool x509_stage2c_crl_pem_roundtrip(void)
{
	qsc_x509_crl* crl1;
	qsc_x509_crl* crl2;
	char pem[32768] = { 0 };
	size_t pemlen;
	bool res;

	res = false;
	crl1 = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));
	crl2 = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));

	if (crl1 != NULL && crl2 != NULL)
	{
		qsc_memutils_clear(crl1, sizeof(qsc_x509_crl));
		qsc_memutils_clear(crl2, sizeof(qsc_x509_crl));

		if (load_crl_pem(RCRL_PEM_PATH, crl1) == true)
		{
			pemlen = sizeof(pem);

			if (qsc_x509_crl_encode_pem(crl1, pem, &pemlen) == QSC_ASN1_STATUS_SUCCESS)
			{
				res = (qsc_x509_crl_decode_pem(pem, pemlen, crl2) == QSC_ASN1_STATUS_SUCCESS);
			}
		}
	}

	if (crl1 != NULL)
	{
		qsc_x509_crl_clear(crl1);
		qsc_memutils_clear(crl1, sizeof(qsc_x509_crl));
		qsc_memutils_alloc_free(crl1);
	}

	if (crl2 != NULL)
	{
		qsc_x509_crl_clear(crl2);
		qsc_memutils_clear(crl2, sizeof(qsc_x509_crl));
		qsc_memutils_alloc_free(crl2);
	}

	return res;
}

bool x509_stage2c_crl_der_roundtrip(void)
{
	qsc_x509_crl* crl1;
	qsc_x509_crl* crl2;
	uint8_t der[32768] = { 0U };
	size_t derlen;
	bool res;

	res = false;
	crl1 = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));
	crl2 = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));

	if (crl1 != NULL && crl2 != NULL)
	{
		qsc_memutils_clear(crl1, sizeof(qsc_x509_crl));
		qsc_memutils_clear(crl2, sizeof(qsc_x509_crl));

		if (load_crl_pem(RCRL_PEM_PATH, crl1) == true)
		{
			derlen = sizeof(der);

			if (qsc_x509_crl_encode_der(crl1, der, &derlen) == QSC_ASN1_STATUS_SUCCESS)
			{
				res = (qsc_x509_crl_decode_der(der, derlen, crl2) == QSC_ASN1_STATUS_SUCCESS);
			}
		}
	}

	if (crl1 != NULL)
	{
		qsc_x509_crl_clear(crl1);
		qsc_memutils_clear(crl1, sizeof(qsc_x509_crl));
		qsc_memutils_alloc_free(crl1);
	}

	if (crl2 != NULL)
	{
		qsc_x509_crl_clear(crl2);
		qsc_memutils_clear(crl2, sizeof(qsc_x509_crl));
		qsc_memutils_alloc_free(crl2);
	}

	return res;
}

bool x509_stage2c_crl_revoked_lookup(void)
{
	qsc_x509_crl* crl;
	qsc_x509_certificate cert = { 0 };
	bool res;

	crl = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));
	res = false;

	if (crl != NULL)
	{
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));

		if (load_crl_pem(RCRL_PEM_PATH, crl) == true)
		{
			if (load_cert_pem(RCERT_PEM_PATH, &cert) == true)
			{
				res = qsc_x509_crl_is_revoked(crl, &cert);
			}
		}

		qsc_x509_crl_clear(crl);
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));
		qsc_memutils_alloc_free(crl);
	}

	qsc_x509_certificate_clear(&cert);

	return res;
}

bool x509_stage2c_not_revoked_lookup(void)
{
	qsc_x509_crl* crl;
	qsc_x509_certificate cert = { 0 };
	bool res;

	crl = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));
	res = false;

	if (crl != NULL)
	{
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));

		if (load_crl_pem(RCRL_PEM_PATH, crl) == true)
		{
			if (load_cert_pem(GCERT_PEM_PATH, &cert) == true)
			{
				res = (qsc_x509_crl_is_revoked(crl, &cert) == false);
			}
		}

		qsc_x509_crl_clear(crl);
		qsc_memutils_clear(crl, sizeof(qsc_x509_crl));
		qsc_memutils_alloc_free(crl);
	}

	qsc_x509_certificate_clear(&cert);

	return res;
}

bool qsctest_x509_stage2c_crl_tests(void)
{
	bool res;

	res = true;

	if (x509_stage2c_crl_pem_decode() == true)
	{
		qsctest_print_line("[PASS] Decoding CRL in PEM format test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Decoding CRL in PEM format test.");
		res = false;
	}

	if (x509_stage2c_crl_der_decode() == true)
	{
		qsctest_print_line("[PASS] Decoding CRL in DER format test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Decoding CRL in DER format test.");
		res = false;
	}

	if (x509_stage2c_crl_pem_roundtrip() == true)
	{
		qsctest_print_line("[PASS] CRL PEM encoding round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] CRL PEM encoding round-trip test.");
		res = false;
	}

	if (x509_stage2c_crl_der_roundtrip() == true)
	{
		qsctest_print_line("[PASS] CRL DER encoding round-trip test.");
	}
	else
	{
		qsctest_print_line("[FAIL] CRL DER encoding round-trip test.");
		res = false;
	}

	if (x509_stage2c_crl_revoked_lookup() == true)
	{
		qsctest_print_line("[PASS] CRL revocation lookup test.");
	}
	else
	{
		qsctest_print_line("[FAIL] CRL revocation lookup test.");
		res = false;
	}

	if (x509_stage2c_not_revoked_lookup() == true)
	{
		qsctest_print_line("[PASS] CRL non-revoked lookup test.");
	}
	else
	{
		qsctest_print_line("[FAIL] CRL non-revoked lookup test.");
		res = false;
	}

	return res;
}
