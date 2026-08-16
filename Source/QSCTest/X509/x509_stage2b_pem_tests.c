#include "x509_stage2b_pem_tests.h"
#include "../testutils.h"
#include "x509_test_helper.h"
#include "encoding.h"
#include "fileutils.h"
#include "memutils.h"
#include "x509cert.h"
#include "x509certwrite.h"
#include "x509crlwrite.h"
#include "x509csr.h"
#include "x509crl.h"
#include "x509pem.h"

#define QSCTEST_X509_STAGE2B_PEM_BUFFER 32768U
#define QSCTEST_X509_STAGE2B_DER_BUFFER QSC_X509_PEM_DER_MAX

static const char CERT_PEM_PATH[] = "X509/Vectors/Stage2B/cert.pem";
static const char CSR_PEM_PATH[] = "X509/Vectors/Stage2B/csr.pem";
static const char CRL_PEM_PATH[] = "X509/Vectors/Stage2B/crl.pem";

static bool load_crl_from_pem_file(const char* path, qsc_x509_crl* crl)
{
	uint8_t der[QSCTEST_X509_STAGE2B_DER_BUFFER] = { 0U };
	char* pem;
	size_t pemlen;
	size_t derlen;
	bool res;

	res = false;

	pem = qsctest_x509_read_text_file(path, &pemlen);

	if (pem != NULL)
	{
		derlen = 0U;
		res = false;

		if (qsc_encoding_pem_decode(pem, pemlen, der, sizeof(der), &derlen) == true)
		{
			res = (qsc_x509_crl_decode_der(der, derlen, crl) == QSC_ASN1_STATUS_SUCCESS);
		}
	}

	qsc_memutils_alloc_free(pem);

	return res;
}

bool x509_stage2b_certificate_pem_roundtrip(void)
{
	qsc_x509_certificate* cert1;
	qsc_x509_certificate* cert2;
	uint8_t der[QSCTEST_X509_STAGE2B_DER_BUFFER] = { 0U };
	char outpem[QSCTEST_X509_STAGE2B_PEM_BUFFER] = { 0U };
	size_t derlen;
	size_t outpemlen;
	size_t pemlen;
	char* pem;
	bool res;

	cert1 = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate));
	cert2 = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate));

	if (cert1 != NULL)
	{
		qsc_memutils_clear(cert1, sizeof(qsc_x509_certificate));
	}

	if (cert2 != NULL)
	{
		qsc_memutils_clear(cert2, sizeof(qsc_x509_certificate));
	}

	res = (cert1 != NULL && cert2 != NULL);
	pem = NULL;

	if (res == true)
	{
		pem = qsctest_x509_read_text_file(CERT_PEM_PATH, &pemlen);
	}

	if (pem != NULL)
	{
		if (qsc_x509_certificate_decode_pem(pem, pemlen, cert1) == QSC_ASN1_STATUS_SUCCESS)
		{
			derlen = 0U;

			if (qsc_encoding_pem_decode(pem, pemlen, der, sizeof(der), &derlen) == true)
			{
				outpemlen = sizeof(outpem);

				if (qsc_x509_certificate_encode_pem(der, derlen, outpem, &outpemlen) == QSC_ASN1_STATUS_SUCCESS)
				{
					res = (qsc_x509_certificate_decode_pem(outpem, outpemlen, cert2) == QSC_ASN1_STATUS_SUCCESS);
				}
			}
		}

		qsc_memutils_alloc_free(pem);
	}

	if (cert1 != NULL)
	{
		qsc_x509_certificate_clear(cert1);
		qsc_memutils_alloc_free(cert1);
	}

	if (cert2 != NULL)
	{
		qsc_x509_certificate_clear(cert2);
		qsc_memutils_alloc_free(cert2);
	}

	return res;
}

bool x509_stage2b_csr_pem_roundtrip(void)
{
	qsc_x509_csr* csr1;
	qsc_x509_csr* csr2;
	uint8_t der[QSCTEST_X509_STAGE2B_DER_BUFFER] = { 0U };
	char outpem[QSCTEST_X509_STAGE2B_PEM_BUFFER] = { 0U };
	size_t derlen;
	size_t outpemlen;
	size_t pemlen;
	char* pem;
	bool res;

	csr1 = (qsc_x509_csr*)qsc_memutils_malloc(sizeof(qsc_x509_csr));
	csr2 = (qsc_x509_csr*)qsc_memutils_malloc(sizeof(qsc_x509_csr));

	if (csr1 != NULL)
	{
		qsc_memutils_clear(csr1, sizeof(qsc_x509_csr));
	}

	if (csr2 != NULL)
	{
		qsc_memutils_clear(csr2, sizeof(qsc_x509_csr));
	}

	res = (csr1 != NULL && csr2 != NULL);
	pem = NULL;

	if (res == true)
	{
		pem = qsctest_x509_read_text_file(CSR_PEM_PATH, &pemlen);
	}

	if (pem != NULL)
	{
		if (qsc_x509_csr_decode_pem(csr1, pem, pemlen) == QSC_ASN1_STATUS_SUCCESS)
		{
			derlen = 0U;

			if (qsc_encoding_pem_decode(pem, pemlen, der, sizeof(der), &derlen) == true)
			{
				outpemlen = sizeof(outpem);

				if (qsc_x509_csr_encode_pem(der, derlen, outpem, &outpemlen) == QSC_ASN1_STATUS_SUCCESS)
				{
					res = (qsc_x509_csr_decode_pem(csr2, outpem, outpemlen) == QSC_ASN1_STATUS_SUCCESS);
				}
			}
		}

		qsc_memutils_alloc_free(pem);
	}

	if (csr1 != NULL)
	{
		qsc_x509_csr_clear(csr1);
		qsc_memutils_alloc_free(csr1);
	}

	if (csr2 != NULL)
	{
		qsc_x509_csr_clear(csr2);
		qsc_memutils_alloc_free(csr2);
	}
	
	return res;
}

bool x509_stage2b_crl_pem_roundtrip(void)
{
	qsc_x509_crl* crl1;
	qsc_x509_crl* crl2;
	char outpem[QSCTEST_X509_STAGE2B_PEM_BUFFER] = { 0U };
	size_t outpemlen;
	bool res;

	res = false;
	crl1 = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));
	crl2 = (qsc_x509_crl*)qsc_memutils_malloc(sizeof(qsc_x509_crl));

	if (crl1 != NULL)
	{
		qsc_memutils_clear(crl1, sizeof(qsc_x509_crl));
	}

	if (crl2 != NULL)
	{
		qsc_memutils_clear(crl2, sizeof(qsc_x509_crl));
	}

	if (crl1 != NULL && crl2 != NULL)
	{
		if (load_crl_from_pem_file(CRL_PEM_PATH, crl1) == true)
		{
			outpemlen = sizeof(outpem);

			if (qsc_x509_crl_encode_pem(crl1, outpem, &outpemlen) == QSC_ASN1_STATUS_SUCCESS)
			{
				res = (qsc_x509_crl_decode_pem(outpem, outpemlen, crl2) == QSC_ASN1_STATUS_SUCCESS);
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

bool x509_stage2b_private_key_pem_negative(void)
{
	char badpem[] = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
	qsc_x509_private_key key = { 0 };
	bool haskey;
	bool res;

	haskey = qsc_x509_private_key_decode_pem_from_bundle(badpem, strlen(badpem), &key);
	res = (haskey != QSC_ASN1_STATUS_SUCCESS);

	return res;
}

bool x509_stage2b_public_key_pem_negative(void)
{
	char badpem[] = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
	qsc_x509_certificate cert = { 0 };
	bool res;

	qsc_memutils_clear(&cert, sizeof(cert));
	res = (qsc_x509_certificate_decode_pem(badpem, strlen(badpem), &cert) != QSC_ASN1_STATUS_SUCCESS);
	qsc_x509_certificate_clear(&cert);

	return res;
}

bool qsctest_x509_stage2b_pem_tests(void)
{
	bool res;

	res = true;

	if (x509_stage2b_certificate_pem_roundtrip() == true)
	{
		qsctest_print_line("[PASS] PEM encoding and decoding test.");
	}
	else
	{
		qsctest_print_line("[FAIL] PEM encoding and decoding test.");
		res = false;
	}

	if (x509_stage2b_csr_pem_roundtrip() == true)
	{
		qsctest_print_line("[PASS] CSR PEM encoding and decoding test.");
	}
	else
	{
		qsctest_print_line("[FAIL] CSR PEM encoding and decoding test.");
		res = false;
	}

	if (x509_stage2b_crl_pem_roundtrip() == true)
	{
		qsctest_print_line("[PASS] CRL PEM encoding and decoding test.");
	}
	else
	{
		qsctest_print_line("[FAIL] CRL PEM encoding and decoding test.");
		res = false;
	}

	if (x509_stage2b_private_key_pem_negative() == true)
	{
		qsctest_print_line("[PASS] PEM malformed private key test.");
	}
	else
	{
		qsctest_print_line("[FAIL] PEM malformed private key test.");
		res = false;
	}

	if (x509_stage2b_public_key_pem_negative() == true)
	{
		qsctest_print_line("[PASS] PEM malformed public key test.");
	}
	else
	{
		qsctest_print_line("[FAIL] PEM malformed public key test.");
		res = false;
	}

	return res;
}
