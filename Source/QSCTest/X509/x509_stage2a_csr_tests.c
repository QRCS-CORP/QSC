#include "x509_stage2a_csr_tests.h"
#include "../testutils.h"
#include "x509_test_helper.h"
#include "fileutils.h"
#include "memutils.h"
#include "x509csr.h"
#include "x509pem.h"

static const char CSR_DER_PATH[] = "X509/Vectors/Stage2A/valid.csr.der";
static const char CSR_PEM_PATH[] = "X509/Vectors/Stage2A/valid.csr.pem";

static bool csr_decode_pem_file(const char* path, qsc_x509_csr* csr)
{
	char* pem;
	size_t pemlen;
	bool res;

	res = false;

	if (csr != NULL)
	{
		pem = qsctest_x509_read_text_file(path, &pemlen);

		if (pem != NULL)
		{
			res = (qsc_x509_csr_decode_pem(csr, pem, pemlen) == QSC_ASN1_STATUS_SUCCESS);
			qsc_memutils_alloc_free(pem);
		}
	}

	return res;
}

static bool csr_decode_der_file(const char* path, qsc_x509_csr* csr)
{
	uint8_t* der;
	size_t derlen;
	bool res;

	if (csr != NULL)
	{
		der = qsctest_x509_read_binary_file(path, &derlen);

		if (der != NULL)
		{
			res = (qsc_x509_csr_decode_der(csr, der, derlen) == QSC_ASN1_STATUS_SUCCESS);
			qsc_memutils_alloc_free(der);
		}
	}

	return res;
}

bool x509_stage2a_valid_csr_pem(void)
{
	qsc_x509_csr csr = { 0 };
	bool res;

	res = false;

	if (csr_decode_pem_file(CSR_PEM_PATH, &csr) == true)
	{
		res = qsc_x509_csr_verify(&csr);
	}

	return res;
}

bool x509_stage2a_valid_csr_der(void)
{
	qsc_x509_csr csr;
	bool res;

	res = false;

	qsc_memutils_clear(&csr, sizeof(csr));

	if (csr_decode_der_file(CSR_DER_PATH, &csr) == true)
	{
		res = qsc_x509_csr_verify(&csr);
	}

	return res;
}

bool x509_stage2a_tampered_csr_signature(void)
{
	qsc_x509_csr csr = { 0 };
	uint8_t* der;
	size_t derlen;
	bool res;

	res = false;
	der = qsctest_x509_read_binary_file(CSR_DER_PATH, &derlen);

	if (der != NULL && derlen >= 16U)
	{
		der[derlen - 8U] ^= 0x01U;

		if (qsc_x509_csr_decode_der(&csr, der, derlen) == QSC_ASN1_STATUS_SUCCESS)
		{
			res = (qsc_x509_csr_verify(&csr) == false);
		}

		qsc_memutils_alloc_free(der);
	}

	return res;
}

bool x509_stage2a_extension_request_present(void)
{
	qsc_x509_csr csr = { 0 };
	bool res;

	res = false;
	qsc_memutils_clear(&csr, sizeof(csr));

	if (csr_decode_pem_file(CSR_PEM_PATH, &csr) == true)
	{
		res = (csr.attributecount != 0U);
	}

	return res;
}

bool qsctest_x509_stage2a_csr_tests(void)
{
	bool res;

	res = true;

	if (x509_stage2a_valid_csr_pem() == true)
	{
		qsctest_print_line("[PASS] PEM decoding validation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] PEM decoding validation test.");
		res = false;
	}

	if (x509_stage2a_valid_csr_der() == true)
	{
		qsctest_print_line("[PASS] DER decoding validation test.");
	}
	else
	{
		qsctest_print_line("[FAIL] DER decoding validation test.");
		res = false;
	}

	if (x509_stage2a_tampered_csr_signature() == true)
	{
		qsctest_print_line("[PASS] Tampered CSR rejection test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Tampered CSR rejection test.");
		res = false;
	}

	if (x509_stage2a_extension_request_present())
	{
		qsctest_print_line("[PASS] Extension request parsing test.");
	}
	else
	{
		qsctest_print_line("[FAIL] Extension request parsing test.");
		res = false;
	}

	return res;
}
