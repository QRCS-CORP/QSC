#include "x509_test.h"
#include "testutils.h"
#include "X509/x509_stage1_tests.h"
#include "X509/x509_stage2a_csr_tests.h"
#include "X509/x509_stage2b_pem_tests.h"
#include "X509/x509_stage2c_crl_tests.h"
#include "X509/x509_stage2d_negative_validation_tests.h"
#include "X509/x509_stage3_positive_interop_tests.h"
#include "X509/x509_stage4a_encoding_tests.h"
#include "X509/x509_stage4b_pqc_tests.h"

bool qsctest_x509_stage1_run(void)
{
	return qsctest_x509_stage1_tests();
}

bool qsctest_x509_stage2a_run(void)
{
	return qsctest_x509_stage2a_csr_tests();
}

bool qsctest_x509_stage2b_run(void) 
{
	return qsctest_x509_stage2b_pem_tests();
}

bool qsctest_x509_stage2c_run(void)
{
	return qsctest_x509_stage2c_crl_tests();
}

bool qsctest_x509_stage2d_run(void)
{
	return qsctest_x509_stage2d_negative_validation_tests();
}

bool qsctest_x509_stage3_run(void)
{
	return qsctest_x509_stage3_positive_interop_tests();
}

bool qsctest_x509_stage4a_run(void)
{
	return qsctest_x509_stage4a_encoding_tests();
}

bool qsctest_x509_stage4b_run(void)
{
	return qsctest_x509_stage4b_pqc_tests();
}

void qsctest_x509_run(void)
{
	bool res;

	res = true;

	qsctest_print_line("Tests chain verification, CRL handling, CSR/PEM processing, and negative/positive validation scenarios.");

	if (qsctest_x509_stage1_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 certificate, chain, and revocation validation tests.");
	}
	else
	{
		qsctest_print_safe("Failure! Failed one or more X509 certificate, chain, and revocation validation tests.");
	}

	if (qsctest_x509_stage2a_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 CSR generation, parsing, encoding, and round-trip tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 CSR generation, parsing, encoding tests.");
	}

	if (qsctest_x509_stage2b_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 PEM decoding, PEM encoding, bundle handling, and DER/PEM round-trip operations tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 PEM decoding, PEM encoding, bundle handling, and DER/PEM tests.");
	}

	if (qsctest_x509_stage2c_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 validate CRL encoding, decoding, signature verification, revocation lookup tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 CRL encoding, decoding, signature verification tests.");
	}

	if (qsctest_x509_stage2d_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 validate rejection behavior for malformed, expired, invalid certificates tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 rejection behavior tests.");
	}

	if (qsctest_x509_stage3_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 validate successful processing of correct certificates, chains, and related objects tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 processing of correct certificates tests.");
	}

	if (qsctest_x509_stage4a_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 PQC ML-DSA/ML-KEM encoding tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 PQC ML-DSA/ML-KEM encoding tests.");
	}

	if (qsctest_x509_stage4b_run() == true)
	{
		qsctest_print_line("Success! Passed the X509 PQC ML-DSA/ML-KEM coverage tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed one or more X509 PQC ML-DSA/ML-KEM tests.");
	}
}
