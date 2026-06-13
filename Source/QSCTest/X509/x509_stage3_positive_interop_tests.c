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
#include "x509pkcs12.h"
#include "x509time.h"
#include "encoding.h"
#include "stringutils.h"

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

#define QSCTEST_X509_RFC9879_A1_DER_SIZE 2702U
#define QSCTEST_X509_RFC9879_A3_DER_SIZE 2736U
#define QSCTEST_X509_RFC9879_A4_DER_SIZE 2703U
#define QSCTEST_X509_RFC9879_A5_DER_SIZE 2702U
#define QSCTEST_X509_RFC9879_A6_DER_SIZE 2700U

/* RFC 9879 Appendix A.1: valid PKCS #12 file with SHA-256 HMAC and PRF. */
static const char QSCTEST_X509_RFC9879_A1_B64[] =
    "MIIKigIBAzCCCgUGCSqGSIb3DQEHAaCCCfYEggnyMIIJ7jCCBGIGCSqGSIb3DQEH"
    "BqCCBFMwggRPAgEAMIIESAYJKoZIhvcNAQcBMFcGCSqGSIb3DQEFDTBKMCkGCSqG"
    "SIb3DQEFDDAcBAg9pxXxY2yscwICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQME"
    "ASoEEK7yYaFQDi1pYwWzm9F/fs+AggPgFIT2XapyaFgDppdvLkdvaF3HXw+zjzKb"
    "7xFC76DtVPhVTWVHD+kIss+jsj+XyvMwY0aCuAhAG/Dig+vzWomnsqB5ssw5/kTb"
    "+TMQ5PXLkNeoBmB6ArKeGc/QmCBQvQG/a6b+nXSWmxNpP+71772dmWmB8gcSJ0kF"
    "Fj75NrIbmNiDMCb71Q8gOzBMFf6BpXf/3xWAJtxyic+tSNETfOJa8zTZb0+lV0w9"
    "5eUmDrPUpuxEVbb0KJtIc63gRkcfrPtDd6Ii4Zzbzj2Evr4/S4hnrQBsiryVzJWy"
    "IEjaD0y6+DmG0JwMgRuGi1wBoGowi37GMrDCOyOZWC4n5wHLtYyhR6JaElxbrhxP"
    "H46z2USLKmZoF+YgEQgYcSBXMgP0t36+XQocFWYi2N5niy02TnctwF430FYsQlhJ"
    "Suma4I33E808dJuMv8T/soF66HsD4Zj46hOf4nWmas7IaoSAbGKXgIa7KhGRJvij"
    "xM3WOX0aqNi/8bhnxSA7fCmIy/7opyx5UYJFWGBSmHP1pBHBVmx7Ad8SAsB9MSsh"
    "nbGjGiUk4h0QcOi29/M9WwFlo4urePyI8PK2qtVAmpD3rTLlsmgzguZ69L0Q/CFU"
    "fbtqsMF0bgEuh8cfivd1DYFABEt1gypuwCUtCqQ7AXK2nQqOjsQCxVz9i9K8NDeD"
    "aau98VAl0To2sk3/VR/QUq0PRwU1jPN5BzUevhE7SOy/ImuJKwpGqqFljYdrQmj5"
    "jDe+LmYH9QGVRlfN8zuU+48FY8CAoeBeHn5AAPml0PYPVUnt3/jQN1+v+CahNVI+"
    "La8q1Nen+j1R44aa2I3y/pUgtzXRwK+tPrxTQbG030EU51LYJn8amPWmn3w75ZIA"
    "MJrXWeKj44de7u4zdUsEBVC2uM44rIHM8MFjyYAwYsey0rcp0emsaxzar+7ZA67r"
    "lDoXvvS3NqsnTXHcn3T9tkPRoee6L7Dh3x4Od96lcRwgdYT5BwyH7e34ld4VTUmJ"
    "bDEq7Ijvn4JKrwQJh1RCC+Z/ObfkC42xAm7G010u3g08xB0Qujpdg4a7VcuWrywF"
    "c7hLNquuaF4qoDaVwYXHH3iuX6YlJ/3siTKbYCVXPEZOAMBP9lF/OU76UMJBQNfU"
    "0xjDx+3AhUVgnGuCsmYlK6ETDp8qOZKGyV0KrNSGtqLx3uMhd7PETeW+ML3tDQ/0"
    "X9fMkcZHi4C2fXnoHV/qa2dGhBj4jjQ0Xh1poU6mxGn2Mebe2hDsBZkkBpnn7pK4"
    "wP/VqXdQTwqEuvzGHLVFsCuADe40ZFBmtBrf70wG7ZkO8SUZ8Zz1IX3+S024g7yj"
    "QRev/6x6TtkwggWEBgkqhkiG9w0BBwGgggV1BIIFcTCCBW0wggVpBgsqhkiG9w0B"
    "DAoBAqCCBTEwggUtMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAhTxzw+"
    "VptrYAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEK9nSqc1I2t4tMVG"
    "bWHpdtQEggTQzCwI7j34gCTvfj6nuOSndAjShGv7mN2j7WMV0pslTpq2b9Bn3vn1"
    "Y0JMvL4E7sLrUzNU02pdOcfCnEpMFccNv2sQrLp1mOCKxu8OjSqHZLoKVL0ROVsZ"
    "8dMECLLigDlPKRiSyLErl14tErX4/zbkUaWMROO28kFbTbubQ8YoHlRUwsKW1xLg"
    "vfi0gRkG/zHXRfQHjX/8NStv7hXlehn7/Gy2EKPsRFhadm/iUHAfmCMkMgHTU248"
    "JER9+nsXltd59H+IeDpj/kbxZ+YvHow9XUZKu828d3MQnUpLZ1BfJGhMBPVwbVUD"
    "A40CiQBVdCoGtPJyalL28xoS3H0ILFCnwQOr6u0HwleNJPGHq78HUyH6Hwxnh0b0"
    "5o163r6wTFZn5cMOxpbs/Ttd+3TrxmrYpd2XnuRme3cnaYJ0ILvpc/8eLLR7SKjD"
    "T4JhZ0h/CfcV2WWvhpQugkY0pWrZ+EIMneB1dZB96mJVLxOi148OeSgi0PsxZMNi"
    "YM33rTpwQT5WqOsEyDwUQpne5b8Kkt/s7EN0LJNnPyJJRL1LcqOdr6j+6YqRtPa7"
    "a9oWJqMcuTP+bqzGRJh+3HDlFBw2Yzp9iadv4KmB2MzhStLUoi2MSjvnnkkd5Led"
    "sshAd6WbKfF7kLAHQHT4Ai6dMEO4EKkEVF9JBtxCR4JEn6C98Lpg+Lk+rfY7gHOf"
    "ZxtgGURwgXRY3aLUrdT55ZKgk3ExVKPzi5EhdpAau7JKhpOwyKozAp/OKWMNrz6h"
    "obu2Mbn1B+IA60psYHHxynBgsJHv7WQmbYh8HyGfHgVvaA8pZCYqxxjpLjSJrR8B"
    "Bu9H9xkTh7KlhxgreXYv19uAYbUd95kcox9izad6VPnovgFSb+Omdy6PJACPj6hF"
    "W6PJbucP0YPpO0VtWtQdZZ3df1P0hZ7qvKwOPFA+gKZSckgqASfygiP9V3Zc8jIi"
    "wjNzoDM2QT+UUJKiiGYXJUEOO9hxzFHlGj759DcNRhpgl5AgR57ofISD9yBuCAJY"
    "PQ/aZHPFuRTrcVG3RaIbCAS73nEznKyFaLOXfzyfyaSmyhsH253tnyL1MejC+2bR"
    "Eko/yldgFUxvU5JI+Q3KJ6Awj+PnduHXx71E4UwSuu2xXYMpxnQwI6rroQpZBX82"
    "HhqgcLV83P8lpzQwPdHjH5zkoxmWdC0+jU/tcQfNXYpJdyoaX7tDmVclLhwl9ps/"
    "O841pIsNLJWXwvxG6B+3LN/kw4QjwN194PopiOD7+oDm5mhttO78CrBrRxHMD/0Q"
    "qniZjKzSZepxlZq+J792u8vtMnuzzChxu0Bf3PhIXcJNcVhwUtr0yKe/N+NvC0tm"
    "p8wyik/BlndxN9eKbdTOi2wIi64h2QG8nOk66wQ/PSIJYwZl6eDNEQSzH/1mGCfU"
    "QnUT17UC/p+Qgenf6Auap2GWlvsJrB7u/pytz65rtjt/ouo6Ih6EwWqwVVpGXZD0"
    "7gVWH0Ke/Vr6aPGNvkLcmftPuDZsn9jiig3guhdeyRVf10Ox369kKWcG75q77hxE"
    "IzSzDyUlBNbnom9SIjut3r+qVYmWONatC6q/4D0I42Lnjd3dEyZx7jmH3g/S2ASM"
    "FzWr9pvXc61dsYOkdZ4PYa9XPUZxXFagZsoS3F1sU799+IJVU0tC0MExJTAjBgkq"
    "hkiG9w0BCRUxFgQUwWO5DorvVWYF3BWUmAw0rUEajScwfDBtMEkGCSqGSIb3DQEF"
    "DjA8MCwGCSqGSIb3DQEFDDAfBAhvRzw4sC4xcwICCAACASAwDAYIKoZIhvcNAgkF"
    "ADAMBggqhkiG9w0CCQUABCB6pW2FOdcCNj87zS64NUXG36K5aXDnFHctIk5Bf4kG"
    "3QQITk9UIFVTRUQCAQE=";

/* RFC 9879 Appendix A.3: valid PKCS #12 file with SHA-512 HMAC and PRF. */
static const char QSCTEST_X509_RFC9879_A3_B64[] =
    "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";

/* RFC 9879 Appendix A.4: invalid PKCS #12 file with incorrect iteration count. */
static const char QSCTEST_X509_RFC9879_A4_B64[] =
    "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"
    "3QQITk9UIFVTRUQCAggA";

/* RFC 9879 Appendix A.5: invalid PKCS #12 file with incorrect salt. */
static const char QSCTEST_X509_RFC9879_A5_B64[] =
    "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"
    "3QQIb0c8OLAuMXMCAQE=";

/* RFC 9879 Appendix A.6: invalid PKCS #12 file with missing key length. */
static const char QSCTEST_X509_RFC9879_A6_B64[] =
    "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"
    "b0c8OLAuMXMCAggA";


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

static bool x509_stage3_decode_rfc9879_vector(uint8_t* output, size_t outlen, const char* vector)
{
	bool res;
	size_t declen;

	res = false;

	if (output != NULL && vector != NULL)
	{
		declen = qsc_encoding_base64_decoded_size(vector, qsc_stringutils_string_size(vector));

		if (declen == outlen)
		{
			res = qsc_encoding_base64_decode(output, outlen, vector, qsc_stringutils_string_size(vector));
		}
	}

	return res;
}

static bool x509_stage3_pkcs12_pbmac1_parse_vector(const char* vector, size_t vectorlen, bool expectvalid)
{
	uint8_t data[QSCTEST_X509_RFC9879_A3_DER_SIZE] = { 0U };
	bool parsed;
	bool res;

	res = false;

	if (x509_stage3_decode_rfc9879_vector(data, vectorlen, vector) == true)
	{
		parsed = qsc_x509_pkcs12_verify_mac_data(data, vectorlen, "1234");
		res = (parsed == expectvalid);
	}

	qsc_memutils_clear(data, sizeof(data));

	return res;
}

bool x509_stage3_pkcs12_pbmac1_rfc9879_vectors(void)
{
	bool res;

	res = true;

	if (x509_stage3_pkcs12_pbmac1_parse_vector(QSCTEST_X509_RFC9879_A1_B64, QSCTEST_X509_RFC9879_A1_DER_SIZE, true) != true)
	{
		res = false;
	}

	if (x509_stage3_pkcs12_pbmac1_parse_vector(QSCTEST_X509_RFC9879_A3_B64, QSCTEST_X509_RFC9879_A3_DER_SIZE, true) != true)
	{
		res = false;
	}

	if (x509_stage3_pkcs12_pbmac1_parse_vector(QSCTEST_X509_RFC9879_A4_B64, QSCTEST_X509_RFC9879_A4_DER_SIZE, false) != true)
	{
		res = false;
	}

	if (x509_stage3_pkcs12_pbmac1_parse_vector(QSCTEST_X509_RFC9879_A5_B64, QSCTEST_X509_RFC9879_A5_DER_SIZE, false) != true)
	{
		res = false;
	}

	if (x509_stage3_pkcs12_pbmac1_parse_vector(QSCTEST_X509_RFC9879_A6_B64, QSCTEST_X509_RFC9879_A6_DER_SIZE, false) != true)
	{
		res = false;
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

	if (x509_stage3_pkcs12_pbmac1_rfc9879_vectors() == true)
	{
		qsctest_print_line("[PASS] RFC 9879 PKCS#12 PBMAC1 interoperability vectors.");
	}
	else
	{
		qsctest_print_line("[FAIL] RFC 9879 PKCS#12 PBMAC1 interoperability vectors.");
		res = false;
	}

	return res;
}
