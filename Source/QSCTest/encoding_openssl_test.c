/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "encoding_openssl_test.h"
#include "encoding.h"
#include "asn1.h"
#include "memutils.h"
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(QSCTEST_OPENSSL_ENABLED)
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/** \brief Deterministic test generator state; tests are single threaded. */
static uint64_t test_seed = UINT64_C(0xA30799836B164C91);
/** \brief Number of successful differential cases. */
static size_t test_cases = 0U;
/** \brief Number of accepted-format divergences, tracked separately. */
static size_t test_differences = 0U;

/** \brief Generate repeatable, nonsecret test bytes. \return Next pseudorandom word. */
static uint64_t test_random(void)
{
	test_seed ^= test_seed >> 12U;
	test_seed ^= test_seed << 25U;
	test_seed ^= test_seed >> 27U;
	return test_seed * UINT64_C(2685821657736338717);
}

/** \brief Print a detailed failed assertion and exit the current test. \param group Test name. \param index Input case. \param detail Failure description. */
static void test_error(const char* group, size_t index, const char* detail)
{
	fprintf(stderr, "FAIL: %s case=%zu: %s\n", group, index, detail);
}

/** \brief Compare QSC Base64 output against OpenSSL block encoder and decoder.
 * \param input Input bytes. \param length Input length, 1..8192. \param index Case ID.
 * \return True if all encodings/decodings match, including decoded length. */
static bool test_base64_one(const uint8_t* input, size_t length, size_t index)
{
	char qencoded[11000U];
	uint8_t qdecoded[8194U];
	uint8_t odecoded[8194U];
	unsigned char oencoded[11000U];
	size_t encoded;
	int olen;
	int decoded;
	bool ok;

	ok = false;
	encoded = qsc_encoding_base64_encoded_size(length);
	olen = EVP_EncodeBlock(oencoded, input, (int)length);

	if (encoded == (size_t)olen && encoded > 0U && encoded < sizeof(qencoded))
	{
		memset(qencoded, 0xCE, sizeof(qencoded));
		memset(qdecoded, 0xA5, sizeof(qdecoded));
		memset(odecoded, 0xB6, sizeof(odecoded));
		ok = qsc_encoding_base64_encode(qencoded, sizeof(qencoded), input, length);
		ok = (ok && memcmp(qencoded, oencoded, encoded) == 0);
		ok = (ok && qsc_encoding_base64_decoded_size(qencoded, encoded) == length);
		ok = (ok && qsc_encoding_base64_decode(qdecoded, length, qencoded, encoded));
		decoded = EVP_DecodeBlock(odecoded, oencoded, olen);

		if (decoded >= 0)
		{
			if (oencoded[olen - 1] == '=')
			{
				--decoded;
			}

			if (oencoded[olen - 2] == '=')
			{
				--decoded;
			}
		}

		ok = (ok && decoded == (int)length);
		ok = (ok && memcmp(qdecoded, input, length) == 0);
		ok = (ok && memcmp(odecoded, input, length) == 0);
		ok = (ok && memcmp(qdecoded, odecoded, length) == 0);
		ok = (ok && qdecoded[length] == 0xA5U);
	}

	if (ok == false)
	{
		test_error("Base64 independent EVP", index, "encoded bytes, decoded bytes, size or output canary disagree");
	}
	else
	{
		++test_cases;
	}

	return ok;
}

/** \brief Exhaustively compare 1-byte and 2-byte Base64 against OpenSSL. \return True on full pass. */
static bool qsctest_encoding_openssl_base64_exhaustive_test(void)
{
	uint8_t input[2U];
	size_t i;
	bool ok;

	ok = true;

	for (i = 0U; i < 256U && ok == true; ++i)
	{
		input[0U] = (uint8_t)i;
		ok = test_base64_one(input, 1U, i);
	}

	for (i = 0U; i < 65536U && ok == true; ++i)
	{
		input[0U] = (uint8_t)(i >> 8U);
		input[1U] = (uint8_t)i;
		ok = test_base64_one(input, 2U, i + 256U);
	}

	printf("%s: exhaustive 256 one-byte and 65,536 two-byte Base64 EVP comparisons\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Compare OpenSSL encoding to QSC single-shot and randomized streaming. \return True on full pass. */
static bool qsctest_encoding_openssl_base64_stream_openssl_test(void)
{
	uint8_t source[8192U];
	uint8_t decoded[8193U];
	unsigned char reference[11000U];
	char encoded[11000U];
	qsc_encoding_base64_stream_state state;
	size_t len;
	size_t offset;
	size_t total;
	size_t amount;
	size_t written;
	int olen;
	bool ok;

	ok = true;

	for (size_t run = 0U; run < 20000U && ok == true; ++run)
	{
		len = 1U + (size_t)(test_random() % sizeof(source));

		for (size_t i = 0U; i < len; ++i)
		{
			source[i] = (uint8_t)test_random();
		}

		ok = test_base64_one(source, len, run + 100000U);
		olen = EVP_EncodeBlock(reference, source, (int)len);
		qsc_encoding_base64_stream_initialize(&state);
		offset = 0U;
		total = 0U;

		while (offset < len && ok == true)
		{
			amount = 1U + (size_t)(test_random() % 131U);

			if (amount > len - offset)
			{
				amount = len - offset;
			}

			ok = qsc_encoding_base64_stream_encode_update(&state, encoded + total, sizeof(encoded) - total, source + offset, amount, &written);
			offset += amount;
			total += written;
		}

		if (ok == true)
		{
			ok = qsc_encoding_base64_stream_encode_final(&state, encoded + total, sizeof(encoded) - total, &written);
			total += written;
			ok = (ok && total == (size_t)olen && memcmp(encoded, reference, total) == 0);
		}

		qsc_encoding_base64_stream_initialize(&state);
		offset = 0U;
		total = 0U;
		memset(decoded, 0xE7, sizeof(decoded));

		while (offset < (size_t)olen && ok == true)
		{
			amount = 1U + (size_t)(test_random() % 71U);

			if (amount > ((size_t)olen - offset))
			{
				amount = (size_t)olen - offset;
			}

			ok = qsc_encoding_base64_stream_decode_update(&state, decoded + total, sizeof(decoded) - total, encoded + offset, amount, &written);
			offset += amount;
			total += written;
		}

		ok = (ok && qsc_encoding_base64_stream_decode_final(&state));
		ok = (ok && total == len && memcmp(decoded, source, len) == 0 && decoded[len] == 0xE7U);

		if (ok == false)
		{
			test_error("Base64 stream versus EVP", run, "chunked bytes or finalization disagree");
		}
	}

	printf("%s: 20,000 randomized streaming cases and EVP byte comparisons\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Exhaustively compare hexadecimal encoding/decoding with OpenSSL. \return True on pass. */
static bool qsctest_encoding_openssl_hex_exhaustive_test(void)
{
	uint8_t input[2U];
	uint8_t decoded[4U];
	unsigned char openssl_decoded[4U];
	char qhex[8U];
	char ohex[8U];
	size_t olen;
	size_t qlen;
	bool ok;

	ok = true;

	for (size_t i = 0U; i < 65536U && ok == true; ++i)
	{
		input[0U] = (uint8_t)(i >> 8U);
		input[1U] = (uint8_t)i;
		ok = qsc_encoding_hex_encode(input, sizeof(input), qhex, sizeof(qhex));
		ok = (ok && OPENSSL_buf2hexstr_ex(ohex, sizeof(ohex), &olen, input, sizeof(input), '\0'));
		ok = (ok && olen == 5U && memcmp(qhex, ohex, 5U) == 0);
		ok = (ok && qsc_encoding_hex_decode(qhex, 4U, decoded, sizeof(decoded), &qlen));
		ok = (ok && OPENSSL_hexstr2buf_ex(openssl_decoded, sizeof(openssl_decoded), &olen, qhex, '\0'));
		ok = (ok && olen == 2U && qlen == 2U);
		ok = (ok && memcmp(decoded, openssl_decoded, 2U) == 0 && memcmp(decoded, input, 2U) == 0);

		if (ok == false)
		{
			test_error("Hex exhaustive versus OpenSSL", i, "encoder/decoder disagree");
		}
		else
		{
			++test_cases;
		}
	}

	printf("%s: all 65,536 binary two-byte hex values versus OpenSSL\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Compare randomly sized hexadecimal strings with OpenSSL. \return True on pass. */
static bool qsctest_encoding_openssl_hex_boundaries_test(void)
{
	uint8_t source[4096U];
	uint8_t decoded[4097U];
	unsigned char openssl_decoded[4097U];
	char qhex[8200U];
	char ohex[8200U];
	size_t olen;
	size_t qlen;
	size_t n;
	bool ok;

	ok = true;

	for (size_t run = 0U; run < 10000U && ok == true; ++run)
	{
		n = 1U + (size_t)(test_random() % sizeof(source));

		for (size_t i = 0U; i < n; ++i)
		{
			source[i] = (uint8_t)test_random();
		}

		ok = qsc_encoding_hex_encode(source, n, qhex, sizeof(qhex));
		ok = (ok && OPENSSL_buf2hexstr_ex(ohex, sizeof(ohex), &olen, source, n, '\0'));
		ok = (ok && olen == 2U * n + 1U && memcmp(qhex, ohex, olen) == 0);
		memset(decoded, 0x97, sizeof(decoded));
		ok = (ok && qsc_encoding_hex_decode(ohex, olen - 1U, decoded, n, &qlen));
		ok = (ok && OPENSSL_hexstr2buf_ex(openssl_decoded, sizeof(openssl_decoded), &olen, qhex, '\0'));
		ok = (ok && olen == n && qlen == n && memcmp(decoded, openssl_decoded, n) == 0);
		ok = (ok && decoded[n] == 0x97U);

		if (ok == false)
		{
			test_error("Hex random versus OpenSSL", run, "byte or length mismatch");
		}
	}

	printf("%s: 10,000 randomized length/unaligned hexadecimal comparisons\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Compare PEM encoding exactly and decoding independently against OpenSSL. \return True on pass. */
static bool qsctest_encoding_openssl_pem_openssl_test(void)
{
	uint8_t source[4096U];
	uint8_t decoded[4096U];
	unsigned char* openssl_decoded;
	char qpem[9000U];
	char* label;
	char* header;
	BIO* output;
	BIO* input;
	BUF_MEM* mem;
	long olen;
	size_t got;
	size_t n;
	bool ok;

	ok = true;

	for (size_t run = 0U; run < 3000U && ok == true; ++run)
	{
		n = 1U + (size_t)(test_random() % sizeof(source));

		for (size_t i = 0U; i < n; ++i)
		{
			source[i] = (uint8_t)test_random();
		}

		output = BIO_new(BIO_s_mem());
		ok = (output != NULL);
		ok = (ok && PEM_write_bio(output, "CERTIFICATE", NULL, source, (long)n) > 0);
		BIO_get_mem_ptr(output, &mem);
		ok = (ok && qsc_encoding_pem_encode("CERTIFICATE", qpem, sizeof(qpem), source, n));
		ok = (ok && strlen(qpem) == mem->length && memcmp(qpem, mem->data, mem->length) == 0);
		got = 0U;
		ok = (ok && qsc_encoding_pem_decode(mem->data, mem->length, decoded, sizeof(decoded), &got));
		ok = (ok && got == n && memcmp(decoded, source, n) == 0);
		input = BIO_new_mem_buf(qpem, (int)strlen(qpem));
		label = NULL;
		header = NULL;
		openssl_decoded = NULL;
		olen = -1L;
		ok = (ok && input != NULL);

		if (input != NULL)
		{
			ok = (ok && PEM_read_bio(input, &label, &header, &openssl_decoded, &olen) == 1);
			ok = (ok && olen == (long)n && memcmp(openssl_decoded, source, n) == 0);
			BIO_free(input);
		}

		OPENSSL_free(label);
		OPENSSL_free(header);
		OPENSSL_free(openssl_decoded);
		BIO_free(output);

		if (ok == false)
		{
			test_error("PEM versus OpenSSL", run, "encoded text, decoded bytes or length disagree");
			fprintf(stderr,"PEM n=%zu qsc=%zu\n",n,strlen(qpem));
		}
		else
		{
			++test_cases;
		}
	}

	printf("%s: 3,000 independent OpenSSL PEM writes/reads, exact text and binary equality\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Parse one primitive/sequence with OpenSSL, checking exact re-encoding. \param der DER data. \param length Byte length. \return True when OpenSSL accepts exact canonical output. */
static bool test_openssl_der_exact(const uint8_t* der, size_t length)
{
	const unsigned char* ptr;
	unsigned char* recoded;
	unsigned char* cursor;
	ASN1_TYPE* item;
	int outlen;
	bool valid;

	ptr = der;
	item = d2i_ASN1_TYPE(NULL, &ptr, (long)length);
	valid = (item != NULL && ptr == der + length);

	if (valid == true)
	{
		outlen = i2d_ASN1_TYPE(item, NULL);
		valid = (outlen == (int)length);

		if (valid == true)
		{
			recoded = OPENSSL_malloc(length);
			valid = (recoded != NULL);

			if (valid == true)
			{
				cursor = recoded;
				valid = (i2d_ASN1_TYPE(item, &cursor) == outlen && memcmp(recoded, der, length) == 0);
				OPENSSL_free(recoded);
			}
		}
	}

	ASN1_TYPE_free(item);
	return valid;
}

/** \brief Generate primitive DER using OpenSSL native ASN.1 integer encoder and compare QSC. \return True on pass. */
static bool qsctest_encoding_openssl_der_openssl_integer_test(void)
{
	ASN1_INTEGER* integer;
	qsc_encoding_ber_element* element;
	const unsigned char* ptr;
	uint8_t der[32U];
	uint8_t qder[32U];
	unsigned char* dst;
	size_t consumed;
	size_t encoded;
	int derlen;
	bool ok;

	ok = true;

	for (size_t run = 0U; run < 10000U && ok == true; ++run)
	{
		integer = ASN1_INTEGER_new();
		ok = (integer != NULL);
		ok = (ok && ASN1_INTEGER_set_int64(integer, (int64_t)test_random()) == 1);
		dst = der;
		derlen = i2d_ASN1_INTEGER(integer, &dst);
		ASN1_INTEGER_free(integer);
		ok = (ok && derlen > 0 && derlen <= (int)sizeof(der));
		consumed = 0U;
		element = NULL;

		if (ok == true)
		{
			element = qsc_encoding_der_decode_element(der, (size_t)derlen, &consumed);
			ok = (element != NULL && consumed == (size_t)derlen);
		}

		if (ok == true)
		{
			encoded = qsc_encoding_der_encode_element(element, NULL, 0U);
			ok = (encoded == (size_t)derlen && qsc_encoding_der_encode_element(element, qder, sizeof(qder)) == encoded);
			ok = (ok && memcmp(qder, der, encoded) == 0);
			ptr = der;
			ok = (ok && test_openssl_der_exact(ptr, (size_t)derlen));
		}

		if (element != NULL)
		{
			qsc_encoding_ber_free_element(element);
		}

		if (ok == false)
		{
			test_error("DER OpenSSL integers", run, "primitive DER bytes/size/consumed mismatch");
		}
		else
		{
			++test_cases;
		}
	}

	printf("%s: 10,000 DER INTEGER values generated independently by OpenSSL\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Validate OpenSSL TLV parsing, QSC structure and child exact byte ranges. \return True on pass. */
static bool qsctest_encoding_openssl_der_children_openssl_test(void)
{
	uint8_t der[16384U];
	uint8_t child[256U];
	const uint8_t* slice;
	const unsigned char* ptr;
	size_t header;
	size_t length;
	size_t parentlen;
	size_t slice_length;
	size_t childlength;
	size_t consumed;
	size_t children;
	long rawlen;
	int tag;
	int cls;
	int ret;
	bool ok;

	ok = true;

	for (size_t run = 0U; run < 2000U && ok == true; ++run)
	{
		children = 1U + (size_t)(test_random() % 120U);
		length = 0U;

		for (size_t i = 0U; i < children; ++i)
		{
			child[0U] = 0x04U;
			child[1U] = (uint8_t)(1U + (test_random() % 120U));

			for (size_t k = 0U; k < child[1U]; ++k)
			{
				child[k + 2U] = (uint8_t)test_random();
			}

			memcpy(der + 4U + length, child, (size_t)child[1U] + 2U);
			length += (size_t)child[1U] + 2U;
		}

		der[0U] = 0x30U;
		der[1U] = 0x82U;
		der[2U] = (uint8_t)(length >> 8U);
		der[3U] = (uint8_t)length;
		/* Short or long-form encoded sequence lengths must be canonical. */
		if (length < 256U)
		{
			if (length < 128U)
			{
				memmove(der + 2U, der + 4U, length);
				der[1U] = (uint8_t)length;
				header = 2U;
			}
			else
			{
				memmove(der + 3U, der + 4U, length);
				der[1U] = 0x81U;
				der[2U] = (uint8_t)length;
				header = 3U;
			}
		}
		else
		{
			header = 4U;
		}

		parentlen = header + length;
		consumed = 0U;
		ok = qsc_encoding_der_validate(der, header + length, &consumed);
		ok = (ok && consumed == header + length);
		ptr = der;
		ret = ASN1_get_object(&ptr, &rawlen, &tag, &cls, (long)(header + length));
		ok = (ok && ((ret & 0x80) == 0) && ((ret & V_ASN1_CONSTRUCTED) != 0) && tag == V_ASN1_SEQUENCE && cls == V_ASN1_UNIVERSAL);
		ok = (ok && (size_t)rawlen == length && (size_t)(ptr - der) == header);
		consumed = header;

		for (size_t i = 0U; i < children && ok == true; ++i)
		{
			ptr = der + consumed;
			ret = ASN1_get_object(&ptr, &rawlen, &tag, &cls, (long)(parentlen - consumed));
			ok = ((ret & 0x80) == 0 && tag == V_ASN1_OCTET_STRING && cls == V_ASN1_UNIVERSAL && (ret & V_ASN1_CONSTRUCTED) == 0);
			childlength = (size_t)(ptr - (der + consumed)) + (size_t)rawlen;
			slice = NULL;
			slice_length = 0U;
			qsc_asn1_status result = qsc_asn1_der_get_child_region(der, parentlen, i, &slice, &slice_length);
			if (result != QSC_ASN1_STATUS_SUCCESS) { fprintf(stderr,"child failure i=%zu status=%d tag=%d rawlen=%ld computed=%zu\n",i,result,tag,rawlen,childlength); }
			ok = (ok && result == QSC_ASN1_STATUS_SUCCESS);
			if (ok && !(slice == der + consumed && slice_length == childlength)) { fprintf(stderr,"child mismatch i=%zu expectedOff=%zu actualOff=%td gotLen=%zu expectedLen=%zu\n",i,consumed,slice? (ptrdiff_t)(slice-der):-1,slice_length,childlength); }
			ok = (ok && slice == der + consumed && slice_length == childlength);
			consumed += childlength;
		}

		if (ok == false)
		{
			test_error("DER child offsets versus OpenSSL", run, "tag/length or child offset mismatch");
			fprintf(stderr,"DER run=%zu count=%zu header=%zu consumed=%zu length=%zu top=%02x %02x %02x %02x\n",run,children,header,consumed,length,der[0],der[1],der[2],der[3]);
		}
		else
		{
			++test_cases;
		}
	}

	printf("%s: 2,000 DER parent/child walks compared against ASN1_get_object\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Check specific malformed and truncated DER inputs against independent OpenSSL parsing. \return True on pass. */
static bool qsctest_encoding_openssl_der_malformed_exhaustive_test(void)
{
	static const uint8_t valid[] = { 0x30U, 0x06U, 0x02U, 0x01U, 0x01U, 0x02U, 0x01U, 0x02U };
	uint8_t input[8U];
	const uint8_t* slice;
	size_t consumed;
	size_t childlen;
	size_t only_open;
	size_t only_qsc;
	size_t mutations;
	size_t canonical_open;
	size_t canonical_qsc;
	bool qok;
	bool ook;
	bool ok;

	ok = true;
	only_open = 0U;
	only_qsc = 0U;
	mutations = 0U;
	canonical_open = 0U;
	canonical_qsc = 0U;

	for (size_t length = 1U; length <= sizeof(valid) && ok == true; ++length)
	{
		for (size_t pos = 0U; pos < length && ok == true; ++pos)
		{
			for (size_t value = 0U; value < 256U && ok == true; ++value)
			{
				memcpy(input, valid, sizeof(valid));
				input[pos] = (uint8_t)value;
				consumed = 0U;
				qok = qsc_encoding_der_validate(input, length, &consumed);
				ook = test_openssl_der_exact(input, length);

				if (qok == true && consumed == length)
				{
					++canonical_qsc;
				}

				if (ook == true)
				{
					++canonical_open;
				}

				/* Report acceptance differences separately: OpenSSL's ASN1_TYPE is
				 * a typed BER decoder, not a complete strict DER validity oracle. */
				if ((qok && consumed == length) != ook)
				{
					++test_differences;
					if (qok && consumed == length) { ++only_qsc; if (only_qsc <= 3U) { fprintf(stderr,"QSC-only case=%zu pos=%zu input=",value,pos); for (size_t z=0U;z<length;++z) fprintf(stderr,"%02X",input[z]); fprintf(stderr,"\n"); } } else { ++only_open; if (only_open <= 3U) { fprintf(stderr,"OpenSSL-only case=%zu pos=%zu input=",value,pos); for (size_t z=0U;z<length;++z) fprintf(stderr,"%02X",input[z]); fprintf(stderr,"\n"); } }
				}

				if (qok == true && (consumed == 0U || consumed > length))
				{
					test_error("DER mutation", value, "QSC returned impossible consumed value");
					ok = false;
				}
				else if (qok == true && consumed == length && (input[0U] & 0x20U) != 0U)
				{
					slice = NULL;
					childlen = 0U;
					(void)qsc_asn1_der_get_child_region(input, length, 0U, &slice, &childlen);
				}

				++test_cases;
				++mutations;
			}
		}
	}

	printf("%s: %zu exhaustive position/byte mutation cases; OpenSSL canonical=%zu QSC full=%zu format divergences=%zu OpenSSL-only=%zu QSC-only=%zu\n", ok ? "PASS" : "FAIL", mutations, canonical_open, canonical_qsc, test_differences, only_open, only_qsc);
	return ok;
}

/** \brief Check short-buffer and padding rules without presuming OpenSSL identical permissive parsing. \return True on pass. */
static bool qsctest_encoding_openssl_edge_cases_test(void)
{
	static const char* invalid64[] = { "A", "AAA", "AA=A", "A===", "AAAA=", "AA==AA==", "A A=", "!!!!", "AA?A", "AAAA====", "=AAA" };
	static const char* badhex[] = { "0", "Z0", "00Z0", "0x01", "aa:bb", "0g", "aa " };
	uint8_t output[40U];
	uint8_t ref[40U];
	char hex[40U];
	char valid64[40U];
	size_t written;
	bool ok;

	ok = true;

	for (size_t i = 0U; i < sizeof(invalid64) / sizeof(invalid64[0]) && ok == true; ++i)
	{
		memset(output, 0xDA, sizeof(output));
		ok = !qsc_encoding_base64_decode(output, sizeof(output), invalid64[i], strlen(invalid64[i]));
		ok = (ok && output[0U] == 0xDAU);
	}

	for (size_t i = 0U; i < sizeof(badhex) / sizeof(badhex[0]) && ok == true; ++i)
	{
		written = 101U;
		ok = !qsc_encoding_hex_decode(badhex[i], strlen(badhex[i]), output, sizeof(output), &written);
		ok = (ok && written == 0U);
	}

	ok = (ok && qsc_encoding_base64_encoded_size(SIZE_MAX) == 0U);
	ok = (ok && qsc_encoding_base64_encoded_size(SIZE_MAX - 1U) == 0U);
	ok = (ok && qsc_encoding_hex_encode((const uint8_t*)"x", 1U, hex, sizeof(hex)));
	ok = (ok && qsc_encoding_base64_encode(valid64, sizeof(valid64), (const uint8_t*)"x", 1U));
	memset(output, 0xBC, sizeof(output));
	ok = (ok && !qsc_encoding_base64_decode(output, 0U, valid64, 4U));
	ok = (ok && output[0U] == 0xBCU);
	ok = (ok && !qsc_encoding_hex_encode((const uint8_t*)"x", 1U, hex, 2U));
	ok = (ok && qsc_encoding_hex_decode(hex, 2U, ref, sizeof(ref), &written));

	printf("%s: invalid encodings, canaries, short buffers and integer overflow\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Compare complete Base64 padding-bit combinations with OpenSSL EVP. \return True on exact equality. */
static bool qsctest_encoding_openssl_base64_padding_exhaustive_test(void)
{
	static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	uint8_t result[4U];
	uint8_t independent[4U];
	char str[5U];
	int got;
	size_t cases;
	bool ok;

	ok = true;
	cases = 0U;
	str[4U] = '\0';

	for (size_t first = 0U; first < 64U && ok == true; ++first)
	{
		for (size_t second = 0U; second < 64U && ok == true; ++second)
		{
			str[0U] = alphabet[first];
			str[1U] = alphabet[second];
			str[2U] = '=';
			str[3U] = '=';
			got = EVP_DecodeBlock(independent, (const unsigned char*)str, 4);
			ok = (got == 3 && qsc_encoding_base64_decode(result, sizeof(result), str, 4U));
			ok = (ok && independent[0U] == result[0U]);
			++cases;

			for (size_t third = 0U; third < 64U && ok == true; ++third)
			{
				str[2U] = alphabet[third];
				str[3U] = '=';
				got = EVP_DecodeBlock(independent, (const unsigned char*)str, 4);
				ok = (got == 3 && qsc_encoding_base64_decode(result, sizeof(result), str, 4U));
				ok = (ok && independent[0U] == result[0U] && independent[1U] == result[1U]);
				++cases;
			}
		}
	}

	if (ok == false)
	{
		test_error("Base64 padding exhaustive", cases, "QSC and OpenSSL decoded payload differs");
	}

	printf("%s: exhaustive Base64 padded quartets (%zu, including nonzero unused bits)\n", ok ? "PASS" : "FAIL", cases);
	test_cases += cases;
	return ok;
}

/** \brief Compare encoded ASN.1 headers to independent OpenSSL ASN1_put_object.
 * \return True when tag and definite-length encodings are exactly equal. */
static bool qsctest_encoding_openssl_asn1_tag_length_openssl_test(void)
{
	static const int tags[] = { 0, 1, 2, 3, 4, 5, 16, 17, 30, 31, 32, 127, 128, 16383, 16384, 65535, 16777215 };
	static const int lengths[] = { 0, 1, 2, 3, 126, 127, 128, 129, 254, 255, 256, 257, 65535, 65536, 16777215 };
	static const int classes[] = { V_ASN1_UNIVERSAL, V_ASN1_APPLICATION, V_ASN1_CONTEXT_SPECIFIC, V_ASN1_PRIVATE };
	uint8_t encoded[30U];
	uint8_t independent[30U];
	unsigned char* p;
	size_t tlen;
	size_t llen;
	size_t count;
	bool ok;

	ok = true;
	count = 0U;

	for (size_t ci = 0U; ci < sizeof(classes) / sizeof(classes[0U]) && ok == true; ++ci)
	{
		for (size_t ti = 0U; ti < sizeof(tags) / sizeof(tags[0U]) && ok == true; ++ti)
		{
			for (size_t li = 0U; li < sizeof(lengths) / sizeof(lengths[0U]) && ok == true; ++li)
			{
				for (int constructed = 0; constructed <= 1 && ok == true; ++constructed)
				{
					memset(encoded, 0xA9, sizeof(encoded));
					memset(independent, 0xC7, sizeof(independent));
					tlen = qsc_encoding_ber_encode_tag((uint8_t)classes[ci], constructed != 0, (uint32_t)tags[ti], encoded, sizeof(encoded));
					llen = qsc_encoding_ber_encode_length((size_t)lengths[li], encoded + tlen, sizeof(encoded) - tlen);
					p = independent;
					ASN1_put_object(&p, constructed, lengths[li], tags[ti], classes[ci]);
					ok = (tlen != 0U && llen != 0U && (size_t)(p - independent) == tlen + llen);
					ok = (ok && memcmp(encoded, independent, tlen + llen) == 0);
					++count;

					if (ok == false)
					{
						fprintf(stderr, "FAIL: ASN.1 OpenSSL header compare tag=%d length=%d class=%d constructed=%d\n", tags[ti], lengths[li], classes[ci], constructed);
					}
				}
			}
		}
	}

	printf("%s: %zu OpenSSL ASN.1 tag/class/length header comparisons\n", ok ? "PASS" : "FAIL", count);
	test_cases += count;
	return ok;
}

/** \brief Verify short/long-form DER lengths and OpenSSL-generated OCTET STRING encodings.
 * \return True on exact size, byte and decode comparison. */
static bool qsctest_encoding_openssl_der_octet_boundaries_test(void)
{
	static const size_t lengths[] = { 0U, 1U, 2U, 3U, 126U, 127U, 128U, 129U, 254U, 255U, 256U, 257U, 1023U, 1024U, 65534U, 65535U, 65536U };
	uint8_t source[65536U];
	uint8_t der[66000U];
	uint8_t recoded[66000U];
	ASN1_OCTET_STRING* str;
	qsc_encoding_ber_element* elem;
	unsigned char* ptr;
	const unsigned char* readptr;
	size_t consumed;
	size_t size;
	int n;
	bool ok;

	ok = true;

	for (size_t i = 0U; i < sizeof(lengths) / sizeof(lengths[0U]) && ok == true; ++i)
	{
		for (size_t k = 0U; k < lengths[i]; ++k)
		{
			source[k] = (uint8_t)(k * 37U + i);
		}

		str = ASN1_OCTET_STRING_new();
		ok = (str != NULL);
		ok = (ok && ASN1_OCTET_STRING_set(str, source, (int)lengths[i]) == 1);
		ptr = der;
		n = (ok == true) ? i2d_ASN1_OCTET_STRING(str, &ptr) : -1;
		ASN1_OCTET_STRING_free(str);
		ok = (ok && n > 0);
		consumed = 0U;
		ok = (ok && qsc_encoding_der_validate(der, (size_t)n, &consumed) && consumed == (size_t)n);
		elem = NULL;

		if (ok == true)
		{
			elem = qsc_encoding_der_decode_element(der, (size_t)n, &consumed);
			ok = (elem != NULL && consumed == (size_t)n);
		}

		if (ok == true)
		{
			size = qsc_encoding_der_encode_element(elem, NULL, 0U);
			ok = (size == (size_t)n && qsc_encoding_der_encode_element(elem, recoded, sizeof(recoded)) == size);
			ok = (ok && memcmp(der, recoded, size) == 0);
		}

		qsc_encoding_ber_free_element(elem);
		readptr = der;
		ok = (ok && test_openssl_der_exact(readptr, (size_t)n));

		if (ok == false)
		{
			test_error("OpenSSL DER octet boundaries", i, "size/header/data/encoding differs");
		}
		else
		{
			++test_cases;
		}
	}

	printf("%s: all 17 ASN.1 DER length boundaries, including 65,536 bytes\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Check exact OpenSSL DER headers at the recursion-depth limit. \return True on pass. */
static bool qsctest_encoding_openssl_der_nested_boundaries_test(void)
{
	uint8_t current[512U];
	uint8_t next[512U];
	uint8_t header[20U];
	const uint8_t* child;
	unsigned char* ptr;
	size_t len;
	size_t hlen;
	size_t got;
	size_t consumed;
	bool ok;

	ok = true;
	current[0U] = 0x04U;
	current[1U] = 0x01U;
	current[2U] = 0x42U;
	len = 3U;

	for (size_t depth = 1U; depth <= 35U && ok == true; ++depth)
	{
		ptr = header;
		ASN1_put_object(&ptr, 1, (int)len, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
		hlen = (size_t)(ptr - header);
		memcpy(next, header, hlen);
		memcpy(next + hlen, current, len);
		len += hlen;
		memcpy(current, next, len);
		consumed = 0U;

		if (depth <= 32U)
		{
			ok = qsc_encoding_der_validate(current, len, &consumed);
			ok = (ok && consumed == len);
			child = NULL;
			got = 0U;
			ok = (ok && qsc_asn1_der_get_child_region(current, len, 0U, &child, &got) == QSC_ASN1_STATUS_SUCCESS);
			ok = (ok && child == current + hlen && got == len - hlen);
		}
		else
		{
			ok = !qsc_encoding_der_validate(current, len, &consumed);
		}

		if (ok == false)
		{
			test_error("OpenSSL DER nesting limit", depth, "depth handling mismatch");
		}
	}

	printf("%s: 35 nested OpenSSL-encoded DER sequences and QSC depth guard\n", ok ? "PASS" : "FAIL");
	return ok;
}

/** \brief Check standards-mandated DER universal primitive canonical forms. \return True on pass. */
static bool qsctest_encoding_openssl_der_universal_canonical_test(void)
{
	static const uint8_t invalid[][6U] = {
		{ 0x01U, 0x00U }, { 0x01U, 0x01U, 0x01U },
		{ 0x01U, 0x02U, 0x00U, 0x00U }, { 0x05U, 0x01U, 0x00U },
		{ 0x02U, 0x00U }, { 0x02U, 0x02U, 0x00U, 0x01U },
		{ 0x02U, 0x02U, 0xFFU, 0x80U }, { 0x03U, 0x00U },
		{ 0x03U, 0x01U, 0x01U }, { 0x03U, 0x02U, 0x07U, 0x01U },
		{ 0x24U, 0x00U }, { 0x06U, 0x00U },
		{ 0x10U, 0x00U }, { 0x11U, 0x00U },
		{ 0x00U, 0x00U }
	};
	static const size_t invalidlen[] = { 2U, 3U, 4U, 3U, 2U, 4U, 4U, 2U, 3U, 4U, 2U, 2U, 2U, 2U, 2U };
	static const uint8_t valid[][5U] = {
		{ 0x01U, 0x01U, 0x00U }, { 0x01U, 0x01U, 0xFFU },
		{ 0x02U, 0x01U, 0x00U }, { 0x02U, 0x01U, 0x80U },
		{ 0x02U, 0x02U, 0x00U, 0x80U }, { 0x02U, 0x02U, 0xFFU, 0x7FU },
		{ 0x03U, 0x01U, 0x00U }, { 0x03U, 0x02U, 0x03U, 0xE0U },
		{ 0x05U, 0x00U }, { 0x30U, 0x00U }, { 0x31U, 0x00U },
		{ 0x06U, 0x02U, 0x2AU, 0x03U }
	};
	static const size_t validlen[] = { 3U, 3U, 3U, 3U, 4U, 4U, 3U, 4U, 2U, 2U, 2U, 4U };
	size_t consumed;
	bool ok;

	ok = true;

	for (size_t i = 0U; i < sizeof(invalidlen) / sizeof(invalidlen[0U]) && ok == true; ++i)
	{
		consumed = SIZE_MAX;
		ok = !qsc_encoding_der_validate(invalid[i], invalidlen[i], &consumed);
		ok = (ok && consumed == 0U);

		if (ok == false)
		{
			test_error("DER noncanonical universal", i, "QSC accepted an invalid DER universal element");
		}
	}

	for (size_t i = 0U; i < sizeof(validlen) / sizeof(validlen[0U]) && ok == true; ++i)
	{
		consumed = 0U;
		ok = qsc_encoding_der_validate(valid[i], validlen[i], &consumed);
		ok = (ok && consumed == validlen[i]);

		if (ok == false)
		{
			test_error("DER canonical universal", i, "QSC rejected a valid DER universal element");
		}
	}

	printf("%s: 15 invalid and 12 valid universal primitive/constructed DER forms\n", ok ? "PASS" : "FAIL");
	test_cases += (sizeof(invalidlen) / sizeof(invalidlen[0U])) + (sizeof(validlen) / sizeof(validlen[0U]));
	return ok;
}

/** \brief Differential fuzz invalid and valid Base64 quartets against EVP_DecodeBlock.
 * \return True when shared-accepted inputs yield identical outputs. */
static bool qsctest_encoding_openssl_base64_malformed_openssl_test(void)
{
	uint8_t qout[64U];
	uint8_t oout[64U];
	char input[64U];
	size_t length;
	size_t pad;
	size_t both;
	size_t qonly;
	size_t oonly;
	int decoded;
	bool qok;
	bool ook;
	bool ok;

	ok = true;
	both = 0U;
	qonly = 0U;
	oonly = 0U;

	for (size_t run = 0U; run < 200000U && ok == true; ++run)
	{
		length = 4U * (1U + (size_t)(test_random() % 16U));

		for (size_t i = 0U; i < length; ++i)
		{
			input[i] = (char)test_random();
		}

		if ((run % 2U) == 0U)
		{
			for (size_t i = 0U; i < length; ++i)
			{
				input[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[test_random() % 64U];
			}
		}

		if ((run % 3U) == 0U)
		{
			input[length - 1U] = '=';
		}

		if ((run % 5U) == 0U)
		{
			input[length - 2U] = '=';
			input[length - 1U] = '=';
		}

		memset(qout, 0x7FU, sizeof(qout));
		memset(oout, 0x6EU, sizeof(oout));
		qok = qsc_encoding_base64_decode(qout, sizeof(qout), input, length);
		decoded = EVP_DecodeBlock(oout, (const unsigned char*)input, (int)length);
		ook = (decoded >= 0);

		if (qok == true && ook == true)
		{
			pad = 0U;

			if (input[length - 1U] == '=')
			{
				++pad;
			}

			if (input[length - 2U] == '=')
			{
				++pad;
			}

			ok = ((size_t)decoded >= pad && memcmp(qout, oout, (size_t)decoded - pad) == 0);
			++both;
		}
		else if (qok == true)
		{
			++qonly;
		}
		else if (ook == true)
		{
			++oonly;
		}

		if (ok == false)
		{
			test_error("Malformed Base64 EVP differential", run, "shared-accepted byte values differ");
		}
	}

	test_cases += 200000U;
	test_differences += qonly + oonly;
	printf("%s: 200,000 Base64 syntax mutations; both-accepted=%zu QSC-only=%zu OpenSSL-only=%zu\n", ok ? "PASS" : "FAIL", both, qonly, oonly);
	return ok;
}

/** \brief Exhaustively substitute all octets into hexadecimal nibble positions.
 * \return True when OpenSSL and QSC return equal bytes for shared-accepted inputs. */
static bool qsctest_encoding_openssl_hex_malformed_openssl_test(void)
{
	uint8_t qout[4U];
	unsigned char oout[4U];
	char input[5U] = "AABC";
	size_t qlen;
	size_t olen;
	size_t both;
	size_t qonly;
	size_t oonly;
	bool qok;
	bool ook;
	bool ok;

	ok = true;
	both = 0U;
	qonly = 0U;
	oonly = 0U;

	for (size_t pos = 0U; pos < 4U && ok == true; ++pos)
	{
		for (size_t value = 0U; value < 256U && ok == true; ++value)
		{
			input[0U] = 'A';
			input[1U] = 'A';
			input[2U] = 'B';
			input[3U] = 'C';
			input[pos] = (char)value;
			/* NUL terminates the OpenSSL text-only hexadecimal parser. */
			if (value != 0U)
			{
				qlen = 0U;
				olen = 0U;
				qok = qsc_encoding_hex_decode(input, 4U, qout, sizeof(qout), &qlen);
				ook = OPENSSL_hexstr2buf_ex(oout, sizeof(oout), &olen, input, '\0') == 1;

				if (qok == true && ook == true)
				{
					ok = (qlen == olen && memcmp(qout, oout, qlen) == 0);
					++both;
				}
				else if (qok == true)
				{
					++qonly;
				}
				else if (ook == true)
				{
					++oonly;
				}

				if (ok == false)
				{
					test_error("Malformed hex OpenSSL differential", pos * 256U + value, "shared-accepted bytes differ");
				}
			}
		}
	}

	test_cases += 1020U;
	test_differences += qonly + oonly;
	printf("%s: 1,020 hex position/byte substitutions; both-accepted=%zu QSC-only=%zu OpenSSL-only=%zu\n", ok ? "PASS" : "FAIL", both, qonly, oonly);
	return ok;
}

/** \brief Check ASN.1 DER size against OpenSSL and reject integer arithmetic overflow.
 * \return True when all byte sizes and overflow status values are correct. */
static bool qsctest_encoding_openssl_asn1_der_size_boundaries_test(void)
{
	qsc_encoding_ber_element huge;
	qsc_encoding_ber_element children[2U];
	qsc_encoding_ber_element parent;
	qsc_encoding_ber_element* links[2U];
	uint8_t value;
	size_t length;
	bool ok;

	ok = true;
	value = 0U;
	memset(&huge, 0, sizeof(huge));
	huge.tagclass = QSC_ENCODING_BER_CLASS_UNIVERSAL;
	huge.tagnumber = 4U;
	huge.value = &value;
	huge.length = SIZE_MAX - 2U;
	length = 27U;
	ok = (qsc_asn1_der_size(&huge, &length) == QSC_ASN1_STATUS_OUT_OF_RANGE);
	ok = (ok && length == 27U);

	memset(children, 0, sizeof(children));
	memset(&parent, 0, sizeof(parent));
	children[0U].tagclass = QSC_ENCODING_BER_CLASS_UNIVERSAL;
	children[1U].tagclass = QSC_ENCODING_BER_CLASS_UNIVERSAL;
	children[0U].tagnumber = 4U;
	children[1U].tagnumber = 4U;
	children[0U].length = SIZE_MAX / 2U - 6U;
	children[1U].length = SIZE_MAX / 2U - 6U;
	children[0U].value = &value;
	children[1U].value = &value;
	links[0U] = &children[0U];
	links[1U] = &children[1U];
	parent.tagclass = QSC_ENCODING_BER_CLASS_UNIVERSAL;
	parent.tagnumber = 16U;
	parent.constructed = true;
	parent.children = links;
	parent.ccount = 2U;
	length = 31U;
	ok = (ok && qsc_asn1_der_size(&parent, &length) == QSC_ASN1_STATUS_OUT_OF_RANGE);
	ok = (ok && length == 31U);

	if (ok == false)
	{
		test_error("ASN.1 DER size overflow", 0U, "size wrapped or error damaged output");
	}

	printf("%s: ASN.1 primitive and accumulated-child SIZE_MAX overflow\n", ok ? "PASS" : "FAIL");
	return ok;
}


/** \brief OpenSSL-generated RSA X.509 certificate (DER), read-only test vector. */
static const uint8_t qsctest_openssl_rsa_der[] =
{
	0x30U, 0x82U, 0x03U, 0x3DU, 0x30U, 0x82U, 0x02U, 0x25U, 0xA0U, 0x03U, 0x02U, 0x01U,
	0x02U, 0x02U, 0x14U, 0x2EU, 0x82U, 0x2BU, 0xD0U, 0x7CU, 0x9CU, 0x36U, 0x3EU, 0xFDU,
	0xF4U, 0xF8U, 0x3AU, 0xABU, 0x69U, 0xFCU, 0x35U, 0x6BU, 0xD8U, 0x11U, 0x01U, 0x30U,
	0x0DU, 0x06U, 0x09U, 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0BU,
	0x05U, 0x00U, 0x30U, 0x2EU, 0x31U, 0x1DU, 0x30U, 0x1BU, 0x06U, 0x03U, 0x55U, 0x04U,
	0x03U, 0x0CU, 0x14U, 0x51U, 0x53U, 0x43U, 0x20U, 0x64U, 0x69U, 0x66U, 0x66U, 0x65U,
	0x72U, 0x65U, 0x6EU, 0x74U, 0x69U, 0x61U, 0x6CU, 0x20U, 0x52U, 0x53U, 0x41U, 0x31U,
	0x0DU, 0x30U, 0x0BU, 0x06U, 0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU, 0x04U, 0x51U, 0x52U,
	0x43U, 0x53U, 0x30U, 0x1EU, 0x17U, 0x0DU, 0x32U, 0x36U, 0x31U, 0x30U, 0x32U, 0x38U,
	0x30U, 0x31U, 0x35U, 0x38U, 0x35U, 0x35U, 0x5AU, 0x17U, 0x0DU, 0x32U, 0x36U, 0x31U,
	0x30U, 0x32U, 0x39U, 0x30U, 0x31U, 0x35U, 0x38U, 0x35U, 0x35U, 0x5AU, 0x30U, 0x2EU,
	0x31U, 0x1DU, 0x30U, 0x1BU, 0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x14U, 0x51U,
	0x53U, 0x43U, 0x20U, 0x64U, 0x69U, 0x66U, 0x66U, 0x65U, 0x72U, 0x65U, 0x6EU, 0x74U,
	0x69U, 0x61U, 0x6CU, 0x20U, 0x52U, 0x53U, 0x41U, 0x31U, 0x0DU, 0x30U, 0x0BU, 0x06U,
	0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU, 0x04U, 0x51U, 0x52U, 0x43U, 0x53U, 0x30U, 0x82U,
	0x01U, 0x22U, 0x30U, 0x0DU, 0x06U, 0x09U, 0x2AU, 0x86U, 0x48U, 0x86U, 0xF7U, 0x0DU,
	0x01U, 0x01U, 0x01U, 0x05U, 0x00U, 0x03U, 0x82U, 0x01U, 0x0FU, 0x00U, 0x30U, 0x82U,
	0x01U, 0x0AU, 0x02U, 0x82U, 0x01U, 0x01U, 0x00U, 0xBEU, 0x46U, 0xBEU, 0x14U, 0x54U,
	0x82U, 0x75U, 0x27U, 0x8CU, 0x51U, 0xCFU, 0xC0U, 0x0FU, 0x4BU, 0x5EU, 0x95U, 0x67U,
	0x09U, 0xB8U, 0x8FU, 0xA7U, 0x09U, 0x03U, 0x79U, 0xFFU, 0xBEU, 0x7DU, 0x6CU, 0x08U,
	0x02U, 0x09U, 0x76U, 0x6DU, 0xD1U, 0xCDU, 0x36U, 0x0FU, 0x54U, 0xE4U, 0xDCU, 0x4FU,
	0x7EU, 0x94U, 0x31U, 0x1AU, 0x50U, 0x35U, 0xF6U, 0x20U, 0x7CU, 0x13U, 0xF8U, 0x29U,
	0x5BU, 0x0EU, 0x8DU, 0x46U, 0x02U, 0x75U, 0x8CU, 0xFBU, 0x86U, 0x78U, 0xBCU, 0xE9U,
	0x22U, 0x94U, 0x92U, 0x06U, 0x92U, 0x6BU, 0xF2U, 0xE8U, 0x83U, 0xF4U, 0x46U, 0x2BU,
	0xD0U, 0xFCU, 0x74U, 0x1AU, 0x72U, 0x92U, 0xE4U, 0x47U, 0x4BU, 0x8BU, 0x58U, 0x87U,
	0x9DU, 0xD9U, 0x35U, 0x67U, 0x03U, 0x9BU, 0xDCU, 0xEFU, 0x80U, 0x76U, 0x92U, 0x3EU,
	0x74U, 0xC0U, 0xF8U, 0xF7U, 0x17U, 0x81U, 0xD2U, 0xD4U, 0x32U, 0xEBU, 0xC0U, 0x71U,
	0xEEU, 0x80U, 0xF2U, 0xD4U, 0x31U, 0x53U, 0x69U, 0xDDU, 0x6CU, 0xA8U, 0xFBU, 0xA9U,
	0x60U, 0x6EU, 0x89U, 0x48U, 0x54U, 0x7FU, 0xE9U, 0x5BU, 0x98U, 0x2CU, 0xA1U, 0x3DU,
	0x3AU, 0x75U, 0xF6U, 0x96U, 0x13U, 0x76U, 0x58U, 0x12U, 0xA7U, 0x00U, 0x64U, 0xFAU,
	0xA5U, 0x26U, 0x69U, 0xE8U, 0x88U, 0x4BU, 0x13U, 0x39U, 0xBDU, 0xEFU, 0x9CU, 0xE0U,
	0xB0U, 0x66U, 0x30U, 0xA9U, 0x6AU, 0x5BU, 0xD4U, 0x7BU, 0xB3U, 0x18U, 0x27U, 0xCBU,
	0xF2U, 0xC8U, 0x16U, 0xF4U, 0xB2U, 0x71U, 0x93U, 0x68U, 0xA8U, 0x79U, 0x0CU, 0xB0U,
	0xB9U, 0xDCU, 0x4FU, 0x48U, 0x77U, 0x06U, 0xB0U, 0xD8U, 0xC9U, 0x75U, 0xAEU, 0x88U,
	0xFCU, 0xBBU, 0x74U, 0x13U, 0xAFU, 0x33U, 0x18U, 0xDAU, 0x8EU, 0x6AU, 0x2EU, 0x4FU,
	0x09U, 0x5FU, 0x3CU, 0xC5U, 0xB1U, 0xACU, 0x7EU, 0x15U, 0x22U, 0xFDU, 0x33U, 0xB4U,
	0x6BU, 0x7FU, 0x10U, 0x61U, 0xC5U, 0x07U, 0x9DU, 0x52U, 0x91U, 0xA6U, 0x8CU, 0x34U,
	0x1CU, 0x66U, 0x61U, 0x71U, 0xCAU, 0x01U, 0x36U, 0x43U, 0x05U, 0x64U, 0x30U, 0xB0U,
	0x27U, 0x4CU, 0x4AU, 0x60U, 0x6BU, 0x66U, 0xD7U, 0xC1U, 0x1EU, 0x5EU, 0x63U, 0x02U,
	0x03U, 0x01U, 0x00U, 0x01U, 0xA3U, 0x53U, 0x30U, 0x51U, 0x30U, 0x1DU, 0x06U, 0x03U,
	0x55U, 0x1DU, 0x0EU, 0x04U, 0x16U, 0x04U, 0x14U, 0x7BU, 0x92U, 0x09U, 0xDDU, 0x74U,
	0x86U, 0xD1U, 0x4CU, 0xD6U, 0x89U, 0xF6U, 0x08U, 0x10U, 0xD7U, 0xC1U, 0x49U, 0x97U,
	0x8EU, 0x4BU, 0x77U, 0x30U, 0x1FU, 0x06U, 0x03U, 0x55U, 0x1DU, 0x23U, 0x04U, 0x18U,
	0x30U, 0x16U, 0x80U, 0x14U, 0x7BU, 0x92U, 0x09U, 0xDDU, 0x74U, 0x86U, 0xD1U, 0x4CU,
	0xD6U, 0x89U, 0xF6U, 0x08U, 0x10U, 0xD7U, 0xC1U, 0x49U, 0x97U, 0x8EU, 0x4BU, 0x77U,
	0x30U, 0x0FU, 0x06U, 0x03U, 0x55U, 0x1DU, 0x13U, 0x01U, 0x01U, 0xFFU, 0x04U, 0x05U,
	0x30U, 0x03U, 0x01U, 0x01U, 0xFFU, 0x30U, 0x0DU, 0x06U, 0x09U, 0x2AU, 0x86U, 0x48U,
	0x86U, 0xF7U, 0x0DU, 0x01U, 0x01U, 0x0BU, 0x05U, 0x00U, 0x03U, 0x82U, 0x01U, 0x01U,
	0x00U, 0x89U, 0xE8U, 0x01U, 0xF7U, 0xB7U, 0xBFU, 0x9EU, 0x73U, 0x62U, 0xDDU, 0x79U,
	0x60U, 0x8AU, 0xA2U, 0x63U, 0x9BU, 0x1CU, 0x3FU, 0x44U, 0xCDU, 0x6DU, 0x39U, 0x3AU,
	0xD7U, 0xD3U, 0x82U, 0xCBU, 0x14U, 0x2DU, 0xFDU, 0x56U, 0xE6U, 0x4BU, 0xBFU, 0xF3U,
	0x88U, 0xF3U, 0x69U, 0x93U, 0xCCU, 0xAFU, 0x5FU, 0x96U, 0xD3U, 0xA0U, 0x68U, 0x66U,
	0xC9U, 0xE6U, 0x55U, 0xEEU, 0x9AU, 0xD9U, 0x60U, 0xDBU, 0x55U, 0x25U, 0x67U, 0x96U,
	0x04U, 0xEDU, 0xC2U, 0xE9U, 0x03U, 0x8FU, 0xAFU, 0xE7U, 0xBCU, 0xF0U, 0xA8U, 0xA6U,
	0x62U, 0x26U, 0x06U, 0x98U, 0xE4U, 0x34U, 0x63U, 0x2EU, 0x36U, 0x78U, 0x2DU, 0x94U,
	0x5DU, 0xC5U, 0x30U, 0x97U, 0xB6U, 0x69U, 0x15U, 0x7DU, 0xDBU, 0xBEU, 0x1FU, 0xA3U,
	0x26U, 0x13U, 0x59U, 0xE0U, 0xFCU, 0x4EU, 0xD2U, 0xD2U, 0x4BU, 0x07U, 0x93U, 0x35U,
	0xB8U, 0xACU, 0x17U, 0x96U, 0x48U, 0x47U, 0x7DU, 0xC2U, 0xC7U, 0x0CU, 0xBAU, 0x71U,
	0x5EU, 0xCAU, 0xE0U, 0x76U, 0x0FU, 0x92U, 0xD7U, 0xADU, 0x7DU, 0xB4U, 0xA1U, 0x9AU,
	0x6EU, 0x18U, 0x7AU, 0x64U, 0x46U, 0x36U, 0x24U, 0x4FU, 0x69U, 0x75U, 0x7DU, 0xB2U,
	0xFAU, 0xEEU, 0x12U, 0xDEU, 0x56U, 0x83U, 0x4EU, 0x32U, 0x84U, 0x91U, 0xBDU, 0xE3U,
	0x65U, 0x42U, 0xD6U, 0x46U, 0x68U, 0xE1U, 0xDCU, 0x7FU, 0x62U, 0xBFU, 0x9EU, 0x79U,
	0xF6U, 0x6FU, 0xD1U, 0x3EU, 0x4EU, 0x14U, 0xF8U, 0x74U, 0x57U, 0xB4U, 0x0BU, 0xD8U,
	0xE9U, 0x82U, 0xC9U, 0x45U, 0x3EU, 0xEAU, 0xCDU, 0xA7U, 0x10U, 0x36U, 0x91U, 0x87U,
	0x1FU, 0x91U, 0x35U, 0x34U, 0x31U, 0x60U, 0xE1U, 0x3CU, 0xF0U, 0x6AU, 0x50U, 0x99U,
	0x7CU, 0x6FU, 0x55U, 0x2BU, 0xA9U, 0x51U, 0xF6U, 0xAAU, 0x53U, 0xFBU, 0x9AU, 0x1CU,
	0xB1U, 0x4AU, 0xCBU, 0x16U, 0x00U, 0xDCU, 0x08U, 0xA1U, 0x0CU, 0xCEU, 0x9CU, 0xF1U,
	0x45U, 0xB5U, 0x43U, 0xC0U, 0x08U, 0xF0U, 0x25U, 0xB7U, 0x92U, 0xADU, 0xD0U, 0x01U,
	0xAFU, 0x9FU, 0x90U, 0x9FU, 0xC7U, 0xC1U, 0x9FU, 0xB1U, 0x4DU, 0x1BU, 0x8CU, 0x61U,
	0x36U, 0xE5U, 0x1EU, 0x40U, 0x0BU
};

/** \brief OpenSSL-generated ECP256 X.509 certificate (DER), read-only test vector. */
static const uint8_t qsctest_openssl_ecp256_der[] =
{
	0x30U, 0x82U, 0x01U, 0xB5U, 0x30U, 0x82U, 0x01U, 0x5BU, 0xA0U, 0x03U, 0x02U, 0x01U,
	0x02U, 0x02U, 0x14U, 0x77U, 0xA6U, 0x59U, 0x19U, 0x76U, 0x10U, 0xA9U, 0x9CU, 0xCBU,
	0x44U, 0xE0U, 0x2EU, 0xF2U, 0x97U, 0x81U, 0x42U, 0xDCU, 0xF4U, 0xE7U, 0x4FU, 0x30U,
	0x0AU, 0x06U, 0x08U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x02U, 0x30U,
	0x30U, 0x31U, 0x1FU, 0x30U, 0x1DU, 0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x16U,
	0x51U, 0x53U, 0x43U, 0x20U, 0x64U, 0x69U, 0x66U, 0x66U, 0x65U, 0x72U, 0x65U, 0x6EU,
	0x74U, 0x69U, 0x61U, 0x6CU, 0x20U, 0x45U, 0x43U, 0x44U, 0x53U, 0x41U, 0x31U, 0x0DU,
	0x30U, 0x0BU, 0x06U, 0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU, 0x04U, 0x51U, 0x52U, 0x43U,
	0x53U, 0x30U, 0x1EU, 0x17U, 0x0DU, 0x32U, 0x36U, 0x31U, 0x30U, 0x32U, 0x38U, 0x30U,
	0x31U, 0x35U, 0x38U, 0x35U, 0x35U, 0x5AU, 0x17U, 0x0DU, 0x32U, 0x36U, 0x31U, 0x30U,
	0x32U, 0x39U, 0x30U, 0x31U, 0x35U, 0x38U, 0x35U, 0x35U, 0x5AU, 0x30U, 0x30U, 0x31U,
	0x1FU, 0x30U, 0x1DU, 0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x16U, 0x51U, 0x53U,
	0x43U, 0x20U, 0x64U, 0x69U, 0x66U, 0x66U, 0x65U, 0x72U, 0x65U, 0x6EU, 0x74U, 0x69U,
	0x61U, 0x6CU, 0x20U, 0x45U, 0x43U, 0x44U, 0x53U, 0x41U, 0x31U, 0x0DU, 0x30U, 0x0BU,
	0x06U, 0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU, 0x04U, 0x51U, 0x52U, 0x43U, 0x53U, 0x30U,
	0x59U, 0x30U, 0x13U, 0x06U, 0x07U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x02U, 0x01U,
	0x06U, 0x08U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U, 0x03U, 0x42U,
	0x00U, 0x04U, 0xFBU, 0x44U, 0xFBU, 0x24U, 0x9FU, 0x29U, 0xB0U, 0x1EU, 0x1EU, 0x07U,
	0x98U, 0x69U, 0x9BU, 0x74U, 0xE9U, 0x0BU, 0x89U, 0xB7U, 0xC4U, 0x72U, 0xF7U, 0x58U,
	0x8DU, 0x48U, 0x5FU, 0x2BU, 0xE1U, 0xF8U, 0x45U, 0xE9U, 0xA7U, 0x92U, 0x39U, 0x6BU,
	0x3BU, 0xB4U, 0x86U, 0xF8U, 0xE0U, 0x13U, 0x57U, 0x4BU, 0xA2U, 0xCEU, 0xF8U, 0x6AU,
	0x7CU, 0x1BU, 0xE7U, 0x9AU, 0x4EU, 0xD9U, 0xFBU, 0x0BU, 0x52U, 0xBDU, 0xF8U, 0x7AU,
	0xE9U, 0xEFU, 0xF5U, 0x0BU, 0xE3U, 0x86U, 0xA3U, 0x53U, 0x30U, 0x51U, 0x30U, 0x1DU,
	0x06U, 0x03U, 0x55U, 0x1DU, 0x0EU, 0x04U, 0x16U, 0x04U, 0x14U, 0xB0U, 0x11U, 0x32U,
	0xA6U, 0x7FU, 0xECU, 0x91U, 0xA5U, 0x90U, 0x49U, 0x62U, 0xB1U, 0x23U, 0xD0U, 0x06U,
	0x33U, 0xB8U, 0xF4U, 0x93U, 0x2FU, 0x30U, 0x1FU, 0x06U, 0x03U, 0x55U, 0x1DU, 0x23U,
	0x04U, 0x18U, 0x30U, 0x16U, 0x80U, 0x14U, 0xB0U, 0x11U, 0x32U, 0xA6U, 0x7FU, 0xECU,
	0x91U, 0xA5U, 0x90U, 0x49U, 0x62U, 0xB1U, 0x23U, 0xD0U, 0x06U, 0x33U, 0xB8U, 0xF4U,
	0x93U, 0x2FU, 0x30U, 0x0FU, 0x06U, 0x03U, 0x55U, 0x1DU, 0x13U, 0x01U, 0x01U, 0xFFU,
	0x04U, 0x05U, 0x30U, 0x03U, 0x01U, 0x01U, 0xFFU, 0x30U, 0x0AU, 0x06U, 0x08U, 0x2AU,
	0x86U, 0x48U, 0xCEU, 0x3DU, 0x04U, 0x03U, 0x02U, 0x03U, 0x48U, 0x00U, 0x30U, 0x45U,
	0x02U, 0x20U, 0x17U, 0x09U, 0x93U, 0x76U, 0xC9U, 0xF0U, 0x13U, 0xF1U, 0xF5U, 0x8BU,
	0x6AU, 0xE6U, 0x56U, 0xD4U, 0xB1U, 0x69U, 0xB1U, 0x2CU, 0xB5U, 0x5AU, 0x4FU, 0xB4U,
	0x64U, 0x54U, 0x08U, 0xF9U, 0xD3U, 0x17U, 0xE5U, 0x51U, 0x3FU, 0x29U, 0x02U, 0x21U,
	0x00U, 0xF8U, 0x06U, 0xA2U, 0x9EU, 0x11U, 0x2AU, 0x16U, 0xC7U, 0x15U, 0xE0U, 0xB0U,
	0xCEU, 0xE8U, 0xE4U, 0xB9U, 0xA2U, 0x62U, 0x3AU, 0xA0U, 0x95U, 0x4DU, 0x95U, 0x40U,
	0x3FU, 0xCCU, 0x81U, 0x26U, 0xCCU, 0x83U, 0x36U, 0xB3U, 0xD7U
};

/** \brief OpenSSL-generated ED25519 X.509 certificate (DER), read-only test vector. */
static const uint8_t qsctest_openssl_ed25519_der[] =
{
	0x30U, 0x82U, 0x01U, 0x79U, 0x30U, 0x82U, 0x01U, 0x2BU, 0xA0U, 0x03U, 0x02U, 0x01U,
	0x02U, 0x02U, 0x14U, 0x1CU, 0x70U, 0x26U, 0xE9U, 0x3DU, 0x32U, 0x6AU, 0xF0U, 0x99U,
	0xABU, 0xD4U, 0x4EU, 0x09U, 0x64U, 0xEAU, 0xFFU, 0x17U, 0xA5U, 0x1FU, 0x9DU, 0x30U,
	0x05U, 0x06U, 0x03U, 0x2BU, 0x65U, 0x70U, 0x30U, 0x32U, 0x31U, 0x21U, 0x30U, 0x1FU,
	0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x18U, 0x51U, 0x53U, 0x43U, 0x20U, 0x64U,
	0x69U, 0x66U, 0x66U, 0x65U, 0x72U, 0x65U, 0x6EU, 0x74U, 0x69U, 0x61U, 0x6CU, 0x20U,
	0x45U, 0x64U, 0x32U, 0x35U, 0x35U, 0x31U, 0x39U, 0x31U, 0x0DU, 0x30U, 0x0BU, 0x06U,
	0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU, 0x04U, 0x51U, 0x52U, 0x43U, 0x53U, 0x30U, 0x1EU,
	0x17U, 0x0DU, 0x32U, 0x36U, 0x31U, 0x30U, 0x32U, 0x38U, 0x30U, 0x31U, 0x35U, 0x38U,
	0x35U, 0x35U, 0x5AU, 0x17U, 0x0DU, 0x32U, 0x36U, 0x31U, 0x30U, 0x32U, 0x39U, 0x30U,
	0x31U, 0x35U, 0x38U, 0x35U, 0x35U, 0x5AU, 0x30U, 0x32U, 0x31U, 0x21U, 0x30U, 0x1FU,
	0x06U, 0x03U, 0x55U, 0x04U, 0x03U, 0x0CU, 0x18U, 0x51U, 0x53U, 0x43U, 0x20U, 0x64U,
	0x69U, 0x66U, 0x66U, 0x65U, 0x72U, 0x65U, 0x6EU, 0x74U, 0x69U, 0x61U, 0x6CU, 0x20U,
	0x45U, 0x64U, 0x32U, 0x35U, 0x35U, 0x31U, 0x39U, 0x31U, 0x0DU, 0x30U, 0x0BU, 0x06U,
	0x03U, 0x55U, 0x04U, 0x0AU, 0x0CU, 0x04U, 0x51U, 0x52U, 0x43U, 0x53U, 0x30U, 0x2AU,
	0x30U, 0x05U, 0x06U, 0x03U, 0x2BU, 0x65U, 0x70U, 0x03U, 0x21U, 0x00U, 0x22U, 0x5EU,
	0xACU, 0xBBU, 0x76U, 0xA8U, 0x0CU, 0xEAU, 0xFAU, 0xB5U, 0x50U, 0xDCU, 0xC5U, 0xB8U,
	0xF3U, 0xAFU, 0x66U, 0x0BU, 0xE1U, 0x0BU, 0xA8U, 0x65U, 0xB2U, 0x8BU, 0x38U, 0xB9U,
	0x10U, 0x7DU, 0x2CU, 0x39U, 0x7FU, 0x39U, 0xA3U, 0x53U, 0x30U, 0x51U, 0x30U, 0x1DU,
	0x06U, 0x03U, 0x55U, 0x1DU, 0x0EU, 0x04U, 0x16U, 0x04U, 0x14U, 0x39U, 0x48U, 0x46U,
	0x82U, 0x55U, 0x1FU, 0xF2U, 0xFCU, 0x3AU, 0x05U, 0x50U, 0xE8U, 0x15U, 0x82U, 0x91U,
	0x8AU, 0x54U, 0xE5U, 0x63U, 0x39U, 0x30U, 0x1FU, 0x06U, 0x03U, 0x55U, 0x1DU, 0x23U,
	0x04U, 0x18U, 0x30U, 0x16U, 0x80U, 0x14U, 0x39U, 0x48U, 0x46U, 0x82U, 0x55U, 0x1FU,
	0xF2U, 0xFCU, 0x3AU, 0x05U, 0x50U, 0xE8U, 0x15U, 0x82U, 0x91U, 0x8AU, 0x54U, 0xE5U,
	0x63U, 0x39U, 0x30U, 0x0FU, 0x06U, 0x03U, 0x55U, 0x1DU, 0x13U, 0x01U, 0x01U, 0xFFU,
	0x04U, 0x05U, 0x30U, 0x03U, 0x01U, 0x01U, 0xFFU, 0x30U, 0x05U, 0x06U, 0x03U, 0x2BU,
	0x65U, 0x70U, 0x03U, 0x41U, 0x00U, 0xB4U, 0xC5U, 0xE3U, 0xBFU, 0xC3U, 0x6DU, 0x25U,
	0x4AU, 0x51U, 0x05U, 0x85U, 0x3EU, 0xD9U, 0xB0U, 0x27U, 0x16U, 0x2EU, 0x66U, 0x15U,
	0x20U, 0x2AU, 0x78U, 0x3BU, 0x47U, 0xEEU, 0x58U, 0x32U, 0x07U, 0xA4U, 0x8BU, 0xCFU,
	0xADU, 0x04U, 0xB9U, 0x00U, 0x79U, 0xB6U, 0xE7U, 0xABU, 0x9EU, 0xC8U, 0x72U, 0xB5U,
	0x95U, 0x1BU, 0x70U, 0xFEU, 0x91U, 0x9EU, 0x5AU, 0xB0U, 0x66U, 0x0EU, 0x29U, 0x4EU,
	0x2AU, 0xC3U, 0x80U, 0xB4U, 0xC9U, 0x56U, 0xC7U, 0xA1U, 0x02U
};

/**
 * \brief Compare the original OpenSSL-produced X.509 DER data, child offsets,
 *        full re-encoding, and PEM output against QSC.
 * \param name Distinct certificate algorithm label used in diagnostics.
 * \param raw Immutable DER certificate bytes, owned by the fixture.
 * \param rawlen Number of bytes in the certificate.
 * \return True only when every independent output comparison is identical.
 * \note No retained allocations. Not thread-safe with respect to test output.
 */
static bool qsctest_openssl_certificate_test(const char* name, const uint8_t* raw, size_t rawlen)
{
	uint8_t* recoded;
	X509* cert;
	const unsigned char* ptr;
	unsigned char* writeptr;
	qsc_encoding_ber_element* root;
	const uint8_t* child;
	const unsigned char* cursor;
	BIO* pem;
	BUF_MEM* membuf;
	char* qtext;
	size_t count;
	size_t consumed;
	size_t childlen;
	size_t position;
	size_t tlen;
	size_t i;
	long objectlen;
	int tag;
	int cls;
	int flags;
	bool ok;

	cert = NULL;
	root = NULL;
	pem = NULL;
	recoded = NULL;
	qtext = NULL;
	ok = (name != NULL && raw != NULL && rawlen > 0U && rawlen <= (size_t)INT_MAX);

	if (ok == true)
	{
		recoded = (uint8_t*)qsc_memutils_malloc(rawlen + 16U);
		qtext = (char*)qsc_memutils_malloc((rawlen * 2U) + 1024U);
		ok = (recoded != NULL && qtext != NULL);
	}

	if (ok == true)
	{
		ptr = raw;
		cert = d2i_X509(NULL, &ptr, (long)rawlen);
		ok = (cert != NULL && ptr == raw + rawlen);
	}

	if (ok == true)
	{
		consumed = 0U;
		ok = (qsc_encoding_der_validate(raw, rawlen, &consumed) == true && consumed == rawlen);
	}

	if (ok == true)
	{
		ok = (qsc_asn1_der_decode_exact(raw, rawlen, &root) == QSC_ASN1_STATUS_SUCCESS);
		ok = (ok == true && root != NULL && root->ccount == 3U);
	}

	if (ok == true)
	{
		cursor = raw;
		flags = ASN1_get_object(&cursor, &objectlen, &tag, &cls, (long)rawlen);
		ok = ((flags & 0x80) == 0 && tag == V_ASN1_SEQUENCE);
		position = (size_t)(cursor - raw);

		for (i = 0U; i < 3U && ok == true; ++i)
		{
			cursor = raw + position;
			flags = ASN1_get_object(&cursor, &objectlen, &tag, &cls, (long)(rawlen - position));
			tlen = (size_t)(cursor - (raw + position)) + (size_t)objectlen;
			child = NULL;
			childlen = 0U;
			ok = ((flags & 0x80) == 0 && qsc_asn1_der_get_child_region(raw, rawlen, i, &child, &childlen) == QSC_ASN1_STATUS_SUCCESS);
			ok = (ok == true && child == raw + position && childlen == tlen);
			position += tlen;
		}

		ok = (ok == true && position == rawlen);
	}

	if (ok == true)
	{
		writeptr = recoded;
		count = (size_t)i2d_X509(cert, &writeptr);
		ok = (count == rawlen && memcmp(raw, recoded, rawlen) == 0);
	}

	if (ok == true)
	{
		ok = qsc_encoding_pem_encode("CERTIFICATE", qtext, (rawlen * 2U) + 1024U, raw, rawlen);
		pem = BIO_new(BIO_s_mem());
		ok = (ok == true && pem != NULL);
	}

	if (ok == true)
	{
		ok = (PEM_write_bio_X509(pem, cert) > 0);
	}

	if (ok == true)
	{
		BIO_get_mem_ptr(pem, &membuf);
		ok = (membuf != NULL && membuf->length == strlen(qtext));
		if (ok == true)
		{
			ok = (memcmp(qtext, membuf->data, membuf->length) == 0);
		}
	}

	if (ok == false)
	{
		fprintf(stderr, "FAIL: OpenSSL X.509 %s differential output mismatch or resource failure\n", name);
	}

	printf("%s: X.509 OpenSSL differential %s (DER, children, PEM)\n", ok ? "PASS" : "FAIL", name);

	if (pem != NULL)
	{
		BIO_free(pem);
	}
	if (root != NULL)
	{
		qsc_encoding_ber_free_element(root);
	}
	if (cert != NULL)
	{
		X509_free(cert);
	}
	qsc_memutils_alloc_free(qtext);
	qsc_memutils_alloc_free(recoded);

	return ok;
}

/** \brief Execute named differential test functions without dispatch tables or loops.
 * \return True if every invoked test succeeds, false otherwise. */
bool qsctest_encoding_openssl_run(void)
{
	bool valid;

	valid = true;
	test_seed = UINT64_C(0xA30799836B164C91);
	test_cases = 0U;
	test_differences = 0U;

	if (qsctest_encoding_openssl_base64_exhaustive_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_base64_stream_openssl_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_hex_exhaustive_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_hex_boundaries_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_pem_openssl_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_der_openssl_integer_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_der_children_openssl_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_der_malformed_exhaustive_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_edge_cases_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_base64_padding_exhaustive_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_asn1_tag_length_openssl_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_der_octet_boundaries_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_der_nested_boundaries_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_der_universal_canonical_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_base64_malformed_openssl_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_hex_malformed_openssl_test() == false)
	{
		valid = false;
	}

	if (qsctest_encoding_openssl_asn1_der_size_boundaries_test() == false)
	{
		valid = false;
	}

	if (qsctest_openssl_certificate_test("RSA", qsctest_openssl_rsa_der, sizeof(qsctest_openssl_rsa_der)) == false)
	{
		valid = false;
	}

	if (qsctest_openssl_certificate_test("ECP256", qsctest_openssl_ecp256_der, sizeof(qsctest_openssl_ecp256_der)) == false)
	{
		valid = false;
	}

	if (qsctest_openssl_certificate_test("ED25519", qsctest_openssl_ed25519_der, sizeof(qsctest_openssl_ed25519_der)) == false)
	{
		valid = false;
	}

	printf("%s: QSCTest OpenSSL differential suite, comparisons=%zu, format divergences=%zu, reference=%s\n", valid ? "PASS" : "FAIL", test_cases, test_differences, OpenSSL_version(OPENSSL_VERSION));
	return valid;
}
#else

/** \brief Report an intentionally disabled optional OpenSSL integration.
 * \return True because no test was attempted; the output explicitly says SKIP.
 * \note OpenSSL has no link or header requirement when the macro is absent. */
bool qsctest_encoding_openssl_run(void)
{
	printf("SKIP: QSCTest OpenSSL differential suite (enable QSCTEST_OPENSSL_ENABLED and link OpenSSL libcrypto)\n");
	return true;
}

#endif
