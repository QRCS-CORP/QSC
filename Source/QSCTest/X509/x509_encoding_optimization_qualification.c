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

#include "asn1.h"
#include "encoding.h"
#include "memutils.h"
#include "x509store.h"
#include <stdio.h>

/**
 * \file x509_encoding_optimization_qualification.c
 * \brief Standalone ASN.1, issuer-selection and Base64 regression qualification.
 * \details The caller owns all inputs. Each test is independent and invoked directly.
 */

/**
 * \brief Verify DER child extraction, byte ownership and malformed-input rejection.
 * \return True if all boundary and validation checks pass.
 * \note Input and output are local; no allocation or shared state is used.
 */
static bool qualification_asn1_child_regions(void)
{
	static const uint8_t der[] = { 0x30U, 0x0DU, 0x30U, 0x03U, 0x02U, 0x01U, 0x01U,
		0x04U, 0x03U, 0x41U, 0x42U, 0x43U, 0x02U, 0x01U, 0x02U };
	static const uint8_t nonminimal[] = { 0x30U, 0x81U, 0x03U, 0x02U, 0x01U, 0x01U };
	const uint8_t* child;
	size_t childlen;
	bool res;

	child = NULL;
	childlen = 0U;
	res = true;

	if (qsc_asn1_der_get_child_region(der, sizeof(der), 0U, &child, &childlen) != QSC_ASN1_STATUS_SUCCESS ||
		child != der + 2U || childlen != 5U)
	{
		res = false;
	}
	if (qsc_asn1_der_get_child_region(der, sizeof(der), 1U, &child, &childlen) != QSC_ASN1_STATUS_SUCCESS ||
		child != der + 7U || childlen != 5U)
	{
		res = false;
	}
	if (qsc_asn1_der_get_child_region(der, sizeof(der), 2U, &child, &childlen) != QSC_ASN1_STATUS_SUCCESS ||
		child != der + 12U || childlen != 3U)
	{
		res = false;
	}
	if (qsc_asn1_der_get_child_region(der, sizeof(der), 3U, &child, &childlen) != QSC_ASN1_STATUS_NOT_FOUND)
	{
		res = false;
	}
	if (qsc_asn1_der_get_child_region(der, sizeof(der) - 1U, 0U, &child, &childlen) == QSC_ASN1_STATUS_SUCCESS)
	{
		res = false;
	}
	if (qsc_asn1_der_get_child_region(nonminimal, sizeof(nonminimal), 0U, &child, &childlen) == QSC_ASN1_STATUS_SUCCESS)
	{
		res = false;
	}

	return res;
}

/**
 * \brief Verify first-match fallback and later AKI-qualified issuer precedence.
 * \return True if each issuer-selection case returns its expected anchor.
 * \note All certificate storage is allocated, initialized and released here; not thread-shared.
 */
static bool qualification_x509_anchor_preference(void)
{
	qsc_x509_certificate* leaf;
	qsc_x509_store store;
	qsc_x509_trust_anchor* anchors;
	const qsc_x509_trust_anchor* match;
	bool res;

	leaf = (qsc_x509_certificate*)qsc_memutils_malloc(sizeof(qsc_x509_certificate));
	anchors = (qsc_x509_trust_anchor*)qsc_memutils_malloc(3U * sizeof(qsc_x509_trust_anchor));
	res = (leaf != NULL && anchors != NULL);

	if (res == true)
	{
		qsc_memutils_clear(leaf, sizeof(*leaf));
		qsc_memutils_clear(anchors, 3U * sizeof(*anchors));
		qsc_x509_store_initialize(&store, anchors, 3U);
		store.count = 3U;

		leaf->issuer.count = 1U;
		leaf->issuer.attributes[0U].type = QSC_X509_NAME_ATTRIBUTE_COMMON_NAME;
		leaf->issuer.attributes[0U].length = 4U;
		qsc_memutils_copy((uint8_t*)leaf->issuer.attributes[0U].value, (const uint8_t*)"test", 4U);

		anchors[0U].certificate.subject = leaf->issuer;
		anchors[2U].certificate.subject = leaf->issuer;
		match = qsc_x509_store_find_anchor_for_certificate(&store, leaf);
		res = (match == &anchors[0U]);

		leaf->extensions.authoritykeyidentifier.present = true;
		leaf->extensions.authoritykeyidentifier.keyidentifierlen = 4U;
		qsc_memutils_copy(leaf->extensions.authoritykeyidentifier.keyidentifier, (const uint8_t*)"KEY2", 4U);
		anchors[2U].certificate.extensions.subjectkeyidentifier.present = true;
		anchors[2U].certificate.extensions.subjectkeyidentifier.identifierlen = 4U;
		qsc_memutils_copy(anchors[2U].certificate.extensions.subjectkeyidentifier.identifier, (const uint8_t*)"KEY2", 4U);
		match = qsc_x509_store_find_anchor_for_certificate(&store, leaf);
		res = (match == &anchors[2U]) && res;
	}

	if (leaf != NULL)
	{
		qsc_memutils_alloc_free(leaf);
	}
	if (anchors != NULL)
	{
		qsc_memutils_alloc_free(anchors);
	}

	return res;
}

/**
 * \brief Verify RFC 4648 decoding and rejection without partial output writes.
 * \return True if valid and invalid input cases preserve expected behavior.
 * \note All buffers are local; no allocation and no retained state.
 */
static bool qualification_base64_validation(void)
{
	uint8_t output[8U];
	uint8_t expected[3U] = { 'M', 'a', 'n' };
	bool res;

	qsc_memutils_clear(output, sizeof(output));
	res = qsc_encoding_base64_decode(output, sizeof(output), "TWFu", 4U);
	res = (qsc_memutils_are_equal(output, expected, sizeof(expected)) == true) && res;
	qsc_memutils_clear(output, sizeof(output));
	res = (qsc_encoding_base64_decode(output, sizeof(output), "TWE=", 4U) == true &&
		output[0U] == 'M' && output[1U] == 'a') && res;
	qsc_memutils_clear(output, sizeof(output));
	res = (qsc_encoding_base64_decode(output, sizeof(output), "TQ==", 4U) == true && output[0U] == 'M') && res;
	qsc_memutils_clear(output, sizeof(output));
	res = (qsc_encoding_base64_decode(output, sizeof(output), "T=Fu", 4U) == false && output[0U] == 0U) && res;
	res = (qsc_encoding_base64_decode(output, sizeof(output), "TQ=A", 4U) == false && output[0U] == 0U) && res;
	res = (qsc_encoding_base64_decode(output, sizeof(output), "TWFu#AAA", 8U) == false && output[0U] == 0U) && res;
	return res;
}

/**
 * \brief Execute the individual, noninteractive qualification tests.
 * \return Zero on complete success, nonzero on any failed test.
 * \note All tests run sequentially and own their resources; no test registry is used.
 */
int main(void)
{
	bool passed;
	bool res;

	printf("QSC X.509 AND ENCODING OPTIMIZATION QUALIFICATION\n");
	passed = true;
	res = qualification_asn1_child_regions();
	printf("%s: ASN.1 validated child-span extraction\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qualification_x509_anchor_preference();
	printf("%s: X.509 preferred and fallback issuer selection\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	res = qualification_base64_validation();
	printf("%s: Base64 prevalidation and output isolation\n", res ? "PASS" : "FAIL");
	passed = res && passed;
	printf("SUMMARY: %s\n", passed ? "PASS" : "FAIL");
	return passed ? 0 : 1;
}
