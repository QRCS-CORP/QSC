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

#include "qsort_test.h"
#include "qsort.h"
#include "memutils.h"
#include "testutils.h"
#include <stdlib.h>

#define QSCTEST_QSORT_COUNT 8192U

/*! \brief Compares the signed int8_t sorter against libc on six adversarial distributions.
 * \return true if every distribution and unchanged sentinel range match.
 */
static int qsctest_qsort_compare_i8(const void* a, const void* b)
{
	int8_t va;
	int8_t vb;
	int res;

	va = *(const int8_t*)a;
	vb = *(const int8_t*)b;
	res = (va > vb) - (va < vb);
	return res;
}

/*! \brief Tests duplicate, sorted, reversed, alternating, sawtooth and generated inputs.
 * \return true if all six comparisons pass.
 */
static bool qsctest_qsort_i8_test(void)
{
	int8_t arr[QSCTEST_QSORT_COUNT];
	int8_t reference[QSCTEST_QSORT_COUNT];
	uint32_t seed;
	size_t pass;
	size_t i;
	bool res;

	res = true;
	seed = 0x7B74D39AU;
	for (pass = 0U; pass < 6U && res == true; ++pass)
	{
		for (i = 0U; i < QSCTEST_QSORT_COUNT; ++i)
		{
			seed ^= seed << 13;
			seed ^= seed >> 17;
			seed ^= seed << 5;
			if (pass == 0U)
			{
				arr[i] = (int8_t)7;
			}
			else if (pass == 1U)
			{
				arr[i] = (int8_t)(i % 99U);
			}
			else if (pass == 2U)
			{
				arr[i] = (int8_t)(98 - (int32_t)(i % 99U));
			}
			else if (pass == 3U)
			{
				arr[i] = (int8_t)((i & 1U) ? -37 : 37);
			}
			else if (pass == 4U)
			{
				arr[i] = (int8_t)((int32_t)(i % 17U) - 8);
			}
			else
			{
				arr[i] = (int8_t)((int32_t)(seed % 201U) - 100);
			}
		}

		qsc_memutils_copy(reference, arr, sizeof(arr));
		qsort(reference + 7U, QSCTEST_QSORT_COUNT - 14U, sizeof(int8_t), qsctest_qsort_compare_i8);
		qsc_qsort_sort_i8(arr, (int32_t)7, (int32_t)(QSCTEST_QSORT_COUNT - 8U));
		res = qsc_memutils_are_equal((const uint8_t*)arr, (const uint8_t*)reference, sizeof(arr));
	}

	return res;
}

/*! \brief Compares the signed int16_t sorter against libc on six adversarial distributions.
 * \return true if every distribution and unchanged sentinel range match.
 */
static int qsctest_qsort_compare_i16(const void* a, const void* b)
{
	int16_t va;
	int16_t vb;
	int res;

	va = *(const int16_t*)a;
	vb = *(const int16_t*)b;
	res = (va > vb) - (va < vb);
	return res;
}

/*! \brief Tests duplicate, sorted, reversed, alternating, sawtooth and generated inputs.
 * \return true if all six comparisons pass.
 */
static bool qsctest_qsort_i16_test(void)
{
	int16_t arr[QSCTEST_QSORT_COUNT];
	int16_t reference[QSCTEST_QSORT_COUNT];
	uint32_t seed;
	size_t pass;
	size_t i;
	bool res;

	res = true;
	seed = 0x7B74D39AU;
	for (pass = 0U; pass < 6U && res == true; ++pass)
	{
		for (i = 0U; i < QSCTEST_QSORT_COUNT; ++i)
		{
			seed ^= seed << 13;
			seed ^= seed >> 17;
			seed ^= seed << 5;
			if (pass == 0U)
			{
				arr[i] = (int16_t)7;
			}
			else if (pass == 1U)
			{
				arr[i] = (int16_t)(i % 99U);
			}
			else if (pass == 2U)
			{
				arr[i] = (int16_t)(98 - (int32_t)(i % 99U));
			}
			else if (pass == 3U)
			{
				arr[i] = (int16_t)((i & 1U) ? -37 : 37);
			}
			else if (pass == 4U)
			{
				arr[i] = (int16_t)((int32_t)(i % 17U) - 8);
			}
			else
			{
				arr[i] = (int16_t)((int32_t)(seed % 201U) - 100);
			}
		}

		qsc_memutils_copy(reference, arr, sizeof(arr));
		qsort(reference + 7U, QSCTEST_QSORT_COUNT - 14U, sizeof(int16_t), qsctest_qsort_compare_i16);
		qsc_qsort_sort_i16(arr, (int32_t)7, (int32_t)(QSCTEST_QSORT_COUNT - 8U));
		res = qsc_memutils_are_equal((const uint8_t*)arr, (const uint8_t*)reference, sizeof(arr));
	}

	return res;
}

/*! \brief Compares the signed int32_t sorter against libc on six adversarial distributions.
 * \return true if every distribution and unchanged sentinel range match.
 */
static int qsctest_qsort_compare_i32(const void* a, const void* b)
{
	int32_t va;
	int32_t vb;
	int res;

	va = *(const int32_t*)a;
	vb = *(const int32_t*)b;
	res = (va > vb) - (va < vb);
	return res;
}

/*! \brief Tests duplicate, sorted, reversed, alternating, sawtooth and generated inputs.
 * \return true if all six comparisons pass.
 */
static bool qsctest_qsort_i32_test(void)
{
	int32_t arr[QSCTEST_QSORT_COUNT];
	int32_t reference[QSCTEST_QSORT_COUNT];
	uint32_t seed;
	size_t pass;
	size_t i;
	bool res;

	res = true;
	seed = 0x7B74D39AU;
	for (pass = 0U; pass < 6U && res == true; ++pass)
	{
		for (i = 0U; i < QSCTEST_QSORT_COUNT; ++i)
		{
			seed ^= seed << 13;
			seed ^= seed >> 17;
			seed ^= seed << 5;
			if (pass == 0U)
			{
				arr[i] = (int32_t)7;
			}
			else if (pass == 1U)
			{
				arr[i] = (int32_t)(i % 99U);
			}
			else if (pass == 2U)
			{
				arr[i] = (int32_t)(98 - (int32_t)(i % 99U));
			}
			else if (pass == 3U)
			{
				arr[i] = (int32_t)((i & 1U) ? -37 : 37);
			}
			else if (pass == 4U)
			{
				arr[i] = (int32_t)((int32_t)(i % 17U) - 8);
			}
			else
			{
				arr[i] = (int32_t)((int32_t)(seed % 201U) - 100);
			}
		}

		qsc_memutils_copy(reference, arr, sizeof(arr));
		qsort(reference + 7U, QSCTEST_QSORT_COUNT - 14U, sizeof(int32_t), qsctest_qsort_compare_i32);
		qsc_qsort_sort_i32(arr, (int32_t)7, (int32_t)(QSCTEST_QSORT_COUNT - 8U));
		res = qsc_memutils_are_equal((const uint8_t*)arr, (const uint8_t*)reference, sizeof(arr));
	}

	return res;
}

/*! \brief Compares the signed int64_t sorter against libc on six adversarial distributions.
 * \return true if every distribution and unchanged sentinel range match.
 */
static int qsctest_qsort_compare_i64(const void* a, const void* b)
{
	int64_t va;
	int64_t vb;
	int res;

	va = *(const int64_t*)a;
	vb = *(const int64_t*)b;
	res = (va > vb) - (va < vb);
	return res;
}

/*! \brief Tests duplicate, sorted, reversed, alternating, sawtooth and generated inputs.
 * \return true if all six comparisons pass.
 */
static bool qsctest_qsort_i64_test(void)
{
	int64_t arr[QSCTEST_QSORT_COUNT];
	int64_t reference[QSCTEST_QSORT_COUNT];
	uint32_t seed;
	size_t pass;
	size_t i;
	bool res;

	res = true;
	seed = 0x7B74D39AU;
	for (pass = 0U; pass < 6U && res == true; ++pass)
	{
		for (i = 0U; i < QSCTEST_QSORT_COUNT; ++i)
		{
			seed ^= seed << 13;
			seed ^= seed >> 17;
			seed ^= seed << 5;
			if (pass == 0U)
			{
				arr[i] = (int64_t)7;
			}
			else if (pass == 1U)
			{
				arr[i] = (int64_t)(i % 99U);
			}
			else if (pass == 2U)
			{
				arr[i] = (int64_t)(98 - (int32_t)(i % 99U));
			}
			else if (pass == 3U)
			{
				arr[i] = (int64_t)((i & 1U) ? -37 : 37);
			}
			else if (pass == 4U)
			{
				arr[i] = (int64_t)((int32_t)(i % 17U) - 8);
			}
			else
			{
				arr[i] = (int64_t)((int32_t)(seed % 201U) - 100);
			}
		}

		qsc_memutils_copy(reference, arr, sizeof(arr));
		qsort(reference + 7U, QSCTEST_QSORT_COUNT - 14U, sizeof(int64_t), qsctest_qsort_compare_i64);
		qsc_qsort_sort_i64(arr, (int64_t)7, (int64_t)(QSCTEST_QSORT_COUNT - 8U));
		res = qsc_memutils_are_equal((const uint8_t*)arr, (const uint8_t*)reference, sizeof(arr));
	}

	return res;
}

/*! \brief Runs independent quicksort regression tests with distinct results. */
void qsctest_qsort_run(void)
{
	if (qsctest_qsort_i8_test() == true)
	{
		qsctest_print_line("PASS: qsort i8 adversarial distributions");
	}
	else
	{
		qsctest_print_line("FAIL: qsort i8 adversarial distributions");
	}

	if (qsctest_qsort_i16_test() == true)
	{
		qsctest_print_line("PASS: qsort i16 adversarial distributions");
	}
	else
	{
		qsctest_print_line("FAIL: qsort i16 adversarial distributions");
	}

	if (qsctest_qsort_i32_test() == true)
	{
		qsctest_print_line("PASS: qsort i32 adversarial distributions");
	}
	else
	{
		qsctest_print_line("FAIL: qsort i32 adversarial distributions");
	}

	if (qsctest_qsort_i64_test() == true)
	{
		qsctest_print_line("PASS: qsort i64 adversarial distributions");
	}
	else
	{
		qsctest_print_line("FAIL: qsort i64 adversarial distributions");
	}
}
