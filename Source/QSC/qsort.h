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

#ifndef QSC_QSORT_H
#define QSC_QSORT_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file qsort.h
 * \brief An implementation of the quicksort sorting function.
 *
 * \details
 * This header defines functions for sorting arrays of signed integers of various sizes
 * (8-bit, 16-bit, 32-bit, and 64-bit) using the quicksort algorithm. The implementation
 * utilizes an in-place recursive partitioning method to achieve an average-case time
 * complexity of O(n log n). Quicksort is well-known for its efficiency and simplicity,
 * and it is widely used in numerous software systems.
 *
 * \code
 * // Example usage for sorting an array of 32-bit integers:
 * int32_t arr[10] = { 34, -7, 23, 0, 5, -3, 12, 99, -45, 8 };
 * qsc_qsort_sort_i32(arr, 0, 9);
 * \endcode
 *
 * \section qsort_links Reference Links:
 * - <a href="https://dl.acm.org/doi/abs/10.1145/362929.362947">Hoare's Quicksort Original Paper</a>
 */

/**
 * \brief Sort an array of 8-bit signed integers.
 *
 * \param arr8:		[int8_t*] The array of 8-bit signed integers to sort.
 * \param start:	[int32_t] The starting index of the sort.
 * \param end:		[int32_t] The end index of the sort.
 */
QSC_EXPORT_API void qsc_qsort_sort_i8(int8_t* arr8, int32_t start, int32_t end);

/**
 * \brief Sort an array of 16-bit signed integers.
 *
 * \param arr16:	[int16_t*] The array of 16-bit signed integers to sort.
 * \param start:	[int32_t] The starting index of the sort.
 * \param end:		[int32_t] The end index of the sort.
 */
QSC_EXPORT_API void qsc_qsort_sort_i16(int16_t* arr16, int32_t start, int32_t end);

/**
 * \brief Sort an array of 32-bit signed integers.
 *
 * \param arr32:	[int32_t*] The array of 32-bit signed integers to sort.
 * \param start:	[int32_t] The starting index of the sort.
 * \param end:		[int32_t] The end index of the sort.
 */
QSC_EXPORT_API void qsc_qsort_sort_i32(int32_t* arr32, int32_t start, int32_t end);

/**
 * \brief Sort an array of 64-bit signed integers.
 *
 * \param arr64:	[int64_t*] The array of 64-bit signed integers to sort.
 * \param start:	[int64_t] The starting index of the sort.
 * \param end:		[int64_t] The end index of the sort.
 */
QSC_EXPORT_API void qsc_qsort_sort_i64(int64_t* arr64, int64_t start, int64_t end);

QSC_CPLUSPLUS_ENABLED_END

#endif
