/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_QSORT_H
#define QSC_QSORT_H

#include "common.h"

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
