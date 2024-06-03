
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSC_QSORT_H
#define QSC_QSORT_H

#include "common.h"

/**
* \brief Sort an array of 8-bit unsigned integers
*
* \param arr8: The array of 8-bit unsigned integers to sort
* \param start: The starting index of the sort
* \param end: The end index of the sort
*/
QSC_EXPORT_API void qsc_qsort_sort_u8(int8_t* arr8, int start, int end);

/**
* \brief Sort an array of 16-bit unsigned integers
*
* \param arr16: The array of 16-bit unsigned integers to sort
* \param start: The starting index of the sort
* \param end: The end index of the sort
*/
QSC_EXPORT_API void qsc_qsort_sort_u16(int16_t* arr16, int start, int end);

/**
* \brief Sort an array of 32-bit unsigned integers
*
* \param arr32: The array of 32-bit unsigned integers to sort
* \param start: The starting index of the sort
* \param end: The end index of the sort
*/
QSC_EXPORT_API void qsc_qsort_sort_u32(int* arr32, int start, int end);

/**
* \brief Sort an array of 64-bit unsigned integers
*
* \param arr64: The array of 64-bit unsigned integers to sort
* \param start: The starting index of the sort
* \param end: The end index of the sort
*/
QSC_EXPORT_API void qsc_qsort_sort_u64(int64_t* arr64, int64_t start, int64_t end);

#endif