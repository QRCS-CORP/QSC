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

#include "qsort.h"

/**
 * \brief Restore the int8_t max-heap property for a selected node.
 * \param arr Mutable signed integer array; must outlive this call.
 * \param first Offset of the heap segment.
 * \param root Index relative to the heap segment.
 * \param count Number of heap entries.
 * \details The caller provides an exclusively owned array; not thread-safe with concurrent mutation.
 */
static void qsc_qsort_sift_i8(int8_t* arr, size_t first, size_t root, size_t count)
{
	size_t child;
	size_t pick;
	int8_t value;

	value = arr[first + root];

	while (root < (count / 2U))
	{
		child = (root * 2U) + 1U;
		pick = child;

		if (child + 1U < count && arr[first + child] < arr[first + child + 1U])
		{
			pick = child + 1U;
		}

		if (value >= arr[first + pick])
		{
			break;
		}

		arr[first + root] = arr[first + pick];
		root = pick;
	}

	arr[first + root] = value;
}

/**
 * \brief In-place worst-case O(n log n) fallback for int8_t sorting.
 * \param arr Mutable array with at least last + 1 elements.
 * \param first Inclusive first element.
 * \param last Inclusive final element.
 * \details No allocations; the caller synchronizes concurrent access.
 */
static void qsc_qsort_heap_i8(int8_t* arr, size_t first, size_t last)
{
	size_t count;
	size_t i;
	int8_t temp;

	count = (last - first) + 1U;
	i = count / 2U;

	while (i != 0U)
	{
		--i;
		qsc_qsort_sift_i8(arr, first, i, count);
	}

	while (count > 1U)
	{
		--count;
		temp = arr[first];
		arr[first] = arr[first + count];
		arr[first + count] = temp;
		qsc_qsort_sift_i8(arr, first, 0U, count);
	}
}

/**
 * \brief Sort signed integers using bounded-depth three-way partitioning.
 * \param arr Mutable signed integer array of at least last + 1 elements.
 * \param first Inclusive beginning of the subrange.
 * \param last Inclusive end of the subrange.
 * \param budget Remaining partition-depth allowance.
 * \details Small ranges use insertion sort; exhausted budgets use heapsort.
 * \details Does not allocate and is not safe against concurrent mutation.
 */
static void qsc_qsort_intro_i8(int8_t* arr, size_t first, size_t last, size_t budget)
{
	size_t lt;
	size_t mid;
	size_t i;
	size_t gt;
	size_t j;
	int8_t a;
	int8_t b;
	int8_t c;
	int8_t pivot;
	int8_t temp;

	while (first < last)
	{
		if (last - first < 24U)
		{
			/* Binary-search-free insertion minimizes overhead on tiny partitions. */
			for (i = first + 1U; i <= last; ++i)
			{
				temp = arr[i];
				j = i;

				while (j > first && arr[j - 1U] > temp)
				{
					arr[j] = arr[j - 1U];
					--j;
				}

				arr[j] = temp;
			}

			break;
		}

		if (budget == 0U)
		{
			qsc_qsort_heap_i8(arr, first, last);
			break;
		}

		--budget;
		mid = first + ((last - first) / 2U);
		a = arr[first];
		b = arr[mid];
		c = arr[last];

		if (a < b)
		{
			pivot = (b < c) ? b : ((a < c) ? c : a);
		}
		else
		{
			pivot = (a < c) ? a : ((b < c) ? c : b);
		}

		lt = first;
		i = first;
		gt = last;

		while (i <= gt)
		{
			if (arr[i] < pivot)
			{
				temp = arr[lt];
				arr[lt] = arr[i];
				arr[i] = temp;
				++lt;
				++i;
			}
			else if (arr[i] > pivot)
			{
				temp = arr[i];
				arr[i] = arr[gt];
				arr[gt] = temp;
				--gt;
			}
			else
			{
				++i;
			}
		}

		if (lt - first < last - gt)
		{
			if (lt > first + 1U)
			{
				qsc_qsort_intro_i8(arr, first, lt - 1U, budget);
			}

			if (gt == last)
			{
				break;
			}

			first = gt + 1U;
		}
		else
		{
			if (gt < last - 1U)
			{
				qsc_qsort_intro_i8(arr, gt + 1U, last, budget);
			}

			if (lt == first)
			{
				break;
			}

			last = lt - 1U;
		}
	}
}

/**
 * \brief Sort a selected inclusive range of signed int8_t values in ascending order.
 * \param arr Mutable array owned by the caller.
 * \param start First index, nonnegative and no greater than end.
 * \param end Last index, inclusive.
 * \details Invalid ranges are ignored; no allocation or persistent state.
 * \details Caller must synchronize concurrent access to arr.
 */
void qsc_qsort_sort_i8(int8_t* arr, int32_t start, int32_t end)
{
	size_t count;
	size_t budget;
	size_t n;

	QSC_ASSERT(arr != NULL);
	QSC_ASSERT(start >= 0);
	QSC_ASSERT(start <= end);

	if (arr != NULL && start >= 0 && start < end)
	{
		count = (size_t)((uint64_t)end - (uint64_t)start) + 1U;

		if (count >= 2048U)
		{
			/* Fixed 8-bit domain: counting sort has linear runtime and bounded stack usage. */
			size_t counts[256U] = { 0U };
			size_t position;

			for (size_t i = (size_t)start; i <= (size_t)end; ++i)
			{
				++counts[(size_t)((int32_t)arr[i] + 128)];
			}

			position = (size_t)start;

			for (size_t i = 0U; i < 256U; ++i)
			{
				while (counts[i] != 0U)
				{
					arr[position] = (int8_t)((int32_t)i - 128);
					++position;
					--counts[i];
				}
			}
		}
		else
		{
			budget = 0U;
		n = count;

		while (n > 1U)
		{
			budget += 2U;
			n >>= 1U;
		}

			qsc_qsort_intro_i8(arr, (size_t)start, (size_t)end, budget);
		}
	}
}
/**
 * \brief Restore the int16_t max-heap property for a selected node.
 * \param arr Mutable signed integer array; must outlive this call.
 * \param first Offset of the heap segment.
 * \param root Index relative to the heap segment.
 * \param count Number of heap entries.
 * \details The caller provides an exclusively owned array; not thread-safe with concurrent mutation.
 */
static void qsc_qsort_sift_i16(int16_t* arr, size_t first, size_t root, size_t count)
{
	size_t child;
	size_t pick;
	int16_t value;

	value = arr[first + root];

	while (root < (count / 2U))
	{
		child = (root * 2U) + 1U;
		pick = child;

		if (child + 1U < count && arr[first + child] < arr[first + child + 1U])
		{
			pick = child + 1U;
		}

		if (value >= arr[first + pick])
		{
			break;
		}

		arr[first + root] = arr[first + pick];
		root = pick;
	}

	arr[first + root] = value;
}

/**
 * \brief In-place worst-case O(n log n) fallback for int16_t sorting.
 * \param arr Mutable array with at least last + 1 elements.
 * \param first Inclusive first element.
 * \param last Inclusive final element.
 * \details No allocations; the caller synchronizes concurrent access.
 */
static void qsc_qsort_heap_i16(int16_t* arr, size_t first, size_t last)
{
	size_t count;
	size_t i;
	int16_t temp;

	count = (last - first) + 1U;
	i = count / 2U;

	while (i != 0U)
	{
		--i;
		qsc_qsort_sift_i16(arr, first, i, count);
	}

	while (count > 1U)
	{
		--count;
		temp = arr[first];
		arr[first] = arr[first + count];
		arr[first + count] = temp;
		qsc_qsort_sift_i16(arr, first, 0U, count);
	}
}

/**
 * \brief Sort signed integers using bounded-depth three-way partitioning.
 * \param arr Mutable signed integer array of at least last + 1 elements.
 * \param first Inclusive beginning of the subrange.
 * \param last Inclusive end of the subrange.
 * \param budget Remaining partition-depth allowance.
 * \details Small ranges use insertion sort; exhausted budgets use heapsort.
 * \details Does not allocate and is not safe against concurrent mutation.
 */
static void qsc_qsort_intro_i16(int16_t* arr, size_t first, size_t last, size_t budget)
{
	size_t lt;
	size_t mid;
	size_t i;
	size_t gt;
	size_t j;
	int16_t a;
	int16_t b;
	int16_t c;
	int16_t pivot;
	int16_t temp;

	while (first < last)
	{
		if (last - first < 24U)
		{
			/* Binary-search-free insertion minimizes overhead on tiny partitions. */
			for (i = first + 1U; i <= last; ++i)
			{
				temp = arr[i];
				j = i;

				while (j > first && arr[j - 1U] > temp)
				{
					arr[j] = arr[j - 1U];
					--j;
				}

				arr[j] = temp;
			}

			break;
		}

		if (budget == 0U)
		{
			qsc_qsort_heap_i16(arr, first, last);
			break;
		}

		--budget;
		mid = first + ((last - first) / 2U);
		a = arr[first];
		b = arr[mid];
		c = arr[last];

		if (a < b)
		{
			pivot = (b < c) ? b : ((a < c) ? c : a);
		}
		else
		{
			pivot = (a < c) ? a : ((b < c) ? c : b);
		}

		lt = first;
		i = first;
		gt = last;

		while (i <= gt)
		{
			if (arr[i] < pivot)
			{
				temp = arr[lt];
				arr[lt] = arr[i];
				arr[i] = temp;
				++lt;
				++i;
			}
			else if (arr[i] > pivot)
			{
				temp = arr[i];
				arr[i] = arr[gt];
				arr[gt] = temp;
				--gt;
			}
			else
			{
				++i;
			}
		}

		if (lt - first < last - gt)
		{
			if (lt > first + 1U)
			{
				qsc_qsort_intro_i16(arr, first, lt - 1U, budget);
			}

			if (gt == last)
			{
				break;
			}

			first = gt + 1U;
		}
		else
		{
			if (gt < last - 1U)
			{
				qsc_qsort_intro_i16(arr, gt + 1U, last, budget);
			}

			if (lt == first)
			{
				break;
			}

			last = lt - 1U;
		}
	}
}

/**
 * \brief Sort a selected inclusive range of signed int16_t values in ascending order.
 * \param arr Mutable array owned by the caller.
 * \param start First index, nonnegative and no greater than end.
 * \param end Last index, inclusive.
 * \details Invalid ranges are ignored; no allocation or persistent state.
 * \details Caller must synchronize concurrent access to arr.
 */
void qsc_qsort_sort_i16(int16_t* arr, int32_t start, int32_t end)
{
	size_t count;
	size_t budget;
	size_t n;

	QSC_ASSERT(arr != NULL);
	QSC_ASSERT(start >= 0);
	QSC_ASSERT(start <= end);

	if (arr != NULL && start >= 0 && start < end)
	{
		count = (size_t)((uint64_t)end - (uint64_t)start) + 1U;
		budget = 0U;
		n = count;

		while (n > 1U)
		{
			budget += 2U;
			n >>= 1U;
		}

		qsc_qsort_intro_i16(arr, (size_t)start, (size_t)end, budget);
	}
}
/**
 * \brief Restore the int32_t max-heap property for a selected node.
 * \param arr Mutable signed integer array; must outlive this call.
 * \param first Offset of the heap segment.
 * \param root Index relative to the heap segment.
 * \param count Number of heap entries.
 * \details The caller provides an exclusively owned array; not thread-safe with concurrent mutation.
 */
static void qsc_qsort_sift_i32(int32_t* arr, size_t first, size_t root, size_t count)
{
	size_t child;
	size_t pick;
	int32_t value;

	value = arr[first + root];

	while (root < (count / 2U))
	{
		child = (root * 2U) + 1U;
		pick = child;

		if (child + 1U < count && arr[first + child] < arr[first + child + 1U])
		{
			pick = child + 1U;
		}

		if (value >= arr[first + pick])
		{
			break;
		}

		arr[first + root] = arr[first + pick];
		root = pick;
	}

	arr[first + root] = value;
}

/**
 * \brief In-place worst-case O(n log n) fallback for int32_t sorting.
 * \param arr Mutable array with at least last + 1 elements.
 * \param first Inclusive first element.
 * \param last Inclusive final element.
 * \details No allocations; the caller synchronizes concurrent access.
 */
static void qsc_qsort_heap_i32(int32_t* arr, size_t first, size_t last)
{
	size_t count;
	size_t i;
	int32_t temp;

	count = (last - first) + 1U;
	i = count / 2U;

	while (i != 0U)
	{
		--i;
		qsc_qsort_sift_i32(arr, first, i, count);
	}

	while (count > 1U)
	{
		--count;
		temp = arr[first];
		arr[first] = arr[first + count];
		arr[first + count] = temp;
		qsc_qsort_sift_i32(arr, first, 0U, count);
	}
}

/**
 * \brief Sort signed integers using bounded-depth three-way partitioning.
 * \param arr Mutable signed integer array of at least last + 1 elements.
 * \param first Inclusive beginning of the subrange.
 * \param last Inclusive end of the subrange.
 * \param budget Remaining partition-depth allowance.
 * \details Small ranges use insertion sort; exhausted budgets use heapsort.
 * \details Does not allocate and is not safe against concurrent mutation.
 */
static void qsc_qsort_intro_i32(int32_t* arr, size_t first, size_t last, size_t budget)
{
	size_t lt;
	size_t mid;
	size_t i;
	size_t gt;
	size_t j;
	int32_t a;
	int32_t b;
	int32_t c;
	int32_t pivot;
	int32_t temp;

	while (first < last)
	{
		if (last - first < 24U)
		{
			/* Binary-search-free insertion minimizes overhead on tiny partitions. */
			for (i = first + 1U; i <= last; ++i)
			{
				temp = arr[i];
				j = i;

				while (j > first && arr[j - 1U] > temp)
				{
					arr[j] = arr[j - 1U];
					--j;
				}

				arr[j] = temp;
			}

			break;
		}

		if (budget == 0U)
		{
			qsc_qsort_heap_i32(arr, first, last);
			break;
		}

		--budget;
		mid = first + ((last - first) / 2U);
		a = arr[first];
		b = arr[mid];
		c = arr[last];

		if (a < b)
		{
			pivot = (b < c) ? b : ((a < c) ? c : a);
		}
		else
		{
			pivot = (a < c) ? a : ((b < c) ? c : b);
		}

		lt = first;
		i = first;
		gt = last;

		while (i <= gt)
		{
			if (arr[i] < pivot)
			{
				temp = arr[lt];
				arr[lt] = arr[i];
				arr[i] = temp;
				++lt;
				++i;
			}
			else if (arr[i] > pivot)
			{
				temp = arr[i];
				arr[i] = arr[gt];
				arr[gt] = temp;
				--gt;
			}
			else
			{
				++i;
			}
		}

		if (lt - first < last - gt)
		{
			if (lt > first + 1U)
			{
				qsc_qsort_intro_i32(arr, first, lt - 1U, budget);
			}

			if (gt == last)
			{
				break;
			}

			first = gt + 1U;
		}
		else
		{
			if (gt < last - 1U)
			{
				qsc_qsort_intro_i32(arr, gt + 1U, last, budget);
			}

			if (lt == first)
			{
				break;
			}

			last = lt - 1U;
		}
	}
}

/**
 * \brief Sort a selected inclusive range of signed int32_t values in ascending order.
 * \param arr Mutable array owned by the caller.
 * \param start First index, nonnegative and no greater than end.
 * \param end Last index, inclusive.
 * \details Invalid ranges are ignored; no allocation or persistent state.
 * \details Caller must synchronize concurrent access to arr.
 */
void qsc_qsort_sort_i32(int32_t* arr, int32_t start, int32_t end)
{
	size_t count;
	size_t budget;
	size_t n;

	QSC_ASSERT(arr != NULL);
	QSC_ASSERT(start >= 0);
	QSC_ASSERT(start <= end);

	if (arr != NULL && start >= 0 && start < end)
	{
		count = (size_t)((uint64_t)end - (uint64_t)start) + 1U;
		budget = 0U;
		n = count;

		while (n > 1U)
		{
			budget += 2U;
			n >>= 1U;
		}

		qsc_qsort_intro_i32(arr, (size_t)start, (size_t)end, budget);
	}
}
/**
 * \brief Restore the int64_t max-heap property for a selected node.
 * \param arr Mutable signed integer array; must outlive this call.
 * \param first Offset of the heap segment.
 * \param root Index relative to the heap segment.
 * \param count Number of heap entries.
 * \details The caller provides an exclusively owned array; not thread-safe with concurrent mutation.
 */
static void qsc_qsort_sift_i64(int64_t* arr, size_t first, size_t root, size_t count)
{
	size_t child;
	size_t pick;
	int64_t value;

	value = arr[first + root];

	while (root < (count / 2U))
	{
		child = (root * 2U) + 1U;
		pick = child;

		if (child + 1U < count && arr[first + child] < arr[first + child + 1U])
		{
			pick = child + 1U;
		}

		if (value >= arr[first + pick])
		{
			break;
		}

		arr[first + root] = arr[first + pick];
		root = pick;
	}

	arr[first + root] = value;
}

/**
 * \brief In-place worst-case O(n log n) fallback for int64_t sorting.
 * \param arr Mutable array with at least last + 1 elements.
 * \param first Inclusive first element.
 * \param last Inclusive final element.
 * \details No allocations; the caller synchronizes concurrent access.
 */
static void qsc_qsort_heap_i64(int64_t* arr, size_t first, size_t last)
{
	size_t count;
	size_t i;
	int64_t temp;

	count = (last - first) + 1U;
	i = count / 2U;

	while (i != 0U)
	{
		--i;
		qsc_qsort_sift_i64(arr, first, i, count);
	}

	while (count > 1U)
	{
		--count;
		temp = arr[first];
		arr[first] = arr[first + count];
		arr[first + count] = temp;
		qsc_qsort_sift_i64(arr, first, 0U, count);
	}
}

/**
 * \brief Sort signed integers using bounded-depth three-way partitioning.
 * \param arr Mutable signed integer array of at least last + 1 elements.
 * \param first Inclusive beginning of the subrange.
 * \param last Inclusive end of the subrange.
 * \param budget Remaining partition-depth allowance.
 * \details Small ranges use insertion sort; exhausted budgets use heapsort.
 * \details Does not allocate and is not safe against concurrent mutation.
 */
static void qsc_qsort_intro_i64(int64_t* arr, size_t first, size_t last, size_t budget)
{
	size_t lt;
	size_t mid;
	size_t i;
	size_t gt;
	size_t j;
	int64_t a;
	int64_t b;
	int64_t c;
	int64_t pivot;
	int64_t temp;

	while (first < last)
	{
		if (last - first < 24U)
		{
			/* Binary-search-free insertion minimizes overhead on tiny partitions. */
			for (i = first + 1U; i <= last; ++i)
			{
				temp = arr[i];
				j = i;

				while (j > first && arr[j - 1U] > temp)
				{
					arr[j] = arr[j - 1U];
					--j;
				}

				arr[j] = temp;
			}

			break;
		}

		if (budget == 0U)
		{
			qsc_qsort_heap_i64(arr, first, last);
			break;
		}

		--budget;
		mid = first + ((last - first) / 2U);
		a = arr[first];
		b = arr[mid];
		c = arr[last];

		if (a < b)
		{
			pivot = (b < c) ? b : ((a < c) ? c : a);
		}
		else
		{
			pivot = (a < c) ? a : ((b < c) ? c : b);
		}

		lt = first;
		i = first;
		gt = last;

		while (i <= gt)
		{
			if (arr[i] < pivot)
			{
				temp = arr[lt];
				arr[lt] = arr[i];
				arr[i] = temp;
				++lt;
				++i;
			}
			else if (arr[i] > pivot)
			{
				temp = arr[i];
				arr[i] = arr[gt];
				arr[gt] = temp;
				--gt;
			}
			else
			{
				++i;
			}
		}

		if (lt - first < last - gt)
		{
			if (lt > first + 1U)
			{
				qsc_qsort_intro_i64(arr, first, lt - 1U, budget);
			}

			if (gt == last)
			{
				break;
			}

			first = gt + 1U;
		}
		else
		{
			if (gt < last - 1U)
			{
				qsc_qsort_intro_i64(arr, gt + 1U, last, budget);
			}

			if (lt == first)
			{
				break;
			}

			last = lt - 1U;
		}
	}
}

/**
 * \brief Sort a selected inclusive range of signed int64_t values in ascending order.
 * \param arr Mutable array owned by the caller.
 * \param start First index, nonnegative and no greater than end.
 * \param end Last index, inclusive.
 * \details Invalid ranges are ignored; no allocation or persistent state.
 * \details Caller must synchronize concurrent access to arr.
 */
void qsc_qsort_sort_i64(int64_t* arr, int64_t start, int64_t end)
{
	size_t count;
	size_t budget;
	size_t n;

	QSC_ASSERT(arr != NULL);
	QSC_ASSERT(start >= 0);
	QSC_ASSERT(start <= end);

	if (arr != NULL && start >= 0 && start < end)
	{
		count = (size_t)((uint64_t)end - (uint64_t)start) + 1U;
		budget = 0U;
		n = count;

		while (n > 1U)
		{
			budget += 2U;
			n >>= 1U;
		}

		qsc_qsort_intro_i64(arr, (size_t)start, (size_t)end, budget);
	}
}
