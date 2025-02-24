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

#ifndef QSC_LIST_H
#define QSC_LIST_H

#include "common.h"

/*!
 * \file list.h
 * \brief Memory-aligned list management functions.
 *
 * \details
 * This header defines the public API for managing a memory-aligned list data structure.
 * The list is designed to store items in a contiguous memory block with a specified width (in bytes),
 * ensuring proper alignment for performance-critical operations and compatibility with SIMD instructions.
 *
 * The module provides functions to:
 * - Initialize and allocate a memory-aligned list.
 * - Add and remove items from the list.
 * - Copy list contents.
 * - Sort the list using efficient algorithms.
 * - Serialize and deserialize the list to/from binary formats.
 * - Perform self-tests to verify the integrity and functionality of the list.
 *
 * This design is ideal for cryptographic and high-performance applications where data alignment
 * is crucial for optimal hardware utilization.
 *
 * \code
 * // Example usage:
 * // Initialize a list capable of holding 100 items, each 64 bytes wide.
 * qsc_list_state myList;
 * qsc_list_initialize(&myList, 100, 64);
 * 
 * // Add an item to the list.
 * uint8_t item[64] = { ... item data ... };
 * qsc_list_add(&myList, item);
 *
 * // Sort the list.
 * qsc_list_sort(&myList);
 *
 * // Serialize the list into a binary format.
 * uint8_t* serialized = list_serialize(&myList);
 *
 * // Clean up and free allocated resources.
 * qsc_list_dispose(&myList);
 * \endcode
 *
 * \section list_links Reference Links:
 * <a href="https://www.intel.com/content/www/us/en/develop/documentation/64-ia-32-architectures-software-developer-instruction-set-reference-guide.html">Intel 64 and IA-32 Architectures Software Developer's Manual</a>
 * <a href="https://gcc.gnu.org/onlinedocs/gcc/Aligned.html">GCC Data Alignment Documentation</a>
 */

/*!
 * \def QSC_LIST_ALIGNMENT
 * \brief The internal memory alignment constant.
 */
#define QSC_LIST_ALIGNMENT 64ULL

/*!
 * \def QSC_LIST_MAX_DEPTH
 * \brief The maximum list depth.
 */
#define QSC_LIST_MAX_DEPTH 102400ULL

/*!
 * \struct qsc_list_state
 * \brief Contains the list context state.
 *
 * This structure holds the state of a list, including a pointer to the items,
 * the number of items, and the byte width of each item.
 */
QSC_EXPORT_API typedef struct
{
    uint8_t* items;   /*!< A pointer to the items array. */
    size_t   count;   /*!< The number of list items. */
    size_t   width;   /*!< The byte length of a list item. */
} qsc_list_state;

/**
 * \brief Add an item to the list.
 *
 * \param ctx:      [qsc_list_state*] Pointer to the list state structure.
 * \param item:     [void*] Pointer to the item to be added.
 */
QSC_EXPORT_API void qsc_list_add(qsc_list_state* ctx, void* item);

/**
 * \brief Copy an item from the list.
 *
 * \param ctx:      [const qsc_list_state*] Pointer to the list state structure.
 * \param index:    [size_t] The index number of the list item.
 * \param item:     [void*] Pointer to the memory that receives the copy.
 */
QSC_EXPORT_API void qsc_list_copy(const qsc_list_state* ctx, size_t index, void* item);

/**
 * \brief Get the number of items in the list.
 *
 * \param ctx:      [const qsc_list_state*] Pointer to the list state structure.
 * \return          [size_t] Returns the number of items in the list.
 */
QSC_EXPORT_API size_t qsc_list_count(const qsc_list_state* ctx);

/**
 * \brief Convert a serialized list into a list context.
 *
 * \param ctx:      [qsc_list_state*] Pointer to the list state structure.
 * \param input:    [const uint8_t*]  Pointer to the serialized list.
 */
QSC_EXPORT_API void qsc_list_deserialize(qsc_list_state* ctx, const uint8_t* input);

/**
 * \brief Dispose of the list state.
 *
 * \param ctx:      [qsc_list_state*] Pointer to the list state structure.
 */
QSC_EXPORT_API void qsc_list_dispose(qsc_list_state* ctx);

/**
 * \brief Initialize the list state.
 *
 * \param ctx:      [qsc_list_state*] Pointer to the list state structure.
 * \param width:    [size_t] The maximum size of each list item in bytes.
 */
QSC_EXPORT_API void qsc_list_initialize(qsc_list_state* ctx, size_t width);

/**
 * \brief Check if the list is empty.
 *
 * \param ctx:      [const qsc_list_state*] Pointer to the list state structure.
 * \return          [bool] Returns true if the list is empty.
 */
QSC_EXPORT_API bool qsc_list_empty(const qsc_list_state* ctx);

/**
 * \brief Check if the list is full.
 *
 * \param ctx:      [const qsc_list_state*] Pointer to the list state structure.
 * \return          [bool] Returns true if the list is full.
 */
QSC_EXPORT_API bool qsc_list_full(const qsc_list_state* ctx);

/**
 * \brief Retrieve a pointer to a list item.
 *
 * \param ctx:      [const qsc_list_state*] Pointer to the list state structure.
 * \param item:     [uint8_t*] Pointer to the buffer that receives the item.
 * \param index:    [size_t] The index of the list item.
 */
QSC_EXPORT_API void qsc_list_item(const qsc_list_state* ctx, uint8_t* item, size_t index);

/**
 * \brief Randomly shuffle the items in the list.
 *
 * \param ctx:      [qsc_list_state*] Pointer to the list state structure.
 */
QSC_EXPORT_API void qsc_list_rshuffle(qsc_list_state* ctx);

/**
 * \brief Remove an item from the list.
 *
 * \param ctx:      [qsc_list_state*] Pointer to the list state structure.
 * \param index     [size_t] The index number of the item to remove.
 */
QSC_EXPORT_API void qsc_list_remove(qsc_list_state* ctx, size_t index);

/**
 * \brief Serialize the list into a byte array.
 *
 * \param output:   [uint8_t*] Pointer to the output serialized array.
 * \param ctx:      [const qsc_list_state*] Pointer to the list state structure.
 * \return          [size_t] Returns the number of bytes in the serialized list.
 */
QSC_EXPORT_API size_t qsc_list_serialize(uint8_t* output, const qsc_list_state* ctx);

/**
 * \brief Get the serialized size of the list.
 *
 * \param ctx:      [const qsc_list_state*] Pointer to the list state structure.
 * \return          [size_t] Returns the byte size of the serialized list.
 */
QSC_EXPORT_API size_t qsc_list_size(const qsc_list_state* ctx);

/**
 * \brief Sort the items in the list.
 *
 * \param ctx:      [qsc_list_state*] Pointer to the list state structure.
 */
QSC_EXPORT_API void qsc_list_sort(qsc_list_state* ctx);

#if defined(QSC_DEBUG_MODE)
/**
 * \brief Self-test for list functions.
 *
 * \return          [bool] Returns true if all tests pass.
 */
QSC_EXPORT_API bool qsc_list_self_test(void);
#endif

#endif
