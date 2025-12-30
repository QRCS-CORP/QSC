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

#ifndef QSC_COLLECTION_H
#define QSC_COLLECTION_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file collection.h
 * \brief A Keyed Collection Implementation.
 *
 * \details
 * This header defines the public API for a keyed collection that facilitates the storage,
 * retrieval, and management of items associated with unique keys. Items are stored in a 
 * contiguous memory block with a fixed width (in bytes) specified at initialization. The API 
 * supports operations such as adding, removing, finding, serializing, and disposing of items.
 *
 * \par Example:
 * \code
 * #include "collection.h"
 *
 * qsc_collection_state col;
 * // Initialize the collection with a fixed item size (e.g., 32 bytes).
 * qsc_collection_initialize(&col, 32);
 *
 * uint8_t sample_item[32] = { item data };
 * uint8_t sample_key[QSC_COLLECTION_KEY_WIDTH] = { key data };
 *
 * // Add an item to the collection.
 * qsc_collection_add(&col, sample_item, sample_key);
 *
 * // Check if an item exists using its key.
 * if (qsc_collection_item_exists(&col, sample_key))
 * {
 *     uint8_t retrieved[32];
 *     qsc_collection_find(&col, retrieved, sample_key);
 * }
 *
 * // Serialize the collection.
 * size_t serialized_size = qsc_collection_size(&col);
 * uint8_t* serialized = (uint8_t*)malloc(serialized_size);
 * qsc_collection_serialize(serialized, &col);
 *
 * // Dispose of the collection and free the serialized data.
 * qsc_collection_dispose(&col);
 * free(serialized);
 * \endcode
 */

/*!
 * \def QSC_COLLECTION_KEY_WIDTH
 * \brief The length (in bytes) of the key used to index collection items.
 */
#define QSC_COLLECTION_KEY_WIDTH 16ULL

/*!
 * \def QSC_COLLECTION_MAX_ENTRIES
 * \brief The maximum collection entries.
 */
#define QSC_COLLECTION_MAX_ENTRIES 32768

/*!
 * \def QSC_COLLECTION_MAX_WIDTH
 * \brief The maximum collection item width.
 */
#define QSC_COLLECTION_MAX_WIDTH 102400000

/*!
 * \struct qsc_collection_state
 * \brief Collection state structure.
 *
 * This structure represents the state of a keyed collection.
 * It maintains pointers to the array of stored items and the corresponding keys,
 * along with the count of items and the fixed size (in bytes) of each item.
 */
typedef struct
{
    uint8_t* items;   /*!< [uint8_t*] Pointer to the contiguous array storing collection items. */
    uint8_t* keys;    /*!< [uint8_t*] Pointer to the array storing keys corresponding to each item. */
    uint32_t count;   /*!< [uint32_t] Number of items currently stored in the collection. */
    uint32_t width;   /*!< [uint32_t] Fixed byte size of an individual item in the collection. */
} qsc_collection_state;

/**
 * \brief Add an item to the collection.
 *
 * Adds a new item to the collection and associates it with the specified key.
 *
 * \param ctx:      [qsc_collection_state*] Pointer to the collection state.
 * \param item:     [const uint8_t*] Pointer to the item data to be added.
 * \param key:      [const uint8_t*] Pointer to the key that uniquely identifies the item.
 */
QSC_EXPORT_API void qsc_collection_add(qsc_collection_state* ctx, const uint8_t* item, const uint8_t* key);

/**
 * \brief Deserialize a collection.
 *
 * Converts a serialized byte array into a collection state.
 *
 * \param ctx:      [qsc_collection_state*] Pointer to the collection state that will be populated.
 * \param input:    [const uint8_t*] Pointer to the serialized collection data.
 */
QSC_EXPORT_API void qsc_collection_deserialize(qsc_collection_state* ctx, const uint8_t* input);

/**
 * \brief Dispose of the collection.
 *
 * Frees any allocated memory and clears the collection state.
 *
 * \param ctx:      [qsc_collection_state*] Pointer to the collection state to dispose.
 */
QSC_EXPORT_API void qsc_collection_dispose(qsc_collection_state* ctx);

/**
 * \brief Erase the collection.
 *
 * Removes all items from the collection without deallocating the underlying storage.
 *
 * \param ctx:      [qsc_collection_state*] Pointer to the collection state to erase.
 */
QSC_EXPORT_API void qsc_collection_erase(qsc_collection_state* ctx);

/**
 * \brief Check if an item exists in the collection.
 *
 * Determines whether an item with the specified key exists in the collection.
 *
 * \param ctx:      [const qsc_collection_state*] Pointer to the collection state.
 * \param key:      [const uint8_t*] Pointer to the key of the item to check.
 *
 * \return          [bool] Returns true if the item exists; otherwise, false.
 */
QSC_EXPORT_API bool qsc_collection_item_exists(const qsc_collection_state* ctx, const uint8_t* key);

/**
 * \brief Find an item in the collection.
 *
 * Searches for an item by its key and copies it into the provided output buffer.
 *
 * \param ctx:      [const qsc_collection_state*] Pointer to the collection state.
 * \param item:     [uint8_t*] Pointer to the destination array that will receive the item data.
 * \param key:      [const uint8_t*] Pointer to the key of the item to find.
 *
 * \return          [bool] Returns true if the item was found; otherwise, false.
 */
QSC_EXPORT_API bool qsc_collection_find(const qsc_collection_state* ctx, uint8_t* item, const uint8_t* key);

/**
 * \brief Initialize the collection.
 *
 * Sets up the collection state for use by specifying the byte size of each item.
 *
 * \param ctx:      [qsc_collection_state*] Pointer to the collection state to initialize.
 * \param width:    [uint32_t] The fixed byte size of each item in the collection.
 */
QSC_EXPORT_API void qsc_collection_initialize(qsc_collection_state* ctx, uint32_t width);

/**
 * \brief Retrieve a collection item by index.
 *
 * Copies the item at the specified index into the provided output buffer.
 *
 * \param ctx:      [qsc_collection_state*] Pointer to the collection state.
 * \param item:     [uint8_t*] Pointer to the array that will receive the item data.
 * \param index:    [size_t] The zero-based index of the item to retrieve.
 */
QSC_EXPORT_API void qsc_collection_item(qsc_collection_state* ctx, uint8_t* item, size_t index);

/**
 * \brief Remove an item from the collection.
 *
 * Removes the item associated with the specified key from the collection.
 *
 * \param ctx:      [qsc_collection_state*]  Pointer to the collection state.
 * \param key:      [const uint8_t*] Pointer to the key of the item to remove.
 */
QSC_EXPORT_API void qsc_collection_remove(qsc_collection_state* ctx, const uint8_t* key);

/**
 * \brief Serialize the collection.
 *
 * Converts the entire collection into a contiguous byte array for storage or transmission.
 *
 * \param output:   [uint8_t*]  Pointer to the output buffer that will receive the serialized data.
 * \param ctx:      [const qsc_collection_state*] Pointer to the collection state.
 *
 * \return          [size_t] Returns the size in bytes of the serialized collection.
 */
QSC_EXPORT_API size_t qsc_collection_serialize(uint8_t* output, const qsc_collection_state* ctx);

/**
 * \brief Get the serialized collection size.
 *
 * Calculates the total size in bytes that the serialized collection will occupy.
 *
 * \param ctx:      [const qsc_collection_state*] Pointer to the collection state.
 *
 * \return          [size_t] Returns the byte size of the serialized collection.
 */
QSC_EXPORT_API size_t qsc_collection_size(const qsc_collection_state* ctx);

#if defined(QSC_DEBUG_MODE)
/**
 * \brief Run a self-test of the collection functions.
 *
 * Executes a series of tests to verify the correct operation of the collection API.
 *
 * \return          [bool] Returns true if all tests pass; otherwise, false.
 */
QSC_EXPORT_API bool qsc_collection_test(void);
#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
