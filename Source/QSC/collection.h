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

#ifndef QSC_COLLECTION_H
#define QSC_COLLECTION_H

#include "common.h"

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
 * \param width:    [size_t] The fixed byte size of each item in the collection.
 */
QSC_EXPORT_API void qsc_collection_initialize(qsc_collection_state* ctx, size_t width);

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
