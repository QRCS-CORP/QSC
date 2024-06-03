
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

#ifndef QSC_COLLECTION_H
#define QSC_COLLECTION_H

#include "common.h"

#define QSC_COLLECTION_KEY_WIDTH 16

/*!
* \struct qsc_collection_state
* \brief The collection state structure
*/
typedef struct qsc_collection_state
{
	uint8_t* items;		/*!< A pointer to the items array */
	uint8_t* keys;		/*!< A pointer to the key array */
	uint32_t count;		/*!< The number of items */
	uint32_t width;		/*!< The item byte size */
} qsc_collection_state;

/**
* \brief Add an item to the collection
*
* \param ctx [struct] The function state
* \param item: [const] The item to add
* \param key: [const] The item key
*/
QSC_EXPORT_API void qsc_collection_add(qsc_collection_state* ctx, const uint8_t* item, const uint8_t* key);

/**
* \brief Convert a serialized collection into a collection ctx
* 
* \param ctx: [struct] The function state
* \param input: [const] The serialized collection
*/
QSC_EXPORT_API void qsc_collection_deserialize(qsc_collection_state* ctx, const uint8_t* input);

/**
* \brief Dispose of the collection and free memory
* 
* \param ctx: [struct] The function state
*/
QSC_EXPORT_API void qsc_collection_dispose(qsc_collection_state* ctx);

/**
* \brief Erase the collection
* 
* \param ctx: [struct] The function state
*/
QSC_EXPORT_API void qsc_collection_erase(qsc_collection_state* ctx);

/**
* \brief Check if an item exists in the collection
* 
* \param ctx: [struct] The function state
* \param key: [const] The item key
* 
* \return Returns true if the item exists
*/
QSC_EXPORT_API bool qsc_collection_item_exists(const qsc_collection_state* ctx, const uint8_t* key);

/**
* \brief Find an item in the collection
*
* \param ctx: [struct] The function state
* \param item: The destination item array
* \param key: [const] The item key
* 
* \return Returns true if the item was found
*/
QSC_EXPORT_API bool qsc_collection_find(const qsc_collection_state* ctx, uint8_t* item, const uint8_t* key);

/**
* \brief Initialize the collection
*
* \param ctx: [struct] The function state
* \param width: The byte size of an item
*/
QSC_EXPORT_API void qsc_collection_initialize(qsc_collection_state* ctx, size_t width);

/**
* \brief Retrieve a pointer to a collection item
*
* \param ctx: [struct] The function state
* \param index: [size] The item index
* \param item: [array] The array receiving the item
*/
QSC_EXPORT_API void qsc_collection_item(qsc_collection_state* ctx, uint8_t* item, size_t index);

/**
* \brief Remove an item from the collection
*
* \param ctx: [struct] The function state
* \param key: [const] The item key
*/
QSC_EXPORT_API void qsc_collection_remove(qsc_collection_state* ctx, const uint8_t* key);

/**
* \brief Serialize a collection into a byte array
* \param output: The serialized collection ctx
* \param ctx: [struct] The function state
* 
* \return Returns the size of the serialized collection
*/
QSC_EXPORT_API size_t qsc_collection_serialize(uint8_t* output, const qsc_collection_state* ctx);

/**
* \brief Get the serialized size of a collection
* 
* \param ctx: [struct] The function state
* 
* \return Returns the byte size of a serialized collection
*/
QSC_EXPORT_API size_t qsc_collection_size(const qsc_collection_state* ctx);

#if defined(QSC_DEBUG_MODE)
/**
* \brief Test the collections functions
*/
QSC_EXPORT_API bool qsc_collection_test();
#endif

#endif