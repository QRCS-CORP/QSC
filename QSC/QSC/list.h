
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

#ifndef QSC_LIST_H
#define QSC_LIST_H

#include "common.h"

/*
* \file list.h
* \brief Memory aligned list function definitions
*/

/*!
\def QSC_LIST_ALIGNMENT
* The internal memory alignment constant
*/
#define QSC_LIST_ALIGNMENT 64

/*!
\def QSC_LIST_MAX_DEPTH
* The maximum list depth
*/
#define QSC_LIST_MAX_DEPTH 102400

/*! \struct qsc_queue_state
* Contains the queue context state
*/
QSC_EXPORT_API typedef struct qsc_list_state
{
	uint8_t* items;						/*!< A pointer to the items array */
	size_t count;						/*!< The number of list items */
	size_t width;						/*!< The byte length of a list item */
} qsc_list_state;

/**
* \brief Add an item to the list
*
* \param ctx: [struct] The function state
* \param input: [pointer] The item to be added to the list
*/
QSC_EXPORT_API void qsc_list_add(qsc_list_state* ctx, void* item);

/**
* \brief Copy an item from the list
*
* \param ctx: [struct] The function state
* \param index: The index number of the list item
* \param item: A pointer to the item receiving the copy
*/
QSC_EXPORT_API void qsc_list_copy(const qsc_list_state* ctx, size_t index, void* item);

/**
* \brief Get the number of items in the list
*
* \param ctx: [struct] The function state
* 
* \return The number of items in the queue
*/
QSC_EXPORT_API size_t qsc_list_count(const qsc_list_state* ctx);

/**
* \brief Convert a serialized list into a list context
* 
* \param ctx: [struct] The function state
* \param input: [const] The serialized list
*/
QSC_EXPORT_API void qsc_list_deserialize(qsc_list_state* ctx, const uint8_t* input);

/**
* \brief Dispose of the list state
*
* \param ctx: [struct] The function state
*/
QSC_EXPORT_API void qsc_list_dispose(qsc_list_state* ctx);

/**
* \brief Initialize the list state
*
* \param ctx: [struct] The function state
* \param width: [size] The maximum size of each queue item in bytes
*/
QSC_EXPORT_API void qsc_list_initialize(qsc_list_state* ctx, size_t width);

/**
* \brief Get the empty status from the list
*
* \param ctx: [struct] The function state
* 
* \return Returns true if the list is empty
*/
QSC_EXPORT_API bool qsc_list_empty(const qsc_list_state* ctx);

/**
* \brief Get the full status from the list
*
* \param ctx: [struct] The function state
* 
* \return Returns true if the list is full
*/
QSC_EXPORT_API bool qsc_list_full(const qsc_list_state* ctx);

/**
* \brief Retrieve a pointer to a list item
*
* \param ctx: [struct] The function state
* \param item: the array receiving the item
* \param index: [size] The item index
*/
QSC_EXPORT_API void qsc_list_item(const qsc_list_state* ctx, uint8_t* item, size_t index);

/**
* \brief Returns the first member of the queue, and erases that item from the queue
*
* \param ctx: [struct] The function state
* \param index: The index number of the list item
*/
QSC_EXPORT_API void qsc_list_remove(qsc_list_state* ctx, size_t index);

/**
* \brief Serialize a list into a byte array
* 
* \param output: The serialized collection ctx
* \param ctx: [struct] The function state
*/
QSC_EXPORT_API size_t qsc_list_serialize(uint8_t* output, const qsc_list_state* ctx);

/**
* \brief Get the serialized size of a list
* 
* \param ctx: [struct] The function state
* 
* \return Returns the byte size of a serialized list
*/
QSC_EXPORT_API size_t qsc_list_size(const qsc_list_state* ctx);

/**
* \brief Sort the items in the list
*
* \param ctx: [struct] The function state
*/
QSC_EXPORT_API void qsc_list_sort(qsc_list_state* ctx);

#if defined(QSC_DEBUG_MODE)
/**
* \brief The list functions self test
*
* \return Returns true upon success
*/
QSC_EXPORT_API bool qsc_list_self_test(void);
#endif

#endif
