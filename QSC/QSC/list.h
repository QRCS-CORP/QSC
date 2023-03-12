/*
* Copyright (c) 2023 Quantum Secure Cryptographic Solutions QSCS Corp. (QSCS.ca).
* This file is part of the QSC Cryptographic library.
* The QSC library was written as a prototyping library for post-quantum primitives,
* in the hopes that it would be useful for educational purposes only.
* Any use of the QSC library in a commercial context, or reproduction of original material
* contained in this library is strictly forbidden unless prior written consent is obtained
* from the QSCS Corporation.
*
* The AGPL version 3 License (AGPLv3)
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
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
	uint8_t** items;					/*!< The pointer to a 2 dimensional array */
	size_t count;						/*!< The number of list items */
	size_t depth;						/*!< The maximum number of items in the list */
	size_t width;						/*!< The byte length of a list item */
} qsc_list_state;

/**
* \brief Add an item to the list
*
* \param ctx [struct] The function state
* \param input [pointer] The item to be added to the list
*/
QSC_EXPORT_API bool qsc_list_add(qsc_list_state* ctx, void* item);

/**
* \brief Copy an item from the list
*
* \param ctx [struct] The function state
* \param index The index number of the list item
* \param item A pointer to the item receiving the copy
*/
QSC_EXPORT_API void qsc_list_copy(const qsc_list_state* ctx, size_t index, void* item);

/**
* \brief Get the number of items in the list
*
* \param ctx [struct] The function state
* \return The number of items in the queue
*/
QSC_EXPORT_API size_t qsc_list_count(const qsc_list_state* ctx);

/**
* \brief Destroy the list state
*
* \param ctx [struct] The function state
*/
QSC_EXPORT_API void qsc_list_destroy(qsc_list_state* ctx);

/**
* \brief Initialize the list state
*
* \param ctx [struct] The function state
* \param depth [size] The number of queue items to initialize, maximum is QSC_QUEUE_MAX_DEPTH
* \param width [size] The maximum size of each queue item in bytes
*/
QSC_EXPORT_API void qsc_list_initialize(qsc_list_state* ctx, size_t depth, size_t width);

/**
* \brief Get the empty status from the list
*
* \param ctx [struct] The function state
* \return Returns true if the list is empty
*/
QSC_EXPORT_API bool qsc_list_isempty(const qsc_list_state* ctx);

/**
* \brief Get the full status from the list
*
* \param ctx [struct] The function state
* \return Returns true if the list is full
*/
QSC_EXPORT_API bool qsc_list_isfull(const qsc_list_state* ctx);

/**
* \brief Returns the first member of the queue, and erases that item from the queue
*
* \param ctx [struct] The function state
* \param index The index number of the list item
*/
QSC_EXPORT_API void qsc_list_remove(qsc_list_state* ctx, size_t index);

#if defined(QSC_DEBUG_MODE)
/**
* \brief The list functions self test
*
* \return [bool] Returns true upon success
*/
QSC_EXPORT_API bool qsc_list_self_test(void);
#endif

#endif
