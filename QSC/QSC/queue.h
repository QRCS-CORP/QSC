
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

#ifndef QSC_QUEUE_H
#define QSC_QUEUE_H

#include "common.h"

/*
* \file queue.h
* \brief Memory queue function definitions
*/

/*!
\def QSC_QUEUE_ALIGNMENT
* The internal memory alignment constant
*/
#define QSC_QUEUE_ALIGNMENT 64

/*!
\def QSC_QUEUE_MAX_DEPTH
* The maximum queue depth
*/
#define QSC_QUEUE_MAX_DEPTH 64

/*! \struct qsc_queue_state
* Contains the queue context state
*/
QSC_EXPORT_API typedef struct qsc_queue_state
{
	uint8_t** queue;					/*!< The pointer to a 2 dimensional queue array */
	uint64_t tags[QSC_QUEUE_MAX_DEPTH];	/*!< The 64-bit tag associated with each queue item  */
	size_t count;						/*!< The number of queue items */
	size_t depth;						/*!< The maximum number of items in the queue */
	size_t position;					/*!< The next empty slot in the queue */
	size_t width;						/*!< The maximum byte length of a queue item */
} qsc_queue_state;

/**
* \brief Destroy the queue state
*
* \param ctx [struct] The function state
*/
QSC_EXPORT_API void qsc_queue_dispose(qsc_queue_state* ctx);

/**
* \brief Flush the content of the queue to an array
*
* \param ctx [struct] The function state
* \param output [array] The array receiving the queue items
*/
QSC_EXPORT_API void qsc_queue_flush(qsc_queue_state* ctx, uint8_t* output);

/**
* \brief Initialize the queue state
*
* \param ctx [struct] The function state
* \param depth [size] The number of queue items to initialize, maximum is QSC_QUEUE_MAX_DEPTH
* \param width [size] The maximum size of each queue item in bytes
*/
QSC_EXPORT_API void qsc_queue_initialize(qsc_queue_state* ctx, size_t depth, size_t width);

/**
* \brief Get the number of items in the queue
*
* \param ctx [struct] The function state
* \return The number of items in the queue
*/
QSC_EXPORT_API size_t qsc_queue_items(const qsc_queue_state* ctx);

/**
* \brief Get the full status from the queue
*
* \param ctx [struct] The function state
* \return Returns true if the queue is full
*/
QSC_EXPORT_API bool qsc_queue_full(const qsc_queue_state* ctx);

/**
* \brief Get the empty status from the queue
*
* \param ctx [struct] The function state
* \return Returns true if the queue is empty
*/
QSC_EXPORT_API bool qsc_queue_empty(const qsc_queue_state* ctx);

/**
* \brief Returns the first member of the queue, and erases that item from the queue
*
* \param ctx [struct] The function state
* \param output [array] The array receiving the queue item
* \param otplen [size] The number of bytes to copy from the queue item
* \return The items associated tag
*/
QSC_EXPORT_API uint64_t qsc_queue_pop(qsc_queue_state* ctx, uint8_t* output, size_t otplen);

/**
* \brief Add an item to the queue
*
* \param ctx [struct] The function state
* \param input [array] The array item to be added to the queue
* \param inplen [size] The byte size of the the queue item to be added
* \param tag [integer] The items associated tag
*/
QSC_EXPORT_API void qsc_queue_push(qsc_queue_state* ctx, const uint8_t* input, size_t inplen, uint64_t tag);

#if defined(QSC_DEBUG_MODE)
/**
* \brief The queuing functions self test
*
* \return [bool] Returns true upon success
*/
QSC_EXPORT_API bool qsc_queue_self_test(void);
#endif

#endif
