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

#ifndef QSC_QUEUE_H
#define QSC_QUEUE_H

#include "qsccommon.h"
#include "async.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file queue.h
 * \brief Memory queue function definitions.
 *
 * \details
 * The queue implementation provides functions for managing a memory queue that stores items along with associated
 * 64-bit tags. The queue supports operations to push items onto the queue, pop items off the queue,
 * and flush the queue contents into a contiguous byte array for serialization or further processing.
 * Additionally, the header provides functions to check if the queue is full or empty, and to retrieve
 * the current number of items in the queue. The queue is implemented as a contiguous memory block with
 * fixed capacity, ensuring predictable memory usage and performance.
 *
 * \par Example Usage:
 * \code
 * #include "queue.h"
 *
 * qsc_queue_state collection;
 * // Initialize the queue with a depth of 32 items, each 64 bytes wide.
 * qsc_queue_initialize(&collection, 32, 64);
 *
 * uint8_t sample_item[64] = { item data };
 * uint64_t tag = 123456789;
 *
 * // Push the item into the queue.
 * qsc_queue_push(&collection, sample_item, sizeof(sample_item), tag);
 *
 * // Check if the queue is empty.
 * if (!qsc_queue_empty(&collection))
 * {
 *     uint8_t retrieved[64];
 *     uint64_t retrieved_tag = qsc_queue_pop(&collection, retrieved, sizeof(retrieved));
 * }
 *
 * // Serialize the queue into an array.
 * size_t serialized_size = qsc_queue_size(&collection);
 * uint8_t* serialized = malloc(serialized_size);
 * qsc_queue_serialize(serialized, &collection);
 *
 * // Dispose the collection.
 * qsc_queue_dispose(&collection);
 * free(serialized);
 * \endcode
 */

/*!
 * \def QSC_QUEUE_ALIGNMENT
 * \brief The internal memory alignment constant.
 */
#define QSC_QUEUE_ALIGNMENT 64ULL

/*!
 * \def QSC_QUEUE_MAX_DEPTH
 * \brief The maximum queue depth.
 */
#define QSC_QUEUE_MAX_DEPTH 64UL

/*! \struct qsc_queue_state
 * \brief Contains the queue context state.
 */
QSC_EXPORT_API typedef struct
{
    uint8_t** queue;                    /*!< The pointer to a 2-dimensional queue array. */
    uint64_t tags[QSC_QUEUE_MAX_DEPTH]; /*!< The 64-bit tag associated with each queue item. */
    size_t count;                       /*!< The number of queue items. */
    size_t depth;                       /*!< The maximum number of items in the queue. */
    size_t position;                    /*!< The next empty slot in the queue. */
    size_t width;                       /*!< The maximum byte length of a queue item. */
    qsc_mutex opmtx;                    /*!< The operations mutex. */
} qsc_queue_state;

/**
 * \brief Destroy the queue state.
 *
 * \param ctx: [struct] A pointer to the queue state structure.
 */
QSC_EXPORT_API void qsc_queue_dispose(qsc_queue_state* ctx);

/**
 * \brief Flush the content of the queue to an array.
 *
 * \param ctx: [qsc_queue_state*] A pointer to the queue state structure.
 * \param output: [uint8_t*] A pointer to the array receiving the queue items.
 */
QSC_EXPORT_API void qsc_queue_flush(qsc_queue_state* ctx, uint8_t* output);

/**
 * \brief Initialize the queue state.
 *
 * \param ctx: [qsc_queue_state*] A pointer to the queue state structure.
 * \param depth: [size_t] The number of queue items to initialize, maximum is QSC_QUEUE_MAX_DEPTH.
 * \param width: [size_t] The maximum size of each queue item in bytes.
 */
QSC_EXPORT_API void qsc_queue_initialize(qsc_queue_state* ctx, size_t depth, size_t width);

/**
 * \brief Get the number of items in the queue.
 *
 * \param ctx: [const qsc_queue_state*] A pointer to the queue state structure.
 * 
 * \return [size_t] The number of items in the queue.
 */
QSC_EXPORT_API size_t qsc_queue_items(const qsc_queue_state* ctx);

/**
 * \brief Get the full status from the queue.
 *
 * \param ctx: [const qsc_queue_state*] A pointer to the queue state structure.
 * 
 * \return [bool] Returns true if the queue is full.
 */
QSC_EXPORT_API bool qsc_queue_full(const qsc_queue_state* ctx);

/**
 * \brief Get the empty status from the queue.
 *
 * \param ctx: [const qsc_queue_state*] A pointer to the queue state structure.
 * 
 * \return [bool] Returns true if the queue is empty.
 */
QSC_EXPORT_API bool qsc_queue_empty(const qsc_queue_state* ctx);

/**
 * \brief Returns the first member of the queue, and erases that item from the queue.
 *
 * \param ctx: [qsc_queue_state*] A pointer to the queue state structure.
 * \param output: [uint8_t*] A pointer to the array receiving the queue item.
 * \param otplen: [size_t] The number of bytes to copy from the queue item.
 * 
 * \return [uint64_t] The tag associated with the removed item.
 */
QSC_EXPORT_API uint64_t qsc_queue_pop(qsc_queue_state* ctx, uint8_t* output, size_t otplen);

/**
 * \brief Add an item to the queue.
 *
 * \param ctx: [qsc_queue_state*] A pointer to the queue state structure.
 * \param input: [uint8_t*] A pointer to the array item to be added to the queue.
 * \param inplen: [size_t] The byte size of the queue item to be added.
 * \param tag: [uint64_t] The tag associated with the item.
 */
QSC_EXPORT_API void qsc_queue_push(qsc_queue_state* ctx, const uint8_t* input, size_t inplen, uint64_t tag);

#if defined(QSC_DEBUG_MODE)
/**
 * \brief Self-test function for the queue operations.
 *
 * \return [bool] Returns true upon success.
 */
QSC_EXPORT_API bool qsc_queue_self_test(void);
#endif

QSC_CPLUSPLUS_ENABLED_END

#endif
