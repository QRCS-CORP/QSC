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

#include "event.h"
#include "memutils.h"
#include <stddef.h>
#include <string.h>

/** \brief Private allocation header. Items remain naturally aligned; no public ABI change. */
typedef struct qsc_event_storage
{
	size_t capacity;             /*!< Number of allocated listener slots. */
	qsc_event_handler items[];  /*!< Contiguous, naturally aligned listener storage. */
} qsc_event_storage;

/** \brief Recover the owner of a library-allocated listener array. */
static qsc_event_storage* event_storage_from_items(qsc_event_handler* items)
{
	qsc_event_storage* res;

	res = (qsc_event_storage*)((uint8_t*)items - offsetof(qsc_event_storage, items));

	return res;
}

/** \brief Compare fixed-size event names without reading past the first terminator. */
static bool event_name_equal(const char* left, const char* right)
{
	bool res;

	res = (strncmp(left, right, QSC_EVENT_NAME_SIZE) == 0);

	return res;
}

/** \brief Copy at most the fixed event-name extent, zero-filling unused bytes. */
static void event_name_copy(char* output, const char* input)
{
	size_t i;

	qsc_memutils_clear(output, QSC_EVENT_NAME_SIZE);

	for (i = 0U; i < QSC_EVENT_NAME_SIZE; ++i)
	{
		if (input[i] == '\0')
		{
			break;
		}

		output[i] = input[i];
	}
}

/** \brief Find a callback while the caller holds the state's mutex. */
static size_t event_find_locked(const event_state* ctx, const char* name)
{
	size_t res;

	res = ctx->lcount;

	for (size_t i = 0U; i < ctx->lcount; ++i)
	{
		if (event_name_equal(ctx->listeners[i].name, name) == true)
		{
			res = i;
			break;
		}
	}

	return res;
}

/** \brief Increase listener capacity geometrically; preserve state on allocation failure. */
static bool event_reserve_locked(event_state* ctx, size_t needed)
{
	qsc_event_storage* storage;
	qsc_event_storage* grown;
	size_t capacity;
	bool res;

	res = false;
	storage = NULL;
	capacity = 0U;

	if (ctx->listeners != NULL)
	{
		storage = event_storage_from_items(ctx->listeners);
		capacity = storage->capacity;
	}

	if (needed <= capacity)
	{
		res = true;
	}
	else if (needed <= QSC_EVENT_MAX_LISTENERS)
	{
		capacity = (capacity == 0U) ? 8U : capacity;

		while (capacity < needed && capacity < QSC_EVENT_MAX_LISTENERS)
		{
			capacity = (capacity <= (QSC_EVENT_MAX_LISTENERS / 2U)) ? (capacity * 2U) : QSC_EVENT_MAX_LISTENERS;
		}

		if (capacity <= ((SIZE_MAX - offsetof(qsc_event_storage, items)) / sizeof(qsc_event_handler)))
		{
			if (storage == NULL)
			{
				grown = (qsc_event_storage*)qsc_memutils_malloc(offsetof(qsc_event_storage, items) + (capacity * sizeof(qsc_event_handler)));
			}
			else
			{
				grown = (qsc_event_storage*)qsc_memutils_realloc(storage, offsetof(qsc_event_storage, items) + (capacity * sizeof(qsc_event_handler)));
			}

			if (grown != NULL)
			{
				grown->capacity = capacity;
				ctx->listeners = grown->items;
				res = true;
			}
		}
	}

	return res;
}

void qsc_event_clear_listener(event_state* ctx, const char name[QSC_EVENT_NAME_SIZE])
{
	size_t index;

	if (ctx != NULL && name != NULL && ctx->initialized == true && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		index = event_find_locked(ctx, name);

		if (index < ctx->lcount)
		{
			for (size_t i = index; (i + 1U) < ctx->lcount; ++i)
			{
				ctx->listeners[i] = ctx->listeners[i + 1U];
			}

			--ctx->lcount;
			qsc_memutils_clear(&ctx->listeners[ctx->lcount], sizeof(qsc_event_handler));
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}
}

void qsc_event_dispose(event_state* ctx)
{
	qsc_event_storage* storage;

	if (ctx != NULL && ctx->initialized == true && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->listeners != NULL)
		{
			storage = event_storage_from_items(ctx->listeners);
			qsc_memutils_secure_erase(ctx->listeners, ctx->lcount * sizeof(qsc_event_handler));
			qsc_memutils_alloc_free(storage);
		}

		ctx->listeners = NULL;
		ctx->lcount = 0U;
		ctx->initialized = false;
		qsc_async_mutex_unlock(ctx->opmtx);
		(void)qsc_async_mutex_destroy(ctx->opmtx);
		ctx->opmtx = NULL;
	}
}

qsc_event_callback qsc_event_get_callback(event_state* ctx, const char name[QSC_EVENT_NAME_SIZE])
{
	qsc_event_callback res;
	size_t index;

	res = NULL;

	if (ctx != NULL && name != NULL && ctx->initialized == true && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		index = event_find_locked(ctx, name);

		if (index < ctx->lcount)
		{
			res = ctx->listeners[index].callback;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

void qsc_event_initialize(event_state* ctx)
{
	if (ctx != NULL)
	{
		ctx->opmtx = qsc_async_mutex_create();
		ctx->lcount = 0U;
		ctx->listeners = NULL;
		ctx->initialized = (ctx->opmtx != NULL);
	}
}

bool qsc_event_listener_name_exists(const event_state* ctx, const char name[QSC_EVENT_NAME_SIZE])
{
	bool res;

	res = false;

	if (ctx != NULL && name != NULL && ctx->initialized == true && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);
		res = (event_find_locked(ctx, name) < ctx->lcount);
		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}

int32_t qsc_event_register(event_state* ctx, const char name[QSC_EVENT_NAME_SIZE], qsc_event_callback callback)
{
	qsc_event_handler* handler;
	int32_t res;

	res = -1;

	if (ctx != NULL && name != NULL && callback != NULL && ctx->initialized == true && ctx->opmtx != NULL)
	{
		qsc_async_mutex_lock(ctx->opmtx);

		if (ctx->lcount < QSC_EVENT_MAX_LISTENERS && event_find_locked(ctx, name) == ctx->lcount && event_reserve_locked(ctx, ctx->lcount + 1U) == true)
		{
			handler = &ctx->listeners[ctx->lcount];
			qsc_memutils_clear(handler, sizeof(qsc_event_handler));
			event_name_copy(handler->name, name);
			handler->callback = callback;
			++ctx->lcount;
			res = 0;
		}

		qsc_async_mutex_unlock(ctx->opmtx);
	}

	return res;
}
