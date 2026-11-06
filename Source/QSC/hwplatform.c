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

#include "hwplatform.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PLATFORM_ENABLED)

#include "memutils.h"

/** \struct hwplatform_key
 * \brief Transient snapshot of persistent public identity; no secret bytes.
 */
typedef struct hwplatform_key
{
	qsc_hw_platform_key_attributes attributes; /**< Original key attributes and public identity. */
} hwplatform_key;

/** \brief Validate a single bounded ASCII alias character.
 * \param c Character byte, unsigned for classification.
 * \return True only for permitted alias characters.
 */
static bool hwplatform_alias_char(uint8_t c)
{
	bool valid;

	valid = ((c >= (uint8_t)'a' && c <= (uint8_t)'z') ||
		(c >= (uint8_t)'A' && c <= (uint8_t)'Z') ||
		(c >= (uint8_t)'0' && c <= (uint8_t)'9') || c == (uint8_t)'_' ||
		c == (uint8_t)'.' || c == (uint8_t)'-');

	return valid;
}

/** \brief Validate exact alias spelling without reading beyond configured limit.
 * \param alias NUL-terminated caller alias, required non-NULL.
 * \param length Output bytes excluding NUL; non-NULL.
 * \return True for nonempty bounded alphanumeric identifiers only.
 */
static bool hwplatform_alias_valid(const char* alias, size_t* length)
{
	bool valid;
	size_t i;

	valid = false;
	i = 0U;

	if (alias != NULL && length != NULL)
	{
		while (i < QSC_HW_PLATFORM_ALIAS_MAX && alias[i] != '\0')
		{
			if (hwplatform_alias_char((uint8_t)alias[i]) == false)
			{
				break;
			}

			++i;
		}

		if (i > 0U && i < QSC_HW_PLATFORM_ALIAS_MAX && alias[i] == '\0')
		{
			*length = i;
			valid = true;
		}
	}

	return valid;
}

/** \brief Compute the canonical provider prefix without dynamic allocation.
 * \param context Initialized context.
 * \return Literal prefix or NULL for invalid family.
 */
static const char* hwplatform_prefix(const qsc_hw_platform_context* context)
{
	const char* prefix;

	prefix = NULL;

	if (context->family == qsc_hw_platform_family_apple)
	{
		prefix = "apple://";
	}
	else if (context->family == qsc_hw_platform_family_android)
	{
		prefix = "android://";
	}

	return prefix;
}

/** \brief Obtain fixed locator length and optionally write exact locator.
 * \param context Initialized context.
 * \param output Writable output or NULL for length-only mode.
 * \return Exact required length including NUL.
 */
static size_t hwplatform_format_locator(const qsc_hw_platform_context* context, char* output)
{
	const char* prefix;
	size_t i;
	size_t j;

	prefix = hwplatform_prefix(context);
	i = 0U;

	while (prefix[i] != '\0')
	{
		if (output != NULL)
		{
			output[i] = prefix[i];
		}

		++i;
	}

	j = 0U;

	while (context->alias[j] != '\0')
	{
		if (output != NULL)
		{
			output[i + j] = context->alias[j];
		}

		++j;
	}

	if (output != NULL)
	{
		output[i + j] = '\0';
	}

	return i + j + 1U;
}

/** \brief Check exact canonical string length and identity.
 * \param context Initialized identity context.
 * \param locator Untrusted NUL-terminated locator.
 * \return True if exactly equal to the configured key.
 */
static bool hwplatform_locator_matches(const qsc_hw_platform_context* context, const char* locator)
{
	char expected[QSC_HW_PLATFORM_LOCATOR_MAX] = { 0U };
	size_t expected_length;
	size_t actual_length;
	bool valid;

	valid = false;

	if (locator != NULL)
	{
		expected_length = hwplatform_format_locator(context, expected);
		actual_length = 0U;

		while (actual_length < expected_length && locator[actual_length] != '\0')
		{
			++actual_length;
		}

		if (actual_length + 1U == expected_length && locator[actual_length] == '\0')
		{
			valid = qsc_memutils_are_equal((const uint8_t*)expected, (const uint8_t*)locator, expected_length);
		}
	}

	return valid;
}

/** \brief Verify live public key and mandatory platform security properties.
 * \param context Initialized identity context.
 * \param attributes Metadata read from native keystore.
 * \return Success, unsupported or policy error.
 */
static qsc_hw_status hwplatform_attributes_check(const qsc_hw_platform_context* context,
	const qsc_hw_platform_key_attributes* attributes)
{
	qsc_hw_status status;
	bool permitted;

	status = qsc_hw_status_policy;
	permitted = false;

	if (attributes->size == sizeof(qsc_hw_platform_key_attributes) &&
		attributes->version == QSC_HW_ABI_VERSION && attributes->persistent == true &&
		attributes->private_exportable == false && attributes->public_key[0U] == 0x04U)
	{
		if (context->family == qsc_hw_platform_family_apple)
		{
			permitted = (attributes->security == qsc_hw_platform_security_enclave);
		}
		else if (context->family == qsc_hw_platform_family_android)
		{
			permitted = (attributes->security == qsc_hw_platform_security_tee ||
				attributes->security == qsc_hw_platform_security_strongbox);

			if (context->require_strongbox == true)
			{
				permitted = (attributes->security == qsc_hw_platform_security_strongbox);
			}
		}

		if (permitted == true)
		{
			status = qsc_hw_status_success;
		}
	}

	return status;
}

/** \brief Build key metadata with conservative custody if hardware is unqualified.
 * \param context Platform configuration and qualification status.
 * \param info Caller-owned output key metadata.
 */
static void hwplatform_key_info(const qsc_hw_platform_context* context, qsc_hw_key_info* info)
{
	info->size = sizeof(qsc_hw_key_info);
	info->version = QSC_HW_ABI_VERSION;
	info->algorithm = qsc_hw_algorithm_ecdsa_p256;
	info->usage = qsc_hw_usage_sign;
	info->extractable = false;
	info->custody = qsc_hw_custody_software;

	if (context->hardware_verified == true)
	{
		info->custody = qsc_hw_custody_hardware_nonexportable;
	}
}

/** \brief Bind an allowed platform public identity to transient key reference.
 * \param context Platform state.
 * \param attributes Verified live attributes.
 * \param key Receives allocated nonsecret key reference.
 * \param info Output QSC generic metadata.
 * \return Success or memory error.
 */
static qsc_hw_status hwplatform_bind(const qsc_hw_platform_context* context,
	const qsc_hw_platform_key_attributes* attributes, void** key, qsc_hw_key_info* info)
{
	hwplatform_key* reference;
	qsc_hw_status status;

	reference = (hwplatform_key*)qsc_memutils_calloc(1U, sizeof(hwplatform_key));
	status = qsc_hw_status_memory;

	if (reference != NULL)
	{
		reference->attributes = *attributes;
		*key = reference;
		hwplatform_key_info(context, info);
		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Refresh public identity to detect alias replacement or security downgrade.
 * \param context Initialized platform adapter.
 * \param reference Snapshot returned on open/generation.
 * \return Success only if key identity and security properties are unchanged.
 */
static qsc_hw_status hwplatform_refresh(qsc_hw_platform_context* context, const hwplatform_key* reference)
{
	qsc_hw_platform_key_attributes live = { 0U };
	qsc_hw_status status;

	status = qsc_hw_status_stale_key;

	if (context != NULL && context->initialized == true && reference != NULL)
	{
		live.size = sizeof(live);
		live.version = QSC_HW_ABI_VERSION;
		status = context->callbacks.query(context->service, context->alias, &live);

		if (status == qsc_hw_status_success)
		{
			status = hwplatform_attributes_check(context, &live);

			if (status == qsc_hw_status_success)
			{
				status = qsc_hw_status_stale_key;

				if (live.security == reference->attributes.security &&
					live.persistent == reference->attributes.persistent &&
					live.private_exportable == reference->attributes.private_exportable &&
					live.authentication_required == reference->attributes.authentication_required &&
					qsc_memutils_are_equal(live.public_key, reference->attributes.public_key,
						QSC_HW_PLATFORM_PUBLIC_SIZE) == true)
				{
					status = qsc_hw_status_success;
				}
			}
		}
	}

	return status;
}

/** \brief Report only actual operations provided by this native bridge.
 * \param context Initialized platform scope.
 * \param capabilities Caller-owned versioned capability output.
 * \return Typed status.
 */
static qsc_hw_status hwplatform_capabilities(void* context, qsc_hw_capabilities* capabilities)
{
	qsc_hw_platform_context* state;
	qsc_hw_status status;

	state = (qsc_hw_platform_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && state->initialized == true && capabilities != NULL &&
		capabilities->size == sizeof(qsc_hw_capabilities) &&
		capabilities->version == QSC_HW_ABI_VERSION)
	{
		capabilities->flags = qsc_hw_capability_key_open | qsc_hw_capability_public_key;
		capabilities->max_sessions = 1U;
		capabilities->thread_safe = false;
		capabilities->requires_serialization = true;
		capabilities->operation_can_block = true;
		capabilities->supports_cancel = false;

		if (state->callbacks.create != NULL)
		{
			capabilities->flags |= qsc_hw_capability_generate;
		}

		if (state->callbacks.sign_digest != NULL)
		{
			capabilities->flags |= qsc_hw_capability_sign;
		}

		status = qsc_hw_status_success;
	}

	return status;
}

/** \brief Open one exact persistent nonexportable key.
 * \param context Caller-owned native state.
 * \param locator Canonical persistent key locator.
 * \param key Receives transient reference or NULL.
 * \param info Receives key metadata on success.
 * \return Success or typed failure.
 */
static qsc_hw_status hwplatform_open_key(void* context, const char* locator, void** key, qsc_hw_key_info* info)
{
	qsc_hw_platform_key_attributes attributes = { 0U };
	qsc_hw_platform_context* state;
	qsc_hw_status status;

	state = (qsc_hw_platform_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (state != NULL && state->initialized == true && locator != NULL && key != NULL && info != NULL)
	{
		status = qsc_hw_status_stale_key;

		if (hwplatform_locator_matches(state, locator) == true)
		{
			attributes.size = sizeof(attributes);
			attributes.version = QSC_HW_ABI_VERSION;
			status = state->callbacks.query(state->service, state->alias, &attributes);

			if (status == qsc_hw_status_success)
			{
				status = hwplatform_attributes_check(state, &attributes);

				if (status == qsc_hw_status_success)
				{
					status = hwplatform_bind(state, &attributes, key, info);
				}
			}
		}
	}

	return status;
}

/** \brief Generate an entirely new persistent protected key without alias overwrite.
 * \param context Platform bridge.
 * \param policy Required key algorithm, usage and custody policy.
 * \param key Receives transient reference on success.
 * \param info Receives metadata on success.
 * \return Typed result; rollback newly created rejected key.
 */
static qsc_hw_status hwplatform_generate_key(void* context, const qsc_hw_key_policy* policy,
	void** key, qsc_hw_key_info* info)
{
	qsc_hw_platform_key_attributes attributes = { 0U };
	qsc_hw_platform_context* state;
	qsc_hw_status status;
	qsc_hw_status rollback;

	state = (qsc_hw_platform_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (key != NULL)
	{
		*key = NULL;
	}

	if (state != NULL && state->initialized == true && state->callbacks.create != NULL &&
		policy != NULL && key != NULL && info != NULL &&
		policy->algorithm == qsc_hw_algorithm_ecdsa_p256 &&
		policy->usage == qsc_hw_usage_sign && policy->allow_export == false &&
		policy->allow_derived_secret_export == false && state->callbacks.sign_digest != NULL)
	{
		status = qsc_hw_status_policy;

		if (state->hardware_verified == true ||
			(policy->require_hardware == false && policy->allow_software_fallback == true))
		{
			attributes.size = sizeof(attributes);
			attributes.version = QSC_HW_ABI_VERSION;
			status = state->callbacks.query(state->service, state->alias, &attributes);
		}

		if (status == qsc_hw_status_stale_key)
		{
			qsc_memutils_clear(&attributes, sizeof(attributes));
			attributes.size = sizeof(attributes);
			attributes.version = QSC_HW_ABI_VERSION;
			status = state->callbacks.create(state->service, state->alias,
				state->require_strongbox, &attributes);

			if (status == qsc_hw_status_success)
			{
				status = hwplatform_attributes_check(state, &attributes);

				if (status == qsc_hw_status_success)
				{
					status = hwplatform_bind(state, &attributes, key, info);
				}

				if (status != qsc_hw_status_success)
				{
					rollback = state->callbacks.rollback(state->service, state->alias);

					if (rollback != qsc_hw_status_success)
					{
						status = qsc_hw_status_internal;
					}
				}
			}
		}
		else if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_policy;
		}
	}

	return status;
}

/** \brief Release only transient host memory, preserving persistent private key.
 * \param context Unused platform configuration.
 * \param key Transient key snapshot allocation.
 */
static void hwplatform_release_key(void* context, void* key)
{
	(void)context;

	if (key != NULL)
	{
		qsc_memutils_secure_erase(key, sizeof(hwplatform_key));
		qsc_memutils_alloc_free(key);
	}
}

/** \brief Get live P-256 SEC1 public point from this protected key.
 * \param context Platform state.
 * \param key Transient validated key.
 * \param output Caller destination or NULL for size query.
 * \param outputlen In/out size including required byte count.
 * \return Typed result; no partial output on failure.
 */
static qsc_hw_status hwplatform_public_key(void* context, void* key, uint8_t* output, size_t* outputlen)
{
	qsc_hw_platform_context* state;
	hwplatform_key* reference;
	qsc_hw_status status;
	size_t capacity;

	state = (qsc_hw_platform_context*)context;
	reference = (hwplatform_key*)key;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && reference != NULL && outputlen != NULL)
	{
		status = hwplatform_refresh(state, reference);

		if (status == qsc_hw_status_success)
		{
			capacity = *outputlen;
			*outputlen = QSC_HW_PLATFORM_PUBLIC_SIZE;
			status = qsc_hw_status_buffer_too_small;

			if (output == NULL)
			{
				status = qsc_hw_status_success;
			}
			else if (capacity >= QSC_HW_PLATFORM_PUBLIC_SIZE)
			{
				qsc_memutils_copy(output, reference->attributes.public_key, QSC_HW_PLATFORM_PUBLIC_SIZE);
				status = qsc_hw_status_success;
			}
		}
	}

	return status;
}

/** \brief Sign one 32-byte digest with the exact persistent platform key.
 * \param context Native adapter context.
 * \param key Transient key snapshot.
 * \param algorithm Must equal ECDSA P-256.
 * \param message Precomputed SHA-256 digest.
 * \param msglen Exactly 32 bytes.
 * \param signature Caller output or NULL for size query.
 * \param signaturelen In/out capacity/actual byte count.
 * \return Success or typed failure; caller output cleared on failed signing.
 */
static qsc_hw_status hwplatform_sign(void* context, void* key, qsc_hw_algorithm algorithm,
	const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen)
{
	qsc_hw_platform_context* state;
	hwplatform_key* reference;
	qsc_hw_status status;
	size_t capacity;
	size_t written;

	state = (qsc_hw_platform_context*)context;
	reference = (hwplatform_key*)key;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && reference != NULL && message != NULL && signaturelen != NULL &&
		state->callbacks.sign_digest != NULL && algorithm == qsc_hw_algorithm_ecdsa_p256 && msglen == 32U)
	{
		status = hwplatform_refresh(state, reference);

		if (status == qsc_hw_status_success)
		{
			capacity = *signaturelen;
			*signaturelen = QSC_HW_PLATFORM_SIGNATURE_SIZE;
			status = qsc_hw_status_buffer_too_small;

			if (signature == NULL)
			{
				status = qsc_hw_status_success;
			}
			else if (capacity >= QSC_HW_PLATFORM_SIGNATURE_SIZE)
			{
				written = capacity;
				status = state->callbacks.sign_digest(state->service, state->alias, message,
					msglen, signature, &written);

				if (status == qsc_hw_status_success && written != QSC_HW_PLATFORM_SIGNATURE_SIZE)
				{
					status = qsc_hw_status_policy;
				}

				if (status != qsc_hw_status_success)
				{
					qsc_memutils_secure_erase(signature, capacity);
				}
			}
		}
	}

	return status;
}

qsc_hw_status qsc_hw_platform_initialize(qsc_hw_platform_context* context,
	const qsc_hw_platform_callbacks* callbacks, void* service, qsc_hw_platform_family family,
	const char* alias, bool require_strongbox, bool hardware_verified)
{
	qsc_hw_status status;
	size_t length;

	status = qsc_hw_status_invalid_parameter;
	length = 0U;

	if (context != NULL && callbacks != NULL && service != NULL &&
		callbacks->size == sizeof(qsc_hw_platform_callbacks) &&
		callbacks->version == QSC_HW_ABI_VERSION && callbacks->query != NULL &&
		(callbacks->create == NULL || callbacks->rollback != NULL) &&
		(family == qsc_hw_platform_family_apple || family == qsc_hw_platform_family_android) &&
		(require_strongbox == false || family == qsc_hw_platform_family_android) &&
		hwplatform_alias_valid(alias, &length) == true && context->initialized == false)
	{
		qsc_memutils_clear(context, sizeof(qsc_hw_platform_context));
		context->callbacks = *callbacks;
		context->service = service;
		context->family = family;
		context->require_strongbox = require_strongbox;
		context->hardware_verified = hardware_verified;
		qsc_memutils_copy(context->alias, alias, length);
		context->alias[length] = '\0';
		context->initialized = true;
		status = qsc_hw_status_success;
	}

	return status;
}

qsc_hw_status qsc_hw_platform_get_operations(qsc_hw_provider_ops* operations)
{
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (operations != NULL)
	{
		qsc_memutils_clear(operations, sizeof(qsc_hw_provider_ops));
		operations->size = sizeof(qsc_hw_provider_ops);
		operations->version = QSC_HW_ABI_VERSION;
		operations->get_capabilities = hwplatform_capabilities;
		operations->release_key = hwplatform_release_key;
		operations->open_key = hwplatform_open_key;
		operations->generate_key = hwplatform_generate_key;
		operations->sign = hwplatform_sign;
		operations->public_key = hwplatform_public_key;
		status = qsc_hw_status_success;
	}

	return status;
}

qsc_hw_status qsc_hw_platform_locator(const qsc_hw_platform_context* context, char* output, size_t* outputlen)
{
	size_t required;
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && context->initialized == true && outputlen != NULL)
	{
		required = hwplatform_format_locator(context, NULL);
		status = qsc_hw_status_buffer_too_small;

		if (output == NULL)
		{
			status = qsc_hw_status_success;
		}
		else if (*outputlen >= required)
		{
			(void)hwplatform_format_locator(context, output);
			status = qsc_hw_status_success;
		}

		*outputlen = required;
	}

	return status;
}

void qsc_hw_platform_dispose(qsc_hw_platform_context* context)
{
	if (context != NULL)
	{
		qsc_memutils_secure_erase(context, sizeof(qsc_hw_platform_context));
	}
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PLATFORM_ENABLED */
