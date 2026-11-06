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

#include "hwmock.h"

#if defined(QSC_HARDWARE_ENABLED)

#include "memutils.h"

#include "stringutils.h"

/** \file hwmock.c
 * \brief Deterministic PKCS#11-like backend simulator without genuine cryptography.
 * \note Single-threaded tests only. It deliberately models backend errors, not timing leakage.
 */

/** \brief Check whether a selected mock action should fail.
 * \param context Active mock token.
 * \param action Requested backend operation.
 * \return success when no fault configured; otherwise configured error.
 */
static qsc_hw_status hwmock_fault(qsctest_hwmock_context* context, qsctest_hwmock_action action)
{
	qsc_hw_status status;

	status = qsc_hw_status_success;

	if (context->fault_action == action)
	{
		context->fault_issued = true;
		status = context->fault_status;
	}

	return status;
}

/** \brief Verify token readiness and its simulated single-operation queue.
 * \param context Active simulated token.
 * \param authenticated True when operation requires a logged-in user.
 * \return success, device_removed, busy, locked or auth_required.
 */
static qsc_hw_status hwmock_ready(const qsctest_hwmock_context* context, bool authenticated)
{
	qsc_hw_status status;

	status = qsc_hw_status_success;

	if (context->present == false)
	{
		status = qsc_hw_status_device_removed;
	}
	else if (context->operation_active == true)
	{
		status = qsc_hw_status_busy;
	}
	else if (context->pin_locked == true)
	{
		status = qsc_hw_status_locked;
	}
	else if (authenticated == true && context->authenticated == false)
	{
		status = qsc_hw_status_auth_required;
	}

	return status;
}

/** \brief Fill metadata using the mock object's attributes.
 * \param context Simulator holding metadata-corruption switches.
 * \param key Synthetic backend key.
 * \param info Versioned, caller-owned metadata output.
 */
static void hwmock_fill_info(const qsctest_hwmock_context* context, const qsctest_hwmock_key* key, qsc_hw_key_info* info)
{
	info->size = sizeof(qsc_hw_key_info);
	info->version = (context->bad_metadata == true) ? 0U : QSC_HW_ABI_VERSION;
	info->algorithm = key->algorithm;
	info->usage = key->usage;
	info->custody = (context->software_custody == true) ? qsc_hw_custody_software : key->custody;
	info->extractable = (context->extractable == true) ? true : key->extractable;
}

/** \brief Map an exact synthetic persistent locator to an existing object.
 * \param context Simulator instance with fixed object table.
 * \param locator Required NUL-terminated persistent selector.
 * \return Matching object, or NULL when selector is unknown/serial changed.
 */
static qsctest_hwmock_key* hwmock_find(qsctest_hwmock_context* context, const char* locator)
{
	qsctest_hwmock_key* key;

	key = NULL;

	if (qsc_stringutils_strings_equal(locator, "mock:010203:01") == true)
	{
		key = &context->keys[0U];
	}
	else if (qsc_stringutils_strings_equal(locator, "mock:010203:02") == true)
	{
		key = &context->keys[1U];
	}

	if (key != NULL)
	{
		if (key->exists == false || key->serial != context->serial)
		{
			key = NULL;
		}
	}

	return key;
}

/** \brief Return exact test backend capabilities without inventing hardware assurance.
 * \param context Caller-owned simulator state.
 * \param capabilities Versioned caller-owned output.
 * \return success, injected error, or invalid_parameter.
 */
static qsc_hw_status hwmock_capabilities(void* context, qsc_hw_capabilities* capabilities)
{
	qsctest_hwmock_context* state;
	qsc_hw_status status;

	state = (qsctest_hwmock_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && capabilities != NULL)
	{
		status = hwmock_fault(state, qsctest_hwmock_action_capabilities);

		if (status == qsc_hw_status_success)
		{
			capabilities->flags = qsc_hw_capability_key_open | qsc_hw_capability_generate | qsc_hw_capability_sign |
				qsc_hw_capability_agree | qsc_hw_capability_random | qsc_hw_capability_attest | qsc_hw_capability_public_key;
			capabilities->max_sessions = QSCTEST_HWMOCK_SESSION_LIMIT;
			capabilities->thread_safe = false;
			capabilities->requires_serialization = true;
			capabilities->operation_can_block = true;
			capabilities->supports_cancel = false;

			if (state->bad_capabilities == true)
			{
				capabilities->flags |= 0x80000000U;
			}
		}
	}

	return status;
}

/** \brief Open a synthetic persistent key and consume one simulated session.
 * \param context Mock token state.
 * \param locator Known locator selected by caller.
 * \param key Output backend handle, never private bytes.
 * \param info Output mock key attributes.
 * \return Typed device, auth, timeout, busy, missing-key or success status.
 */
static qsc_hw_status hwmock_open(void* context, const char* locator, void** key, qsc_hw_key_info* info)
{
	qsctest_hwmock_context* state;
	qsctest_hwmock_key* found;
	qsc_hw_status status;

	state = (qsctest_hwmock_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && locator != NULL && key != NULL && info != NULL)
	{
		status = hwmock_ready(state, true);

		if (status == qsc_hw_status_success)
		{
			status = hwmock_fault(state, qsctest_hwmock_action_open);
		}

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_busy;

			if (state->sessions < QSCTEST_HWMOCK_SESSION_LIMIT)
			{
				found = hwmock_find(state, locator);
				status = qsc_hw_status_unsupported;

				if (found != NULL)
				{
					*key = found;
					found->references += 1U;
					state->sessions += 1U;
					state->opens += 1U;
					hwmock_fill_info(state, found, info);
					status = qsc_hw_status_success;
				}
			}
		}
	}

	return status;
}

/** \brief Create a deterministic synthetic key object under requested policy.
 * \param context Caller-owned simulator.
 * \param policy QSC validated requested policy.
 * \param key Output transient synthetic key pointer.
 * \param info Output actual mock key metadata.
 * \return success, unsupported on full object table, busy, auth or injected error.
 */
static qsc_hw_status hwmock_generate(void* context, const qsc_hw_key_policy* policy, void** key, qsc_hw_key_info* info)
{
	qsctest_hwmock_context* state;
	qsctest_hwmock_key* found;
	qsc_hw_status status;
	size_t i;

	state = (qsctest_hwmock_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && policy != NULL && key != NULL && info != NULL)
	{
		status = hwmock_ready(state, true);

		if (status == qsc_hw_status_success)
		{
			status = hwmock_fault(state, qsctest_hwmock_action_generate);
		}

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_busy;

			if (state->sessions < QSCTEST_HWMOCK_SESSION_LIMIT)
			{
				status = qsc_hw_status_unsupported;

				for (i = 0U; i < QSCTEST_HWMOCK_KEY_CAPACITY; ++i)
				{
					if (state->keys[i].exists == false)
					{
						found = &state->keys[i];
						found->exists = true;
						found->object_id = (uint32_t)(i + 1U);
						found->serial = state->serial;
						found->algorithm = policy->algorithm;
						found->usage = policy->usage;
						found->custody = qsc_hw_custody_hardware_nonexportable;
						found->extractable = false;
						found->references = 1U;
						state->sessions += 1U;
						state->generations += 1U;
						*key = found;
						hwmock_fill_info(state, found, info);
						status = qsc_hw_status_success;
						break;
					}
				}
			}
		}
	}

	return status;
}

/** \brief Release one mock transient key reference, retaining its persistent object.
 * \param context Caller-owned simulator state.
 * \param key Previously returned synthetic key pointer.
 */
static void hwmock_release(void* context, void* key)
{
	qsctest_hwmock_context* state;
	qsctest_hwmock_key* entry;
	size_t i;

	state = (qsctest_hwmock_context*)context;

	if (state != NULL && key != NULL)
	{
		for (i = 0U; i < QSCTEST_HWMOCK_KEY_CAPACITY; ++i)
		{
			entry = &state->keys[i];

			if (key == entry && entry->references > 0U && state->sessions > 0U)
			{
				entry->references -= 1U;
				state->sessions -= 1U;
				state->releases += 1U;
				break;
			}
		}
	}
}

/** \brief Count provider disposal without freeing caller-owned simulator state.
 * \param context Caller-owned simulator state.
 */
static void hwmock_dispose(void* context)
{
	qsctest_hwmock_context* state;

	state = (qsctest_hwmock_context*)context;

	if (state != NULL)
	{
		state->closes += 1U;
	}
}

/** \brief Emit deterministic noncryptographic signatures with buffer-size contract.
 * \param context Caller-owned simulator state.
 * \param key Active synthetic key reference.
 * \param algorithm Requested algorithm matching key.
 * \param message Caller-owned input bytes.
 * \param msglen Input byte length.
 * \param signature Caller-owned output or NULL for size query.
 * \param signaturelen In/out capacity or required length.
 * \return success, buffer_too_small or typed injected error.
 */
static qsc_hw_status hwmock_sign(void* context, void* key, qsc_hw_algorithm algorithm, const uint8_t* message, size_t msglen, uint8_t* signature, size_t* signaturelen)
{
	qsctest_hwmock_context* state;
	qsctest_hwmock_key* entry;
	qsc_hw_status status;
	size_t i;
	uint8_t sum;

	state = (qsctest_hwmock_context*)context;
	entry = (qsctest_hwmock_key*)key;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && entry != NULL && signaturelen != NULL && (message != NULL || msglen == 0U))
	{
		status = hwmock_ready(state, true);

		if (status == qsc_hw_status_success && entry->algorithm != algorithm)
		{
			status = qsc_hw_status_unsupported;
		}

		if (status == qsc_hw_status_success)
		{
			status = hwmock_fault(state, qsctest_hwmock_action_sign);

			if (status != qsc_hw_status_success && state->fault_partial_output == true && signature != NULL && *signaturelen > 0U)
			{
				signature[0U] = 0xA5U;
			}
		}

		if (status == qsc_hw_status_success)
		{
			state->signatures += 1U;
			status = qsc_hw_status_buffer_too_small;

			if (signature != NULL && *signaturelen >= QSCTEST_HWMOCK_SIGNATURE_SIZE)
			{
				sum = 0U;

				for (i = 0U; i < msglen; ++i)
				{
					sum ^= message[i];
				}

				for (i = 0U; i < QSCTEST_HWMOCK_SIGNATURE_SIZE; ++i)
				{
					signature[i] = (uint8_t)(sum ^ (uint8_t)i ^ (uint8_t)entry->object_id);
				}

				status = qsc_hw_status_success;
			}

			*signaturelen = QSCTEST_HWMOCK_SIGNATURE_SIZE;
		}
	}

	return status;
}

/** \brief Simulate agreement with synthetic, exportable test output.
 * \param context Caller-owned simulator.
 * \param key Active synthetic backend key.
 * \param peer Nonempty synthetic peer-public input.
 * \param peerlen Peer byte count.
 * \param secret Caller-owned test output, or NULL for sizing.
 * \param secretlen In/out output size.
 * \return success, buffer_too_small or injected failure.
 */
static qsc_hw_status hwmock_agree(void* context, void* key, const uint8_t* peer, size_t peerlen, uint8_t* secret, size_t* secretlen)
{
	qsctest_hwmock_context* state;
	qsctest_hwmock_key* entry;
	qsc_hw_status status;
	size_t i;

	state = (qsctest_hwmock_context*)context;
	entry = (qsctest_hwmock_key*)key;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && entry != NULL && peer != NULL && peerlen > 0U && secretlen != NULL)
	{
		status = hwmock_ready(state, true);

		if (status == qsc_hw_status_success)
		{
			status = hwmock_fault(state, qsctest_hwmock_action_agree);

			if (status != qsc_hw_status_success && state->fault_partial_output == true && secret != NULL && *secretlen > 0U)
			{
				secret[0U] = 0xA5U;
			}
		}

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_buffer_too_small;

			if (secret != NULL && *secretlen >= QSCTEST_HWMOCK_SECRET_SIZE)
			{
				for (i = 0U; i < QSCTEST_HWMOCK_SECRET_SIZE; ++i)
				{
					secret[i] = (uint8_t)(0xC0U ^ peer[i % peerlen] ^ (uint8_t)i);
				}

				status = qsc_hw_status_success;
			}

			*secretlen = QSCTEST_HWMOCK_SECRET_SIZE;
		}
	}

	return status;
}

/** \brief Emit noncryptographic deterministic test randomness.
 * \param context Caller-owned simulator.
 * \param output Caller-owned output bytes.
 * \param length Requested test byte count.
 * \return success or injected fault; never real entropy.
 */
static qsc_hw_status hwmock_random(void* context, uint8_t* output, size_t length)
{
	qsctest_hwmock_context* state;
	qsc_hw_status status;
	size_t i;

	state = (qsctest_hwmock_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && (output != NULL || length == 0U))
	{
		status = hwmock_ready(state, false);

		if (status == qsc_hw_status_success)
		{
			status = hwmock_fault(state, qsctest_hwmock_action_random);

			if (status != qsc_hw_status_success && state->fault_partial_output == true && output != NULL && length > 0U)
			{
				output[0U] = 0xA5U;
			}
		}

		if (status == qsc_hw_status_success)
		{
			for (i = 0U; i < length; ++i)
			{
				output[i] = (uint8_t)(0x30U ^ (uint8_t)i);
			}
		}
	}

	return status;
}

/** \brief Produce a synthetic quote-like envelope, not real attestation.
 * \param context Caller-owned mock.
 * \param key Synthetic backend key.
 * \param challenge Required nonempty challenge.
 * \param challengelen Challenge length.
 * \param evidence Caller-owned output or NULL for size query.
 * \param evidencelen In/out size.
 * \return success, buffer_too_small or injected error.
 */
static qsc_hw_status hwmock_attest(void* context, void* key, const uint8_t* challenge, size_t challengelen, uint8_t* evidence, size_t* evidencelen)
{
	qsctest_hwmock_context* state;
	qsc_hw_status status;
	size_t i;

	state = (qsctest_hwmock_context*)context;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && key != NULL && challenge != NULL && challengelen > 0U && evidencelen != NULL)
	{
		status = hwmock_ready(state, true);

		if (status == qsc_hw_status_success)
		{
			status = hwmock_fault(state, qsctest_hwmock_action_attest);

			if (status != qsc_hw_status_success && state->fault_partial_output == true && evidence != NULL && *evidencelen > 0U)
			{
				evidence[0U] = 0xA5U;
			}
		}

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_buffer_too_small;

			if (evidence != NULL && *evidencelen >= QSCTEST_HWMOCK_EVIDENCE_SIZE)
			{
				for (i = 0U; i < QSCTEST_HWMOCK_EVIDENCE_SIZE; ++i)
				{
					evidence[i] = (uint8_t)(0xA0U ^ challenge[i % challengelen] ^ (uint8_t)i);
				}

				status = qsc_hw_status_success;
			}

			*evidencelen = QSCTEST_HWMOCK_EVIDENCE_SIZE;
		}
	}

	return status;
}

/** \brief Return fixed public test bytes without revealing private material.
 * \param context Caller-owned simulator.
 * \param key Synthetic key pointer.
 * \param output Caller-owned bytes or NULL for size query.
 * \param outputlen In/out capacity/required bytes.
 * \return success, buffer_too_small or injected failure.
 */
static qsc_hw_status hwmock_public(void* context, void* key, uint8_t* output, size_t* outputlen)
{
	qsctest_hwmock_context* state;
	qsctest_hwmock_key* entry;
	qsc_hw_status status;

	state = (qsctest_hwmock_context*)context;
	entry = (qsctest_hwmock_key*)key;
	status = qsc_hw_status_invalid_parameter;

	if (state != NULL && entry != NULL && outputlen != NULL)
	{
		status = hwmock_ready(state, true);

		if (status == qsc_hw_status_success)
		{
			status = hwmock_fault(state, qsctest_hwmock_action_public);
		}

		if (status == qsc_hw_status_success)
		{
			status = qsc_hw_status_buffer_too_small;

			if (output != NULL && *outputlen >= QSCTEST_HWMOCK_PUBLIC_SIZE)
			{
				output[0U] = 0x04U;
				output[1U] = (uint8_t)entry->object_id;
				output[2U] = 0x12U;
				output[3U] = 0x34U;
				status = qsc_hw_status_success;
			}

			*outputlen = QSCTEST_HWMOCK_PUBLIC_SIZE;
		}
	}

	return status;
}

void qsctest_hwmock_initialize(qsctest_hwmock_context* context)
{
	if (context != NULL)
	{
		qsc_memutils_clear(context, sizeof(qsctest_hwmock_context));
		context->serial = 0x010203U;
		context->slot = 7U;
		context->present = true;
		context->keys[0U].exists = true;
		context->keys[0U].object_id = 1U;
		context->keys[0U].serial = context->serial;
		context->keys[0U].algorithm = qsc_hw_algorithm_ecdsa_p256;
		context->keys[0U].usage = qsc_hw_usage_sign | qsc_hw_usage_agree | qsc_hw_usage_attest;
		context->keys[0U].custody = qsc_hw_custody_hardware_nonexportable;
		context->keys[1U].exists = true;
		context->keys[1U].object_id = 2U;
		context->keys[1U].serial = context->serial;
		context->keys[1U].algorithm = qsc_hw_algorithm_ecdsa_p256;
		context->keys[1U].usage = qsc_hw_usage_sign;
		context->keys[1U].custody = qsc_hw_custody_hardware_nonexportable;
	}
}

void qsctest_hwmock_make_ops(qsc_hw_provider_ops* operations)
{
	if (operations != NULL)
	{
		qsc_memutils_clear(operations, sizeof(qsc_hw_provider_ops));
		operations->size = sizeof(qsc_hw_provider_ops);
		operations->version = QSC_HW_ABI_VERSION;
		operations->get_capabilities = hwmock_capabilities;
		operations->open_key = hwmock_open;
		operations->generate_key = hwmock_generate;
		operations->release_key = hwmock_release;
		operations->dispose = hwmock_dispose;
		operations->sign = hwmock_sign;
		operations->agree = hwmock_agree;
		operations->random = hwmock_random;
		operations->attest = hwmock_attest;
		operations->public_key = hwmock_public;
	}
}

qsc_hw_status qsctest_hwmock_login(qsctest_hwmock_context* context, const uint8_t* pin, size_t length)
{
	static const uint8_t expected[4U] = { 0x31U, 0x32U, 0x33U, 0x34U };
	qsc_hw_status status;

	status = qsc_hw_status_invalid_parameter;

	if (context != NULL && (pin != NULL || length == 0U))
	{
		status = qsc_hw_status_device_removed;

		if (context->present == true)
		{
			status = qsc_hw_status_locked;

			if (context->pin_locked == false)
			{
				status = qsc_hw_status_auth_failed;

				if (length == sizeof(expected) && qsc_memutils_are_equal(pin, expected, sizeof(expected)) == true)
				{
					context->authenticated = true;
					context->pin_failures = 0U;
					status = qsc_hw_status_success;
				}
				else
				{
					context->authenticated = false;
					context->pin_failures += 1U;

					if (context->pin_failures >= 3U)
					{
						context->pin_locked = true;
						status = qsc_hw_status_locked;
					}
				}
			}
		}
	}

	return status;
}

void qsctest_hwmock_logout(qsctest_hwmock_context* context)
{
	if (context != NULL)
	{
		context->authenticated = false;
	}
}

void qsctest_hwmock_remove(qsctest_hwmock_context* context)
{
	if (context != NULL)
	{
		context->present = false;
		context->authenticated = false;
	}
}

void qsctest_hwmock_insert(qsctest_hwmock_context* context, bool replace_token)
{
	if (context != NULL)
	{
		context->present = true;
		context->authenticated = false;
		context->slot = 11U;

		if (replace_token == true)
		{
			context->serial = 0x091827U;
		}
	}
}

void qsctest_hwmock_set_fault(qsctest_hwmock_context* context, qsctest_hwmock_action action, qsc_hw_status status, bool partial_output)
{
	if (context != NULL)
	{
		context->fault_action = action;
		context->fault_status = status;
		context->fault_partial_output = partial_output;
		context->fault_issued = false;
	}
}

#endif /* QSC_HARDWARE_ENABLED */
