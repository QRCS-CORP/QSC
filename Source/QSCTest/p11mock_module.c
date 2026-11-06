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

/* Independent PKCS#11 test library. The test fixture does not perform cryptography. */
#include <pkcs11.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#if defined(_WIN32)
#   define QSCTEST_P11_EXPORT __declspec(dllexport)
#else
#   define QSCTEST_P11_EXPORT __attribute__((visibility("default")))
#endif

/** \file p11mock_module.c
 * \brief Standalone synthetic Cryptoki shared module for Stage 3 loader/session tests.
 * \details Compile independently into a shared library using a system PKCS#11 header.
 * Does not perform key operations or provide cryptographic security.
 */

/** \def QSCTEST_P11_EXPORT
 * \brief Export fixture controls and Cryptoki entrypoints from the test shared library.
 */

/** \enum qsctest_p11_fault
 * \brief Test-only error injection identifiers; reset between individual tests.
 */
typedef enum qsctest_p11_fault
{
	qsctest_p11_fault_none = 0, /**< Default state. */
	qsctest_p11_fault_removed = 1, /**< Token removed during operation. */
	qsctest_p11_fault_big_slots = 2, /**< Unreasonably large slot list. */
	qsctest_p11_fault_external_init = 3, /**< Simulate external pre-initialization. */
	qsctest_p11_fault_race_count = 4, /**< Slot count increases between calls. */
	qsctest_p11_fault_duplicate_key = 5, /**< Emit duplicate private objects with one CKA_ID. */
	qsctest_p11_fault_not_sensitive = 6, /**< Return a non-sensitive private key. */
	qsctest_p11_fault_extractable = 7, /**< Return an extractable private key. */
	qsctest_p11_fault_partial_signature = 8, /**< Write then reject signature output. */
	qsctest_p11_fault_new_serial = 9, /**< Change the logical token serial. */
	qsctest_p11_fault_wrong_curve = 10, /**< Report a different private-key EC curve. */
	qsctest_p11_fault_generate_error = 11, /**< Refuse synthetic key generation. */
	qsctest_p11_fault_malformed_point = 12, /**< Return invalid public EC point encoding. */
	qsctest_p11_fault_partial_secret = 13, /**< Write then reject derived-secret output. */
	qsctest_p11_fault_public_private = 14, /**< Return public private-attribute policy violation. */
	qsctest_p11_fault_partial_secret_short = 15, /**< Return BUFFER_TOO_SMALL after writing a partial secret. */
	qsctest_p11_fault_partial_signature_short = 16 /**< Return BUFFER_TOO_SMALL after writing a partial signature. */
} qsctest_p11_fault;

/** \brief Initialization flag for this test module. */
static bool p11mock_initialized = false;
/** \brief Number of actual successful C_Initialize transitions. */
static uint32_t p11mock_initialize_count = 0U;
/** \brief Number of actual successful C_Finalize transitions. */
static uint32_t p11mock_finalize_count = 0U;
/** \brief Active mock session mask, allowing two simultaneous sessions. */
static uint32_t p11mock_sessions = 0U;
/** \brief Number of consecutive incorrect PIN attempts. */
static uint32_t p11mock_bad_pins = 0U;
/** \brief Token-wide login status. */
static bool p11mock_authenticated = false;
/** \brief Whether a temporary ECDH-derived secret token object exists. */
static bool p11mock_derived = false;
/** \brief Current controlled backend failure mode. */
static qsctest_p11_fault p11mock_fault = qsctest_p11_fault_none;

/** \brief Set a deterministic injection mode and reset transient PIN lockout.
 * \param fault qsctest_p11_fault test code.
 */
QSCTEST_P11_EXPORT void qsctest_p11mock_set_fault(uint32_t fault)
{
	if (p11mock_fault == qsctest_p11_fault_external_init)
	{
		p11mock_initialized = false;
	}

	p11mock_fault = (qsctest_p11_fault)fault;
	p11mock_bad_pins = 0U;

	if (p11mock_fault == qsctest_p11_fault_external_init)
	{
		p11mock_initialized = true;
	}
}

/** \brief Read a deterministic fixture counter for lifecycle assertions.
 * \param which 1 means Initialize, 2 means Finalize, 3 means sessions, 4 means derived-secret objects.
 * \return Counter value for requested type, zero for unknown.
 */
QSCTEST_P11_EXPORT uint32_t qsctest_p11mock_counter(uint32_t which)
{
	uint32_t count;
	count = 0U;

	if (which == 1U)
	{
		count = p11mock_initialize_count;
	}
	else if (which == 2U)
	{
		count = p11mock_finalize_count;
	}
	else if (which == 3U)
	{
		count = ((p11mock_sessions & 1U) != 0U ? 1U : 0U) + ((p11mock_sessions & 2U) != 0U ? 1U : 0U);
	}
	else if (which == 4U)
	{
		count = p11mock_derived == true ? 1U : 0U;
	}

	return count;
}

/** \brief Preset token private key ID for deterministic test discovery. */
static const uint8_t p11mock_fixed_id[1U] = { 0xA1U };
/** \brief Fixed ECDH test key CKA_ID, distinct from the signature identity. */
static const uint8_t p11mock_ecdh_id[1U] = { 0xB1U };
/** \brief P-256 DER object identifier used by the synthetic token. */
static const uint8_t p11mock_p256_oid[10U] = { 0x06U, 0x08U, 0x2AU, 0x86U, 0x48U, 0xCEU, 0x3DU, 0x03U, 0x01U, 0x07U };
/** \brief Whether a second test-only persistent keypair exists. */
static bool p11mock_generated = false;
/** \brief Whether generated private object is still present. */
static bool p11mock_generated_private = false;
/** \brief Whether generated public object is still present. */
static bool p11mock_generated_public = false;
/** \brief Generated test key CKA_ID, bounded and nonsecret. */
static uint8_t p11mock_generated_id[64U] = { 0U };
/** \brief Number of bytes in generated test key CKA_ID. */
static size_t p11mock_generated_idlen = 0U;
/** \brief Whether one synthetic FindObjects operation is active. */
static bool p11mock_search_active = false;
/** \brief Search object class for the active test-only find. */
static CK_OBJECT_CLASS p11mock_search_class = CKO_PRIVATE_KEY;
/** \brief Exact search ID buffer; never a private key. */
static uint8_t p11mock_search_id[64U] = { 0U };
/** \brief Search ID length in bytes. */
static size_t p11mock_search_idlen = 0U;
/** \brief Test-only CKM_ECDSA signing operation state. */
static bool p11mock_signing = false;


/** \brief Test initialization with CKR_ALREADY_INITIALIZED semantics.
 * \param args Optional CK_C_INITIALIZE_ARGS.
 * \return Cryptoki status.
 */
static CK_RV p11mock_initialize(CK_VOID_PTR args)
{
	CK_RV rv;
	(void)args;
	rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (p11mock_initialized == false)
	{
		p11mock_initialized = true;
		p11mock_initialize_count += 1U;
		rv = CKR_OK;
	}

	return rv;
}

/** \brief Test finalization.
 * \param reserved Always NULL.
 * \return Cryptoki status.
 */
static CK_RV p11mock_finalize(CK_VOID_PTR reserved)
{
	CK_RV rv;
	(void)reserved;
	rv = CKR_CRYPTOKI_NOT_INITIALIZED;

	if (p11mock_initialized == true)
	{
		p11mock_initialized = false;
		p11mock_finalize_count += 1U;
		p11mock_sessions = 0U;
		p11mock_authenticated = false;
		p11mock_search_active = false;
		p11mock_signing = false;
		p11mock_derived = false;
		rv = CKR_OK;
	}

	return rv;
}

/** \brief Enumerate two fixed slots, one with token present.
 * \param present Token-present filter.
 * \param slots Optional caller-owned slot identifiers.
 * \param count In/out capacity and actual slot count.
 * \return Cryptoki status.
 */
static CK_RV p11mock_slots(CK_BBOOL present, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
{
	CK_RV rv;
	CK_ULONG required;
	required = (present == CK_TRUE) ? 1UL : 2UL;
	rv = CKR_OK;

	if (count == NULL_PTR)
	{
		rv = CKR_ARGUMENTS_BAD;
	}
	else if (p11mock_initialized == false)
	{
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	else if (p11mock_fault == qsctest_p11_fault_big_slots)
	{
		*count = 5000UL;
	}
	else if (slots == NULL_PTR)
	{
		*count = (p11mock_fault == qsctest_p11_fault_race_count) ? 1UL : required;
	}
	else if (p11mock_fault == qsctest_p11_fault_race_count)
	{
		*count = 2UL;
		rv = CKR_BUFFER_TOO_SMALL;
	}
	else if (*count < required)
	{
		*count = required;
		rv = CKR_BUFFER_TOO_SMALL;
	}
	else
	{
		slots[0U] = 7UL;

		if (present == CK_FALSE)
		{
			slots[1U] = 9UL;
		}
		*count = required;
	}

	return rv;
}

/** \brief Return public token data for slot 7.
 * \param slot Token slot.
 * \param info Caller-owned Cryptoki metadata output.
 * \return Cryptoki status.
 */
static CK_RV p11mock_token(CK_SLOT_ID slot, CK_TOKEN_INFO_PTR info)
{
	CK_RV rv;
	rv = CKR_OK;

	if (info == NULL_PTR || slot != 7UL)
	{
		rv = CKR_SLOT_ID_INVALID;
	}
	else if (p11mock_fault == qsctest_p11_fault_removed)
	{
		rv = CKR_TOKEN_NOT_PRESENT;
	}
	else
	{
		memset(info, 0, sizeof(*info));
		memset(info->label, ' ', sizeof(info->label));
		memset(info->serialNumber, ' ', sizeof(info->serialNumber));
		memcpy(info->label, "QSC MOCK TOKEN", 14U);
		if (p11mock_fault == 9)
		{
			memcpy(info->serialNumber, "DIFFERENT", 9U);
		}
		else
		{
			memcpy(info->serialNumber, "12345678", 8U);
		}
		info->flags = CKF_TOKEN_INITIALIZED;
	}

	return rv;
}

/** \brief Enumerate two deterministic, synthetic mechanisms.
 * \param slot Token slot.
 * \param mechanisms Optional native Cryptoki mechanism buffer.
 * \param count In/out entry count.
 * \return Cryptoki status.
 */
static CK_RV p11mock_mechanisms(CK_SLOT_ID slot, CK_MECHANISM_TYPE_PTR mechanisms, CK_ULONG_PTR count)
{
	CK_RV rv;
	rv = CKR_OK;

	if (count == NULL_PTR || slot != 7UL)
	{
		rv = CKR_SLOT_ID_INVALID;
	}
	else if (mechanisms == NULL_PTR)
	{
		*count = 2UL;
	}
	else if (*count < 2UL)
	{
		*count = 2UL;
		rv = CKR_BUFFER_TOO_SMALL;
	}
	else
	{
		mechanisms[0U] = CKM_ECDSA;
		mechanisms[1U] = CKM_SHA256;
		*count = 2UL;
	}

	return rv;
}

/** \brief Return a single supported ECC mechanism size and flags.
 * \param slot Token slot.
 * \param mechanism Requested native mechanism.
 * \param info Caller-owned result.
 * \return Cryptoki status.
 */
static CK_RV p11mock_mechanism_info(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR info)
{
	CK_RV rv;
	rv = CKR_MECHANISM_INVALID;

	if (slot == 7UL && mechanism == CKM_ECDSA && info != NULL_PTR)
	{
		info->ulMinKeySize = 256UL;
		info->ulMaxKeySize = 256UL;
		info->flags = CKF_SIGN;
		rv = CKR_OK;
	}
	else if (slot == 7UL && mechanism == CKM_ECDH1_DERIVE && info != NULL_PTR)
	{
		info->ulMinKeySize = 256UL;
		info->ulMaxKeySize = 256UL;
		info->flags = CKF_DERIVE;
		rv = CKR_OK;
	}
	else if (slot == 7UL && mechanism == CKM_EC_KEY_PAIR_GEN && info != NULL_PTR)
	{
		info->ulMinKeySize = 256UL;
		info->ulMaxKeySize = 256UL;
		info->flags = CKF_GENERATE_KEY_PAIR;
		rv = CKR_OK;
	}

	return rv;
}

/** \brief Open a synthetic session, bounded to two handles.
 * \param slot Token slot.
 * \param flags Session access flags.
 * \param application Unused application pointer.
 * \param notify Unused callback.
 * \param session Receives native session handle.
 * \return Cryptoki status.
 */
static CK_RV p11mock_open_session(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR application, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR session)
{
	CK_RV rv;
	(void)application;
	(void)notify;
	(void)flags;
	rv = CKR_SLOT_ID_INVALID;

	if (slot == 7UL && session != NULL_PTR)
	{
		rv = CKR_SESSION_COUNT;

		if (p11mock_fault == qsctest_p11_fault_removed)
		{
			rv = CKR_TOKEN_NOT_PRESENT;
		}
		else if ((p11mock_sessions & 1U) == 0U)
		{
			p11mock_sessions |= 1U;
			*session = 21UL;
			rv = CKR_OK;
		}
		else if ((p11mock_sessions & 2U) == 0U)
		{
			p11mock_sessions |= 2U;
			*session = 22UL;
			rv = CKR_OK;
		}
	}

	return rv;
}

/** \brief Release one synthetic session.
 * \param session Native session handle.
 * \return Cryptoki status.
 */
static CK_RV p11mock_close_session(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	rv = CKR_SESSION_HANDLE_INVALID;

	if (p11mock_fault == qsctest_p11_fault_removed)
	{
		rv = CKR_DEVICE_REMOVED;
		p11mock_sessions = 0U;
	}
	else if (session == 21UL && (p11mock_sessions & 1U) != 0U)
	{
		p11mock_sessions &= ~1U;
		rv = CKR_OK;
	}
	else if (session == 22UL && (p11mock_sessions & 2U) != 0U)
	{
		p11mock_sessions &= ~2U;
		rv = CKR_OK;
	}

	return rv;
}

/** \brief Authenticate against fixture-only PIN, locking after three failures.
 * \param session Native session handle.
 * \param user Login role.
 * \param pin Caller PIN bytes, not retained.
 * \param pinlen PIN length in bytes.
 * \return Cryptoki status.
 */
static CK_RV p11mock_login(CK_SESSION_HANDLE session, CK_USER_TYPE user, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen)
{
	static const uint8_t correct[4U] = { 0x31U, 0x32U, 0x33U, 0x34U };
	CK_RV rv;
	rv = CKR_USER_TYPE_INVALID;

	if (user == CKU_USER && (session == 21UL || session == 22UL))
	{
		rv = CKR_PIN_INCORRECT;

		if (p11mock_bad_pins >= 3U)
		{
			rv = CKR_PIN_LOCKED;
		}
		else if (p11mock_authenticated == true)
		{
			rv = CKR_USER_ALREADY_LOGGED_IN;
		}
		else if (pinlen == sizeof(correct) && pin != NULL_PTR && memcmp(pin, correct, sizeof(correct)) == 0)
		{
			p11mock_authenticated = true;
			rv = CKR_OK;
		}
		else
		{
			p11mock_bad_pins += 1U;
		}
	}

	return rv;
}

/** \brief Explicitly log out synthetic token-wide session state.
 * \param session Native session handle.
 * \return Cryptoki status.
 */
static CK_RV p11mock_logout(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	rv = CKR_USER_NOT_LOGGED_IN;

	if ((session == 21UL || session == 22UL) && p11mock_authenticated == true)
	{
		p11mock_authenticated = false;
		p11mock_search_active = false;
		p11mock_signing = false;
		p11mock_derived = false;
		rv = CKR_OK;
	}

	return rv;
}

/** \brief Determine whether a private/public fixture object exists.
 * \param object Synthetic object handle.
 * \return True if an object has been provisioned and exists.
 */
static bool p11mock_object_exists(CK_OBJECT_HANDLE object)
{
	bool exists;
	exists = (object == 41UL || object == 42UL || object == 61UL || object == 62UL || (p11mock_generated == true && (object == 51UL || object == 52UL)) || (p11mock_derived == true && object == 71UL));
	return exists;
}

/** \brief Find active token objects by exact private/public class and binary CKA_ID.
 * \param session Open synthetic session.
 * \param attrs Search attribute array.
 * \param count Number of input attributes.
 * \return Cryptoki status, no secret material returned.
 */
static CK_RV p11mock_find_init(CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attrs, CK_ULONG count)
{
	CK_RV rv;
	CK_ULONG i;
	bool has_class;
	bool has_id;

	rv = CKR_ARGUMENTS_BAD;
	has_class = false;
	has_id = false;
	p11mock_search_active = false;

	if (attrs != NULL_PTR && (session == 21UL || session == 22UL))
	{
		for (i = 0UL; i < count; ++i)
		{
			if (attrs[i].type == CKA_CLASS && attrs[i].pValue != NULL_PTR && attrs[i].ulValueLen == sizeof(CK_OBJECT_CLASS))
			{
				memcpy(&p11mock_search_class, attrs[i].pValue, sizeof(CK_OBJECT_CLASS));
				has_class = true;
			}
			else if (attrs[i].type == CKA_ID && attrs[i].pValue != NULL_PTR && attrs[i].ulValueLen != 0UL && attrs[i].ulValueLen <= sizeof(p11mock_search_id))
			{
				p11mock_search_idlen = (size_t)attrs[i].ulValueLen;
				memcpy(p11mock_search_id, attrs[i].pValue, p11mock_search_idlen);
				has_id = true;
			}
		}

		if (has_class == true && has_id == true)
		{
			rv = CKR_OK;

			if (p11mock_search_class == CKO_PRIVATE_KEY && p11mock_authenticated == false)
			{
				rv = CKR_USER_NOT_LOGGED_IN;
			}

			p11mock_search_active = (rv == CKR_OK);
		}
	}

	return rv;
}

/** \brief Emit synthetic matching object handles (at most two for ambiguity tests).
 * \param session Open synthetic session.
 * \param objects Caller output objects.
 * \param max_objects Output capacity.
 * \param count Receives number found.
 * \return Cryptoki status.
 */
static CK_RV p11mock_find(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects, CK_ULONG max_objects, CK_ULONG_PTR count)
{
	CK_RV rv;
	CK_OBJECT_HANDLE match;
	bool found;

	rv = CKR_OPERATION_NOT_INITIALIZED;

	if (p11mock_search_active == true && (session == 21UL || session == 22UL) && count != NULL_PTR)
	{
		found = false;
		match = 0UL;

		if (p11mock_search_idlen == sizeof(p11mock_fixed_id) && memcmp(p11mock_search_id, p11mock_fixed_id, sizeof(p11mock_fixed_id)) == 0)
		{
			found = true;
			match = (p11mock_search_class == CKO_PRIVATE_KEY) ? 41UL : 42UL;
		}
		else if (p11mock_search_idlen == sizeof(p11mock_ecdh_id) && memcmp(p11mock_search_id, p11mock_ecdh_id, sizeof(p11mock_ecdh_id)) == 0)
		{
			found = true;
			match = (p11mock_search_class == CKO_PRIVATE_KEY) ? 61UL : 62UL;
		}
		else if (p11mock_generated == true && p11mock_search_idlen == p11mock_generated_idlen &&
			memcmp(p11mock_search_id, p11mock_generated_id, p11mock_generated_idlen) == 0)
		{
			found = true;
			match = (p11mock_search_class == CKO_PRIVATE_KEY) ? 51UL : 52UL;
		}

		*count = 0UL;
		rv = CKR_OK;

		if (found == true && objects != NULL_PTR && max_objects != 0UL)
		{
			objects[0U] = match;
			*count = 1UL;

			if (p11mock_fault == 5 && max_objects >= 2UL)
			{
				objects[1U] = match + 10UL;
				*count = 2UL;
			}
		}
	}

	return rv;
}

/** \brief Complete synthetic object search, including error cleanup.
 * \param session Active session.
 * \return Cryptoki status.
 */
static CK_RV p11mock_find_final(CK_SESSION_HANDLE session)
{
	CK_RV rv;
	rv = CKR_OPERATION_NOT_INITIALIZED;

	if (p11mock_search_active == true && (session == 21UL || session == 22UL))
	{
		p11mock_search_active = false;
		rv = CKR_OK;
	}

	return rv;
}

/** \brief Serve public attributes and protected policy flags; private CKA_VALUE is never readable.
 * \param session Active session.
 * \param object Synthetic object handle.
 * \param attrs Requested native Cryptoki attribute array.
 * \param count Number of requested attributes.
 * \return Cryptoki status; CKA_VALUE for private objects always returns sensitive.
 */
static CK_RV p11mock_attributes(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR attrs, CK_ULONG count)
{
	uint8_t point[67U];
	const uint8_t* value;
	CK_OBJECT_CLASS object_class;
	CK_KEY_TYPE key_type;
	CK_BBOOL flag;
	CK_ULONG i;
	CK_ULONG length;
	CK_RV rv;
	bool private_object;

	rv = CKR_OBJECT_HANDLE_INVALID;

	if ((session == 21UL || session == 22UL) && attrs != NULL_PTR && p11mock_object_exists(object) == true)
	{
		private_object = (object == 41UL || object == 51UL || object == 61UL);
		rv = CKR_OK;

		if (object == 71UL)
		{
			for (i = 0UL; i < count && rv == CKR_OK; ++i)
			{
				if (attrs[i].type != CKA_VALUE)
				{
					rv = CKR_ATTRIBUTE_TYPE_INVALID;
				}
				else if (attrs[i].pValue != NULL_PTR && attrs[i].ulValueLen >= 32UL)
				{
					memset(attrs[i].pValue, 0xA7U, 32U);
					attrs[i].ulValueLen = 32UL;

					if (p11mock_fault == 13)
					{
						rv = CKR_DEVICE_ERROR;
					}
					else if (p11mock_fault == 15)
					{
						rv = CKR_BUFFER_TOO_SMALL;
					}
				}
				else if (attrs[i].pValue == NULL_PTR)
				{
					attrs[i].ulValueLen = 32UL;
				}
				else
				{
					rv = CKR_BUFFER_TOO_SMALL;
				}
			}
		}
		else
		{
			object_class = private_object == true ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
			key_type = CKK_EC;
			memset(point, 0, sizeof(point));
			point[0U] = 0x04U;
			point[1U] = 65U;
			point[2U] = 0x04U;

			for (i = 3UL; i < sizeof(point); ++i)
			{
				point[i] = (uint8_t)(i + (object == 51UL || object == 52UL ? 1UL : 0UL));
			}

			for (i = 0UL; i < count && rv == CKR_OK; ++i)
			{
				value = NULL;
				length = 0UL;
				flag = CK_TRUE;

				switch (attrs[i].type)
				{
					case CKA_CLASS:
						value = (const uint8_t*)&object_class;
						length = sizeof(object_class);
						break;
					case CKA_KEY_TYPE:
						value = (const uint8_t*)&key_type;
						length = sizeof(key_type);
						break;
					case CKA_PRIVATE:
						flag = (p11mock_fault == 14) ? CK_FALSE : CK_TRUE;
						value = &flag;
						length = sizeof(flag);
						break;
					case CKA_SENSITIVE:
						flag = (p11mock_fault == 6) ? CK_FALSE : CK_TRUE;
						value = &flag;
						length = sizeof(flag);
						break;
					case CKA_EXTRACTABLE:
						flag = (p11mock_fault == 7) ? CK_TRUE : CK_FALSE;
						value = &flag;
						length = sizeof(flag);
						break;
					case CKA_TOKEN:
						value = &flag;
						length = sizeof(flag);
						break;
					case CKA_SIGN:
					case CKA_VERIFY:
						flag = (object == 61UL || object == 62UL) ? CK_FALSE : CK_TRUE;
						value = &flag;
						length = sizeof(flag);
						break;
					case CKA_DERIVE:
						flag = (object == 61UL || object == 62UL) ? CK_TRUE : CK_FALSE;
						value = &flag;
						length = sizeof(flag);
						break;
					case CKA_ID:
						value = (object == 41UL || object == 42UL) ? p11mock_fixed_id : ((object == 61UL || object == 62UL) ? p11mock_ecdh_id : p11mock_generated_id);
						length = (CK_ULONG)((object == 41UL || object == 42UL) ? sizeof(p11mock_fixed_id) : ((object == 61UL || object == 62UL) ? sizeof(p11mock_ecdh_id) : p11mock_generated_idlen));
						break;
					case CKA_EC_PARAMS:
						value = p11mock_p256_oid;
						length = sizeof(p11mock_p256_oid);
						if (p11mock_fault == 10)
						{
							length -= 1UL;
						}
						break;
					case CKA_EC_POINT:
						if (private_object == false)
						{
							value = point;
							length = sizeof(point);
							if (p11mock_fault == 12)
							{
								length = 4UL;
							}
						}
						break;
					case CKA_VALUE:
						rv = CKR_ATTRIBUTE_SENSITIVE;
						break;
					default:
						rv = CKR_ATTRIBUTE_TYPE_INVALID;
						break;
				}

				if (rv == CKR_OK && value == NULL)
				{
					rv = CKR_ATTRIBUTE_TYPE_INVALID;
				}

				if (rv == CKR_OK)
				{
					if (attrs[i].pValue != NULL_PTR && attrs[i].ulValueLen < length)
					{
						rv = CKR_BUFFER_TOO_SMALL;
					}
					else if (attrs[i].pValue != NULL_PTR)
					{
						memcpy(attrs[i].pValue, value, length);
					}
					attrs[i].ulValueLen = length;
				}
			}
		}
	}

	return rv;
}

/** \brief Perform synthetic EC key generation with strict attributes, not cryptographic keypair creation.
 * \param session Active test session.
 * \param mechanism Required EC keypair generation mechanism.
 * \param public_attrs Token public-key template.
 * \param public_count Public template entries.
 * \param private_attrs Protected private-key template.
 * \param private_count Private template entries.
 * \param public_key Receives synthetic public handle.
 * \param private_key Receives synthetic private handle.
 * \return Cryptoki result.
 */
static CK_RV p11mock_generate(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR public_attrs, CK_ULONG public_count,
	CK_ATTRIBUTE_PTR private_attrs, CK_ULONG private_count, CK_OBJECT_HANDLE_PTR public_key, CK_OBJECT_HANDLE_PTR private_key)
{
	CK_ULONG i;
	CK_RV rv;
	bool private_sensitive;
	bool private_nonexportable;
	bool public_curve;
	bool has_id;

	rv = CKR_ARGUMENTS_BAD;
	private_sensitive = false;
	private_nonexportable = false;
	public_curve = false;
	has_id = false;

	if (session == 21UL || session == 22UL)
	{
		if (mechanism != NULL_PTR && mechanism->mechanism == CKM_EC_KEY_PAIR_GEN && public_key != NULL_PTR &&
			private_key != NULL_PTR && public_attrs != NULL_PTR && private_attrs != NULL_PTR && p11mock_generated == false)
		{
			for (i = 0UL; i < public_count; ++i)
			{
				if (public_attrs[i].type == CKA_EC_PARAMS && public_attrs[i].ulValueLen == sizeof(p11mock_p256_oid) &&
					memcmp(public_attrs[i].pValue, p11mock_p256_oid, sizeof(p11mock_p256_oid)) == 0)
				{
					public_curve = true;
				}
				else if (public_attrs[i].type == CKA_ID && public_attrs[i].ulValueLen != 0UL &&
					public_attrs[i].ulValueLen <= sizeof(p11mock_generated_id))
				{
					p11mock_generated_idlen = (size_t)public_attrs[i].ulValueLen;
					memcpy(p11mock_generated_id, public_attrs[i].pValue, p11mock_generated_idlen);
					has_id = true;
				}
			}

			for (i = 0UL; i < private_count; ++i)
			{
				if (private_attrs[i].type == CKA_SENSITIVE && private_attrs[i].ulValueLen == sizeof(CK_BBOOL))
				{
					private_sensitive = (*(CK_BBOOL*)private_attrs[i].pValue == CK_TRUE);
				}
				else if (private_attrs[i].type == CKA_EXTRACTABLE && private_attrs[i].ulValueLen == sizeof(CK_BBOOL))
				{
					private_nonexportable = (*(CK_BBOOL*)private_attrs[i].pValue == CK_FALSE);
				}
			}

			rv = CKR_TEMPLATE_INCONSISTENT;

			if (public_curve == true && has_id == true && private_sensitive == true && private_nonexportable == true && p11mock_fault != 11)
			{
				p11mock_generated = true;
				p11mock_generated_private = true;
				p11mock_generated_public = true;
				*public_key = 52UL;
				*private_key = 51UL;
				rv = CKR_OK;
			}
		}
	}

	return rv;
}

/** \brief Delete only freshly provisioned fixture objects on generation rollback.
 * \param session Active session.
 * \param object Object handle.
 * \return Cryptoki result.
 */
static CK_RV p11mock_destroy(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
	CK_RV rv;
	rv = CKR_OBJECT_HANDLE_INVALID;

	if ((session == 21UL || session == 22UL) && p11mock_generated == true && object == 51UL && p11mock_generated_private == true)
	{
		p11mock_generated_private = false;
		rv = CKR_OK;
	}
	else if ((session == 21UL || session == 22UL) && p11mock_generated == true && object == 52UL && p11mock_generated_public == true)
	{
		p11mock_generated_public = false;
		rv = CKR_OK;
	}

	if (p11mock_generated_private == false && p11mock_generated_public == false)
	{
		p11mock_generated = false;
	}
	else if ((session == 21UL || session == 22UL) && object == 71UL && p11mock_derived == true)
	{
		p11mock_derived = false;
		rv = CKR_OK;
	}

	return rv;
}

/** \brief Initialize synthetic ECDSA operation with pre-existing nonexportable private key.
 * \param session Open token session.
 * \param mechanism CKM_ECDSA without parameters.
 * \param key Existing protected key handle.
 * \return Cryptoki status.
 */
static CK_RV p11mock_sign_init(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key)
{
	CK_RV rv;
	rv = CKR_KEY_HANDLE_INVALID;
	p11mock_signing = false;

	if ((session == 21UL || session == 22UL) && mechanism != NULL_PTR && mechanism->mechanism == CKM_ECDSA &&
		(key == 41UL || (key == 51UL && p11mock_generated == true)))
	{
		rv = CKR_USER_NOT_LOGGED_IN;

		if (p11mock_authenticated == true)
		{
			p11mock_signing = true;
			rv = CKR_OK;
		}
	}

	return rv;
}

/** \brief Emit deterministic NONCRYPTOGRAPHIC 64-byte r||s-shaped test response.
 * \param session Open session.
 * \param data Synthetic digest.
 * \param datalen Must equal 32 bytes.
 * \param signature Output bytes, or NULL for query.
 * \param signaturelen In/out buffer size.
 * \return Cryptoki result. Never use fixture signatures for actual authentication.
 */
static CK_RV p11mock_sign(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG datalen, CK_BYTE_PTR signature, CK_ULONG_PTR signaturelen)
{
	CK_RV rv;
	rv = CKR_OPERATION_NOT_INITIALIZED;

	if ((session == 21UL || session == 22UL) && p11mock_signing == true && signaturelen != NULL_PTR && data != NULL_PTR && datalen == 32UL)
	{
		rv = CKR_BUFFER_TOO_SMALL;

		if (signature == NULL_PTR)
		{
			rv = CKR_OK;
		}
		else if (*signaturelen >= 64UL)
		{
			memset(signature, 0x5AU, 64U);
			signature[0U] = data[0U];
			rv = CKR_OK;

			if (p11mock_fault == 8)
			{
				rv = CKR_DEVICE_ERROR;
			}
			else if (p11mock_fault == 16)
			{
				rv = CKR_BUFFER_TOO_SMALL;
			}

			p11mock_signing = false;
		}
		*signaturelen = 64UL;
	}

	return rv;
}

/** \brief Make one synthetic ephemeral ECDH secret from a fixed protected private key.
 * \param session Active session.
 * \param mechanism CKM_ECDH1_DERIVE with uncompressed peer point.
 * \param private_key Nonexportable test ECDH private key.
 * \param attrs Derived secret template; host export must be explicitly allowed.
 * \param count Number of template attributes.
 * \param secret Receives disposable test-only secret handle.
 * \return Cryptoki result; no actual elliptic-curve computation is done.
 */
static CK_RV p11mock_derive(CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE private_key,
	CK_ATTRIBUTE_PTR attrs, CK_ULONG count, CK_OBJECT_HANDLE_PTR secret)
{
	CK_ECDH1_DERIVE_PARAMS* params;
	CK_RV rv;
	rv = CKR_ARGUMENTS_BAD;
	(void)attrs;
	(void)count;

	if ((session == 21UL || session == 22UL) && mechanism != NULL_PTR && secret != NULL_PTR &&
		private_key == 61UL && mechanism->mechanism == CKM_ECDH1_DERIVE && mechanism->pParameter != NULL_PTR &&
		mechanism->ulParameterLen == sizeof(CK_ECDH1_DERIVE_PARAMS))
	{
		params = (CK_ECDH1_DERIVE_PARAMS*)mechanism->pParameter;

		if (params->kdf == CKD_NULL && params->ulPublicDataLen == 65UL && params->pPublicData != NULL_PTR &&
			params->pPublicData[0U] == 0x04U && p11mock_authenticated == true)
		{
			p11mock_derived = true;
			*secret = 71UL;
			rv = CKR_OK;
		}
	}

	return rv;
}

/** \brief Return Cryptoki function list; no source crypto operations implemented.
 * \param functions Receives static CK_FUNCTION_LIST pointer.
 * \return Cryptoki status.
 */
QSCTEST_P11_EXPORT CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR functions)
{
	static CK_FUNCTION_LIST ops = {
		.version = { 2U, 40U },
		.C_Initialize = p11mock_initialize,
		.C_Finalize = p11mock_finalize,
		.C_GetFunctionList = C_GetFunctionList,
		.C_GetSlotList = p11mock_slots,
		.C_GetTokenInfo = p11mock_token,
		.C_GetMechanismList = p11mock_mechanisms,
		.C_GetMechanismInfo = p11mock_mechanism_info,
		.C_OpenSession = p11mock_open_session,
		.C_CloseSession = p11mock_close_session,
		.C_Login = p11mock_login,
		.C_Logout = p11mock_logout,
		.C_FindObjectsInit = p11mock_find_init,
		.C_FindObjects = p11mock_find,
		.C_FindObjectsFinal = p11mock_find_final,
		.C_GetAttributeValue = p11mock_attributes,
		.C_GenerateKeyPair = p11mock_generate,
		.C_DestroyObject = p11mock_destroy,
		.C_SignInit = p11mock_sign_init,
		.C_Sign = p11mock_sign,
		.C_DeriveKey = p11mock_derive
	};
	CK_RV rv;
	rv = CKR_ARGUMENTS_BAD;

	if (functions != NULL_PTR)
	{
#if defined(QSCTEST_P11_BAD_ABI)
		ops.version.major = 1U;
#else
		ops.version.major = 2U;
#endif
		*functions = &ops;
		rv = CKR_OK;
	}

	return rv;
}
