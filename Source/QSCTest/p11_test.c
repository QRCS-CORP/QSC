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

#include "p11_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED)

#include "hwpkcs11.h"
#include "testutils.h"
#include "stringutils.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#   if !defined(NOMINMAX)
#       define NOMINMAX
#   endif
#   include <windows.h>
#else
#   include <dlfcn.h>
#endif

/** \file p11_test.c
 * \brief Individually invoked tests against a dynamic synthetic PKCS#11 module.
 */

/** \typedef p11_test_fault_callback
 * \brief Test-only set-error-control callback.
 * \param fault Error mode, 0=normal, 1=device removed, 2=oversized slot count.
 */
typedef void (*p11_test_fault_callback)(uint32_t fault);

/** \typedef p11_test_counter_callback
 * \brief Test-only lifecycle inspection callback.
 * \param which 1=initialize, 2=finalize, 3=session count.
 * \return Current fixture counter.
 */
typedef uint32_t (*p11_test_counter_callback)(uint32_t which);

/** \brief Caller-provided test-only shared module path. */
static const char* p11_test_path = NULL;
/** \brief Caller-provided bad-ABI shared module path. */
static const char* p11_test_bad_path = NULL;
/** \brief Handle keeping fixture test-control symbols alive. */
static void* p11_test_fixture = NULL;
/** \brief Mock fault injection function from fixture (no cryptography). */
static p11_test_fault_callback p11_test_fault = NULL;
/** \brief Mock lifecycle counter inspection function. */
static p11_test_counter_callback p11_test_counter = NULL;

/** \brief Load an already-trusted external test fixture for its control symbols.
 * \param path Absolute test shared library path.
 * \return True only when both test-control callbacks resolve.
 */
static bool p11_test_bind(const char* path)
{
	bool pass;
	pass = false;
#if defined(QSC_SYSTEM_OS_WINDOWS)
	p11_test_fixture = (void*)LoadLibraryExA(path, NULL, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

	if (p11_test_fixture != NULL)
	{
		p11_test_fault = (p11_test_fault_callback)GetProcAddress((HMODULE)p11_test_fixture, "qsctest_p11mock_set_fault");
		p11_test_counter = (p11_test_counter_callback)GetProcAddress((HMODULE)p11_test_fixture, "qsctest_p11mock_counter");
	}
#else
	p11_test_fixture = dlopen(path, RTLD_NOW | RTLD_LOCAL);

	if (p11_test_fixture != NULL)
	{
		p11_test_fault = (p11_test_fault_callback)dlsym(p11_test_fixture, "qsctest_p11mock_set_fault");
		p11_test_counter = (p11_test_counter_callback)dlsym(p11_test_fixture, "qsctest_p11mock_counter");
	}
#endif
	pass = (p11_test_fixture != NULL && p11_test_fault != NULL && p11_test_counter != NULL);
	return pass;
}

/** \brief Unload the test-control reference when no provider remains open. */
static void p11_test_unbind(void)
{
	if (p11_test_fixture != NULL)
	{
#if defined(QSC_SYSTEM_OS_WINDOWS)
		(void)FreeLibrary((HMODULE)p11_test_fixture);
#else
		(void)dlclose(p11_test_fixture);
#endif
		p11_test_fixture = NULL;
	}
	p11_test_fault = NULL;
	p11_test_counter = NULL;
}

/** \brief Load synthetic Cryptoki module for one isolated test.
 * \param module Output module, NULL on failure.
 * \return True on success.
 */
static bool p11_test_open(qsc_hw_pkcs11_module** module)
{
	qsc_hw_status status;
	p11_test_fault(0U);
	status = qsc_hw_pkcs11_module_open(module, p11_test_path);
	return (status == qsc_hw_status_success);
}

/** \brief Close optional test module.
 * \param module In/out module handle.
 * \return True only when closed or already NULL.
 */
static bool p11_test_close(qsc_hw_pkcs11_module** module)
{
	bool pass;
	pass = true;

	if (*module != NULL)
	{
		pass = (qsc_hw_pkcs11_module_close(module) == qsc_hw_status_success);
	}
	return pass;
}

/** \brief Validate invalid paths are rejected before OS dynamic loading.
 * \return True for rejected relative and traversal paths.
 */
static bool p11_test_path_rejection(void)
{
	qsc_hw_pkcs11_module* module;
	bool pass;
	module = NULL;
	pass = (qsc_hw_pkcs11_module_open(&module, "relative/mock.so") == qsc_hw_status_invalid_parameter && module == NULL);
	pass = (qsc_hw_pkcs11_module_open(&module, "/tmp/../untrusted.so") == qsc_hw_status_invalid_parameter && module == NULL) && pass;
	return pass;
}

/** \brief Validate absent absolute path does not permit fallback.
 * \return True on failure without module handle.
 */
static bool p11_test_missing_module(void)
{
	qsc_hw_pkcs11_module* module;
	bool pass;
	module = NULL;
	pass = (qsc_hw_pkcs11_module_open(&module, "/qsc-tests/nonexistent-module-very-unlikely.so") != qsc_hw_status_success && module == NULL);
	return pass;
}

/** \brief Validate incorrect module function-list major version is rejected.
 * \return True when bad-ABI library cannot initialize.
 */
static bool p11_test_bad_version(void)
{
	qsc_hw_pkcs11_module* module;
	bool pass;
	module = NULL;
	pass = (qsc_hw_pkcs11_module_open(&module, p11_test_bad_path) != qsc_hw_status_success && module == NULL);
	return pass;
}

/** \brief Ensure two clients share initialization and release only on final close.
 * \return True when module opens once, closes once, and both clients remain valid.
 */
static bool p11_test_reference_count(void)
{
	qsc_hw_pkcs11_module* first;
	qsc_hw_pkcs11_module* second;
	uint32_t init_before;
	uint32_t fini_before;
	bool pass;
	first = NULL;
	second = NULL;
	init_before = p11_test_counter(1U);
	fini_before = p11_test_counter(2U);
	pass = p11_test_open(&first);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_module_open(&second, p11_test_path) == qsc_hw_status_success && second == first);
	}

	if (pass == true)
	{
		pass = (p11_test_counter(1U) == init_before + 1U);
		pass = p11_test_close(&first) && pass;
		pass = (p11_test_counter(2U) == fini_before) && pass;
	}
	pass = p11_test_close(&second) && pass;
	pass = (p11_test_counter(2U) == fini_before + 1U) && pass;
	return pass;
}

/** \brief Validate token-present and token-absent slot enumeration.
 * \return True when counts, entries and size queries match native module.
 */
static bool p11_test_slot_enumeration(void)
{
	qsc_hw_pkcs11_module* module;
	uint64_t slots[2U];
	size_t count;
	bool pass;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		count = 0U;
		pass = (qsc_hw_pkcs11_slot_list(module, true, NULL, &count) == qsc_hw_status_success && count == 1U);
		count = 2U;
		pass = (qsc_hw_pkcs11_slot_list(module, false, slots, &count) == qsc_hw_status_success && count == 2U && slots[0U] == 7U && slots[1U] == 9U) && pass;
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Validate capacity rejection without modifying output.
 * \return True when insufficient slot buffer reports required count.
 */
static bool p11_test_slot_capacity(void)
{
	qsc_hw_pkcs11_module* module;
	uint64_t slot;
	size_t count;
	bool pass;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		slot = UINT64_C(0x1234);
		count = 1U;
		pass = (qsc_hw_pkcs11_slot_list(module, false, &slot, &count) == qsc_hw_status_buffer_too_small && count == 2U && slot == UINT64_C(0x1234));
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Verify malicious oversized enumeration is bounded.
 * \return True when no allocation/copy occurs for unreasonably many slots.
 */
static bool p11_test_oversized_list(void)
{
	qsc_hw_pkcs11_module* module;
	size_t count;
	bool pass;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		p11_test_fault(2U);
		count = 0U;
		pass = (qsc_hw_pkcs11_slot_list(module, false, NULL, &count) == qsc_hw_status_policy && count == 0U);
		p11_test_fault(0U);
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Verify public token identity and protection metadata are trimmed.
 * \return True on exact label, serial and initialized attributes.
 */
static bool p11_test_token_info(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_token_info info;
	bool pass;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_token_info_get(module, 7U, &info) == qsc_hw_status_success &&
			qsc_stringutils_strings_equal(info.label, "QSC MOCK TOKEN") == true &&
			qsc_stringutils_strings_equal(info.serial, "12345678") == true && info.token_initialized == true);
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Validate mechanism inventory and limits are capability-derived.
 * \return True for ECDSA availability and unsupported mechanism rejection.
 */
static bool p11_test_mechanisms(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_mechanism_info info;
	uint64_t mechanisms[2U];
	size_t count;
	bool pass;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		count = 2U;
		pass = (qsc_hw_pkcs11_mechanism_list(module, 7U, mechanisms, &count) == qsc_hw_status_success && count == 2U);
		pass = (qsc_hw_pkcs11_mechanism_info_get(module, 7U, mechanisms[0U], &info) == qsc_hw_status_success && info.min_key_bits == 256U && info.max_key_bits == 256U) && pass;
		pass = (qsc_hw_pkcs11_mechanism_info_get(module, 7U, UINT64_C(0xdeadbeef), &info) == qsc_hw_status_unsupported) && pass;
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Ensure a module cannot unload while a Cryptoki session remains alive.
 * \return True when busy close is rejected until session close.
 */
static bool p11_test_session_busy_close(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	bool pass;
	session = NULL;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_open(&session, module, 7U, false) == qsc_hw_status_success);
		pass = (qsc_hw_pkcs11_module_close(&module) == qsc_hw_status_busy && module != NULL) && pass;
	}

	if (session != NULL)
	{
		pass = (qsc_hw_pkcs11_session_close(&session) == qsc_hw_status_success) && pass;
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Validate two sessions and busy third session, with recovery.
 * \return True when live sessions are independent under synthetic cap.
 */
static bool p11_test_session_limit(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* one;
	qsc_hw_pkcs11_session* two;
	qsc_hw_pkcs11_session* three;
	bool pass;
	one = NULL;
	two = NULL;
	three = NULL;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_open(&one, module, 7U, false) == qsc_hw_status_success);
		pass = (qsc_hw_pkcs11_session_open(&two, module, 7U, true) == qsc_hw_status_success) && pass;
		pass = (qsc_hw_pkcs11_session_open(&three, module, 7U, false) == qsc_hw_status_busy && three == NULL) && pass;
	}
	if (one != NULL)
	{
		pass = (qsc_hw_pkcs11_session_close(&one) == qsc_hw_status_success) && pass;
	}
	if (module != NULL)
	{
		pass = (qsc_hw_pkcs11_session_open(&three, module, 7U, false) == qsc_hw_status_success) && pass;
	}
	if (two != NULL)
	{
		pass = (qsc_hw_pkcs11_session_close(&two) == qsc_hw_status_success) && pass;
	}
	if (three != NULL)
	{
		pass = (qsc_hw_pkcs11_session_close(&three) == qsc_hw_status_success) && pass;
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Validate PIN login and explicit logout, with no retained credentials.
 * \return True on login/logout and caller PIN unchanged.
 */
static bool p11_test_pin_login(void)
{
	static const uint8_t pin[4U] = { 0x31U, 0x32U, 0x33U, 0x34U };
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	bool pass;
	session = NULL;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_open(&session, module, 7U, false) == qsc_hw_status_success);
	}
	if (session != NULL)
	{
		pass = (qsc_hw_pkcs11_session_login(session, pin, sizeof(pin)) == qsc_hw_status_success) && pass;
		pass = (qsc_hw_pkcs11_session_login(session, pin, sizeof(pin)) == qsc_hw_status_success) && pass;
		pass = (qsc_hw_pkcs11_session_logout(session) == qsc_hw_status_success) && pass;
		pass = (qsc_hw_pkcs11_session_close(&session) == qsc_hw_status_success) && pass;
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Validate wrong PIN lockout is surfaced without retries.
 * \return True after exactly three failing PIN calls and typed lockout.
 */
static bool p11_test_pin_lockout(void)
{
	static const uint8_t wrong[4U] = { 0x39U, 0x39U, 0x39U, 0x39U };
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	bool pass;
	session = NULL;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_open(&session, module, 7U, false) == qsc_hw_status_success);
	}
	if (session != NULL)
	{
		pass = (qsc_hw_pkcs11_session_login(session, wrong, sizeof(wrong)) == qsc_hw_status_auth_failed) && pass;
		pass = (qsc_hw_pkcs11_session_login(session, wrong, sizeof(wrong)) == qsc_hw_status_auth_failed) && pass;
		pass = (qsc_hw_pkcs11_session_login(session, wrong, sizeof(wrong)) == qsc_hw_status_auth_failed) && pass;
		pass = (qsc_hw_pkcs11_session_login(session, wrong, sizeof(wrong)) == qsc_hw_status_locked) && pass;
		pass = (qsc_hw_pkcs11_session_close(&session) == qsc_hw_status_success) && pass;
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Validate token removal returns typed error and invalidates session on close.
 * \return True on device-removed status and no leaked wrapper.
 */
static bool p11_test_token_removed(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_token_info info;
	bool pass;
	session = NULL;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_open(&session, module, 7U, false) == qsc_hw_status_success);
	}
	if (session != NULL)
	{
		p11_test_fault(1U);
		pass = (qsc_hw_pkcs11_token_info_get(module, 7U, &info) == qsc_hw_status_device_removed) && pass;
		pass = (qsc_hw_pkcs11_session_close(&session) == qsc_hw_status_device_removed && session == NULL) && pass;
		p11_test_fault(0U);
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Validate PIN bounds are checked before invoking the vendor callback.
 * \return True for oversized PIN rejection without touching live session.
 */
static bool p11_test_pin_bounds(void)
{
	static const uint8_t pin[1U] = { 0U };
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	bool pass;
	session = NULL;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_open(&session, module, 7U, false) == qsc_hw_status_success);
	}
	if (session != NULL)
	{
		pass = (qsc_hw_pkcs11_session_login(session, pin, QSC_HW_PKCS11_MAX_PIN_LENGTH + 1U) == qsc_hw_status_invalid_parameter) && pass;
		pass = (qsc_hw_pkcs11_session_close(&session) == qsc_hw_status_success) && pass;
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Ensure preinitialized external module is not finalized by this adapter.
 * \return True when C_Initialize reports already initialized and QSC skips Finalize.
 */
static bool p11_test_external_initialization(void)
{
	qsc_hw_pkcs11_module* module;
	uint32_t before;
	bool pass;
	module = NULL;
	before = p11_test_counter(2U);
	p11_test_fault(3U);
	pass = (qsc_hw_pkcs11_module_open(&module, p11_test_path) == qsc_hw_status_success);
	pass = p11_test_close(&module) && pass;
	pass = (p11_test_counter(2U) == before) && pass;
	p11_test_fault(0U);
	return pass;
}

/** \brief Verify required count is updated when the token changes between enumeration calls.
 * \return True when a second-call buffer-too-small error reports its new count.
 */
static bool p11_test_enumeration_race(void)
{
	qsc_hw_pkcs11_module* module;
	uint64_t slot;
	size_t count;
	bool pass;
	pass = p11_test_open(&module);

	if (pass == true)
	{
		p11_test_fault(4U);
		slot = 0U;
		count = 1U;
		pass = (qsc_hw_pkcs11_slot_list(module, false, &slot, &count) == qsc_hw_status_buffer_too_small && count == 2U && slot == 0U);
		p11_test_fault(0U);
	}
	pass = p11_test_close(&module) && pass;
	return pass;
}

/** \brief Fixed private key identifier in the deterministic Cryptoki module. */
static const uint8_t p11_test_key_id[1U] = { 0xA1U };
/** \brief Correct PIN for the synthetic test token only. */
static const uint8_t p11_test_token_pin[4U] = { 0x31U, 0x32U, 0x33U, 0x34U };

/** \brief Open one session with optional synthetic token USER login.
 * \param module Receives loaded module.
 * \param session Receives open session.
 * \param login Whether to authenticate.
 * \param write Whether to request read-write access.
 * \return True if every requested operation succeeds.
 */
static bool p11_test_key_setup(qsc_hw_pkcs11_module** module, qsc_hw_pkcs11_session** session, bool login, bool write)
{
	bool pass;
	*module = NULL;
	*session = NULL;
	pass = p11_test_open(module);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_open(session, *module, 7U, write) == qsc_hw_status_success);
	}

	if (pass == true && login == true)
	{
		pass = (qsc_hw_pkcs11_session_login(*session, p11_test_token_pin, sizeof(p11_test_token_pin)) == qsc_hw_status_success);
	}

	return pass;
}

/** \brief Close a key, session and module with all transient references released.
 * \param key Optional key reference address.
 * \param session Session reference address.
 * \param module Module reference address.
 * \return True only when all resources were released without errors.
 */
static bool p11_test_key_cleanup(qsc_hw_pkcs11_key** key, qsc_hw_pkcs11_session** session, qsc_hw_pkcs11_module** module)
{
	bool pass;
	pass = true;
	p11_test_fault(0U);

	if (key != NULL && *key != NULL)
	{
		pass = (qsc_hw_pkcs11_key_release(key) == qsc_hw_status_success) && pass;
	}

	if (*session != NULL)
	{
		pass = (qsc_hw_pkcs11_session_close(session) == qsc_hw_status_success) && pass;
	}

	pass = p11_test_close(module) && pass;
	return pass;
}

/** \brief Private key search requires token USER authorization.
 * \return True when an unauthenticated private lookup fails closed.
 */
static bool p11_test_key_auth_required(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, false, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_auth_required && key == NULL);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Locate and release exactly one nonexportable P-256 private key.
 * \return True for successful protected discovery and release.
 */
static bool p11_test_key_unique(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success && key != NULL);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Ensure a missing binary CKA_ID never selects an unrelated key.
 * \return True if absent key is rejected and no reference allocated.
 */
static bool p11_test_key_missing(void)
{
	static const uint8_t wrong[1U] = { 0xFEU };
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, wrong, sizeof(wrong), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_unsupported && key == NULL);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Reject two matching private object handles instead of silently picking the first.
 * \return True for rejected ambiguous locator.
 */
static bool p11_test_key_duplicate(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		p11_test_fault(5U);
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_policy && key == NULL);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Reject token private keys whose CKA_SENSITIVE was silently disabled.
 * \return True on required custody failure.
 */
static bool p11_test_key_sensitive_policy(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		p11_test_fault(6U);
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_policy && key == NULL);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Reject private keys advertised as CKA_EXTRACTABLE=true.
 * \return True when unsafe custody cannot be adopted.
 */
static bool p11_test_key_export_policy(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		p11_test_fault(7U);
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_policy && key == NULL);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Require exact EC curve and reject unsupported key use.
 * \return True for P-384 mismatch and forbidden ECDH use.
 */
static bool p11_test_key_curve_policy(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p384) == qsc_hw_status_stale_key && key == NULL);
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdh_p256) == qsc_hw_status_policy && key == NULL) && pass;
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Keep active private-key references from outliving the session allocation.
 * \return True when session-close refuses an outstanding key, then closes after release.
 */
static bool p11_test_key_session_busy(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_session_close(&session) == qsc_hw_status_busy && session != NULL);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Decode public EC point and preserve small caller buffers.
 * \return True for SEC1 uncompressed point, exact length and capacity checks.
 */
static bool p11_test_key_public(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t point[65U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		count = 0U;
		pass = (qsc_hw_pkcs11_key_public(key, NULL, &count) == qsc_hw_status_success && count == sizeof(point));
		point[0U] = 0xABU;
		count = 1U;
		pass = (qsc_hw_pkcs11_key_public(key, point, &count) == qsc_hw_status_buffer_too_small && count == sizeof(point) && point[0U] == 0xABU) && pass;
		count = sizeof(point);
		pass = (qsc_hw_pkcs11_key_public(key, point, &count) == qsc_hw_status_success && count == sizeof(point) && point[0U] == 0x04U && point[1U] == 0x03U) && pass;
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Reject malformed DER EC_POINT rather than forwarding untrusted bytes.
 * \return True when no malformed public point reaches the caller.
 */
static bool p11_test_key_malformed_point(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t point[65U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		p11_test_fault(12U);
		memset(point, 0xABU, sizeof(point));
		count = sizeof(point);
		pass = (qsc_hw_pkcs11_key_public(key, point, &count) == qsc_hw_status_policy && point[0U] == 0U);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Produce a raw deterministic r||s-shaped signature with no private byte export.
 * \return True on digest/size checks and signature equality.
 */
static bool p11_test_key_sign_raw(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t digest[32U] = { 0xB7U };
	uint8_t sig[64U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		count = 0U;
		pass = (qsc_hw_pkcs11_key_sign(key, digest, sizeof(digest), NULL, &count) == qsc_hw_status_success && count == sizeof(sig));
		count = 1U;
		sig[0U] = 0xABU;
		pass = (qsc_hw_pkcs11_key_sign(key, digest, sizeof(digest), sig, &count) == qsc_hw_status_buffer_too_small && count == sizeof(sig) && sig[0U] == 0xABU) && pass;
		count = sizeof(sig);
		pass = (qsc_hw_pkcs11_key_sign(key, digest, sizeof(digest), sig, &count) == qsc_hw_status_success && count == sizeof(sig) && sig[0U] == digest[0U] && sig[1U] == 0x5AU) && pass;
		count = sizeof(sig);
		pass = (qsc_hw_pkcs11_key_sign(key, digest, 31U, sig, &count) == qsc_hw_status_invalid_parameter) && pass;
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Erase partial signature bytes after a backend error.
 * \return True if no failed signature is exposed to the caller.
 */
static bool p11_test_key_sign_failure(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t digest[32U] = { 0U };
	uint8_t sig[64U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		p11_test_fault(8U);
		memset(sig, 0xABU, sizeof(sig));
		count = sizeof(sig);
		pass = (qsc_hw_pkcs11_key_sign(key, digest, sizeof(digest), sig, &count) == qsc_hw_status_device_removed && sig[0U] == 0U && sig[63U] == 0U);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Invalidate a key reference after a token-serial change.
 * \return True when a replacement token cannot authorize an old object handle.
 */
static bool p11_test_key_stale_token(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t digest[32U] = { 0U };
	uint8_t sig[64U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		p11_test_fault(9U);
		count = sizeof(sig);
		pass = (qsc_hw_pkcs11_key_sign(key, digest, sizeof(digest), sig, &count) == qsc_hw_status_stale_key);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Refuse persistent token-key generation from a read-only session.
 * \return True when generation is rejected before vendor calls.
 */
static bool p11_test_key_readonly_generate(void)
{
	static const uint8_t id[1U] = { 0xA2U };
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_generate(&key, session, id, sizeof(id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_invalid_parameter && key == NULL);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Fail generation without leaving a registered private token handle.
 * \return True when provider creation error is reported without an adopted key.
 */
static bool p11_test_key_generation_error(void)
{
	static const uint8_t id[1U] = { 0xA3U };
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, true);

	if (pass == true)
	{
		p11_test_fault(11U);
		pass = (qsc_hw_pkcs11_key_generate(&key, session, id, sizeof(id), qsc_hw_algorithm_ecdsa_p256) != qsc_hw_status_success && key == NULL);
		p11_test_fault(0U);
		pass = (qsc_hw_pkcs11_key_find(&key, session, id, sizeof(id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_unsupported && key == NULL) && pass;
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Generate a token-protected keypair and reject duplicate persistent CKA_ID.
 * \return True for non-exportable generation, public key read and duplicate refusal.
 */
static bool p11_test_key_generate_protected(void)
{
	static const uint8_t id[1U] = { 0xA2U };
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	qsc_hw_pkcs11_key* duplicate;
	uint8_t point[65U];
	size_t count;
	bool pass;
	key = NULL;
	duplicate = NULL;
	pass = p11_test_key_setup(&module, &session, true, true);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_generate(&key, session, id, sizeof(id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success && key != NULL);
	}

	if (pass == true)
	{
		count = sizeof(point);
		pass = (qsc_hw_pkcs11_key_public(key, point, &count) == qsc_hw_status_success && point[0U] == 0x04U);
		pass = (qsc_hw_pkcs11_key_generate(&duplicate, session, id, sizeof(id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_policy && duplicate == NULL) && pass;
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief ECDH-only mock private key identity. */
static const uint8_t p11_test_ecdh_id[1U] = { 0xB1U };

/** \brief Require explicit caller permission before a derived secret enters host memory.
 * \return True if policy failure occurs without touching output or leaving a token secret.
 */
static bool p11_test_ecdh_export_policy(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t peer[65U] = { 0x04U };
	uint8_t secret[32U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_ecdh_id, sizeof(p11_test_ecdh_id), qsc_hw_algorithm_ecdh_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		memset(secret, 0xABU, sizeof(secret));
		count = sizeof(secret);
		pass = (qsc_hw_pkcs11_key_agree(key, peer, sizeof(peer), secret, &count, false) == qsc_hw_status_policy && secret[0U] == 0xABU && p11_test_counter(4U) == 0U);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Derive synthetic test secret only after explicit permission and bounded-size checks.
 * \return True for exact size, output and disposal of the derived token object.
 */
static bool p11_test_ecdh_derived_secret(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t peer[65U] = { 0x04U };
	uint8_t secret[32U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_ecdh_id, sizeof(p11_test_ecdh_id), qsc_hw_algorithm_ecdh_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		count = 0U;
		pass = (qsc_hw_pkcs11_key_agree(key, peer, sizeof(peer), NULL, &count, true) == qsc_hw_status_success && count == sizeof(secret));
		memset(secret, 0xABU, sizeof(secret));
		count = 1U;
		pass = (qsc_hw_pkcs11_key_agree(key, peer, sizeof(peer), secret, &count, true) == qsc_hw_status_buffer_too_small && count == sizeof(secret) && secret[0U] == 0xABU) && pass;
		count = sizeof(secret);
		pass = (qsc_hw_pkcs11_key_agree(key, peer, sizeof(peer), secret, &count, true) == qsc_hw_status_success && count == sizeof(secret) && secret[0U] == 0xA7U && secret[31U] == 0xA7U && p11_test_counter(4U) == 0U) && pass;
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Reject malformed or non-uncompressed ECDH peer encodings.
 * \return True when no vendor derive is attempted for malformed public data.
 */
static bool p11_test_ecdh_peer_validation(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t peer[65U] = { 0x03U };
	uint8_t secret[32U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_ecdh_id, sizeof(p11_test_ecdh_id), qsc_hw_algorithm_ecdh_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		count = sizeof(secret);
		pass = (qsc_hw_pkcs11_key_agree(key, peer, sizeof(peer), secret, &count, true) == qsc_hw_status_invalid_parameter);
		peer[0U] = 0x04U;
		pass = (qsc_hw_pkcs11_key_agree(key, peer, sizeof(peer) - 1U, secret, &count, true) == qsc_hw_status_invalid_parameter) && pass;
		pass = (p11_test_counter(4U) == 0U) && pass;
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Erase partial derived secret and destroy the temporary token object on module failure.
 * \return True when no secret escapes and object count returns to zero.
 */
static bool p11_test_ecdh_failure_cleanup(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t peer[65U] = { 0x04U };
	uint8_t secret[32U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_ecdh_id, sizeof(p11_test_ecdh_id), qsc_hw_algorithm_ecdh_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		p11_test_fault(13U);
		memset(secret, 0xABU, sizeof(secret));
		count = sizeof(secret);
		pass = (qsc_hw_pkcs11_key_agree(key, peer, sizeof(peer), secret, &count, true) == qsc_hw_status_device_removed && secret[0U] == 0U && secret[31U] == 0U && p11_test_counter(4U) == 0U);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Reject a purported private token object not marked CKA_PRIVATE.
 * \return True when private key policy is enforced before returning a reference.
 */
static bool p11_test_key_private_flag(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		p11_test_fault(14U);
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_policy && key == NULL);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Abort newly created keypair when the token violates protected-key attributes.
 * \return True when private and public objects are both rolled back after custody rejection.
 */
static bool p11_test_key_generation_rollback(void)
{
	static const uint8_t id[1U] = { 0xA4U };
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, true);

	if (pass == true)
	{
		p11_test_fault(6U);
		pass = (qsc_hw_pkcs11_key_generate(&key, session, id, sizeof(id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_policy && key == NULL);
		p11_test_fault(0U);
		pass = (qsc_hw_pkcs11_key_find(&key, session, id, sizeof(id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_unsupported && key == NULL) && pass;
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Clear a token's partially written signature when it returns BUFFER_TOO_SMALL despite adequate capacity.
 * \return True when a non-successful sign cannot expose partial output.
 */
static bool p11_test_key_sign_misreported_capacity(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t digest[32U] = { 0U };
	uint8_t signature[64U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_key_id, sizeof(p11_test_key_id), qsc_hw_algorithm_ecdsa_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		p11_test_fault(16U);
		memset(signature, 0xABU, sizeof(signature));
		count = sizeof(signature);
		pass = (qsc_hw_pkcs11_key_sign(key, digest, sizeof(digest), signature, &count) == qsc_hw_status_buffer_too_small &&
			signature[0U] == 0U && signature[63U] == 0U);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

/** \brief Clear partial derived secret after malicious BUFFER_TOO_SMALL result with adequate capacity.
 * \return True when derived object and caller output are erased after a faulty vendor response.
 */
static bool p11_test_ecdh_misreported_capacity(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_pkcs11_session* session;
	qsc_hw_pkcs11_key* key;
	uint8_t peer[65U] = { 0x04U };
	uint8_t secret[32U];
	size_t count;
	bool pass;
	key = NULL;
	pass = p11_test_key_setup(&module, &session, true, false);

	if (pass == true)
	{
		pass = (qsc_hw_pkcs11_key_find(&key, session, p11_test_ecdh_id, sizeof(p11_test_ecdh_id), qsc_hw_algorithm_ecdh_p256) == qsc_hw_status_success);
	}

	if (pass == true)
	{
		p11_test_fault(15U);
		memset(secret, 0xABU, sizeof(secret));
		count = sizeof(secret);
		pass = (qsc_hw_pkcs11_key_agree(key, peer, sizeof(peer), secret, &count, true) == qsc_hw_status_buffer_too_small &&
			secret[0U] == 0U && secret[31U] == 0U && p11_test_counter(4U) == 0U);
	}

	pass = p11_test_key_cleanup(&key, &session, &module) && pass;
	return pass;
}

bool qsctest_p11_run(void)
{
	bool passed;
	bool environment_ready;
#if defined(_MSC_VER)
	char* modulepath;
	char* badmodulepath;
	size_t pathlen;
#endif

	passed = true;
#if defined(_MSC_VER)
	modulepath = NULL;
	badmodulepath = NULL;
	pathlen = 0U;
	environment_ready = (_dupenv_s(&modulepath, &pathlen, "QSC_TEST_PKCS11_MODULE") == 0);
	environment_ready = (_dupenv_s(&badmodulepath, &pathlen, "QSC_TEST_PKCS11_BAD_MODULE") == 0) && environment_ready;
	p11_test_path = modulepath;
	p11_test_bad_path = badmodulepath;
#else
	environment_ready = true;
	p11_test_path = getenv("QSC_TEST_PKCS11_MODULE");
	p11_test_bad_path = getenv("QSC_TEST_PKCS11_BAD_MODULE");
#endif

	if (environment_ready == false)
	{
		qsctest_print_safe("[FAIL] HW Stage3 PKCS11 fixture environment lookup failed\n");
		passed = false;
	}
	else if (p11_test_path == NULL || p11_test_bad_path == NULL)
	{
		qsctest_print_safe("[SKIP] HW Stage3 PKCS11 synthetic module fixtures not configured\n");
	}
	else if (p11_test_bind(p11_test_path) == false)
	{
		qsctest_print_safe("[FAIL] HW Stage3 test fixture control entrypoints missing\n");
		passed = false;
	}
	else
	{
		if (p11_test_path_rejection() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 reject relative and traversal module paths\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 reject relative and traversal module paths\n");
			passed = false;
		}
		if (p11_test_missing_module() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 missing absolute module fails closed\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 missing absolute module fails closed\n");
			passed = false;
		}
		if (p11_test_bad_version() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 reject incompatible Cryptoki ABI\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 reject incompatible Cryptoki ABI\n");
			passed = false;
		}
		if (p11_test_reference_count() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 shared initialization and finalization reference count\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 shared initialization and finalization reference count\n");
			passed = false;
		}
		if (p11_test_slot_enumeration() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 deterministic slot enumeration\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 deterministic slot enumeration\n");
			passed = false;
		}
		if (p11_test_slot_capacity() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 slot output capacity enforcement\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 slot output capacity enforcement\n");
			passed = false;
		}
		if (p11_test_oversized_list() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 reject malicious oversized slot count\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 reject malicious oversized slot count\n");
			passed = false;
		}
		if (p11_test_token_info() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 public token identity metadata\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 public token identity metadata\n");
			passed = false;
		}
		if (p11_test_mechanisms() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 mechanism discovery and unsupported rejection\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 mechanism discovery and unsupported rejection\n");
			passed = false;
		}
		if (p11_test_session_busy_close() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 prevent unload while session active\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 prevent unload while session active\n");
			passed = false;
		}
		if (p11_test_session_limit() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 session exhaustion and recovery\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 session exhaustion and recovery\n");
			passed = false;
		}
		if (p11_test_pin_login() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 transient PIN authentication and logout\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 transient PIN authentication and logout\n");
			passed = false;
		}
		if (p11_test_pin_lockout() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 wrong PIN and typed lockout\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 wrong PIN and typed lockout\n");
			passed = false;
		}
		if (p11_test_token_removed() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 token removal and session invalidation\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 token removal and session invalidation\n");
			passed = false;
		}
		if (p11_test_external_initialization() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 preserve external Cryptoki initialization owner\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 preserve external Cryptoki initialization owner\n");
			passed = false;
		}
		if (p11_test_enumeration_race() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 changing slot count reports second-call required size\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 changing slot count reports second-call required size\n");
			passed = false;
		}
		if (p11_test_pin_bounds() == true)
		{
			qsctest_print_safe("[PASS] HW Stage3 reject oversized PIN before vendor call\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage3 reject oversized PIN before vendor call\n");
			passed = false;
		}

		if (p11_test_key_auth_required() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject unauthenticated protected-key search\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject unauthenticated protected-key search\n");
			passed = false;
		}
		if (p11_test_key_unique() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 find and release unique sensitive nonexportable P-256 key\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 find and release unique sensitive nonexportable P-256 key\n");
			passed = false;
		}
		if (p11_test_key_missing() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject missing exact binary CKA_ID\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject missing exact binary CKA_ID\n");
			passed = false;
		}
		if (p11_test_key_duplicate() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject ambiguous duplicate token keys\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject ambiguous duplicate token keys\n");
			passed = false;
		}
		if (p11_test_key_sensitive_policy() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject private key lacking CKA_SENSITIVE\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject private key lacking CKA_SENSITIVE\n");
			passed = false;
		}
		if (p11_test_key_export_policy() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject extractable token private key\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject extractable token private key\n");
			passed = false;
		}
		if (p11_test_key_curve_policy() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject wrong EC curve and forbidden ECDH use\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject wrong EC curve and forbidden ECDH use\n");
			passed = false;
		}
		if (p11_test_key_session_busy() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 prevent session close while key reference exists\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 prevent session close while key reference exists\n");
			passed = false;
		}
		if (p11_test_key_public() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 public SEC1 point output and size contract\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 public SEC1 point output and size contract\n");
			passed = false;
		}
		if (p11_test_key_malformed_point() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject malformed public EC point\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject malformed public EC point\n");
			passed = false;
		}
		if (p11_test_key_sign_raw() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 prehashed CKM_ECDSA raw signature, input and output bounds\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 prehashed CKM_ECDSA raw signature, input and output bounds\n");
			passed = false;
		}
		if (p11_test_key_sign_failure() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 erase partial raw signature after backend failure\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 erase partial raw signature after backend failure\n");
			passed = false;
		}
		if (p11_test_key_stale_token() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject key handle after token serial changes\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject key handle after token serial changes\n");
			passed = false;
		}
		if (p11_test_key_readonly_generate() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 refuse key generation from read-only session\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 refuse key generation from read-only session\n");
			passed = false;
		}
		if (p11_test_key_generation_error() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 failed generation does not adopt a private key\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 failed generation does not adopt a private key\n");
			passed = false;
		}
		if (p11_test_key_private_flag() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject key missing CKA_PRIVATE protection\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject key missing CKA_PRIVATE protection\n");
			passed = false;
		}
		if (p11_test_key_generation_rollback() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 rollback generated private and public objects on custody failure\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 rollback generated private and public objects on custody failure\n");
			passed = false;
		}
		if (p11_test_key_generate_protected() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 generate nonexportable key and reject duplicate CKA_ID\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 generate nonexportable key and reject duplicate CKA_ID\n");
			passed = false;
		}

		if (p11_test_ecdh_export_policy() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 deny host secret export without explicit caller authorization\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 deny host secret export without explicit caller authorization\n");
			passed = false;
		}
		if (p11_test_ecdh_derived_secret() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 derived-secret size and disposable token object\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 derived-secret size and disposable token object\n");
			passed = false;
		}
		if (p11_test_ecdh_peer_validation() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 reject malformed ECDH peer points\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 reject malformed ECDH peer points\n");
			passed = false;
		}
		if (p11_test_ecdh_failure_cleanup() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 erase partial derived secret and destroy temporary token object\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 erase partial derived secret and destroy temporary token object\n");
			passed = false;
		}
		if (p11_test_key_sign_misreported_capacity() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 clear partial signature on misleading token buffer error\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 clear partial signature on misleading token buffer error\n");
			passed = false;
		}
		if (p11_test_ecdh_misreported_capacity() == true)
		{
			qsctest_print_safe("[PASS] HW Stage4 erase derived secret on misleading token buffer error\n");
		}
		else
		{
			qsctest_print_safe("[FAIL] HW Stage4 erase derived secret on misleading token buffer error\n");
			passed = false;
		}
		p11_test_unbind();
	}

#if defined(_MSC_VER)
	free(modulepath);
	free(badmodulepath);
#endif
	p11_test_path = NULL;
	p11_test_bad_path = NULL;

	return passed;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED */
