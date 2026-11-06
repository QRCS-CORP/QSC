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

#include "hwse050_test.h"

#if defined(QSC_HARDWARE_ENABLED) && defined(QSC_HARDWARE_PKCS11_ENABLED) && defined(QSC_HARDWARE_SE050_ENABLED)

#include "hwse050.h"
#include "memutils.h"
#include "testutils.h"
#include <stdlib.h>

/** \brief Populate a known synthetic token serial to test strict policy matching.
 * \param policy Writable fixed-size versioned test policy.
 */
static void hwse050_test_policy(qsc_hw_se050_policy* policy)
{
	qsc_memutils_clear(policy, sizeof(qsc_hw_se050_policy));
	policy->size = sizeof(qsc_hw_se050_policy);
	policy->version = QSC_HW_ABI_VERSION;
	qsc_memutils_copy(policy->expected_serial, "12345678", 9U);
}

/** \brief Check baseline mechanism discovery and strict token-serial matching.
 * \param module Open synthetic test module.
 * \return True when token identity and CKM_ECDSA match.
 */
static bool hwse050_test_valid_token(qsc_hw_pkcs11_module* module)
{
	qsc_hw_se050_policy policy;
	bool valid;

	hwse050_test_policy(&policy);
	valid = (qsc_hw_se050_preflight(module, 7U, &policy) == qsc_hw_status_success);
	qsctest_print_line(valid ? "[PASS] Stage9 SE050 PKCS11 exact serial and ECDSA discovery" : "[FAIL] Stage9 SE050 PKCS11 exact serial and ECDSA discovery");
	return valid;
}

/** \brief Prevent selecting a different logical token after slot reassignment.
 * \param module Open synthetic test module.
 * \return True when wrong configured identity cannot pass.
 */
static bool hwse050_test_wrong_serial(qsc_hw_pkcs11_module* module)
{
	qsc_hw_se050_policy policy;
	bool valid;

	hwse050_test_policy(&policy);
	policy.expected_serial[0U] = 'X';
	valid = (qsc_hw_se050_preflight(module, 7U, &policy) == qsc_hw_status_policy);
	qsctest_print_line(valid ? "[PASS] Stage9 SE050 wrong PKCS11 token serial rejected" : "[FAIL] Stage9 SE050 wrong PKCS11 token serial rejected");
	return valid;
}

/** \brief Deny unsupported EC key pair generation instead of implying capability.
 * \param module Open synthetic test module.
 * \return True when absent mechanism is explicit unsupported.
 */
static bool hwse050_test_generation_absent(qsc_hw_pkcs11_module* module)
{
	qsc_hw_se050_policy policy;
	bool valid;

	hwse050_test_policy(&policy);
	policy.require_ec_key_generation = true;
	valid = (qsc_hw_se050_preflight(module, 7U, &policy) == qsc_hw_status_unsupported);
	qsctest_print_line(valid ? "[PASS] Stage9 SE050 absent EC generation mechanism rejected" : "[FAIL] Stage9 SE050 absent EC generation mechanism rejected");
	return valid;
}

/** \brief Require explicit OEM secure-channel state before selecting the token.
 * \param module Open synthetic test module.
 * \return True when unconfirmed SCP03 is rejected.
 */
static bool hwse050_test_scp03_unconfirmed(qsc_hw_pkcs11_module* module)
{
	qsc_hw_se050_policy policy;
	bool valid;

	hwse050_test_policy(&policy);
	policy.require_scp03 = true;
	valid = (qsc_hw_se050_preflight(module, 7U, &policy) == qsc_hw_status_policy);
	qsctest_print_line(valid ? "[PASS] Stage9 SE050 unconfirmed SCP03 policy refused" : "[FAIL] Stage9 SE050 unconfirmed SCP03 policy refused");
	return valid;
}

/** \brief Reject unsupported protected-authentication flags.
 * \param module Open synthetic test module.
 * \return True when PIN-path requirement does not silently downgrade.
 */
static bool hwse050_test_protected_auth_absent(qsc_hw_pkcs11_module* module)
{
	qsc_hw_se050_policy policy;
	bool valid;

	hwse050_test_policy(&policy);
	policy.require_protected_authentication = true;
	valid = (qsc_hw_se050_preflight(module, 7U, &policy) == qsc_hw_status_policy);
	qsctest_print_line(valid ? "[PASS] Stage9 SE050 missing protected auth capability refused" : "[FAIL] Stage9 SE050 missing protected auth capability refused");
	return valid;
}

/** \brief Validate policy size/version and all bounded serial fields.
 * \param module Open synthetic test module.
 * \return True when malformed or unterminated policy is rejected.
 */
static bool hwse050_test_malformed_policy(qsc_hw_pkcs11_module* module)
{
	qsc_hw_se050_policy policy;
	bool valid;
	size_t i;

	hwse050_test_policy(&policy);
	valid = (qsc_hw_se050_preflight(NULL, 7U, &policy) == qsc_hw_status_invalid_parameter);
	policy.version = QSC_HW_ABI_VERSION + 1U;
	valid = (qsc_hw_se050_preflight(module, 7U, &policy) == qsc_hw_status_invalid_parameter) && valid;
	policy.version = QSC_HW_ABI_VERSION;

	for (i = 0U; i < sizeof(policy.expected_serial); ++i)
	{
		policy.expected_serial[i] = 'A';
	}

	valid = (qsc_hw_se050_preflight(module, 7U, &policy) == qsc_hw_status_invalid_parameter) && valid;
	qsctest_print_line(valid ? "[PASS] Stage9 SE050 malformed or unterminated serial rejected" : "[FAIL] Stage9 SE050 malformed or unterminated serial rejected");
	return valid;
}

bool qsctest_hwse050_run(void)
{
	qsc_hw_pkcs11_module* module;
	qsc_hw_status status;
	const char* path;
	bool valid;
	bool environment_ready;
#if defined(_MSC_VER)
	char* modulepath;
	size_t pathlen;
#endif

	valid = true;
	module = NULL;
#if defined(_MSC_VER)
	modulepath = NULL;
	pathlen = 0U;
	environment_ready = (_dupenv_s(&modulepath, &pathlen, "QSC_TEST_PKCS11_MODULE") == 0);
	path = modulepath;
#else
	environment_ready = true;
	path = getenv("QSC_TEST_PKCS11_MODULE");
#endif

	if (environment_ready == false)
	{
		qsctest_print_line("[FAIL] Stage9 SE050 fixture environment lookup failed");
		valid = false;
	}
	else if (path != NULL && path[0U] != '\0')
	{
		status = qsc_hw_pkcs11_module_open(&module, path);
		valid = (status == qsc_hw_status_success);

		if (valid == true)
		{
			valid = hwse050_test_valid_token(module) && valid;
			valid = hwse050_test_wrong_serial(module) && valid;
			valid = hwse050_test_generation_absent(module) && valid;
			valid = hwse050_test_scp03_unconfirmed(module) && valid;
			valid = hwse050_test_protected_auth_absent(module) && valid;
			valid = hwse050_test_malformed_policy(module) && valid;
			valid = (qsc_hw_pkcs11_module_close(&module) == qsc_hw_status_success) && valid;
		}
		else
		{
			qsctest_print_line("[FAIL] Stage9 SE050 synthetic PKCS11 module failed to open");
		}
	}
	else
	{
		qsctest_print_line("[SKIP] Stage9 SE050 requires QSC_TEST_PKCS11_MODULE synthetic fixture");
	}

#if defined(_MSC_VER)
	free(modulepath);
#endif
	return valid;
}

#endif /* QSC_HARDWARE_ENABLED && QSC_HARDWARE_PKCS11_ENABLED && QSC_HARDWARE_SE050_ENABLED */
