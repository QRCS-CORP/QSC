/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_SELFTEST_H
#define QSC_SELFTEST_H

#include "common.h"

/*!
 * \file selftest.h
 * \brief Symmetric functions self-test.
 *
 * \details
 * This header provides self-test functions for the cryptographic library's symmetric
 * primitives including AES, ChaCha, CSX, RCS, SHA2, and SHA3 implementations. These tests
 * perform known-answer tests (KATs) to verify correct operation of the implementations.
 */

/*!
 * \brief Tests the AES cipher for correct operation.
 *
 * \return	[bool] Returns true if the AES test passes.
 */
QSC_EXPORT_API bool qsc_selftest_aes_test(void);

/*!
 * \brief Tests the ChaCha cipher for correct operation.
 *
 * \return	[bool] Returns true if the ChaCha test passes.
 */
QSC_EXPORT_API bool qsc_selftest_chacha_test(void);

/*!
 * \brief Tests the CSX cipher for correct operation.
 *
 * \return	[bool] Returns true if the CSX test passes.
 */
QSC_EXPORT_API bool qsc_selftest_csx_test(void);

/*!
 * \brief Tests the RCS cipher for correct operation.
 *
 * \return	[bool] Returns true if the RCS test passes.
 */
QSC_EXPORT_API bool qsc_selftest_rcs_test(void);

/*!
 * \brief Tests the SHA2 digests, HKDF and HMAC for correct operation.
 *
 * \return	[bool] Returns true if the SHA2 test passes.
 */
QSC_EXPORT_API bool qsc_selftest_sha2_test(void);

/*!
 * \brief Tests the SHA3 digests, SHAKE, cSHAKE, and KMAC for correct operation.
 *
 * \return	[bool] Returns true if the SHA3 test passes.
 */
QSC_EXPORT_API bool qsc_selftest_sha3_test(void);

/*!
 * \brief Runs the library self tests.
 *
 * Tests the symmetric primitives with a set of known-answer tests.
 *
 * \return	[bool] Returns true if all tests pass successfully.
 */
QSC_EXPORT_API bool qsc_selftest_symmetric_run(void);

#endif
