
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

#ifndef QSC_SELFTEST_H
#define QSC_SELFTEST_H

#include "common.h"

/**
* \file selftest.h
* \brief Symmetric functions self-test
*/

/**
* \brief Tests the AES cipher for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_selftest_aes_test(void);

/**
* \brief Tests the ChaCha cipher for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_selftest_chacha_test(void);

/**
* \brief Tests the CSX cipher for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_selftest_csx_test(void);

/**
* \brief Tests the Poly1305 cipher for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_selftest_poly1305_test(void);

/**
* \brief Tests the RCS cipher for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_selftest_rcs_test(void);

/**
* \brief Tests the SHA2 digests, HKDF and HMAC for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_selftest_sha2_test(void);

/**
* \brief Tests the SHA3 digests, SHAKE, cSHAKE, and KMAC for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_selftest_sha3_test(void);

/**
* \brief Runs the library self tests.
* Tests the symmetric primitives with a set of known-answer tests.
*
* \return Returns true if all tests pass successfully
*/
QSC_EXPORT_API bool qsc_selftest_symmetric_run(void);

#endif
