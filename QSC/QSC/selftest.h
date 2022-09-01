/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
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
