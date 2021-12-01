/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
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
