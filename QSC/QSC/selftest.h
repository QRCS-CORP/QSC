#ifndef QSC_SELFTEST_H
#define QSC_SELFTEST_H

#include "common.h"

/**
* \brief Tests the ChaCha cipher for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsctest_chacha_test();

/**
* \brief Tests the CSX cipher for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsctest_csx_test();

/**
* \brief Tests the Poly1305 cipher for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsctest_poly1305_test();

/**
* \brief Tests the RCS cipher for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsctest_rcs_test();

/**
* \brief Tests the SHA2 digests, HKDF and HMAC for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsctest_sha2_test();

/**
* \brief Tests the SHA3 digests, SHAKE, cSHAKE, and KMAC for correct operation.
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsctest_sha3_test();

/**
* \brief Runs the library self tests.
* Tests the symmetric primitives with a set of known-answer tests.
*
* \return Returns true if all tests pass successfully
*/
QSC_EXPORT_API bool qsctest_symmetric_selftest_run();

#endif