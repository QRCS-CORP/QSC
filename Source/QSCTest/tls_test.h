#ifndef QSCTEST_TLS_TEST_H
#define QSCTEST_TLS_TEST_H

#include "qsctestcommon.h"
#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tls_test.h
 * \brief Declares the top-level TLS function-test harness entry points.
 *
 * \details
 * This header declares the consolidated TLS test-harness entry points used by
 * the qsctest framework. The TLS harness is organized as deterministic,
 * function-level stages that validate the QSC TLS implementation as a
 * self-contained protocol stack without any dependency on OpenSSL binaries,
 * processes, shell commands, or runtime-generated artifacts.
 */

/**
 * \brief Run Stage 1 of the TLS function-test suite.
 *
 * \return Returns true only if all Stage 1 tests pass.
 */
bool qsctest_tls_stage1_run(void);

/**
 * \brief Run Stage 2 of the TLS function-test suite.
 *
 * \return Returns true only if all Stage 2 tests pass.
 */
bool qsctest_tls_stage2_run(void);

/**
 * \brief Run Stage 3 of the TLS function-test suite.
 *
 * \return Returns true only if all Stage 3 tests pass.
 */
bool qsctest_tls_stage3_run(void);

/**
 * \brief Run Stage 4 of the TLS function-test suite.
 *
 * \return Returns true only if all Stage 4 tests pass.
 */
bool qsctest_tls_stage4_run(void);

/**
 * \brief Run Stage 5 of the TLS function-test suite.
 *
 * \return Returns true only if all Stage 5 tests pass.
 */
bool qsctest_tls_stage5_run(void);

/**
 * \brief Run Stage 6 of the TLS function-test suite.
 *
 * \details
 * Stage 6 validates Certificate, CertificateRequest, and CertificateVerify
 * message serialization and parsing, together with certificate callback
 * interface handling and negative-path validation.
 *
 * \return Returns true only if all Stage 6 tests pass.
 */
bool qsctest_tls_stage6_run(void);

/**
 * \brief Run the complete staged TLS function-test suite.
 *
 * \return Returns true only if all enabled TLS stages pass.
 */
bool qsctest_tls_run(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
