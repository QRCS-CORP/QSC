\
#ifndef QSCTEST_X509_TEST_H
#define QSCTEST_X509_TEST_H

#include "qsctestcommon.h"
#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file x509_test.h
 * \brief Declares the QRCS X.509 test harness entry points.
 *
 * \details
 * This header defines the master X.509 test runner and the per-stage dispatch
 * functions used by the qsctest framework. The X.509 tests are organized under
 * the qsctest\X509 directory, while all non-code fixtures such as PEM, DER,
 * CSR, CRL, and interoperability artifacts are stored beneath the vector root.
 *
 * The default vector root is:
 *
 * \code
 * X509/Vectors
 * \endcode
 *
 * Individual stages append their own sub-directory names, for example:
 *
 * \code
 * X509/Vectors/Stage1
 * X509/Vectors/Stage2A
 * X509/Vectors/Stage2B
 * X509/Vectors/Stage2C
 * X509/Vectors/Stage2D
 * X509/Vectors/Stage3
 * \endcode
 *
 * Each stage runner returns true only when that complete stage passes.
 * The master runner executes the enabled stages according to the
 * QSCTEST_X509_ENABLE_STAGE* compile-time macros.
 */

#if !defined(QSCTEST_X509_VECTOR_ROOT)
/**
 * \def QSCTEST_X509_VECTOR_ROOT
 * \brief The default relative root directory containing X.509 support files.
 */
#define QSCTEST_X509_VECTOR_ROOT "X509/Vectors"
#endif

/**
 * \brief Run the Stage 1 X.509 tests.
 *
 * \details
 * Stage 1 covers the initial certificate-chain verification tests, hostname
 * matching checks, and CRL-based revocation checks built during the first phase
 * of the harness.
 *
 * \return  [bool] Returns true only if all Stage 1 tests pass.
 */
bool qsctest_x509_stage1_run(void);

/**
 * \brief Run the Stage 2A X.509 CSR tests.
 *
 * \details
 * Stage 2A covers CSR decoding, CSR signature verification, tamper rejection,
 * and extension-request presence checks.
 *
 * \return  [bool] Returns true only if all Stage 2A tests pass.
 */
bool qsctest_x509_stage2a_run(void);

/**
 * \brief Run the Stage 2B X.509 PEM round-trip tests.
 *
 * \details
 * Stage 2B covers PEM decode/encode/decode round-trip handling for
 * certificates, CSRs, CRLs, and negative PEM input handling for key objects.
 *
 * \return  [bool] Returns true only if all Stage 2B tests pass.
 */
bool qsctest_x509_stage2b_run(void);

/**
 * \brief Run the Stage 2C X.509 CRL parse/write tests.
 *
 * \details
 * Stage 2C covers CRL PEM and DER decoding, CRL re-encoding, and revoked /
 * non-revoked serial lookups.
 *
 * \return  [bool] Returns true only if all Stage 2C tests pass.
 */
bool qsctest_x509_stage2c_run(void);

/**
 * \brief Run the Stage 2D X.509 negative validation tests.
 *
 * \details
 * Stage 2D covers expected-failure validation cases including time validity,
 * trust-anchor rejection, hostname mismatch, CA misuse, path-length violation,
 * and purpose rejection.
 *
 * \return  [bool] Returns true only if all Stage 2D tests pass.
 */
bool qsctest_x509_stage2d_run(void);

/**
 * \brief Run the Stage 3 X.509 positive interoperability tests.
 *
 * \details
 * Stage 3 covers positive interoperability validation using OpenSSL-generated
 * chains and fixtures together with known-answer checks derived from RFC 5280
 * time encodings and known-good CSR / CRL / DER certificate inputs.
 *
 * \return  [bool] Returns true only if all Stage 3 tests pass.
 */
bool qsctest_x509_stage3_run(void);

/**
 * \brief Executes the Stage 4A X.509 encoder validation test suite.
 *
 * This function runs a series of low-level encoding and decoding tests targeting
 * DER and PEM container correctness. The test suite is designed to isolate and
 * validate individual encoding paths independent of higher-level certificate
 * verification logic.
 *
 * The Stage 4A tests include round-trip validation of the following components:
 * - ASN.1 BIT STRING encoding and decoding
 * - SubjectPublicKeyInfo (SPKI) DER encode/decode
 * - PKCS#8 private key DER and PEM encode/decode
 * - CSR signature field DER and PEM encode/decode
 * - Certificate signature field DER and PEM encode/decode
 *
 * Large randomized buffers are used to ensure that encoder implementations do not
 * alter or truncate raw byte sequences. Each test verifies that input data matches
 * output data exactly after a full encode/decode cycle.
 *
 * The purpose of this stage is to confirm that container-level transformations do
 * not corrupt cryptographic material, particularly large ML-DSA signature blobs.
 *
 * \return Returns true if all Stage 4A encoder tests pass successfully.
 *         Returns false if any encoding or decoding validation fails.
 */
bool qsctest_x509_stage4a_run(void);

/**
 * \brief Executes the Stage 4B X.509 integration and round-trip test suite.
 *
 * This function runs higher-level X.509 tests that exercise full object
 * construction, encoding, decoding, and signature verification paths.
 * The tests focus on CSR and certificate workflows using post-quantum
 * ML-DSA signatures.
 *
 * The Stage 4B tests include:
 * - CSR generation, DER/PEM encoding, decoding, and signature verification
 * - Certificate generation, DER/PEM encoding, decoding, and signature verification
 * - End-to-end validation of signing callbacks and verification routines
 *
 * These tests verify that the signed data and signature fields remain consistent
 * across the complete container path, including ASN.1 encoding, DER serialization,
 * and PEM transformation.
 *
 * The suite is specifically designed to detect discrepancies between:
 * - the original signed message (e.g. CertificationRequestInfo)
 * - the reconstructed message used during verification
 *
 * Failures in this stage typically indicate inconsistencies in:
 * - CSR or certificate re-encoding
 * - signed data reconstruction during verification
 * - signature container handling for ML-DSA
 *
 * \return Returns true if all Stage 4B integration tests pass successfully.
 *         Returns false if any round-trip or verification test fails.
 */
bool qsctest_x509_stage4b_run(void);

/**
 * \brief Run the complete X.509 test harness.
 *
 * \details
 * Executes the enabled X.509 test stages according to the compile-time
 * QSCTEST_X509_ENABLE_STAGE* macros. A success message is emitted only when
 * all enabled stages pass.
 */
void qsctest_x509_run(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
