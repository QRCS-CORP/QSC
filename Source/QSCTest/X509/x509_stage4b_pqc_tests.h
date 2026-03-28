#ifndef QSCTEST_X509_STAGE4B_PQC_TESTS_H
#define QSCTEST_X509_STAGE4B_PQC_TESTS_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509_stage4_pqc_tests.h
 * \brief Stage 4 X.509 post-quantum integration test declarations.
 *
 * \details
 * This header declares the Stage 4 X.509 test routines used to validate
 * post-quantum public-key and signature integration paths, including ML-DSA
 * SubjectPublicKeyInfo round-trip handling, ML-DSA CSR generation and
 * verification, tamper rejection, certificate-chain verification, ML-KEM CA
 * rejection behavior, ML-KEM SubjectPublicKeyInfo round-trip handling, and
 * PKCS #8 private-key round-trip and certificate matching checks.
 *
 * The entry-point test function executes the Stage 4 PQC test set as an
 * aggregate suite.
 */

/*!
 * \brief Test ML-DSA SubjectPublicKeyInfo round-trip encoding and decoding.
 *
 * \details
 * Verifies that an ML-DSA SubjectPublicKeyInfo object can be constructed,
 * encoded, decoded, and compared without loss of algorithm or public-key
 * information.
 *
 * \return Returns true if the test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mldsa_spki_roundtrip(void);

/*!
 * \brief Test ML-DSA CSR round-trip encoding and verification.
 *
 * \details
 * Verifies that an ML-DSA-backed certificate signing request can be generated,
 * encoded, decoded, and signature-verified successfully.
 *
 * \return Returns true if the test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mldsa_csr_roundtrip(void);

/*!
 * \brief Test rejection of a tampered ML-DSA CSR.
 *
 * \details
 * Verifies that modifying an ML-DSA certificate signing request causes
 * signature verification failure or equivalent rejection by the CSR validation
 * path.
 *
 * \return Returns true if the tampered CSR is correctly rejected; otherwise returns false.
 */
bool x509_stage4b_mldsa_csr_tamper_reject(void);

/*!
 * \brief Test ML-DSA certificate chain verification.
 *
 * \details
 * Verifies that a certificate chain signed and verified through the ML-DSA
 * integration path is accepted when all chain elements and signatures are
 * valid.
 *
 * \return Returns true if the chain verification test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mldsa_chain_verify(void);

/*!
 * \brief Test rejection of ML-KEM keys in CA signing roles.
 *
 * \details
 * Verifies that ML-KEM keys are rejected when used in a certification-authority
 * role or other signing context where an encryption or key-establishment key
 * must not be accepted as a certificate-signing key.
 *
 * \return Returns true if the invalid CA usage is correctly rejected; otherwise returns false.
 */
bool x509_stage4b_mlkem_ca_reject(void);

/*!
 * \brief Test ML-KEM SubjectPublicKeyInfo round-trip encoding and decoding.
 *
 * \details
 * Verifies that an ML-KEM SubjectPublicKeyInfo object can be constructed,
 * encoded, decoded, and compared without loss of algorithm or public-key
 * information.
 *
 * \return Returns true if the test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mlkem_spki_roundtrip(void);

/*!
 * \brief Test ML-DSA PKCS #8 round-trip decoding and certificate-key matching.
 *
 * \details
 * Verifies that an ML-DSA private key can be encoded and decoded through the
 * PKCS #8 path and that the recovered key material matches the corresponding
 * certificate public key.
 *
 * \return Returns true if the test completed successfully; otherwise returns false.
 */
bool x509_stage4b_mldsa_pkcs8_roundtrip_and_match(void);

/*!
 * \brief Execute the full Stage 4 X.509 post-quantum test suite.
 *
 * \details
 * Runs the complete collection of Stage 4 PQC tests declared in this header
 * and returns a single aggregate success or failure result.
 *
 * \return Returns true if all Stage 4 tests completed successfully; otherwise returns false.
 */
bool qsctest_x509_stage4b_pqc_tests(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
