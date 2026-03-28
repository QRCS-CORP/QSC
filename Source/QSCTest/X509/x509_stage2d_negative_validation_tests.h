#ifndef QSCTEST_X509_STAGE2D_NEGATIVE_VALIDATION_TESTS_H
#define QSCTEST_X509_STAGE2D_NEGATIVE_VALIDATION_TESTS_H

#include "qsccommon.h"

/**
 * \file x509_stage2d_negative_validation_tests.h
 * \brief X.509 Stage 2D Negative Validation Test Interface.
 *
 * Declares the stage 2D X.509 negative validation test entry point.
 * This stage is used to validate rejection behavior for malformed,
 * mis-issued, expired, not-yet-valid, policy-incompatible,
 * or otherwise invalid certificate and chain inputs.
 * The function returns true only when every negative validation case behaves as expected.
 */

 /**
  * \brief Tests rejection of an expired certificate.
  *
  * \details
  * This test verifies that certificate validation fails when the current time
  * is beyond the certificate’s Not After validity bound. It ensures correct
  * enforcement of validity period constraints during chain verification.
  *
  * \return
  * true if the expired certificate is correctly rejected; false otherwise.
  */
bool x509_stage2d_expired_certificate(void);

/**
 * \brief Tests rejection of a certificate that is not yet valid.
 *
 * \details
 * This test validates that a certificate with a Not Before timestamp in the
 * future is rejected during verification. It ensures correct handling of
 * validity windows and enforcement of temporal constraints.
 *
 * \return
 * true if the not-yet-valid certificate is correctly rejected; false otherwise.
 */
bool x509_stage2d_not_yet_valid_certificate(void);

/**
 * \brief Tests rejection of a chain anchored to an untrusted root.
 *
 * \details
 * This test verifies that certificate chain validation fails when the root
 * certificate is not present in the trusted store. It ensures that only
 * explicitly trusted anchors are accepted during chain verification.
 *
 * \return
 * true if the chain is correctly rejected due to an untrusted root; false otherwise.
 */
bool x509_stage2d_untrusted_root(void);

/**
 * \brief Tests rejection of a certificate due to hostname mismatch.
 *
 * \details
 * This test ensures that certificate verification fails when the expected
 * hostname does not match the certificate’s Subject Alternative Name (SAN)
 * or Common Name (CN). It validates correct hostname binding enforcement.
 *
 * \return
 * true if the certificate is correctly rejected for hostname mismatch; false otherwise.
 */
bool x509_stage2d_hostname_mismatch(void);

/**
 * \brief Tests rejection of a certificate used improperly as a certificate authority.
 *
 * \details
 * This test verifies that a certificate lacking CA privileges (e.g. missing
 * Basic Constraints CA flag) is not accepted as an issuing authority within
 * a chain. It ensures enforcement of CA usage constraints during path validation.
 *
 * \return
 * true if CA misuse is correctly detected and rejected; false otherwise.
 */
bool x509_stage2d_ca_misuse(void);

/**
 * \brief Tests rejection of an expired certificate.
 *
 * \details
 * This test verifies that certificate validation fails when the current time
 * is beyond the certificate’s Not After validity bound. It ensures correct
 * enforcement of validity period constraints during chain verification.
 *
 * \return
 * true if the expired certificate is correctly rejected; false otherwise.
 */
bool x509_stage2d_expired_certificate(void);

/**
 * \brief Tests rejection of a certificate for improper usage purpose.
 *
 * \details
 * This test ensures that certificate validation enforces Extended Key Usage
 * (EKU) and related purpose constraints. A certificate not valid for the
 * requested usage (e.g. server authentication) is expected to be rejected.
 *
 * \return
 * true if the certificate is correctly rejected due to purpose mismatch; false otherwise.
 */
bool x509_stage2d_purpose_rejection(void);

/**
 * \brief Tests rejection of a certificate chain that exceeds the Basic Constraints path length.
 *
 * \details
 * This test constructs or loads a certificate chain in which one or more CA
 * certificates specify a pathLen constraint that is violated by the depth of
 * subordinate certificates in the chain. During verification, the chain
 * evaluation must detect that the allowed maximum number of intermediate CAs
 * has been exceeded and fail validation accordingly.
 *
 * The test ensures:
 * - Correct parsing and enforcement of the Basic Constraints extension.
 * - Accurate tracking of CA depth during chain construction.
 * - Rejection of chains exceeding the specified pathLen limit.
 *
 * \return
 * true if the path length violation is correctly detected; false otherwise.
 */
bool x509_stage2d_pathlen_violation(void);

/**
 * \brief Execute the x.509 stage 2d negative validation test.
 *
 * Runs the complete test set associated with this stage of the X.509 test
 * framework.
 *
 * \return Returns true if the full stage passes; otherwise returns false.
 */
bool qsctest_x509_stage2d_negative_validation_tests(void);

#endif
