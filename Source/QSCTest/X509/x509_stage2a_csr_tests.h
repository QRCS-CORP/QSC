#ifndef QSCTEST_X509_STAGE2A_CSR_TESTS_H
#define QSCTEST_X509_STAGE2A_CSR_TESTS_H

#include "qsccommon.h"

/**
 * \file x509_stage2a_csr_tests.h
 * \brief X.509 Stage 2A CSR Test Interface.
 *
 * Declares the stage 2A X.509 certificate signing request test entry point. 
 * This stage is used to validate CSR generation, parsing, encoding, 
 * and round-trip behavior for the CSR portion of the implementation. 
 * The function returns true only when all CSR tests succeed.
 */

/**
 * \brief Tests decoding and validation of a valid CSR in PEM format.
 *
 * \details
 * This test verifies that a correctly formed Certificate Signing Request (CSR)
 * encoded in PEM format can be successfully parsed, decoded, and validated.
 * It ensures that the CSR structure, signature, and embedded subject and public
 * key information conform to expected encoding and verification rules.
 *
 * \return
 * true if the CSR is successfully decoded and verified; false otherwise.
 */
bool x509_stage2a_valid_csr_pem(void);

/**
 * \brief Tests decoding and validation of a valid CSR in DER format.
 *
 * \details
 * This test validates that a properly encoded DER CSR can be parsed and its
 * signature verified. It ensures that the ASN.1 structure is correctly handled
 * and that the extracted subject and public key information are consistent
 * with the CSR contents.
 *
 * \return
 * true if the DER CSR is successfully decoded and verified; false otherwise.
 */
bool x509_stage2a_valid_csr_der(void);

/**
 * \brief Tests detection of a tampered CSR signature.
 *
 * \details
 * This test modifies a valid CSR to corrupt its signature and verifies that
 * signature validation fails as expected. It ensures that the CSR verification
 * logic detects integrity violations and rejects altered or forged requests.
 *
 * \return
 * true if the tampered CSR is correctly rejected; false otherwise.
 */
bool x509_stage2a_tampered_csr_signature(void);

/**
 * \brief Tests presence and parsing of the extensionRequest attribute in a CSR.
 *
 * \details
 * This test verifies that the CSR contains the PKCS#10 extensionRequest attribute
 * and that it is correctly decoded. It ensures that requested extensions such as
 * subject alternative names or key usage are properly extracted from the CSR
 * attributes section.
 *
 * \return
 * true if the extensionRequest attribute is present and correctly parsed; false otherwise.
 */
bool x509_stage2a_extension_request_present(void);

/**
 * \brief Execute the x.509 stage 2a csr test.
 *
 * Runs the complete test set associated with this stage of the X.509 test
 * framework.
 *
 * \return Returns true if the full stage passes; otherwise returns false.
 */
bool qsctest_x509_stage2a_csr_tests(void);

#endif
