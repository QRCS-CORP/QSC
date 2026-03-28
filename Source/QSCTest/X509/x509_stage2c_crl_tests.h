#ifndef QSCTEST_X509_STAGE2C_CRL_TESTS_H
#define QSCTEST_X509_STAGE2C_CRL_TESTS_H

#include "qsccommon.h"

/**
 * \file x509_stage2c_crl_tests.h
 * \brief X.509 Stage 2C CRL Test Interface.
 *
 * Declares the stage 2C X.509 certificate revocation list test entry point. 
 * This stage is used to validate CRL encoding, decoding, signature verification, 
 * revocation lookup, and related revocation handling paths. 
 * The function returns true only when all CRL tests succeed.
 */

/**
 * \brief Tests decoding of a CRL in PEM format.
 *
 * \details
 * This test verifies that a PEM-encoded Certificate Revocation List (CRL) can
 * be successfully parsed and decoded into its internal representation. It
 * ensures correct handling of the ASN.1 structure, issuer, signature, and
 * revoked certificate entries.
 *
 * \return
 * true if the CRL is successfully decoded from PEM; false otherwise.
 */
bool x509_stage2c_crl_pem_decode(void);

/**
 * \brief Tests decoding of a CRL in DER format.
 *
 * \details
 * This test validates that a DER-encoded CRL can be parsed and decoded correctly.
 * It ensures proper interpretation of ASN.1 encoding, including issuer fields,
 * signature, and the list of revoked certificates.
 *
 * \return
 * true if the CRL is successfully decoded from DER; false otherwise.
 */
bool x509_stage2c_crl_der_decode(void);

/**
 * \brief Tests CRL PEM encoding and decoding round-trip.
 *
 * \details
 * This test verifies that a CRL can be encoded to PEM format and decoded back
 * without loss of information. It ensures that issuer data, signature, and
 * revoked certificate entries remain consistent through the conversion.
 *
 * \return
 * true if the PEM round-trip succeeds and CRL integrity is preserved; false otherwise.
 */
bool x509_stage2c_crl_pem_roundtrip(void);

/**
 * \brief Tests CRL DER encoding and decoding round-trip.
 *
 * \details
 * This test ensures that a CRL can be encoded to DER format and decoded back
 * while preserving all structural and semantic information. It validates
 * correct ASN.1 serialization and deserialization of the CRL.
 *
 * \return
 * true if the DER round-trip succeeds and data integrity is maintained; false otherwise.
 */
bool x509_stage2c_crl_der_roundtrip(void);

/**
 * \brief Tests lookup of a revoked certificate within a CRL.
 *
 * \details
 * This test verifies that a certificate known to be revoked is correctly
 * identified in the CRL. It ensures accurate matching of serial numbers
 * against the CRL revocation entries.
 *
 * \return
 * true if the revoked certificate is correctly detected; false otherwise.
 */
bool x509_stage2c_crl_revoked_lookup(void);

/**
 * \brief Tests lookup of a non-revoked certificate within a CRL.
 *
 * \details
 * This test ensures that a certificate not present in the CRL is correctly
 * identified as not revoked. It validates that no false positives occur
 * during serial number lookup.
 *
 * \return
 * true if the certificate is correctly identified as not revoked; false otherwise.
 */
bool x509_stage2c_not_revoked_lookup(void);

/**
 * \brief Execute the x.509 stage 2c crl test.
 *
 * Runs the complete test set associated with this stage of the X.509 test
 * framework.
 *
 * \return Returns true if the full stage passes; otherwise returns false.
 */
bool qsctest_x509_stage2c_crl_tests(void);

#endif
