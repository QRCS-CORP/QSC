/**
 * \file x509_stage4a_encoder_tests.h
 * \brief Declares the stage 4A X.509 encoder round-trip test functions.
 *
 * This header exposes the test entry points used to validate the X.509
 * encoder and decoder paths exercised by the stage 4A test suite. The
 * tests are intended to confirm that encoded values can be serialized and
 * decoded without alteration across the target container paths, including
 * BIT STRING fields, Subject Public Key Info (SPKI), PKCS#8 private keys,
 * certificate request signatures, and certificate signatures.
 *
 * Each function returns true only if the targeted round-trip path preserves
 * the expected value and all associated validation checks succeed.
 */
#ifndef QSCTEST_X509_STAGE4A_ENCODING_TESTS_H
#define QSCTEST_X509_STAGE4A_ENCODING_TESTS_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \brief Tests BIT STRING encoder and decoder round-trip correctness.
 *
 * This test validates that a BIT STRING value written by the encoder can be
 * decoded without modification to its payload or associated metadata. The
 * function is intended to detect corruption in BIT STRING container handling,
 * including length encoding and unused-bit processing.
 *
 * \return Returns true if the BIT STRING round-trip test succeeds.
 */
bool x509_stage4a_encoder_bit_string_roundtrip(void);

/**
 * \brief Tests SPKI encoder and decoder round-trip correctness.
 *
 * This test validates that a Subject Public Key Info structure can be
 * encoded and decoded without altering the algorithm identifier, public key
 * encoding, or associated structural fields.
 *
 * \return Returns true if the SPKI round-trip test succeeds.
 */
bool x509_stage4a_encoder_spki_roundtrip(void);

/**
 * \brief Tests PKCS#8 encoder and decoder round-trip correctness.
 *
 * This test validates that a PKCS#8 private key container can be encoded and
 * decoded without altering the wrapped private key material, algorithm
 * identifier, or container structure.
 *
 * \return Returns true if the PKCS#8 round-trip test succeeds.
 */
bool x509_stage4a_encoder_pkcs8_roundtrip(void);

/**
 * \brief Tests CSR signature field encoder and decoder round-trip correctness.
 *
 * This test validates that the signature field of a certificate signing
 * request can be encoded and decoded without modification. It is intended to
 * detect corruption in the CSR signature container path, including DER and
 * related wrapper handling.
 *
 * \return Returns true if the CSR signature round-trip test succeeds.
 */
bool x509_stage4a_encoder_csr_signature_roundtrip(void);

/**
 * \brief Tests certificate signature field encoder and decoder round-trip correctness.
 *
 * This test validates that the certificate signature field can be encoded and
 * decoded without altering the signature bytes or associated container
 * representation.
 *
 * \return Returns true if the certificate signature round-trip test succeeds.
 */
bool x509_stage4a_encoder_certificate_signature_roundtrip(void);

/**
 * \brief Runs the complete stage 4A encoder test suite.
 *
 * This function executes the full set of stage 4A encoder round-trip tests,
 * including BIT STRING, SPKI, PKCS#8, CSR signature, and certificate
 * signature validation.
 *
 * \return Returns true if all stage 4A encoder tests succeed.
 */
bool qsctest_x509_stage4a_encoding_tests(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
