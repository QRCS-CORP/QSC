#ifndef QSCTEST_TLS_STAGE6_CERTIFICATE_MESSAGE_TESTS_H
#define QSCTEST_TLS_STAGE6_CERTIFICATE_MESSAGE_TESTS_H

#include "qsccommon.h"

/**
 * \file tls_stage6_certificate_message_tests.h
 * \brief TLS Stage 6 certificate-message test interface.
 *
 * \details
 * Declares the Stage 6 TLS function tests covering Certificate,
 * CertificateRequest, and CertificateVerify message construction and parsing,
 * together with certificate-interface callback handling and negative-path
 * validation. The tests are deterministic and operate entirely on in-memory
 * serialized objects.
 */

QSC_CPLUSPLUS_ENABLED_START

/**
 * \brief Tests Certificate message build and parse round-trip behavior.
 *
 * \details
 * This test builds a TLS Certificate message containing a request context and
 * multiple certificate entries, parses the serialized message, and verifies
 * that all entry boundaries and lengths are preserved exactly.
 *
 * \return Returns true if the round-trip succeeds; otherwise returns false.
 */
bool tls_stage6_certificate_message_roundtrip(void);

/**
 * \brief Tests Certificate message malformed-input rejection.
 *
 * \details
 * This test exercises invalid-input and malformed-length handling for the TLS
 * Certificate message encoder and parser.
 *
 * \return Returns true if all invalid cases are rejected; otherwise returns false.
 */
bool tls_stage6_certificate_message_negative(void);

/**
 * \brief Tests CertificateRequest message build and parse round-trip behavior.
 *
 * \details
 * This test constructs a CertificateRequest message with a request context and
 * signature_algorithms extension, parses the message, and verifies that the
 * decoded signature-scheme list matches the original input.
 *
 * \return Returns true if the round-trip succeeds; otherwise returns false.
 */
bool tls_stage6_certificate_request_roundtrip(void);

/**
 * \brief Tests CertificateRequest message malformed-extension rejection.
 *
 * \details
 * This test tampers with serialized CertificateRequest extension lengths and
 * signature-scheme list lengths to confirm strict parser rejection.
 *
 * \return Returns true if malformed cases are rejected; otherwise returns false.
 */
bool tls_stage6_certificate_request_negative(void);

/**
 * \brief Tests CertificateVerify message build and parse round-trip behavior.
 *
 * \details
 * This test builds and parses a CertificateVerify message using an allowed
 * certificate-verify signature scheme and validates exact signature recovery.
 *
 * \return Returns true if the round-trip succeeds; otherwise returns false.
 */
bool tls_stage6_certificate_verify_roundtrip(void);

/**
 * \brief Tests CertificateVerify scheme filtering and malformed-input rejection.
 *
 * \details
 * This test confirms that unsupported signature schemes and inconsistent
 * serialized signature lengths are rejected by the builder and parser.
 *
 * \return Returns true if all invalid cases are rejected; otherwise returns false.
 */
bool tls_stage6_certificate_verify_negative(void);

/**
 * \brief Tests certificate-interface initialization and peer-chain validation.
 *
 * \details
 * This test validates interface initialization, validity checks, callback
 * dispatch, required-peer-certificate handling, and authentication-failure
 * propagation for peer certificate-chain validation.
 *
 * \return Returns true if all interface and peer-validation cases succeed; otherwise returns false.
 */
bool tls_stage6_certificate_peer_validation(void);

/**
 * \brief Tests CertificateVerify callback validation behavior.
 *
 * \details
 * This test validates transcript and signer dispatch into the configured
 * CertificateVerify callback and confirms authentication-failure and
 * invalid-state handling.
 *
 * \return Returns true if all CertificateVerify callback cases succeed; otherwise returns false.
 */
bool tls_stage6_certificate_verify_validation(void);

/**
 * \brief Execute the TLS Stage 6 test suite.
 *
 * \return Returns true if the full stage passes; otherwise returns false.
 */
bool qsctest_tls_stage6_tests(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
