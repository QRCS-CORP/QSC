#ifndef QSCTEST_TLS_STAGE4_SCHEDULE_TESTS_H
#define QSCTEST_TLS_STAGE4_SCHEDULE_TESTS_H

#include "qsccommon.h"

/**
 * \file tls_stage4_schedule_tests.h
 * \brief TLS Stage 4 key-schedule test interface.
 *
 * \details
 * Declares the Stage 4 TLS key-schedule test entry point. This stage validates
 * HKDF extract handling, HKDF-Expand-Label construction, transcript-bound
 * secret derivation, finished-key derivation, empty-hash generation, and
 * negative-path rejection for invalid inputs and unsupported hash selections.
 *
 * The tests are deterministic and operate entirely in memory. No socket I/O,
 * process creation, or external tooling is used.
 */

/**
 * \brief Tests HKDF extract behavior for the supported transcript hashes.
 *
 * \details
 * This test compares qsc_tls_schedule_extract() against the underlying HKDF
 * implementation used by the library for SHA-256, SHA-384, and SHA-512 based
 * schedules.
 *
 * \return
 * true if the extract checks succeed; false otherwise.
 */
bool tls_stage4_schedule_extract(void);

/**
 * \brief Tests HKDF-Expand-Label output construction.
 *
 * \details
 * This test reconstructs the TLS 1.3 HKDF label encoding in the test harness
 * and confirms that qsc_tls_schedule_expand_label() produces the same derived
 * bytes as a direct HKDF expansion using the encoded label as the info field.
 *
 * \return
 * true if the expand-label checks succeed; false otherwise.
 */
bool tls_stage4_schedule_expand_label(void);

/**
 * \brief Tests transcript-bound secret derivation and finished-key generation.
 *
 * \details
 * This test constructs a transcript, snapshots its hash, and verifies that
 * qsc_tls_schedule_derive_secret() and qsc_tls_schedule_finished_key() match
 * the expected outputs derived from the lower-level schedule primitives.
 *
 * \return
 * true if the derive-secret and finished-key checks succeed; false otherwise.
 */
bool tls_stage4_schedule_derive_finished(void);

/**
 * \brief Tests empty-hash generation and schedule negative paths.
 *
 * \return
 * true if empty-hash generation and negative-path handling are correct;
 * false otherwise.
 */
bool tls_stage4_schedule_negative_paths(void);

/**
 * \brief Execute the TLS Stage 4 key-schedule tests.
 *
 * Runs the complete test set associated with the TLS key schedule.
 *
 * \return Returns true if the full stage passes; otherwise returns false.
 */
bool qsctest_tls_stage4_tests(void);

#endif
