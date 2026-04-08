#ifndef QSCTEST_TLS_STAGE3_TRANSCRIPT_TESTS_H
#define QSCTEST_TLS_STAGE3_TRANSCRIPT_TESTS_H

#include "qsccommon.h"

/**
 * \file tls_stage3_transcript_tests.h
 * \brief TLS Stage 3 transcript test interface.
 *
 * \details
 * Declares the Stage 3 TLS transcript test entry point. This stage validates
 * transcript initialization, append behavior, snapshot generation, cloning,
 * reset semantics, hash-size mapping, and invalid-state rejection.
 *
 * The tests are deterministic and operate entirely in memory. No socket I/O,
 * process creation, or external tooling is used.
 */

/**
 * \brief Tests transcript hash-size mapping and basic initialization behavior.
 *
 * \return
 * true if the transcript hash-size and initialization checks succeed;
 * false otherwise.
 */
bool tls_stage3_transcript_initialize(void);

/**
 * \brief Tests transcript append and snapshot correctness.
 *
 * \details
 * This test appends fixed transcript fragments and verifies that the snapshot
 * digest matches the digest computed directly with the underlying SHA-2
 * implementation for each supported transcript hash algorithm.
 *
 * \return
 * true if the transcript snapshot checks succeed; false otherwise.
 */
bool tls_stage3_transcript_snapshot(void);

/**
 * \brief Tests transcript clone and reset semantics.
 *
 * \details
 * This test verifies that cloning preserves transcript state exactly, and that
 * reset returns the transcript to a clean initialized state while preserving
 * the configured hash algorithm.
 *
 * \return
 * true if the clone and reset checks succeed; false otherwise.
 */
bool tls_stage3_transcript_clone_reset(void);

/**
 * \brief Tests transcript invalid-input and invalid-state rejection.
 *
 * \return
 * true if invalid input and invalid state paths are handled correctly;
 * false otherwise.
 */
bool tls_stage3_transcript_negative_paths(void);

/**
 * \brief Execute the TLS Stage 3 transcript tests.
 *
 * Runs the complete test set associated with transcript handling.
 *
 * \return Returns true if the full stage passes; otherwise returns false.
 */
bool qsctest_tls_stage3_tests(void);

#endif
