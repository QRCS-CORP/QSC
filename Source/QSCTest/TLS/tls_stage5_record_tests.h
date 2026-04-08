#ifndef QSCTEST_TLS_STAGE5_RECORD_TESTS_H
#define QSCTEST_TLS_STAGE5_RECORD_TESTS_H

#include "../qsctestcommon.h"
#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tls_stage5_record_tests.h
 * \brief Declares Stage 5 TLS record-layer function tests.
 *
 * \details
 * Stage 5 validates TLS record-state lifecycle behavior, plaintext record
 * encoding and decoding, protected record encryption and decryption,
 * sequence-driven nonce behavior, content-type transitions, and malformed
 * record rejection. The tests are deterministic and execute entirely
 * in memory.
 */

/**
 * \brief Tests record-state initialization and disposal behavior.
 *
 * \return [bool] Returns true only if the lifecycle checks succeed.
 */
bool tls_stage5_record_state_lifecycle(void);

/**
 * \brief Tests plaintext record encode and decode behavior.
 *
 * \return [bool] Returns true only if the plaintext round-trip checks succeed.
 */
bool tls_stage5_record_plaintext_roundtrip(void);

/**
 * \brief Tests protected record encryption and decryption behavior.
 *
 * \return [bool] Returns true only if the protected-record round-trip checks succeed.
 */
bool tls_stage5_record_protected_roundtrip(void);

/**
 * \brief Tests sequence-driven nonce effects on protected records.
 *
 * \details
 * This test verifies that repeated encryption of the same plaintext with the
 * same key and IV produces distinct records as the sequence number advances,
 * and that a peer with mirrored sequence state can decrypt both records.
 *
 * \return [bool] Returns true only if the sequence checks succeed.
 */
bool tls_stage5_record_sequence_nonces(void);

/**
 * \brief Tests malformed-input and negative-path handling for records.
 *
 * \return [bool] Returns true only if the negative-path checks succeed.
 */
bool tls_stage5_record_negative_paths(void);

/**
 * \brief Run the Stage 5 TLS record-layer tests.
 *
 * \return [bool] Returns true only if all Stage 5 tests pass.
 */
bool qsctest_tls_stage5_tests(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
