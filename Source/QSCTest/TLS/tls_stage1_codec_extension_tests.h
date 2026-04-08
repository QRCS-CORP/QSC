#ifndef QSCTEST_TLS_STAGE1_CODEC_EXTENSION_TESTS_H
#define QSCTEST_TLS_STAGE1_CODEC_EXTENSION_TESTS_H

#include "../qsctestcommon.h"
#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tls_stage1_codec_extension_tests.h
 * \brief Declares Stage 1 TLS codec and extension function tests.
 *
 * \details
 * Stage 1 validates the lowest-level TLS serialization and parsing helpers.
 * These tests cover integer codec helpers, length-prefixed vectors, and the
 * base extension encoders and decoders used by ClientHello and ServerHello
 * processing.
 *
 * The stage is intentionally deterministic and isolated. It does not perform
 * any socket operations, process creation, external certificate generation, or
 * cross-tool invocation. All objects are constructed in-memory and validated
 * directly against the QSC implementation.
 */

/**
 * \brief Run the Stage 1 TLS codec and extension tests.
 *
 * \return [bool] Returns true only if all Stage 1 tests pass.
 */
bool qsctest_tls_stage1_tests(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
