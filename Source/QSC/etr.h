/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef QSC_ETR_H
#define QSC_ETR_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file etr.h
 * \brief External True Random entropy provider (ETR).
 *
 * \details
 * The External True Random entropy provider accepts raw entropy from a caller-supplied
 * true random number generator (TRNG). The external source is registered through
 * qsc_etr_initialize and is invoked by qsc_etr_generate whenever conditioned random
 * output is requested. Raw source data is validated and absorbed incrementally into
 * SHAKE-512 before the conditioned output is released to the caller.
 *
 * ETR is intended for hardware random-number generators, dedicated entropy appliances,
 * external devices, and application-defined entropy services. The external callback is
 * responsible for device access, source-specific startup tests, continuous health tests,
 * timeout handling, and reporting partial or failed reads. ETR does not retry a failed
 * source request and does not fall back to another entropy provider.
 *
 * Before source data is processed, ETR verifies the callback result, requires an exact
 * byte count, rejects an all-zero block, rejects a uniform-byte block, and rejects a raw
 * block that repeats the comparable prefix of the preceding block in the same generation
 * operation. Source data is collected in bounded requests and is securely erased after
 * use. If any check fails, qsc_etr_generate returns false and clears the output buffer.
 *
 * \section etr_features Features
 * - Accepts entropy from a caller-supplied external TRNG callback.
 * - Detects failed and partial source reads before processing.
 * - Rejects all-zero, uniform, and immediately repeated raw source blocks.
 * - Conditions validated source data with SHAKE-512.
 * - Provides no fallback, retry, or partial-output path.
 * - Clears the output buffer and internal entropy buffers on failure.
 *
 * \section etr_usage Usage Example
 * \code
 * #include "etr.h"
 *
 * static bool external_trng_generate(uint8_t* output, size_t length, size_t* written, void* context)
 * {
 *     bool res;
 *
 *     // Read exactly length bytes from the external TRNG represented by context.
 *     // Set written to the number of bytes actually produced.
 *     res = external_device_read(context, output, length, written);
 *
 *     return res;
 * }
 *
 * int32_t main(void)
 * {
 *     uint8_t random_bytes[64U] = { 0U };
 *     void* device;
 *     bool res;
 *
 *     device = external_device_open();
 *     res = qsc_etr_initialize(external_trng_generate, device);
 *
 *     if (res == true)
 *     {
 *         res = qsc_etr_generate(random_bytes, sizeof(random_bytes));
 *         qsc_etr_dispose();
 *     }
 *
 *     external_device_close(device);
 *
 *     return (res == true) ? 0 : 1;
 * }
 * \endcode
 *
 * \section etr_links Reference Links
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA-3 Standard: FIPS 202</a>
 * - <a href="https://csrc.nist.gov/pubs/sp/800/90/b/final">NIST SP 800-90B: Entropy Sources</a>
 */

/*!
 * \def QSC_ETR_SEED_MAX
 * \brief The maximum number of conditioned bytes that can be generated in a single call.
 */
#define QSC_ETR_SEED_MAX 10240000U

/**
 * \brief The external true-random source callback.
 *
 * \details The callback must attempt to fill the complete output buffer with raw entropy
 * from the external TRNG. The written parameter must always be set to the number of bytes
 * actually produced. Returning true indicates that the source operation completed without
 * a device, transport, timeout, or health-test failure; ETR separately verifies that the
 * number of bytes written exactly matches the requested length.
 *
 * The callback may use the context pointer supplied to qsc_etr_initialize to access a
 * caller-owned device handle or source state. ETR does not access, modify, or free the
 * context object directly.
 *
 * \param output: [uint8_t*] Pointer to the raw entropy output buffer.
 * \param length: [size_t] The number of raw entropy bytes requested.
 * \param written: [size_t*] Pointer receiving the number of bytes produced by the source.
 * \param context: [void*] Pointer to the caller-owned external source context.
 *
 * \return [bool] Returns true if the source operation succeeded, or false on failure.
 */
typedef bool (*qsc_etr_source_callback)(uint8_t* output, size_t length, size_t* written, void* context);

/**
 * \brief Dispose of the registered external true-random source.
 *
 * \details Clears the registered callback and context pointer. The context remains owned
 * by the caller and is not released by ETR. This function must not be called concurrently
 * with qsc_etr_generate.
 *
 * \sa qsc_etr_initialize
 */
QSC_EXPORT_API void qsc_etr_dispose(void);

/**
 * \brief Generate SHAKE-512 conditioned random bytes from the external TRNG.
 *
 * \details Collects at least one byte of raw source entropy for every output byte, with a
 * minimum raw collection of 64 bytes. Source requests are bounded to a maximum of 1024
 * bytes per callback invocation. Each returned block is checked before it is absorbed into
 * SHAKE-512. Conditioned output is produced only after all source requests and validation
 * checks have succeeded.
 *
 * Concurrent generation calls are permitted only when the registered external callback and
 * its context are thread-safe. Initialization and disposal must not occur concurrently with
 * generation.
 *
 * \param output: [uint8_t*] Pointer to the output buffer that receives the conditioned bytes.
 * \param length: [size_t] The number of conditioned bytes to generate; must not exceed QSC_ETR_SEED_MAX.
 *
 * \return [bool] Returns true on success. Returns false if ETR is not initialized, the source
 * fails, a partial read occurs, or a raw source validation check fails. On failure, a valid
 * output buffer is cleared.
 *
 * \sa qsc_etr_initialize, qsc_etr_dispose, qsc_shake512_compute
 */
QSC_EXPORT_API bool qsc_etr_generate(uint8_t* output, size_t length);

/**
 * \brief Initialize ETR with an external true-random source.
 *
 * \details Registers the callback and caller-owned context used by qsc_etr_generate. The
 * context pointer may be NULL when the callback does not require external state. A source
 * cannot be replaced while ETR is initialized; call qsc_etr_dispose before registering a
 * different source.
 *
 * This function registers the source but does not invoke it. Device initialization and
 * source-specific startup health tests must be completed by the caller or callback before
 * random output is requested.
 *
 * \param source: [qsc_etr_source_callback] The external TRNG callback.
 * \param context: [void*] Pointer to the caller-owned external source context, or NULL.
 *
 * \return [bool] Returns true if the source was registered, or false if the callback is NULL
 * or ETR is already initialized.
 *
 * \sa qsc_etr_generate, qsc_etr_dispose
 */
QSC_EXPORT_API bool qsc_etr_initialize(qsc_etr_source_callback source, void* context);

QSC_CPLUSPLUS_ENABLED_END

#endif
