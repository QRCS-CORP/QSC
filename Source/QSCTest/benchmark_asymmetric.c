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
#include "benchmark_extended.h"
#include "testutils.h"
#include "csp.h"
#include "ecdsa.h"
#include "ecdh.h"
#include "eddh.h"
#include "eddsa.h"
#include "dilithium.h"
#include "sphincsplus.h"
#include "kyber.h"
#include "hqc.h"
#include "memutils.h"
#include "timerex.h"
#include <stdio.h>

/*! \def QSCTEST_BENCHMARK_MESSAGE_SIZE
 * \brief Fixed message length used for asymmetric signature measurements in bytes.
 */
#define QSCTEST_BENCHMARK_MESSAGE_SIZE 1024U

/*! \def QSCTEST_BENCHMARK_SAMPLES
 * \brief Independent samples collected for each asymmetric operation.
 */
#define QSCTEST_BENCHMARK_SAMPLES 7U

/*! \def QSCTEST_BENCHMARK_SAMPLE_TIME_US
 * \brief Target minimum microseconds per sample, before the operation limit.
 */
#define QSCTEST_BENCHMARK_SAMPLE_TIME_US 75000U

/*! \def QSCTEST_BENCHMARK_MAX_CALLS
 * \brief Maximum operation count within one sample.
 */
#define QSCTEST_BENCHMARK_MAX_CALLS 16384U

/*! \def QSCTEST_BENCHMARK_PUBLIC_CAPACITY
 * \brief Maximum supported key/ciphertext buffer capacity in this suite.
 */
#define QSCTEST_BENCHMARK_PUBLIC_CAPACITY 16384U

/*! \def QSCTEST_BENCHMARK_PRIVATE_CAPACITY
 * \brief Maximum supported private key buffer capacity in this suite.
 */
#define QSCTEST_BENCHMARK_PRIVATE_CAPACITY 8192U

/*! \struct qsctest_benchmark_asymmetric_context
 * \brief Allocated benchmark workspace holding independently owned sensitive buffers.
 */
typedef struct
{
	uint8_t publickey[QSCTEST_BENCHMARK_PUBLIC_CAPACITY]; /*!< Active public key. */
	uint8_t privatekey[QSCTEST_BENCHMARK_PRIVATE_CAPACITY]; /*!< Active private key. */
	uint8_t peer_publickey[QSCTEST_BENCHMARK_PUBLIC_CAPACITY]; /*!< Peer public key. */
	uint8_t peer_privatekey[QSCTEST_BENCHMARK_PRIVATE_CAPACITY]; /*!< Peer private key. */
	uint8_t ciphertext[QSCTEST_BENCHMARK_PUBLIC_CAPACITY]; /*!< Encapsulated KEM ciphertext. */
	uint8_t secret[128U]; /*!< Shared secret or operation output. */
	uint8_t peer_secret[128U]; /*!< Comparison shared secret. */
	uint8_t seed[192U]; /*!< Random EdDSA key generation seed. */
	uint8_t message[QSCTEST_BENCHMARK_MESSAGE_SIZE]; /*!< Non-secret benchmark input. */
	uint8_t recovered[QSCTEST_BENCHMARK_MESSAGE_SIZE]; /*!< Recovered signed-message payload. */
	uint8_t signedmsg[QSC_SPHINCSPLUS_SIGNATURE_SIZE + QSCTEST_BENCHMARK_MESSAGE_SIZE + 64U]; /*!< Signed message output. */
	size_t signedlen; /*!< Actual signed message length in bytes. */
	size_t recoveredlen; /*!< Actual recovered message length in bytes. */
} qsctest_benchmark_asymmetric_context;

/*! \typedef qsctest_benchmark_asymmetric_op
 * \brief Callback for a single full cryptographic operation.
 * \param ctx: Caller-owned active benchmark workspace.
 * \return True when the operation completes successfully.
 * \details Callback pointers are only used within fixed, directly invoked tests.
 */
typedef bool (*qsctest_benchmark_asymmetric_op)(qsctest_benchmark_asymmetric_context* ctx);

/*! \var qsctest_benchmark_passed
 * \brief Number of benchmark operation measurements completed successfully.
 */
static size_t qsctest_benchmark_passed;

/*! \var qsctest_benchmark_failed
 * \brief Number of benchmark operation measurements that failed.
 */
static size_t qsctest_benchmark_failed;

/*! \var qsctest_benchmark_skipped
 * \brief Number of measurement groups not run after setup or correctness failure.
 */
static size_t qsctest_benchmark_skipped;

/*! \brief Allocate and initialize a workspace outside the timed interval.
 * \return Owned workspace or NULL on allocation failure.
 * \details The caller must release the workspace using qsctest_asym_free.
 */
static qsctest_benchmark_asymmetric_context* qsctest_asym_allocate(void)
{
	qsctest_benchmark_asymmetric_context* ctx;
	size_t i;

	ctx = (qsctest_benchmark_asymmetric_context*)qsc_memutils_malloc(sizeof(qsctest_benchmark_asymmetric_context));

	if (ctx != NULL)
	{
		qsc_memutils_clear(ctx, sizeof(*ctx));
		for (i = 0U; i < QSCTEST_BENCHMARK_MESSAGE_SIZE; ++i)
		{
			ctx->message[i] = (uint8_t)(i & 0xFFU);
		}
	}

	return ctx;
}

/*! \brief Erase all key material and release a benchmark workspace.
 * \param ctx: Caller-owned workspace or NULL.
 */
static void qsctest_asym_free(qsctest_benchmark_asymmetric_context* ctx)
{
	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx, sizeof(*ctx));
		qsc_memutils_alloc_free(ctx);
	}
}

/*! \brief Verify the recovered message from a completed signature verification.
 * \param ctx: Workspace containing message and recovered output.
 * \return True when both length and public-data bytes match.
 */
static bool qsctest_asym_recovered_valid(qsctest_benchmark_asymmetric_context* ctx)
{
	bool result;

	result = ctx->recoveredlen == QSCTEST_BENCHMARK_MESSAGE_SIZE;
	if (result == true)
	{
		result = qsc_memutils_are_equal(ctx->recovered, ctx->message, sizeof(ctx->message));
	}

	return result;
}

/*! \brief Display one compile-selected parameter set in the Option C console layout.
 * \param name: Non-NULL parameter-set name; not retained by this function.
 * \details Prints the parameter heading without an intervening blank line; benchmark state is unchanged.
 */
static void qsctest_asym_parameter_heading(const char* name)
{
	char line[128U] = { 0U };

	(void)snprintf(line, sizeof(line), "  %s", name);
	qsctest_print_line(line);
	qsctest_print_line("  --------------------------------------------------------");
}

/*! \brief Collect seven adaptive samples and print median latency and operation rate.
 * \param name: Unique algorithm and operation name for PASS/FAIL output.
 * \param operation: Operation under test; called sequentially, not as a dispatch registry.
 * \param ctx: Initialized workspace with valid inputs for the requested operation.
 * \return True when all calls complete and elapsed time is measurable.
 * \details Input setup is excluded; key generation and signing RNG costs are included.
 */
static bool qsctest_asym_measure(const char* name, qsctest_benchmark_asymmetric_op operation, qsctest_benchmark_asymmetric_context* ctx)
{
	double latencies[QSCTEST_BENCHMARK_SAMPLES];
	char line[192U];
	uint64_t start;
	uint64_t elapsed;
	size_t iteration;
	size_t sample;
	size_t calls;
	size_t batch;
	size_t i;
	size_t j;
	double value;
	double median;
	double low;
	double high;
	bool result;

	result = operation(ctx);

	for (sample = 0U; sample < QSCTEST_BENCHMARK_SAMPLES && result == true; ++sample)
	{
		calls = 0U;
		batch = 1U;
		elapsed = 0U;
		start = qsc_timerex_stopwatch_start();

		while (result == true && elapsed < QSCTEST_BENCHMARK_SAMPLE_TIME_US && calls < QSCTEST_BENCHMARK_MAX_CALLS)
		{
			if (batch > QSCTEST_BENCHMARK_MAX_CALLS - calls)
			{
				batch = QSCTEST_BENCHMARK_MAX_CALLS - calls;
			}

			for (iteration = 0U; iteration < batch && result == true; ++iteration)
			{
				result = operation(ctx);
				++calls;
			}

			elapsed = qsc_timerex_stopwatch_elapsed_microseconds(start);
			if (batch <= QSCTEST_BENCHMARK_MAX_CALLS / 2U)
			{
				batch *= 2U;
			}
		}

		if (elapsed == 0U || calls == 0U)
		{
			result = false;
		}
		else
		{
			latencies[sample] = (double)elapsed / (double)calls;
		}
	}

	if (result == true)
	{
		/* Fixed-size insertion sort; never dispatches benchmark tests. */
		for (i = 1U; i < QSCTEST_BENCHMARK_SAMPLES; ++i)
		{
			value = latencies[i];
			j = i;
			while (j > 0U && latencies[j - 1U] > value)
			{
				latencies[j] = latencies[j - 1U];
				--j;
			}
			latencies[j] = value;
		}

		low = latencies[0U];
		high = latencies[QSCTEST_BENCHMARK_SAMPLES - 1U];
		median = latencies[QSCTEST_BENCHMARK_SAMPLES / 2U];
		(void)snprintf(line, sizeof(line), "    [PASS] %-24s %10.2f us    %10.0f ops/s    range %.2f-%.2f us", name, median, 1000000.0 / median, low, high);
		qsctest_print_line(line);
		++qsctest_benchmark_passed;
	}
	else
	{
		(void)snprintf(line, sizeof(line), "    [FAIL] %s: operation, RNG, or monotonic timing failure", name);
		qsctest_print_line(line);
		++qsctest_benchmark_failed;
	}

	return result;
}

/*! \brief Report a failed setup/correctness precondition and skipped measurements.
 * \param name: Unique benchmark family name.
 * \param reason: Description of setup or correctness failure.
 */
static void qsctest_asym_preflight_fail(const char* name, const char* reason)
{
	char line[192U];

	(void)snprintf(line, sizeof(line), "    [FAIL] %s: %s", name, reason);
	qsctest_print_line(line);
	++qsctest_benchmark_failed;
	++qsctest_benchmark_skipped;
}

/*! \brief ECDSA key generation including RNG costs.
 * \param ctx: Workspace for the selected QSC curve.
 * \return True on successful key generation.
 */
static bool qsctest_asym_ecdsa_keygen(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_ecdsa_generate_keypair(ctx->publickey, ctx->privatekey, qsc_csp_generate);
}

/*! \brief ECDSA signed-message production.
 * \param ctx: Workspace with a valid ECDSA private key.
 * \return True on successful signing.
 */
static bool qsctest_asym_ecdsa_sign(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_ecdsa_sign(ctx->signedmsg, &ctx->signedlen, ctx->message, sizeof(ctx->message), ctx->privatekey);
}

/*! \brief ECDSA signature verification excluding unrelated input generation.
 * \param ctx: Workspace with a valid public key and signed message.
 * \return True when signature verification succeeds.
 */
static bool qsctest_asym_ecdsa_verify(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_ecdsa_verify(ctx->recovered, &ctx->recoveredlen, ctx->signedmsg, ctx->signedlen, ctx->publickey);
}

/*! \brief Run the three ECDSA benchmarks using the compiled QSC curve.
 * \details Named operations are each called explicitly and sequentially.
 */
void qsctest_benchmark_ecdsa_run(void)
{
	qsctest_benchmark_asymmetric_context* ctx;
	bool valid;
	const char* reason = "workspace allocation failed";
	const char* name;

#if defined(QSC_ECDSA_S5P521)
	name = "ECDSA P-521";
#elif defined(QSC_ECDSA_S3P384)
	name = "ECDSA P-384";
#else
	name = "ECDSA P-256";
#endif
	qsctest_asym_parameter_heading(name);
	ctx = qsctest_asym_allocate();
	if (ctx == NULL)
	{
		qsctest_asym_preflight_fail(name, reason);
	}
	else
	{
		reason = "key-generation or RNG failure";
		valid = qsctest_asym_ecdsa_keygen(ctx);
		if (valid == true)
		{
			reason = "signing failure";
			valid = qsctest_asym_ecdsa_sign(ctx);
		}
		if (valid == true)
		{
			reason = "signature verification or recovered message mismatch";
			valid = qsctest_asym_ecdsa_verify(ctx) && qsctest_asym_recovered_valid(ctx);
		}
		if (valid == true)
		{
			(void)qsctest_asym_measure("ECDSA KeyGen", qsctest_asym_ecdsa_keygen, ctx);
			(void)qsctest_asym_measure("ECDSA Sign", qsctest_asym_ecdsa_sign, ctx);
			(void)qsctest_asym_measure("ECDSA Verify", qsctest_asym_ecdsa_verify, ctx);
		}
		else
		{
			qsctest_asym_preflight_fail(name, reason);
		}
		qsctest_asym_free(ctx);
	}
}

/*! \brief ECDH key generation on the QSC compile-selected NIST curve.
 * \param ctx: Workspace receiving one keypair.
 * \return True on successful generation.
 */
static bool qsctest_asym_ecdh_keygen(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_ecdh_generate_keypair(ctx->publickey, ctx->privatekey, qsc_csp_generate);
}

/*! \brief ECDH shared-secret derivation with a fixed independent peer key.
 * \param ctx: Workspace containing local private and peer public keys.
 * \return True when key agreement succeeds.
 */
static bool qsctest_asym_ecdh_exchange(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_ecdh_key_exchange(ctx->secret, ctx->privatekey, ctx->peer_publickey);
}

/*! \brief Benchmark selected ECDH key generation and key exchange. */
void qsctest_benchmark_ecdh_run(void)
{
	qsctest_benchmark_asymmetric_context* ctx;
	bool valid;
	const char* reason = "workspace allocation failed";

#if defined(QSC_ECDH_S5P521)
	qsctest_asym_parameter_heading("ECDH P-521");
#elif defined(QSC_ECDH_S3P384)
	qsctest_asym_parameter_heading("ECDH P-384");
#else
	qsctest_asym_parameter_heading("ECDH P-256");
#endif
	ctx = qsctest_asym_allocate();
	if (ctx == NULL)
	{
		qsctest_asym_preflight_fail("ECDH", reason);
	}
	else
	{
		reason = "local key-generation or RNG failure";
		valid = qsctest_asym_ecdh_keygen(ctx);
		if (valid == true)
		{
			reason = "peer key-generation or RNG failure";
			valid = qsc_ecdh_generate_keypair(ctx->peer_publickey, ctx->peer_privatekey, qsc_csp_generate);
		}
		if (valid == true)
		{
			reason = "local key agreement failure";
			valid = qsctest_asym_ecdh_exchange(ctx);
		}
		if (valid == true)
		{
			reason = "peer key agreement failure";
			valid = qsc_ecdh_key_exchange(ctx->peer_secret, ctx->peer_privatekey, ctx->publickey);
		}
		if (valid == true)
		{
			reason = "independent shared-secret mismatch";
			valid = qsc_memutils_are_equal(ctx->secret, ctx->peer_secret, QSC_ECDH_SHAREDSECRET_SIZE);
		}
		if (valid == true)
		{
			(void)qsctest_asym_measure("ECDH KeyGen", qsctest_asym_ecdh_keygen, ctx);
			(void)qsctest_asym_measure("ECDH Agreement", qsctest_asym_ecdh_exchange, ctx);
		}
		else
		{
			qsctest_asym_preflight_fail("ECDH", reason);
		}
		qsctest_asym_free(ctx);
	}
}

/*! \brief EdDH key generation using the selected Edwards/Montgomery curve.
 * \param ctx: Workspace receiving the local keypair.
 * \return True on successful generation.
 */
static bool qsctest_asym_eddh_keygen(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_eddh_generate_keypair(ctx->publickey, ctx->privatekey, qsc_csp_generate);
}

/*! \brief EdDH shared-secret derivation with an independently generated peer.
 * \param ctx: Workspace with valid local and peer keys.
 * \return True when key agreement succeeds.
 */
static bool qsctest_asym_eddh_exchange(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_eddh_key_exchange(ctx->secret, ctx->privatekey, ctx->peer_publickey);
}

/*! \brief Benchmark X25519 or X448 key generation and shared secret derivation. */
void qsctest_benchmark_eddh_run(void)
{
	qsctest_benchmark_asymmetric_context* ctx;
	bool valid;
	const char* reason = "workspace allocation failed";

#if defined(QSC_EDDH_S3EC448)
	qsctest_asym_parameter_heading("EdDH X448");
#else
	qsctest_asym_parameter_heading("EdDH X25519");
#endif
	ctx = qsctest_asym_allocate();
	if (ctx == NULL)
	{
		qsctest_asym_preflight_fail("EdDH", reason);
	}
	else
	{
		reason = "local key-generation or RNG failure";
		valid = qsctest_asym_eddh_keygen(ctx);
		if (valid == true)
		{
			reason = "peer key-generation or RNG failure";
			valid = qsc_eddh_generate_keypair(ctx->peer_publickey, ctx->peer_privatekey, qsc_csp_generate);
		}
		if (valid == true)
		{
			reason = "local key agreement failure";
			valid = qsctest_asym_eddh_exchange(ctx);
		}
		if (valid == true)
		{
			reason = "peer key agreement failure";
			valid = qsc_eddh_key_exchange(ctx->peer_secret, ctx->peer_privatekey, ctx->publickey);
		}
		if (valid == true)
		{
			reason = "independent shared-secret mismatch";
			valid = qsc_memutils_are_equal(ctx->secret, ctx->peer_secret, QSC_EDDH_SHAREDSECRET_SIZE);
		}
		if (valid == true)
		{
			(void)qsctest_asym_measure("EdDH KeyGen", qsctest_asym_eddh_keygen, ctx);
			(void)qsctest_asym_measure("EdDH Agreement", qsctest_asym_eddh_exchange, ctx);
		}
		else
		{
			qsctest_asym_preflight_fail("EdDH", reason);
		}
		qsctest_asym_free(ctx);
	}
}

/*! \brief EdDSA seeded keypair generation with fresh RNG seed per operation.
 * \param ctx: Workspace receiving keys.
 * \return True when the seed RNG succeeds.
 */
static bool qsctest_asym_eddsa_keygen(qsctest_benchmark_asymmetric_context* ctx)
{
	bool result;

	result = qsc_csp_generate(ctx->seed, QSC_EDDSA_SEED_SIZE);
	if (result == true)
	{
		qsc_eddsa_generate_seeded_keypair(ctx->publickey, ctx->privatekey, ctx->seed);
	}
	return result;
}

/*! \brief EdDSA signed-message operation.
 * \param ctx: Workspace with valid signing key.
 * \return True after the QSC EdDSA signing operation completes.
 */
static bool qsctest_asym_eddsa_sign(qsctest_benchmark_asymmetric_context* ctx)
{
	ctx->signedlen = 0U;
	qsc_eddsa_sign(ctx->signedmsg, &ctx->signedlen, ctx->message, sizeof(ctx->message), ctx->privatekey);
	return ctx->signedlen == QSC_EDDSA_SIGNATURE_SIZE + QSCTEST_BENCHMARK_MESSAGE_SIZE;
}

/*! \brief EdDSA verification operation.
 * \param ctx: Workspace with valid signed message and public key.
 * \return True when verification succeeds.
 */
static bool qsctest_asym_eddsa_verify(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_eddsa_verify(ctx->recovered, &ctx->recoveredlen, ctx->signedmsg, ctx->signedlen, ctx->publickey);
}

/*! \brief Benchmark Ed25519 or Ed448 signing operations. */
void qsctest_benchmark_eddsa_run(void)
{
	qsctest_benchmark_asymmetric_context* ctx;
	bool valid;
	const char* reason = "workspace allocation failed";

#if defined(QSC_EDDSA_S3EC448)
	qsctest_asym_parameter_heading("EdDSA Ed448");
#else
	qsctest_asym_parameter_heading("EdDSA Ed25519");
#endif
	ctx = qsctest_asym_allocate();
	if (ctx == NULL)
	{
		qsctest_asym_preflight_fail("EdDSA", reason);
	}
	else
	{
		reason = "seed-generation or RNG failure";
		valid = qsctest_asym_eddsa_keygen(ctx);
		if (valid == true)
		{
			reason = "signed-message generation failure";
			valid = qsctest_asym_eddsa_sign(ctx);
		}
		if (valid == true)
		{
			reason = "signature verification or recovered message mismatch";
			valid = qsctest_asym_eddsa_verify(ctx) && qsctest_asym_recovered_valid(ctx);
		}
		if (valid == true)
		{
			(void)qsctest_asym_measure("EdDSA KeyGen", qsctest_asym_eddsa_keygen, ctx);
			(void)qsctest_asym_measure("EdDSA Sign", qsctest_asym_eddsa_sign, ctx);
			(void)qsctest_asym_measure("EdDSA Verify", qsctest_asym_eddsa_verify, ctx);
		}
		else
		{
			qsctest_asym_preflight_fail("EdDSA", reason);
		}
		qsctest_asym_free(ctx);
	}
}

/*! \brief ML-DSA key generation with QSC CSP.
 * \param ctx: Workspace receiving keys.
 * \return True on successful key generation.
 */
static bool qsctest_asym_mldsa_keygen(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_dilithium_generate_keypair(ctx->publickey, ctx->privatekey, qsc_csp_generate);
}

/*! \brief ML-DSA signing including algorithm-selected RNG requirements.
 * \param ctx: Workspace with valid private key.
 * \return True when a valid signed-message length is produced.
 */
static bool qsctest_asym_mldsa_sign(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_dilithium_sign(ctx->signedmsg, &ctx->signedlen, ctx->message, sizeof(ctx->message), ctx->privatekey, qsc_csp_generate);
}

/*! \brief ML-DSA verification.
 * \param ctx: Workspace with valid signed message and public key.
 * \return True when signature verification succeeds.
 */
static bool qsctest_asym_mldsa_verify(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_dilithium_verify(ctx->recovered, &ctx->recoveredlen, ctx->signedmsg, ctx->signedlen, ctx->publickey);
}

/*! \brief Benchmark selected ML-DSA parameter set key generation, sign and verify. */
void qsctest_benchmark_mldsa_run(void)
{
	qsctest_benchmark_asymmetric_context* ctx;
	bool valid;
	const char* reason = "workspace allocation failed";

#if defined(QSC_DILITHIUM_S5P87)
	qsctest_asym_parameter_heading("ML-DSA-87");
#elif defined(QSC_DILITHIUM_S3P65)
	qsctest_asym_parameter_heading("ML-DSA-65");
#else
	qsctest_asym_parameter_heading("ML-DSA-44");
#endif
	ctx = qsctest_asym_allocate();
	if (ctx == NULL)
	{
		qsctest_asym_preflight_fail("ML-DSA", reason);
	}
	else
	{
		reason = "key-generation or RNG failure";
		valid = qsctest_asym_mldsa_keygen(ctx);
		if (valid == true)
		{
			reason = "signing failure";
			valid = qsctest_asym_mldsa_sign(ctx);
		}
		if (valid == true)
		{
			reason = "signature verification or recovered message mismatch";
			valid = qsctest_asym_mldsa_verify(ctx) && qsctest_asym_recovered_valid(ctx);
		}
		if (valid == true)
		{
			(void)qsctest_asym_measure("ML-DSA KeyGen", qsctest_asym_mldsa_keygen, ctx);
			(void)qsctest_asym_measure("ML-DSA Sign", qsctest_asym_mldsa_sign, ctx);
			(void)qsctest_asym_measure("ML-DSA Verify", qsctest_asym_mldsa_verify, ctx);
		}
		else
		{
			qsctest_asym_preflight_fail("ML-DSA", reason);
		}
		qsctest_asym_free(ctx);
	}
}

/*! \brief SLH-DSA key generation using the selected variant.
 * \param ctx: Workspace receiving keys.
 * \return True on successful generation.
 */
static bool qsctest_asym_slhdsa_keygen(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_sphincsplus_generate_keypair(ctx->publickey, ctx->privatekey, qsc_csp_generate);
}

/*! \brief SLH-DSA signing using selected variant and supported RNG provider.
 * \param ctx: Workspace with signing key.
 * \return True when signing succeeds.
 */
static bool qsctest_asym_slhdsa_sign(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_sphincsplus_sign(ctx->signedmsg, &ctx->signedlen, ctx->message, sizeof(ctx->message), ctx->privatekey, qsc_csp_generate);
}

/*! \brief SLH-DSA verification.
 * \param ctx: Workspace with signed message and public key.
 * \return True when verification succeeds.
 */
static bool qsctest_asym_slhdsa_verify(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_sphincsplus_verify(ctx->recovered, &ctx->recoveredlen, ctx->signedmsg, ctx->signedlen, ctx->publickey);
}

/*! \brief Benchmark compiled SLH-DSA key generation, sign, and verify. */
void qsctest_benchmark_slhdsa_run(void)
{
	qsctest_benchmark_asymmetric_context* ctx;
	bool valid;
	const char* reason = "workspace allocation failed";

	qsctest_asym_parameter_heading(QSC_SPHINCSPLUS_ALGNAME);
	ctx = qsctest_asym_allocate();
	if (ctx == NULL)
	{
		qsctest_asym_preflight_fail("SLH-DSA", reason);
	}
	else
	{
		reason = "key-generation or RNG failure";
		valid = qsctest_asym_slhdsa_keygen(ctx);
		if (valid == true)
		{
			reason = "signing failure";
			valid = qsctest_asym_slhdsa_sign(ctx);
		}
		if (valid == true)
		{
			reason = "signature verification or recovered message mismatch";
			valid = qsctest_asym_slhdsa_verify(ctx) && qsctest_asym_recovered_valid(ctx);
		}
		if (valid == true)
		{
			(void)qsctest_asym_measure("SLH-DSA KeyGen", qsctest_asym_slhdsa_keygen, ctx);
			(void)qsctest_asym_measure("SLH-DSA Sign", qsctest_asym_slhdsa_sign, ctx);
			(void)qsctest_asym_measure("SLH-DSA Verify", qsctest_asym_slhdsa_verify, ctx);
		}
		else
		{
			qsctest_asym_preflight_fail("SLH-DSA", reason);
		}
		qsctest_asym_free(ctx);
	}
}

/*! \brief ML-KEM key generation.
 * \param ctx: Workspace receiving encapsulation/decapsulation keys.
 * \return True on success.
 */
static bool qsctest_asym_mlkem_keygen(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_kyber_generate_keypair(ctx->publickey, ctx->privatekey, qsc_csp_generate);
}

/*! \brief ML-KEM encapsulation.
 * \param ctx: Workspace with encapsulation public key.
 * \return True on success.
 */
static bool qsctest_asym_mlkem_encapsulate(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_kyber_encapsulate(ctx->secret, ctx->ciphertext, ctx->publickey, qsc_csp_generate);
}

/*! \brief ML-KEM decapsulation.
 * \param ctx: Workspace with valid ciphertext and decapsulation key.
 * \return True on successful decapsulation.
 */
static bool qsctest_asym_mlkem_decapsulate(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_kyber_decapsulate(ctx->peer_secret, ctx->ciphertext, ctx->privatekey);
}

/*! \brief Benchmark selected ML-KEM key generation, encapsulation, and decapsulation. */
void qsctest_benchmark_mlkem_run(void)
{
	qsctest_benchmark_asymmetric_context* ctx;
	bool valid;
	const char* reason = "workspace allocation failed";

#if defined(QSC_KYBER_S6K5P1280)
	qsctest_asym_parameter_heading("Kyber-1280 (non-FIPS parameter set)");
#elif defined(QSC_KYBER_S5K4P1024)
	qsctest_asym_parameter_heading("ML-KEM-1024");
#elif defined(QSC_KYBER_S3K3P768)
	qsctest_asym_parameter_heading("ML-KEM-768");
#else
	qsctest_asym_parameter_heading("ML-KEM-512");
#endif
	ctx = qsctest_asym_allocate();
	if (ctx == NULL)
	{
		qsctest_asym_preflight_fail("ML-KEM", reason);
	}
	else
	{
		reason = "key-generation or RNG failure";
		valid = qsctest_asym_mlkem_keygen(ctx);
		if (valid == true)
		{
			reason = "encapsulation or RNG failure";
			valid = qsctest_asym_mlkem_encapsulate(ctx);
		}
		if (valid == true)
		{
			reason = "decapsulation failure";
			valid = qsctest_asym_mlkem_decapsulate(ctx);
		}
		if (valid == true)
		{
			reason = "decapsulated shared-secret mismatch";
			valid = qsc_memutils_are_equal(ctx->secret, ctx->peer_secret, QSC_KYBER_SHAREDSECRET_SIZE);
		}
		if (valid == true)
		{
			(void)qsctest_asym_measure("ML-KEM KeyGen", qsctest_asym_mlkem_keygen, ctx);
			(void)qsctest_asym_measure("ML-KEM Encapsulate", qsctest_asym_mlkem_encapsulate, ctx);
			(void)qsctest_asym_measure("ML-KEM Decapsulate", qsctest_asym_mlkem_decapsulate, ctx);
		}
		else
		{
			qsctest_asym_preflight_fail("ML-KEM", reason);
		}
		qsctest_asym_free(ctx);
	}
}

/*! \brief HQC key generation.
 * \param ctx: Workspace receiving KEM keys.
 * \return True on success.
 */
static bool qsctest_asym_hqc_keygen(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_hqc_generate_keypair(ctx->publickey, ctx->privatekey, qsc_csp_generate);
}

/*! \brief HQC encapsulation with valid encapsulation key.
 * \param ctx: Workspace receiving shared secret and ciphertext.
 * \return True on success.
 */
static bool qsctest_asym_hqc_encapsulate(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_hqc_encapsulate(ctx->secret, ctx->ciphertext, ctx->publickey, qsc_csp_generate);
}

/*! \brief HQC decapsulation with valid encapsulated ciphertext.
 * \param ctx: Workspace receiving the decapsulated shared secret.
 * \return True on success.
 */
static bool qsctest_asym_hqc_decapsulate(qsctest_benchmark_asymmetric_context* ctx)
{
	return qsc_hqc_decapsulate(ctx->peer_secret, ctx->ciphertext, ctx->privatekey);
}

/*! \brief Benchmark selected HQC key generation, encapsulation and decapsulation. */
void qsctest_benchmark_hqc_run(void)
{
	qsctest_benchmark_asymmetric_context* ctx;
	bool valid;
	const char* reason = "workspace allocation failed";

#if defined(QSC_HQC_S5N7333)
	qsctest_asym_parameter_heading("HQC-256");
#elif defined(QSC_HQC_S3N4602)
	qsctest_asym_parameter_heading("HQC-192");
#else
	qsctest_asym_parameter_heading("HQC-128");
#endif
	ctx = qsctest_asym_allocate();
	if (ctx == NULL)
	{
		qsctest_asym_preflight_fail("HQC", reason);
	}
	else
	{
		reason = "key-generation or RNG failure";
		valid = qsctest_asym_hqc_keygen(ctx);
		if (valid == true)
		{
			reason = "encapsulation or RNG failure";
			valid = qsctest_asym_hqc_encapsulate(ctx);
		}
		if (valid == true)
		{
			reason = "decapsulation failure";
			valid = qsctest_asym_hqc_decapsulate(ctx);
		}
		if (valid == true)
		{
			reason = "decapsulated shared-secret mismatch";
			valid = qsc_memutils_are_equal(ctx->secret, ctx->peer_secret, QSC_HQC_SHAREDSECRET_SIZE);
		}
		if (valid == true)
		{
			(void)qsctest_asym_measure("HQC KeyGen", qsctest_asym_hqc_keygen, ctx);
			(void)qsctest_asym_measure("HQC Encapsulate", qsctest_asym_hqc_encapsulate, ctx);
			(void)qsctest_asym_measure("HQC Decapsulate", qsctest_asym_hqc_decapsulate, ctx);
		}
		else
		{
			qsctest_asym_preflight_fail("HQC", reason);
		}
		qsctest_asym_free(ctx);
	}
}

/*! \brief Print completed/failed/skipped operation measurements.
 * \return True if all scheduled asymmetric measurements and preflight checks succeeded.
 * \details Counts exclude the existing symmetric benchmark functions.
 */
bool qsctest_benchmark_extended_summary_run(void)
{
	char line[128U];

	qsctest_print_line("  Extended asymmetric benchmark summary");
	(void)snprintf(line, sizeof(line), "  Completed: %zu  Failed: %zu  Skipped groups: %zu", qsctest_benchmark_passed, qsctest_benchmark_failed, qsctest_benchmark_skipped);
	qsctest_print_line(line);
	qsctest_print_line("  Statistic: median of 7 independent samples, microseconds per operation.");
	qsctest_print_line("  Scope: selected compile-time algorithm variants; one thread.");
	qsctest_print_line("");

	return qsctest_benchmark_failed == 0U && qsctest_benchmark_passed > 0U;
}
