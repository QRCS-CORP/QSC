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

#include "ed25519.h"
#include "ed448.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * \brief Validate an encoded Ed25519 or Ed448 public point through QSC's own field implementation.
 * \param key Borrowed public-key encoding; 32 bytes for Ed25519 or 57 bytes for Ed448.
 * \param length Input buffer size in bytes.
 * \return True only for a canonical, non-small-order, decodable curve point.
 * \details No key is retained and no heap allocation is performed. Calls on independent buffers are thread-safe.
 *          This is a qualification adapter, not a replacement public cryptographic API.
 */
bool qsc_acvp_eddsa_publickey_valid(const uint8_t* key, size_t length)
{
	bool result;

	result = false;

	if (key != NULL)
	{
		if (length == 32U)
		{
			qsc_ge25519_p3 point;

			if (qsc_ge25519_is_canonical(key) != 0 && qsc_ge25519_has_small_order(key) == 0 &&
				qsc_ge25519_from_bytes_negate_vartime(&point, key) == 0)
			{
				result = true;
			}
		}
		else if (length == 57U)
		{
			qsc_ge448_p3 point;

			if (qsc_ge448_is_canonical(key) != 0 && qsc_ge448_has_small_order(key) == 0 &&
				qsc_ge448_from_bytes_negate_vartime(&point, key) == 0)
			{
				result = true;
			}
		}
	}

	return result;
}
