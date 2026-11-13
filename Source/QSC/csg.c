#include "csg.h"
#include "acp.h"
#include "memutils.h"
#include "sha3.h"

/* \cond DOXYGEN_NO_DOCUMENT */

static bool csg_xof_operation(const uint8_t* first, size_t firstlen, const uint8_t* additional, size_t addlen, uint8_t operation, uint8_t* output, size_t outlen)
{
	/* perform one SHAKE-256 operation using the XDRBG Appendix B encoding */
	uint8_t input[(2U * QSC_CSG_STATE_SIZE) + QSC_CSG_MAX_ADDITIONAL_SIZE + 1U] = { 0U };
	bool res;

	res = false;

	if (first != NULL && firstlen != 0U && firstlen <= (2U * QSC_CSG_STATE_SIZE) &&
		(additional != NULL || addlen == 0U) && addlen <= QSC_CSG_MAX_ADDITIONAL_SIZE &&
		operation <= 2U && output != NULL && outlen != 0U &&
		outlen <= QSC_CSG_STATE_SIZE + QSC_CSG_MAX_REQUEST_SIZE)
	{
		qsc_memutils_copy(input, first, firstlen);

		if (addlen != 0U)
		{
			qsc_memutils_copy(input + firstlen, additional, addlen);
		}

		input[firstlen + addlen] = (uint8_t)((85U * (uint32_t)operation) + (uint32_t)addlen);
		qsc_shake256_compute(output, outlen, input, firstlen + addlen + 1U);
		res = true;
	}

	qsc_memutils_secure_erase(input, sizeof(input));

	return res;
}

static bool csg_auto_reseed(qsc_csg_state* ctx)
{
	/* perform an ACP-backed reseed without retaining acquired seed bytes */
	uint8_t entropy[QSC_CSG_MIN_RESEED_SIZE] = { 0U };
	bool res;

	res = false;

	if (ctx != NULL && ctx->initialized == true)
	{
		if (qsc_acp_generate(entropy, sizeof(entropy)) == true)
		{
			res = qsc_csg_reseed(ctx, entropy, sizeof(entropy), NULL, 0U);
		}
	}

	qsc_memutils_secure_erase(entropy, sizeof(entropy));

	return res;
}

void qsc_csg_dispose(qsc_csg_state* ctx)
{
	if (ctx != NULL)
	{
		qsc_memutils_secure_erase(ctx, sizeof(qsc_csg_state));
	}
}

bool qsc_csg_instantiate(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen)
{
	uint8_t value[QSC_CSG_STATE_SIZE] = { 0U };
	bool res;

	res = false;

	if (ctx != NULL)
	{
		/* a caller must not pass seed or personalization pointing into the state */
		if (seed != NULL && seedlen >= QSC_CSG_MIN_INSTANTIATE_SIZE &&
			seedlen <= QSC_CSG_MAX_SEED_SIZE && (info != NULL || infolen == 0U) &&
			infolen <= QSC_CSG_MAX_ADDITIONAL_SIZE)
		{
			res = csg_xof_operation(seed, seedlen, info, infolen, 0U, value, sizeof(value));
		}

		qsc_csg_dispose(ctx);

		if (res == true)
		{
			qsc_memutils_copy(ctx->value, value, sizeof(value));
			ctx->reseed_counter = 1U;
			ctx->initialized = true;
		}
	}

	qsc_memutils_secure_erase(value, sizeof(value));

	return res;
}

bool qsc_csg_initialize_auto(qsc_csg_state* ctx, const uint8_t* info, size_t infolen, bool predres)
{
	uint8_t entropy[QSC_CSG_MAX_SEED_SIZE] = { 0U };
	bool res;

	res = false;

	if (ctx != NULL)
	{
		qsc_csg_dispose(ctx);

		if ((info != NULL || infolen == 0U) && infolen <= QSC_CSG_MAX_ADDITIONAL_SIZE)
		{
			if (qsc_acp_generate(entropy, sizeof(entropy)) == true)
			{
				res = qsc_csg_instantiate(ctx, entropy, sizeof(entropy), info, infolen);

				if (res == true)
				{
					ctx->auto_reseed = true;
					ctx->pres = predres;
				}
			}
		}
	}

	qsc_memutils_secure_erase(entropy, sizeof(entropy));

	return res;
}

void qsc_csg_initialize(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predres)
{
	uint8_t value[QSC_CSG_STATE_SIZE] = { 0U };
	bool res;

	res = false;

	if (seedlen == QSC_CSG_256_SEED_SIZE && ctx != NULL && seed != NULL && (info != NULL || infolen == 0U) && infolen <= QSC_CSG_MAX_ADDITIONAL_SIZE)
	{
		res = csg_xof_operation(seed, seedlen, info, infolen, 0U, value, sizeof(value));
		qsc_csg_dispose(ctx);

		if (res == true)
		{
			qsc_memutils_copy(ctx->value, value, sizeof(value));
			ctx->initialized = true;
			ctx->reseed_counter = 1U;
			ctx->legacy_seed = true;
		}
	}
	else
	{
		res = qsc_csg_instantiate(ctx, seed, seedlen, info, infolen);
	}

	if (res == true && ctx != NULL)
	{
		ctx->pres = predres;
		ctx->auto_reseed = predres;
	}

	qsc_memutils_secure_erase(value, sizeof(value));
}

bool qsc_csg_reseed(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* additional, size_t addlen)
{
	uint8_t input[QSC_CSG_STATE_SIZE + QSC_CSG_MAX_SEED_SIZE] = { 0U };
	uint8_t newvalue[QSC_CSG_STATE_SIZE] = { 0U };
	bool res;

	res = false;

	if (ctx != NULL && ctx->initialized == true && seed != NULL &&
		seedlen >= QSC_CSG_MIN_RESEED_SIZE && seedlen <= QSC_CSG_MAX_SEED_SIZE &&
		(additional != NULL || addlen == 0U) && addlen <= QSC_CSG_MAX_ADDITIONAL_SIZE)
	{
		qsc_memutils_copy(input, ctx->value, QSC_CSG_STATE_SIZE);
		qsc_memutils_copy(input + QSC_CSG_STATE_SIZE, seed, seedlen);
		res = csg_xof_operation(input, QSC_CSG_STATE_SIZE + seedlen, additional, addlen, 1U, newvalue, sizeof(newvalue));

		if (res == true)
		{
			qsc_memutils_copy(ctx->value, newvalue, sizeof(newvalue));
			ctx->reseed_counter = 1U;
			ctx->generated_bytes = 0U;
			ctx->legacy_seed = false;
		}
	}

	qsc_memutils_secure_erase(newvalue, sizeof(newvalue));
	qsc_memutils_secure_erase(input, sizeof(input));

	return res;
}

bool qsc_csg_generate_ex(qsc_csg_state* ctx, uint8_t* output, size_t otplen, const uint8_t* additional, size_t addlen)
{
	uint8_t stream[QSC_CSG_STATE_SIZE + QSC_CSG_MAX_REQUEST_SIZE] = { 0U };
	bool res;

	res = false;

	if (ctx != NULL && ctx->initialized == true && output != NULL &&
		otplen != 0U && otplen <= QSC_CSG_MAX_REQUEST_SIZE &&
		(additional != NULL || addlen == 0U) && addlen <= QSC_CSG_MAX_ADDITIONAL_SIZE)
	{
		if (ctx->pres == true ||
			(ctx->auto_reseed == true && ctx->generated_bytes >= QSC_CSG_RESEED_THRESHOLD) ||
			ctx->reseed_counter > QSC_CSG_RESEED_INTERVAL)
		{
			if (ctx->auto_reseed == false)
			{
				/* a deterministic caller can recover by providing fresh entropy. */
				qsc_memutils_clear(output, otplen);
			}
			else if (csg_auto_reseed(ctx) == true)
			{
				res = true;
			}
			else
			{
				/* an operational entropy-source failure invalidates auto mode. */
				qsc_memutils_clear(output, otplen);
				qsc_csg_dispose(ctx);
			}
		}
		else
		{
			res = true;
		}

		if (res == true)
		{
			res = csg_xof_operation(ctx->value, sizeof(ctx->value), additional, addlen, 2U, stream, QSC_CSG_STATE_SIZE + otplen);

			if (res == true)
			{
				qsc_memutils_copy(ctx->value, stream, QSC_CSG_STATE_SIZE);
				qsc_memutils_copy(output, stream + QSC_CSG_STATE_SIZE, otplen);
				ctx->reseed_counter += 1U;
				ctx->generated_bytes += (uint64_t)otplen;
			}
			else
			{
				qsc_memutils_clear(output, otplen);
				qsc_csg_dispose(ctx);
			}
		}
	}
	else if (output != NULL && otplen != 0U && otplen <= QSC_CSG_MAX_REQUEST_SIZE)
	{
		qsc_memutils_clear(output, otplen);
	}

	qsc_memutils_secure_erase(stream, sizeof(stream));

	return res;
}

bool qsc_csg_generate(qsc_csg_state* ctx, uint8_t* output, size_t otplen)
{
	size_t pos;
	size_t step;
	bool res;

	res = false;
	pos = 0U;

	if (ctx != NULL && ctx->initialized == true && output != NULL && otplen != 0U)
	{
		res = true;

		while (pos < otplen && res == true)
		{
			step = otplen - pos;

			if (step > QSC_CSG_MAX_REQUEST_SIZE)
			{
				step = QSC_CSG_MAX_REQUEST_SIZE;
			}

			res = qsc_csg_generate_ex(ctx, output + pos, step, NULL, 0U);
			pos += step;
		}

		if (res == false)
		{
			qsc_memutils_clear(output, otplen);
		}
	}
	else if (output != NULL && otplen != 0U)
	{
		qsc_memutils_clear(output, otplen);
	}

	return res;
}

void qsc_csg_update(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen)
{
	(void)qsc_csg_reseed(ctx, seed, seedlen, NULL, 0U);
}

/* \endcond DOXYGEN_NO_DOCUMENT */

