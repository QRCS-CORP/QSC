#include "secrand_test.h"
#include "testutils.h"
#include "../QSC/acp.h"
#include "../QSC/csg.h"
#include "../QSC/csp.h"
#include "../QSC/hcg.h"
#include "../QSC/intutils.h"
#include "../QSC/memutils.h"
#include "../QSC/rdp.h"
#include "../QSC/scb.h"
#include "../QSC/secrand.h"
#include "../QSC/sysutils.h"

static const double Z_MAX = 6.0;
static const double LOG_SQRT_PI = 0.5723649429247000870717135;
static const double I_SQRT_PI = 0.5641895835477562869480795;
static const double BIGX = 20.0;

static double secrand_ex(double x)
{
    double result;
    
    if (x < -BIGX)
    {
        result = 0.0;
    }
    else
    {
        result = qsc_intutils_calculate_exp(x);
    }
    
    return result;
}

static double secrand_poz(const double z)
{
	/* borrowed from the ENT project: https://www.fourmilab.ch/random/
	* returns cumulative probability from -oo to z */
	double w;
	double x;
	double y;

	if (z == 0.0)
	{
		x = 0.0;
	}
	else
	{
		y = 0.5 * qsc_intutils_calculate_fabs(z);

		if (y >= (Z_MAX * 0.5))
		{
			x = 1.0;
		}
		else if (y < 1.0)
		{
			w = y * y;
			x = ((((((((0.000124818987 * w
				- 0.001075204047) * w + 0.005198775019) * w
				- 0.019198292004) * w + 0.059054035642) * w
				- 0.151968751364) * w + 0.319152932694) * w
				- 0.531923007300) * w + 0.797884560593) * y * 2.0;
		}
		else
		{
			y -= 2.0;
			x = (((((((((((((-0.000045255659 * y
				+ 0.000152529290) * y - 0.000019538132) * y
				- 0.000676904986) * y + 0.001390604284) * y
				- 0.000794620820) * y - 0.002034254874) * y
				+ 0.006549791214) * y - 0.010557625006) * y
				+ 0.011630447319) * y - 0.009279453341) * y
				+ 0.005353579108) * y - 0.002141268741) * y
				+ 0.000535310849) * y + 0.999936657524;
		}
	}

	return (z > 0.0 ? ((x + 1.0) * 0.5) : ((1.0 - x) * 0.5));
}

static double secrand_po_chi_sq(const double ax, const int32_t df)
{
	/* obtained chi-square value degrees of freedom */
	double x;
	double a;
	double s;
	double e;
	double c;
	double z;
	double y;
	double res;
	int32_t even;

	y = 0.0;
	x = ax;

	if (x <= 0.0 || df < 1)
	{
		res = 1.0;
	}
	else
	{
		a = 0.5 * x;
		even = (2 * (df / 2)) == df;

		if (df > 1)
		{
			y = secrand_ex(-a);
		}

		s = (even ? y : (2.0 * secrand_poz(-qsc_intutils_calculate_sqrt(x))));

		if (df > 2)
		{
			x = 0.5 * ((double)df - 1.0);
			z = (even ? 1.0 : 0.5);

			if (a > BIGX)
			{
				e = (even ? 0.0 : LOG_SQRT_PI);
				c = qsc_intutils_calculate_log(a);

				while (z <= x)
				{
					e = qsc_intutils_calculate_log(z) + e;
					s += secrand_ex(c * z - a - e);
					z += 1.0;
				}

				res = s;
			}
			else
			{
				e = (even ? 1.0 : (I_SQRT_PI / qsc_intutils_calculate_sqrt(a)));
				c = 0.0;

				while (z <= x)
				{
					e = e * (a / z);
					c = c + e;
					z += 1.0;
				}

				res = (c * y + s);
			}
		}
		else
		{
			res = s;
		}
	}

	return res;
}

static double secrand_chi_square(const uint8_t* input, size_t length)
{
	long count[256] = { 0 };
	double a;
	double cexp;
	double chisq;
	long totalc;
	size_t i;

	chisq = 0.0;
	totalc = (long)length;

	for (i = 0; i < length; ++i)
	{
		count[input[i]]++;
	}

	/* Expected count per bin */
	cexp = (double)totalc / 256.0;

	for (i = 0; i < 256; i++)
	{
		a = (double)count[i] - cexp;
		chisq += (a * a) / cexp;
	}

	return secrand_po_chi_sq(chisq, 255);
}

static double secrand_mean_value(const uint8_t* input, size_t length)
{
	double ret;

	ret = 0.0;

	for (size_t i = 0; i < length; ++i)
	{
		ret += (double)input[i];
	}

	return ret / (double)length;
}

static bool secrand_ordered_runs(const uint8_t* input, size_t length, size_t threshold)
{
	size_t c;
	uint8_t val;
	bool res;

	c = 0;
	res = false;
	val = input[0];

	/* indicates zeroed output or bad run */
	for (size_t i = 1; i < length; ++i)
	{
		if (input[i] == val)
		{
			++c;

			if (c >= threshold)
			{
				res = true;
				break;
			}
		}
		else
		{
			val = input[i];
			c = 0;
		}
	}

	return res;
}

static bool secrand_succesive_seros(const uint8_t* input, size_t length, size_t threshold)
{
	size_t c;
	bool res;

	c = 0;
	res = false;

	for (size_t i = 0; i < length; ++i)
	{
		if (input[i] == 0x00)
		{
			++c;
			if (c >= threshold)
			{
				res = true;
				break;
			}
		}
		else
		{
			c = 0;
		}
	}

	return res;
}

static void secrand_print_double(double input)
{
	int32_t len = snprintf(NULL, 0, "%g", input);
	char* str = qsc_memutils_malloc((size_t)len + 1);

	if (str != NULL)
	{
		qsc_memutils_clear(str, len);
		snprintf(str, (size_t)len + 1, "%g", input);
		qsctest_print_safe(str);
		qsc_memutils_alloc_free(str);
	}
}

void qsctest_secrand_evaluate(const char* name, const uint8_t* sample, size_t length)
{
	double x;

	// mean value test
	x = secrand_mean_value(sample, length);

	qsctest_print_safe(name);
	qsctest_print_safe(": Mean distribution value is ");
	secrand_print_double(x);
	qsctest_print_safe(" (127.5 is optimal) ");

	if (x < 122.5 || x > 132.5)
	{
		qsctest_print_safe(": FAIL! \n");
	}
	else if (x < 125.0 || x > 130.0)
	{
		qsctest_print_safe(": WARN \n");
	}
	else
	{
		qsctest_print_safe(": PASS \n");
	}

	// ChiSquare
	x = secrand_chi_square(sample, length) * 100.0;
	qsctest_print_safe(name);
	qsctest_print_safe(": ChiSquare: random would exceed this value ");
	secrand_print_double(x);
	qsctest_print_safe(" percent of the time ");

	if (x < 1.0 || x > 99.0)
	{
		qsctest_print_safe(": FAIL! \n");
	}
	else if (x < 5.0 || x > 95.0)
	{
		qsctest_print_safe(": WARN \n");
	}
	else
	{
		qsctest_print_safe(": PASS \n");
	}

	// ordered runs
	if (secrand_ordered_runs(sample, length, 6))
	{
		qsctest_print_safe(name);
		qsctest_print_safe(": Ordered runs test failure! \n");
	}
	else
	{
		qsctest_print_safe(name);
		qsctest_print_safe(": Ordered runs test passed. \n");
	}

	// succesive zeroes
	if (secrand_succesive_seros(sample, length, 4))
	{
		qsctest_print_safe(name);
		qsctest_print_safe(": Succesive zeroes test failure! \n");
	}
	else
	{
		qsctest_print_safe(name);
		qsctest_print_safe(": Succesive zeroes test passed. \n");
	}
}

void qsctest_secrand_acp_evaluate()
{
	uint8_t smp[QSCTEST_SECRAND_SAMPLE_SIZE] = { 0 };

	qsc_acp_generate(smp, sizeof(smp));

	qsctest_secrand_evaluate("ACP", smp, sizeof(smp));
}

void qsctest_secrand_csg_evaluate()
{
	uint8_t seed[QSC_CSG_256_SEED_SIZE] = { 0 };
	uint8_t smp[QSCTEST_SECRAND_SAMPLE_SIZE] = { 0 };
	qsc_csg_state ctx;

	qsc_csp_generate(seed, sizeof(seed));

	qsc_csg_initialize(&ctx, seed, sizeof(seed), NULL, 0, false);
	qsc_csg_generate(&ctx, smp, sizeof(smp));
	qsc_csg_dispose(&ctx);

	qsctest_secrand_evaluate("CSG", smp, sizeof(smp));
}

void qsctest_secrand_csp_evaluate()
{
	uint8_t smp[QSCTEST_SECRAND_SAMPLE_SIZE] = { 0 };

	qsc_csp_generate(smp, sizeof(smp));

	qsctest_secrand_evaluate("CSP", smp, sizeof(smp));
}

void qsctest_secrand_hcg_evaluate()
{
	uint8_t seed[QSC_HCG_SEED_SIZE] = { 0 };
	uint8_t smp[QSCTEST_SECRAND_SAMPLE_SIZE] = { 0 };
	qsc_hcg_state ctx;

	qsc_csp_generate(seed, sizeof(seed));

	qsc_hcg_initialize(&ctx, seed, sizeof(seed), NULL, 0, false);
	qsc_hcg_generate(&ctx, smp, sizeof(smp));
	qsc_hcg_dispose(&ctx);

	qsctest_secrand_evaluate("HCG", smp, sizeof(smp));
}

void qsctest_secrand_rdp_evaluate()
{
	uint8_t smp[QSCTEST_SECRAND_SAMPLE_SIZE] = { 0 };

	qsc_rdp_generate(smp, sizeof(smp));
	qsctest_secrand_evaluate("RDP", smp, sizeof(smp));
}

void qsctest_secrand_scb_evaluate()
{
	uint8_t seed[QSC_SCB_256_SEED_SIZE] = { 0 };
	uint8_t smp[QSCTEST_SECRAND_SAMPLE_SIZE] = { 0 };
	qsc_scb_state ctx = { 0 };

	qsc_csp_generate(seed, sizeof(seed));

	qsc_scb_initialize(&ctx, seed, sizeof(seed), NULL, 0, 1, 1);
	qsc_scb_generate(&ctx, smp, sizeof(smp));
	qsc_scb_dispose(&ctx);

	qsctest_secrand_evaluate("SCB", smp, sizeof(smp));
}

bool qsctest_secrand_stress()
{
	uint8_t seed[32] = { 0 };
	bool res;

	res = true;

	qsc_acp_generate(seed, sizeof(seed));
	qsc_secrand_initialize(seed, 32, NULL, 0);

	int8_t xs8 = qsc_secrand_next_char();

	if (xs8 == 0)
	{
		res = false;
	}

	uint8_t xu8 = qsc_secrand_next_uchar();

	if (xu8 == 0)
	{
		res = false;
	}

	double xd = qsc_secrand_next_double();

	if (xd == 0.0)
	{
		res = false;
	}

	int16_t xs16 = qsc_secrand_next_int16();

	if (xs16 == 0)
	{
		res = false;
	}

	int16_t xs16m = qsc_secrand_next_int16_max(1000);

	if (xs16m > 1000)
	{
		res = false;
	}

	int16_t xs16mm = qsc_secrand_next_int16_maxmin(1000, 900);

	if (xs16mm > 1000 || xs16mm < 900)
	{
		res = false;
	}

	uint16_t xu16 = qsc_secrand_next_uint16();

	if (xu16 == 0)
	{
		res = false;
	}

	uint16_t xu16m = qsc_secrand_next_uint16_max(1000);

	if (xu16m > 1000)
	{
		res = false;
	}

	uint16_t xu16mm = qsc_secrand_next_uint16_maxmin(1000, 900);

	if (xu16mm > 1000 || xu16mm < 900)
	{
		res = false;
	}

	int32_t xs32 = qsc_secrand_next_int32();

	if (xs32 == 0)
	{
		res = false;
	}

	int32_t xs32m = qsc_secrand_next_int32_max(1000);

	if (xs32m > 1000)
	{
		res = false;
	}

	int32_t xs32mm = qsc_secrand_next_int32_maxmin(1000, 900);

	if (xs32mm > 1000 || xs32mm < 900)
	{
		res = false;
	}

	uint32_t xu32 = qsc_secrand_next_uint32();

	if (xu32 == 0)
	{
		res = false;
	}

	uint32_t xu32m = qsc_secrand_next_uint32_max(1000);

	if (xu32m > 1000)
	{
		res = false;
	}

	uint32_t xu32mm = qsc_secrand_next_uint32_maxmin(1000, 900);

	if (xu32mm > 1000 || xu32mm < 900)
	{
		res = false;
	}

	int64_t xs64 = qsc_secrand_next_int64();

	if (xs64 == 0)
	{
		res = false;
	}

	int64_t xs64m = qsc_secrand_next_int64_max(1000);

	if (xs64m > 1000)
	{
		res = false;
	}

	int64_t xs64mm = qsc_secrand_next_int64_maxmin(1000, 900);

	if (xs64mm > 1000 || xs64mm < 900)
	{
		res = false;
	}

	uint64_t xu64 = qsc_secrand_next_uint64();

	if (xu64 == 0)
	{
		res = false;
	}

	uint64_t xu64m = qsc_secrand_next_uint64_max(1000);

	if (xu64m > 1000)
	{
		res = false;
	}

	uint64_t xu64mm = qsc_secrand_next_uint64_maxmin(1000, 900);

	if (xu64mm > 1000 || xu64mm < 900)
	{
		res = false;
	}

	return res;
}

void qsctest_secrand_run()
{
	qsctest_print_safe("*** Note: Random generators will ocassionally fail this test. \n");
	qsctest_print_safe("This is not the fault of the provider, but the nature of random data. \n");
	qsctest_print_safe("Only if a random provider fails these tests consistantly, is it considered faulty. \n\n");

	if (qsctest_secrand_stress() == true)
	{
		qsctest_print_safe("Success! Passed the secrand stress and wellness test. \n");
	}
	else
	{
		qsctest_print_safe("Failure! Failed the secrand stress and wellness test. \n");
	}

	qsctest_print_safe("*** Testing random entropy providers *** \n");
	qsctest_secrand_acp_evaluate();
	qsctest_secrand_csp_evaluate();
#if defined(QSC_RDRAND_COMPATIBLE)
	qsctest_secrand_rdp_evaluate();
#endif
	qsctest_print_safe("*** Testing deterministic random bit generators *** \n");
	qsctest_secrand_csg_evaluate();
	qsctest_secrand_hcg_evaluate();

	qsctest_print_safe("*** Testing key derivation functions *** \n");
	qsctest_secrand_scb_evaluate();
}
