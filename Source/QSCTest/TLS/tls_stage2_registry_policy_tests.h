#ifndef QSCTEST_TLS_STAGE2_REGISTRY_POLICY_TESTS_H
#define QSCTEST_TLS_STAGE2_REGISTRY_POLICY_TESTS_H

#include "../qsctestcommon.h"
#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tls_stage2_registry_policy_tests.h
 * \brief Declares Stage 2 TLS registry and policy function tests.
 *
 * \details
 * Stage 2 validates the static TLS registries and policy filters that govern
 * named-group admission, signature-scheme admission, and the descriptive
 * properties associated with each supported identifier.
 *
 * These tests are deterministic and do not perform any network I/O. They are
 * intended to confirm that the public registry helpers and policy gates remain
 * internally consistent as the TLS implementation evolves.
 */

/**
 * \brief Run the Stage 2 TLS registry and policy tests.
 *
 * \return [bool] Returns true only if all Stage 2 tests pass.
 */
bool qsctest_tls_stage2_tests(void);

QSC_CPLUSPLUS_ENABLED_END

#endif
