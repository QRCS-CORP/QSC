
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSCTEST_TIMER_H
#define QSCTEST_TIMER_H

#include "common.h"
#include <time.h>

/**
* \brief Returns the clock time at the start of a timed operation
*
* \return The starting clock time
*/
clock_t qsctest_timer_start();

/**
* \brief Returns the time difference between the start and current time in milliseconds
*
* \return The timke difference in milliseconds
*/
uint64_t qsctest_timer_elapsed(clock_t start);

#endif