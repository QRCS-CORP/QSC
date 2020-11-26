#ifndef QSC_PARALLEL_H
#define QSC_PARALLEL_H

#include "common.h"

/**
* \brief Run a function asynchronously on its own thread.
*
* \param ctx: [struct] A pointer to a function state structure
* \param func: [pointer] A pointer to a function
*/
QSC_EXPORT_API void qsc_parallel_async_launch(void* ctx, void (*func)(void*));

/**
* \brief Run a function in a for loop with each iteration executing on a new thread.
*
* \param from: [size] The starting iteration in the for loop
* \param to: [size] The last iteration in the for loop
* \param func: [pointer] A pointer to a function
*/
QSC_EXPORT_API void qsc_parallel_for(size_t from, size_t to, void (*func)(size_t));

/**
* \brief Run a function in a for loop with each iteration executing on a new thread, 
* with each thread receiving a function state.
*
* \param from: [size] The starting iteration in the for loop
* \param to: [size] The last iteration in the for loop
* \param ctx: [struct] A pointer to a function state structure
* \param func: [pointer] A pointer to a function
*/
QSC_EXPORT_API void qsc_parallel_state_for(size_t from, size_t to, void* ctx, void (*func)(size_t, void*));

/**
* \brief Returns the number of cpu cores (including hyperthreads) available on the system.
*/
QSC_EXPORT_API size_t qsc_parallel_processor_count();

#endif
