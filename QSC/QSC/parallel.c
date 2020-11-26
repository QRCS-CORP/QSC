#include "parallel.h"
#include <omp.h>

void qsc_parallel_async_launch(void* ctx, void (*func)(void*))
{
#pragma omp parallel
	func(ctx);
}

void qsc_parallel_for(size_t from, size_t to, void (*func)(size_t))
{
	int32_t i;

#pragma omp parallel for
	for (i = (int32_t)from; i < (int32_t)to; ++i)
	{
		func(i);
	}
}

void qsc_parallel_state_for(size_t from, size_t to, void* ctx, void (*func)(size_t, void*))
{
	int32_t i;

#pragma omp parallel for
	for (i = (int32_t)from; i < (int32_t)to; ++i)
	{
		func(i, ctx);
	}
}

size_t qsc_parallel_processor_count()
{
	return (size_t)omp_get_num_procs();
}