#include "async_test.h"
#include "../QSC/async.h"
#include "testutils.h"

/* \cond DOXYGEN_IGNORE */

typedef struct
{
	int32_t x;
	int32_t y;
	int32_t z;
} thread_data;

/* \endcond DOXYGEN_IGNORE */

static void thread_func(thread_data* data)
{
	data->z = data->x * data->y;
}

static bool qsctest_thread_test()
{
	thread_data data = { data.x = 10, data.y = 20 };
	bool res;

	qsc_async_launch_thread((void*)&thread_func, &data);

	if (data.z == data.x * data.y)
	{
		res = true;
	}
	else
	{
		qsctest_print_line("thread test: result does not match the expected value.");
		res = false;
	}

	return res;
}

static bool qsctest_multithread_test()
{
	thread_data data1 = { data1.x = 10, data1.y = 10 };
	thread_data data2 = { data2.x = 10, data2.y = 20 };
	thread_data data3 = { data3.x = 10, data3.y = 30 };
	thread_data data4 = { data4.x = 10, data4.y = 40 };
	bool res;

	qsc_async_launch_parallel_threads((void*)&thread_func, 4, &data1, &data2, &data3, &data4);

	if (data1.z == data1.x * data1.y && data2.z == data2.x * data2.y && 
		data3.z == data3.x * data3.y && data4.z == data4.x * data4.y)
	{
		res = true;
	}
	else
	{
		qsctest_print_line("multithread test: results do not match expected values.");
		res = false;
	}

	return res;
}

void qsctest_async_run()
{
	if (qsctest_thread_test() == true)
	{
		qsctest_print_line("Success! Passed the async thread tests.");
	}
	else
	{
		qsctest_print_line("Failure! Passed the async thread tests.");
	}

	if (qsctest_multithread_test() == true)
	{
		qsctest_print_line("Success! Passed the async multi-thread tests.");
	}
	else
	{
		qsctest_print_line("Failure! Failed the async multi-thread tests.");
	}
}
