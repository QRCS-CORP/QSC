#include "threadpool.h"
#include "memutils.h"
#include <stdint.h>

#if defined(QSC_SYSTEM_OS_WINDOWS)
#   if !defined(WIN32_LEAN_AND_MEAN)
#       define WIN32_LEAN_AND_MEAN
#   endif
#   if !defined(NOMINMAX)
#       define NOMINMAX
#   endif
#   include <windows.h>
#elif defined(QSC_SYSTEM_OS_POSIX)
#   include <pthread.h>
#endif

/** \brief An indexed task in a bounded persistent-worker queue. */
typedef struct
{
	void (*func)(void*); /*!< Caller-provided task; never invoked with an internal lock held. */
	void* state;         /*!< Caller-owned task argument; must outlive execution. */
} qsc_threadpool_work_item;

/** \brief Private per-instance synchronization for the legacy, ABI-fixed pool. */
typedef struct qsc_threadpool_legacy_lock
{
	qsc_threadpool_state* context;			/*!< Caller-owned public state. */
	qsc_mutex mutex;						/*!< Instance-owned mutex. */
	struct qsc_threadpool_legacy_lock* next;/*!< Next registered legacy pool. */
	size_t references;						/*!< Operations accessing this instance. */
} qsc_threadpool_legacy_lock;

/** \brief Opaque persistent-worker pool with bounded FIFO queue. */
struct qsc_threadpool_worker_state
{
	qsc_thread* threads;					/*!< Joinable worker handles. */
	qsc_threadpool_work_item* queue;		/*!< Owned bounded task ring. */
	size_t workers;							/*!< Successfully launched workers. */
	size_t capacity;						/*!< Fixed queue capacity. */
	size_t head;							/*!< Index of oldest queued task. */
	size_t tail;							/*!< Next free task slot. */
	size_t queued;							/*!< Waiting tasks. */
	size_t active;							/*!< Currently executing tasks. */
	bool stopping;							/*!< Reject submissions and drain before exit. */
#if defined(QSC_SYSTEM_OS_WINDOWS)
	CRITICAL_SECTION mutex;					/*!< Protects queue state. */
	CONDITION_VARIABLE ready;				/*!< Task arrival or shutdown. */
	CONDITION_VARIABLE idle;				/*!< Queue and callbacks drained. */
#elif defined(QSC_SYSTEM_OS_POSIX)
	pthread_mutex_t mutex;					/*!< Protects queue state. */
	pthread_cond_t ready;					/*!< Task arrival or shutdown. */
	pthread_cond_t idle;					/*!< Queue and callbacks drained. */
#endif
};

/* The registry spin gate guards *only* private metadata discovery and reference counts.
 * Each legacy pool uses its own mutex for task operations. No public ABI changes. */
static volatile int32_t qsc_threadpool_registry_gate = 0;
static qsc_threadpool_legacy_lock* qsc_threadpool_legacy_head = NULL;

/** \brief Acquire the short-lived registry metadata gate. \note Does not invoke user callbacks. */
static void qsc_threadpool_registry_lock(void)
{
	while (qsc_async_atomic_int32_compare_exchange(&qsc_threadpool_registry_gate, 0, 1) == false)
	{
		qsc_async_thread_sleep(1U);
	}
}

static void qsc_threadpool_registry_unlock(void)
{
	qsc_async_atomic_int32_store(&qsc_threadpool_registry_gate, 0);
}

static qsc_threadpool_legacy_lock* qsc_threadpool_legacy_acquire(const qsc_threadpool_state* ctx)
{
	/* obtain a safe reference to a registered legacy pool lock */
	qsc_threadpool_legacy_lock* current;
	qsc_threadpool_legacy_lock* result;

	result = NULL;
	qsc_threadpool_registry_lock();

	for (current = qsc_threadpool_legacy_head; current != NULL; current = current->next)
	{
		if (current->context == ctx)
		{
			++current->references;
			result = current;
			break;
		}
	}

	qsc_threadpool_registry_unlock();
	return result;
}

static void qsc_threadpool_legacy_release(qsc_threadpool_legacy_lock* entry)
{
	qsc_threadpool_registry_lock();
	--entry->references;
	qsc_threadpool_registry_unlock();
}

bool qsc_threadpool_add_task(qsc_threadpool_state* ctx, void (*func)(void*), void* state)
{
	qsc_threadpool_legacy_lock* entry;
	qsc_thread handle;
	bool result;

	QSC_ASSERT(ctx != NULL);
	QSC_ASSERT(func != NULL);
	result = false;

	if (ctx != NULL && func != NULL)
	{
		entry = qsc_threadpool_legacy_acquire(ctx);

		if (entry != NULL)
		{
			qsc_async_mutex_lock(entry->mutex);

			if (ctx->tcount >= 0 && (size_t)ctx->tcount < (size_t)QSC_THREADPOOL_THREADS_MAX)
			{
				handle = qsc_async_thread_create(func, state);

				if (handle != (qsc_thread)0)
				{
					ctx->tpool[ctx->tcount] = handle;
					++ctx->tcount;
					result = true;
				}
			}

			qsc_async_mutex_unlock(entry->mutex);
			qsc_threadpool_legacy_release(entry);
		}
	}

	return result;
}

void qsc_threadpool_destroy(qsc_threadpool_state* ctx)
{
	qsc_threadpool_legacy_lock* current;
	qsc_threadpool_legacy_lock* previous;
	qsc_threadpool_legacy_lock* entry;
	bool draining;
	size_t i;

	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		entry = NULL;
		previous = NULL;
		qsc_threadpool_registry_lock();

		for (current = qsc_threadpool_legacy_head; current != NULL; current = current->next)
		{
			if (current->context == ctx)
			{
				entry = current;
				if (previous == NULL)
				{
					qsc_threadpool_legacy_head = current->next;
				}
				else
				{
					previous->next = current->next;
				}
				break;
			}

			previous = current;
		}

		qsc_threadpool_registry_unlock();

		if (entry != NULL)
		{
			do
			{
				qsc_threadpool_registry_lock();
				draining = (entry->references != 0U);
				qsc_threadpool_registry_unlock();

				if (draining == true)
				{
					qsc_async_thread_sleep(1U);
				}
			} while (draining == true);

			for (i = 0U; i < (size_t)ctx->tcount; ++i)
			{
				if (ctx->tpool[i] != (qsc_thread)0)
				{
					(void)qsc_async_thread_terminate(ctx->tpool[i]);
				}
			}

			(void)qsc_async_mutex_destroy(entry->mutex);
			qsc_memutils_alloc_free(entry);
			qsc_memutils_clear(ctx->tpool, sizeof(ctx->tpool));
			ctx->tcount = 0;
		}
	}
}

void qsc_threadpool_initialize(qsc_threadpool_state* ctx)
{
	qsc_threadpool_legacy_lock* entry;
	qsc_threadpool_legacy_lock* current;
	bool found;
	bool registered;

	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		registered = false;
		entry = (qsc_threadpool_legacy_lock*)qsc_memutils_calloc(1U, sizeof(qsc_threadpool_legacy_lock));

		if (entry != NULL)
		{
			entry->mutex = qsc_async_mutex_create();

			if (entry->mutex != NULL)
			{
				entry->context = ctx;
				found = false;
				qsc_threadpool_registry_lock();

				for (current = qsc_threadpool_legacy_head; current != NULL; current = current->next)
				{
					if (current->context == ctx)
					{
						found = true;
						break;
					}
				}

				if (found == false)
				{
					qsc_memutils_clear(ctx->tpool, sizeof(ctx->tpool));
					ctx->tcount = 0;
					entry->next = qsc_threadpool_legacy_head;
					qsc_threadpool_legacy_head = entry;
					registered = true;
				}

				qsc_threadpool_registry_unlock();

				if (found == true)
				{
					(void)qsc_async_mutex_destroy(entry->mutex);
					qsc_memutils_alloc_free(entry);
				}
			}
			else
			{
				qsc_memutils_alloc_free(entry);
			}
		}

		if (registered == false)
		{
			/* void-returning initializer cannot report allocation failure.
			 * leave a safe, empty public state unless already initialized. */
			current = qsc_threadpool_legacy_acquire(ctx);

			if (current == NULL)
			{
				qsc_memutils_clear(ctx->tpool, sizeof(ctx->tpool));
				ctx->tcount = 0;
			}
			else
			{
				qsc_threadpool_legacy_release(current);
			}
		}
	}
}

void qsc_threadpool_sort(qsc_threadpool_state* ctx)
{
	qsc_threadpool_legacy_lock* entry;
	size_t source;
	size_t dest;

	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		entry = qsc_threadpool_legacy_acquire(ctx);

		if (entry != NULL)
		{
			qsc_async_mutex_lock(entry->mutex);
			dest = 0U;

			for (source = 0U; source < (size_t)ctx->tcount; ++source)
			{
				if (ctx->tpool[source] != (qsc_thread)0)
				{
					ctx->tpool[dest] = ctx->tpool[source];
					++dest;
				}
			}

			for (source = dest; source < (size_t)QSC_THREADPOOL_THREADS_MAX; ++source)
			{
				ctx->tpool[source] = (qsc_thread)0;
			}

			ctx->tcount = (int32_t)dest;
			qsc_async_mutex_unlock(entry->mutex);
			qsc_threadpool_legacy_release(entry);
		}
	}
}

bool qsc_threadpool_thread_active(const qsc_threadpool_state* ctx, size_t index)
{
	qsc_threadpool_legacy_lock* entry;
	bool result;

	QSC_ASSERT(ctx != NULL);
	result = false;

	if (ctx != NULL)
	{
		entry = qsc_threadpool_legacy_acquire(ctx);

		if (entry != NULL)
		{
			qsc_async_mutex_lock(entry->mutex);

			if (index < (size_t)ctx->tcount)
			{
				result = (ctx->tpool[index] != (qsc_thread)0);
			}

			qsc_async_mutex_unlock(entry->mutex);
			qsc_threadpool_legacy_release(entry);
		}
	}

	return result;
}

void qsc_threadpool_remove_task(qsc_threadpool_state* ctx, size_t index)
{
	qsc_threadpool_legacy_lock* entry;
	qsc_thread handle;

	QSC_ASSERT(ctx != NULL);

	if (ctx != NULL)
	{
		entry = qsc_threadpool_legacy_acquire(ctx);

		if (entry != NULL)
		{
			handle = (qsc_thread)0;
			qsc_async_mutex_lock(entry->mutex);

			if (index < (size_t)ctx->tcount)
			{
				handle = ctx->tpool[index];
				--ctx->tcount;
				ctx->tpool[index] = ctx->tpool[ctx->tcount];
				ctx->tpool[ctx->tcount] = (qsc_thread)0;
			}

			qsc_async_mutex_unlock(entry->mutex);

			if (handle != (qsc_thread)0)
			{
				(void)qsc_async_thread_terminate(handle);
			}

			qsc_threadpool_legacy_release(entry);
		}
	}
}

static void qsc_threadpool_worker_lock(qsc_threadpool_worker_state* pool)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	EnterCriticalSection(&pool->mutex);
#else
	(void)pthread_mutex_lock(&pool->mutex);
#endif
}

static void qsc_threadpool_worker_unlock(qsc_threadpool_worker_state* pool)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	LeaveCriticalSection(&pool->mutex);
#else
	(void)pthread_mutex_unlock(&pool->mutex);
#endif
}

static void qsc_threadpool_worker_await(qsc_threadpool_worker_state* pool)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	(void)SleepConditionVariableCS(&pool->ready, &pool->mutex, INFINITE);
#else
	(void)pthread_cond_wait(&pool->ready, &pool->mutex);
#endif
}

static void qsc_threadpool_worker_await_idle(qsc_threadpool_worker_state* pool)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	(void)SleepConditionVariableCS(&pool->idle, &pool->mutex, INFINITE);
#else
	(void)pthread_cond_wait(&pool->idle, &pool->mutex);
#endif
}

static void qsc_threadpool_worker_signal(qsc_threadpool_worker_state* pool)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	WakeConditionVariable(&pool->ready);
#else
	(void)pthread_cond_signal(&pool->ready);
#endif
}

static void qsc_threadpool_worker_broadcast(qsc_threadpool_worker_state* pool)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	WakeAllConditionVariable(&pool->ready);
#else
	(void)pthread_cond_broadcast(&pool->ready);
#endif
}

static void qsc_threadpool_worker_signal_idle(qsc_threadpool_worker_state* pool)
{
#if defined(QSC_SYSTEM_OS_WINDOWS)
	WakeAllConditionVariable(&pool->idle);
#else
	(void)pthread_cond_broadcast(&pool->idle);
#endif
}

static void qsc_threadpool_worker_execute(void* state)
{
	/* execute tasks from the pool until shutdown and queue exhaustion */
	qsc_threadpool_worker_state* pool;
	qsc_threadpool_work_item item;
	bool done;

	pool = (qsc_threadpool_worker_state*)state;
	done = false;

	while (done == false)
	{
		qsc_threadpool_worker_lock(pool);

		while (pool->queued == 0U && pool->stopping == false)
		{
			qsc_threadpool_worker_await(pool);
		}

		if (pool->queued != 0U)
		{
			item = pool->queue[pool->head];
			pool->head = (pool->head + 1U == pool->capacity) ? 0U : pool->head + 1U;
			--pool->queued;
			++pool->active;
			qsc_threadpool_worker_unlock(pool);

			item.func(item.state);

			qsc_threadpool_worker_lock(pool);
			--pool->active;

			if (pool->queued == 0U && pool->active == 0U)
			{
				qsc_threadpool_worker_signal_idle(pool);
			}

			qsc_threadpool_worker_unlock(pool);
		}
		else
		{
			qsc_threadpool_worker_unlock(pool);
			done = true;
		}
	}
}

qsc_threadpool_worker_state* qsc_threadpool_worker_create(size_t worker_count, size_t queue_capacity)
{
	qsc_threadpool_worker_state* pool;
	bool ready;
	size_t i;

	pool = NULL;
	ready = false;

	if (worker_count != 0U && worker_count <= (size_t)QSC_THREADPOOL_THREADS_MAX &&
		queue_capacity != 0U && queue_capacity <= SIZE_MAX / sizeof(qsc_threadpool_work_item))
	{
		pool = (qsc_threadpool_worker_state*)qsc_memutils_calloc(1U, sizeof(qsc_threadpool_worker_state));

		if (pool != NULL)
		{
			pool->threads = (qsc_thread*)qsc_memutils_calloc(worker_count, sizeof(qsc_thread));
			pool->queue = (qsc_threadpool_work_item*)qsc_memutils_calloc(queue_capacity, sizeof(qsc_threadpool_work_item));

			if (pool->threads != NULL && pool->queue != NULL)
			{
				pool->capacity = queue_capacity;
#if defined(QSC_SYSTEM_OS_WINDOWS)
				if (InitializeCriticalSectionEx(&pool->mutex, 0U, 0U) != 0)
				{
					InitializeConditionVariable(&pool->ready);
					InitializeConditionVariable(&pool->idle);
					ready = true;
				}
#elif defined(QSC_SYSTEM_OS_POSIX)
				if (pthread_mutex_init(&pool->mutex, NULL) == 0)
				{
					if (pthread_cond_init(&pool->ready, NULL) == 0)
					{
						if (pthread_cond_init(&pool->idle, NULL) == 0)
						{
							ready = true;
						}
						else
						{
							(void)pthread_cond_destroy(&pool->ready);
						}
					}

					if (ready == false)
					{
						(void)pthread_mutex_destroy(&pool->mutex);
					}
				}
#endif
			}

			if (ready == true)
			{
				for (i = 0U; i < worker_count; ++i)
				{
					pool->threads[i] = qsc_async_thread_create(qsc_threadpool_worker_execute, pool);

					if (pool->threads[i] == (qsc_thread)0)
					{
						break;
					}

					++pool->workers;
				}

				if (pool->workers != worker_count)
				{
					qsc_threadpool_worker_destroy(pool);
					pool = NULL;
				}
			}
			else
			{
				qsc_memutils_alloc_free(pool->threads);
				qsc_memutils_alloc_free(pool->queue);
				qsc_memutils_alloc_free(pool);
				pool = NULL;
			}
		}
	}

	return pool;
}

bool qsc_threadpool_worker_submit(qsc_threadpool_worker_state* pool, void (*func)(void*), void* state)
{
	bool result;

	result = false;

	if (pool != NULL && func != NULL)
	{
		qsc_threadpool_worker_lock(pool);

		if (pool->stopping == false && pool->queued < pool->capacity)
		{
			pool->queue[pool->tail].func = func;
			pool->queue[pool->tail].state = state;
			pool->tail = (pool->tail + 1U == pool->capacity) ? 0U : pool->tail + 1U;
			++pool->queued;
			result = true;
			qsc_threadpool_worker_signal(pool);
		}

		qsc_threadpool_worker_unlock(pool);
	}

	return result;
}

void qsc_threadpool_worker_wait(qsc_threadpool_worker_state* pool)
{
	if (pool != NULL)
	{
		qsc_threadpool_worker_lock(pool);

		while (pool->queued != 0U || pool->active != 0U)
		{
			qsc_threadpool_worker_await_idle(pool);
		}

		qsc_threadpool_worker_unlock(pool);
	}
}

void qsc_threadpool_worker_destroy(qsc_threadpool_worker_state* pool)
{
	size_t i;

	if (pool != NULL)
	{
		qsc_threadpool_worker_lock(pool);
		pool->stopping = true;
		qsc_threadpool_worker_broadcast(pool);
		qsc_threadpool_worker_unlock(pool);

		for (i = 0U; i < pool->workers; ++i)
		{
			qsc_async_thread_wait(pool->threads[i]);
		}

#if defined(QSC_SYSTEM_OS_WINDOWS)
		DeleteCriticalSection(&pool->mutex);
#else
		(void)pthread_cond_destroy(&pool->idle);
		(void)pthread_cond_destroy(&pool->ready);
		(void)pthread_mutex_destroy(&pool->mutex);
#endif
		qsc_memutils_alloc_free(pool->threads);
		qsc_memutils_alloc_free(pool->queue);
		qsc_memutils_alloc_free(pool);
	}
}
