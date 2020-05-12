/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git2_util.h"
#include "global.h"

static git_global_shutdown_fn shutdown_callback[16];
static git_atomic shutdown_callback_count;

static git_atomic init_count;

static int init_common(git_global_init_fn init_fns[])
{
	size_t i;
	int ret;

	for (i = 0; init_fns[i] != NULL; i++) {
		if ((ret = init_fns[i]()) != 0)
			break;
	}

	GIT_MEMORY_BARRIER;

	return ret;
}

static void shutdown_common(void)
{
	int pos;

	for (pos = git_atomic_get(&shutdown_callback_count);
	     pos > 0;
	     pos = git_atomic_dec(&shutdown_callback_count)) {
		git_global_shutdown_fn cb = git__swap(shutdown_callback[pos - 1], NULL);

		if (cb != NULL)
			cb();
	}
}

int git_global_shutdown_register(git_global_shutdown_fn callback)
{
	int count = git_atomic_inc(&shutdown_callback_count);

	if (count > (int)ARRAY_SIZE(shutdown_callback) || count == 0) {
		git_error_set(GIT_ERROR_INVALID,
		              "too many shutdown callbacks registered");
		git_atomic_dec(&shutdown_callback_count);
		return -1;
	}

	shutdown_callback[count - 1] = callback;

	return 0;
}

#if defined(GIT_THREADS) && defined(GIT_WIN32)

static volatile LONG init_mutex = 0;

int git_global_init(git_global_init_fn init_fns[])
{
	int ret, error;

	/* Enter the lock */
	while (InterlockedCompareExchange(&init_mutex, 1, 0))
		Sleep(0);

	/* Only do work on a 0 -> 1 transition of the refcount */
	if ((ret = git_atomic_inc(&init_count)) == 1) {
		if ((error = init_common(init_fns)) < 0)
			ret = error;
	}

	/* Exit the lock */
	InterlockedExchange(&init_mutex, 0);

	return ret;
}

int git_global_shutdown(void)
{
	int ret;

	/* Enter the lock */
	while (InterlockedCompareExchange(&init_mutex, 1, 0))
		Sleep(0);

	/* Only do work on a 1 -> 0 transition of the refcount */
	if ((ret = git_atomic_dec(&init_count)) == 0) {
		shutdown_common();
		FlsFree(_fls_index);
	}

	/* Exit the lock */
	InterlockedExchange(&init_mutex, 0);

	return ret;
}

#elif defined(GIT_THREADS) && defined(_POSIX_THREADS)

static pthread_mutex_t init_mutex = PTHREAD_MUTEX_INITIALIZER;

int git_global_init(git_global_init_fn init_fns[])
{
	int ret, error;

	if ((error = pthread_mutex_lock(&init_mutex)) != 0)
		return error;

	/* Only do work on a 0 -> 1 transition of the refcount */
	if ((ret = git_atomic_inc(&init_count)) == 1) {
		if ((error = init_common(init_fns)) < 0)
			ret = error;
	}

	if ((error = pthread_mutex_unlock(&init_mutex)) < 0)
		ret = error;

	return ret;
}

int git_global_shutdown(void)
{
	int ret, error;

	if ((error = pthread_mutex_lock(&init_mutex)) != 0)
		return -1;

	/* Only do work on a 1 -> 0 transition of the refcount */
	if ((ret = git_atomic_dec(&init_count)) == 0)
		shutdown_common();

	if ((error = pthread_mutex_unlock(&init_mutex)) != 0)
		return -1;

	return ret;
}

#elif defined(GIT_THREADS)
# error unknown threading model
#else

int git_global_init(git_global_init_fn init_fns[])
{
	int ret, error;

	/* Only do work on a 0 -> 1 transition of the refcount */
	if ((ret = git_atomic_inc(&init_count)) == 1) {
		if ((error = init_common(init_fns)) < 0)
			ret = error;
	}

	return ret;
}

int git_global_shutdown(void)
{
	int ret;

	/* Only do work on a 1 -> 0 transition of the refcount */
	if ((ret = git_atomic_dec(&init_count)) == 0)
		shutdown_common();

	return ret;
}

#endif
