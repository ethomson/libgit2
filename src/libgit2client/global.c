/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <git2.h>
#include <git2client.h>
#include "git2_util.h"
#include "alloc.h"
#include "hash.h"

static int libgit2_init(void);
static void libgit2_shutdown(void);

static git_global_init_fn client_init_fn[] = {
	libgit2_init,
	git_allocator_global_init,
	git_threads_global_init,
	git_hash_global_init,
	NULL
};

static int libgit2_init(void)
{
	if (git_libgit2_init() < 0)
		return -1;

	return git_global_shutdown_register(libgit2_shutdown);
}

static void libgit2_shutdown(void)
{
	git_libgit2_shutdown();
}

int git_client_init(void)
{
	return git_global_init(client_init_fn);
}

int git_client_shutdown(void)
{
	return git_global_shutdown();
}
