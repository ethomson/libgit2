/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <git2.h>
#include <git2client.h>
#include "alloc.h"

int git_client_init(void)
{
	git_allocator_global_init();
	return git_libgit2_init();
}

int git_client_shutdown(void)
{
	return git_libgit2_shutdown();
}
