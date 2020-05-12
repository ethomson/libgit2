/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>
#include <git2.h>
#include <git2client.h>
#include "git2_util.h"
#include "hash.h"
#include "cli.h"

static int client_init(void);
static void client_shutdown(void);

static git_global_init_fn cli_init_fn[] = {
	client_init,
	git_allocator_global_init,
	git_hash_global_init,
	git_ssh_subtransport_register,
	git_exec_filter_register,
	NULL
};

static int client_init(void)
{
	if (git_client_init() < 0)
		return -1;

	return git_global_shutdown_register(client_shutdown);
}

static void client_shutdown(void)
{
	git_client_shutdown();
}

int cli_global_init()
{
	return git_global_init(cli_init_fn);
}

int cli_global_shutdown()
{
	return git_global_shutdown();
}
