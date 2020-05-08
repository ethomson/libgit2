/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>
#include <git2.h>
#include <git2client.h>
#include "cli.h"

int cli_global_init()
{
	git_client_init();

	git_allocator_global_init();

	git_ssh_subtransport_register();
	git_exec_filter_register();

	return 0;
}

int cli_global_shutdown()
{
	git_client_shutdown();
	return 0;
}
