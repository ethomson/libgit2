/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"
#include "global.h"

double git_timeout__ms = 0;

void git_timeout_set(double ms)
{
	git_timeout__ms = ms;
}

void git_timeout__start()
{
	assert(GIT_GLOBAL->timer_count >= 0);

	if (GIT_GLOBAL->timer_count++ == 0)
		GIT_GLOBAL->timer_start = git__timer();
}

void git_timeout__end()
{
	assert(GIT_GLOBAL->timer_count > 0);

	if (--GIT_GLOBAL->timer_count == 0)
		GIT_GLOBAL->timer_start = 0;
}
