/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_timeout_h__
#define INCLUDE_timeout_h__

#define GITERR_CHECK_TIMEOUT() \
	do { \
		assert(GIT_GLOBAL->timer_count); \
		if (git__timer() - GIT_GLOBAL->timer_start > git_timeout__ms) { \
			GIT_GLOBAL->timer_count = 0; \
			GIT_GLOBAL->timer_start = 0; \
			giterr_set(GITERR_TIMEOUT, "the operation timed out"); \
			return GIT_ETIMEOUT; \
		} \
	} while (0)

extern void git_timeout__start(void);
extern void git_timeout__end(void);

#endif
