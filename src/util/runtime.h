/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_util_runtime_h__
#define INCLUDE_util_runtime_h__

#include "git2_util.h"

typedef int (*git_runtime_init_fn)(void);
typedef void (*git_runtime_shutdown_fn)(void);

int git_runtime_init(git_runtime_init_fn init_fns[]);
int git_runtime_shutdown(void);
int git_runtime_shutdown_register(git_runtime_shutdown_fn callback);

#endif
