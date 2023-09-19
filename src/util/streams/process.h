/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_streams_file_h__
#define INCLUDE_streams_file_h__

#include "git2_util.h"

#include "stream.h"
#include "../process.h"

extern int git_stream_process_new(
	git_stream **out,
	git_process *process,
	bool owned);

#endif
