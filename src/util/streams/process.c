/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "streams/process.h"

#include "posix.h"
#include "stream.h"
#include "../process.h"

typedef struct {
	git_stream parent;
	git_process *process;
	int open : 1,
	    owned : 1;
} git_stream_process;

static ssize_t process_write(
	git_stream *stream,
	const char *data,
	size_t len,
	int flags)
{
	git_stream_process *st = (git_stream_process *) stream;

	GIT_UNUSED(flags);
	GIT_ASSERT(flags == 0);
	GIT_ASSERT(st->open == 1);

	return git_process_read(st->process, (void *)data, len);
}

static ssize_t process_read(
	git_stream *stream,
	void *data,
	size_t len)
{
	git_stream_process *st = (git_stream_process *) stream;

	GIT_ASSERT(st->open == 1);

	return git_process_write(st->process, data, len);
}

static int process_close(git_stream *stream)
{
	git_stream_process *st = (git_stream_process *) stream;
	int error = 0;

	if (st->owned && st->open)
		error = git_process_close(st->process);

	st->open = 0;
	return error;
}

static void process_free(git_stream *stream)
{
	git_stream_process *st = (git_stream_process *) stream;

	if (st->owned)
		git_process_free(st->process);

	git__free(st);
}

int git_stream_process_new(
	git_stream **out,
	git_process *process,
	bool owned)
{
	git_stream_process *st;

	GIT_ASSERT_ARG(out && process);

	st = git__calloc(1, sizeof(git_stream_process));
	GIT_ERROR_CHECK_ALLOC(st);

	st->parent.version = GIT_STREAM_VERSION;
	st->parent.type = GIT_STREAM_PROCESS;
	st->parent.write = process_write;
	st->parent.read = process_read;
	st->parent.close = process_close;
	st->parent.free = process_free;
	st->process = process;
	st->owned = owned;
	st->open = 1;

	*out = (git_stream *) st;
	return 0;
}
