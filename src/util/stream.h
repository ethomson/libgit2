/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_stream_h__
#define INCLUDE_stream_h__

#include "git2_util.h"
#include "git2/sys/stream.h"

GIT_INLINE(int) git_stream_connect(
	git_stream *st,
	const char *host,
	const char *port,
	const git_stream_connect_options *opts)
{
	GIT_ASSERT_ARG(st);
	GIT_ASSERT(st->type == GIT_STREAM_SOCKET || st->type == GIT_STREAM_TLS);
	GIT_ASSERT(st->connect);

	return st->connect(st, host, port, opts);
}

GIT_INLINE(int) git_stream_wrap(
	git_stream *st,
	git_stream *in,
	const char *host)
{
	GIT_ASSERT_ARG(st);
	GIT_ASSERT(st->type == GIT_STREAM_TLS);
	GIT_ASSERT(st->wrap);

	return st->wrap(st, in, host);
}

GIT_INLINE(git_stream_t) git_stream_type(git_stream *st)
{
	return st->type;
}

GIT_INLINE(GIT_SOCKET) git_stream_get_socket(git_stream *st)
{
	GIT_ASSERT_ARG(st);
	GIT_ASSERT(st->type == GIT_STREAM_SOCKET);
	GIT_ASSERT(st->get_socket);

	return st->get_socket(st);
}

GIT_INLINE(int) git_stream_certificate(git_cert **out, git_stream *st)
{
	GIT_ASSERT_ARG(st);
	GIT_ASSERT(st->type == GIT_STREAM_TLS);
	GIT_ASSERT(st->certificate);

	return st->certificate(out, st);
}

GIT_INLINE(ssize_t) git_stream_read(git_stream *st, void *data, size_t len)
{
	return st->read(st, data, len);
}

GIT_INLINE(ssize_t) git_stream_write(git_stream *st, const char *data, size_t len, int flags)
{
	return st->write(st, data, len, flags);
}

GIT_INLINE(int) git_stream__write_full(git_stream *st, const char *data, size_t len, int flags)
{
	size_t total_written = 0;

	while (total_written < len) {
		ssize_t written = git_stream_write(st, data + total_written, len - total_written, flags);
		if (written <= 0)
			return -1;

		total_written += written;
	}

	return 0;
}

GIT_INLINE(int) git_stream_close(git_stream *st)
{
	return st->close(st);
}

GIT_INLINE(void) git_stream_free(git_stream *st)
{
	if (!st)
		return;

	st->free(st);
}

#endif
