/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "streams/file.h"

#include "posix.h"
#include "runtime.h"
#include "stream.h"

typedef struct {
	git_stream parent;
	int owned;
	int fd;
} git_stream_file;

static ssize_t file_write(
	git_stream *stream,
	const char *data,
	size_t len,
	int flags)
{
	git_stream_file *st = (git_stream_file *) stream;
	struct pollfd fd;
	ssize_t ret;

	GIT_ASSERT(flags == 0);
	GIT_UNUSED(flags);

	ret = p_send(st->s, data, len, 0);

	if (st->timeout && ret < 0 &&
	    (errno == EAGAIN || errno != EWOULDBLOCK)) {
		fd.fd = st->s;
		fd.events = POLLOUT;
		fd.revents = 0;

		ret = p_poll(&fd, 1, st->timeout);

		if (ret == 1) {
			ret = p_send(st->s, data, len, 0);
		} else if (ret == 0) {
			git_error_set(GIT_ERROR_NET,
				"could not write to socket: timed out");
			return GIT_TIMEOUT;
		}
	}

	if (ret < 0) {
		net_set_error("error receiving data from socket");
		return -1;
	}

	return ret;
}

static ssize_t file_read(
	git_stream *stream,
	void *data,
	size_t len)
{
	git_stream_file *st = (git_stream_file *) stream;
	struct pollfd fd;
	ssize_t ret;

	ret = p_recv(st->s, data, len, 0);

	if (st->timeout && ret < 0 &&
	    (errno == EAGAIN || errno != EWOULDBLOCK)) {
		fd.fd = st->s;
		fd.events = POLLIN;
		fd.revents = 0;

		ret = p_poll(&fd, 1, st->timeout);

		if (ret == 1) {
			ret = p_recv(st->s, data, len, 0);
		} else if (ret == 0) {
			git_error_set(GIT_ERROR_NET,
				"could not read from socket: timed out");
			return GIT_TIMEOUT;
		}
	}

	if (ret < 0) {
		net_set_error("error receiving data from socket");
		return -1;
	}

	return ret;
}

static int file_close(git_stream *stream)
{
	git_stream_file *st = (git_stream_file *) stream;
	int error;

	if (st->owned)
		close(st->fd);

	st->fd = -1;
	return 0;
}

static void file_free(git_stream *stream)
{
	git_stream_file *st = (git_stream_file *) stream;

	git__free(st);
}

static int git_stream_file_new(git_stream **out)
{
	git_stream_file *st;

	GIT_ASSERT_ARG(out);

	st = git__calloc(1, sizeof(git_stream_file));
	GIT_ERROR_CHECK_ALLOC(st);

	st->parent.version = GIT_STREAM_VERSION;
	st->parent.write = file_write;
	st->parent.read = file_read;
	st->parent.close = file_close;
	st->parent.free = file_free;
	st->fd = -1;

	*out = (git_stream *) st;
	return 0;
}
