/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git2/buffer.h"
#include "buffer.h"
#include "buf_text.h"

int git_buf_grow(git_buf *buffer, size_t target_size)
{
	return git_buf_try_grow(buffer, target_size, true);
}

void git_buf_dispose(git_buf *buf)
{
	if (!buf) return;

	if (buf->asize > 0 && buf->ptr != NULL && buf->ptr != git_buf__oom)
		git__free(buf->ptr);

	git_buf_init(buf, 0);
}

void git_buf_free(git_buf *buf)
{
	git_buf_dispose(buf);
}

int git_buf_set(git_buf *buf, const void *data, size_t len)
{
	size_t alloclen;

	if (len == 0 || data == NULL) {
		git_buf_clear(buf);
	} else {
		if (data != buf->ptr) {
			GIT_ERROR_CHECK_ALLOC_ADD(&alloclen, len, 1);
			ENSURE_SIZE(buf, alloclen);
			memmove(buf->ptr, data, len);
		}

		buf->size = len;
		if (buf->asize > buf->size)
			buf->ptr[buf->size] = '\0';

	}
	return 0;
}

int git_buf_is_binary(const git_buf *buf)
{
	return git_buf_text_is_binary(buf);
}

int git_buf_contains_nul(const git_buf *buf)
{
	return git_buf_text_contains_nul(buf);
}
