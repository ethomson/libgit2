/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>
#include <git2.h>

#include "git2_util.h"
#include "process.h"
#include "git2/strarray.h"

struct git_process {
	git_strarray arg;
	git_strarray env;

	unsigned int capture_in  : 1,
	             capture_out : 1,
	             capture_err : 1;

	pid_t pid;

	int child_in;
	int child_out;
	int child_err;
	int status;
};

GIT_INLINE(int) strarray_copy_with_null(git_strarray *out, git_strarray *in)
{
	size_t count;

	if (!in)
		return 0;

	GIT_ERROR_CHECK_ALLOC_ADD(&count, in->count, 1);

	out->strings = git__calloc(count, sizeof(char *));
	GIT_ERROR_CHECK_ALLOC(out->strings);

	if (git_strarray_copy_strings(out, in, in->count) < 0) {
		git__free(out->strings);
		return -1;
	}

	out->count = count;
	return 0;
}

int git_process_new(
	git_process **out,
	git_strarray *arg,
	git_strarray *env,
	git_process_options *opts)
{
	git_process *process;

	assert(out && arg && arg->count > 0);

	*out = NULL;

	process = git__calloc(sizeof(git_process), 1);
	GIT_ERROR_CHECK_ALLOC(process);

	if (strarray_copy_with_null(&process->arg, arg) < 0 ||
	    strarray_copy_with_null(&process->env, env) < 0) {
		git_process_free(process);
		return -1;
	}

	if (opts) {
		process->capture_in = opts->capture_in;
		process->capture_out = opts->capture_out;
		process->capture_err = opts->capture_err;
	}

	process->child_in  = -1;
	process->child_out = -1;
	process->child_err = -1;
	process->status    = -1;

	*out = process;
	return 0;
}

#define CLOSE_FD(fd) \
	if (fd >= 0) {     \
		close(fd); \
		fd = -1;   \
	}

static int read_status(int fd)
{
	size_t status_len = sizeof(int) * 2, read_len = 0;
	char buffer[status_len];
	int error, os_error, ret = -1;

	while (ret && read_len < status_len) {
		ret = read(fd, buffer + read_len, status_len - read_len);

		if (ret < 0 && errno != EAGAIN && errno != EINTR) {
			git_error_set(GIT_ERROR_OS, "could not read child status");
			return -1;
		}

		read_len += ret;
	}

	/* Immediate EOF indicates the exec succeeded. */
	if (read_len == 0)
		return 0;

	if (read_len < status_len) {
		git_error_set(GIT_ERROR_INVALID, "child status truncated");
		return -1;
	}

	memcpy(&error, &buffer[0], sizeof(int));
	memcpy(&os_error, &buffer[sizeof(int)], sizeof(int));

	errno = os_error;
	git_error_set(GIT_ERROR_OS, "could not exec");

	return error;
}

static void write_status(int fd, int error, int os_error)
{
	size_t status_len = sizeof(int) * 2, write_len = 0;
	char buffer[status_len];
	int ret;

	memcpy(&buffer[0], &error, sizeof(int));
	memcpy(&buffer[sizeof(int)], &os_error, sizeof(int));

	/* Do our best effort to write all the status. */
	while (write_len < status_len) {
		ret = write(fd, buffer + write_len, status_len - write_len);

		if (ret <= 0)
			break;

		write_len += ret;
	}
}

int git_process_start(git_process *process)
{
	int in[2] = { -1, -1 }, out[2] = { -1, -1 },
	    err[2] = { -1, -1 }, status[2] = { -1, -1 };
	int fdflags, os_error, state, error;
	pid_t pid;

	/* Set up the pipes to read from/write to the process */
	if ((process->capture_in && pipe(in) < 0) ||
	    (process->capture_out && pipe(out) < 0) ||
	    (process->capture_err && pipe(err) < 0)) {
		git_error_set(GIT_ERROR_OS, "could not create pipe");
		goto on_error;
	}

	/* Set up a self-pipe for status from the forked process. */
	if (pipe(status) < 0 ||
	    (fdflags = fcntl(status[1], F_GETFD)) < 0 ||
	    fcntl(status[1], F_SETFD, fdflags | FD_CLOEXEC) < 0) {
		git_error_set(GIT_ERROR_OS, "could not create pipe");
		goto on_error;
	}

	switch (pid = fork()) {
	case -1:
		git_error_set(GIT_ERROR_OS, "could not fork");
		goto on_error;

	/* Child: start the process. */
	case 0:
		/* Close the opposing side of the pipes */
		CLOSE_FD(status[0]);

		if (process->capture_in) {
			CLOSE_FD(in[1]);
			dup2(in[0],  STDIN_FILENO);
		}

		if (process->capture_out) {
			CLOSE_FD(out[0]);
			dup2(out[1], STDOUT_FILENO);
		}

		if (process->capture_err) {
			CLOSE_FD(err[0]);
			dup2(err[1], STDERR_FILENO);
		}

		/*
		 * Exec the process and write the results back if the
		 * call fails.  If it succeeds, we'll close the status
		 * pipe (via CLOEXEC) and the parent will know.
		 */
		error = execve(process->arg.strings[0],
		               process->arg.strings,
			       process->env.count ? process->env.strings : NULL);
		os_error = errno;

		write_status(status[1], error, os_error);
		exit(0);

	/* Parent: make sure the child process exec'd correctly. */
	default:
		/* Close the opposing side of the pipes */
		CLOSE_FD(status[1]);

		if (process->capture_in) {
			CLOSE_FD(in[0]);
			process->child_in  = in[1];
		}

		if (process->capture_out) {
			CLOSE_FD(out[1]);
			process->child_out = out[0];
		}

		if (process->capture_err) {
			CLOSE_FD(err[1]);
			process->child_err = err[0];
		}

		/* Try to read the status */
		process->status = status[0];
		if ((error = read_status(status[0])) < 0) {
			waitpid(process->pid, &state, 0);
			goto on_error;
		}

		process->pid = pid;
		return 0;
	}

on_error:
	CLOSE_FD(in[0]);     CLOSE_FD(in[1]);
	CLOSE_FD(out[0]);    CLOSE_FD(out[1]);
	CLOSE_FD(err[0]);    CLOSE_FD(err[1]);
	CLOSE_FD(status[0]); CLOSE_FD(status[1]);
	return -1;
}

ssize_t git_process_read(git_process *process, void *buf, size_t count)
{
	ssize_t ret;

	assert(process && process->capture_out);

	if (count > SSIZE_MAX)
		count = SSIZE_MAX;

	if ((ret = read(process->child_out, buf, count)) < 0) {
		git_error_set(GIT_ERROR_OS, "could not read from child process");
		return -1;
	}

	return ret;
}

ssize_t git_process_write(git_process *process, const void *buf, size_t count)
{
	ssize_t ret;

	assert(process && process->capture_in);

	if (count > SSIZE_MAX)
		count = SSIZE_MAX;

	if ((ret = write(process->child_in, buf, count)) < 0) {
		git_error_set(GIT_ERROR_OS, "could not write to child process");
		return -1;
	}

	return ret;
}

void git_process_close(git_process *process)
{
	int state;

	if (!process->pid)
		return;

	waitpid(process->pid, &state, 0);

	CLOSE_FD(process->child_in);
	CLOSE_FD(process->child_out);
	CLOSE_FD(process->child_err);
	CLOSE_FD(process->status);

	process->pid = 0;
}

void git_process_free(git_process *process)
{
	if (!process)
		return;

	git_process_close(process);
	git__free(process);
}
