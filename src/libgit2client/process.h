/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#ifndef CLIENT_process_h__
#define CLIENT_process_h__

typedef struct git_process git_process;

typedef struct {
	int capture_in  : 1,
	    capture_out : 1,
	    capture_err : 1;
} git_process_options;

#define CLI_PROCESS_OPTIONS_INIT {0}

/**
 * Create a new process.  The command to run should be specified as the
 * element of the `arg` array.  If `setup_pipe` is true, then this
 * process can be written to and its output read from.
 *
 * @param out location to store the process
 * @param arg the command (with arguments) to run
 * @param env the environment (or NULL)
 * @param opts the options for creating the process
 * @return 0 or an error code
 */
extern int git_process_new(
	git_process **out,
	git_strarray *arg,
	git_strarray *env,
	git_process_options *opts);

/**
 * Start the process.
 *
 * @param process the process to start
 * @return 0 or an error code
 */
extern int git_process_start(git_process *process);

/**
 * Read from the process's stdout.  The process must have been created with
 * `setup_pipe` set to true.
 *
 * @param process the process to read from
 * @param buf the buf to read into
 * @param count maximum number of bytes to read
 * @return number of bytes read or an error code
 */
extern ssize_t git_process_read(git_process *process, void *buf, size_t count);

/**
 * Write to the process's stdin.  The process must have been created with
 * `setup_pipe` set to true.
 *
 * @param process the process to write to
 * @param buf the buf to write
 * @param count maximum number of bytes to write
 * @return number of bytes written or an error code
 */
extern ssize_t git_process_write(git_process *process, const void *buf, size_t count);

/**
 * Wait for the process to finish and close any input/output pipes.
 *
 * @param process the process to close
 */
extern void git_process_close(git_process *process);

/**
 * Free a process structure
 *
 * @param process the process to free
 */
extern void git_process_free(git_process *process);

#endif /* CLIENT_process_h__ */
