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
	    capture_err : 1,
	    exclude_env : 1;

	char *cwd;
} git_process_options;

typedef enum {
	GIT_PROCESS_STATUS_NONE,
	GIT_PROCESS_STATUS_NORMAL,
	GIT_PROCESS_STATUS_ERROR
} git_process_result_status;

#define GIT_PROCESS_RESULT_INIT { GIT_PROCESS_STATUS_NONE }

typedef struct {
	git_process_result_status status;
	int exitcode;
	int signal;
} git_process_result;

#define CLI_PROCESS_OPTIONS_INIT {0}

/**
 * Create a new process.  The command to run should be specified as the
 * element of the `arg` array.  If `setup_pipe` is true, then this
 * process can be written to and its output read from.
 *
 * This function will add the given environment variables (in `env`)
 * to the current environment.  Operations on environment variables
 * are not thread safe, so you may not modify the environment during
 * this call.  You can avoid this by setting `exclude_env` in the
 * options and providing the entire environment yourself.
 *
 * @param out location to store the process
 * @param arg the command (with arguments) to run
 * @param env environment variables to add (or NULL)
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
 * @param result the result of the process or NULL
 * @param process the process to close
 */
extern int git_process_close(git_process_result *result, git_process *process);


/**
 * Place a human-readable error message in the given git buffer.
 *
 * @param msg the buffer to store the message
 * @param result the process result that produced an error
 */
extern int git_process_result_msg(git_buf *msg, git_process_result *result);

/**
 * Free a process structure
 *
 * @param process the process to free
 */
extern void git_process_free(git_process *process);

#endif /* CLIENT_process_h__ */
