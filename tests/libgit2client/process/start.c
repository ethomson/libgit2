#include "git2client_tests.h"
#include "process.h"
#include "vector.h"

void test_process_start__returncode(void)
{
	const char *args_array[] = { "/usr/bin/false" };
	git_strarray args = { (char **)args_array, 1 };

	git_process *process;
	git_process_options opts = GIT_PROCESS_OPTIONS_INIT;
	git_process_result result = GIT_PROCESS_RESULT_INIT;

	cl_git_pass(git_process_new(&process, &args, NULL, &opts));
	cl_git_pass(git_process_start(process));
	git_process_close(&result, process);

	cl_assert_equal_i(GIT_PROCESS_STATUS_NORMAL, result.status);
	cl_assert_equal_i(1, result.exitcode);
	cl_assert_equal_i(0, result.signal);

	git_process_free(process);
}

void test_process_start__not_found(void)
{
	const char *args_array[] = { "/a/b/z/y/not_found" };
	git_strarray args = { (char **)args_array, 1 };

	git_process *process;
	git_process_options opts = GIT_PROCESS_OPTIONS_INIT;

	cl_git_pass(git_process_new(&process, &args, NULL, &opts));
	cl_git_fail(git_process_start(process));
	git_process_free(process);
}

void test_process_start__redirect_stdio(void)
{
	const char *args_array[] = { "/bin/cat" };
	git_strarray args = { (char **)args_array, 1 };

	git_process *process;
	git_process_options opts = GIT_PROCESS_OPTIONS_INIT;
	git_process_result result = GIT_PROCESS_RESULT_INIT;
	char buf[14];

	opts.capture_in = 1;
	opts.capture_out = 1;

	cl_git_pass(git_process_new(&process, &args, NULL, &opts));
	cl_git_pass(git_process_start(process));

	cl_assert_equal_i(13, git_process_write(process, "Hello, world.", 13));
	cl_assert_equal_i(13, git_process_read(process, buf, 13));

	buf[13] = '\0';
	cl_assert_equal_s("Hello, world.", buf);

	git_process_close(&result, process);

	cl_assert_equal_i(GIT_PROCESS_STATUS_NORMAL, result.status);
	cl_assert_equal_i(0, result.exitcode);
	cl_assert_equal_i(0, result.signal);

	git_process_free(process);
}

void test_process_start__catch_signal(void)
{
	const char *args_array[] = { "/bin/cat", "/etc/passwd" };
	git_strarray args = { (char **)args_array, 2 };

	git_process *process;
	git_process_options opts = GIT_PROCESS_OPTIONS_INIT;
	git_process_result result = GIT_PROCESS_RESULT_INIT;

	opts.capture_out = 1;

	cl_git_pass(git_process_new(&process, &args, NULL, &opts));
	cl_git_pass(git_process_start(process));
	git_process_close(&result, process);

	cl_assert_equal_i(GIT_PROCESS_STATUS_ERROR, result.status);
	cl_assert_equal_i(0, result.exitcode);
	cl_assert_equal_i(SIGPIPE, result.signal);

	git_process_free(process);
}

void test_process_start__can_chdir(void)
{
	const char *args_array[] = { "/bin/pwd" };
	git_strarray args = { (char **)args_array, 1 };

	git_process *process;
	git_process_options opts = GIT_PROCESS_OPTIONS_INIT;
	git_process_result result = GIT_PROCESS_RESULT_INIT;
	char buf[32];

	opts.cwd = "/";
	opts.capture_out = 1;

	cl_git_pass(git_process_new(&process, &args, NULL, &opts));
	cl_git_pass(git_process_start(process));

	cl_assert_equal_i(2, git_process_read(process, buf, 32));

	buf[3] = '\0';
	cl_assert_equal_s("/\n", buf);

	git_process_close(&result, process);

	cl_assert_equal_i(GIT_PROCESS_STATUS_NORMAL, result.status);
	cl_assert_equal_i(0, result.exitcode);
	cl_assert_equal_i(0, result.signal);

	git_process_free(process);
}

void test_process_start__cannot_chdir_to_nonexistent_dir(void)
{
	const char *args_array[] = { "/bin/pwd" };
	git_strarray args = { (char **)args_array, 1 };

	git_process *process;
	git_process_options opts = GIT_PROCESS_OPTIONS_INIT;

	opts.cwd = "/a/b/z/y/not_found";
	opts.capture_out = 1;

	cl_git_pass(git_process_new(&process, &args, NULL, &opts));
	cl_git_fail(git_process_start(process));
	git_process_free(process);
}
