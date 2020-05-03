#include "git2client_tests.h"
#include "process.h"
#include "vector.h"

static git_buf accumulator = GIT_BUF_INIT;
static git_vector env_result = GIT_VECTOR_INIT;

void test_process_env__initialize(void)
{
	cl_git_pass(git_vector_init(&env_result, 32, git__strcmp_cb));
}

void test_process_env__cleanup(void)
{
	git_vector_free(&env_result);
	git_buf_dispose(&accumulator);
}

static void run_env(const char **env_array, size_t env_len, bool exclude_env)
{
	const char *args_array[] = { "/usr/bin/env" };
	git_strarray args = { (char **)args_array, 1 };
	git_strarray env = { (char **)env_array, env_len };

	git_process *process;
	git_process_options opts = GIT_PROCESS_OPTIONS_INIT;
	git_process_result result = GIT_PROCESS_RESULT_INIT;

	char buf[1024], *tok;
	ssize_t ret;

	opts.capture_out = 1;
	opts.exclude_env = exclude_env;

	cl_git_pass(git_process_new(&process, &args, &env, &opts));
	cl_git_pass(git_process_start(process));

	while ((ret = git_process_read(process, buf, 1024)) > 0)
		cl_git_pass(git_buf_put(&accumulator, buf, (size_t)ret));

	cl_git_pass(ret);

	git_process_close(&result, process);

	cl_assert_equal_i(GIT_PROCESS_STATUS_NORMAL, result.status);
	cl_assert_equal_i(0, result.exitcode);
	cl_assert_equal_i(0, result.signal);

	for (tok = strtok(accumulator.ptr, "\n"); tok; tok = strtok(NULL, "\n"))
		cl_git_pass(git_vector_insert(&env_result, tok));

	git_process_free(process);
}

void test_process_env__can_add_env(void)
{
	const char *env_array[] = { "TEST_NEW_ENV=added", "TEST_OTHER_ENV=also_added" };
	run_env(env_array, 2, false);

	cl_git_pass(git_vector_search(NULL, &env_result, "TEST_NEW_ENV=added"));
	cl_git_pass(git_vector_search(NULL, &env_result, "TEST_OTHER_ENV=also_added"));
}

void test_process_env__can_propagate_env(void)
{
	cl_setenv("TEST_NEW_ENV", "propagated");
	run_env(NULL, 0, false);

	cl_git_pass(git_vector_search(NULL, &env_result, "TEST_NEW_ENV=propagated"));
}

void test_process_env__can_remove_env(void)
{
	const char *env_array[] = { "TEST_NEW_ENV=" };
	char *str;
	size_t i;

	cl_setenv("TEST_NEW_ENV", "propagated");
	run_env(env_array, 1, false);

	git_vector_foreach(&env_result, i, str)
		cl_assert(git__prefixcmp(str, "TEST_NEW_ENV=") != 0);
}

void test_process_env__can_clear_env(void)
{
	const char *env_array[] = { "TEST_NEW_ENV=added", "TEST_OTHER_ENV=also_added" };

	run_env(env_array, 2, true);

	cl_assert_equal_i(2, env_result.length);
	cl_assert_equal_s("TEST_NEW_ENV=added", env_result.contents[0]);
	cl_assert_equal_s("TEST_OTHER_ENV=also_added", env_result.contents[1]);
}
