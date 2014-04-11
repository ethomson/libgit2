#include "clar_libgit2.h"
#include "posix.h"

static void do_symlink(const char *old, const char *new)
{
	cl_must_pass(symlink(old, new));
}

static void do_hardlink(const char *old, const char *new)
{
	cl_must_pass(link(old, new));
}

void test_core_link__stat_symlink(void)
{
	struct stat st;

	cl_git_rewritefile("stat_target", "This is the target of a symbolic link.\n");
	do_symlink("stat_target", "stat_symlink");

	cl_must_pass(p_stat("stat_target", &st));
	cl_assert(S_ISREG(st.st_mode));
	cl_assert_equal_i(39, st.st_size);

	cl_must_pass(p_stat("stat_symlink", &st));
	cl_assert(S_ISREG(st.st_mode));
	cl_assert_equal_i(39, st.st_size);
}

void test_core_link__stat_dangling_symlink(void)
{
	struct stat st;

	do_symlink("stat_nonexistent", "stat_dangling");

	cl_must_fail(p_stat("stat_nonexistent", &st));
	cl_must_fail(p_stat("stat_dangling", &st));
}

void test_core_link__lstat_symlink(void)
{
	struct stat st;

	cl_git_rewritefile("lstat_target", "This is the target of a symbolic link.\n");
	do_symlink("lstat_target", "lstat_symlink");

	cl_must_pass(p_lstat("lstat_target", &st));
	cl_assert(S_ISREG(st.st_mode));
	cl_assert_equal_i(39, st.st_size);

	cl_must_pass(p_lstat("lstat_symlink", &st));
	cl_assert(S_ISLNK(st.st_mode));
	cl_assert_equal_i(strlen("lstat_target"), st.st_size);
}

void test_core_link__lstat_dangling_symlink(void)
{
	struct stat st;

	do_symlink("lstat_nonexistent", "lstat_dangling");

	cl_must_fail(p_lstat("lstat_nonexistent", &st));

	cl_must_pass(p_lstat("lstat_dangling", &st));
	cl_assert(S_ISLNK(st.st_mode));
	cl_assert_equal_i(strlen("lstat_nonexistent"), st.st_size);
}

void test_core_link__stat_hardlink(void)
{
	struct stat st;

	cl_git_rewritefile("hardlink1", "This file has many names!\n");
	do_hardlink("hardlink1", "hardlink2");

	cl_must_pass(p_stat("hardlink1", &st));
	cl_assert(S_ISREG(st.st_mode));
	cl_assert_equal_i(26, st.st_size);

	cl_must_pass(p_stat("hardlink2", &st));
	cl_assert(S_ISREG(st.st_mode));
	cl_assert_equal_i(26, st.st_size);
}

