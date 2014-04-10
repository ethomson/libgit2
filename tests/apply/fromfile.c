#include "clar_libgit2.h"
#include "git2/sys/repository.h"

#include "apply.h"
#include "repository.h"
#include "buf_text.h"

#include "apply_common.h"

static git_repository *repo = NULL;

void test_apply_fromfile__initialize(void)
{
	repo = cl_git_sandbox_init("renames");
}

void test_apply_fromfile__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

static int apply_patchfile(
	const char *old,
	const char *new,
	const char *patch_expected,
	const git_diff_options *diff_opts)
{
	git_patch *patch_fromdiff, *patch_fromfile;
	git_buf result = GIT_BUF_INIT;
	git_buf patchbuf = GIT_BUF_INIT;
	char *filename;
	unsigned int mode;
	int error;

	cl_git_pass(git_patch_from_buffers(&patch_fromdiff,
		old, old ? strlen(old) : 0, "file.txt",
		new, new ? strlen(new) : 0, "file.txt",
		diff_opts));
	cl_git_pass(git_patch_to_buf(&patchbuf, patch_fromdiff));

	cl_assert_equal_s(patch_expected, patchbuf.ptr);

	cl_git_pass(git_patch_from_patchfile(&patch_fromfile,
		patchbuf.ptr, patchbuf.size));

	error = git_apply__patch(&result, &filename, &mode, old, old ? strlen(old) : 0, patch_fromfile);

	if (error == 0 && new == NULL) {
		cl_assert_equal_i(0, result.size);
		cl_assert_equal_p(NULL, filename);
		cl_assert_equal_i(0, mode);
	} else {
		cl_assert_equal_s(new, result.ptr);
		cl_assert_equal_s("b/file.txt", filename);
		cl_assert_equal_i(0100644, mode);
	}

	git__free(filename);
	git_buf_free(&result);
	git_buf_free(&patchbuf);
	git_patch_free(patch_fromdiff);
	git_patch_free(patch_fromfile);

	return error;
}

void test_apply_fromfile__change_middle(void)
{
	cl_git_pass(apply_patchfile(FILE_ORIGINAL, FILE_CHANGE_MIDDLE,
		PATCH_ORIGINAL_TO_CHANGE_MIDDLE, NULL));
}

void test_apply_fromfile__change_middle_nocontext(void)
{
	git_diff_options diff_opts = GIT_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_pass(apply_patchfile(FILE_ORIGINAL, FILE_CHANGE_MIDDLE,
		PATCH_ORIGINAL_TO_CHANGE_MIDDLE_NOCONTEXT, &diff_opts));
}

void test_apply_fromfile__change_firstline(void)
{
	cl_git_pass(apply_patchfile(FILE_ORIGINAL, FILE_CHANGE_FIRSTLINE,
		PATCH_ORIGINAL_TO_CHANGE_FIRSTLINE, NULL));
}

void test_apply_fromfile__lastline(void)
{
	cl_git_pass(apply_patchfile(FILE_ORIGINAL, FILE_CHANGE_LASTLINE,
		PATCH_ORIGINAL_TO_CHANGE_LASTLINE, NULL));
}

void test_apply_fromfile__prepend(void)
{
	cl_git_pass(apply_patchfile(FILE_ORIGINAL, FILE_PREPEND,
		PATCH_ORIGINAL_TO_PREPEND, NULL));
}

void test_apply_fromfile__prepend_nocontext(void)
{
	git_diff_options diff_opts = GIT_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_pass(apply_patchfile(FILE_ORIGINAL, FILE_PREPEND,
		PATCH_ORIGINAL_TO_PREPEND_NOCONTEXT, &diff_opts));
}

void test_apply_fromfile__append(void)
{
	cl_git_pass(apply_patchfile(FILE_ORIGINAL, FILE_APPEND,
		PATCH_ORIGINAL_TO_APPEND, NULL));
}

void test_apply_fromfile__append_nocontext(void)
{
	git_diff_options diff_opts = GIT_DIFF_OPTIONS_INIT;
	diff_opts.context_lines = 0;

	cl_git_pass(apply_patchfile(FILE_ORIGINAL, FILE_APPEND,
		PATCH_ORIGINAL_TO_APPEND_NOCONTEXT, &diff_opts));
}

void test_apply_fromfile__prepend_and_append(void)
{
	cl_git_pass(apply_patchfile(FILE_ORIGINAL, FILE_PREPEND_AND_APPEND,
		PATCH_ORIGINAL_TO_PREPEND_AND_APPEND, NULL));
}

void test_apply_fromfile__to_empty_file(void)
{
	cl_git_pass(apply_patchfile(FILE_ORIGINAL, "", PATCH_ORIGINAL_TO_EMPTY_FILE, NULL));
}

void test_apply_fromfile__from_empty_file(void)
{
	cl_git_pass(apply_patchfile("", FILE_ORIGINAL, PATCH_EMPTY_FILE_TO_ORIGINAL, NULL));
}

void test_apply_fromfile__add(void)
{
	cl_git_pass(apply_patchfile(NULL, FILE_ORIGINAL, PATCH_ADD_ORIGINAL, NULL));
}

void test_apply_fromfile__delete(void)
{
	cl_git_pass(apply_patchfile(FILE_ORIGINAL, NULL, PATCH_DELETE_ORIGINAL, NULL));
}

static void apply_rename_patchfile(
	const char *old,
	const char *new,
	const char *patchfile,
	const char *filename_expected,
	unsigned int mode_expected)
{
	git_patch *patch;
	git_buf result = GIT_BUF_INIT;
	git_buf patchbuf = GIT_BUF_INIT;
	char *filename;
	unsigned int mode;

	cl_git_pass(git_patch_from_patchfile(&patch, patchfile, strlen(patchfile)));
	cl_git_pass(git_apply__patch(&result, &filename, &mode, old, strlen(old), patch));

	cl_assert_equal_s(new, result.ptr);
	cl_assert_equal_s(filename_expected, filename);
	cl_assert_equal_i(mode_expected, mode);

	git__free(filename);
	git_buf_free(&result);
	git_buf_free(&patchbuf);
	git_patch_free(patch);
}

void test_apply_fromfile__rename_exact(void)
{
	apply_rename_patchfile(FILE_ORIGINAL, FILE_ORIGINAL, PATCH_RENAME_EXACT, "b/newfile.txt", 0);
}

void test_apply_fromfile__rename_similar(void)
{
	apply_rename_patchfile(FILE_ORIGINAL, FILE_CHANGE_MIDDLE, PATCH_RENAME_SIMILAR, "b/newfile.txt", 0100644);
}

void test_apply_fromfile__rename_similar_quotedname(void)
{
	apply_rename_patchfile(FILE_ORIGINAL, FILE_CHANGE_MIDDLE, PATCH_RENAME_SIMILAR_QUOTEDNAME,
		"b/foo\"bar.txt", 0100644);
}
