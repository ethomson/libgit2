#include "clar_libgit2.h"

#include "patch_common.h"

void test_patch_print__from_patchfile(void)
{
	git_patch *patch;
	git_buf buf = GIT_BUF_INIT;

	cl_git_pass(git_patch_from_patchfile(&patch, PATCH_ORIGINAL_TO_CHANGE_MIDDLE, strlen(PATCH_ORIGINAL_TO_CHANGE_MIDDLE)));
	cl_git_pass(git_patch_to_buf(&buf, patch));

	cl_assert_equal_s(PATCH_ORIGINAL_TO_CHANGE_MIDDLE, buf.ptr);

	git_patch_free(patch);
	git_buf_free(&buf);
}
