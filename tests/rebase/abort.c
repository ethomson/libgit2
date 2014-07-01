#include "clar_libgit2.h"
#include "git2/rebase.h"
#include "posix.h"

#include <fcntl.h>

#define APPLY_REPO_PATH "rebase-apply"
#define MERGE_REPO_PATH "rebase-merge"

static git_repository *repo;

static git_oid orig_head_id;
static git_oid master_head_id;

// Fixture setup and teardown
void test_rebase_abort__initialize(void)
{
	git_oid_fromstr(&orig_head_id, "00783e2307458bb15a11595126704e037e31aee1");
	git_oid_fromstr(&master_head_id, "4dfd451f933e4cb1ca2338b9fffebada97f7b2cc");
}

void test_rebase_abort__cleanup(void)
{
	cl_git_sandbox_cleanup();
}

static void test_abort(int state, bool detached)
{
	git_reference *head_ref, *branch_ref = NULL;
	git_signature *signature;
	git_status_list *statuslist;
	git_reflog *reflog;
	const git_reflog_entry *reflog_entry;
		
	cl_assert_equal_i(state, git_repository_state(repo));
	
	cl_git_pass(git_signature_new(&signature, "Rebaser", "rebaser@example.com", 1404157834, -400));
	cl_git_pass(git_rebase_abort(repo, signature));
	
	cl_assert_equal_i(GIT_REPOSITORY_STATE_NONE, git_repository_state(repo));
	
	cl_git_pass(git_reference_lookup(&head_ref, repo, "HEAD"));
	
	if (detached)
		cl_assert_equal_oid(&orig_head_id, git_reference_target(head_ref));
	else {
		cl_assert_equal_s("refs/heads/branch", git_reference_symbolic_target(head_ref));
		cl_git_pass(git_reference_lookup(&branch_ref, repo, git_reference_symbolic_target(head_ref)));
		cl_assert_equal_oid(&orig_head_id, git_reference_target(branch_ref));
	}

	git_status_list_new(&statuslist, repo, NULL);
	cl_assert_equal_i(0, git_status_list_entrycount(statuslist));
	git_status_list_free(statuslist);
	
	cl_git_pass(git_reflog_read(&reflog, repo, "HEAD"));
	cl_assert_equal_i(11, git_reflog_entrycount(reflog));

	cl_assert(reflog_entry = git_reflog_entry_byindex(reflog, 0));
	cl_assert_equal_oid(&master_head_id, git_reflog_entry_id_old(reflog_entry));
	cl_assert_equal_oid(&orig_head_id, git_reflog_entry_id_new(reflog_entry));
	cl_assert_equal_s("rebase: aborting", git_reflog_entry_message(reflog_entry));

	git_reflog_free(reflog);
	git_reference_free(head_ref);
	git_reference_free(branch_ref);
	git_signature_free(signature);
}

void test_rebase_abort__apply(void)
{
	repo = cl_git_sandbox_init(APPLY_REPO_PATH);
	test_abort(GIT_REPOSITORY_STATE_REBASE, 0);
}

void test_rebase_abort__merge(void)
{
	repo = cl_git_sandbox_init(MERGE_REPO_PATH);
	test_abort(GIT_REPOSITORY_STATE_REBASE_MERGE, 0);
}

void test_rebase_abort__orig_head_is_detached(void)
{
	repo = cl_git_sandbox_init(MERGE_REPO_PATH);
	cl_git_rewritefile("rebase-merge/.git/rebase-merge/head-name",
		"detached HEAD\n");
	test_abort(GIT_REPOSITORY_STATE_REBASE_MERGE, 1);
}

void test_rebase_abort__old_style_head_file(void)
{
	repo = cl_git_sandbox_init(MERGE_REPO_PATH);
	p_rename("rebase-merge/.git/rebase-merge/orig-head",
		"rebase-merge/.git/rebase-merge/head");
	test_abort(GIT_REPOSITORY_STATE_REBASE_MERGE, 0);
}
