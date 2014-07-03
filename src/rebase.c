#include "common.h"
#include "buffer.h"
#include "repository.h"
#include "posix.h"
#include "filebuf.h"

#include <git2/types.h>
#include <git2/rebase.h>
#include <git2/commit.h>
#include <git2/reset.h>

#define REBASE_APPLY_DIR	"rebase-apply"
#define REBASE_MERGE_DIR	"rebase-merge"

#define HEAD_NAME_FILE		"head-name"
#define ORIG_HEAD_FILE		"orig-head"
#define HEAD_FILE			"head"
#define QUIET_FILE			"quiet"

#define REBASE_DIR_MODE		0777
#define REBASE_FILE_MODE	0666

typedef enum {
	GIT_REBASE_TYPE_APPLY = 1,
	GIT_REBASE_TYPE_MERGE = 2,
} git_rebase_type;

typedef struct {
	git_rebase_type type;
	char *state_path;
	
	int head_detached : 1;

	char *head_name;
	git_oid head_id;
} git_rebase_state;

int rebase_state_type(git_rebase_state *state, git_repository *repo)
{
	git_buf path = GIT_BUF_INIT;

	if (git_buf_joinpath(&path, repo->path_repository, REBASE_APPLY_DIR) < 0)
		return -1;

	if (git_path_isdir(git_buf_cstr(&path))) {
		state->type = GIT_REBASE_TYPE_APPLY;
		goto done;
	}

	git_buf_clear(&path);
	if (git_buf_joinpath(&path, repo->path_repository, REBASE_MERGE_DIR) < 0)
		return -1;

	if (git_path_isdir(git_buf_cstr(&path))) {
		state->type = GIT_REBASE_TYPE_MERGE;
		goto done;
	}

	git_buf_free(&path);
	return GIT_ENOTFOUND;

done:
	state->state_path = git_buf_detach(&path);
	git_buf_free(&path);

	return 0;
}

int rebase_state(git_rebase_state *state, git_repository *repo)
{
	git_buf path = GIT_BUF_INIT, head_name = GIT_BUF_INIT,
		orig_head = GIT_BUF_INIT;
	int state_path_len, error = -1;

	memset(state, 0x0, sizeof(git_rebase_state));

	if ((error = rebase_state_type(state, repo)) < 0)
		goto done;

	if ((error = git_buf_puts(&path, state->state_path)) < 0)
		goto done;

	state_path_len = git_buf_len(&path);
	
	if ((error = git_buf_joinpath(&path, path.ptr, HEAD_NAME_FILE)) < 0 ||
		(error = git_futils_readbuffer(&head_name, path.ptr)) < 0)
		goto done;
	
	git_buf_rtrim(&head_name);
	
	if (strcmp("detached HEAD", head_name.ptr) == 0)
		state->head_detached = 1;

	git_buf_truncate(&path, state_path_len);

	if ((error = git_buf_joinpath(&path, path.ptr, ORIG_HEAD_FILE)) < 0)
		goto done;

	if (!git_path_isfile(path.ptr)) {
		/* Previous versions of git.git used 'head' here; support that. */
		git_buf_truncate(&path, state_path_len);

		if ((error = git_buf_joinpath(&path, path.ptr, HEAD_FILE)) < 0)
			goto done;
	}

	if ((error = git_futils_readbuffer(&orig_head, path.ptr)) < 0)
		goto done;

	git_buf_rtrim(&orig_head);
	
	if ((error = git_oid_fromstr(&state->head_id, orig_head.ptr)) < 0)
		goto done;

	if (!state->head_detached)
		state->head_name = git_buf_detach(&head_name);

done:
	git_buf_free(&path);
	git_buf_free(&head_name);
	git_buf_free(&orig_head);
	return error;
}

void rebase_state_free(git_rebase_state *state)
{
	if (state == NULL)
		return;

	git__free(state->head_name);
	git__free(state);
}

int rebase_finish(git_repository *repo, git_rebase_state *state)
{
	const char *paths[] = {
		state->state_path
	};

	return git_repository__cleanup_files(repo, paths, 1);
}

static int rebase_setupfile(git_repository *repo, const char *filename, const char *fmt, ...)
{
	git_buf path = GIT_BUF_INIT,
		contents = GIT_BUF_INIT;
	va_list ap;
	int error;

	va_start(ap, fmt);
	git_buf_vprintf(&contents, fmt, ap);
	va_end(ap);

	if ((error = git_buf_joinpath(&path, repo->path_repository, REBASE_MERGE_DIR)) == 0 &&
		(error = git_buf_joinpath(&path, path.ptr, filename)) == 0)
		error = git_futils_writebuffer(&contents, path.ptr, O_RDWR|O_CREAT, REBASE_FILE_MODE);

	git_buf_free(&path);
	git_buf_free(&contents);

	return error;
}

static int rebase_setup(
	git_repository *repo,
	const git_rebase_options *opts)
{
	git_buf state_path = GIT_BUF_INIT;
	int error;

	if (git_buf_joinpath(&state_path, repo->path_repository, REBASE_MERGE_DIR) < 0)
		return -1;

	if ((error = p_mkdir(state_path.ptr, REBASE_DIR_MODE)) < 0) {
		giterr_set(GITERR_OS, "Failed to create rebase directory '%s'",
			state_path.ptr);
		goto done;
	}

	if ((error = rebase_setupfile(repo, QUIET_FILE, opts->quiet ? "t\n" : "\n")) < 0)
		goto done;

	if ((error = rebase_setupfile(repo, )))

done:
	if (error < 0)
		git_repository__cleanup_files(repo, (const char **)&state_path.ptr, 1);

	git_buf_free(&state_path);

	return error;
}

int git_rebase(
	git_repository *repo,
	const git_merge_head *ours,
	const git_merge_head *upstream,
	const git_merge_head *onto,
	const git_rebase_options *opts)
{
	int error;

	assert(repo && ours && upstream);

	/* TODO: allow NULL upstream? (read config) */

	if (!onto)
		upstream = onto;

	if ((error = rebase_setup(repo, opts)) < 0)
		goto done;

done:
	return error;
}

int git_rebase_abort(git_repository *repo, git_signature *signature)
{
	git_rebase_state state;
	git_reference *head_ref = NULL;
	git_commit *head_commit = NULL;
	int error = 0;

	if ((error = rebase_state(&state, repo)) < 0)
		goto done;

	error = state.head_detached ?
		git_reference_create(&head_ref, repo, GIT_HEAD_FILE,
			 &state.head_id, 1, signature, "rebase: aborting") :
		git_reference_symbolic_create(
			&head_ref, repo, GIT_HEAD_FILE, state.head_name, 1,
			signature, "rebase: aborting");

	if (error < 0)
		goto done;
	
	if ((error = git_commit_lookup(&head_commit, repo, &state.head_id)) < 0 ||
		(error = git_reset(repo, (git_object *)head_commit,
			GIT_RESET_HARD, signature, NULL)) < 0)
		goto done;

	error = rebase_finish(repo, &state);

done:
	git_commit_free(head_commit);
	git_reference_free(head_ref);
	return error;
}

