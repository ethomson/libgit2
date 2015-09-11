#include "git2/patch.h"
#include "patch.h"

size_t git_patch_size(
	git_patch *patch,
	int include_context,
	int include_hunk_headers,
	int include_file_headers)
{
	size_t out;

	assert(patch);

	out = patch->content_size;

	if (!include_context)
		out -= patch->context_size;

	if (include_hunk_headers)
		out += patch->header_size;

	if (include_file_headers) {
		git_buf file_header = GIT_BUF_INIT;

		if (git_diff_delta__format_file_header(
			&file_header, patch->delta, NULL, NULL, 0) < 0)
			giterr_clear();
		else
			out += git_buf_len(&file_header);

		git_buf_free(&file_header);
	}

	return out;
}

int git_patch_line_stats(
	size_t *total_ctxt,
	size_t *total_adds,
	size_t *total_dels,
	const git_patch *patch)
{
	size_t totals[3], idx;

	memset(totals, 0, sizeof(totals));

	for (idx = 0; idx < git_array_size(patch->lines); ++idx) {
		git_diff_line *line = git_array_get(patch->lines, idx);
		if (!line)
			continue;

		switch (line->origin) {
		case GIT_DIFF_LINE_CONTEXT:  totals[0]++; break;
		case GIT_DIFF_LINE_ADDITION: totals[1]++; break;
		case GIT_DIFF_LINE_DELETION: totals[2]++; break;
		default:
			/* diff --stat and --numstat don't count EOFNL marks because
			* they will always be paired with a ADDITION or DELETION line.
			*/
			break;
		}
	}

	if (total_ctxt)
		*total_ctxt = totals[0];
	if (total_adds)
		*total_adds = totals[1];
	if (total_dels)
		*total_dels = totals[2];

	return 0;
}

static void git_patch__free(git_patch *patch)
{
	git_array_clear(patch->lines);
	git_array_clear(patch->hunks);

	git__free((char *)patch->binary.old_file.data);
	git__free((char *)patch->binary.new_file.data);

	if (patch->free_fn)
		patch->free_fn(patch);
}

void git_patch_free(git_patch *patch)
{
	if (patch)
		GIT_REFCOUNT_DEC(patch, git_patch__free);
}
