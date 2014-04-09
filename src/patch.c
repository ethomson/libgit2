#include "git2/patch.h"
#include "diff_patch.h"

#define parse_err(...) \
	( giterr_set(GITERR_PATCH, __VA_ARGS__), -1 )

typedef struct {
	const char *content;
	size_t content_len;

	const char *line;
	size_t line_len;
	size_t line_num;

	size_t remain;

	const char *default_name;
} patch_parse_ctx;


static void parse_advance_line(patch_parse_ctx *ctx)
{
	ctx->line += ctx->line_len;
	ctx->remain -= ctx->line_len;
	ctx->line_len = git__linenlen(ctx->line, ctx->remain);
	ctx->line_num++;
}

static void parse_advance_chars(patch_parse_ctx *ctx, size_t char_cnt)
{
	ctx->line += char_cnt;
	ctx->remain -= char_cnt;
	ctx->line_len -= char_cnt;
}

static char *wsdup(const char *line, size_t len)
{
	while(len > 0 && isspace(line[len-1]))
		len--;

	return git__strndup(line, len);
}

static int parse_header_git_oldname(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	patch->ofile.file->path = wsdup(ctx->line, ctx->line_len);
	GITERR_CHECK_ALLOC(patch->ofile.file->path);

	return 0;
}

static int parse_header_git_newname(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	patch->nfile.file->path = wsdup(ctx->line, ctx->line_len);
	GITERR_CHECK_ALLOC(patch->nfile.file->path);

	return 0;
}

static int parse_header_mode(
	uint16_t *mode,
	git_patch *patch,
	patch_parse_ctx *ctx,
	const char *desc)
{
	int32_t m;
	int ret;

	if (ctx->line_len < 1 || !git__isdigit(ctx->line[0]))
		return parse_err("invalid %s at line %d", desc, ctx->line_num);

	if ((ret = git__strtonl32(&m, ctx->line, ctx->line_len, NULL, 8)) >= 0)
		*mode = (uint16_t)m;

	return ret;
}

static int parse_header_git_index(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	const char *next;
	int error = 0;

	if ((next = git__strnchr(ctx->line, ctx->line_len, ' ')) == NULL)
		return 0;

	/* TODO: we try to parse the ids just as a sanity check, we should
	 * actually store them instead of throwing them away. 
	 */
	parse_advance_chars(ctx, (next - ctx->line) + 1);

	if ((error = parse_header_mode(
		&patch->ofile.file->mode, patch, ctx, "index mode")) < 0)
		return error;

	return 0;
}

static int parse_header_git_oldmode(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	return parse_header_mode(
		&patch->ofile.file->mode, patch, ctx, "old mode");
}

static int parse_header_git_newmode(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	return parse_header_mode(
		&patch->nfile.file->mode, patch, ctx, "new mode");
}

static int parse_header_git_deletedfilemode(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	free((char *)patch->ofile.file->path);

	patch->ofile.file->path = NULL;
	patch->delta->status = GIT_DELTA_DELETED;

	return parse_header_mode(
		&patch->ofile.file->mode, patch, ctx, "deleted file mode");
}

static int parse_header_git_newfilemode(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	free((char *)patch->nfile.file->path);

	patch->nfile.file->path = NULL;
	patch->delta->status = GIT_DELTA_ADDED;

	return parse_header_mode(
		&patch->nfile.file->mode, patch, ctx, "new file mode");
}

static int parse_header_renamefrom(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	patch->ofile.file->path = wsdup(ctx->line, ctx->line_len);
	GITERR_CHECK_ALLOC(patch->ofile.file->path);

	return 0;
}

static int parse_header_renameto(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	patch->nfile.file->path = wsdup(ctx->line, ctx->line_len);
	GITERR_CHECK_ALLOC(patch->nfile.file->path);

	return 0;
}

typedef struct {
	const char *str;
	int (*fn)(git_patch *, patch_parse_ctx *);
} header_git_op;

static const header_git_op header_git_ops[] = {
	{ "@@ -", NULL },
	{ "--- ", parse_header_git_oldname },
	{ "+++ ", parse_header_git_newname },
	{ "index ", parse_header_git_index },
	{ "old mode ", parse_header_git_oldmode },
	{ "new mode ", parse_header_git_newmode },
	{ "deleted file mode ", parse_header_git_deletedfilemode },
	{ "new file mode ", parse_header_git_newfilemode },
	{ "rename from ", parse_header_renamefrom },
	{ "rename to ", parse_header_renameto },
	{ "rename old ", parse_header_renamefrom },
	{ "rename new ", parse_header_renameto },
};

static int parse_header_git(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	size_t i;
	int error = 0;

	/* TODO: parse the diff --git line, get the default name */

	for (parse_advance_line(ctx); ctx->remain > 0; parse_advance_line(ctx)) {
		if (ctx->line_len == 0 || ctx->line[ctx->line_len - 1] != '\n')
			break;

		for (i = 0; i < ARRAY_SIZE(header_git_ops); i++) {
			const header_git_op *op = &header_git_ops[i];
			size_t op_len = strlen(op->str);

			if (memcmp(ctx->line, op->str, min(op_len, ctx->line_len)) != 0)
				continue;

			/* Do not advance if this is the patch separator */
			if (op->fn == NULL)
				goto done;

			parse_advance_chars(ctx, op_len);

			if ((error = op->fn(patch, ctx)) < 0)
				goto done;

			break;
		}
	}

done:
	return error;
}

static int parse_patch_header(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	int error = 0;

	for (ctx->line = ctx->content; ctx->remain > 0; parse_advance_line(ctx)) {
		if ((ctx->line_len =
			git__linenlen(ctx->line, ctx->remain)) == 0)
			break;

		/* This line is too short to be a patch header. */
		if (ctx->line_len < 6)
			continue;

		/* TODO : unconnected patch fragments, memcmp("@@ -") == 0 */

		/* This buffer is too short to contain a patch. */
		if (ctx->remain < ctx->line_len + 6)
			break;

		if (ctx->line_len >= 11 && memcmp(ctx->line, "diff --git ", 11) == 0) {
			if ((error = parse_header_git(patch, ctx)) < 0)
				goto done;

			if (!patch->ofile.file->path && !patch->nfile.file->path) {
				/* TODO: update old / new paths with default name */

				error = parse_err("git diff header lacks old / new names");
				goto done;
			}

			break;
		} else {
			error = parse_err(
				"Non-git unified patches are not supported at line %d",
				ctx->line_num);
			goto done;
		}
	}

done:
	return error;
}

static int parse_advance_expected(
	patch_parse_ctx *ctx,
	const char *expected,
	size_t expected_len)
{
	if (ctx->line_len < expected_len)
		return -1;

	if (memcmp(ctx->line, expected, expected_len) != 0)
		return -1;

	parse_advance_chars(ctx, expected_len);
	return 0;
}

static int parse_number(size_t *out, patch_parse_ctx *ctx)
{
	const char *end;
	int64_t num;

	if (!git__isdigit(ctx->line[0]))
		return -1;

	if (git__strtonl64(&num, ctx->line, ctx->line_len, &end, 10) < 0)
		return -1;

	if (num < 0)
		return -1;

	*out = (size_t)num;
	parse_advance_chars(ctx, (end - ctx->line));

	return 0;
}

static int parse_hunk_header(
	git_patch *patch,
	diff_patch_hunk *hunk,
	patch_parse_ctx *ctx)
{
	const char *line = ctx->line;
	size_t line_len = ctx->line_len;

	if (parse_advance_expected(ctx, "@@ -", 4) < 0 ||
		parse_number(&hunk->hunk.old_start, ctx) < 0)
		goto fail;

	if (ctx->line_len > 0 && ctx->line[0] == ',') {
		if (parse_advance_expected(ctx, ",", 1) < 0 ||
			parse_number(&hunk->hunk.old_lines, ctx) < 0)
			goto fail;
	}

	if (parse_advance_expected(ctx, " +", 2) < 0 ||
		parse_number(&hunk->hunk.new_start, ctx) < 0)
		goto fail;

	if (ctx->line_len > 0 && ctx->line[0] == ',') {
		if (parse_advance_expected(ctx, ",", 1) < 0 ||
			parse_number(&hunk->hunk.new_lines, ctx) < 0)
			goto fail;
	}

	if (parse_advance_expected(ctx, " @@", 3) < 0)
		goto fail;

	parse_advance_line(ctx);
	return 0;

fail:
	giterr_set(GITERR_PATCH, "Invalid patch hunk header at line %d",
		ctx->line_num);
	return -1;
}

static int parse_hunk_body(
	git_patch *patch,
	diff_patch_hunk *hunk,
	patch_parse_ctx *ctx)
{
	git_diff_line *line;
	int error = 0;

	for (;
		ctx->remain > 4 && memcmp(ctx->line, "@@ -", 4) != 0;
		parse_advance_line(ctx)) {
		int origin;

		switch (ctx->line[0]) {
		case ' ':
			origin = GIT_DIFF_LINE_CONTEXT;
			break;
		case '-':
			origin = GIT_DIFF_LINE_DELETION;
			break;
		case '+':
			origin = GIT_DIFF_LINE_ADDITION;
			break;
		default:
			error = parse_err("Invalid patch hunk at line %d", ctx->line_num);
			goto done;
		}

		line = git_array_alloc(patch->lines);
		GITERR_CHECK_ALLOC(line);

		memset(line, 0x0, sizeof(git_diff_line));

		line->content = ctx->line + 1;
		line->content_len = ctx->line_len - 1;
		line->content_offset = ctx->content_len - ctx->remain;
		line->origin = origin;

		hunk->line_count++;
	}

done:
	return error;
}

static int parse_patch_body(
	git_patch *patch,
	patch_parse_ctx *ctx)
{
	diff_patch_hunk *hunk;
	int error = 0;

	for (; ctx->line_len > 4 && memcmp(ctx->line, "@@ -", 4) == 0; ) {

		hunk = git_array_alloc(patch->hunks);
		GITERR_CHECK_ALLOC(hunk);

		hunk->line_start = git_array_size(patch->lines);
		hunk->line_count = 0;

		if ((error = parse_hunk_header(patch, hunk, ctx)) < 0 ||
			(error = parse_hunk_body(patch, hunk, ctx)) < 0)
			goto done;
	}

done:
	return error;
}

static int check_patch(git_patch *patch)
{
	if (patch->ofile.file->path && patch->nfile.file->path) {
		if (!patch->nfile.file->mode)
			patch->nfile.file->mode = patch->ofile.file->mode;
	}

	return 0;
}

int git_patch_from_patchfile(
	git_patch **out,
	const char *content,
	size_t content_len)
{
	patch_parse_ctx ctx = {0};
	git_patch *patch;
	int error = 0;

	*out = NULL;

	patch = git__calloc(1, sizeof(git_patch));
	GITERR_CHECK_ALLOC(patch);

	patch->delta = git__calloc(1, sizeof(git_diff_delta));
	patch->ofile.file = git__calloc(1, sizeof(git_diff_file));
	patch->nfile.file = git__calloc(1, sizeof(git_diff_file));

	ctx.content = content;
	ctx.content_len = content_len;
	ctx.remain = content_len;

	if ((error = parse_patch_header(patch, &ctx)) < 0 ||
		(error = parse_patch_body(patch, &ctx)) < 0 ||
		(error = check_patch(patch)) < 0)
		goto done;

	*out = patch;

done:
	return error;
}
