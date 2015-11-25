/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git2/index.h"

#include "common.h"
#include "diff.h"

static int diff_entry_cmp(const void *a, const void *b)
{
	const git_index_entry *entry_a = a;
	const git_index_entry *entry_b = b;

	return strcmp(entry_a->path, entry_b->path);
}

static int diff_entry_icmp(const void *a, const void *b)
{
	const git_index_entry *entry_a = a;
	const git_index_entry *entry_b = b;

	return strcasecmp(entry_a->path, entry_b->path);
}

void git_diff__set_ignore_case(git_diff *diff, bool ignore_case)
{
	if (!ignore_case) {
		diff->strcomp    = git__strcmp;
		diff->strncomp   = git__strncmp;
		diff->pfxcomp    = git__prefixcmp;
		diff->entrycomp  = diff_entry_cmp;

		diff->opts.flags &= ~GIT_DIFF_IGNORE_CASE;

		git_vector_set_cmp(&diff->deltas, git_diff_delta__cmp);
	} else {
		diff->strcomp    = git__strcasecmp;
		diff->strncomp   = git__strncasecmp;
		diff->pfxcomp    = git__prefixcmp_icase;
		diff->entrycomp  = diff_entry_icmp;

		diff->opts.flags |= GIT_DIFF_IGNORE_CASE;

		git_vector_set_cmp(&diff->deltas, git_diff_delta__casecmp);
	}

	git_vector_sort(&diff->deltas);
}

void git_diff_addref(git_diff *diff)
{
	GIT_REFCOUNT_INC(diff);
}

void git_diff_free(git_diff *diff)
{
	if (!diff)
		return;

	GIT_REFCOUNT_DEC(diff, diff->free_fn);
}

GIT_INLINE(const char *) diff_delta__path(const git_diff_delta *delta)
{
	const char *str = delta->old_file.path;

	if (!str ||
		delta->status == GIT_DELTA_ADDED ||
		delta->status == GIT_DELTA_RENAMED ||
		delta->status == GIT_DELTA_COPIED)
		str = delta->new_file.path;

	return str;
}

const char *git_diff_delta__path(const git_diff_delta *delta)
{
	return diff_delta__path(delta);
}

int git_diff_delta__cmp(const void *a, const void *b)
{
	const git_diff_delta *da = a, *db = b;
	int val = strcmp(diff_delta__path(da), diff_delta__path(db));
	return val ? val : ((int)da->status - (int)db->status);
}

int git_diff_delta__casecmp(const void *a, const void *b)
{
	const git_diff_delta *da = a, *db = b;
	int val = strcasecmp(diff_delta__path(da), diff_delta__path(db));
	return val ? val : ((int)da->status - (int)db->status);
}

size_t git_diff_num_deltas(const git_diff *diff)
{
	assert(diff);
	return diff->deltas.length;
}

size_t git_diff_num_deltas_of_type(const git_diff *diff, git_delta_t type)
{
	size_t i, count = 0;
	const git_diff_delta *delta;

	assert(diff);

	git_vector_foreach(&diff->deltas, i, delta)
		count += (delta->status == type);

	return count;
}

int git_diff_is_sorted_icase(const git_diff *diff)
{
	assert(diff);
	return (diff->opts.flags & GIT_DIFF_IGNORE_CASE) != 0;
}

int git_diff_find_similar(
	git_diff *diff,
	const git_diff_find_options *options)
{
	assert(diff);
	return diff->find_similar_fn ? diff->find_similar_fn(diff, options) : 0;
}

int git_diff_get_perfdata(git_diff_perfdata *out, const git_diff *diff)
{
	GITERR_CHECK_VERSION(out, GIT_DIFF_PERFDATA_VERSION, "git_diff_perfdata");
	out->stat_calls = diff->perf.stat_calls;
	out->oid_calculations = diff->perf.oid_calculations;
	return 0;
}

const git_diff_delta *git_diff_get_delta(const git_diff *diff, size_t idx)
{
	assert(diff);
	return git_vector_get(&diff->deltas, idx);
}
