/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_diff_h__
#define INCLUDE_diff_h__

#include "git2/diff.h"
#include "git2/sys/diff.h"

#include "common.h"
#include "vector.h"
#include "pool.h"
#include "iterator.h"

#define DIFF_OLD_PREFIX_DEFAULT "a/"
#define DIFF_NEW_PREFIX_DEFAULT "b/"

struct git_diff {
	git_refcount rc;

	git_repository *repo;
	git_diff_options opts;
	git_pool pool;
	git_vector deltas; /* vector of git_diff_delta */
	git_diff_perfdata perf;

	git_iterator_type_t old_src;
	git_iterator_type_t new_src;

	int (*strcomp)(const char *, const char *);
	int (*strncomp)(const char *, const char *, size_t);
	int (*pfxcomp)(const char *str, const char *pfx);
	int (*entrycomp)(const void *a, const void *b);

	int (*find_similar_fn)(git_diff *diff, const git_diff_find_options *options);
	void (*free_fn)(git_diff *diff);
};

extern void git_diff_addref(git_diff *diff);

extern void git_diff__set_ignore_case(git_diff *diff, bool ignore_case);

extern int git_diff_delta__cmp(const void *a, const void *b);
extern int git_diff_delta__casecmp(const void *a, const void *b);

extern const char *git_diff_delta__path(const git_diff_delta *delta);

#endif
