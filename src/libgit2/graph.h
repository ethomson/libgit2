/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_graph_h__
#define INCLUDE_graph_h__

#include "common.h"

int git_graph__reachable_from_any(
	git_repository *repo,
	const git_oid *commit_id,
	const git_oid **descendants,
	size_t length);

#endif
