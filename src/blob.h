/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_blob_h__
#define INCLUDE_blob_h__

#include "git2/blob.h"
#include "repository.h"
#include "odb.h"
#include "fileops.h"

struct git_blob {
	git_object object;
	git_odb_object *odb_object;
};

static git_oid empty_blob = {{ 0xe6, 0x9d, 0xe2, 0x9b, 0xb2, 0xd1, 0xd6, 0x43, 0x4b, 0x8b,
			       0x29, 0xae, 0x77, 0x5a, 0xd8, 0xc2, 0xe4, 0x8c, 0x53, 0x91 }};


void git_blob__free(void *blob);
int git_blob__parse(void *blob, git_odb_object *obj);
int git_blob__getbuf(git_buf *buffer, git_blob *blob);

extern int git_blob__create_from_paths(
	git_oid *out_oid,
	struct stat *out_st,
	git_repository *repo,
	const char *full_path,
	const char *hint_path,
	mode_t hint_mode,
	bool apply_filters);

#endif
