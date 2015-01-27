/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_attr_h__
#define INCLUDE_attr_h__

#include "attr_file.h"
#include "attrcache.h"

typedef struct {
	git_repository *repo;
	git_buf last_path;
	uint32_t last_flags;
	git_vector files;
} git_attrreader;

extern int git_attrreader_init(git_attrreader *out, git_repository *repo);
extern int git_attrreader_files(
	git_vector **out,
	git_attrreader *reader,
	const char *path,
	uint32_t flags);
extern int git_attrreader_get(
	const char **value,
	git_attrreader *reader,
	uint32_t flags,
	const char *pathname,
	const char *name);
extern int git_attrreader_get_many(
	const char **values,
	git_attrreader *reader,
	uint32_t flags,
	const char *pathname,
	size_t num_attr,
	const char **names);
extern void git_attrreader_free(git_attrreader *reader);

#endif
