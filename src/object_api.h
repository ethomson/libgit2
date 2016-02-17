/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_object_api_h
#define INCLUDE_object_api_h

extern int git_commit_dup(git_commit **out, git_commit *source);

extern int git_tree_dup(git_tree **out, git_tree *source);

extern int git_tag_dup(git_tag **out, git_tag *source);

extern int git_blob_dup(git_blob **out, git_blob *source);

#endif
