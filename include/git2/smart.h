/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_smart_h__
#define INCLUDE_git_smart_h__

#include "common.h"
#include "types.h"
#include "oid.h"

/**
 * @file git2/smart.h
 * @brief Git smart transport routines
 * @defgroup git_merge Git smart transport routines
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

typedef struct git_smart_server git_smart_server;

GIT_EXTERN(int) git_smart_server_init(
	git_smart_server **out,
	git_repository *repo);

GIT_EXTERN(int) git_smart_server_uploadpack(git_smart_server *server);

GIT_EXTERN(int) git_smart_server_receivepack(git_smart_server *server);

GIT_EXTERN(void) git_smart_server_free(git_smart_server *server);

/** @} */
GIT_END_DECL
#endif
