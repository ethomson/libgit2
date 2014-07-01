/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_git_rebase_h__
#define INCLUDE_git_rebase_h__

#include "common.h"
#include "types.h"
#include "oid.h"

/**
 * @file git2/rebase.h
 * @brief Git rebase routines
 * @defgroup git_rebase Git merge routines
 * @ingroup Git
 * @{
 */
GIT_BEGIN_DECL

/**
 * Aborts a rebase that is currently in progress, resetting the repository
 * and working directory to their state before rebase began.
 *
 * @param repo The repository with the in-progress rebase
 * @param signature The identity that is aborting the rebase
 * @return Zero on success; GIT_ENOTFOUND if a rebase is not in progress,
 *         -1 on other errors.
 */
GIT_EXTERN(int) git_rebase_abort(
	git_repository *repo,
	git_signature *signature);

/** @} */
GIT_END_DECL
#endif
