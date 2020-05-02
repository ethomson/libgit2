/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "oid.h"
#include "global.h"

char *git_oid_tostr_s(const git_oid *oid)
{
	char *str = GIT_GLOBAL->oid_fmt;
	git_oid_nfmt(str, GIT_OID_HEXSZ + 1, oid);
	return str;
}
