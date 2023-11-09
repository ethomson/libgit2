/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_transports_smart_new_h__
#define INCLUDE_transports_smart_new_h__

#include "common.h"

typedef struct {
} git_smart_client;

int git_smart_client_connect(git_smart_client *smart_client);

#endif
