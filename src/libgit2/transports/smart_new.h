/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */
#ifndef INCLUDE_smart_h__
#define INCLUDE_smart_h__

#include "common.h"
#include "vector.h"
#include "oidarray.h"
#include "stream.h"
#include "git2/sys/transport.h"
#include "git2/sys/remote.h"

typedef enum {
	GIT_SMART_PACKET_NONE,
	GIT_SMART_PACKET_REF,
	GIT_SMART_PACKET_FLUSH,
	GIT_SMART_PACKET_ACK,
	GIT_SMART_PACKET_NAK,
	GIT_SMART_PACKET_ERR,
	GIT_SMART_PACKET_SHALLOW,
	GIT_SMART_PACKET_UNSHALLOW,
	GIT_SMART_PACKET_DEEPEN,
	GIT_SMART_PACKET_WANT,
	GIT_SMART_PACKET_HAVE,	
	GIT_SMART_PACKET_DONE
} git_smart_packet_t;

typedef enum {
	GIT_SMART_CAPABILITY_MULTI_ACK                    = (1 <<  0),
	GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED           = (1 <<  1),
	GIT_SMART_CAPABILITY_NO_DONE                      = (1 <<  2),
	GIT_SMART_CAPABILITY_THIN_PACK                    = (1 <<  3),
	GIT_SMART_CAPABILITY_SIDE_BAND                    = (1 <<  4),
	GIT_SMART_CAPABILITY_SIDE_BAND_64K                = (1 <<  5),
	GIT_SMART_CAPABILITY_OFS_DELTA                    = (1 <<  6),
	GIT_SMART_CAPABILITY_AGENT                        = (1 <<  7),
	GIT_SMART_CAPABILITY_OBJECT_FORMAT                = (1 <<  8),
	GIT_SMART_CAPABILITY_SYMREF                       = (1 <<  9),
	GIT_SMART_CAPABILITY_SHALLOW                      = (1 << 10),
	GIT_SMART_CAPABILITY_DEEPEN_SINCE                 = (1 << 11),
	GIT_SMART_CAPABILITY_DEEPEN_NOT                   = (1 << 12),
	GIT_SMART_CAPABILITY_DEEPEN_RELATIVE              = (1 << 13),
	GIT_SMART_CAPABILITY_NO_PROGRESS                  = (1 << 14),
	GIT_SMART_CAPABILITY_INCLUDE_TAG                  = (1 << 15),
	GIT_SMART_CAPABILITY_REPORT_STATUS                = (1 << 16),
	GIT_SMART_CAPABILITY_REPORT_STATUS_V2             = (1 << 17),
	GIT_SMART_CAPABILITY_DELETE_REFS                  = (1 << 18),
	GIT_SMART_CAPABILITY_QUIET                        = (1 << 19),
	GIT_SMART_CAPABILITY_ATOMIC                       = (1 << 20),
	GIT_SMART_CAPABILITY_PUSH_OPTIONS                 = (1 << 21),
	GIT_SMART_CAPABILITY_ALLOW_TIP_SHA1_IN_WANT       = (1 << 22),
	GIT_SMART_CAPABILITY_ALLOW_REACHABLE_SHA1_IN_WANT = (1 << 23),
	GIT_SMART_CAPABILITY_ALLOW_ANY_SHA1_IN_WANT       = (1 << 24),
	GIT_SMART_CAPABILITY_PUSH_CERT                    = (1 << 25),
	GIT_SMART_CAPABILITY_FILTER                       = (1 << 26),
	GIT_SMART_CAPABILITY_SESSION_ID                   = (1 << 27)
} git_smart_capability;

struct git_smart_packet {
	git_smart_packet_t type;

	/* Raw data in the packet */
	const char *data;
	size_t len;

	/* If the packet "owns" the raw data and should be free */
	int owned;

	/* For reference advertisements, wants, etc. */
	const char *oid;
	size_t oid_len;

	/* For reference advertisements, the reference itself. */
	const char *refname;
	size_t refname_len;

	/* The first want packet includes capabilities */
	const char *capabilities;
	size_t capabilities_len;
};

typedef struct git_smart_client git_smart_client;

int git_smart_client_init(
	git_smart_client **out,
	git_repository *repo,
	git_stream *stream);
int git_smart_client_fetchpack(git_smart_client *out);
int git_smart_client_capabilities(
	unsigned int *out,
	git_smart_client *client);
int git_smart_client_oid_type(
	git_oid_t *out,
	git_smart_client *client);
int git_smart_client_refs(
	const git_remote_head ***out,
	size_t *size,
	git_smart_client *client);
int git_smart_client_negotiate(
	git_smart_client *client,
	const git_fetch_negotiation *wants);
void git_smart_client_free(git_smart_client *client);

#endif
