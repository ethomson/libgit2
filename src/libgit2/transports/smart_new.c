/*
* Copyright (C) the libgit2 contributors. All rights reserved.
*
* This file is part of libgit2, distributed under the GNU GPL v2 with
* a Linking Exception. For full terms see the included COPYING file.
*/

#include "smart_new.h"

#include "common.h"
#include "refs.h"
#include "settings.h"
#include "vector.h"
#include "pack-objects.h"

#include "git2/odb.h"
#include "git2/revwalk.h"
#include "git2/version.h"
#include "git2/sys/refs.h"

/* TODO : 1024 or something */
#define READ_SIZE 1

typedef struct {
	git_smart_capability_t capability;
	const char *name;
} smart_capability_name;

static const smart_capability_name smart_capabilities[] = {
	{ GIT_SMART_CAPABILITY_MULTI_ACK, "multi_ack" },
	{ GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED, "multi_ack_detailed" },
	{ GIT_SMART_CAPABILITY_NO_DONE, "no-done" },
	{ GIT_SMART_CAPABILITY_THIN_PACK, "thin-pack" },
	{ GIT_SMART_CAPABILITY_SIDE_BAND, "side-band" },
	{ GIT_SMART_CAPABILITY_SIDE_BAND_64K, "side-band-64k" },
	{ GIT_SMART_CAPABILITY_OFS_DELTA, "ofs-delta" },
	{ GIT_SMART_CAPABILITY_AGENT, "agent" },
	{ GIT_SMART_CAPABILITY_OBJECT_FORMAT, "object-format" },
	{ GIT_SMART_CAPABILITY_SYMREF, "symref" },
	{ GIT_SMART_CAPABILITY_SHALLOW, "shallow" },
	{ GIT_SMART_CAPABILITY_DEEPEN_SINCE, "deepen-since" },
	{ GIT_SMART_CAPABILITY_DEEPEN_NOT, "deepen-not" },
	{ GIT_SMART_CAPABILITY_DEEPEN_RELATIVE, "deepen-relative" },
	{ GIT_SMART_CAPABILITY_NO_PROGRESS, "no-progress" },
	{ GIT_SMART_CAPABILITY_INCLUDE_TAG, "include-tag" },
	{ GIT_SMART_CAPABILITY_REPORT_STATUS, "report-status" },
	{ GIT_SMART_CAPABILITY_REPORT_STATUS_V2, "report-status-v2" },
	{ GIT_SMART_CAPABILITY_DELETE_REFS, "delete-refs" },
	{ GIT_SMART_CAPABILITY_QUIET, "quiet" },
	{ GIT_SMART_CAPABILITY_ATOMIC, "atomic" },
	{ GIT_SMART_CAPABILITY_PUSH_OPTIONS, "push-options" },
	{ GIT_SMART_CAPABILITY_ALLOW_TIP_SHA1_IN_WANT, "allow-tip-sha1-in-want" },
	{ GIT_SMART_CAPABILITY_ALLOW_REACHABLE_SHA1_IN_WANT, "allow-reachable-sha1-in-want" },
	{ GIT_SMART_CAPABILITY_ALLOW_ANY_SHA1_IN_WANT, "allow-any-sha1-in-want" },
	{ GIT_SMART_CAPABILITY_PUSH_CERT, "push-cert" },
	{ GIT_SMART_CAPABILITY_FILTER, "filter" },
	{ GIT_SMART_CAPABILITY_SESSION_ID, "session-id" },
	{ 0, NULL }
};

typedef struct {
	git_smart_packet_t type;

	/* Raw packet data (including the length prefix) */
	const char *data;
	size_t len;

	/* Parsed object ID; for wants, haves, etc */
	git_oid oid;

	/* The first packet includes capabilities */
	const char *capabilities;
} git_smart_packet;

struct git_smart_parser {
	/* The current packet being parsed */
	struct git_smart_packet pkt;

	/*
	 * The total length of the packet (including size prefix) and
	 * how many bytes of the packet have been consumed.
	 */
	size_t total_len;
	size_t consumed;

	/* The remaining data to parse of the message and its length. */
	const char *data;
	size_t len;
};

struct git_smart_client {
	git_repository *repo;
	git_oid_t oid_type;

	/* Configuration */
	/* TODO: git_smart_client_options? */
	unsigned int capabilities;

	struct git_smart_packet_parser parser;
};

/*
 * The client reads a chunk at a time from the server, buffering it.
 * This will fill the read buffer with a minimum of `len`, or until
 * EOL from the server.
 */
static int fill_read_buf(git_str *read_buf, size_t len)
{
	char *buf;
	int ret;

	fprintf(debug, "filling read buf - size: %d / wanted: %d\n", (int)server->read_buf.size, (int)len);

	while (read_buf->size < len) {
		/* TODO: make sure this doesn't continutally realloc */
		if (git_str_grow(read_buf, READ_SIZE) < 0)
				return -1;

		buf = read_buf->ptr + read_buf->size;

		if ((ret = read(STDIN_FILENO, buf, READ_SIZE)) < 0) {
				git_error_set(GIT_ERROR_OS, "could not read from client");
				return -1;
		}

		fprintf(debug, ">>>read>>> %.*s\n", ret, buf);

		/* TODO: check overflow, ensure size <= asize */
		read_buf->size += ret;

		if (ret == 0) {
				git_error_set(GIT_ERROR_NET, "unexpected eof from client");
				return -1;
		}
	}

	fprintf(debug, "filled read buf\n");

	return 0;
}

int pkt_read(git_smart_packet **out, git_smart_client *client)
{

}

int git_smart_client_init(git_smart_client **out, git_repository *repo)
{
	git_smart_client *client;

	GIT_ASSERT_ARG(out && repo);

	client = git__calloc(1, sizeof(git_smart_client));
	GIT_ERROR_CHECK_ALLOC(client);

	client->repo = repo;
	client->oid_type = git_repository_oid_type(repo);
	client->capabilities = GIT_SMART_CLIENT_CAPABILITIES;

	*out = client;
	return 0;
}

void git_smart_client_free(git_smart_client *client)
{
	git__free(client);
}
