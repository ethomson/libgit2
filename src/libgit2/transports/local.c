/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#include "pack-objects.h"
#include "refs.h"
#include "posix.h"
#include "fs_path.h"
#include "repository.h"
#include "odb.h"
#include "push.h"
#include "remote.h"
#include "process.h"

#include "git2/types.h"
#include "git2/net.h"
#include "git2/repository.h"
#include "git2/object.h"
#include "git2/tag.h"
#include "git2/transport.h"
#include "git2/revwalk.h"
#include "git2/odb_backend.h"
#include "git2/pack.h"
#include "git2/commit.h"
#include "git2/revparse.h"
#include "git2/sys/remote.h"

typedef struct {
	git_transport parent;
	git_remote *owner;

	git_remote_connect_options connect_opts;

	git_process *process;

	int connected : 1;
} transport_local;

static int get_git_cmdline(git_str *out, const char *path, int direction)
{
	const char *cmd;

	/* TODO: support --upload-pack semantics */

	switch (direction) {
	case GIT_DIRECTION_FETCH:
		cmd = "git upload-pack";
		break;
	case GIT_DIRECTION_PUSH:
		cmd = "git receive-pack";
		break;
	default:
		git_error_set(GIT_ERROR_NET, "invalid direction");
		return -1;
	}

	return git_str_printf(out, "%s \"%s\"", cmd, path);
}

static int local_connect(
	git_transport *_transport,
	const char *base_url,
	int direction,
	const git_remote_connect_options *connect_opts)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);
	git_process_options process_opts = GIT_PROCESS_OPTIONS_INIT;
	git_str cmdline = GIT_STR_INIT;
	git_net_url url = GIT_NET_URL_INIT;
	const char *repo_path;
	int error = -1;

	process_opts.capture_in = 1;
	process_opts.capture_out = 1;
	process_opts.capture_err = 0;

	if (git__prefixcmp(base_url, "file://") == 0) {
		if (git_net_url_parse(&url, base_url) < 0)
			goto done;

		repo_path = url.path;
	} else {
		repo_path = base_url;
	}

	if (git_remote_connect_options_normalize(&transport->connect_opts,
			transport->owner->repo, connect_opts) < 0 ||
	    get_git_cmdline(&cmdline, repo_path, direction) < 0)
		goto done;

	if (git_process_new_from_cmdline(&transport->process,
			cmdline.ptr, NULL, 0,
			&process_opts) < 0 ||
	    git_process_start(transport->process) < 0) {
		git_process_free(transport->process);
		goto done;
	}

	transport->connected = 1;

	error = 0;

done:
	git_net_url_dispose(&url);
	git_str_dispose(&cmdline);
	return error;
}

static int local_set_connect_opts(
	git_transport *_transport,
	const git_remote_connect_options *opts)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	if (!transport->connected) {
		git_error_set(GIT_ERROR_NET, "cannot reconfigure a transport that is not connected");
		return -1;
	}

	return git_remote_connect_options_normalize(
		&transport->connect_opts, transport->owner->repo, opts);
}

static int local_is_connected(git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	return transport->connected;
}

static int local_capabilities(
	unsigned int *capabilities,
	git_transport *_transport)
{
/*
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	*capabilities = 0;

	if ((transport->server_capabilities & GIT_SMART_CAPABILITY_...))
		*capabilities |= GIT_REMOTE_CAPABILITY_TIP_OID;

	if ((transports->server_capabilities & GIT_SMART_CAP...))
		*capabilities |= GIT_REMOTE_CAPABILITY_REACHABLE_OID;

*/
	return 0;
}

static int local_oid_type(git_oid_t *out, git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	*out = 0;

	return 0;
}

static int local_close(git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	if (!transport->connected)
		return 0;

	git_process_close(transport->process);
	git_process_free(transport->process);
	transport->process = NULL;

	transport->connected = 0;
	return 0;
}

static void local_free(git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	git__free(transport);
}

int git_transport_local(
	git_transport **out,
	git_remote *owner,
	void *param)
{
	transport_local *transport;

	GIT_UNUSED(param);

	transport = git__calloc(1, sizeof(transport_local));
	GIT_ERROR_CHECK_ALLOC(transport);

	transport->owner = owner;

	transport->parent.version = GIT_TRANSPORT_VERSION;
	transport->parent.connect = local_connect;
	transport->parent.set_connect_opts = local_set_connect_opts;
	transport->parent.is_connected = local_is_connected;
	transport->parent.close = local_close;
	transport->parent.free = local_free;

	*out = (git_transport *)transport;
	return 0;
}
