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
#include "streams/process.h"
#include "smart_new.h"

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

extern char *git_http__user_agent;

typedef struct {
	git_transport parent;
	git_remote *owner;

	git_remote_connect_options connect_opts;

	git_process *process;
	git_stream *stream;
	git_smart_client *client;

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
	git_smart_client_options smart_opts = GIT_SMART_CLIENT_OPTIONS_INIT;
	git_str cmdline = GIT_STR_INIT;
	git_net_url url = GIT_NET_URL_INIT;
	const char *repo_path;
	int error = -1;

	process_opts.capture_in = 1;
	process_opts.capture_out = 1;
	process_opts.capture_err = 0;

	if (connect_opts) {
		smart_opts.sideband_progress = connect_opts->callbacks.sideband_progress;
		smart_opts.indexer_progress = connect_opts->callbacks.transfer_progress;
		smart_opts.progress_payload = connect_opts->callbacks.payload;
	}

	smart_opts.agent = git_http__user_agent;

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
	    git_stream_process_new(&transport->stream,
			transport->process, 0) < 0 ||
	    git_smart_client_init(&transport->client,
			transport->owner->repo, transport->stream,
			&smart_opts) < 0 ||
	    git_process_start(transport->process) < 0)
		goto done;

	if (direction == GIT_DIRECTION_FETCH) {
		if (git_smart_client_fetchpack(transport->client) < 0)
			goto done;
	} else if (direction == GIT_DIRECTION_PUSH) {
		/* TODO
		if (git_smart_client_sendpack() < 0)
			goto done;
		*/
		abort();

	} else {
		GIT_ASSERT(!"invalid direction");
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
	unsigned int *out,
	git_transport *_transport)
{
	unsigned int caps;
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	GIT_ASSERT(transport->client);

	if (git_smart_client_capabilities(&caps, transport->client) < 0)
		return -1;

	*out = 0;

	if ((caps & GIT_SMART_CAPABILITY_ALLOW_TIP_SHA1_IN_WANT))
		*out |= GIT_REMOTE_CAPABILITY_TIP_OID;

	if ((caps & GIT_SMART_CAPABILITY_ALLOW_REACHABLE_SHA1_IN_WANT))
		*out |= GIT_REMOTE_CAPABILITY_TIP_OID;

	return 0;
}

static int local_ls(
	const git_remote_head ***out,
	size_t *size,
	git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	return git_smart_client_refs(out, size, transport->client);
}

#ifdef GIT_EXPERIMENTAL_SHA256
static int local_oid_type(git_oid_t *out, git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	return git_smart_client_oid_type(out, transport->client);
}
#endif

static int local_negotiate_fetch(
	git_transport *_transport,
	git_repository *repo,
	const git_fetch_negotiation *wants)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	return git_smart_client_negotiate(transport->client, repo, wants);
}

static int local_download_pack(
	git_transport *_transport,
	git_repository *repo,
	git_indexer_progress *progress)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	return git_smart_client_download_pack(transport->client, repo, progress);
}

static int local_shallow_roots(git_oidarray *out, git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	return git_smart_client_shallow_roots(out, transport->client);
}

static void local_cancel(git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	git_smart_client_cancel(transport->client);	
}

static int local_close(git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	if (!transport->connected)
		return 0;

	git_stream_close(transport->stream);
	git_process_close(transport->process);
	git_stream_free(transport->stream);
	git_process_free(transport->process);
	transport->process = NULL;

	transport->connected = 0;
	return 0;
}

static void local_free(git_transport *_transport)
{
	transport_local *transport =
		GIT_CONTAINER_OF(_transport, transport_local, parent);

	git_smart_client_free(transport->client);
	git_process_free(transport->process);
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
	transport->parent.capabilities = local_capabilities;
#ifdef GIT_EXPERIMENTAL_SHA256
	transport->parent.oid_type = local_oid_type;
#endif
	transport->parent.ls = local_ls;
	transport->parent.negotiate_fetch = local_negotiate_fetch;
	transport->parent.download_pack = local_download_pack;
	transport->parent.shallow_roots = local_shallow_roots;
	transport->parent.cancel = local_cancel;
	transport->parent.close = local_close;
	transport->parent.free = local_free;

	*out = (git_transport *)transport;
	return 0;
}
