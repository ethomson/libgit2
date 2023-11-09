/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#ifndef GIT_WINHTTP

#include "http_parser.h"
#include "net.h"
#include "remote.h"
#include "smart.h"
#include "smart_new.h"
#include "auth.h"
#include "http.h"
#include "auth_negotiate.h"
#include "auth_ntlm.h"
#include "trace.h"
#include "streams/tls.h"
#include "streams/socket.h"
#include "httpclient.h"
#include "git2/sys/credential.h"

#define HTTP_UPLOADPACK_REFS_PATH "/info/refs?service=git-upload-pack"
#define HTTP_UPLOADPACK_REFS_RESPONSE_TYPE "application/x-git-upload-pack-advertisement"

#define HTTP_RECEIVEPACK_REFS_PATH "/info/refs?service=git-receive-pack"
#define HTTP_RECEIVEPACK_REFS_RESPONSE_TYPE "application/x-git-receive-pack-advertisement"

#define SERVER_TYPE_REMOTE "remote"
#define SERVER_TYPE_PROXY  "proxy"

bool git_http__expect_continue = false;

struct http_server {
	git_net_url url;

	git_credential *cred;
	unsigned auth_schemetypes;
	unsigned url_cred_presented : 1;
};

typedef struct {
	git_transport parent;
	git_remote *owner;

	git_smart_client smart_client;

	git_remote_connect_options connect_opts;

	int connected : 1;

	struct http_server server;
	struct http_server proxy;

	git_http_client *client;
} http_transport;

GIT_INLINE(void) free_cred(git_credential **cred)
{
	if (*cred) {
		git_credential_free(*cred);
		(*cred) = NULL;
	}
}

static int http_close(git_transport *_transport)
{
	http_transport *transport =
		GIT_CONTAINER_OF(_transport, http_transport, parent);

	free_cred(&transport->server.cred);
	free_cred(&transport->proxy.cred);

	transport->server.url_cred_presented = false;
	transport->proxy.url_cred_presented = false;

	git_net_url_dispose(&transport->server.url);
	git_net_url_dispose(&transport->proxy.url);

	return 0;
}

static int lookup_proxy(
	bool *out_use,
	http_transport *transport)
{
	git_remote_connect_options *connect_opts = &transport->connect_opts;
	const char *proxy;
	git_remote *remote;
	char *config = NULL;
	int error = 0;

	*out_use = false;
	git_net_url_dispose(&transport->proxy.url);

	switch (connect_opts->proxy_opts.type) {
	case GIT_PROXY_SPECIFIED:
		proxy = connect_opts->proxy_opts.url;
		break;

	case GIT_PROXY_AUTO:
		remote = transport->owner;

		error = git_remote__http_proxy(&config, remote, &transport->server.url);

		if (error || !config)
			goto done;

		proxy = config;
		break;

	default:
		return 0;
	}

	if (!proxy ||
	    (error = git_net_url_parse_http(&transport->proxy.url, proxy)) < 0)
		goto done;

	if (!git_net_url_valid(&transport->proxy.url)) {
		git_error_set(GIT_ERROR_HTTP, "invalid URL: '%s'", proxy);
		error = -1;
		goto done;
	}

	*out_use = true;

done:
	git__free(config);
	return error;
}

static int generate_inforefs_request(
	git_net_url *url,
	git_http_request *request,
	http_transport *transport,
	int direction)
{
	bool use_proxy = false;
	const char *path;

	if (direction == GIT_DIRECTION_FETCH)
		path = HTTP_UPLOADPACK_REFS_PATH;
	else if (direction == GIT_DIRECTION_PUSH)
		path = HTTP_RECEIVEPACK_REFS_PATH;
	else
		GIT_ASSERT(!"invalid service");

	if (git_net_url_joinpath(url, &transport->server.url, path) < 0 ||
	    lookup_proxy(&use_proxy, transport) < 0)
		return -1;

	request->method = GIT_HTTP_METHOD_GET;
	request->url = url;
	request->credentials = transport->server.cred;
	request->proxy = use_proxy ? &transport->proxy.url : NULL;
	request->proxy_credentials = transport->proxy.cred;
	request->custom_headers = &transport->connect_opts.custom_headers;

	return 0;
}

static int apply_url_credentials(
	git_credential **cred,
	unsigned int allowed_types,
	const char *username,
	const char *password)
{
	GIT_ASSERT_ARG(username);

	if (!password)
		password = "";

	if (allowed_types & GIT_CREDENTIAL_USERPASS_PLAINTEXT)
		return git_credential_userpass_plaintext_new(cred, username, password);

	if ((allowed_types & GIT_CREDENTIAL_DEFAULT) && *username == '\0' && *password == '\0')
		return git_credential_default_new(cred);

	return GIT_PASSTHROUGH;
}

static int handle_auth(
	struct http_server *server,
	const char *server_type,
	const char *url,
	unsigned int allowed_schemetypes,
	unsigned int allowed_credtypes,
	git_credential_acquire_cb callback,
	void *callback_payload)
{
	int error = 1;

	if (server->cred)
		free_cred(&server->cred);

	/* Start with URL-specified credentials, if there were any. */
	if ((allowed_credtypes & GIT_CREDENTIAL_USERPASS_PLAINTEXT) &&
	    !server->url_cred_presented &&
	    server->url.username) {
		error = apply_url_credentials(&server->cred, allowed_credtypes, server->url.username, server->url.password);
		server->url_cred_presented = 1;

		/* treat GIT_PASSTHROUGH as if callback isn't set */
		if (error == GIT_PASSTHROUGH)
			error = 1;
	}

	if (error > 0 && callback) {
		error = callback(&server->cred, url, server->url.username, allowed_credtypes, callback_payload);

		/* treat GIT_PASSTHROUGH as if callback isn't set */
		if (error == GIT_PASSTHROUGH)
			error = 1;
	}

	if (error > 0) {
		git_error_set(GIT_ERROR_HTTP, "%s authentication required but no callback set", server_type);
		error = GIT_EAUTH;
	}

	if (!error)
		server->auth_schemetypes = allowed_schemetypes;

	return error;
}

GIT_INLINE(int) handle_remote_auth(
	http_transport *transport,
	git_http_response *response)
{
	git_remote_connect_options *connect_opts = &transport->connect_opts;

	if (response->server_auth_credtypes == 0) {
		git_error_set(GIT_ERROR_HTTP, "server requires authentication that we do not support");
		return GIT_EAUTH;
	}

	/* Otherwise, prompt for credentials. */
	return handle_auth(
		&transport->server,
		SERVER_TYPE_REMOTE,
		transport->owner->url,
		response->server_auth_schemetypes,
		response->server_auth_credtypes,
		connect_opts->callbacks.credentials,
		connect_opts->callbacks.payload);
}

GIT_INLINE(int) handle_proxy_auth(
	http_transport *transport,
	git_http_response *response)
{
	git_remote_connect_options *connect_opts = &transport->connect_opts;

	if (response->proxy_auth_credtypes == 0) {
		git_error_set(GIT_ERROR_HTTP, "proxy requires authentication that we do not support");
		return GIT_EAUTH;
	}

	/* Otherwise, prompt for credentials. */
	return handle_auth(
		&transport->proxy,
		SERVER_TYPE_PROXY,
		connect_opts->proxy_opts.url,
		response->server_auth_schemetypes,
		response->proxy_auth_credtypes,
		connect_opts->proxy_opts.credentials,
		connect_opts->proxy_opts.payload);
}

static bool allow_redirect(http_transport *transport, bool is_initial)
{
	switch (transport->connect_opts.follow_redirects) {
	case GIT_REMOTE_REDIRECT_INITIAL:
		return (is_initial == true);
	case GIT_REMOTE_REDIRECT_ALL:
		return true;
	default:
		return false;
	}
}

static int handle_inforefs_response(
	bool *complete,
	http_transport *transport,
	git_http_response *response,
	int direction)
{
	const char *path, *content_type;

	if (direction == GIT_DIRECTION_FETCH) {
		path = HTTP_UPLOADPACK_REFS_PATH;
		content_type = HTTP_UPLOADPACK_REFS_RESPONSE_TYPE;
	} else if (direction == GIT_DIRECTION_PUSH) {
		path = HTTP_RECEIVEPACK_REFS_PATH;
		content_type = HTTP_RECEIVEPACK_REFS_RESPONSE_TYPE;
	} else {
		GIT_ASSERT(!"invalid service");
	}

	printf("resdirect? %d\n", git_http_response_is_redirect(response));

	/* Handle redirects */
	if (git_http_response_is_redirect(response)) {
		if (!response->location) {
			git_error_set(GIT_ERROR_HTTP, "http redirect without location");
			return -1;
		}

		if (git_net_url_apply_redirect(&transport->server.url,
				response->location,
				allow_redirect(transport, true),
				path) < 0)
			return -1;

		return 0;
	}

	/* Handle authentication */
	if (response->status == GIT_HTTP_STATUS_UNAUTHORIZED) {
		if (handle_remote_auth(transport, response) < 0)
			return -1;

		return git_http_client_skip_body(transport->client);
	} else if (response->status == GIT_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED) {
		if (handle_proxy_auth(transport, response) < 0)
			return -1;

		return git_http_client_skip_body(transport->client);
	}

	if (response->status != GIT_HTTP_STATUS_OK) {
		git_error_set(GIT_ERROR_HTTP,
			"unexpected http status code: %d",
			response->status);
		return -1;
	}

	/* Ensure that we're talking smart HTTP */

	/*
	 * TODO: currently we look at the content type to determine if
	 * this is a smart http server or not. This is generally legit,
	 * but git doesn't actually do this, and we could peek at the
	 * bytes to determine instead.
	 */
	if (!response->content_type) {
		git_error_set(GIT_ERROR_HTTP,
			"dumb http is not supported (received content-type '%s' for info/refs request)",
			response->content_type);
		return -1;
	} else if (strcmp(response->content_type, content_type) != 0) {
		git_error_set(GIT_ERROR_HTTP,
			"dumb http is not supported (received content-type '%s' for info/refs request)",
			response->content_type);
		return -1;
	}

	*complete = true;
	return 0;
}

static int http_connect(
	git_transport *_transport,
	const char *base_url,
	int direction,
	const git_remote_connect_options *connect_opts)
{
	http_transport *transport =
		GIT_CONTAINER_OF(_transport, http_transport, parent);
	git_net_url url = GIT_NET_URL_INIT;
	git_http_client_options client_opts = {0};
	git_http_request request = {0};
	git_http_response response = {0};
	size_t replay_count = 0;
	bool complete = false;
	int error = -1;

	/* TODO: do we really need to close or can we keepalive? */
	if (http_close(_transport) < 0 ||
	    git_http_client_new(&transport->client, &client_opts) < 0)
		goto done;

	if (git_net_url_parse(&transport->server.url, base_url) < 0 ||
	    git_remote_connect_options_normalize(&transport->connect_opts,
			transport->owner->repo, connect_opts) < 0)
		goto done;

	while (!complete && replay_count < GIT_HTTP_REPLAY_MAX) {
		if (generate_inforefs_request(&url, &request, transport, direction) < 0 ||
		    git_http_client_send_request(transport->client, &request) < 0 ||
		    git_http_client_read_response(&response, transport->client) < 0 ||
		    handle_inforefs_response(&complete, transport, &response, direction) < 0)
			goto done;

		replay_count++;
	}

	if (!complete) {
		git_error_set(GIT_ERROR_HTTP, "too many redirects or authentication replays");
		error = GIT_ERROR; /* not GIT_EAUTH, because the exact cause is unclear */
		goto done;
	}

	if (git_smart_client_connect(&transport->smart_client) < 0)
		goto done;

	transport->connected = 1;
	error = 0;

done:
	git_http_response_dispose(&response);
	git_net_url_dispose(&url);
	return error;
}

static int http_set_connect_opts(
	git_transport *_transport,
	const git_remote_connect_options *opts)
{
	http_transport *transport =
		GIT_CONTAINER_OF(_transport, http_transport, parent);

	if (!transport->connected) {
		git_error_set(GIT_ERROR_NET, "cannot reconfigure a transport that is not connected");
		return -1;
	}

	return git_remote_connect_options_normalize(
		&transport->connect_opts, transport->owner->repo, opts);
}

static int http_is_connected(git_transport *_transport)
{
	http_transport *transport =
		GIT_CONTAINER_OF(_transport, http_transport, parent);

	return transport->connected;
}

static void http_free(git_transport *_transport)
{
	http_transport *transport =
		GIT_CONTAINER_OF(_transport, http_transport, parent);

	http_close(_transport);

	git_http_client_free(transport->client);
	git__free(transport);
}

int git_transport_http(git_transport **out, git_remote *owner, void *param)
{
	http_transport *transport;

	GIT_UNUSED(param);

	transport = git__calloc(1, sizeof(http_transport));
	GIT_ERROR_CHECK_ALLOC(transport);

	transport->owner = owner;

	transport->parent.version = GIT_TRANSPORT_VERSION;
	transport->parent.connect = http_connect;
	transport->parent.set_connect_opts = http_set_connect_opts;
	transport->parent.is_connected = http_is_connected;
	/*
	transport->parent.capabilities = http_capabilities;
#ifdef GIT_EXPERIMENTAL_SHA256
	transport->parent.oid_type = http__oid_type;
#endif
	transport->parent.negotiate_fetch = http_negotiate_fetch;
	transport->parent.shallow_roots = http_shallow_roots;
	transport->parent.download_pack = http_download_pack;
	transport->parent.push = http_push;
	transport->parent.ls = http_ls;
	transport->parent.cancel = http_cancel;
	*/
	transport->parent.close = http_close;
	transport->parent.free = http_free;

	*out = (git_transport *)transport;
	return 0;
}

#endif /* !GIT_WINHTTP */
