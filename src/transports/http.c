/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "common.h"

#ifndef GIT_WINHTTP

#include "git2.h"
#include "http_parser.h"
#include "buffer.h"
#include "net.h"
#include "netops.h"
#include "global.h"
#include "remote.h"
#include "git2/sys/cred.h"
#include "smart.h"
#include "auth.h"
#include "http.h"
#include "auth_negotiate.h"
#include "auth_ntlm.h"
#include "trace.h"
#include "streams/tls.h"
#include "streams/socket.h"

bool git_http__expect_continue = false;

git_http_auth_scheme auth_schemes[] = {
	{ GIT_AUTHTYPE_NEGOTIATE, "Negotiate", GIT_CREDTYPE_DEFAULT, git_http_auth_negotiate },
	{ GIT_AUTHTYPE_NTLM, "NTLM", GIT_CREDTYPE_USERPASS_PLAINTEXT, git_http_auth_ntlm },
	{ GIT_AUTHTYPE_BASIC, "Basic", GIT_CREDTYPE_USERPASS_PLAINTEXT, git_http_auth_basic },
};

git_http_service upload_pack_ls_service = {
	GET, "/info/refs?service=git-upload-pack",
	NULL,
	"application/x-git-upload-pack-advertisement",
	0
};
git_http_service upload_pack_service = {
	POST, "/git-upload-pack",
	"application/x-git-upload-pack-request",
	"application/x-git-upload-pack-result",
	0
};
git_http_service receive_pack_ls_service = {
	GET, "/info/refs?service=git-receive-pack",
	NULL,
	"application/x-git-receive-pack-advertisement",
	0
};
git_http_service receive_pack_service = {
	POST, "/git-receive-pack",
	"application/x-git-receive-pack-request",
	"application/x-git-receive-pack-result",
	0
};

#define AUTH_HEADER_SERVER "Authorization"
#define AUTH_HEADER_PROXY  "Proxy-Authorization"

#define SERVER_TYPE_REMOTE "remote"
#define SERVER_TYPE_PROXY  "proxy"

#define OWNING_SUBTRANSPORT(s) ((http_subtransport *)(s)->parent.subtransport)

#define PARSE_ERROR_GENERIC	-1
#define PARSE_ERROR_REPLAY	-2
/** Look at the user field */
#define PARSE_ERROR_EXT         -3

#define CHUNK_SIZE	4096

typedef struct {
	git_smart_subtransport_stream parent;
	git_http_service *service;
	char *redirect_url;
	char *chunk_buffer;
	unsigned chunk_buffer_len;
	unsigned sent_request : 1,
		received_response : 1;
} http_stream;

typedef struct {
	git_net_url url;
	git_stream *stream;

	git_http_authtype_t authtypes;
	git_credtype_t credtypes;

	git_cred *cred;
	unsigned url_cred_presented : 1,
	    authenticated : 1;
	git_http_authtype_t prior_authtype;

	git_vector auth_challenges;
	git_http_auth_context *auth_context;
} http_server;

typedef enum {
	PARSE_HEADER_NONE = 0,
	PARSE_HEADER_NAME,
	PARSE_HEADER_VALUE,
	PARSE_HEADER_COMPLETE
} parse_header_state;

typedef struct {
	git_smart_subtransport parent;
	transport_smart *owner;
	git_stream *gitserver_stream;
	bool connected;

	http_server server;

	http_server proxy;
	char *proxy_url;
	git_proxy_options proxy_opts;

	/* Parser structures */
	http_parser parser;
	http_parser_settings settings;
	gitno_buffer parse_buffer;
	parse_header_state parse_header_state;
	git_buf parse_header_name;
	git_buf parse_header_value;
	char parse_buffer_data[NETIO_BUFSIZE];
	char *content_type;
	char *content_length;
	char *location;
	int parse_error;
	int error;
	unsigned request_count;
	unsigned parse_finished : 1,
	    keepalive : 1,
	    carryover : 1,
	    replay_count : 4;
} http_subtransport;

typedef struct {
	http_stream *s;
	http_subtransport *t;

	/* Target buffer details from read() */
	char *buffer;
	size_t buf_size;
	size_t *bytes_read;
} parser_context;

static git_http_auth_scheme *scheme_for_challenge(
	const char *challenge,
	git_cred *cred)
{
	git_http_auth_scheme *scheme = NULL;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(auth_schemes); i++) {
		const char *scheme_name = auth_schemes[i].name;
		const git_credtype_t scheme_types = auth_schemes[i].credtypes;
		size_t scheme_len;

		scheme_len = strlen(scheme_name);

		if ((!cred || (cred->credtype & scheme_types)) &&
		    strncasecmp(challenge, scheme_name, scheme_len) == 0 &&
		    (challenge[scheme_len] == '\0' || challenge[scheme_len] == ' ')) {
			scheme = &auth_schemes[i];
			break;
		}
	}

	return scheme;
}

static int apply_credentials(
	git_buf *buf,
	http_server *server,
	const char *header_name)
{
	git_buf token = GIT_BUF_INIT;
	int error = 0;

	if (!server->auth_context)
		goto done;

	if ((error = server->auth_context->next_token(&token, server->auth_context, server->cred)) < 0)
		goto done;

	error = git_buf_printf(buf, "%s: %s\r\n", header_name, token.ptr);

done:
	git_buf_dispose(&token);
	return error;
}

static int gen_request(
	git_buf *buf,
	http_stream *s,
	size_t content_length,
	bool expect_continue)
{
	http_subtransport *t = OWNING_SUBTRANSPORT(s);
	const char *verb = s->service->verb == POST ? "POST" : "GET";
	const char *path = t->server.url.path ? t->server.url.path : "/";
	size_t i;

	if (t->proxy_opts.type == GIT_PROXY_SPECIFIED)
		git_buf_printf(buf, "%s %s://%s:%s%s%s HTTP/1.1\r\n",
			verb,
			t->server.url.scheme,
			t->server.url.host,
			t->server.url.port,
			path,
			s->service->url);
	else
		git_buf_printf(buf, "%s %s%s HTTP/1.1\r\n",
			verb, path, s->service->url);

	git_buf_puts(buf, "User-Agent: ");
	git_http__user_agent(buf);
	git_buf_puts(buf, "\r\n");
	git_buf_printf(buf, "Host: %s", t->server.url.host);

	if (!git_net_url_is_default_port(&t->server.url))
		git_buf_printf(buf, ":%s", t->server.url.port);

	git_buf_puts(buf, "\r\n");

	if (s->service->chunked || content_length > 0) {
		git_buf_printf(buf, "Accept: %s\r\n", s->service->response_type);
		git_buf_printf(buf, "Content-Type: %s\r\n", s->service->request_type);

		if (s->service->chunked)
			git_buf_puts(buf, "Transfer-Encoding: chunked\r\n");
		else
			git_buf_printf(buf, "Content-Length: %"PRIuZ "\r\n", content_length);
	} else
		git_buf_puts(buf, "Accept: */*\r\n");

	if (expect_continue)
		git_buf_printf(buf, "Expect: 100-continue\r\n");

	for (i = 0; i < t->owner->custom_headers.count; i++) {
		if (t->owner->custom_headers.strings[i])
			git_buf_printf(buf, "%s\r\n", t->owner->custom_headers.strings[i]);
	}

	/* Apply proxy and server credentials to the request */
	if (t->proxy_opts.type != GIT_PROXY_NONE &&
	    apply_credentials(buf, &t->proxy, AUTH_HEADER_PROXY) < 0)
		return -1;

	if (apply_credentials(buf, &t->server, AUTH_HEADER_SERVER) < 0)
		return -1;

	git_buf_puts(buf, "\r\n");

	if (git_buf_oom(buf))
		return -1;

	return 0;
}

static int set_authentication_challenge(http_server *server)
{
	const char *challenge;

	if (git_vector_length(&server->auth_challenges) > 1) {
		git_error_set(GIT_ERROR_NET, "received multiple authentication challenges");
		return -1;
	}

	challenge = git_vector_get(&server->auth_challenges, 0);

	if (server->auth_context->set_challenge)
		return server->auth_context->set_challenge(server->auth_context, challenge);
	else
		return 0;
}

static int set_authentication_types(http_server *server)
{
	git_http_auth_scheme *scheme;
	char *challenge;
	size_t i;

	git_vector_foreach(&server->auth_challenges, i, challenge) {
		if ((scheme = scheme_for_challenge(challenge, NULL)) != NULL) {
			server->authtypes |= scheme->type;
			server->credtypes |= scheme->credtypes;
		}
	}

	return 0;
}

static bool auth_context_complete(http_server *server)
{
	/* If there's no is_complete function, we're always complete */
	if (!server->auth_context->is_complete)
		return true;

	if (server->auth_context->is_complete(server->auth_context))
		return true;

	return false;
}

static void free_auth_context(http_server *server)
{
	if (!server->auth_context)
		return;

	if (server->auth_context->free)
		server->auth_context->free(server->auth_context);

	server->auth_context = NULL;
}

static int parse_authenticate_response(http_server *server)
{
	/*
	 * If we think that we've completed authentication (ie, we've either
	 * sent a basic credential or we've sent the NTLM/Negotiate response)
	 * but we've got an authentication request from the server then our
	 * last authentication did not succeed.  Start over.
	 */
	if (server->auth_context && auth_context_complete(server)) {
		free_auth_context(server);

		server->authenticated = 0;
	}

	/*
	 * If we've begun authentication, give the challenge to the context.
	 * Otherwise, set up the types to prepare credentials.
	 */
	if (git_vector_length(&server->auth_challenges) == 0)
		return 0;
	else if (server->auth_context)
		return set_authentication_challenge(server);
	else
		return set_authentication_types(server);
}

static int on_header_complete(http_subtransport *t)
{
	git_buf *name = &t->parse_header_name;
	git_buf *value = &t->parse_header_value;

	if (!strcasecmp("Content-Type", git_buf_cstr(name))) {
		if (t->content_type) {
			git_error_set(GIT_ERROR_NET, "multiple Content-Type headers");
			return -1;
		}

		t->content_type = git__strndup(value->ptr, value->size);
		GIT_ERROR_CHECK_ALLOC(t->content_type);
	}
	else if (!strcasecmp("Content-Length", git_buf_cstr(name))) {
		if (t->content_length) {
			git_error_set(GIT_ERROR_NET, "multiple Content-Length headers");
			return -1;
		}

		t->content_length = git__strndup(value->ptr, value->size);
		GIT_ERROR_CHECK_ALLOC(t->content_length);
	}
	else if (!strcasecmp("Proxy-Authenticate", git_buf_cstr(name))) {
		char *dup = git__strndup(value->ptr, value->size);
		GIT_ERROR_CHECK_ALLOC(dup);

		if (git_vector_insert(&t->proxy.auth_challenges, dup) < 0)
			return -1;
	}
	else if (!strcasecmp("WWW-Authenticate", git_buf_cstr(name))) {
		char *dup = git__strndup(value->ptr, value->size);
		GIT_ERROR_CHECK_ALLOC(dup);

		if (git_vector_insert(&t->server.auth_challenges, dup) < 0)
			return -1;
	}
	else if (!strcasecmp("Location", git_buf_cstr(name))) {
		if (t->location) {
			git_error_set(GIT_ERROR_NET, "multiple Location headers");
			return -1;
		}

		t->location = git__strndup(value->ptr, value->size);
		GIT_ERROR_CHECK_ALLOC(t->location);
	}

	return 0;
}

static int on_header_field(http_parser *parser, const char *str, size_t len)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;

	/* We last saw a piece of a header value */
	if (t->parse_header_state == PARSE_HEADER_VALUE &&
	    on_header_complete(t) < 0)
		return t->parse_error = PARSE_ERROR_GENERIC;

	if (t->parse_header_state != PARSE_HEADER_NAME) {
		git_buf_clear(&t->parse_header_name);
		git_buf_clear(&t->parse_header_value);
	}

	t->parse_header_state = PARSE_HEADER_NAME;

	if (git_buf_put(&t->parse_header_name, str, len) < 0)
		return t->parse_error = PARSE_ERROR_GENERIC;

	return 0;
}

static int on_header_value(http_parser *parser, const char *str, size_t len)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;

	t->parse_header_state = PARSE_HEADER_VALUE;

	if (git_buf_put(&t->parse_header_value, str, len) < 0)
		return t->parse_error = PARSE_ERROR_GENERIC;

	return 0;
}

GIT_INLINE(void) free_cred(git_cred **cred)
{
	if (*cred) {
		git_cred_free(*cred);
		(*cred) = NULL;
	}
}

static int apply_url_credentials(
	git_cred **cred,
	unsigned int allowed_types,
	const char *username,
	const char *password)
{
	if (allowed_types & GIT_CREDTYPE_USERPASS_PLAINTEXT)
		return git_cred_userpass_plaintext_new(cred, username, password);

	if ((allowed_types & GIT_CREDTYPE_DEFAULT) && *username == '\0' && *password == '\0')
		return git_cred_default_new(cred);

	return GIT_PASSTHROUGH;
}

static int init_auth(http_server *server)
{
	git_http_auth_scheme *s, *scheme = NULL;
	char *c, *challenge = NULL;
	size_t i;
	int error;

	git_vector_foreach(&server->auth_challenges, i, c) {
		s = scheme_for_challenge(c, server->cred);

		if (s && !!(s->credtypes & server->credtypes)) {
			scheme = s;
			challenge = c;
			break;
		}
	}

	if (!scheme) {
		git_error_set(GIT_ERROR_NET, "no authentication mechanism could be negotiated");
		return -1;
	}

	if ((error = scheme->init_context(&server->auth_context, &server->url)) == GIT_PASSTHROUGH)
		return 0;
	else if (error < 0)
		return error;

	if (server->auth_context->set_challenge &&
		(error = server->auth_context->set_challenge(server->auth_context, challenge)) < 0)
		return error;

	return 0;
}

static int on_auth_required(
	http_parser *parser,
	http_server *server,
	const char *url,
	const char *type,
	git_cred_acquire_cb callback,
	void *callback_payload)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;
	int error = 1;

	if (parse_authenticate_response(server) < 0) {
		t->parse_error = PARSE_ERROR_GENERIC;
		return t->parse_error;
	}

	/* If we're in the middle of challenge/response auth, continue */
	if (parser->status_code == 407 || parser->status_code == 401) {
		if (server->auth_context && !auth_context_complete(server)) {
			t->parse_error = PARSE_ERROR_REPLAY;
			return 0;
		}
	}

	/* Enforce a reasonable cap on the number of replays */
	if (t->replay_count++ >= GIT_HTTP_REPLAY_MAX) {
		git_error_set(GIT_ERROR_NET, "too many redirects or authentication replays");
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	if (!server->credtypes) {
		git_error_set(GIT_ERROR_NET, "%s requested authentication but did not negotiate mechanisms", type);
		t->parse_error = PARSE_ERROR_GENERIC;
		return t->parse_error;
	}

	free_auth_context(server);
	free_cred(&server->cred);

	/* Start with URL-specified credentials, if there were any. */
	if (!server->url_cred_presented && server->url.username && server->url.password) {
		error = apply_url_credentials(&server->cred, server->credtypes, server->url.username, server->url.password);
		server->url_cred_presented = 1;

		if (error == GIT_PASSTHROUGH) {
			/* treat GIT_PASSTHROUGH as if callback isn't set */
			error = 1;
		}
	}

	if (error > 0 && callback) {
		error = callback(&server->cred, url, server->url.username, server->credtypes, callback_payload);

		if (error == GIT_PASSTHROUGH) {
			/* treat GIT_PASSTHROUGH as if callback isn't set */
			error = 1;
		}
	}

	if (error > 0) {
		git_error_set(GIT_ERROR_NET, "%s authentication required but no callback set",
			type);
		t->parse_error = PARSE_ERROR_GENERIC;
		return t->parse_error;
	} else if (error < 0) {
		t->error = error;
		t->parse_error = PARSE_ERROR_EXT;
		return t->parse_error;
	}

	assert(server->cred);

	if (!(server->cred->credtype & server->credtypes)) {
		git_error_set(GIT_ERROR_NET, "%s credential provider returned an invalid cred type", type);
		t->parse_error = PARSE_ERROR_GENERIC;
		return t->parse_error;
	}

	/* Successfully acquired a credential. Start an auth context. */
	if (init_auth(server) < 0) {
		t->parse_error = PARSE_ERROR_GENERIC;
		return t->parse_error;
	}

	t->parse_error = PARSE_ERROR_REPLAY;
	return 0;
}

static void on_auth_success(http_server *server)
{
	server->url_cred_presented = 0;
	server->authenticated = 1;
}

GIT_INLINE(int) on_proxy_auth_required(http_parser *parser)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *transport = ctx->t;

	return on_auth_required(
	    parser,
	    &transport->proxy,
	    transport->proxy_opts.url,
	    SERVER_TYPE_PROXY,
	    transport->proxy_opts.credentials,
	    transport->proxy_opts.payload);
}

GIT_INLINE(int) on_remote_auth_required(http_parser *parser)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *transport = ctx->t;

	return on_auth_required(
	    parser,
	    &transport->server,
	    transport->owner->url,
	    SERVER_TYPE_REMOTE,
	    transport->owner->cred_acquire_cb,
	    transport->owner->cred_acquire_payload);
}

static int on_headers_complete(http_parser *parser)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;
	http_stream *s = ctx->s;

	/* Finalize the last seen header */
	if (t->parse_header_state == PARSE_HEADER_VALUE &&
	    on_header_complete(t) < 0)
	    return t->parse_error = PARSE_ERROR_GENERIC;

	if (t->parse_header_state == PARSE_HEADER_NAME) {
		git_error_set(GIT_ERROR_NET, "invalid header handling");
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	t->parse_header_state = PARSE_HEADER_COMPLETE;

	/* Check for a proxy authentication failure. */
	if (parser->status_code == 407)
		return on_proxy_auth_required(parser);
	else
		on_auth_success(&t->proxy);

	/* Check for an authentication failure. */
	if (parser->status_code == 401)
		return on_remote_auth_required(parser);
	else
		on_auth_success(&t->server);

	/* Check for a redirect.
	 * Right now we only permit a redirect to the same hostname. */
	if ((parser->status_code == 301 ||
	     parser->status_code == 302 ||
	     (parser->status_code == 303 && s->service->verb == GET) ||
	     parser->status_code == 307 ||
	     parser->status_code == 308) &&
	    t->location) {

		if (git_net_url_apply_redirect(&t->server.url, t->location, s->service->url) < 0)
			return t->parse_error = PARSE_ERROR_GENERIC;

		t->connected = 0;
		t->parse_error = PARSE_ERROR_REPLAY;
		return 0;
	}

	/* Check for a 200 HTTP status code. */
	if (parser->status_code != 200) {
		git_error_set(GIT_ERROR_NET,
			"unexpected HTTP status code: %d",
			parser->status_code);
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	/* The response must contain a Content-Type header. */
	if (!t->content_type) {
		git_error_set(GIT_ERROR_NET, "no Content-Type header in response");
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	/* The Content-Type header must match our expectation. */
	if (strcmp(t->content_type, s->service->response_type) != 0) {
		git_error_set(GIT_ERROR_NET,
			"invalid Content-Type: %s",
			t->content_type);
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	return 0;
}

static int on_message_complete(http_parser *parser)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;

	t->parse_finished = 1;
	t->keepalive = http_should_keep_alive(parser);

	return 0;
}

static int on_body_fill_buffer(http_parser *parser, const char *str, size_t len)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;

	/* If there's no buffer set, we're explicitly ignoring the body. */
	if (ctx->buffer) {
		if (ctx->buf_size < len) {
			git_error_set(GIT_ERROR_NET, "can't fit data in the buffer");
			return t->parse_error = PARSE_ERROR_GENERIC;
		}

		memcpy(ctx->buffer, str, len);
		ctx->buffer += len;
		ctx->buf_size -= len;
	}

	*(ctx->bytes_read) += len;

	return 0;
}

static void clear_parser_state(http_subtransport *t)
{
	http_parser_init(&t->parser, HTTP_RESPONSE);
	gitno_buffer_setup_fromstream(t->server.stream,
		&t->parse_buffer,
		t->parse_buffer_data,
		sizeof(t->parse_buffer_data));

	t->parse_header_state = PARSE_HEADER_NONE;
	t->parse_error = 0;
	t->parse_finished = 0;
	t->keepalive = 0;

	git_buf_dispose(&t->parse_header_name);
	git_buf_init(&t->parse_header_name, 0);

	git_buf_dispose(&t->parse_header_value);
	git_buf_init(&t->parse_header_value, 0);

	git__free(t->content_type);
	t->content_type = NULL;

	git__free(t->content_length);
	t->content_length = NULL;

	git__free(t->location);
	t->location = NULL;

	git_vector_free_deep(&t->proxy.auth_challenges);
	git_vector_free_deep(&t->server.auth_challenges);
}

GIT_INLINE(int) stream_write(git_stream *stream, const char *data, size_t len, int flags)
{
	git_trace(GIT_TRACE_TRACE, "Sending request:\n%.*s", (int)len, data);
	return git_stream__write_full(stream, data, len, flags);
}

static int write_chunk(git_stream *io, const char *buffer, size_t len)
{
	git_buf buf = GIT_BUF_INIT;

	/* Chunk header */
	git_buf_printf(&buf, "%" PRIxZ "\r\n", len);

	if (git_buf_oom(&buf))
		return -1;

	if (stream_write(io, buf.ptr, buf.size, 0) < 0) {
		git_buf_dispose(&buf);
		return -1;
	}

	git_buf_dispose(&buf);

	/* Chunk body */
	if (len > 0 && stream_write(io, buffer, len, 0) < 0)
		return -1;

	/* Chunk footer */
	if (stream_write(io, "\r\n", 2, 0) < 0)
		return -1;

	return 0;
}

static int load_proxy_config(http_subtransport *t)
{
	int error;

	switch (t->owner->proxy.type) {
	case GIT_PROXY_NONE:
		return 0;

	case GIT_PROXY_AUTO:
		git__free(t->proxy_url);
		t->proxy_url = NULL;

		git_proxy_options_init(&t->proxy_opts, GIT_PROXY_OPTIONS_VERSION);

		if ((error = git_remote__get_http_proxy(t->owner->owner,
			!strcmp(t->server.url.scheme, "https"), &t->proxy_url)) < 0)
			return error;

		if (!t->proxy_url)
			return 0;

		t->proxy_opts.type = GIT_PROXY_SPECIFIED;
		t->proxy_opts.url = t->proxy_url;
		t->proxy_opts.credentials = t->owner->proxy.credentials;
		t->proxy_opts.certificate_check = t->owner->proxy.certificate_check;
		t->proxy_opts.payload = t->owner->proxy.payload;
		break;

	case GIT_PROXY_SPECIFIED:
		memcpy(&t->proxy_opts, &t->owner->proxy, sizeof(git_proxy_options));
		break;

	default:
		assert(0);
		return -1;
	}

	git_net_url_dispose(&t->proxy.url);

	return git_net_url_parse(&t->proxy.url, t->proxy_opts.url);
}

static int check_certificate(
	git_stream *stream,
	git_net_url *url,
	int is_valid,
	git_transport_certificate_check_cb cert_cb,
	void *cert_cb_payload)
{
	git_cert *cert;
	git_error_state last_error = {0};
	int error;

	if ((error = git_stream_certificate(&cert, stream)) < 0)
		return error;

	git_error_state_capture(&last_error, GIT_ECERTIFICATE);

	error = cert_cb(cert, is_valid, url->host, cert_cb_payload);

	if (error == GIT_PASSTHROUGH && !is_valid)
		return git_error_state_restore(&last_error);
	else if (error == GIT_PASSTHROUGH)
		error = 0;
	else if (error && !git_error_last())
		git_error_set(GIT_ERROR_NET, "user rejected certificate for %s", url->host);

	git_error_state_free(&last_error);
	return error;
}

static int stream_connect(
	git_stream *stream,
	git_net_url *url,
	git_transport_certificate_check_cb cert_cb,
	void *cb_payload)
{
	int error;

	GIT_ERROR_CHECK_VERSION(stream, GIT_STREAM_VERSION, "git_stream");

	error = git_stream_connect(stream);

	if (error && error != GIT_ECERTIFICATE)
		return error;

	if (git_stream_is_encrypted(stream) && cert_cb != NULL)
		error = check_certificate(stream, url, !error, cert_cb, cb_payload);

	return error;
}

static int gen_connect_req(git_buf *buf, http_subtransport *t)
{
	git_buf_printf(buf, "CONNECT %s:%s HTTP/1.1\r\n",
		t->server.url.host, t->server.url.port);

	git_buf_puts(buf, "User-Agent: ");
	git_http__user_agent(buf);
	git_buf_puts(buf, "\r\n");

	git_buf_printf(buf, "Host: %s\r\n", t->proxy.url.host);

	if (apply_credentials(buf, &t->proxy, AUTH_HEADER_PROXY) < 0)
		return -1;

	git_buf_puts(buf, "\r\n");

	return git_buf_oom(buf) ? -1 : 0;
}

static int proxy_headers_complete(http_parser *parser)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;

	if (t->parse_header_state == PARSE_HEADER_VALUE &&
	    on_header_complete(t) < 0)
	    return t->parse_error = PARSE_ERROR_GENERIC;

	if (t->parse_header_state == PARSE_HEADER_NAME) {
		git_error_set(GIT_ERROR_NET, "invalid header handling");
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	t->parse_header_state = PARSE_HEADER_COMPLETE;

	/* Check for a proxy authentication failure. */

	/*
	 * Capture authentication headers for the proxy or final endpoint,
	 * these may be 407/401 (authentication is not complete) or a 200
	 * (informing us that auth has completed).
	 */
	if (parse_authenticate_response(&t->proxy) < 0)
		return t->parse_error = PARSE_ERROR_GENERIC;

	/* If we're in the middle of challenge/response auth, continue */
	if (parser->status_code == 407) {
		if (t->proxy.auth_context && !auth_context_complete(&t->proxy)) {
			t->parse_error = PARSE_ERROR_REPLAY;
			return 0;
		}
	}

	/* Enforce a reasonable cap on the number of replays */
	if (t->replay_count++ >= GIT_HTTP_REPLAY_MAX) {
		git_error_set(GIT_ERROR_NET, "too many redirects or authentication replays");
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	/* Check for a proxy authentication failure. */
	if (parser->status_code == 407)
		return on_auth_required(
			parser,
			&t->proxy,
			t->proxy_opts.url,
			SERVER_TYPE_PROXY,
			t->proxy_opts.credentials,
			t->proxy_opts.payload);

	if (parser->status_code != 200) {
		git_error_set(GIT_ERROR_NET, "unexpected status code from proxy: %d",
			parser->status_code);
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	if (!t->content_length || strcmp(t->content_length, "0") == 0)
		t->parse_finished = 1;

	return 0;
}

static int read_response(
	size_t *bytes_read,
	bool *auth_replay,
	http_stream *s,
	http_subtransport *t,
	http_parser_settings *parser_settings,
	char *body_buffer,
	size_t body_buf_size)
{
	parser_context ctx;
	bool read_body = (body_buffer != NULL);
	size_t bytes_parsed;
	int error = 0;

	while (!*bytes_read && !t->parse_finished) {
		/*
		 * If we have carryover data from an expect/continue call,
		 * use it, don't read from the socket.  (Otherwise, start
		 * reading at the end of the parse buffer.)
		 */
		size_t data_offset = t->carryover ? 0 : t->parse_buffer.offset;
		size_t orig_buffer_len = t->parse_buffer.len;

		/*
		 * If our output buffer is not as big as the parse buffer,
		 * shrink the parse buffer to ensure that we don't read more
		 * than would fit in the output buffer.
		 */
		if (read_body && body_buf_size < t->parse_buffer.len)
			t->parse_buffer.len = body_buf_size;

		if (t->carryover) {
			t->carryover = 0;
		} else if ((error = gitno_recv(&t->parse_buffer)) < 0) {
			goto done;
		} else if (error == 0 && t->request_count > 0) {
			/* Server closed a keep-alive socket; reconnect. */
			*auth_replay = true;
			goto done;
		} else if (error == 0) {
			git_error_set(GIT_ERROR_NET, "unexpected disconnection from server");
			error = -1;
			goto done;
		}

		git_trace(GIT_TRACE_TRACE, "Receiving data:\n%.*s", t->parse_buffer.offset - data_offset, t->parse_buffer.data + data_offset);

		t->parse_buffer.len = orig_buffer_len;

		/*
		 * This call to http_parser_execute will result in invocations
		 * of the on_* family of callbacks, including on_body_fill_buffer
		 * which will write into the target buffer unless we're ignoring it.
		 */
		ctx.t = t;
		ctx.s = s;
		ctx.buffer = read_body ? body_buffer : NULL;
		ctx.buf_size = read_body ? body_buf_size : 0;
		ctx.bytes_read = bytes_read;

		/* Set the context, call the parser, then unset the context. */
		t->parser.data = &ctx;

		bytes_parsed = http_parser_execute(&t->parser,
			parser_settings,
			t->parse_buffer.data + data_offset,
			t->parse_buffer.offset - data_offset);

		t->parser.data = NULL;

		/* On a 401, read the rest of the response then retry. */
		if (t->parse_error == PARSE_ERROR_REPLAY) {
			*auth_replay = true;
		} else if (t->parse_error == PARSE_ERROR_EXT) {
			error = t->error;
			goto done;
		} else if (t->parse_error < 0) {
			error = -1;
			goto done;
		}

		if (read_body && bytes_parsed != t->parse_buffer.offset - data_offset) {
			git_error_set(GIT_ERROR_NET,
				"HTTP parser error: %s",
				http_errno_description((enum http_errno)t->parser.http_errno));
			error = -1;
			goto done;
		}

		/*
		 * The server may have given us more than just a single response
		 * to our request.  eg, when sending an Expect: 100-continue, the
		 * server may reply with a 100 Continue and immediately reply with
		 * a 200 OK.  If so, move that 200 response up to the front of the
		 * buffer for subsequent read calls to consume.  Mark that we'll
		 * "carryover" this data, which means that the subsequent parser
		 * call shouldn't do a read on the socket, it already has data in
		 * the buffer that it should use.
		 */
		if (!read_body && t->parse_buffer.offset > bytes_parsed) {
			size_t new_offset = t->parse_buffer.offset - bytes_parsed;

			memmove(t->parse_buffer.data, t->parse_buffer.data + bytes_parsed, new_offset);
			t->parse_buffer.offset = new_offset;
			t->carryover = 1;
		}
	}

done:
	return error;
}

static int proxy_connect(
	git_stream **out, git_stream *proxy_stream, http_subtransport *t)
{
	git_buf request = GIT_BUF_INIT;
	static http_parser_settings proxy_parser_settings = {0};
	size_t bytes_read = 0;
	bool auth_replay;
	int error;

	/* Use the parser settings only to parser headers. */
	proxy_parser_settings.on_header_field = on_header_field;
	proxy_parser_settings.on_header_value = on_header_value;
	proxy_parser_settings.on_headers_complete = proxy_headers_complete;
	proxy_parser_settings.on_message_complete = on_message_complete;

replay:
	git_buf_clear(&request);
	clear_parser_state(t);
	auth_replay = false;

	gitno_buffer_setup_fromstream(proxy_stream,
		&t->parse_buffer,
		t->parse_buffer_data,
		sizeof(t->parse_buffer_data));

	if ((error = gen_connect_req(&request, t)) < 0 ||
	    (error = stream_write(proxy_stream, request.ptr, request.size, 0)) < 0 ||
	    (error = read_response(&bytes_read, &auth_replay, NULL, t, &proxy_parser_settings, NULL, 0)) < 0)
		goto done;

	/* Ensure that we didn't get a redirect; unsupported. */
	if (t->location) {
		git_error_set(GIT_ERROR_NET, "proxy server sent unsupported redirect during CONNECT");
		error = -1;
		goto done;
	}

	t->request_count++;

	if (auth_replay) {
		if (t->keepalive && t->parse_finished)
			goto replay;

		return PARSE_ERROR_REPLAY;
	}

	if ((error = git_tls_stream_wrap(out, proxy_stream, t->server.url.host)) == 0)
		error = stream_connect(*out, &t->server.url,
		    t->owner->certificate_check_cb,
			t->owner->message_cb_payload);

	/*
	 * Since we've connected via a HTTPS proxy tunnel, we don't behave
	 * as if we have an HTTP proxy.
	 */
	t->proxy_opts.type = GIT_PROXY_NONE;
	t->replay_count = 0;
	t->request_count = 0;

done:
	git_buf_dispose(&request);
	return error;
}

static void reset_auth_connection(http_server *server)
{
	/*
	 * If we've authenticated and we're doing "normal"
	 * authentication with a request affinity (Basic, Digest)
	 * then we want to _keep_ our context, since authentication
	 * survives even through non-keep-alive connections.  If
	 * we've authenticated and we're doing connection-based
	 * authentication (NTLM, Negotiate) - indicated by the presence
	 * of an `is_complete` callback - then we need to restart
	 * authentication on a new connection.
	 */

	if (server->authenticated &&
		server->auth_context &&
	    server->auth_context->connection_affinity) {
		server->prior_authtype = server->auth_context->type;

		free_auth_context(server);

		server->url_cred_presented = 0;
		server->authenticated = 0;
	}
}

static int http_connect(http_subtransport *t)
{
	git_net_url *url;
	git_stream *proxy_stream = NULL, *stream = NULL;
	git_transport_certificate_check_cb cert_cb;
	void *cb_payload;
	int error;

auth_replay:
	if (t->connected && t->keepalive && t->parse_finished)
		return 0;

	if ((error = load_proxy_config(t)) < 0)
		return error;

	if (t->server.stream) {
		git_stream_close(t->server.stream);
		git_stream_free(t->server.stream);
		t->server.stream = NULL;
	}

	if (t->proxy.stream) {
		git_stream_close(t->proxy.stream);
		git_stream_free(t->proxy.stream);
		t->proxy.stream = NULL;
	}

	reset_auth_connection(&t->server);
	reset_auth_connection(&t->proxy);

	t->connected = 0;
	t->keepalive = 0;
	t->request_count = 0;

	if (t->proxy_opts.type == GIT_PROXY_SPECIFIED) {
		url = &t->proxy.url;
		cert_cb = t->proxy_opts.certificate_check;
		cb_payload = t->proxy_opts.payload;
	} else {
		url = &t->server.url;
		cert_cb = t->owner->certificate_check_cb;
		cb_payload = t->owner->message_cb_payload;
	}

	if (strcmp(url->scheme, "https") == 0)
		error = git_tls_stream_new(&stream, url->host, url->port);
	else
		error = git_socket_stream_new(&stream, url->host, url->port);

	if (error < 0)
		goto on_error;

	if ((error = stream_connect(stream, url, cert_cb, cb_payload)) < 0)
		goto on_error;

	/*
	 * At this point we have a connection to the remote server or to
	 * a proxy.  If it's a proxy and the remote server is actually
	 * an HTTPS connection, then we need to build a CONNECT tunnel.
	 */
	if (t->proxy_opts.type == GIT_PROXY_SPECIFIED &&
	    strcmp(t->server.url.scheme, "https") == 0) {
		proxy_stream = stream;
		stream = NULL;

		error = proxy_connect(&stream, proxy_stream, t);

		if (error == PARSE_ERROR_REPLAY) {
			git_stream_close(proxy_stream);
			git_stream_free(proxy_stream);
			goto auth_replay;
		} else if (error < 0) {
			goto on_error;
		}
	}

	t->proxy.stream = proxy_stream;
	t->server.stream = stream;
	t->connected = 1;
	return 0;

on_error:
	if (stream) {
		git_stream_close(stream);
		git_stream_free(stream);
	}

	if (proxy_stream) {
		git_stream_close(proxy_stream);
		git_stream_free(proxy_stream);
	}

	return error;
}

static int http_stream_read(
	git_smart_subtransport_stream *stream,
	char *buffer,
	size_t buf_size,
	size_t *bytes_read)
{
	http_stream *s = (http_stream *)stream;
	http_subtransport *t = OWNING_SUBTRANSPORT(s);
	git_buf request = GIT_BUF_INIT;
	bool auth_replay;
	int error = 0;

replay:
	*bytes_read = 0;
	auth_replay = false;

	assert(t->connected);

	if (!s->sent_request) {
		git_buf_clear(&request);
		clear_parser_state(t);

		if ((error = gen_request(&request, s, 0, false)) < 0 ||
		    (error = stream_write(t->server.stream, request.ptr, request.size, 0)) < 0)
			goto done;

		s->sent_request = 1;
	}

	if (!s->received_response) {
		if (s->service->chunked) {
			assert(s->service->verb == POST);

			/* Flush, if necessary */
			if (s->chunk_buffer_len > 0) {
				if ((error = write_chunk(t->server.stream, s->chunk_buffer, s->chunk_buffer_len)) < 0)
					goto done;

				s->chunk_buffer_len = 0;
			}

			/* Write the final chunk. */
			if ((error = stream_write(t->server.stream,
						   "0\r\n\r\n", 5, 0)) < 0)
				goto done;
		}

		s->received_response = 1;
	}

	if ((error = read_response(bytes_read, &auth_replay, s, t, &t->settings, buffer, buf_size)) < 0)
		goto done;

	t->request_count++;

	if (auth_replay) {
		if (s->service->verb == POST) {
			git_error_set(GIT_ERROR_NET, "unrecoverable authentication failure during POST");
			error = -1;
			goto done;
		}

		s->sent_request = 0;

		if ((error = http_connect(t)) < 0)
			return error;

		goto replay;
	}

done:
	git_buf_dispose(&request);
	return error;
}

static int continue_headers_complete(http_parser *parser)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;

	if (t->parse_header_state == PARSE_HEADER_VALUE &&
	    on_header_complete(t) < 0)
	    return t->parse_error = PARSE_ERROR_GENERIC;

	if (t->parse_header_state == PARSE_HEADER_NAME) {
		git_error_set(GIT_ERROR_NET, "invalid header handling");
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	t->parse_header_state = PARSE_HEADER_COMPLETE;

	/* Check for a proxy authentication failure. */

	/* Check for a proxy authentication failure. */
	if (parser->status_code == 407)
		return on_remote_auth_required(parser);
	else
		on_auth_success(&t->proxy);

	/* Check for an authentication failure. */
	if (parser->status_code == 401)
		return on_proxy_auth_required(parser);
	else
		on_auth_success(&t->server);

	/* Check for a 100 (continue) HTTP status code. */
	if (parser->status_code != 100) {
		git_error_set(GIT_ERROR_NET,
		              "unexpected HTTP status code: %d",
		              parser->status_code);
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	t->parse_finished = 1;
	return 0;
}

static int continue_message_complete(http_parser *parser)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;

	t->parse_finished = 1;
	t->keepalive = http_should_keep_alive(parser);

	/*
	 * Instruct http_parser to stop parsing.  A server may try to
	 * pipeline the 200 OK since it's basically just opening a
	 * connection to git, and any I/O is done through the HTTP
	 * body.  So as long as authentication succeeds, we may get
	 * the expected 100 Continue followed immediately by a
	 * 200 OK.  We want http_parser to stop parsing as soon as
	 * it's seen the 100 Continue; returning 0 here will allow
	 * it to continue parsing the buffer that may have the 200.
	 */
	return -1;
}

static int http_stream_write_request_expectcontinue(http_stream *s, size_t len)
{
	http_subtransport *t = OWNING_SUBTRANSPORT(s);
	static http_parser_settings continue_parser_settings = {0};
	git_buf request = GIT_BUF_INIT;
	size_t bytes_read = 0;
	bool auth_replay;
	int error;

	/* Use the parser settings only to parser headers. */
	continue_parser_settings.on_header_field = on_header_field;
	continue_parser_settings.on_header_value = on_header_value;
	continue_parser_settings.on_headers_complete = continue_headers_complete;
	continue_parser_settings.on_message_complete = continue_message_complete;

replay:
	git_buf_clear(&request);
	clear_parser_state(t);
	auth_replay = false;

	git_trace(GIT_TRACE_DEBUG, "Sending expect/continue request");

	if ((error = gen_request(&request, s, len, true)) < 0 ||
	    (error = stream_write(t->server.stream, request.ptr, request.size, 0)) < 0 ||
	    (error = read_response(&bytes_read, &auth_replay, NULL, t, &continue_parser_settings, NULL, 0)) < 0)
		goto done;

	if (t->parser.http_errno != HPE_CB_message_complete) {
		git_error_set(GIT_ERROR_NET,
						"HTTP parser error: %s",
						http_errno_description((enum http_errno)t->parser.http_errno));
		error = -1;
		goto done;
	}

	t->parser.http_errno = HPE_OK;
	t->request_count++;

	if (auth_replay) {
		s->sent_request = 0;

		if ((error = http_connect(t)) < 0)
			return error;

		goto replay;
	}

	s->sent_request = 1;
	t->parse_finished = 0;

done:
	git_buf_dispose(&request);
	return error;
}

static int http_stream_write_request_standard(http_stream *s, size_t len)
{
	http_subtransport *t = OWNING_SUBTRANSPORT(s);
	git_buf request = GIT_BUF_INIT;
	int error;

	clear_parser_state(t);

	if ((error = gen_request(&request, s, len, false)) < 0 ||
	    (error = stream_write(t->server.stream, request.ptr, request.size, 0)) < 0)
		goto done;

	s->sent_request = 1;

done:
	git_buf_dispose(&request);
	return error;
}

static int probe_headers_complete(http_parser *parser)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;

	if (t->parse_header_state == PARSE_HEADER_VALUE &&
	    on_header_complete(t) < 0)
	    return t->parse_error = PARSE_ERROR_GENERIC;

	if (t->parse_header_state == PARSE_HEADER_NAME) {
		git_error_set(GIT_ERROR_NET, "invalid header handling");
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	t->parse_header_state = PARSE_HEADER_COMPLETE;

	/* Check for a proxy authentication failure. */

	/* Check for a proxy authentication failure. */
	if (parser->status_code == 407)
		return on_proxy_auth_required(parser);
	else
		on_auth_success(&t->proxy);

	/* Check for an authentication failure. */
	if (parser->status_code == 401)
		return on_remote_auth_required(parser);
	else
		on_auth_success(&t->server);

	if (parser->status_code != 200) {
		git_error_set(GIT_ERROR_NET,
		              "unexpected HTTP status code: %d",
		              parser->status_code);
		return t->parse_error = PARSE_ERROR_GENERIC;
	}

	return 0;
}

static int probe_message_complete(http_parser *parser)
{
	parser_context *ctx = (parser_context *) parser->data;
	http_subtransport *t = ctx->t;

	t->parse_finished = 1;
	t->keepalive = http_should_keep_alive(parser);

	return 0;
}

/*
 * Some servers (eg, Apache) do not do "connection affinity" for NTLM or
 * SPNEGO authentication.  Connection affinity is when an entire keep-alive
 * session should be authenticated to prevent unnecessary challenge/request.
 * Servers that don't do this will require us to do a challenge/response on
 * every request.  This is terrible for POSTing data, since we're sending a
 * whole payload in our initial request, then getting a 401 with a challenge,
 * then sending the payload *again* with our response.  Worse, we don't
 * buffer the POST data, so there's no way for us to resend it.
 *
 * Workaround this by sending an initial POST with a "probe packet" (a no-op
 * git packet of "0000").  If we're talking to a server with connection
 * affinity, then this will get a 200 and we can carry on with our
 * actual POST.  If we're talking to a server without, we'll get a 401, and
 * our subsequent POST will include the auth response.
 */
static int http_stream_write_request_with_probe(http_stream *s, size_t len)
{
	http_subtransport *t = OWNING_SUBTRANSPORT(s);
	static http_parser_settings probe_parser_settings = {0};
	git_buf request = GIT_BUF_INIT;
	const char *probe = "0000";
	size_t probe_len = strlen(probe);
	size_t bytes_read = 0;
	bool auth_replay;
	int error;

	/* Use the parser settings only to parse headers. */
	probe_parser_settings.on_header_field = on_header_field;
	probe_parser_settings.on_header_value = on_header_value;
	probe_parser_settings.on_headers_complete = probe_headers_complete;
	probe_parser_settings.on_message_complete = probe_message_complete;

	clear_parser_state(t);
	auth_replay = false;

	if ((error = gen_request(&request, s, probe_len, false)) < 0 ||
	    (error = stream_write(t->server.stream, request.ptr, request.size, 0)) < 0 ||
	    (error = stream_write(t->server.stream, probe, probe_len, 0)) < 0)
		goto done;

	/* Consume the entire message body */
	while ((error = read_response(&bytes_read, &auth_replay, NULL, t, &probe_parser_settings, NULL, 0)) > 0)
		/* do nothing with the data */ ;

	if (error < 0)
		goto done;

	/*
	 * At this point, we either got a 200 (because we're talking to a
	 * server that does SPNEGO connection affinity properly) or a 401.
	 * Our subsequent request will provide the authentication headers
	 * (if we got a 401) and our proper data.
	 */
	s->sent_request = 0;

	if ((error = http_connect(t)) < 0)
		return error;

	error = http_stream_write_request_standard(s, len);

done:
	git_buf_dispose(&request);
	return error;
}

static bool needs_negotiated_auth(http_stream *s)
{
	http_subtransport *t = OWNING_SUBTRANSPORT(s);

	if (t->server.authenticated == 0 &&
	    (t->server.prior_authtype == GIT_AUTHTYPE_NTLM ||
	     t->server.prior_authtype == GIT_AUTHTYPE_NEGOTIATE))
		return true;

	if (t->proxy.authenticated == 0 &&
	    (t->proxy.prior_authtype == GIT_AUTHTYPE_NTLM ||
	     t->proxy.prior_authtype == GIT_AUTHTYPE_NEGOTIATE))
		return true;

	return false;
}

static int http_stream_write_request(http_stream *s, size_t len)
{
	if (needs_negotiated_auth(s) && git_http__expect_continue)
		return http_stream_write_request_expectcontinue(s, len);
	else if (needs_negotiated_auth(s))
		return http_stream_write_request_with_probe(s, len);
	else
		return http_stream_write_request_standard(s, len);
}

static int http_stream_write_chunked(
	http_stream *s,
	const char *buffer,
	size_t len)
{
	http_subtransport *t = OWNING_SUBTRANSPORT(s);

	assert(t->connected);

	/* Send the request, if necessary */
	if (!s->sent_request) {
		if (http_stream_write_request(s, 0) < 0)
			return -1;
	}

	if (len > CHUNK_SIZE) {
		/* Flush, if necessary */
		if (s->chunk_buffer_len > 0) {
			if (write_chunk(t->server.stream,
			    s->chunk_buffer, s->chunk_buffer_len) < 0)
				return -1;

			s->chunk_buffer_len = 0;
		}

		/* Write chunk directly */
		if (write_chunk(t->server.stream, buffer, len) < 0)
			return -1;
	}
	else {
		/* Append as much to the buffer as we can */
		int count = min(CHUNK_SIZE - s->chunk_buffer_len, len);

		if (!s->chunk_buffer) {
			s->chunk_buffer = git__malloc(CHUNK_SIZE);
			GIT_ERROR_CHECK_ALLOC(s->chunk_buffer);
		}

		memcpy(s->chunk_buffer + s->chunk_buffer_len, buffer, count);
		s->chunk_buffer_len += count;
		buffer += count;
		len -= count;

		/* Is the buffer full? If so, then flush */
		if (CHUNK_SIZE == s->chunk_buffer_len) {
			if (write_chunk(t->server.stream,
			    s->chunk_buffer, s->chunk_buffer_len) < 0)
				return -1;

			s->chunk_buffer_len = 0;

			if (len > 0) {
				memcpy(s->chunk_buffer, buffer, len);
				s->chunk_buffer_len = len;
			}
		}
	}

	return 0;
}

static int http_stream_write_single(
	http_stream *s,
	const char *buffer,
	size_t len)
{
	http_subtransport *t = OWNING_SUBTRANSPORT(s);

	assert(t->connected);

	if (s->sent_request) {
		git_error_set(GIT_ERROR_NET, "subtransport configured for only one write");
		return -1;
	}

	if (http_stream_write_request(s, len) < 0)
		return -1;

	if (len && stream_write(t->server.stream, buffer, len, 0) < 0)
		return -1;

	return 0;
}

static int http_stream_write(
	git_smart_subtransport_stream *stream,
	const char *buffer,
	size_t len)
{
	http_stream *s = GIT_CONTAINER_OF(stream, http_stream, parent);

	if (s->service->chunked)
		return http_stream_write_chunked(s, buffer, len);
	else
		return http_stream_write_single(s, buffer, len);
}

static void http_stream_free(git_smart_subtransport_stream *stream)
{
	http_stream *s = GIT_CONTAINER_OF(stream, http_stream, parent);

	if (s->chunk_buffer)
		git__free(s->chunk_buffer);

	git__free(s);
}

static git_http_service *select_service(git_smart_service_t action)
{
	switch (action) {
	case GIT_SERVICE_UPLOADPACK_LS:
		return &upload_pack_ls_service;
	case GIT_SERVICE_UPLOADPACK:
		return &upload_pack_service;
	case GIT_SERVICE_RECEIVEPACK_LS:
		return &receive_pack_ls_service;
	case GIT_SERVICE_RECEIVEPACK:
		return &receive_pack_service;
	}

	return NULL;
}

static int http_action(
	git_smart_subtransport_stream **out,
	git_smart_subtransport *t,
	const char *url,
	git_smart_service_t action)
{
	http_subtransport *transport = GIT_CONTAINER_OF(t, http_subtransport, parent);
	http_stream *stream;
	git_http_service *service;
	int error;

	assert(out && t);

	*out = NULL;

	/*
	 * If we've seen a redirect then preserve the location that we've
	 * been given.  This is important to continue authorization against
	 * the redirect target, not the user-given source; the endpoint may
	 * have redirected us from HTTP->HTTPS and is using an auth mechanism
	 * that would be insecure in plaintext (eg, HTTP Basic).
	 */
	if (!git_net_url_valid(&transport->server.url) &&
	    (error = git_net_url_parse(&transport->server.url, url)) < 0)
		return error;

	if ((error = http_connect(transport)) < 0)
		return error;

	if ((service = select_service(action)) == NULL) {
		git_error_set(GIT_ERROR_NET, "invalid action");
		return -1;
	}

	stream = git__calloc(sizeof(http_stream), 1);
	GIT_ERROR_CHECK_ALLOC(stream);

	stream->service = service;
	stream->parent.subtransport = &transport->parent;
	stream->parent.read = http_stream_read;
	stream->parent.write = http_stream_write;
	stream->parent.free = http_stream_free;

	*out = (git_smart_subtransport_stream *)stream;
	return 0;
}

static int http_close(git_smart_subtransport *t)
{
	http_subtransport *transport = GIT_CONTAINER_OF(t, http_subtransport, parent);

	clear_parser_state(transport);

	transport->connected = 0;

	if (transport->server.stream) {
		git_stream_close(transport->server.stream);
		git_stream_free(transport->server.stream);
		transport->server.stream = NULL;
	}

	if (transport->proxy.stream) {
		git_stream_close(transport->proxy.stream);
		git_stream_free(transport->proxy.stream);
		transport->proxy.stream = NULL;
	}

	free_cred(&transport->server.cred);
	free_cred(&transport->proxy.cred);

	free_auth_context(&transport->server);
	free_auth_context(&transport->proxy);

	transport->server.url_cred_presented = false;
	transport->proxy.url_cred_presented = false;

	git_net_url_dispose(&transport->server.url);
	git_net_url_dispose(&transport->proxy.url);

	git__free(transport->proxy_url);
	transport->proxy_url = NULL;

	return 0;
}

static void http_free(git_smart_subtransport *t)
{
	http_subtransport *transport = GIT_CONTAINER_OF(t, http_subtransport, parent);

	http_close(t);
	git__free(transport);
}

int git_smart_subtransport_http(git_smart_subtransport **out, git_transport *owner, void *param)
{
	http_subtransport *transport;

	GIT_UNUSED(param);

	assert(out);

	transport = git__calloc(sizeof(http_subtransport), 1);
	GIT_ERROR_CHECK_ALLOC(transport);

	transport->owner = (transport_smart *)owner;
	transport->parent.action = http_action;
	transport->parent.close = http_close;
	transport->parent.free = http_free;

	transport->settings.on_header_field = on_header_field;
	transport->settings.on_header_value = on_header_value;
	transport->settings.on_headers_complete = on_headers_complete;
	transport->settings.on_body = on_body_fill_buffer;
	transport->settings.on_message_complete = on_message_complete;

	*out = (git_smart_subtransport *) transport;
	return 0;
}

#endif /* !GIT_WINHTTP */
