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
#include "graph.h"
#include "pack-objects.h"

#include "git2/odb.h"
#include "git2/revwalk.h"
#include "git2/smart.h"
#include "git2/version.h"
#include "git2/sys/refs.h"

/* TODO : 1024 or something */
#define READ_SIZE 1

typedef struct {
	git_smart_capability capability;
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

/* TODO: we don't *actually* support MULTI_ACK_DETAILED or NO_DONE */
#define DEFAULT_SERVER_CAPABILITIES \
	(GIT_SMART_CAPABILITY_MULTI_ACK          | \
	 GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED | \
	 GIT_SMART_CAPABILITY_NO_DONE            | \
	 GIT_SMART_CAPABILITY_THIN_PACK          | \
	 GIT_SMART_CAPABILITY_SIDE_BAND          | \
/*	 GIT_SMART_CAPABILITY_SIDE_BAND_64K      | */ \
	 GIT_SMART_CAPABILITY_OFS_DELTA          | \
	 GIT_SMART_CAPABILITY_AGENT              | \
	 GIT_SMART_CAPABILITY_OBJECT_FORMAT      | \
	 GIT_SMART_CAPABILITY_SYMREF             | \
	 GIT_SMART_CAPABILITY_NO_PROGRESS        | \
	 GIT_SMART_CAPABILITY_INCLUDE_TAG        | \
	 GIT_SMART_CAPABILITY_SESSION_ID)


/* Capabilities that do not make sense for a client to request */
#define DISALLOWED_CLIENT_CAPABILITIES \
	(GIT_SMART_CAPABILITY_OBJECT_FORMAT      | \
	 GIT_SMART_CAPABILITY_SYMREF)

static struct git_smart_packet smart_packet_flush = {
	GIT_SMART_PACKET_FLUSH, "0000", CONST_STRLEN("0000"), 0
};
static struct git_smart_packet smart_packet_nak = {
	GIT_SMART_PACKET_NAK, "0008NAK\n", CONST_STRLEN("0008NAK\n"), 0
};

static struct git_smart_packet smart_packet_internal_error = {
	GIT_SMART_PACKET_ERR,
	"001eERR internal server error\n",
	CONST_STRLEN("001eERR internal server error\n"),
	0
};


static int pkt_write(git_smart_server *server, struct git_smart_packet *pkt);
static int pkt_format_with_buf(
	struct git_smart_packet *pkt,
	git_str *buf,
	git_smart_packet_t type,
	const char *fmt,
	...) GIT_FORMAT_PRINTF(4, 5);


int git_smart_server_init(git_smart_server **out, git_repository *repo)
{
	git_smart_server *server;

	GIT_ASSERT_ARG(out && repo);

	server = git__calloc(1, sizeof(git_smart_server));
	GIT_ERROR_CHECK_ALLOC(server);

	server->pkt_reader.oid_type = git_repository_oid_type(repo);

	server->repo = repo;
	server->capabilities = DEFAULT_SERVER_CAPABILITIES;

	/* TODO */
	server->capabilities |= GIT_SMART_CAPABILITY_ALLOW_ANY_SHA1_IN_WANT;

	*out = server;
	return 0;
}

static void append_useragent(git_str *out)
{
	const char *ua = git_libgit2__user_agent(), *c;

	git_str_puts(out, "git/2.0.(");

	if (!ua) {
		git_str_puts(out, "libgit2." LIBGIT2_VERSION);
	} else {
		for (c = ua; *c; c++)
			git_str_putc(out, isspace(*c) ? '.' : *c);
	}

	git_str_putc(out, ')');
}

static int append_capabilities(
	git_str *out,
	git_smart_server *server,
	const char *head)
{
	unsigned int server_caps = server->capabilities;
	const smart_capability_name *cap;

	git_str_putc(out, '\0');

	/* Implicitly upgrade allow-any to the other allow components */
	if (server_caps & GIT_SMART_CAPABILITY_ALLOW_ANY_SHA1_IN_WANT) {
		server_caps |= GIT_SMART_CAPABILITY_ALLOW_TIP_SHA1_IN_WANT;
		server_caps |= GIT_SMART_CAPABILITY_ALLOW_REACHABLE_SHA1_IN_WANT;
	}

	for (cap = smart_capabilities; cap->capability; cap++) {
		if ((server_caps & cap->capability) == 0)
			continue;

		switch (cap->capability) {
		case GIT_SMART_CAPABILITY_SYMREF:
			if (head) {
				git_str_puts(out, "symref=HEAD:");
				git_str_puts(out, head);
				git_str_putc(out, ' ');
			}
			break;
		case GIT_SMART_CAPABILITY_OBJECT_FORMAT:
			git_str_puts(out, "object-format=");
			git_str_puts(out, git_oid_type_name(git_repository_oid_type(server->repo)));
			git_str_putc(out, ' ');
			break;
		case GIT_SMART_CAPABILITY_AGENT:
			git_str_puts(out, "agent=");
			append_useragent(out);
			git_str_putc(out, ' ');
			break;
		case GIT_SMART_CAPABILITY_SESSION_ID:
			if (server->session_id) {
				git_str_puts(out, "session-id=");
				git_str_puts(out, server->session_id);
				git_str_putc(out, ' ');
			}
			break;
		default:
			if (!cap->name)
				break;

			git_str_puts(out, cap->name);
			git_str_putc(out, ' ');
		}
	}

	return git_str_oom(out) ? -1 : 0;
}

static int refname_cmp(const void *_a, const void *_b)
{
	const git_reference *a = _a, *b = _b;
	return strcmp(git_reference_name(a), git_reference_name(b));
}

static int advertise_ref(
	git_smart_server *server,
	const git_oid *id,
	const char *name,
	const char *target,
	const char *suffix)
{
	struct git_smart_packet ref_pkt = { 0 };
	struct git_smart_packet *response_pkt = &smart_packet_internal_error;
	git_str caps = GIT_STR_INIT;
	int error = -1;

	if (!server->sent_capabilities) {
		/* TODO: write error */
		if (append_capabilities(&caps, server, target) < 0)
			return -1;

		server->sent_capabilities = 1;
	}

	git_str_clear(&server->write_buf);

	if (pkt_format_with_buf(&ref_pkt, &server->write_buf,
			GIT_SMART_PACKET_NONE,
			"%s %s%s%s%s",
			git_oid_tostr_s(id),
			name,
			suffix ? suffix : "",
			caps.size ? "\0" : "",
			caps.size ? caps.ptr : "") == 0)
		response_pkt = &ref_pkt;

	error = pkt_write(server, response_pkt);

	git_str_dispose(&caps);
	return error;
}

static FILE *debug;

static int git_smart_server_advertise(
	git_smart_server *server,
	bool include_head_and_peeled)
{
	git_reference_iterator *iter = NULL;
	git_reference *head = NULL, *branch = NULL, *ref;
	git_reference *resolved;
	git_str advertisement = GIT_STR_INIT;
	const git_oid *peeled_id, *resolved_id;
	size_t i;
	int error = -1;

	if (git_vector_init(&server->advertised_refs, 32, refname_cmp) < 0 ||
	    git_vector_init(&server->resolved_refs, 32, refname_cmp) < 0 ||
	    git_vector_init(&server->advertised_ids, 32, (int (*)(const void *, const void *))(git_oid_cmp)) < 0)
		goto done;

	if (include_head_and_peeled) {
		if (git_reference_lookup(&head, server->repo, GIT_HEAD_FILE) < 0 ||
		    git_reference_resolve(&branch, head) < 0 ||
		    advertise_ref(server, git_reference_target(branch), "HEAD",
				git_reference_name(branch), NULL) < 0)
			goto done;
	}

	if (git_reference_iterator_new(&iter, server->repo) < 0)
		goto done;

	while ((error = git_reference_next(&ref, iter)) == 0) {
		if (git_vector_insert(&server->advertised_refs, ref) < 0)
			goto done;
	}

	if (error == GIT_ITEROVER)
		error = 0;

	git_vector_sort(&server->advertised_refs);

	git_vector_foreach(&server->advertised_refs, i, ref) {
		if (git_reference_resolve(&resolved, ref) < 0 ||
		    git_vector_insert(&server->resolved_refs, resolved) < 0)
			goto done;

		resolved_id = git_reference_target(resolved);
		peeled_id = git_reference_target_peel(ref);

		GIT_ASSERT(resolved_id != NULL);

		/*
		 * The advertised_ids is limited to commit ids; if this
		 * reference can be peeled (is a tag) then omit it.
		 */
		if (!peeled_id &&
		    git_vector_insert(&server->advertised_ids, (void *)resolved_id) < 0)
			goto done;

		if (advertise_ref(server, resolved_id, git_reference_name(ref), NULL, NULL) < 0)
			goto done;

		/* Only upload-pack peels the refs */
		if (include_head_and_peeled && peeled_id) {
			if (git_vector_insert(&server->advertised_ids, (void *)peeled_id) < 0 ||
			    advertise_ref(server, peeled_id, git_reference_name(ref), NULL, "^{}") < 0)
				goto done;
		}
	}

	if (pkt_write(server, &smart_packet_flush) < 0)
		goto done;

	error = 0;

done:
	git_reference_free(head);
	git_reference_free(branch);
	git_reference_iterator_free(iter);
	git_str_dispose(&advertisement);
	return error;
}

static int fill_read_buf(struct pkt_parser *parser, size_t len)
{
	char *buf;
	int ret;

	fprintf(debug, "filling read buf - size: %d / wanted: %d\n", (int)parser->read_buf.size, (int)len);

	while (parser->read_buf.size < len) {
		/* TODO: make sure this doesn't continutally realloc */
		if (git_str_grow(&parser->read_buf, READ_SIZE) < 0)
			return -1;

		buf = parser->read_buf.ptr + parser->read_buf.size;

		if ((ret = read(STDIN_FILENO, buf, READ_SIZE)) < 0) {
			git_error_set(GIT_ERROR_OS, "could not read from client");
			return -1;
		}

		fprintf(debug, ">>>read>>> %.*s\n", ret, buf);

		/* TODO: check overflow, ensure size <= asize */
		parser->read_buf.size += ret;

		if (ret == 0) {
			git_error_set(GIT_ERROR_NET, "unexpected eof from client");
			return -1;
		}
	}

	fprintf(debug, "filled read buf\n");
	fprintf(debug, "read buf is: '%.*s'\n", (int)parser->read_buf.size, parser->read_buf.ptr);

	return 0;
}

/*
 * TODO: we probably don't need to do a full clear on every read.
 * Just occasionally to prevent us from having an unnecessarily large buffer.
 */
GIT_INLINE(int) pkt_parser_reset(struct pkt_parser *parser)
{
	GIT_ASSERT(parser->read_buf.size >= parser->pkt.len);

	memmove(parser->read_buf.ptr,
	        parser->read_buf.ptr + parser->pkt.len,
	        parser->read_buf.size - parser->pkt.len);
	parser->read_buf.size -= parser->pkt.len;

	memset(&parser->pkt, 0, sizeof(struct git_smart_packet));

	parser->total_len = 0;
	parser->consumed = 0;
	parser->remain_data = NULL;
	parser->remain_len = 0;

	return 0;
}


/*
 * fill_read_buf may realloc our data buffer, so this is a wrapper
 * to update the positions.
 */
GIT_INLINE(int) pkt_parser_fill(struct pkt_parser *parser, size_t len)
{
	fprintf(debug, "-------------pkt_parser_fill-------------\n");

	/* TODO: sanity check arithmetic */
	if (fill_read_buf(parser, parser->consumed + len) < 0)
		return -1;

fprintf(debug, "%d %d\n", (int)parser->read_buf.size, (int)parser->consumed);

	GIT_ASSERT(parser->read_buf.size > parser->consumed);

	parser->remain_data = parser->read_buf.ptr + parser->consumed;
	parser->remain_len = len;

	return 0;
}

GIT_INLINE(int) pkt_parser_consume(struct pkt_parser *parser, size_t len)
{
	if (GIT_ADD_SIZET_OVERFLOW(&parser->consumed, parser->consumed, len))
		return -1;

	parser->remain_data = parser->read_buf.ptr + parser->consumed;
	parser->remain_len -= len;

	return 0;
}

static int pkt_parse_len(struct pkt_parser *parser)
{
	int64_t value;

	fprintf(debug, "-----------parsing len---------\n");

	if (parser->remain_len < 4) {
		git_error_set(GIT_ERROR_NET, "invalid packet - does not contain length");
		return -1;
	}

	if (!isxdigit(parser->remain_data[0]) ||
	    !isxdigit(parser->remain_data[1]) ||
	    !isxdigit(parser->remain_data[2]) ||
	    !isxdigit(parser->remain_data[3])) {
		git_error_set(GIT_ERROR_NET, "invalid packet - incorrectly encoded length: '%c%c%c%c'", parser->remain_data[0], parser->remain_data[1], parser->remain_data[2], parser->remain_data[3]);
		return -1;
	}

	printf("len: %c %c %c %c\n", parser->remain_data[0], parser->remain_data[1], parser->remain_data[2], parser->remain_data[3]);

	if (git__strntol64(&value, parser->remain_data, 4, NULL, 16) < 0 ||
	    value < 0 || value > UINT_MAX - 4) {
		git_error_set(GIT_ERROR_NET, "invalid packet - invalid decoded length");
		return -1;
	}

	parser->total_len = value;
	parser->remain_len = value;

	fprintf(debug, "0: total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);

	pkt_parser_consume(parser, 4);

	fprintf(debug, "1: total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);
	return 0;
}

static int pkt_parse_type(struct pkt_parser *parser)
{
	fprintf(debug, "parsing type: %d - '%.*s'\n", (int)parser->remain_len, (int)parser->remain_len, parser->remain_data);

	if (git__prefixncmp(parser->remain_data, parser->remain_len, "want ") == 0) {
		parser->pkt.type = GIT_SMART_PACKET_WANT;
		return pkt_parser_consume(parser, CONST_STRLEN("want "));
	}

	if (git__prefixncmp(parser->remain_data, parser->remain_len, "have ") == 0) {
		parser->pkt.type = GIT_SMART_PACKET_HAVE;
		return pkt_parser_consume(parser, CONST_STRLEN("have "));
	}

		/* TODO: is this right? */
	if (git__strncmp(parser->remain_data, "done\n", parser->remain_len) == 0) {
		parser->pkt.type = GIT_SMART_PACKET_DONE;
		return pkt_parser_consume(parser, CONST_STRLEN("done\n"));
	}

	git_error_set(GIT_ERROR_NET, "unknown packet type");
	return -1;
}

GIT_INLINE(int) pkt_parse_oid(struct pkt_parser *parser)
{
	size_t oid_size;
	int error;

	fprintf(debug, "parsing oid: '%.*s'\n", (int)parser->remain_len, parser->remain_data);

	oid_size = git_oid_hexsize(parser->oid_type);

	if (parser->remain_len < oid_size) {
		git_error_set(GIT_ERROR_NET, "invalid object id in negotiation");
		return -1;
	}

#ifdef GIT_EXPERIMENTAL_SHA256
	error = git_oid_fromstr(&parser->pkt.oid, parser->remain_data, parser->oid_type);
#else
	error = git_oid_fromstr(&parser->pkt.oid, parser->remain_data);
#endif

	if (error) {
		git_error_set(GIT_ERROR_NET, "invalid object id in negotiation");
		return -1;
	}

	return pkt_parser_consume(parser, oid_size);
}

static int pkt_parse_capabilities(struct pkt_parser *parser)
{
	const char *cap = parser->remain_data;
	size_t remain = parser->remain_len, len = 0;

	for (remain = parser->remain_len; remain > 0; remain--, len++) {
		if (cap[len] == '\n') {
			parser->pkt.capabilities = cap;
			parser->pkt.capabilities_len = len;

			return pkt_parser_consume(parser, len);
		}
	}

	git_error_set(GIT_ERROR_NET, "invalid capabilities in negotiation");
	return -1;
}

static int pkt_parse_nl(struct pkt_parser *parser)
{
	if (parser->remain_len < 1 || parser->remain_data[0] != '\n') {
		git_error_set(GIT_ERROR_NET, "expected newline in packet");
		return -1;
	}

	return pkt_parser_consume(parser, 1);
}

static int pkt_ensure_consumed(struct pkt_parser *parser)
{
	if (parser->remain_len != 0) {
		git_error_set(GIT_ERROR_NET, "unexpected trailing packet data");
		return -1;
	}

	return 0;
}

static int pkt_parse_want(struct pkt_parser *parser)
{
fprintf(debug, "parsing want: '%.*s'\n", (int)parser->remain_len, parser->remain_data);
fflush(debug);

	if (pkt_parse_oid(parser) < 0)
		return -1;

	if (!parser->read_capabilities) {
		fprintf(debug, "read capabilities: '%.*s'\n", (int)parser->remain_len, parser->remain_data);
		fflush(debug);

		if (parser->remain_len > 1) {
			if (parser->remain_data[0] != ' ') {
				git_error_set(GIT_ERROR_NET, "expected capabilities in packet");
				return -1;
			}

			if (pkt_parser_consume(parser, 1) < 0 ||
			    pkt_parse_capabilities(parser) < 0)
				return -1;

			fprintf(debug, "caps are: '%.*s'\n", (int)parser->pkt.capabilities_len, parser->pkt.capabilities);
		}

		parser->read_capabilities = 1;
	}

	fprintf(debug, "read nl: '%.*s'\n", (int)parser->remain_len, parser->remain_data);
	fflush(debug);

	if (pkt_parse_nl(parser) < 0 || pkt_ensure_consumed < 0)
		return -1;

	return 0;
}

static int pkt_parse_have(struct pkt_parser *parser)
{
	if (pkt_parse_oid(parser) < 0 ||
	    pkt_parse_nl(parser) < 0 ||
	    pkt_ensure_consumed < 0)
		return -1;

	return 0;
}

static int pkt_read(struct git_smart_packet **out, struct pkt_parser *parser)
{
	int error;

	fprintf(debug, "---------------pkt_read---------------\n");
	fflush(debug);

	/*
	 * We keep a read buffer, and this function returns a packet
	 * pointing to that data. On every `pkt_read`, we clear the
	 * read buffer based on the most-recently-sent packet.
	 */
	if (pkt_parser_reset(parser) < 0)
		return -1;

	fprintf(debug, "inited\n");
	fflush(debug);

	fprintf(debug, "parsing: %d '%.*s'\n", (int)parser->remain_len, (int)parser->remain_len, parser->remain_data);
	fflush(debug);

	/* Fill four bytes for the size of the packet */
	if (pkt_parser_fill(parser, 4) < 0 ||
	    pkt_parse_len(parser) < 0)
		return -1;

	fprintf(debug, "total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);
	fflush(debug);

	/* TODO: move this out of parser */
	if (parser->total_len == 0) {
		parser->pkt.type = GIT_SMART_PACKET_FLUSH;
		parser->pkt.data = parser->read_buf.ptr;
		parser->pkt.len = 4;
		goto done;
	} else if (parser->total_len < 4) {
		git_error_set(GIT_ERROR_NET, "invalid packet - invalid length");
		return -1;
	}

	fprintf(debug, "filling %d\n", (int)(parser->total_len - 4));
	fflush(debug);

	if (pkt_parser_fill(parser, parser->total_len - 4) < 0)
		return -1;

	fprintf(debug, "after fill - total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);
	fflush(debug);

	parser->pkt.data = parser->read_buf.ptr;
	parser->pkt.len = parser->total_len;

	if (pkt_parse_type(parser) < 0)
		return -1;

	fprintf(debug, "type is: %d\n", parser->pkt.type);
	fprintf(debug, "raw data is: %d - '%.*s'\n", (int) parser->pkt.len, (int) parser->pkt.len, parser->pkt.data);
	fflush(debug);

	switch (parser->pkt.type) {
	case GIT_SMART_PACKET_WANT:
		error = pkt_parse_want(parser);
		break;
	case GIT_SMART_PACKET_HAVE:
		error = pkt_parse_have(parser);
		break;
	case GIT_SMART_PACKET_DONE:
		error = 0;
		break;
	default:
		git_error_set(GIT_ERROR_NET, "invalid packet - unknown packet type");
		error = -1;
	}

	if (error < 0)
		return -1;

done:
	*out = &parser->pkt;
	return 0;
}

static int pkt_write(git_smart_server *server, struct git_smart_packet *pkt)
{
	const char *data = pkt->data;
	size_t len = pkt->len;
	int ret;

	GIT_UNUSED(server);

	fprintf(debug, "writing packet: %d :  '%.*s'\n", (int)len, (int)len, data);

	while (len > 0) {
		if ((ret = write(STDOUT_FILENO, data, len)) < 0) {
			git_error_set(GIT_ERROR_OS, "could not write to client");
			return -1;
		}

		data += ret;
		len -= ret;
	}

	return 0;
}

static int pkt_format__with_buf(
	struct git_smart_packet *pkt,
	git_str *buf,
	git_smart_packet_t type,
	const char *fmt,
	va_list ap)
{
	char len[5];
	const char *type_name = NULL;
	int error;

	switch (type) {
	case GIT_SMART_PACKET_NONE:
		break;
	case GIT_SMART_PACKET_ACK:
		type_name = "ACK";
		break;
	case GIT_SMART_PACKET_NAK:
		type_name = "NAK";
		break;
	case GIT_SMART_PACKET_ERR:
		type_name = "ERR";
		break;
	default:
		GIT_ASSERT(!"unknown packet type");
	}

	if ((error = git_str_put(buf, "0000", 4)) < 0)
		goto done;

	if (type_name && (error = git_str_puts(buf, type_name)) < 0)
		goto done;

	if (type_name && fmt && (error = git_str_putc(buf, ' ')) < 0)
		goto done;

	if (fmt && (error = git_str_vprintf(buf, fmt, ap)) < 0)
		goto done;

	if ((error = git_str_putc(buf, '\n')) < 0)
		goto done;

	GIT_ASSERT(buf->size <= 65535);

	if (p_snprintf(len, 5, "%04x", (unsigned int)buf->size) < 0) {
		error = -1;
		goto done;
	}

	memcpy(buf->ptr, len, 4);

	pkt->type = type;
	pkt->len = buf->size;
	pkt->data = buf->ptr;

	fprintf (debug, "raw output message is: '%.*s'\n", (int)pkt->len, pkt->data);

done:
	return error;
}

static int pkt_format_with_buf(
	struct git_smart_packet *pkt,
	git_str *buf,
	git_smart_packet_t type,
	const char *fmt,
	...) GIT_FORMAT_PRINTF(4, 5);

int pkt_format_with_buf(
	struct git_smart_packet *pkt,
	git_str *buf,
	git_smart_packet_t type,
	const char *fmt,
	...)
{
	va_list ap = NULL;
	int error;

	if (fmt)
		va_start(ap, fmt);

	error = pkt_format__with_buf(pkt, buf, type, fmt, ap);

	if (fmt)
		va_end(ap);

	return error;
}

static int pkt_format(
	struct git_smart_packet *pkt,
	git_smart_packet_t type,
	const char *fmt,
	...) GIT_FORMAT_PRINTF(3, 4);

int pkt_format(
	struct git_smart_packet *pkt,
	git_smart_packet_t type,
	const char *fmt,
	...)
{
	git_str buf = GIT_STR_INIT;
	va_list ap = NULL;
	int error;

	if (fmt)
		va_start(ap, fmt);

	error = pkt_format__with_buf(pkt, &buf, type, fmt, ap);

	if (fmt)
		va_end(ap);

	if (error == 0)
		pkt->owned = 1;
	else
		git_str_dispose(&buf);

	return error;
}

static void pkt_dispose(struct git_smart_packet *pkt)
{
	if (pkt && pkt->owned)
		git__free((char *)pkt->data);
}

static int want_is_advertised(bool *found, git_smart_server *server, git_oid *want)
{
	int error;

	if ((error = git_vector_bsearch(NULL, &server->advertised_ids, want)) == 0)
		*found = true;
	else if (error != GIT_ENOTFOUND)
		return -1;

	return 0;
}

static int want_is_tip(bool *found, git_smart_server *server, git_oid *want)
{
	GIT_UNUSED(found);
	GIT_UNUSED(server);
	GIT_UNUSED(want);

	/*
	 * TODO: support allow-tip-sha1-in-want that will examine
	 * the tips of other namespace branches. In the meantime,
	 * allow-tip-sha1-in-want is implicitly supported since we
	 * always just look at tips by default.
	 */

	return 0;
}

static int want_is_reachable(bool *found, git_smart_server *server, git_oid *want)
{
	int error;

	/* TODO: consult the commit graph if it exists */
	if ((error = git_graph__reachable_from_any(server->repo, want,
			(const git_oid **)server->advertised_ids.contents,
			server->advertised_ids.length)) == 1)
		*found = true;
	else if (error < 0)
		return -1;

	return 0;
}

static int want_is_allowed(bool *allowed, git_smart_server *server, git_oid *want)
{

	fprintf(debug, "> start want_is_allowed\n");
	fflush(debug);

	fprintf(debug, "want:: %s\n", git_oid_tostr_s(want));
	fprintf(debug, "server: %p\n", server);
	fflush(debug);

	*allowed = false;

	if ((server->capabilities & GIT_SMART_CAPABILITY_ALLOW_ANY_SHA1_IN_WANT))
		*allowed = true;

	if (!*allowed && want_is_advertised(allowed, server, want) < 0)
		return -1;

	if (!*allowed &&
	    (server->capabilities & GIT_SMART_CAPABILITY_ALLOW_TIP_SHA1_IN_WANT) &&
	    want_is_tip(allowed, server, want) < 0)
		return -1;

	if (!*allowed &&
	    (server->capabilities & GIT_SMART_CAPABILITY_ALLOW_REACHABLE_SHA1_IN_WANT) &&
	    want_is_reachable(allowed, server, want) < 0)
		return -1;

	return 0;
}

static int server_write_error(
	git_smart_server *server,
	struct git_smart_packet *error_pkt)
{
	if (pkt_write(server, error_pkt) < 0)
		return -1;

	server->sent_error = 1;
	return 0;
}

static int handle_capability(git_smart_server *server, const char *data, size_t len)
{
	const smart_capability_name *cap, *match = NULL;
	const char *value = NULL;
	size_t key_len, value_len;

	fprintf(debug, "cap is: '%.*s'\n", (int)len, data);

	for (cap = smart_capabilities; cap->capability && !match; cap++) {
		switch(cap->capability) {
		case GIT_SMART_CAPABILITY_SYMREF:
		case GIT_SMART_CAPABILITY_OBJECT_FORMAT:
		case GIT_SMART_CAPABILITY_AGENT:
		case GIT_SMART_CAPABILITY_SESSION_ID:
			if (git__prefixncmp(data, len, cap->name) != 0)
				break;

			if ((key_len = strlen(cap->name)) == len) {
				git_error_set(GIT_ERROR_NET, "client sent capability without value: '%s'", cap->name);
				return -1;
			}

			if (data[key_len] != '=')
				break;

			match = cap;
			value = &data[key_len + 1];
			value_len = len - (key_len + 1);
			break;

		default:
			if (strncmp(data, cap->name, len) == 0)
				match = cap;

			break;
		}

		if (match)
			break;
	}

	if (!match) {
		git_error_set(GIT_ERROR_NET, "client sent unknown capability: '%.*s'", (int)len, data);
		return -1;
	}

	if ((server->capabilities & cap->capability) == 0) {
		git_error_set(GIT_ERROR_NET, "client sent unsupported capability: '%s'", cap->name);
		return -1;
	}

	if ((DISALLOWED_CLIENT_CAPABILITIES & cap->capability) != 0) {
		git_error_set(GIT_ERROR_NET, "client sent disallowed capability: '%s'", cap->name);
		return -1;
	}

	server->client_capabilities |= cap->capability;

	if (cap->capability == GIT_SMART_CAPABILITY_AGENT) {
		server->client_agent = git__strndup(value, value_len);
		GIT_ERROR_CHECK_ALLOC(server->client_agent);
	} else if (cap->capability == GIT_SMART_CAPABILITY_SESSION_ID) {
		server->client_session_id = git__strndup(value, value_len);
		GIT_ERROR_CHECK_ALLOC(server->client_session_id);
	}

fprintf(debug, "consumed cap : %" PRIuZ "\n", len);
	return 0;
}

static int handle_capabilities(git_smart_server *server, const char *data, size_t len)
{
	const char *cap = data;
	size_t cap_len = 0, consumed = 0;

	GIT_UNUSED(server);

	printf("hi\n");

	while (consumed <= len) {
		if (consumed == len || data[consumed] == ' ') {
			if (handle_capability(server, cap, cap_len) < 0)
				return -1;

			cap = consumed == len ? NULL : data + consumed + 1;
			consumed++;
			cap_len = 0;
		}

		consumed++;
		cap_len++;
	}

	return 0;

/*
fprintf(debug, "parsing caps: '%.*s'\n", (int)parser->remain_len, parser->remain_data);

	while (parser->remain_len > 0) {
		if (parser->remain_data[0] == '\n')
			break;

		if (pkt_parse_capability(parser) < 0)
			return -1;

		if (parser->remain_data[0] == ' ' &&
		    pkt_parser_consume(parser, 1) < 0)
			return -1;
	}

	return 0;
	*/
}


static int handle_want(git_smart_server *server, git_revwalk *revwalk, git_oid *want)
{
	struct git_smart_packet notfound_pkt = { 0 };
	bool allowed = false;
	int error = -1;

	fprintf(debug, "> start handle_want\n");
	fflush(debug);

	fprintf(debug, "want:: %s\n", git_oid_tostr_s(want));
	fprintf(debug, "server: %p / walker: %p\n", server, revwalk);
	fflush(debug);

	if (want_is_allowed(&allowed, server, want) < 0)
		return -1;

	if (!allowed) {
		/* TODO ERR line */
		git_error_set(GIT_ERROR_NET, "the object '%s' is not available", git_oid_tostr_s(want));
		error = GIT_ENOTFOUND;
		goto done;
	}

	/* TODO: revwalk only handles commits */
	error = git_revwalk_push(revwalk, want);
	fprintf(debug, "REVWALK PUSH SAYS: %d / %s / %s\n", error, git_oid_tostr_s(want), git_error_last() ? git_error_last()->message : "(none)");

done:
	if (error == GIT_ENOTFOUND) {
		if (pkt_format(&notfound_pkt, GIT_SMART_PACKET_ERR,
				"the object '%s' is not available",
				git_oid_tostr_s(want)) < 0 ||
		    server_write_error(server, &notfound_pkt) < 0)
			error = -1;
	}

	pkt_dispose(&notfound_pkt);
	return error;
}

static int handle_have(git_smart_server *server, git_revwalk *revwalk, git_oid *have)
{
	struct git_smart_packet ack_pkt = { 0 };
	bool found = false, send_ack = false;
	const char *suffix = NULL;
	int error = -1;

	fprintf(debug, "> start handle_have\n");
	fflush(debug);

	fprintf(debug, "have:: %s\n", git_oid_tostr_s(have));
	fprintf(debug, "server: %p / walker: %p\n", server, revwalk);
	fflush(debug);

	/* Hide this have unless we're ready to deliver the packfile. */
	if (!server->ready) {
		/* TODO: revwalk only handles commits */
		int ret = git_revwalk_hide(revwalk, have);
		fprintf(debug, "REVWALK HIDE SAYS: %d / %s / %s\n", error, git_oid_tostr_s(have), git_error_last() ? git_error_last()->message : "(none)");

		if (ret == 0)
			found = true;
		else if (ret != GIT_ENOTFOUND)
			goto done;

		if (found)
			git_oid_cpy(&server->last_common_have, have);
	}

	if ((server->client_capabilities & GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED)) {
		/* Send an ACK for any object in common */
		send_ack = server->ready || found;
		suffix = server->ready ? "ready" : "common";
	} else if ((server->client_capabilities & GIT_SMART_CAPABILITY_MULTI_ACK)) {
		/* ACK everything after the first have in common */
		send_ack = (found || server->sent_ack);
		suffix = "continue";
	} else {
		/* Only ACK the first have in common */
		send_ack = (found && !server->sent_ack);
	}

	if (send_ack) {
		if (pkt_format(&ack_pkt, GIT_SMART_PACKET_ACK,
				"%s%s%s",
		                git_oid_tostr_s(have),
		                suffix ? " " : "",
		                suffix ? suffix : "") < 0 ||
		    pkt_write(server, &ack_pkt) < 0)
			goto done;

		server->sent_ack = 1;
	}

	error = 0;

done:
	pkt_dispose(&ack_pkt);
	return error;
}

static int handle_flush(git_smart_server *server)
{
	struct git_smart_packet ack_pkt = { 0 };
	int error = -1;

	/* TODO: compute ready here */

	if ((server->client_capabilities & GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED)) {
		/*
		 * If we're ready to send the packfile, ACK then NAK.
		 * Otherwise, only NAK.
		 */
		if (server->ready) {
			if (pkt_format(&ack_pkt, GIT_SMART_PACKET_ACK,
					"%s ready",
			                git_oid_tostr_s(&server->last_common_have)) < 0 ||
			    pkt_write(server, &ack_pkt) < 0)
				goto done;
		}

		if (pkt_write(server, &smart_packet_nak) < 0)
			goto done;
	} else if ((server->client_capabilities & GIT_SMART_CAPABILITY_MULTI_ACK)) {
		if (pkt_write(server, &smart_packet_nak) < 0)
			goto done;
	} else {
		/* In non-multi-ack mode, only NAK if we haven't ACKed. */
		if (!server->sent_ack &&
		    pkt_write(server, &smart_packet_nak) < 0)
			goto done;
	}

	error = 0;

done:
	pkt_dispose(&ack_pkt);
	return error;
}

static int handle_done(git_smart_server *server)
{
	struct git_smart_packet ack_pkt = { 0 };
	int error = -1;

	/* Send an ACK if we have a common base; NAK otherwise. */
	if ((server->client_capabilities & GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED) ||
	    (server->client_capabilities & GIT_SMART_CAPABILITY_MULTI_ACK)) {
		if (server->sent_ack) {
			if (pkt_format(&ack_pkt, GIT_SMART_PACKET_ACK,
					"%s",
					git_oid_tostr_s(&server->last_common_have)) < 0 ||
			    pkt_write(server, &ack_pkt) < 0)
				goto done;
		} else {
			if (pkt_write(server, &smart_packet_nak) < 0)
				goto done;
		}
	} else {
		/* In non-multi-ack mode, only NAK if we haven't ACKed. */
		if (!server->sent_ack &&
		    pkt_write(server, &smart_packet_nak) < 0)
			goto done;
	}

	error = 0;

done:
	pkt_dispose(&ack_pkt);
	return error;
}

int uploadpack_negotiate(git_smart_server *server, git_revwalk *revwalk)
{
	enum { WANT, HAVE, EXPECTING_DONE, DONE } state = WANT;
	struct git_smart_packet *packet;
	int error = -1;

fprintf(debug, "want phase here\n");
fflush(debug);

	/* Phase one: read wants (and shallow/depth information) */
	while (state == WANT) {
		if (pkt_read(&packet, &server->pkt_reader) < 0)
			goto done;

		switch (packet->type) {
		case GIT_SMART_PACKET_WANT:
			if (packet->capabilities &&
			    handle_capabilities(server, packet->capabilities, packet->capabilities_len) < 0)
				goto done;

			if (handle_want(server, revwalk, &packet->oid) < 0)
				goto done;

			break;
		case GIT_SMART_PACKET_FLUSH:
			state = HAVE;
			break;
		default:
			git_error_set(GIT_ERROR_NET, "unexpected packet during negotiation");
			goto done;
		}
	}

fprintf(debug, "have phase here\n");

	/* Phase two: read haves */
	while (state == HAVE) {
		if (pkt_read(&packet, &server->pkt_reader) < 0)
			goto done;

		switch (packet->type) {
		case GIT_SMART_PACKET_HAVE:
			if (handle_have(server, revwalk, &packet->oid) < 0)
				goto done;

			break;
		case GIT_SMART_PACKET_FLUSH:
			if (handle_flush(server) < 0)
				goto done;

			if (server->ready &&
			    (server->client_capabilities & GIT_SMART_CAPABILITY_NO_DONE))
				state = DONE;

			break;
		case GIT_SMART_PACKET_DONE:
			if (handle_done(server) < 0)
				goto done;

			state = DONE;
			break;
		default:
			git_error_set(GIT_ERROR_NET, "unexpected packet during negotiation");
			goto done;
		}
	}

fprintf(debug, "done \n");
fflush(debug);


	GIT_ASSERT(state == DONE);
	error = 0;

done:
	/*
	 * It's polite to send an error message, even when it's not very
	 * informative.
	 */
	if (error < 0 && !server->sent_error) {
		fprintf(debug, "error: %s\n", git_error_last() ? git_error_last()->message : "(no error)");
		pkt_write(server, &smart_packet_internal_error);
	}

	return error;
}

#define SENDPACK_BUFFER_MAX        10240

#define SENDPACK_BUFFER_64K        (65519 + 1 + 4)
#define SENDPACK_BUFFER_SIDEBAND   (9999 + 1 + 4)

struct sendpack_data {
	git_smart_server *server;
	char buffer[SENDPACK_BUFFER_MAX];
	size_t buffer_size;
	size_t prefix_len;
	size_t used;
};

static void sendpack_prepare(struct sendpack_data *sendpack)
{
	if ((sendpack->server->client_capabilities & GIT_SMART_CAPABILITY_SIDE_BAND_64K)) {
		memcpy(sendpack->buffer, "00001", 5);
		sendpack->buffer_size = MIN(SENDPACK_BUFFER_64K, SENDPACK_BUFFER_MAX);
		sendpack->prefix_len = 5;
		sendpack->used = 5;
	} else if ((sendpack->server->client_capabilities & GIT_SMART_CAPABILITY_SIDE_BAND)) {
		memcpy(sendpack->buffer, "00001", 5);
		sendpack->buffer_size = MIN(SENDPACK_BUFFER_SIDEBAND, SENDPACK_BUFFER_MAX);
		sendpack->prefix_len = 5;
		sendpack->used = 5;
	} else {
		sendpack->buffer_size = SENDPACK_BUFFER_MAX;
		sendpack->prefix_len = 0;
		sendpack->used = 0;
	}
}

static int sendpack_flush(struct sendpack_data *sendpack)
{
	struct git_smart_packet pack_pkt = {
		GIT_SMART_PACKET_NONE,
		sendpack->buffer,
		sendpack->used
	};
	char len[5];

	if (sendpack->buffer_size == sendpack->prefix_len)
		return 0;

	if ((sendpack->server->client_capabilities & GIT_SMART_CAPABILITY_SIDE_BAND_64K) ||
	    (sendpack->server->client_capabilities & GIT_SMART_CAPABILITY_SIDE_BAND)) {
		GIT_ASSERT(sendpack->buffer_size <= SENDPACK_BUFFER_64K);

		if (p_snprintf(len, 5, "%04x", (unsigned int)sendpack->used) < 0)
			return -1;

		memcpy(sendpack->buffer, len, 4);
	}

	if (pkt_write(sendpack->server, &pack_pkt) < 0)
		return -1;

	sendpack_prepare(sendpack);

	return 0;
}

static int sendpack_queue(void *buf, size_t size, void *payload)
{
	struct sendpack_data *sendpack = payload;

	while (size > 0) {
		size_t avail = sendpack->buffer_size - sendpack->used;
		size_t consumed = min(avail, size);
		GIT_ASSERT(sendpack->buffer_size > sendpack->used);

		memcpy(sendpack->buffer + sendpack->used, buf, consumed);
		sendpack->used += consumed;

		buf += consumed;
		size -= consumed;

		if (sendpack->buffer_size == sendpack->used &&
		    sendpack_flush(sendpack) < 0)
			return -1;
	}

	return 0;
}

static int sendpack_complete(struct sendpack_data *sendpack)
{
	if (sendpack_flush(sendpack) < 0)
		return -1;

	if ((sendpack->server->client_capabilities & GIT_SMART_CAPABILITY_SIDE_BAND_64K) ||
	    (sendpack->server->client_capabilities & GIT_SMART_CAPABILITY_SIDE_BAND)) {
		if (pkt_write(sendpack->server, &smart_packet_flush) < 0)
			return -1;
	}

	return 0;
}

static int uploadpack_sendpack(git_smart_server *server, git_revwalk *revwalk)
{
	git_packbuilder *packbuilder = NULL;
	struct sendpack_data sendpack = { server };
	int error = -1;

	/* TODO: kick prepare off to a background thread so that we can keep-alive flushes while it's going */
	if (git_packbuilder_new(&packbuilder, server->repo) < 0 ||
	    git_packbuilder_insert_walk(packbuilder, revwalk) < 0 ||
	    git_packbuilder__prepare(packbuilder) < 0)
		goto done;

	fprintf(debug, "===================================================\n");
	fprintf(debug, "  sending packfile  \n");
	fprintf(debug, "===================================================\n");
	fflush(debug);

	sendpack_prepare(&sendpack);

	if (git_packbuilder_foreach(packbuilder, sendpack_queue, &sendpack) < 0)
		goto done;

	sendpack_complete(&sendpack);

	error = 0;

done:
	if (error < 0 && !server->sent_error) {
		fprintf(debug, "error: %s\n", git_error_last() ? git_error_last()->message : "(no error)");
		fflush(debug);
		/* TODO: send an error message on the err sideband */
	}

	git_packbuilder_free(packbuilder);
	return error;
}

int git_smart_server_uploadpack(git_smart_server *server)
{
	git_revwalk *revwalk = NULL;
	int error = -1;


if ((debug = fopen("/tmp/asdf", "w")) == NULL) {
	perror("fopen");
	abort();
 }

fprintf(debug, "opened!\n");
fflush(debug);


	if (git_revwalk_new(&revwalk, server->repo) < 0)
		return -1;

	if (git_smart_server_advertise(server, true) < 0)
		goto done;

fprintf(debug, "---------negotiationphase------------\n");
fflush(debug);
	if (uploadpack_negotiate(server, revwalk) < 0)
		goto done;

fprintf(debug, "---------sendpack   phase------------\n");
fflush(debug);

	if (uploadpack_sendpack(server, revwalk) < 0)
		goto done;

fclose(debug);

	error = 0;

done:
	git_revwalk_free(revwalk);
	return error;
}

int git_smart_server_receivepack(git_smart_server *server)
{
	if (git_smart_server_advertise(server, false) < 0)
		return -1;

	return 0;
}

void git_smart_server_free(git_smart_server *server)
{
	git_reference *ref;
	size_t i;

	if (!server)
		return;

	git_vector_foreach(&server->advertised_refs, i, ref)
		git_reference_free(ref);

	git_vector_foreach(&server->resolved_refs, i, ref)
		git_reference_free(ref);

	git_vector_free(&server->advertised_refs);
	git_vector_free(&server->resolved_refs);
	git_vector_free(&server->advertised_ids);
	git__free(server);
}
