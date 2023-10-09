/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "smart_new.h"

#include "common.h"
#include "refs.h"
#include "vector.h"
#include "graph.h"
#include "pack-objects.h"
#include "revwalk.h"
#include "oidarray.h"
#include "repository.h"

#include "git2/odb.h"
#include "git2/odb_backend.h"
#include "git2/revwalk.h"
#include "git2/version.h"
#include "git2/sys/refs.h"
#include "git2/sys/transport.h"
#include "git2/sys/remote.h"

/* TODO : 1024 or something */
#define READ_SIZE 1

#define DEFAULT_CLIENT_CAPABILITIES \
	(GIT_SMART_CAPABILITY_MULTI_ACK          | \
	 GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED | \
	 GIT_SMART_CAPABILITY_NO_DONE            | \
	 GIT_SMART_CAPABILITY_THIN_PACK          | \
	 GIT_SMART_CAPABILITY_SIDE_BAND          | \
	 GIT_SMART_CAPABILITY_SIDE_BAND_64K      | \
	 GIT_SMART_CAPABILITY_OFS_DELTA          | \
	 GIT_SMART_CAPABILITY_AGENT              | \
	 GIT_SMART_CAPABILITY_OBJECT_FORMAT      | \
	 GIT_SMART_CAPABILITY_SYMREF             | \
	 GIT_SMART_CAPABILITY_NO_PROGRESS        | \
	 GIT_SMART_CAPABILITY_INCLUDE_TAG        | \
	 GIT_SMART_CAPABILITY_SESSION_ID)

#define DISALLOWED_SERVER_CAPABILITIES	0

typedef struct {
	git_smart_capability capability;
	const char *name;
} smart_capability_name;

extern char *git_http__user_agent;

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

static struct git_smart_packet smart_packet_flush = {
	GIT_SMART_PACKET_FLUSH, "0000", CONST_STRLEN("0000"), 0
};
static struct git_smart_packet smart_packet_nak = {
	GIT_SMART_PACKET_NAK, "0008NAK\n", CONST_STRLEN("0008NAK\n"), 0
};

static struct git_smart_packet smart_packet_internal_error = {
	GIT_SMART_PACKET_ERR,
	"001eERR internal error\n",
	CONST_STRLEN("001eERR internal error\n"),
	0
};


typedef enum {
	PKT_READER_CLIENT,
	PKT_READER_SERVER
} pkt_reader_t;

struct pkt_reader {
	git_stream *stream;

	pkt_reader_t type;

	unsigned int seen_capabilities : 1,
	             seen_flush : 1;

	/*
	 * We buffer a chunk of data from the stream, then parse packets
	 * out of that. The `pkt` structure points inside this buffer.
	 */
	git_str read_buf;

	/* Current packet data */

	/* The current packet that we're filling. */
	struct git_smart_packet pkt;

	/*
	 * The total length of the packet (including size prefix) and
	 * our current position within the packet.
	 */
	size_t total_len;
	size_t position;

	/* The remaining data to parse of the message and its length. */
	const char *remain_data;
	size_t remain_len;
};

struct pkt_writer {
	git_stream *stream;

	unsigned int written_capabilities : 1;

	/*
	 * We buffer a chunk of data to write, and set up packets to point to
	 * that. The `pkt` structure points inside this buffer.
	 */
	git_str write_buf;
};

struct git_smart_client {
	git_repository *repo;
	git_oid_t oid_type;

	git_stream *stream;

	struct pkt_reader reader;
	struct pkt_writer writer;

	unsigned int seen_advertisement : 1,
	             cancelled : 1;

	/* Configurable client information */

	/* The client's (our) capabilities */
	const char *agent;
	const char *session_id;
	unsigned int capabilities;

	/* Server information */
	const char *server_agent;
	const char *server_session_id;
	unsigned int server_capabilities;

	/* Negotiation data */
	git_array_oid_t shallow_roots;

	git_strmap *symrefs;
	git_vector heads;
};


static int pkt_format_with_buf(
	struct git_smart_packet *pkt,
	git_str *buf,
	git_smart_packet_t type,
	const char *fmt,
	...) GIT_FORMAT_PRINTF(4, 5);


static void append_useragent(git_str *out)
{
	const char *ua = git_http__user_agent, *c;

	git_str_puts(out, "git/2.0.(");

	if (!ua) {
		git_str_puts(out, "libgit2." LIBGIT2_VERSION);
	} else {
		for (c = ua; *c; c++)
			git_str_putc(out, isspace(*c) ? '.' : *c);
	}

	git_str_putc(out, ')');
}

static int refname_cmp(const void *_a, const void *_b)
{
	const git_reference *a = _a, *b = _b;
	return strcmp(git_reference_name(a), git_reference_name(b));
}

static FILE *debug;

static int fill_read_buf(struct pkt_reader *parser, size_t len)
{
	char *buf;
	ssize_t ret;

	fprintf(debug, "filling read buf - size: %d / wanted: %d\n", (int)parser->read_buf.size, (int)len);

	while (parser->read_buf.size < len) {
		if (git_str_grow_by(&parser->read_buf, READ_SIZE) < 0)
			return -1;

		buf = parser->read_buf.ptr + parser->read_buf.size;

		if ((ret = git_stream_read(parser->stream, buf, READ_SIZE)) < 0)
			return -1;

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

/* TODO: combine reader and writer no? */
GIT_INLINE(int) pkt_reader_init(
	struct pkt_reader *parser,
	git_repository *repo,
	git_stream *stream,
	pkt_reader_t type)
{
	GIT_UNUSED(repo);

	parser->stream = stream;
	parser->type = type;

	return 0;
}

GIT_INLINE(int) pkt_writer_init(
	struct pkt_writer *writer,
	git_stream *stream)
{
	writer->stream = stream;

	return 0;
}

GIT_INLINE(int) pkt_reader_reset(struct pkt_reader *parser)
{
	GIT_ASSERT(parser->read_buf.size >= parser->pkt.len);

	/*
	* TODO: we probably don't need to do a memmove on every read.
	* Just occasionally to prevent us from having an unnecessarily large buffer.
	*/
	memmove(parser->read_buf.ptr,
	        parser->read_buf.ptr + parser->pkt.len,
	        parser->read_buf.size - parser->pkt.len);
	parser->read_buf.size -= parser->pkt.len;

	memset(&parser->pkt, 0, sizeof(struct git_smart_packet));

	parser->total_len = 0;
	parser->position = 0;
	parser->remain_data = NULL;
	parser->remain_len = 0;

	return 0;
}


/*
 * fill_read_buf may realloc our data buffer, so this is a wrapper
 * to update the positions.
 */
GIT_INLINE(int) pkt_reader_fill(struct pkt_reader *parser, size_t len)
{
	fprintf(debug, "-------------pkt_reader_fill-------------\n");

	/* TODO: sanity check arithmetic */
	if (fill_read_buf(parser, parser->position + len) < 0)
		return -1;

fprintf(debug, "%d %d\n", (int)parser->read_buf.size, (int)parser->position);

	GIT_ASSERT(parser->read_buf.size > parser->position);

	parser->remain_data = parser->read_buf.ptr + parser->position;
	parser->remain_len = len;

	return 0;
}

GIT_INLINE(int) pkt_reader_advance(struct pkt_reader *parser, size_t len)
{
	if (GIT_ADD_SIZET_OVERFLOW(&parser->position, parser->position, len))
		return -1;

	parser->remain_data = parser->read_buf.ptr + parser->position;
	return 0;
}

GIT_INLINE(int) pkt_reader_consume(struct pkt_reader *parser, size_t len)
{
	if (pkt_reader_advance(parser, len) < 0)
		return -1;

	parser->remain_len -= len;
	return 0;
}

static int pkt_parse_len(struct pkt_reader *parser)
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

	if (git__strntol64(&value, parser->remain_data, 4, NULL, 16) < 0 ||
	    value < 0 || value > UINT_MAX - 4) {
		git_error_set(GIT_ERROR_NET, "invalid packet - invalid decoded length");
		return -1;
	}

	parser->total_len = value;
	parser->remain_len = value;

	fprintf(debug, "0: total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);

	/*
	 * A flush packet does not encode its own length ("0000"), so we do not
	 * "consume" it (remove the 4 byte length from the message length). We
	 * just advance the stream pointer.
	 */

	if (value && pkt_reader_consume(parser, 4) < 0)
		return -1;

	if (!value && pkt_reader_advance(parser, 4) < 0)
		return -1;

	fprintf(debug, "1: total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);
	return 0;
}

static int pkt_parse_type(struct pkt_reader *parser)
{
	fprintf(debug, "parsing type: %d - '%.*s'\n", (int)parser->remain_len, (int)parser->remain_len, parser->remain_data);

	if (git__prefixncmp(parser->remain_data, parser->remain_len, "want ") == 0) {
		parser->pkt.type = GIT_SMART_PACKET_WANT;
		return pkt_reader_consume(parser, CONST_STRLEN("want "));
	}
	else if (git__prefixncmp(parser->remain_data, parser->remain_len, "have ") == 0) {
		parser->pkt.type = GIT_SMART_PACKET_HAVE;
		return pkt_reader_consume(parser, CONST_STRLEN("have "));
	}
	else if (git__strncmp(parser->remain_data, "done\n", parser->remain_len) == 0) {
		parser->pkt.type = GIT_SMART_PACKET_DONE;
		return pkt_reader_consume(parser, CONST_STRLEN("done\n"));
	}

	else if (git__strncmp(parser->remain_data, "ACK ", parser->remain_len) == 0) {
		parser->pkt.type = GIT_SMART_PACKET_ACK;
		return pkt_reader_consume(parser, CONST_STRLEN("ACK "));
	}
	else if (git__strncmp(parser->remain_data, "NAK\n", parser->remain_len) == 0) {
		parser->pkt.type = GIT_SMART_PACKET_NAK;
		return pkt_reader_consume(parser, CONST_STRLEN("NAK\n"));
	}

	else if (parser->remain_len >= 1 && parser->remain_data[0] == 1) {
		parser->pkt.type = GIT_SMART_PACKET_SIDEBAND_DATA;
		return pkt_reader_consume(parser, 1);
	}
	else if (parser->remain_len >= 1 && parser->remain_data[0] == 2) {
		parser->pkt.type = GIT_SMART_PACKET_SIDEBAND_PROGRESS;
		return pkt_reader_consume(parser, 1);
	}
	else if (parser->remain_len >= 1 && parser->remain_data[0] == 3) {
		parser->pkt.type = GIT_SMART_PACKET_SIDEBAND_ERROR;
		return pkt_reader_consume(parser, 1);
	}

	git_error_set(GIT_ERROR_NET, "unknown packet type");
	return -1;
}

GIT_INLINE(int) pkt_parse_oid(struct pkt_reader *parser)
{
	const char *oid = parser->remain_data;
	size_t remain = parser->remain_len, len = 0;

	while (remain > 0) {
		char c = parser->remain_data[len];

		if (c == ' ' || c == '\n' || c == '\0')
			break;

		if ((c < 'a' || c > 'f') && (c < 'A' || c > 'F') && (c < '0' || c > '9')) {
			git_error_set(GIT_ERROR_NET, "invalid packet - invalid object id");
			return -1;
		}

		remain--;
		len++;
	}

	parser->pkt.oid = oid;
	parser->pkt.oid_len = len;

	return pkt_reader_consume(parser, len);
}

static int pkt_parse_capabilities(struct pkt_reader *parser)
{
	const char *cap = parser->remain_data;
	size_t remain, len = 0;

	for (remain = parser->remain_len; remain > 0; remain--, len++) {
		if (cap[len] == '\n') {
			parser->pkt.capabilities = cap;
			parser->pkt.capabilities_len = len;

			return pkt_reader_consume(parser, len);
		}
	}

fprintf(debug, "remain: %d '%.*s'\n", (int)parser->remain_len, (int)parser->remain_len, parser->remain_data);

	git_error_set(GIT_ERROR_NET, "invalid capabilities in negotiation");
	return -1;
}

static int pkt_parse_char(struct pkt_reader *parser, char c, const char *name)
{
	if (parser->remain_len < 1 || parser->remain_data[0] != c) {
		if (name)
			git_error_set(GIT_ERROR_NET, "expected %s in packet", name);

		return -1;
	}

	return pkt_reader_consume(parser, 1);
}

static int pkt_parse_string(struct pkt_reader *parser, const char *s, const char *name)
{
	size_t s_len;

	if (parser->remain_len < s_len || memcmp(parser->remain_data, s, s_len) != 0) {
		if (name)
			git_error_set(GIT_ERROR_NET, "expected %s in packet", name);

		return -1;
	}

	return pkt_reader_consume(parser, s_len);
}

static int pkt_ensure_consumed(struct pkt_reader *parser)
{
	if (parser->remain_len != 0) {
		git_error_set(GIT_ERROR_NET, "unexpected trailing packet data");
		return -1;
	}

	return 0;
}

static int pkt_parse_refname(struct pkt_reader *parser)
{
	const char *name = parser->remain_data;
	size_t remain = parser->remain_len, len = 0;

	for (remain = parser->remain_len; remain > 0; remain--, len++) {
		if (name[len] == '\0' || name[len] == '\n')
			break;

		/* TODO: check valid chars? */
		if (name[len] == ' ') {
			git_error_set(GIT_ERROR_NET, "invalid character in reference name");
			return -1;
		}
	}

	parser->pkt.refname = name;
	parser->pkt.refname_len = len;

	return pkt_reader_consume(parser, len);
}

static size_t pkt_reader_position(struct pkt_reader *parser)
{
	fprintf(debug, "queried position as: %d\n", (int)parser->position);
	return parser->position;
}

static int pkt_reader_set_position(struct pkt_reader *parser, size_t position)
{
	size_t diff;

	fprintf(debug, "setting position to %d (from %d)\n", (int)position, (int)parser->position);

	if (position <= parser->position) {
		diff = parser->position - position;

		fprintf(debug, "diff is %d\n", (int)diff);

		if (GIT_ADD_SIZET_OVERFLOW(&parser->remain_len, parser->remain_len, diff))
			return -1;
	} else {
		diff = position - parser->position;

		GIT_ASSERT(parser->remain_len >= diff);
		parser->remain_len -= diff;
	}

	parser->position = position;
	parser->remain_data = parser->read_buf.ptr + parser->position;
	fprintf(debug, "set position to: %d (len = %d)\n", (int)parser->position, (int)parser->remain_len);

	return 0;
}

static int pkt_parse_advance_to_char(struct pkt_reader *parser, char c)
{
	size_t advanced = 0;

	fprintf(debug, "advancing to char %x (start: %d '%.*s')\n", c, (int)parser->remain_len, (int)parser->remain_len, parser->remain_data);

	while (advanced < parser->remain_len) {
		if (parser->remain_data[advanced] == c) {
			fprintf(debug, "found - remain len is now %d '%.*s'\n", (int)parser->remain_len, (int)parser->remain_len, parser->remain_data );

			return pkt_reader_consume(parser, advanced);
		}

		advanced++;
	}

	return GIT_ENOTFOUND;
}

static int pkt_parse_ref(struct pkt_reader *parser)
{
	int error;

	fprintf(debug, "parsing ref: %d - '%.*s\n", (int)parser->remain_len, (int)parser->remain_len, parser->remain_data);

	parser->pkt.type = GIT_SMART_PACKET_REF;

	if (pkt_parse_oid(parser) < 0 ||
	    pkt_parse_char(parser, ' ', "space") < 0 ||
	    pkt_parse_refname(parser) < 0)
		return -1;

	/* since capabilities contain the remote's object-format, we need to
	 * parse it first so that we know what oid type we're reading.
	 */
	if (!parser->seen_capabilities) {
		if (pkt_parse_char(parser, '\0', NULL) == 0) {
			fprintf(debug, "found NUL\n");

			if (pkt_parse_capabilities(parser) < 0)
				return -1;

			fprintf(debug, "caps are: '%.*s'\n", (int)parser->pkt.capabilities_len, parser->pkt.capabilities);
		}

		parser->seen_capabilities = 1;
	}

	printf("yo: %d - '%.*s\n", (int)parser->remain_len, (int)parser->remain_len, parser->remain_data);

	if (pkt_parse_char(parser, '\n', "newline") < 0 ||
	    pkt_ensure_consumed(parser) < 0)
		return -1;

	return 0;
}

static int pkt_parse_want(struct pkt_reader *parser)
{
fprintf(debug, "parsing want: '%.*s'\n", (int)parser->remain_len, parser->remain_data);
fflush(debug);

	if (pkt_parse_oid(parser) < 0)
		return -1;

	if (!parser->seen_capabilities) {
		fprintf(debug, "read capabilities: '%.*s'\n", (int)parser->remain_len, parser->remain_data);
		fflush(debug);

		if (parser->remain_len > 1) {
			if (pkt_parse_char(parser, ' ', NULL) < 0) {
				git_error_set(GIT_ERROR_NET, "expected capabilities in packet");
				return -1;
			}

			if (pkt_parse_capabilities(parser) < 0)
				return -1;

			fprintf(debug, "caps are: '%.*s'\n", (int)parser->pkt.capabilities_len, parser->pkt.capabilities);
		}

		parser->seen_capabilities = 1;
	}

	fprintf(debug, "read nl: '%.*s'\n", (int)parser->remain_len, parser->remain_data);
	fflush(debug);

	if (pkt_parse_char(parser, '\n', "newline") < 0 ||
	    pkt_ensure_consumed(parser) < 0)
		return -1;

	return 0;
}

static int pkt_parse_have(struct pkt_reader *parser)
{
	if (pkt_parse_oid(parser) < 0 ||
	    pkt_parse_char(parser, '\n', "newline") < 0 ||
	    pkt_ensure_consumed(parser) < 0)
		return -1;

	return 0;
}

static int pkt_parse_ack(struct pkt_reader *parser)
{
fprintf(debug, "parsing ACK: '%.*s'\n", (int)parser->remain_len, parser->remain_data);
fflush(debug);

	if (pkt_parse_oid(parser) < 0)
		return -1;

	if (pkt_parse_char(parser, ' ', NULL) == 0) {
		if (pkt_parse_string(parser, "common", NULL) == 0) {
			parser->pkt.flags |= GIT_SMART_PACKET_ACK_COMMON;
		} else if (pkt_parse_string(parser, "continue", NULL) == 0) {
			parser->pkt.flags |= GIT_SMART_PACKET_ACK_CONTINUE;
		} else if (pkt_parse_string(parser, "ready", NULL) == 0) {
			parser->pkt.flags |= GIT_SMART_PACKET_ACK_READY;
		} else {
			git_error_set(GIT_ERROR_NET, "unknown ack response");
			return -1;
		}
	}

	if (pkt_parse_char(parser, '\n', "newline") < 0 ||
	    pkt_ensure_consumed(parser) < 0)
		return -1;

	return 0;
}

static int pkt_parse_sideband(struct pkt_reader *parser)
{
	parser->pkt.sideband = parser->remain_data;
	parser->pkt.sideband_len = parser->remain_len;

	return pkt_reader_consume(parser, parser->remain_len);
}

int pkt_read(struct git_smart_packet **out, struct pkt_reader *parser)
{
	int error;

	fprintf(debug, "---------------pkt_read---------------\n");
	fflush(debug);

	/*
	 * We keep a read buffer, and this function returns a packet
	 * pointing to that data. On every `pkt_read`, we clear the
	 * read buffer based on the most-recently-sent packet.
	 */
	if (pkt_reader_reset(parser) < 0)
		return -1;

	fprintf(debug, "inited\n");
	fflush(debug);

	fprintf(debug, "parsing: %d '%.*s'\n", (int)parser->remain_len, (int)parser->remain_len, parser->remain_data);
	fflush(debug);

	/* Fill four bytes for the size of the packet */
	if (pkt_reader_fill(parser, 4) < 0 ||
	    pkt_parse_len(parser) < 0)
		return -1;

	fprintf(debug, "total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);
	fflush(debug);

	/* TODO: move this out of parser? */
	if (parser->total_len == 0) {
		parser->pkt.type = GIT_SMART_PACKET_FLUSH;
		parser->pkt.data = parser->read_buf.ptr;
		parser->pkt.len = 4;
		parser->seen_flush = 1;
		goto done;
	} else if (parser->total_len < 4) {
		git_error_set(GIT_ERROR_NET, "invalid packet - invalid length");
		return -1;
	}

	fprintf(debug, "filling %d\n", (int)(parser->total_len - 4));
	fflush(debug);

	if (pkt_reader_fill(parser, parser->total_len - 4) < 0)
		return -1;

	fprintf(debug, "after fill - total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);
	fflush(debug);

	parser->pkt.data = parser->read_buf.ptr;
	parser->pkt.len = parser->total_len;

	/* TODO: this should probably be more stateful than typed */
	/* maybe separate into read_client and read_server */
	if (parser->type == PKT_READER_CLIENT && !parser->seen_flush) {
		error = pkt_parse_ref(parser);
	} else {
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
		case GIT_SMART_PACKET_ACK:
			error = pkt_parse_ack(parser);
			break;
		case GIT_SMART_PACKET_NAK:
			error = 0;
			break;
		case GIT_SMART_PACKET_DONE:
			error = 0;
			break;
		case GIT_SMART_PACKET_SIDEBAND_DATA:
		case GIT_SMART_PACKET_SIDEBAND_PROGRESS:
		case GIT_SMART_PACKET_SIDEBAND_ERROR:
			error = pkt_parse_sideband(parser);
			break;
		default:
			git_error_set(GIT_ERROR_NET, "invalid packet - unknown packet type");
			error = -1;
		}
	}

	if (error < 0)
		return -1;

done:
	*out = &parser->pkt;
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

/* TODO: for symmetry, sort of feels like we should take a string of preformatted capabilities here
 * or make the pkt reader do the parsing.
 */
int pkt_append_capabilities(
	struct pkt_writer *pkt_writer,
	unsigned int capabilities,
	const char *agent,
	const char *session_id)
{
	const char *name;
	size_t i = 0;

	for (i = 0; (name = smart_capabilities[i].name) != NULL; i++) {
		const char *value = NULL;

		if (smart_capabilities[i].capability == GIT_SMART_CAPABILITY_AGENT && !(value = agent))
			continue;
		
		if (smart_capabilities[i].capability == GIT_SMART_CAPABILITY_SESSION_ID && !(value = session_id))
			continue;

		git_str_putc(&pkt_writer->write_buf, i ? ' ' : '.');
		git_str_puts(&pkt_writer->write_buf, name);

		if (value) {
			git_str_putc(&pkt_writer->write_buf, '=');
			git_str_puts(&pkt_writer->write_buf, value);
		}
	}

	printf("CAPABILITIES: %d\n", capabilities);
	printf("agent: %s\n", agent);
	printf("session_id: %s\n", session_id);

	return git_str_oom(&pkt_writer->write_buf) ? -1 : 0;
}

int pkt_write(
	struct pkt_writer *pkt_writer,
	git_smart_packet_t type,
	...)
{
	const char *type_name = NULL;
	va_list ap;
	size_t start_pos, end_pos, len;
	bool has_capabilities;
	char len_str[5];
	int error;

	start_pos = pkt_writer->write_buf.size;

	has_capabilities = ((type & GIT_SMART_PACKET_HAS_CAPABILITIES) != 0);
	type &= ~GIT_SMART_PACKET_HAS_CAPABILITIES;

	if ((error = git_str_put(&pkt_writer->write_buf, "0000", 4)) < 0)
		return -1;

	if (type == GIT_SMART_PACKET_FLUSH)
		return 0;

	va_start(ap, type);

	switch (type) {
	case GIT_SMART_PACKET_NONE:
		break;
	case GIT_SMART_PACKET_ACK:
		error = git_str_put(&pkt_writer->write_buf, "ACK", 3);
		break;
	case GIT_SMART_PACKET_NAK:
		error = git_str_put(&pkt_writer->write_buf, "NAK", 3);
		break;
	case GIT_SMART_PACKET_WANT:
		{
			git_oid *id = va_arg(ap, const char *);
			char id_str[GIT_OID_MAX_HEXSIZE];
			size_t hexsize = git_oid_hexsize(git_oid_type(id));

			if ((error = git_oid_fmt(id_str, id)) == 0 &&
			    (error = git_str_put(&pkt_writer->write_buf, "want ", 5)) == 0)
				error = git_str_put(&pkt_writer->write_buf, id_str, hexsize);
		}
		break;
	case GIT_SMART_PACKET_DONE:
		error = git_str_put(&pkt_writer->write_buf, "done", 4);
		break;
	case GIT_SMART_PACKET_DEEPEN:
		{
			int depth = va_arg(ap, int);
			GIT_ASSERT(depth >= 0);

			error = git_str_printf(&pkt_writer->write_buf, "deepen %d", depth);
		}
		break;
	case GIT_SMART_PACKET_ERR:
		{
			const char *fmt = va_arg(ap, const git_oid *);

			if ((error = git_str_put(&pkt_writer->write_buf, "ERR ", 4)) == 0)
				error = git_str_vprintf(&pkt_writer->write_buf, fmt, ap);
		}
		break;
	default:
		git_error_set(GIT_ERROR_INVALID, "unknown packet type");
		error = -1;
		break;
	}

	if (!error && !pkt_writer->written_capabilities) {
		if (has_capabilities) {
			int capabilities = va_arg(ap, int);
			const char *agent = va_arg(ap, const char *);
			const char *session_id = va_arg(ap, const char *);

			error = pkt_append_capabilities(pkt_writer, capabilities, agent, session_id);
		}

		pkt_writer->written_capabilities = 1;
	}

	va_end(ap);

	if (error < 0)
		return -1;

	if ((error = git_str_putc(&pkt_writer->write_buf, '\n')) < 0)
		return -1;

	end_pos = pkt_writer->write_buf.size;

	GIT_ASSERT(end_pos > start_pos);
	len = end_pos - start_pos;
	GIT_ASSERT(len <= 65535);

	if (p_snprintf(len_str, 5, "%04x", (unsigned int)len) < 0)
		return -1;

	/* TODO: flush at a certain size */
	memcpy((pkt_writer->write_buf.ptr + start_pos), len_str, 4);
	return error;
}

static int pkt_writer_flush(struct pkt_writer *writer)
{
	if (git_stream__write_full(writer->stream, writer->write_buf.ptr, writer->write_buf.size, 0) < 0)
		return -1;

	writer->write_buf.size = 0;
	return 0;
}

static int handle_capability_value(
	git_smart_client *client,
	const smart_capability_name *cap,
	const char *value,
	size_t value_len)
{
	const char *sep;
	char *src, *tgt;
	size_t src_len, tgt_len;

	switch (cap->capability) {
	case GIT_SMART_CAPABILITY_SYMREF:
		if ((sep = memchr(value, ':', value_len)) == NULL ||
		    (src_len = (sep - value)) == 0 ||
		    (tgt_len = ((value_len - src_len) - 1)) == 0) {
			git_error_set(GIT_ERROR_NET, "invalid symbolic reference mapping");
			return -1;
		}

		src = git__strndup(value, src_len);
		GIT_ERROR_CHECK_ALLOC(src);

		tgt = git__strndup(sep + 1, tgt_len);
		GIT_ERROR_CHECK_ALLOC(tgt);

		if (git_strmap_set(client->symrefs, src, tgt) < 0)
			return -1;

		break;

	case GIT_SMART_CAPABILITY_OBJECT_FORMAT:
		if (client->oid_type) {
			git_error_set(GIT_ERROR_NET, "invalid capabilities - duplicate object format");
			return -1;
		}

		if ((client->oid_type = git_oid_type_fromstrn(value, value_len)) == 0) {
			git_error_set(GIT_ERROR_NET, "unknown object format from server");
			return -1;
		}

		break;

	case GIT_SMART_CAPABILITY_AGENT:
		if (client->server_agent) {
			git_error_set(GIT_ERROR_NET, "invalid capabilities - duplicate agent");
			return -1;
		}

		client->server_agent = git__strndup(value, value_len);
		GIT_ERROR_CHECK_ALLOC(client->server_agent);

		break;

	case GIT_SMART_CAPABILITY_SESSION_ID:
		if (client->server_session_id) {
			git_error_set(GIT_ERROR_NET, "invalid capabilities - duplicate session id");
			return -1;
		}

		client->server_session_id = git__strndup(value, value_len);
		GIT_ERROR_CHECK_ALLOC(client->server_session_id);

		break;
	default:
		GIT_ASSERT(!"unknown value capability");
	}

	return 0;
}

static int handle_capability(git_smart_client *client, const char *data, size_t len)
{
	const smart_capability_name *cap, *match = NULL;
	const char *value = NULL;
	size_t key_len, value_len;
	bool reject_unknown = false, reject_unsupported = false;

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
				git_error_set(GIT_ERROR_NET, "server sent capability without value: '%s'", cap->name);
				return -1;
			}

			if (data[key_len] != '=')
				break;

			match = cap;
			value = &data[key_len + 1];
			value_len = len - (key_len + 1);

			if (handle_capability_value(client, cap, value, value_len) < 0)
				return -1;

			break;

		default:
			if (strncmp(data, cap->name, len) == 0)
				match = cap;

			break;
		}

		if (match)
			break;
	}

	if (!match && reject_unknown) {
		git_error_set(GIT_ERROR_NET, "server sent unknown capability: '%.*s'", (int)len, data);
		return -1;
	}

	if ((client->capabilities & cap->capability) == 0 &&
	    reject_unsupported) {
		git_error_set(GIT_ERROR_NET, "server sent unsupported capability: '%s'", cap->name);
		return -1;
	}

	if ((DISALLOWED_SERVER_CAPABILITIES & cap->capability) != 0) {
		git_error_set(GIT_ERROR_NET, "server sent disallowed capability: '%s'", cap->name);
		return -1;
	}

	client->server_capabilities |= cap->capability;

	fprintf(debug, "consumed cap : %" PRIuZ "\n", len);

	return 0;
}

static int handle_capabilities(git_smart_client *client, const char *data, size_t len)
{
	const char *cap = data;
	size_t cap_len = 0, position = 0;

	printf("hi\n");

	while (position <= len) {
		if (position == len || data[position] == ' ') {
			if (handle_capability(client, cap, cap_len) < 0)
				return -1;

			cap = position == len ? NULL : data + position + 1;
			position++;
			cap_len = 0;
		}

		position++;
		cap_len++;
	}

	/* Set some defaults based on capabilities */
	if (!client->oid_type)
		client->oid_type = GIT_OID_DEFAULT;

	return 0;
}

int git_smart_client_init(
	git_smart_client **out,
	git_repository *repo,
	git_stream *stream)
{
	git_smart_client *client;

	GIT_ASSERT_ARG(out && repo);

	/* TODO*/
	debug = fopen("/tmp/clientdebug", "w");
	printf("INIT %p %s\n", debug, strerror(errno));

	client = git__calloc(1, sizeof(git_smart_client));
	GIT_ERROR_CHECK_ALLOC(client);

	client->repo = repo;
	client->stream = stream;
	client->capabilities = DEFAULT_CLIENT_CAPABILITIES;

	/* TODO */
	client->agent = "libgit2/1.2.3.4.(hello.world)";
	client->session_id = "opaque-session-id";

	pkt_reader_init(&client->reader, repo, stream, PKT_READER_CLIENT);
	pkt_writer_init(&client->writer, stream);

	if (git_strmap_new(&client->symrefs) < 0)
		return -1;

	*out = client;
	return 0;
}

static int handle_ref(
	git_smart_client *client,
	struct git_smart_packet *packet)
{
	git_remote_head *head;
	const char *refname, *symref_target;

	GIT_ASSERT(packet && packet->type == GIT_SMART_PACKET_REF);

	head = git__calloc(1, sizeof(git_remote_head));
	GIT_ERROR_CHECK_ALLOC(head);

	if (packet->oid_len != git_oid_hexsize(client->oid_type) ||
	    (git_oid__fromstrn(&head->oid, packet->oid, packet->oid_len, client->oid_type)) < 0) {
		git_error_set(GIT_ERROR_NET, "invalid packet - invalid object id");
		return -1;
	}

	head->name = git__strndup(packet->refname, packet->refname_len);
	GIT_ERROR_CHECK_ALLOC(head->name);

	if ((symref_target = git_strmap_get(client->symrefs, head->name)) != NULL) {
		head->symref_target = git__strdup(symref_target);
		GIT_ERROR_CHECK_ALLOC(head->symref_target);
	}

	printf("ref :: %s %s %s\n", git_oid_tostr_s(&head->oid), head->name, head->symref_target);

	return git_vector_insert(&client->heads, head);
}

int git_smart_client_fetchpack(git_smart_client *client)
{
	struct git_smart_packet *packet;
	int error = -1;

	GIT_ASSERT(!client->seen_advertisement);

	fprintf(debug, "fetchpack start\n");

	while (!client->seen_advertisement) {
		if (pkt_read(&packet, &client->reader) < 0)
			goto done;

		switch (packet->type) {
		case GIT_SMART_PACKET_REF:
			if (packet->capabilities &&
			    handle_capabilities(client, packet->capabilities, packet->capabilities_len) < 0)
				goto done;

			if (handle_ref(client, packet) < 0)
				goto done;

			break;

		case GIT_SMART_PACKET_FLUSH:
			client->seen_advertisement = 1;
			break;

		default:
			git_error_set(GIT_ERROR_NET, "unexpected packet type during ref advertisement");
			goto done;
		}
	}

	error = 0;

done:
	return error;
}

static int client_setup_depth(
	git_smart_client *client,
	const git_fetch_negotiation *wants)
{
	git_array_clear(client->shallow_roots);

	if (wants->depth > 0) {
		if (!(client->server_capabilities & GIT_SMART_CAPABILITY_SHALLOW)) {
			git_error_set(GIT_ERROR_NET, "server does not support shallow");
			return -1;
		}
	} else {
		client->capabilities &= ~GIT_SMART_CAPABILITY_SHALLOW;
	}

	if (wants->shallow_roots_len > 0) {
		git_array_init_to_size(client->shallow_roots, wants->shallow_roots_len);
		GIT_ERROR_CHECK_ALLOC(client->shallow_roots.ptr);

		memcpy(client->shallow_roots.ptr, wants->shallow_roots,
		       sizeof(git_oid) * wants->shallow_roots_len);
	}

	return 0;
}

#if 0

int git_smart_client_negotiate(
	git_smart_client *client,
	const git_fetch_negotiation *wants)
{
	git_revwalk__push_options opts = GIT_REVWALK__PUSH_OPTIONS_INIT;
	git_str data = GIT_STR_INIT;
	git_revwalk *walk = NULL;
	struct dzk,git_smart_packet *pkt;
	int error = -1;
	unsigned int i;
	git_oid oid;

	opts.insert_by_date = 1;




	/* Tell the other end that we're done negotiating */
	if (t->rpc && t->common.length > 0) {
		git_smart_packet *pkt;
		unsigned int j;

		if ((error = git_pkt_buffer_wants(wants, &t->caps, &data)) < 0)
			goto on_error;

		git_vector_foreach(&t->common, j, pkt) {
			if ((error = git_pkt_buffer_have(&pkt->oid, &data)) < 0)
				goto on_error;
		}

		if (git_str_oom(&data)) {
			error = -1;
			goto on_error;
		}
	}

	if ((error = git_pkt_buffer_done(&data)) < 0)
		goto on_error;

	if (t->cancelled.val) {
		git_error_set(GIT_ERROR_NET, "the fetch was cancelled");
		error = GIT_EUSER;
		goto on_error;
	}

	if ((error = git_smart__negotiation_step(&t->parent, data.ptr, data.size)) < 0)
		goto on_error;

	git_str_dispose(&data);
	git_revwalk_free(walk);

	/* Now let's eat up whatever the server gives us */
	if (!t->caps.multi_ack && !t->caps.multi_ack_detailed) {
		if (pkt_read(&pkt, client->reader) < 0)
			return -1;

		if (pkt->type != GIT_SMART_PACKET_ACK && pkt->type != GIT_SMART_PACKET_NAK) {
			git_error_set(GIT_ERROR_NET, "unexpected packet type in negotiation");
			return -1;
		}
	} else {
		error = wait_while_ack(t);
	}

	return error;

on_error:
	git_revwalk_free(walk);
	git_str_dispose(&data);
	return error;
}
#endif

static int client_negotiate_wants(
	git_smart_client *client,
	const git_fetch_negotiation *wants)
{
	const git_remote_head *head;
	char oid[GIT_OID_MAX_HEXSIZE];
	size_t i;

	for (i = 0; i < wants->refs_len; i++) {
		head = wants->refs[i];

		if (head->local)
			continue;

		if (pkt_write(&client->writer,
				GIT_SMART_PACKET_WANT | GIT_SMART_PACKET_HAS_CAPABILITIES,
				&head->oid,
				client->capabilities,
				client->agent,
				client->session_id) < 0)
			return -1;
	}

	/* Tell the server about our shallow objects */
	for (i = 0; i < wants->shallow_roots_len; i++) {
		if (pkt_write(&client->writer, GIT_SMART_PACKET_SHALLOW, &wants->shallow_roots[i]) < 0)
			return -1;
	}
}

static int client_negotiate_depth(
	git_smart_client *client,
	const git_fetch_negotiation *wants)
{
	struct git_smart_packet *pkt;
	bool complete = false;
	int error;

	if (!wants->depth)
		return 0;

	if (pkt_write(&client->writer, GIT_SMART_PACKET_DEEPEN, wants->depth) < 0 ||
	    pkt_writer_flush(&client->writer) < 0)
		return -1;

	while (!complete && !error &&
	       !(error = pkt_read(&pkt, &client->reader))) {
		switch (pkt->type) {
		case GIT_SMART_PACKET_SHALLOW:
			error = git_oidarray__add(&client->shallow_roots, &pkt->oid);
			break;
		case GIT_SMART_PACKET_UNSHALLOW:
			git_oidarray__remove(&client->shallow_roots, &pkt->oid);
			break;
		case GIT_SMART_PACKET_FLUSH:
			complete = true;
			break;
		default:
			git_error_set(GIT_ERROR_NET, "unexpected packet type during depth negotiation");
			error = -1;
			break;
		}
	}

done:
	return error ? -1 : 0;
}

static int client_negotiate_haves(git_smart_client *client)
{
	git_revwalk *walk = NULL;
	git_revwalk__push_options opts = GIT_REVWALK__PUSH_OPTIONS_INIT;
	git_oid oid;
	size_t i;
	int error = -1;

	opts.insert_by_date = 1;

	if (git_revwalk_new(&walk, client->repo) < 0 ||
	    git_revwalk__push_glob(walk, "refs/*", &opts) < 0)
		goto done;

	/*
	 * Our support for ACK extensions is simply to parse them. On
	 * the first ACK we will accept that as enough common
	 * objects. We give up if we haven't found an answer in the
	 * first 256 we send.
	 */
	for (i = 0; i < 256; ) {
		if ((error = git_revwalk_next(&oid, walk)) == GIT_ITEROVER)
			break;
		else if (error < 0)
			return -1;

		if (pkt_write(&client->writer, GIT_SMART_PACKET_HAVE,
				GIT_SMART_PACKET_HAVE,
				&oid) < 0)
			return -1;

		if (++i % 20 == 0) {
			struct git_smart_packet *response_pkt;
			bool reading_acks = true, done = false;

			if (client->cancelled) {
				git_error_set(GIT_ERROR_NET, "fetch was cancelled by the user");
				error = GIT_EUSER;
				goto done;
			}

			if (pkt_write(&client->writer, GIT_SMART_PACKET_FLUSH) < 0 ||
			    pkt_writer_flush(&client->writer) < 0)
				return -1;

			while (reading_acks) {
				if (pkt_read(&response_pkt, &client->reader) < 0)
					return -1;

				if ((client->capabilities & GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED)) {
					if (response_pkt->type == GIT_SMART_PACKET_ACK) {
						if ((response_pkt->flags & GIT_SMART_PACKET_ACK_COMMON)) {
							/* common? we can stop walking down this line -- so git_revwalk_hide this oid */
							if (git_revwalk_hide(walk, &response_pkt->oid) < 0)
								return 1;
						} else if ((response_pkt->flags & GIT_SMART_PACKET_ACK_READY)) {
							done = true;
						} else if (response_pkt->flags) {
							git_error_set(GIT_ERROR_NET, "unexpected ack data during negotiation");
							return -1;
						}
					} else {
						git_error_set(GIT_ERROR_NET, "unexpected packet type during negotiation");
						return -1;
					}
				}

				else if ((client->capabilities & GIT_SMART_CAPABILITY_MULTI_ACK)) {
					if (response_pkt->type == GIT_SMART_PACKET_ACK) {
						if ((response_pkt->flags & GIT_SMART_PACKET_ACK_CONTINUE)) {
							/* common? we can stop walking down this line -- so git_revwalk_hide this oid */
							if (git_revwalk_hide(walk, &response_pkt->oid) < 0)
								return 1;
						} else if (response_pkt->flags) {
							git_error_set(GIT_ERROR_NET, "unexpected ack data during negotiation");
							return -1;
						} else {
							done = true;
						}
					} else if (response_pkt->type == GIT_SMART_PACKET_NAK) {
						break;
					}
				}

				else {
					if (response_pkt->type == GIT_SMART_PACKET_ACK) {
						done = true;
						break;
					} else if (response_pkt->type != GIT_SMART_PACKET_NAK) {
						git_error_set(GIT_ERROR_NET, "unexpected packet type during negotiation");
						return -1;
					}
				}
			}

			if (done)
				break;
		}
	}

	error = 0;

done:
	git_revwalk_free(walk);
	return error;
}

static int client_negotiate_flush(git_smart_client *client)
{
	if (pkt_write(&client->writer, GIT_SMART_PACKET_FLUSH) < 0 ||
	    pkt_writer_flush(&client->writer) < 0)
		return -1;

	return 0;
}

static int client_negotiate_done(git_smart_client *client)
{
	if (pkt_write(&client->writer, GIT_SMART_PACKET_DONE) < 0 ||
	    pkt_writer_flush(&client->writer) < 0)
		return -1;

	return 0;
}

int git_smart_client_negotiate(
	git_smart_client *client,
	const git_fetch_negotiation *wants)
{
	struct git_smart_packet *final_pkt;

	if (client_setup_depth(client, wants) < 0 ||
	    client_negotiate_wants(client, wants) < 0 ||
		client_negotiate_depth(client, wants) < 0 ||
		client_negotiate_flush(client) < 0 ||
		client_negotiate_haves(client) < 0 ||
		client_negotiate_done(client) < 0)
		return -1;

	if (pkt_read(&final_pkt, &client->reader) < 0)
		return -1;

	if (final_pkt->type != GIT_SMART_PACKET_ACK && final_pkt->type != GIT_SMART_PACKET_NAK) {
		git_error_set(GIT_ERROR_NET, "unexpected packet type during final negotiation");
		return -1;
	}

	return 0;
}

int git_smart_client_capabilities(
	unsigned int *out,
	git_smart_client *client)
{
	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->seen_advertisement);

	*out = (client->server_capabilities & client->capabilities);
	return 0;
}

int git_smart_client_oid_type(
	git_oid_t *out,
	git_smart_client *client)
{
	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->seen_advertisement);

	*out = client->oid_type;
	return 0;
}

int git_smart_client_refs(
	const git_remote_head ***out,
	size_t *size,
	git_smart_client *client)
{
	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->seen_advertisement);

	*out = (const git_remote_head **)client->heads.contents;
	*size = client->heads.length;

	return 0;
}

static int download_with_sideband(
	git_smart_client *client,
	struct git_odb_writepack *packwriter)
{
	git_indexer_progress progress = { 0 };
	struct git_smart_packet *pkt;
	size_t max_sideband = (client->capabilities & GIT_SMART_CAPABILITY_SIDE_BAND_64K) ? 65520 : 1000;
	bool done = false;
	int error;

	while (!done) {
		/* TODO: timeouts, better/faster cancellation handling */
		if (pkt_read(&pkt, &client->reader) < 0)
			return -1;

		if (client->cancelled) {
			git_error_set(GIT_ERROR_NET, "fetch was cancelled by the user");
			return GIT_EUSER;
		}

		if (pkt->sideband_len > max_sideband) {
			git_error_set(GIT_ERROR_NET, "overflow in sideband data");
			return -1;
		}

		switch (pkt->type) {
		case GIT_SMART_PACKET_SIDEBAND_PROGRESS:
			/* TODO */
			/* sideband_progress(pkt->sideband_data, (int)pkt->sideband_len, progress_payload) */
			break;
		case GIT_SMART_PACKET_SIDEBAND_DATA:
			error = packwriter->append(packwriter, pkt->sideband, pkt->sideband_len, &progress);
			break;
		case GIT_SMART_PACKET_FLUSH:
			error = packwriter->commit(packwriter, &progress);
			done = true;
			break;
		default:
			git_error_set(GIT_ERROR_NET, "unexpected packet type during download pack");
			return -1;
		}

		if (error)
			return -1;
	}

	printf("\n\nDONE\n\n");

	return 0;
}

static int download_no_sideband(
	git_smart_client *client,
	struct git_odb_writepack *packwriter)
{
	abort();
}

int git_smart_client_download_pack(git_smart_client *client)
{
	git_odb *odb;
	struct git_odb_writepack *packwriter = NULL;

	/* TODO */
	void *progress_cb = NULL;
	void *progress_payload = NULL;

	int error = -1;

	if (git_repository_odb__weakptr(&odb, client->repo) < 0 ||
	    git_odb_write_pack(&packwriter, odb, progress_cb, progress_payload) < 0)
		goto done;

	if ((client->capabilities & (GIT_SMART_CAPABILITY_SIDE_BAND | GIT_SMART_CAPABILITY_SIDE_BAND_64K)))
		error = download_with_sideband(client, packwriter);
	else
		error = download_no_sideband(client, packwriter);

	if (error)
		goto done;

	error = 0;

done:
	if (packwriter)
		packwriter->free(packwriter);

	return error;
}

int git_smart_client_shallow_roots(git_oidarray *out, git_smart_client *client)
{
	size_t len;

	GIT_ERROR_CHECK_ALLOC_MULTIPLY(&len, client->shallow_roots.size, sizeof(git_oid));

	out->count = client->shallow_roots.size;

	if (len) {
		out->ids = git__malloc(len);
		memcpy(out->ids, client->shallow_roots.ptr, len);
	} else {
		out->ids = NULL;
	}

	return 0;
}

int git_smart_client_cancel(git_smart_client *client)
{
	client->cancelled = 1;
	return 0;
}

void git_smart_client_free(git_smart_client *client)
{
	const char *src, *tgt;
	git_remote_head *head;
	size_t i;

	if (!client)
		return;

	git_strmap_foreach(client->symrefs, src, tgt, {
		git__free((char *)src);
		git__free((char *)tgt);
	});
	git_strmap_free(client->symrefs);

	git_vector_foreach(&client->heads, i, head) {
		git__free(head->name);
		git__free(head->symref_target);
		git__free(head);
	}
	git_vector_free(&client->heads);

	git_str_dispose(&client->writer.write_buf);
	git_str_dispose(&client->reader.read_buf);
	git__free(client);
}
