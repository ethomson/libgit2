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

#include "git2/odb.h"
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

	unsigned int read_capabilities : 1;

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

	struct pkt_reader pkt_reader;
	struct pkt_writer pkt_writer;

	/* TODO: unused? */
	git_str write_buf;

	unsigned int read_advertisement : 1;

	/* Configurable client information */

	/* The client's (our) capabilities */
	unsigned int capabilities;

	git_array_oid_t shallow_roots;

	/* Server information */
	const char *server_agent;
	const char *server_session_id;
	unsigned int server_capabilities;

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
		/* TODO: make sure this doesn't continutally realloc */
		if (git_str_grow(&parser->read_buf, READ_SIZE) < 0)
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

/*
 * TODO: we probably don't need to do a full clear on every read.
 * Just occasionally to prevent us from having an unnecessarily large buffer.
 */
GIT_INLINE(int) pkt_reader_reset(struct pkt_reader *parser)
{
	GIT_ASSERT(parser->read_buf.size >= parser->pkt.len);

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

GIT_INLINE(int) pkt_reader_consume(struct pkt_reader *parser, size_t len)
{
	if (GIT_ADD_SIZET_OVERFLOW(&parser->position, parser->position, len))
		return -1;

	parser->remain_data = parser->read_buf.ptr + parser->position;
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

	printf("len: %c %c %c %c\n", parser->remain_data[0], parser->remain_data[1], parser->remain_data[2], parser->remain_data[3]);

	if (git__strntol64(&value, parser->remain_data, 4, NULL, 16) < 0 ||
	    value < 0 || value > UINT_MAX - 4) {
		git_error_set(GIT_ERROR_NET, "invalid packet - invalid decoded length");
		return -1;
	}

	parser->total_len = value;
	parser->remain_len = value;

	fprintf(debug, "0: total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);

	pkt_reader_consume(parser, 4);

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

	if (git__prefixncmp(parser->remain_data, parser->remain_len, "have ") == 0) {
		parser->pkt.type = GIT_SMART_PACKET_HAVE;
		return pkt_reader_consume(parser, CONST_STRLEN("have "));
	}

		/* TODO: is this right? */
	if (git__strncmp(parser->remain_data, "done\n", parser->remain_len) == 0) {
		parser->pkt.type = GIT_SMART_PACKET_DONE;
		return pkt_reader_consume(parser, CONST_STRLEN("done\n"));
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
		git_error_set(GIT_ERROR_NET, "expected %s in packet", name);
		return -1;
	}

	return pkt_reader_consume(parser, 1);
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

		/* TODO: check valid chars */
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
	if (!parser->read_capabilities) {
		if (pkt_parse_char(parser, '\0', "NUL") == 0) {
			fprintf(debug, "found NUL\n");

			if (pkt_parse_capabilities(parser) < 0)
				return -1;

			fprintf(debug, "caps are: '%.*s'\n", (int)parser->pkt.capabilities_len, parser->pkt.capabilities);
		}

		parser->read_capabilities = 1;
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

	if (!parser->read_capabilities) {
		fprintf(debug, "read capabilities: '%.*s'\n", (int)parser->remain_len, parser->remain_data);
		fflush(debug);

		if (parser->remain_len > 1) {
			if (pkt_parse_char(parser, ' ', "space") < 0) {
				git_error_set(GIT_ERROR_NET, "expected capabilities in packet");
				return -1;
			}

			if (pkt_parse_capabilities(parser) < 0)
				return -1;

			fprintf(debug, "caps are: '%.*s'\n", (int)parser->pkt.capabilities_len, parser->pkt.capabilities);
		}

		parser->read_capabilities = 1;
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

	if (pkt_reader_fill(parser, parser->total_len - 4) < 0)
		return -1;

	fprintf(debug, "after fill - total_len is: %d -- parser len is: %d\n", (int)parser->total_len, (int)parser->remain_len);
	fflush(debug);

	parser->pkt.data = parser->read_buf.ptr;
	parser->pkt.len = parser->total_len;

	/* TODO: this should probably be more stateful than typed */
	if (parser->type == PKT_READER_CLIENT) {
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
		case GIT_SMART_PACKET_DONE:
			error = 0;
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

int pkt_append_capabilities(struct pkt_writer *pkt_writer)
{

}

int pkt_write(
	struct pkt_writer *pkt_writer,
	git_smart_packet_t type,
	...)
{
	const char *type_name = NULL;
	va_list ap;
	size_t start_pos, end_pos, len;
	char len_str[5];
	int error;

	start_pos = pkt_writer->write_buf.size;

	if ((error = git_str_put(&pkt_writer->write_buf, "0000", 4)) < 0)
		return -1;

	if (type == GIT_SMART_PACKET_FLUSH)
		return 0;

	va_start(ap, type);

printf("YO 1: '%s'\n", pkt_writer->write_buf.ptr);

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

	va_end(ap);

	if (error < 0)
		return -1;

	if (!pkt_writer->written_capabilities) {
		if (pkt_append_capabilities(pkt_writer))
			return -1;

		pkt_writer->written_capabilities = 1;
	}

	if ((error = git_str_putc(&pkt_writer->write_buf, '\n')) < 0)
		return -1;

printf("YO 2: '%s'\n", pkt_writer->write_buf.ptr);

	end_pos = pkt_writer->write_buf.size;

	GIT_ASSERT(end_pos > start_pos);
	len = end_pos - start_pos;
	GIT_ASSERT(len <= 65535);

	if (p_snprintf(len_str, 5, "%04x", (unsigned int)len) < 0)
		return -1;

	memcpy((pkt_writer->write_buf.ptr + start_pos), len_str, 4);

printf("YO 3: '%s'\n", pkt_writer->write_buf.ptr);

	return error;
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

	pkt_reader_init(&client->pkt_reader, repo, stream, PKT_READER_CLIENT);

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

	GIT_ASSERT(!client->read_advertisement);

	fprintf(debug, "fetchpack start\n");

	while (!client->read_advertisement) {
		if (pkt_read(&packet, &client->pkt_reader) < 0)
			goto done;

		printf("read packet: %d (%d)\n", packet->type, GIT_SMART_PACKET_REF);

		switch (packet->type) {
		case GIT_SMART_PACKET_REF:
			if (packet->capabilities &&
			    handle_capabilities(client, packet->capabilities, packet->capabilities_len) < 0)
				goto done;

			if (handle_ref(client, packet) < 0)
				goto done;

			break;

		case GIT_SMART_PACKET_FLUSH:
			client->read_advertisement = 1;
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
static int smart_client_setup_wants(
	const git_fetch_negotiation *wants,
	transport_smart_caps *caps,
	git_str *buf)
{
	const git_remote_head *head;
	char oid[GIT_OID_MAX_HEXSIZE];
	git_oid_t oid_type;
	size_t oid_hexsize, want_len, i = 0;

#ifdef GIT_EXPERIMENTAL_SHA256
	oid_type = wants->refs_len > 0 ? wants->refs[0]->oid.type : GIT_OID_SHA1;
#else
	oid_type = GIT_OID_SHA1;
#endif

	oid_hexsize = git_oid_hexsize(oid_type);

	want_len = PKT_LEN_SIZE + CONST_STRLEN(PKT_WANT_PREFIX) +
	      oid_hexsize + 1 /* LF */;

	if (caps->common) {
		for (; i < wants->refs_len; ++i) {
			head = wants->refs[i];
			if (!head->local)
				break;
		}

		if (buffer_want_with_caps(wants->refs[i], caps, oid_type, buf) < 0)
			return -1;

		i++;
	}

	for (; i < wants->refs_len; ++i) {
		head = wants->refs[i];

		if (head->local)
			continue;

		git_oid_fmt(oid, &head->oid);

		git_str_printf(buf, "%04x%s%.*s\n",
			(unsigned int)want_len, PKT_WANT_PREFIX,
			(int)oid_hexsize, oid);

		if (git_str_oom(buf))
			return -1;
	}

	/* Tell the server about our shallow objects */
	for (i = 0; i < wants->shallow_roots_len; i++) {
		char oid[GIT_OID_MAX_HEXSIZE + 1];
		if (pkt_format(&pkt, client->pkt_writer, GIT_SMART_PACKET_SHALLOW, &wants->shallow_roots[i]) < 0)
			return -1;

		if (git_str_oom(buf))
			return -1;
	}

	if (wants->depth > 0) {
		git_str deepen_buf = GIT_STR_INIT;

		git_str_printf(&deepen_buf, "deepen %d\n", wants->depth);
		git_str_printf(buf,"%04x%s", (unsigned int)git_str_len(&deepen_buf) + 4, git_str_cstr(&deepen_buf));

		git_str_dispose(&deepen_buf);

		if (git_str_oom(buf))
			return -1;
	}

	return git_pkt_buffer_flush(buf);
}

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

	if (client_setup_depth(client, wants) < 0 ||
	    git_pkt_buffer_wants(wants, &t->caps, &data) < 0 ||
		git_revwalk_new(&walk, client->repo) < 0 ||
	    git_revwalk__push_glob(walk, "refs/*", &opts) < 0)
		goto on_error;

	if (wants->depth > 0) {
		if ((error = git_smart__negotiation_step(&t->parent, data.ptr, data.size)) < 0)
			goto on_error;

		while ((error = pkt_read(&pkt, &client->pkt_reader)) == 0) {
			bool complete = false;

			if (pkt->type == GIT_SMART_PACKET_SHALLOW) {
				error = git_oidarray__add(&client->shallow_roots, &pkt->oid);
			} else if (pkt->type == GIT_SMART_PACKET_UNSHALLOW) {
				git_oidarray__remove(&client->shallow_roots, &pkt->oid);
			} else if (pkt->type == GIT_SMART_PACKET_FLUSH) {
				/* Server is done, stop processing shallow oids */
				complete = true;
			} else {
				git_error_set(GIT_ERROR_NET, "unexpected packet type");
				error = -1;
			}

			if (complete || error < 0)
				break;
		}

		if (error < 0)
			goto on_error;
	}

	/*
	 * Our support for ACK extensions is simply to parse them. On
	 * the first ACK we will accept that as enough common
	 * objects. We give up if we haven't found an answer in the
	 * first 256 we send.
	 */
	i = 0;
	while (i < 256) {
		if ((error = git_revwalk_next(&oid, walk)) == GIT_ITEROVER)
			break;
		else if (error < 0)
			goto on_error;

		git_pkt_buffer_have(&oid, &data);
		i++;

		if (i % 20 == 0) {
			if (t->cancelled.val) {
				git_error_set(GIT_ERROR_NET, "The fetch was cancelled by the user");
				error = GIT_EUSER;
				goto on_error;
			}

			git_pkt_buffer_flush(&data);
			if (git_str_oom(&data)) {
				error = -1;
				goto on_error;
			}

			if ((error = git_smart__negotiation_step(&t->parent, data.ptr, data.size)) < 0)
				goto on_error;

			git_str_clear(&data);
			if (t->caps.multi_ack || t->caps.multi_ack_detailed) {
				if ((error = store_common(t)) < 0)
					goto on_error;
			} else {
				if ((error = pkt_read(&pkt, &client->pkt_reader)) < 0)
					goto on_error;

				if (pkt->type == GIT_SMART_PACKET_ACK) {
					break;
				} else if (pkt->type == GIT_SMART_PACKET_NAK) {
					continue;
				} else {
					git_error_set(GIT_ERROR_NET, "unexpected pkt type");
					error = -1;
					goto on_error;
				}
			}
		}

		if (t->common.length > 0)
			break;

		if (i % 20 == 0 && t->rpc) {
			git_pkt_ack *pkt;
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
	}

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
		if (pkt_read(&pkt, client->pkt_reader) < 0)
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

static int client_write_wants(
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

		// TODO: include caps on the first packet
		if (pkt_write(&client->pkt_writer, GIT_SMART_PACKET_WANT, &head->oid) < 0)
			return -1;
	}

	/* Tell the server about our shallow objects */
	for (i = 0; i < wants->shallow_roots_len; i++) {
		if (pkt_write(&client->pkt_writer, GIT_SMART_PACKET_SHALLOW, &wants->shallow_roots[i]) < 0)
			return -1;
	}

	if (wants->depth > 0) {
		if (pkt_write(&client->pkt_writer, GIT_SMART_PACKET_DEEPEN, wants->depth) < 0)
			return -1;
	}
}

int git_smart_client_negotiate(
	git_smart_client *client,
	const git_fetch_negotiation *wants)
{
	git_revwalk__push_options opts = GIT_REVWALK__PUSH_OPTIONS_INIT;
	git_str data = GIT_STR_INIT;
	git_revwalk *walk = NULL;
	struct git_smart_packet *pkt;
	int error = -1;
	unsigned int i;
	git_oid oid;

	opts.insert_by_date = 1;

	if (client_setup_depth(client, wants) < 0 ||
		git_revwalk_new(&walk, client->repo) < 0 ||
	    git_revwalk__push_glob(walk, "refs/*", &opts) < 0 ||
	    client_write_wants(client, wants) < 0)
		return -1;



	pkt_write(&client->pkt_writer, GIT_SMART_PACKET_ERR, "foobar: %s %s", "hello", "world");
	printf("FORMATTED: '%s'\n", client->pkt_writer.write_buf.ptr);

	pkt_write(&client->pkt_writer, GIT_SMART_PACKET_ERR, "bar");
	printf("FORMATTED: '%s'\n", client->pkt_writer.write_buf.ptr);

	pkt_write(&client->pkt_writer, GIT_SMART_PACKET_ERR, "barfoo");
	printf("FORMATTED: '%s'\n", client->pkt_writer.write_buf.ptr);

	pkt_write(&client->pkt_writer, GIT_SMART_PACKET_FLUSH);
	printf("FORMATTED: '%s'\n", client->pkt_writer.write_buf.ptr);

	pkt_write(&pkt, &client->pkt_writer, GIT_SMART_PACKET_ERR, "zippy");
	printf("FORMATTED: '%s'\n", client->pkt_writer.write_buf.ptr);
}

int git_smart_client_capabilities(
	unsigned int *out,
	git_smart_client *client)
{
	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->read_advertisement);

	*out = (client->server_capabilities & client->capabilities);
	return 0;
}

int git_smart_client_oid_type(
	git_oid_t *out,
	git_smart_client *client)
{
	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->read_advertisement);

	*out = client->oid_type;
	return 0;
}

int git_smart_client_refs(
	const git_remote_head ***out,
	size_t *size,
	git_smart_client *client)
{
	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->read_advertisement);

	*out = (const git_remote_head **)client->heads.contents;
	*size = client->heads.length;

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

	git_str_dispose(&client->write_buf);
	git__free(client);
}
