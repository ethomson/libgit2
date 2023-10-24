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
#include "push.h"
#include "repository.h"

#include "git2/odb.h"
#include "git2/odb_backend.h"
#include "git2/revwalk.h"
#include "git2/version.h"
#include "git2/sys/refs.h"
#include "git2/sys/transport.h"
#include "git2/sys/remote.h"

/* TODO : 1024 or something */
#define READ_SIZE 1024

#define DEFAULT_CLIENT_FETCH_CAPABILITIES   ( \
	GIT_SMART_CAPABILITY_MULTI_ACK          | \
	GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED | \
	GIT_SMART_CAPABILITY_THIN_PACK          | \
	GIT_SMART_CAPABILITY_SIDE_BAND          | \
	GIT_SMART_CAPABILITY_SIDE_BAND_64K      | \
	GIT_SMART_CAPABILITY_OFS_DELTA          | \
	GIT_SMART_CAPABILITY_INCLUDE_TAG        )

#define DEFAULT_CLIENT_PUSH_CAPABILITIES    ( \
	GIT_SMART_CAPABILITY_REPORT_STATUS_V2   | \
	GIT_SMART_CAPABILITY_REPORT_STATUS      | \
	GIT_SMART_CAPABILITY_SIDE_BAND          | \
	GIT_SMART_CAPABILITY_SIDE_BAND_64K      )

/* Capabilities that must be agreed upon */
/* TODO: Is this always our defaults? */
#define NEGOTIATED_CAPABILITIES             ( \
	GIT_SMART_CAPABILITY_MULTI_ACK          | \
	GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED | \
	GIT_SMART_CAPABILITY_THIN_PACK          | \
	GIT_SMART_CAPABILITY_SIDE_BAND          | \
	GIT_SMART_CAPABILITY_SIDE_BAND_64K      | \
	GIT_SMART_CAPABILITY_OFS_DELTA          | \
	GIT_SMART_CAPABILITY_INCLUDE_TAG        )

#define DISALLOWED_SERVER_CAPABILITIES	0

#define MIN_PROGRESS_UPDATE_INTERVAL 0.5

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
	SMART_IO_CLIENT,
	SMART_IO_SERVER
} smart_io_t;

struct smart_io {
	git_stream *stream;

	unsigned int type : 1,
	             direction : 1,
	             sent_capabilities : 1,
	             received_capabilities : 1,
	             received_flush : 1;

	/* Remote information */
	unsigned int capabilities;
	char *agent;
	char *session_id;
	git_oid_t oid_type;

	git_strmap *symrefs;

	/*
	 * We buffer our I/O and set up packet structs to point into the read
	 * and write buffers. Returned read or write packets generally point
	 * into this data.
	 */
	git_str write_buf;
	git_str read_buf;

	/* The buffer for push-results packets encoded in the sideband. */
	git_str sideband_buf;

	/*
	 * Packet reading: data for the current packet being read.
	 */

	/* The current packet that we're filling. */
	struct git_smart_packet read_pkt;

	/*
	 * The total length of the packet (including size prefix) and
	 * our current position within the packet.
	 */
	size_t read_len;
	size_t read_position;

	/* The remaining data to parse of the message and its length. */
	const char *read_remain_data;
	size_t read_remain_len;
};

struct git_smart_client {
	git_stream *stream;

	git_revwalk *walk;
	struct smart_io server;

	unsigned int direction : 1,
	             rpc : 1,
	             connected : 1,
	             received_advertisement : 1,
	             negotiation_complete : 1,
	             received_report : 1,
	             cancelled : 1;

	/* Configurable client information */

	/* The client's (our) capabilities */
	const char *agent;
	const char *session_id;
	unsigned int capabilities;

	/* Callbacks */
	git_transport_message_cb sideband_progress;
	git_indexer_progress_cb indexer_progress;
	git_push_transfer_progress push_transfer_progress;
	void *progress_payload;	

	/* Negotiation data */

	git_array_oid_t common_tips;
	git_array_oid_t shallow_roots;
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

	if (!ua || !*ua) {
		git_str_puts(out, "libgit2.");
		ua = LIBGIT2_VERSION;
	}

	for (c = ua; *c; c++)
		git_str_putc(out, isspace(*c) ? '.' : *c);

	git_str_putc(out, ')');
}

static int refname_cmp(const void *_a, const void *_b)
{
	const git_reference *a = _a, *b = _b;
	return strcmp(git_reference_name(a), git_reference_name(b));
}

static FILE *debug;

GIT_INLINE(int) smart_io_init(
	struct smart_io *io,
	git_repository *repo,
	git_stream *stream,
	smart_io_t type,
	unsigned int direction)
{
	GIT_UNUSED(repo);
	GIT_ASSERT(type <= 1 && direction <= 1);

	io->stream = stream;
	io->type = type;
	io->direction = direction;

	if (type == SMART_IO_CLIENT && git_strmap_new(&io->symrefs) < 0)
		return -1;

	printf("hmm: %d\n", git_repository_oid_type(repo));

	return 0;
}

GIT_INLINE(void) smart_io_dispose(struct smart_io *io)
{
	const char *src, *tgt;

	git__free(io->agent);
	git__free(io->session_id);

	if (io->type == SMART_IO_CLIENT) {
		git_strmap_foreach(io->symrefs, src, tgt, {
			git__free((char *)src);
			git__free((char *)tgt);
		});
		git_strmap_free(io->symrefs);
	}
}

GIT_INLINE(int) smart_io_reader_reset(struct smart_io *io)
{
	GIT_ASSERT(io->read_buf.size >= io->read_pkt.len);

	/*
	 * TODO: we probably don't need to do a memmove on every read.
	 * Just occasionally to prevent us from having an unnecessarily large buffer.
	 */
	memmove(io->read_buf.ptr,
	        io->read_buf.ptr + io->read_pkt.len,
	        io->read_buf.size - io->read_pkt.len);
	io->read_buf.size -= io->read_pkt.len;

	memset(&io->read_pkt, 0, sizeof(struct git_smart_packet));

	io->read_len = 0;
	io->read_position = 0;
	io->read_remain_data = NULL;
	io->read_remain_len = 0;

	return 0;
}

/*
 * resize the read buf and update positions (since there may be a realloc)
 */
GIT_INLINE(int) smart_io_reader_fill(struct smart_io *io, size_t len)
{
	char *buf;
	ssize_t ret;

	fprintf(debug, "-------------smart_io_reader_fill-------------\n");
	fprintf(debug, "filling read buf - size: %d / wanted: %d\n", (int)io->read_buf.size, (int)len);

	GIT_ASSERT(io->read_buf.size >= io->read_position);

	if (!len)
		return 0;

	while ((io->read_buf.size - io->read_position) < len) {
		if (git_str_grow_by(&io->read_buf, READ_SIZE) < 0)
			return -1;

		buf = io->read_buf.ptr + io->read_buf.size;

		if ((ret = git_stream_read(io->stream, buf, READ_SIZE)) < 0)
			return -1;

		fprintf(debug, ">>>read %d>>> %.*s\n", (int)ret, (int)ret, buf);

		/* TODO: check overflow, ensure size <= asize */
		io->read_buf.size += ret;

		if (ret == 0) {
			git_error_set(GIT_ERROR_NET, "unexpected eof from client");
			return -1;
		}
	}

	fprintf(debug, "filled read buf\n");
	fprintf(debug, "read buf is: '%.*s'\n", (int)io->read_buf.size, io->read_buf.ptr);

fprintf(debug, "%d %d\n", (int)io->read_buf.size, (int)io->read_position);

	GIT_ASSERT(io->read_buf.size > io->read_position);

	io->read_remain_data = io->read_buf.ptr + io->read_position;
	io->read_remain_len = len;

	return 0;
}

GIT_INLINE(int) smart_io_reader_advance(struct smart_io *io, size_t len)
{
	if (GIT_ADD_SIZET_OVERFLOW(&io->read_position, io->read_position, len))
		return -1;

	io->read_remain_data = io->read_buf.ptr + io->read_position;
	return 0;
}

GIT_INLINE(int) smart_io_reader_consume(struct smart_io *io, size_t len)
{
	if (smart_io_reader_advance(io, len) < 0)
		return -1;

	io->read_remain_len -= len;
	return 0;
}

static int parse_len(const char *buf, size_t len)
{
	int value;

	if (!isxdigit(buf[0]) || !isxdigit(buf[1]) ||
	    !isxdigit(buf[2]) || !isxdigit(buf[3])) {
		git_error_set(GIT_ERROR_NET, "invalid packet - incorrectly encoded length: '%c%c%c%c'", buf[0], buf[1], buf[2], buf[3]);
		return -1;
	}

	if (git__strntol64(&value, buf, 4, NULL, 16) < 0 ||
	    value < 0 || value > USHORT_MAX - 4) {
		git_error_set(GIT_ERROR_NET, "invalid packet - invalid decoded length");
		return -1;
	}

	return value;
}

static int pkt_parse_len(struct smart_io *io)
{
	int64_t value;

	fprintf(debug, "-----------parsing len---------\n");

	if (io->read_remain_len < 4) {
		git_error_set(GIT_ERROR_NET, "invalid packet - does not contain length");
		return -1;
	}

	if ((value = parse_len(io->read_remain_data)) < 0)
		return -1;

	io->read_len = value;
	io->read_remain_len = value;

	fprintf(debug, "0: total_len is: %d -- io len is: %d\n", (int)io->read_len, (int)io->read_remain_len);

	/*
	 * A flush packet does not encode its own length ("0000"), so we do not
	 * "consume" it (remove the 4 byte length from the message length). We
	 * just advance the stream pointer.
	 */

	if (value && smart_io_reader_consume(io, 4) < 0)
		return -1;

	if (!value && smart_io_reader_advance(io, 4) < 0)
		return -1;

	fprintf(debug, "1: total_len is: %d -- io len is: %d\n", (int)io->read_len, (int)io->read_remain_len);
	return 0;
}

static int pkt_parse_type(struct smart_io *io)
{
	fprintf(debug, "parsing type: %d - '%.*s'\n", (int)io->read_remain_len, (int)io->read_remain_len, io->read_remain_data);

	if (git__prefixncmp(io->read_remain_data, io->read_remain_len, "want ") == 0) {
		io->read_pkt.type = GIT_SMART_PACKET_WANT;
		return smart_io_reader_consume(io, CONST_STRLEN("want "));
	}
	else if (git__prefixncmp(io->read_remain_data, io->read_remain_len, "have ") == 0) {
		io->read_pkt.type = GIT_SMART_PACKET_HAVE;
		return smart_io_reader_consume(io, CONST_STRLEN("have "));
	}
	else if (git__strncmp(io->read_remain_data, "done\n", io->read_remain_len) == 0) {
		io->read_pkt.type = GIT_SMART_PACKET_DONE;
		return smart_io_reader_consume(io, CONST_STRLEN("done\n"));
	}

	else if (git__prefixncmp(io->read_remain_data, io->read_remain_len, "ACK ") == 0) {
		io->read_pkt.type = GIT_SMART_PACKET_ACK;
		return smart_io_reader_consume(io, CONST_STRLEN("ACK "));
	}
	else if (git__strncmp(io->read_remain_data, "NAK\n", io->read_remain_len) == 0) {
		io->read_pkt.type = GIT_SMART_PACKET_NAK;
		return smart_io_reader_consume(io, CONST_STRLEN("NAK\n"));
	}

	else if (io->read_remain_len >= 1 && io->read_remain_data[0] == 1) {
		io->read_pkt.type = GIT_SMART_PACKET_SIDEBAND_DATA;
		return smart_io_reader_consume(io, 1);
	}
	else if (io->read_remain_len >= 1 && io->read_remain_data[0] == 2) {
		io->read_pkt.type = GIT_SMART_PACKET_SIDEBAND_PROGRESS;
		return smart_io_reader_consume(io, 1);
	}
	else if (io->read_remain_len >= 1 && io->read_remain_data[0] == 3) {
		io->read_pkt.type = GIT_SMART_PACKET_SIDEBAND_ERROR;
		return smart_io_reader_consume(io, 1);
	}

	git_error_set(GIT_ERROR_NET, "unknown packet type");
	return -1;
}

GIT_INLINE(int) pkt_parse_oid(struct smart_io *io)
{
	const char *oid = io->read_remain_data;
	size_t remain = io->read_remain_len, len = 0;
	git_oid_t oid_type = io->oid_type ? io->oid_type : GIT_OID_DEFAULT;

	while (remain > 0) {
		char c = io->read_remain_data[len];

		if (c == ' ' || c == '\n' || c == '\0')
			break;

		if ((c < 'a' || c > 'f') && (c < 'A' || c > 'F') && (c < '0' || c > '9')) {
			git_error_set(GIT_ERROR_NET, "invalid packet - invalid object id");
			return -1;
		}

		remain--;
		len++;
	}

	if (len != git_oid_hexsize(oid_type)) {
		git_error_set(GIT_ERROR_NET, "invalid packet - invalid object id");
		return -1;
	}

	if (git_oid__fromstrn(&io->read_pkt.oid, oid, len, oid_type) < 0)
		return -1;

	return smart_io_reader_consume(io, len);
}


static int parse_capability_value(
	struct smart_io *io,
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

		if (git_strmap_set(io->symrefs, src, tgt) < 0)
			return -1;

		break;

	case GIT_SMART_CAPABILITY_OBJECT_FORMAT:
		if (io->oid_type) {
			git_error_set(GIT_ERROR_NET, "invalid capabilities - duplicate object format");
			return -1;
		}

		if ((io->oid_type = git_oid_type_fromstrn(value, value_len)) == 0) {
			git_error_set(GIT_ERROR_NET, "unknown object format from server");
			return -1;
		}

		break;

	case GIT_SMART_CAPABILITY_AGENT:
		if (io->agent) {
			git_error_set(GIT_ERROR_NET, "invalid capabilities - duplicate agent");
			return -1;
		}

		io->agent = git__strndup(value, value_len);
		GIT_ERROR_CHECK_ALLOC(io->agent);

		break;

	case GIT_SMART_CAPABILITY_SESSION_ID:
		if (io->session_id) {
			git_error_set(GIT_ERROR_NET, "invalid capabilities - duplicate session id");
			return -1;
		}

		io->session_id = git__strndup(value, value_len);
		GIT_ERROR_CHECK_ALLOC(io->session_id);

		break;
	default:
		GIT_ASSERT(!"unknown value capability");
	}

	return 0;
}

static int parse_capability(struct smart_io *io, const char *data, size_t len)
{
	const smart_capability_name *cap, *match = NULL;
	const char *value = NULL;
	size_t key_len, value_len;
	bool reject_unknown = false;

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

			if (parse_capability_value(io, cap, value, value_len) < 0)
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

	if ((DISALLOWED_SERVER_CAPABILITIES & cap->capability) != 0) {
		git_error_set(GIT_ERROR_NET, "server sent disallowed capability: '%s'", cap->name);
		return -1;
	}

	io->capabilities |= cap->capability;

	fprintf(debug, "consumed cap : %" PRIuZ "\n", len);

	return 0;
}

static int pkt_parse_capabilities(struct smart_io *io)
{
	const char *capabilities = io->read_remain_data, *cap = io->read_remain_data;
	size_t remain, capabilities_len = 0, cap_len = 0;

	for (remain = io->read_remain_len; remain > 0; remain--, capabilities_len++) {
		if (capabilities[capabilities_len] != ' ' &&
		    capabilities[capabilities_len] != '\n') {
			cap_len++;
			continue;
		}

		if (!cap_len)
			break;

		if (parse_capability(io, cap, cap_len) < 0)
			return -1;

		if (capabilities[capabilities_len] == ' ') {
			if (!remain)
				break;

			cap = &capabilities[capabilities_len + 1];
			cap_len = 0;
		}

		if (capabilities[capabilities_len] == '\n') {
			io->read_pkt.capabilities = capabilities;
			io->read_pkt.capabilities_len = capabilities_len;

fprintf(debug, "capabilities: %.*s\n", (int)capabilities_len, capabilities);
fprintf(debug, "capabilities: %d\n", io->capabilities);
fprintf(debug, "server session id: %s\n", io->session_id);
fprintf(debug, "server agent: %s\n", io->agent);
fprintf(debug, "oid type: %d\n", io->oid_type);


			return smart_io_reader_consume(io, capabilities_len);
		}
	}

fprintf(debug, "remain: %d '%.*s'\n", (int)io->read_remain_len, (int)io->read_remain_len, io->read_remain_data);

	git_error_set(GIT_ERROR_NET, "invalid capabilities in negotiation");
	return -1;
}

static int pkt_parse_char(struct smart_io *io, char c, const char *name)
{
	if (io->read_remain_len < 1 || io->read_remain_data[0] != c) {
		if (name)
			git_error_set(GIT_ERROR_NET, "expected %s in packet", name);

		return -1;
	}

	return smart_io_reader_consume(io, 1);
}

static int pkt_parse_string(struct smart_io *io, const char *s, const char *name)
{
	size_t s_len = strlen(s);

	if (io->read_remain_len < s_len || memcmp(io->read_remain_data, s, s_len) != 0) {
		if (name)
			git_error_set(GIT_ERROR_NET, "expected %s in packet", name);

		return -1;
	}

	return smart_io_reader_consume(io, s_len);
}

static int pkt_ensure_consumed(struct smart_io *io)
{
	if (io->read_remain_len != 0) {
		git_error_set(GIT_ERROR_NET, "unexpected trailing packet data");
		return -1;
	}

	return 0;
}

static int pkt_parse_refname(struct smart_io *io)
{
	const char *name = io->read_remain_data;
	size_t remain = io->read_remain_len, len = 0;

	for (remain = io->read_remain_len; remain > 0; remain--, len++) {
		if (name[len] == '\0' || name[len] == '\n')
			break;

		/* TODO: check valid chars? */
		if (name[len] == ' ') {
			git_error_set(GIT_ERROR_NET, "invalid character in reference name");
			return -1;
		}
	}

	io->read_pkt.refname = name;
	io->read_pkt.refname_len = len;

	return smart_io_reader_consume(io, len);
}

static size_t smart_io_reader_position(struct smart_io *io)
{
	fprintf(debug, "queried position as: %d\n", (int)io->read_position);
	return io->read_position;
}

static int smart_io_reader_set_position(struct smart_io *io, size_t position)
{
	size_t diff;

	fprintf(debug, "setting position to %d (from %d)\n", (int)position, (int)io->read_position);

	if (position <= io->read_position) {
		diff = io->read_position - position;

		fprintf(debug, "diff is %d\n", (int)diff);

		if (GIT_ADD_SIZET_OVERFLOW(&io->read_remain_len, io->read_remain_len, diff))
			return -1;
	} else {
		diff = position - io->read_position;

		GIT_ASSERT(io->read_remain_len >= diff);
		io->read_remain_len -= diff;
	}

	io->read_position = position;
	io->read_remain_data = io->read_buf.ptr + io->read_position;
	fprintf(debug, "set position to: %d (len = %d)\n", (int)io->read_position, (int)io->read_remain_len);

	return 0;
}

static int pkt_parse_advance_to_char(struct smart_io *io, char c)
{
	size_t advanced = 0;

	fprintf(debug, "advancing to char %x (start: %d '%.*s')\n", c, (int)io->read_remain_len, (int)io->read_remain_len, io->read_remain_data);

	while (advanced < io->read_remain_len) {
		if (io->read_remain_data[advanced] == c) {
			fprintf(debug, "found - remain len is now %d '%.*s'\n", (int)io->read_remain_len, (int)io->read_remain_len, io->read_remain_data );

			return smart_io_reader_consume(io, advanced);
		}

		advanced++;
	}

	return GIT_ENOTFOUND;
}

static int pkt_parse_ref(struct smart_io *io)
{
	size_t end_position = 0;
	int error;

	fprintf(debug, "parsing ref: %d - '%.*s\n", (int)io->read_remain_len, (int)io->read_remain_len, io->read_remain_data);

	io->read_pkt.type = GIT_SMART_PACKET_REF;

	/*
	 * Since capabilities contain the remote's object-format, we need to
	 * parse it first so that we know what OID type we're reading. This
	 * requires us to store and reset our position pointer.
	 */
	if (!io->received_capabilities) {
		size_t original_position = smart_io_reader_position(io);

		if ((error = pkt_parse_advance_to_char(io, '\0')) == 0) {
			if (smart_io_reader_consume(io, 1) < 0 ||
				pkt_parse_capabilities(io) < 0)
				return -1;

			end_position = smart_io_reader_position(io);

			if (smart_io_reader_set_position(io, original_position) < 0)
				return -1;
		} else if (error != GIT_ENOTFOUND) {
			return -1;
		}

		io->received_capabilities = 1;
	}

	if (pkt_parse_oid(io) < 0 ||
	    pkt_parse_char(io, ' ', "space") < 0 ||
	    pkt_parse_refname(io) < 0)
		return -1;

	/* Reset to the end of the message if we had capabilities */
	if (end_position &&
	    smart_io_reader_set_position(io, end_position) < 0)
		return -1;

	if (pkt_parse_char(io, '\n', "newline") < 0 ||
	    pkt_ensure_consumed(io) < 0)
		return -1;

	return 0;
}

static int pkt_parse_want(struct smart_io *io)
{
fprintf(debug, "parsing want: '%.*s'\n", (int)io->read_remain_len, io->read_remain_data);
fflush(debug);

	if (pkt_parse_oid(io) < 0)
		return -1;

	if (!io->received_capabilities) {
		fprintf(debug, "read capabilities: '%.*s'\n", (int)io->read_remain_len, io->read_remain_data);
		fflush(debug);

		if (io->read_remain_len > 1) {
			if (pkt_parse_char(io, ' ', NULL) < 0) {
				git_error_set(GIT_ERROR_NET, "expected capabilities in packet");
				return -1;
			}

			if (pkt_parse_capabilities(io) < 0)
				return -1;

			fprintf(debug, "caps are: '%.*s'\n", (int)io->read_pkt.capabilities_len, io->read_pkt.capabilities);
		}

		io->received_capabilities = 1;
	}

	fprintf(debug, "read nl: '%.*s'\n", (int)io->read_remain_len, io->read_remain_data);
	fflush(debug);

	if (pkt_parse_char(io, '\n', "newline") < 0 ||
	    pkt_ensure_consumed(io) < 0)
		return -1;

	return 0;
}

static int pkt_parse_have(struct smart_io *io)
{
	if (pkt_parse_oid(io) < 0 ||
	    pkt_parse_char(io, '\n', "newline") < 0 ||
	    pkt_ensure_consumed(io) < 0)
		return -1;

	return 0;
}

static int pkt_parse_ack(struct smart_io *io)
{
fprintf(debug, "parsing ACK: '%.*s'\n", (int)io->read_remain_len, io->read_remain_data);
fflush(debug);

	if (pkt_parse_oid(io) < 0)
		return -1;

	if (pkt_parse_char(io, ' ', NULL) == 0) {
		if (pkt_parse_string(io, "common", NULL) == 0) {
			io->read_pkt.flags |= GIT_SMART_PACKET_ACK_COMMON;
		} else if (pkt_parse_string(io, "continue", NULL) == 0) {
			io->read_pkt.flags |= GIT_SMART_PACKET_ACK_CONTINUE;
		} else if (pkt_parse_string(io, "ready", NULL) == 0) {
			io->read_pkt.flags |= GIT_SMART_PACKET_ACK_READY;
		} else {
			git_error_set(GIT_ERROR_NET, "unknown ack response");
			return -1;
		}
	}

	if (pkt_parse_char(io, '\n', "newline") < 0 ||
	    pkt_ensure_consumed(io) < 0)
		return -1;

	return 0;
}

static int pkt_parse_sideband(struct smart_io *io)
{
	io->read_pkt.sideband = io->read_remain_data;
	io->read_pkt.sideband_len = io->read_remain_len;

	return smart_io_reader_consume(io, io->read_remain_len);
}

int pkt_read(struct git_smart_packet **out, struct smart_io *io)
{
	int error;

	fprintf(debug, "---------------pkt_read---------------\n");
	fflush(debug);

	/*
	 * We keep a read buffer, and this function returns a packet
	 * pointing to that data. On every `pkt_read`, we clear the
	 * read buffer based on the most-recently-sent packet.
	 */
	if (smart_io_reader_reset(io) < 0)
		return -1;

	fprintf(debug, "inited\n");
	fflush(debug);

	fprintf(debug, "parsing: %d '%.*s'\n", (int)io->read_remain_len, (int)io->read_remain_len, io->read_remain_data);
	fflush(debug);

	/* Fill four bytes for the size of the packet */
	if (smart_io_reader_fill(io, 4) < 0 ||
	    pkt_parse_len(io) < 0)
		return -1;

	fprintf(debug, "total_len is: %d -- io len is: %d\n", (int)io->read_len, (int)io->read_remain_len);
	fflush(debug);

	if (io->read_len == 0) {
		io->read_pkt.type = GIT_SMART_PACKET_FLUSH;
		io->read_pkt.data = io->read_buf.ptr;
		io->read_pkt.len = 4;
		io->received_flush = 1;
		goto done;
	} else if (io->read_len < 4) {
		git_error_set(GIT_ERROR_NET, "invalid packet - invalid length");
		return -1;
	}

	fprintf(debug, "filling %d\n", (int)(io->read_len - 4));
	fflush(debug);

	if (smart_io_reader_fill(io, io->read_len - 4) < 0)
		return -1;

	fprintf(debug, "after fill - total_len is: %d -- io len is: %d\n", (int)io->read_len, (int)io->read_remain_len);
	fflush(debug);

	io->read_pkt.data = io->read_buf.ptr;
	io->read_pkt.len = io->read_len;

	/* TODO: this should probably be more stateful than typed */
	/* maybe separate into read_client and read_server */
	if (io->type == SMART_IO_CLIENT && !io->received_flush) {
		error = pkt_parse_ref(io);
	} else {
		if (pkt_parse_type(io) < 0)
			return -1;

		fprintf(debug, "type is: %d\n", io->read_pkt.type);
		fprintf(debug, "raw data is: %d - '%.*s'\n", (int) io->read_pkt.len, (int) io->read_pkt.len, io->read_pkt.data);
		fflush(debug);

		switch (io->read_pkt.type) {
		case GIT_SMART_PACKET_WANT:
			error = pkt_parse_want(io);
			break;
		case GIT_SMART_PACKET_HAVE:
			error = pkt_parse_have(io);
			break;
		case GIT_SMART_PACKET_ACK:
			error = pkt_parse_ack(io);
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
			error = pkt_parse_sideband(io);
			break;
		default:
			git_error_set(GIT_ERROR_NET, "invalid packet - unknown packet type");
			error = -1;
		}
	}

	if (error < 0)
		return -1;

done:
	*out = &io->read_pkt;
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

static int fmt_capabilities(
	git_str *out,
	unsigned int capabilities,
	const char *agent,
	const char *session_id)
{
	const char *name;
	size_t i, cnt = 0;

	for (i = 0; (name = smart_capabilities[i].name) != NULL; i++) {
		const char *value = NULL;

		if ((capabilities & smart_capabilities[i].capability) == 0)
			continue;

		if (smart_capabilities[i].capability == GIT_SMART_CAPABILITY_AGENT && !(value = agent))
			continue;
		
		if (smart_capabilities[i].capability == GIT_SMART_CAPABILITY_SESSION_ID && !(value = session_id))
			continue;

		if (cnt++)
			git_str_putc(out, ' ');

		git_str_puts(out, name);

		if (value) {
			git_str_putc(out, '=');
			git_str_puts(out, value);
		}
	}

	return git_str_oom(out) ? -1 : 0;
}

int pkt_write(
	struct smart_io *io,
	git_smart_packet_t type,
	...)
{
	va_list ap;
	size_t start_pos, end_pos, len;
	bool has_capabilities;
	char len_str[5];
	int error;

	start_pos = io->write_buf.size;

	has_capabilities = ((type & GIT_SMART_PACKET_HAS_CAPABILITIES) != 0);
	type &= ~GIT_SMART_PACKET_HAS_CAPABILITIES;

	if ((error = git_str_put(&io->write_buf, "0000", 4)) < 0)
		return -1;

	if (type == GIT_SMART_PACKET_FLUSH)
		return 0;

	va_start(ap, type);

	switch (type) {
	case GIT_SMART_PACKET_NONE:
		break;
	case GIT_SMART_PACKET_ACK:
		error = git_str_put(&io->write_buf, "ACK", 3);
		break;
	case GIT_SMART_PACKET_NAK:
		error = git_str_put(&io->write_buf, "NAK", 3);
		break;
	case GIT_SMART_PACKET_WANT:
		{
			const git_oid *id = va_arg(ap, const git_oid *);
			char id_str[GIT_OID_MAX_HEXSIZE];
			size_t hexsize = git_oid_hexsize(git_oid_type(id));

			if ((error = git_oid_fmt(id_str, id)) == 0 &&
			    (error = git_str_put(&io->write_buf, "want ", 5)) == 0)
				error = git_str_put(&io->write_buf, id_str, hexsize);
		}
		break;
	case GIT_SMART_PACKET_HAVE:
		{
			const git_oid *id = va_arg(ap, const git_oid *);
			char id_str[GIT_OID_MAX_HEXSIZE];
			size_t hexsize = git_oid_hexsize(git_oid_type(id));

			if ((error = git_oid_fmt(id_str, id)) == 0 &&
			    (error = git_str_put(&io->write_buf, "have ", 5)) == 0)
				error = git_str_put(&io->write_buf, id_str, hexsize);
		}
		break;
	case GIT_SMART_PACKET_UPDATE:
		{
			const git_oid *old_id = va_arg(ap, const git_oid *);
			const git_oid *new_id = va_arg(ap, const git_oid *);
			const char *ref_name = va_arg(ap, const char *);
			char id_str[GIT_OID_MAX_HEXSIZE];
			size_t hexsize = git_oid_hexsize(git_oid_type(old_id));

			if ((error = git_oid_fmt(id_str, old_id)) == 0 &&
			    (error = git_str_put(&io->write_buf, id_str, hexsize)) == 0 &&
				(error = git_str_putc(&io->write_buf, ' ')) == 0 &&
			    (error = git_oid_fmt(id_str, new_id)) == 0 &&
			    (error = git_str_put(&io->write_buf, id_str, hexsize)) == 0 &&
				(error = git_str_putc(&io->write_buf, ' ')) == 0)
				error = git_str_puts(&io->write_buf, ref_name);
		}
		break;
	case GIT_SMART_PACKET_DONE:
		error = git_str_put(&io->write_buf, "done", 4);
		break;
	case GIT_SMART_PACKET_DEEPEN:
		{
			int depth = va_arg(ap, int);
			GIT_ASSERT(depth >= 0);

			error = git_str_printf(&io->write_buf, "deepen %d", depth);
		}
		break;
	case GIT_SMART_PACKET_ERR:
		{
			const char *fmt = va_arg(ap, const char *);

			if ((error = git_str_put(&io->write_buf, "ERR ", 4)) == 0)
				error = git_str_vprintf(&io->write_buf, fmt, ap);
		}
		break;
	default:
		git_error_set(GIT_ERROR_INVALID, "unknown packet type");
		error = -1;
		break;
	}

/* TODO: if we're sending a packfile, we should send object format */
	if (!error && !io->sent_capabilities) {
		if (has_capabilities) {
			int capabilities = va_arg(ap, int);
			const char *agent = va_arg(ap, const char *);
			const char *session_id = va_arg(ap, const char *);

			if (io->direction == GIT_DIRECTION_PUSH)
				git_str_putc(&io->write_buf, '\0');

			if ((error = git_str_putc(&io->write_buf, ' ')) == 0)
				error = fmt_capabilities(&io->write_buf, capabilities, agent, session_id);

			printf("buf: '%.*s'\n", (int)io->write_buf.size, io->write_buf.ptr);
		}

		io->sent_capabilities = 1;
	}

	va_end(ap);

	if (error < 0)
		return -1;

	if ((error = git_str_putc(&io->write_buf, '\n')) < 0)
		return -1;

	end_pos = io->write_buf.size;

	GIT_ASSERT(end_pos > start_pos);
	len = end_pos - start_pos;
	GIT_ASSERT(len <= 65535);

	if (p_snprintf(len_str, 5, "%04x", (unsigned int)len) < 0)
		return -1;

	/* TODO: flush at a certain size */
	memcpy((io->write_buf.ptr + start_pos), len_str, 4);
	return error;
}

static void debug_printbuf(const char *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		fprintf(debug, "%c", buf[i] == 0 ? '!' : buf[i]);
	}
}

static int pkt_writer_flush(struct smart_io *io)
{
fprintf(debug, "-------------pkt_writer_flush-------------\n");
debug_printbuf(io->write_buf.ptr, io->write_buf.size);

	if (git_stream__write_full(io->stream, io->write_buf.ptr, io->write_buf.size, 0) < 0)
		return -1;

	io->write_buf.size = 0;
	return 0;
}

int git_smart_client_init(
	git_smart_client **out,
	git_repository *repo,
	git_stream *stream,
	git_smart_client_options *opts)
{
	git_smart_client *client;

	GIT_ASSERT_ARG(out && repo);

	/* TODO*/
	debug = fopen("/tmp/clientdebug", "w");
	printf("INIT %p %s\n", debug, strerror(errno));

	client = git__calloc(1, sizeof(git_smart_client));
	GIT_ERROR_CHECK_ALLOC(client);

	client->stream = stream;
	client->capabilities = (opts && opts->direction == GIT_DIRECTION_FETCH) ?
		DEFAULT_CLIENT_FETCH_CAPABILITIES :
		DEFAULT_CLIENT_PUSH_CAPABILITIES;

	if (opts) {
		client->rpc = opts->rpc;
		client->direction = opts->direction;
		client->indexer_progress = opts->indexer_progress;
		client->sideband_progress = opts->sideband_progress;
		client->progress_payload = opts->progress_payload;

		if (opts->agent) {
			client->agent = git__strdup(opts->agent);
			GIT_ERROR_CHECK_ALLOC(client->agent);
		}

		if (opts->session_id) {
			client->session_id = git__strdup(opts->session_id);
			GIT_ERROR_CHECK_ALLOC(client->session_id);
		}
	}

	/* TODO: make a better estimate */
	git_array_init_to_size(client->common_tips, 32);
	GIT_ERROR_CHECK_ALLOC(client->common_tips.ptr);

	if (!client->sideband_progress)
		client->capabilities |= GIT_SMART_CAPABILITY_QUIET;

	if (smart_io_init(&client->server, repo, stream, SMART_IO_CLIENT, client->direction) < 0)
		return -1;

	client->connected = 1;

	*out = client;
	return 0;
}

static int handle_ref(
	git_smart_client *client,
	struct git_smart_packet *packet)
{
	git_remote_head *head;
	const char *symref_target;

	GIT_ASSERT(packet && packet->type == GIT_SMART_PACKET_REF);

	head = git__calloc(1, sizeof(git_remote_head));
	GIT_ERROR_CHECK_ALLOC(head);

	if (git_oid_cpy(&head->oid, &packet->oid) < 0) {
		git__free(head);
		return -1;
	}

	head->name = git__strndup(packet->refname, packet->refname_len);
	GIT_ERROR_CHECK_ALLOC(head->name);

	if ((symref_target = git_strmap_get(client->server.symrefs, head->name)) != NULL) {
		head->symref_target = git__strdup(symref_target);
		GIT_ERROR_CHECK_ALLOC(head->symref_target);
	}

	printf("ref :: %s %s %s\n", git_oid_tostr_s(&head->oid), head->name, head->symref_target);

	return git_vector_insert(&client->heads, head);
}

static int client_set_capabilities(git_smart_client *client)
{
	client->capabilities &= ((client->server.capabilities & NEGOTIATED_CAPABILITIES) | ~NEGOTIATED_CAPABILITIES);
#if 0
	/* Simplify the capability set to our best offering */
	if ((client->capabilities & GIT_SMART_CAPABILITY_MULTI_ACK) &&
	    (client->capabilities & GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED)) {
		client->capabilities &= ~GIT_SMART_CAPABILITY_MULTI_ACK;
	}

	/* Simplify the capability set to our best offering */
	if ((client->capabilities & GIT_SMART_CAPABILITY_REPORT_STATUS) &&
	    (client->capabilities & GIT_SMART_CAPABILITY_REPORT_STATUS_V2)) {
		client->capabilities &= ~GIT_SMART_CAPABILITY_REPORT_STATUS;
	}
#endif
}

int git_smart_client_connect(git_smart_client *client)
{
	struct git_smart_packet *packet;
	git_str caps = GIT_STR_INIT;
	int error = -1;

	GIT_ASSERT(client->connected);
	GIT_ASSERT(!client->received_advertisement);

	fprintf(debug, "fetchpack start\n");

	while (!client->received_advertisement) {
		if (pkt_read(&packet, &client->server) < 0)
			goto done;

		switch (packet->type) {
		case GIT_SMART_PACKET_REF:
			if (handle_ref(client, packet) < 0)
				goto done;

			break;

		case GIT_SMART_PACKET_FLUSH:
			client->received_advertisement = 1;
			break;

		default:
			git_error_set(GIT_ERROR_NET, "unexpected packet type during ref advertisement");
			goto done;
		}
	}

	/* Set the common capabilities between the client and the server */
	client_set_capabilities(client);

	error = 0;

done:
	git_str_dispose(&caps);
	return error;
}

static int client_setup_depth(
	git_smart_client *client,
	const git_fetch_negotiation *wants)
{
	git_array_clear(client->shallow_roots);

	if (wants->depth > 0) {
		if (!(client->server.capabilities & GIT_SMART_CAPABILITY_SHALLOW)) {
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

/*
 * TODO: does filter wants actually look to see if we have an object or not
 or does it only look at our HEADs? force pushing back in time would have us
 fetching a whole history unnecessarily
 */
static int client_negotiate_wants(
	git_smart_client *client,
	const git_fetch_negotiation *wants)
{
	const git_remote_head *head;
	size_t i;

	for (i = 0; i < wants->refs_len; i++) {
		head = wants->refs[i];

		if (head->local)
			continue;

		if (pkt_write(&client->server,
				GIT_SMART_PACKET_WANT | GIT_SMART_PACKET_HAS_CAPABILITIES,
				&head->oid,
				client->capabilities,
				client->agent,
				client->session_id) < 0)
			return -1;
	}

	/* Tell the server about our shallow objects */
	for (i = 0; i < wants->shallow_roots_len; i++) {
		if (pkt_write(&client->server, GIT_SMART_PACKET_SHALLOW, &wants->shallow_roots[i]) < 0)
			return -1;
	}

	return 0;
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

	if (pkt_write(&client->server, GIT_SMART_PACKET_DEEPEN, wants->depth) < 0 ||
	    pkt_writer_flush(&client->server) < 0)
		return -1;

	while (!complete && !error &&
	       !(error = pkt_read(&pkt, &client->server))) {
		switch (pkt->type) {
		case GIT_SMART_PACKET_SHALLOW:
			error = git_oidarray__add(&client->shallow_roots, &pkt->oid);
			break;
		case GIT_SMART_PACKET_UNSHALLOW:
			error = git_oidarray__remove(&client->shallow_roots, &pkt->oid);
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

	return error ? -1 : 0;
}

static int read_acks(git_smart_client *client)
{
	struct git_smart_packet *response_pkt;
	bool reading_acks = true;

	while (reading_acks) {
		if (pkt_read(&response_pkt, &client->server) < 0)
			return -1;

		if ((client->capabilities & GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED)) {
			if (response_pkt->type == GIT_SMART_PACKET_ACK) {
				if ((response_pkt->flags & GIT_SMART_PACKET_ACK_COMMON)) {
					/*
					 * If this is a common commit we can stop walking this line.
					 */
					if (git_revwalk_hide(client->walk, &response_pkt->oid) < 0)
						return -1;

					if (client->rpc &&
					    git_oidarray__add(&client->common_tips, &response_pkt->oid) < 0)
						return -1;
				} else if ((response_pkt->flags & GIT_SMART_PACKET_ACK_READY)) {
					client->negotiation_complete = true;
				} else if (response_pkt->flags) {
					git_error_set(GIT_ERROR_NET, "unexpected ack data during negotiation");
					return -1;
				}
			} else if (response_pkt->type == GIT_SMART_PACKET_NAK) {
				break;
			} else {
				git_error_set(GIT_ERROR_NET, "unexpected packet type during negotiation");
				return -1;
			}
		}

		else if ((client->capabilities & GIT_SMART_CAPABILITY_MULTI_ACK)) {
			if (response_pkt->type == GIT_SMART_PACKET_ACK) {
				printf("ACK %s %d\n", git_oid_tostr_s(&response_pkt->oid), response_pkt->flags);

				if ((response_pkt->flags & GIT_SMART_PACKET_ACK_CONTINUE)) {
					printf("common!\n");

					/*
					 * If this is a common commit we can stop walking this line.
					 */
					if (git_revwalk_hide(client->walk, &response_pkt->oid) < 0)
						return -1;

					if (client->rpc &&
					    git_oidarray__add(&client->common_tips, &response_pkt->oid) < 0)
						return -1;
				} else if (response_pkt->flags) {
					git_error_set(GIT_ERROR_NET, "unexpected ack data during negotiation");
					return -1;
				} else {
					client->negotiation_complete = true;
				}
			} else if (response_pkt->type == GIT_SMART_PACKET_NAK) {
				break;
			} else {
				git_error_set(GIT_ERROR_NET, "unexpected packet type during negotiation");
				return -1;
			}
		}

		else {
			if (response_pkt->type == GIT_SMART_PACKET_ACK) {
				client->negotiation_complete = true;
				break;
			} else if (response_pkt->type != GIT_SMART_PACKET_NAK) {
				git_error_set(GIT_ERROR_NET, "unexpected packet type during negotiation");
				return -1;
			}
		}
	}

	return 0;
}

static int client_negotiate_haves(
	git_smart_client *client,
	git_repository *repo)
{
	git_oid oid;
	size_t i;
	int error = -1;

	/*
	 * TODO: can we skip negotiation of the remote's tips that we have?
	 * If they're fully deep, then we need not add them to the revwalk
	 * at all, we can just "have" them and be done with it.
	 */

	if (!client->walk) {
		git_revwalk__push_options opts = GIT_REVWALK__PUSH_OPTIONS_INIT;

		opts.insert_by_date = 1;

		if (git_revwalk_new(&client->walk, repo) < 0 ||
			git_revwalk_sorting(client->walk, GIT_SORT_TOPOLOGICAL) < 0 ||
			git_revwalk__push_glob(client->walk, "refs/*", &opts) < 0)
			return -1;
	}

	/*
	 * If we've made multiple requests with want negotiation, then
	 * append any previously negotiated common tips to this request.
	 */
	for (i = 0; i < client->common_tips.size; i++) {
		if (pkt_write(&client->server, GIT_SMART_PACKET_HAVE, &client->common_tips.ptr[i]) < 0)
			return -1;
	}

	for (i = 0; i < 256 && !client->negotiation_complete; ) {
		if ((error = git_revwalk_next(&oid, client->walk)) == GIT_ITEROVER)
			break;
		else if (error < 0)
			return -1;

		if (pkt_write(&client->server, GIT_SMART_PACKET_HAVE, &oid) < 0)
			return -1;

printf("HAVE :: %s\n", git_oid_tostr_s(&oid));

		if (++i % 32 == 0) {
			if (client->cancelled) {
				git_error_set(GIT_ERROR_NET, "fetch was cancelled by the user");
				return GIT_EUSER;
			}

			if (pkt_write(&client->server, GIT_SMART_PACKET_FLUSH) < 0 ||
			    pkt_writer_flush(&client->server) < 0 ||
				read_acks(client) < 0)
					return -1;

			if (client->negotiation_complete)
				break;

			if (client->rpc)
				return GIT_RETRY;
		}
	}

	client->negotiation_complete = true;
	return 0;
}

static int client_negotiate_flush(git_smart_client *client)
{
	if (pkt_write(&client->server, GIT_SMART_PACKET_FLUSH) < 0 ||
	    pkt_writer_flush(&client->server) < 0)
		return -1;

	return 0;
}

static int client_negotiate_done(git_smart_client *client)
{
	struct git_smart_packet *response_pkt;

	if (pkt_write(&client->server, GIT_SMART_PACKET_DONE) < 0 ||
	    pkt_writer_flush(&client->server) < 0)
		return -1;

	if (client->capabilities & (GIT_SMART_CAPABILITY_MULTI_ACK_DETAILED |
	                            GIT_SMART_CAPABILITY_MULTI_ACK)) {
		/*
		 * multi_ack mode is simple: we read a single ACK or NAK packet in
		 * response to our "done" packet.
		 */
		if (pkt_read(&response_pkt, &client->server) < 0)
			return -1;

printf("FINAL PACKET IS: %d\n", response_pkt->type);

		if (response_pkt->type != GIT_SMART_PACKET_ACK &&
		    response_pkt->type != GIT_SMART_PACKET_NAK) {
			git_error_set(GIT_ERROR_NET, "unexpected packet type during final negotiation");
			return -1;
		}
	} else {
		size_t position;

		/*
		 * We don't know how many ACKs the server sent to our haves in
		 * non-multi_ack mode. Drain the read buffer until we have a
		 * non-ACK or NAK packet.
		 */
		do {
			position = smart_io_reader_position(&client->server);

			if (pkt_read(&response_pkt, &client->server) < 0)
				return -1;
		} while (response_pkt->type == GIT_SMART_PACKET_ACK ||
		         response_pkt->type == GIT_SMART_PACKET_NAK);

		if (response_pkt->type != GIT_SMART_PACKET_SIDEBAND_DATA &&
		    response_pkt->type != GIT_SMART_PACKET_SIDEBAND_PROGRESS &&
		    response_pkt->type != GIT_SMART_PACKET_SIDEBAND_ERROR) {
			git_error_set(GIT_ERROR_NET, "unexpected packet type waiting for packfile data");
			return -1;
		}

		smart_io_reader_set_position(&client->server, position);
	}

	return 0;
}

/*
 * This function is re-entrant for stateless RPC. Stateless (eg HTTP)
 * callers will invoke this function until it returns `0` or an error.
 * GIT_RETRY is used to indicate that the caller should reconnect and
 * invoke this function again.
 */
int git_smart_client_negotiate(
	git_smart_client *client,
	git_repository *repo,
	const git_fetch_negotiation *wants)
{
	int error;

	GIT_ASSERT(client->connected && !client->negotiation_complete);

	if ((error = client_setup_depth(client, wants)) < 0 ||
	    (error = client_negotiate_wants(client, wants)) < 0 ||
		(error = client_negotiate_depth(client, wants)) < 0 ||
		(error = client_negotiate_flush(client)) < 0 ||
		(error = client_negotiate_haves(client, repo)) < 0 ||
		(error = client_negotiate_done(client)) < 0)
		return error;

	return 0;
}

int git_smart_client_capabilities(
	unsigned int *out,
	git_smart_client *client)
{
	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->received_advertisement);

	*out = client->capabilities;
	return 0;
}

/*
 * TODO: the fetch (but not clone) workflow should validate that the remote oid type
 * is the same as the local oid type, we're not doing any sanity checking here right
 * now
 */
int git_smart_client_oid_type(
	git_oid_t *out,
	git_smart_client *client)
{
	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->received_advertisement);

	*out = client->server.oid_type;
	return 0;
}

int git_smart_client_refs(
	const git_remote_head ***out,
	size_t *size,
	git_smart_client *client)
{
	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->received_advertisement);

	*out = (const git_remote_head **)client->heads.contents;
	*size = client->heads.length;

	return 0;
}

static int download_with_sideband(
	git_smart_client *client,
	struct git_odb_writepack *packwriter,
	git_indexer_progress *progress)
{
	struct git_smart_packet *pkt;
	size_t max_sideband = (client->capabilities & GIT_SMART_CAPABILITY_SIDE_BAND_64K) ? 65520 : 1000;
	bool done = false;
	int error;

	while (!done) {
		/* TODO: timeouts, better/faster cancellation handling */
		if (pkt_read(&pkt, &client->server) < 0)
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
			error = (client->sideband_progress) ?
				client->sideband_progress(pkt->sideband, (int)pkt->sideband_len, client->progress_payload) :
				0;
			break;
		case GIT_SMART_PACKET_SIDEBAND_DATA:
			error = packwriter->append(packwriter, pkt->sideband, pkt->sideband_len, progress);
			break;
		case GIT_SMART_PACKET_SIDEBAND_ERROR:
			git_error_set(GIT_ERROR_NET, "server error during download pack: %.*s", (int)pkt->sideband_len, pkt->sideband);
			return -1;
		case GIT_SMART_PACKET_FLUSH:
			error = packwriter->commit(packwriter, progress);
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
	struct git_odb_writepack *packwriter,
	git_indexer_progress *progress)
{
	ssize_t ret;

	/* Flush the read buffer */
	if (client->server.read_position < client->server.read_buf.size) {
		const char *ptr = client->server.read_buf.ptr + client->server.read_position;
		size_t len = client->server.read_buf.size - client->server.read_position;

		if (packwriter->append(packwriter, ptr, len, progress) < 0)
			return -1;

		git_str_clear(&client->server.read_buf);
	}

	if (git_str_grow(&client->server.read_buf, READ_SIZE) < 0)
		return -1;

	while ((ret = git_stream_read(client->stream, client->server.read_buf.ptr, READ_SIZE)) > 0) {
		if (packwriter->append(packwriter, client->server.read_buf.ptr, ret, progress) < 0)
			return -1;

		git_str_clear(&client->server.read_buf);
	}

	return packwriter->commit(packwriter, progress);
}

int git_smart_client_download_pack(
	git_smart_client *client,
	git_repository *repo,
	git_indexer_progress *progress)
{
	git_odb *odb;
	struct git_odb_writepack *packwriter = NULL;
	int error = -1;

	GIT_ASSERT_ARG(client && repo);
	GIT_ASSERT(client->connected);
	GIT_ASSERT(client->received_advertisement);

	if (git_repository_odb__weakptr(&odb, repo) < 0 ||
	    git_odb_write_pack(&packwriter, odb, client->indexer_progress, client->progress_payload) < 0)
		goto done;

	if ((client->capabilities & (GIT_SMART_CAPABILITY_SIDE_BAND | GIT_SMART_CAPABILITY_SIDE_BAND_64K)))
		error = download_with_sideband(client, packwriter, progress);
	else
		error = download_no_sideband(client, packwriter, progress);

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

	GIT_ASSERT_ARG(out && client);
	GIT_ASSERT(client->received_advertisement);

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

static int client_write_updates(git_smart_client *client, git_push *push)
{
	push_spec *spec;
	size_t i;

	git_vector_foreach(&push->specs, i, spec) {
		if (pkt_write(&client->server,
		              GIT_SMART_PACKET_UPDATE | GIT_SMART_PACKET_HAS_CAPABILITIES,
					  &spec->roid,
					  &spec->loid,
					  spec->refspec.dst,
					  client->capabilities) < 0)
			return -1;
	}

	if (pkt_write(&client->server, GIT_SMART_PACKET_FLUSH) < 0 ||
		pkt_writer_flush(&client->server) < 0)
		return -1;

	return 0;
}

struct write_packfile_payload
{
	git_smart_client *client;
	git_packbuilder *packbuilder;
	size_t bytes_written;
	uint64_t last_update_time;
};

static int write_packfile(void *buf, size_t size, void *data)
{
	struct write_packfile_payload *payload = data;
	git_smart_client *client = payload->client;
	int error = 0;

	if (git_stream__write_full(client->server.stream, buf, size, 0) < 0)
		return -1;

	if (client->push_transfer_progress) {
		uint64_t current_time = git_time_monotonic();
		uint64_t elapsed = current_time - payload->last_update_time;

		payload->bytes_written += size;

		if (elapsed >= MIN_PROGRESS_UPDATE_INTERVAL) {
			payload->last_update_time = current_time;

			error = client->push_transfer_progress(
				payload->packbuilder->nr_written,
				payload->packbuilder->nr_objects,
				payload->bytes_written,
				client->progress_payload);
		}
	}

	return error;
}

static int handle_report(
	git_smart_client *client,
	git_push *push,
	struct git_smart_packet *pkt)
{
	push_status *status;

	GIT_UNUSED(client);

	if (pkt->type == GIT_SMART_PACKET_FLUSH) {
		client->received_report = true;
		return 0;
	}

	if (pkt->type == GIT_SMART_PACKET_UNPACK) {
		push->unpack_ok = (git__strncmp("ok", pkt->message, pkt->message_len) == 0);
		return 0;
	}

	status = git__calloc(1, sizeof(push_status));
	GIT_ERROR_CHECK_ALLOC(status);

	status->ref = git__strndup(pkt->refname, pkt->refname_len);
	GIT_ERROR_CHECK_ALLOC(status->ref);

	if (pkt->type == GIT_SMART_PACKET_NG) {
		status->msg = git__strndup(pkt->message, pkt->message_len);
		GIT_ERROR_CHECK_ALLOC(status->ref);
	}

	if (git_vector_insert(&push->status, status) < 0)
		return -1;

	return 0;
}

static int handle_report_sideband(
	git_smart_client *client,
	git_push *push,
	struct git_smart_packet *pkt)
{
	int len;

	/*
	 * When sending the results, it writes the push report packets
	 * (ok/ng/unpack ok) within a sideband packet. So we need to buffer the
	 * sideband output and reparse it as packets. :/
	 */
	if (git_str_put(client->server.sideband_buf, pkt->sideband, pkt->sideband_len) < 0)
		return -1;

	/* Need at least four bytes for a packet */
	while (client->server.sideband_buf.size >= 4) {
		size_t consumed = 0;

		if ((len = parse_len(client->server.sideband_buf, client->server.sideband_buf.size)) < 0)
			return -1;

		if ((client->server.sideband_buf.size - 4) < len)
			break;

		git_str_consume_bytes(&client->server.sideband_buf, 4);

		if (len == 0) {
			pkt = flush;
		} else {
			pkt.type ...

		}

		if (handle_report(client, push, pkt) < 0)
			return -1;

		git_str_consume_bytes(&client->server.sideband_buf, (size_t)len);
	}

	return 0;
}

static int client_parse_report(git_smart_client *client, git_push *push)
{
	struct git_smart_packet *pkt;

	while (!client->received_report) {
		if (pkt_read(&pkt, &client->server) < 0)
			return -1;

		switch (pkt->type) {
		case GIT_SMART_PACKET_SIDEBAND_DATA:
			/* This is a sideband packet which contains other packets */
			if (handle_report_sideband(client, push, pkt) < 0)
				return -1;

			break;

		case GIT_SMART_PACKET_SIDEBAND_PROGRESS:
			if (client->sideband_progress) {
				if (client->sideband_progress(pkt->sideband, pkt->sideband_len, client->progress_payload) < 0)
					return -1;
			}

			break;

		case GIT_SMART_PACKET_SIDEBAND_ERROR:
			git_error_set(GIT_ERROR_NET,
				"server error during download pack: %.*s",
				(int)pkt->sideband_len, pkt->sideband);
			return -1;

		case GIT_SMART_PACKET_OK:
		case GIT_SMART_PACKET_NG:
		case GIT_SMART_PACKET_UNPACK:
		case GIT_SMART_PACKET_FLUSH:
			if (handle_report(client, push, pkt) < 0)
				return -1;

			break;

		default:
			git_error_set(GIT_ERROR_NET, "unexpected packet during pack download");
			return -1;
		}
	}

	if (client->server.sideband_buf.size > 0) {
		git_error_set(GIT_ERROR_NET, "unexpected sideband push results");
		return -1;
	}

	return 0;
}

static int handle_updates(git_smart_client *client, git_push *push)
{
	/* 
	 * For each push spec we sent to the server, we should have
	 * gotten back a status packet in the push report.
	 */
	if (push->specs.length != push->status.length) {
		git_error_set(GIT_ERROR_NET, "expected status report for each update");
		return -1;
	}

#if 0
	git_pkt_ref *ref;
	push_spec *push_spec;
	push_status *push_status;
	size_t i, j, heads_len;
	int cmp;


	/*
	 * We require that push_specs be sorted with push_spec_rref_cmp,
	 * and that push_report be sorted with push_status_ref_cmp
	 */
	git_vector_sort(&push->specs);
	git_vector_sort(&push->status);

	git_vector_foreach(&push->specs, i, push_spec) {
		push_status = git_vector_get(&push->status, i);

		/*
		 * For each push spec we sent to the server, we should have
		 * gotten back a status packet in the push report which matches
		 */
		if (strcmp(push_spec->refspec.dst, push_status->ref)) {
			git_error_set(GIT_ERROR_NET, "expected matching status report for each update");
			return -1;
		}
	}

/* TODO */
	/* We require that refs be sorted with ref_name_cmp */
	git_vector_sort(&client->heads);
	i = j = 0;
	heads_len = client->heads.length;

	/* Merge join push_specs with refs */
	while (i < push_specs->length && j < refs_len) {
		push_spec = git_vector_get(push_specs, i);
		push_status = git_vector_get(push_report, i);
		ref = git_vector_get(refs, j);

		cmp = strcmp(push_spec->refspec.dst, ref->head.name);

		/* Iterate appropriately */
		if (cmp <= 0) i++;
		if (cmp >= 0) j++;

		/* Add case */
		if (cmp < 0 &&
			!push_status->msg &&
			add_ref_from_push_spec(refs, push_spec) < 0)
			return -1;

		/* Update case, delete case */
		if (cmp == 0 &&
			!push_status->msg)
			git_oid_cpy(&ref->head.oid, &push_spec->loid);
	}

	for (; i < push_specs->length; i++) {
		push_spec = git_vector_get(push_specs, i);
		push_status = git_vector_get(push_report, i);

		/* Add case */
		if (!push_status->msg &&
			add_ref_from_push_spec(refs, push_spec) < 0)
			return -1;
	}

	/* Remove any refs which we updated to have a zero OID. */
	git_vector_rforeach(refs, i, ref) {
		if (git_oid_is_zero(&ref->head.oid)) {
			git_vector_remove(refs, i);
			git_pkt_free((git_pkt *)ref);
		}
	}

	git_vector_sort(refs);

	return 0;
#endif
}

int git_smart_client_push(git_smart_client *client, git_push *push)
{
	struct write_packfile_payload payload = { client, push->pb };
	push_spec *spec;
	size_t i;
	bool need_pack = false;
	int error = -1;

	GIT_ASSERT_ARG(client && push);

#ifdef PUSH_DEBUG
{
	git_remote_head *head;
	char hex[GIT_OID_SHA1_HEXSIZE+1]; hex[GIT_OID_SHA1_HEXSIZE] = '\0';

	git_vector_foreach(&push->remote->refs, i, head) {
		git_oid_fmt(hex, &head->oid);
		fprintf(debug, "PUSH : %s (%s)\n", hex, head->name);
	}

	git_vector_foreach(&push->specs, i, spec) {
		git_oid_fmt(hex, &spec->roid);
		fprintf(debug, "PUSH : %s (%s) -> ", hex, spec->lref);
		git_oid_fmt(hex, &spec->loid);
		fprintf(debug, "PUSH : %s (%s)\n", hex, spec->rref ?
			spec->rref : spec->lref);
	}
}
#endif

	/*
	 * Figure out if we need to send a packfile; which is in all
	 * cases except when we only send delete commands
	 */
	git_vector_foreach(&push->specs, i, spec) {
		if (spec->refspec.src && spec->refspec.src[0] != '\0') {
			need_pack = true;
			break;
		}
	}

	/* TODO */
	/* Prepare pack before sending pack header to avoid timeouts. */
	if (need_pack && git_packbuilder__prepare(push->pb) < 0)
		goto done;

	if (client_write_updates(client, push) < 0)
		goto done;

	if (need_pack &&
		git_packbuilder_foreach(push->pb, &write_packfile, &payload) < 0)
		goto done;

	/*
	 * If we sent nothing or the server doesn't support report-status, then
	 * we consider the pack to have been unpacked successfully.
	 */
	if (push->specs.length == 0 ||
	    (client->capabilities & (GIT_SMART_CAPABILITY_REPORT_STATUS | GIT_SMART_CAPABILITY_REPORT_STATUS_V2)) == 0)
		push->unpack_ok = 1;
	else if (client_parse_report(client, push) < 0)
		goto done;

	/* If progress is being reported write the final report */
	if (client->push_transfer_progress) {
		if (client->push_transfer_progress(
					push->pb->nr_written,
					push->pb->nr_objects,
					payload.bytes_written,
					client->progress_payload) < 0)
			goto done;
	}

	if (push->status.length && handle_updates(client, push) < 0)
		goto done;

	error = 0;

done:
	return error;
}

int git_smart_client_cancel(git_smart_client *client)
{
	GIT_ASSERT_ARG(client);

	client->cancelled = 1;
	return 0;
}

int git_smart_client_close(git_smart_client *client)
{
	int error = 0;

	GIT_ASSERT_ARG(client);

	/*
	 * If we're still connected at this point and not using RPC,
	 * we should say goodbye by sending a flush, or git-daemon
	 * will complain that we disconnected unexpectedly.
	 */
	if (client->connected) {
		if (pkt_write(&client->server, GIT_SMART_PACKET_FLUSH) < 0 ||
		    pkt_writer_flush(&client->server) < 0)
			error = -1;

		client->connected = 0;
	}

	return error;
}

void git_smart_client_free(git_smart_client *client)
{
	git_remote_head *head;
	size_t i;

	if (!client)
		return;

	git_revwalk_free(client->walk);

	smart_io_dispose(&client->server);

	git_vector_foreach(&client->heads, i, head) {
		git__free(head->name);
		git__free(head->symref_target);
		git__free(head);
	}
	git_vector_free(&client->heads);

	git_str_dispose(&client->server.sideband_buf);
	git_str_dispose(&client->server.write_buf);
	git_str_dispose(&client->server.read_buf);
	git__free(client);
}