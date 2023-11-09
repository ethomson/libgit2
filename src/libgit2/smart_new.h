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
#include "git2/smart.h"

typedef enum {
	GIT_SMART_PACKET_NONE,
	GIT_SMART_PACKET_FLUSH,
	GIT_SMART_PACKET_ACK,
	GIT_SMART_PACKET_NAK,
	GIT_SMART_PACKET_ERR,
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

	/* For wants, haves, etc, the object ID in question */
	git_oid oid;

	/* The first want packet includes capabilities */
	const char *capabilities;
	size_t capabilities_len;
};

struct pkt_parser {
	git_oid_t oid_type;

	int read_capabilities : 1;

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
	 * how many bytes of that we've consumed.
	 */
	size_t total_len;
	size_t consumed;

	/* The remaining data to parse of the message and its length. */
	const char *remain_data;
	size_t remain_len;
};

struct git_smart_server {
	git_repository *repo;
	git_oid_t oid_type;

	struct pkt_parser pkt_reader;

	git_str write_buf;

	git_vector advertised_refs;
	git_vector resolved_refs;
	git_vector advertised_ids;

	const char *session_id;

	/* Configurable server information */

	/* The server's capabilities */
	unsigned int capabilities;

	/* State */
	git_oid last_common_have;

	/* Client information */
	const char *client_agent;
	const char *client_session_id;
	unsigned int client_capabilities;

	/* Server state */
	int sent_capabilities : 1,
	    sent_error : 1,
	    sent_ack : 1,
	    ready : 1;
};

#endif
