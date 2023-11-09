/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "smart_new.h"

int git_smart_client_connect(git_smart_client *smart_client)
{


	return 0;
}

/*
int git_smart__store_refs(transport_smart *t, int flushes)
{
	git_vector *refs = &t->refs;
	int error, flush = 0, recvd;
	const char *line_end = NULL;
	git_pkt *pkt = NULL;
	git_pkt_parse_data pkt_parse_data = { 0 };
	size_t i;

	/. Clear existing refs in case git_remote_connect() is called again
	 . after git_remote_disconnect().
	 ./
	git_vector_foreach(refs, i, pkt) {
		git_pkt_free(pkt);
	}
	git_vector_clear(refs);
	pkt = NULL;

	do {
		if (t->buffer.len > 0)
			error = git_pkt_parse_line(&pkt, &line_end,
				t->buffer.data, t->buffer.len,
				&pkt_parse_data);
		else
			error = GIT_EBUFS;

		if (error < 0 && error != GIT_EBUFS)
			return error;

		if (error == GIT_EBUFS) {
			if ((recvd = git_smart__recv(t)) < 0)
				return recvd;

			if (recvd == 0) {
				git_error_set(GIT_ERROR_NET, "early EOF");
				return GIT_EEOF;
			}

			continue;
		}

		git_staticstr_consume(&t->buffer, line_end);

		if (pkt->type == GIT_PKT_ERR) {
			git_error_set(GIT_ERROR_NET, "remote error: %s", ((git_pkt_err *)pkt)->error);
			git__free(pkt);
			return -1;
		}

		if (pkt->type != GIT_PKT_FLUSH && git_vector_insert(refs, pkt) < 0)
			return -1;

		if (pkt->type == GIT_PKT_FLUSH) {
			flush++;
			git_pkt_free(pkt);
		}
	} while (flush < flushes);

	return flush;
}
*/
