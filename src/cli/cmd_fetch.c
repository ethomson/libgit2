/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>
#include <git2.h>
#include "common.h"
#include "cmd.h"
#include "error.h"
#include "sighandler.h"
#include "progress.h"

#include "fs_path.h"
#include "futils.h"

#define COMMAND_NAME "fetch"

static char *remote_path, *upload_pack_cmd;
static int show_help, quiet, verbose;
static cli_progress progress = CLI_PROGRESS_INIT;

static const cli_opt_spec opts[] = {
	CLI_COMMON_OPT,

	{ CLI_OPT_TYPE_SWITCH,    "quiet",       'q', &quiet,       1,
	  CLI_OPT_USAGE_DEFAULT,   NULL,         "don't display progress information" },
	{ CLI_OPT_TYPE_SWITCH,    "verbose",     'v', &verbose,     1,
	  CLI_OPT_USAGE_DEFAULT,   NULL,         "display additional information about the remote" },
    { CLI_OPT_TYPE_VALUE,     "upload-pack", 'u', &upload_pack_cmd, 0,
      CLI_OPT_USAGE_DEFAULT,  "upload-pack", "upload pack command to execute" },
	{ CLI_OPT_TYPE_LITERAL },
	{ CLI_OPT_TYPE_ARG,       "repository",   0,  &remote_path, 0,
	  0,                      "repository",  "repository path or remote name" },
	{ 0 }
};

static void print_help(void)
{
	cli_opt_usage_fprint(stdout, PROGRAM_NAME, COMMAND_NAME, opts);
	printf("\n");

	printf("Fetch changes from a remote into the current repository.\n");
	printf("\n");

	printf("Options:\n");

	cli_opt_help_fprint(stdout, opts);
}

static int update_tips(
	const char *refname,
	const git_oid *src,
	const git_oid *tgt,
	void *data)
{
	if (git_oid_is_zero(src)) {
		printf(" * [new branch]      %-10s -> %-10s\n", refname, refname);
	} else if (git_oid_equal(src, tgt)) {
		if (verbose)
			printf(" = [up to date]      %-10s -> %-10s\n", refname, refname);
	} else if (git_oid_is_zero(tgt)) {
		printf(" - [deleted]         %-10s -> %-10s", "(none)", refname);
	} else {
		char src_str[GIT_OID_MAX_HEXSIZE];
		char tgt_str[GIT_OID_MAX_HEXSIZE];
		size_t id_abbrev = 7;

		if (git_oid_fmt(src_str, src) < 0 ||
		    git_oid_fmt(tgt_str, tgt) < 0)
			return -1;

		printf("   %.*s..%.*s  %-10s -> %-10s\n",
			(int)id_abbrev, src_str, (int)id_abbrev, tgt_str,
			refname, refname);
	}

	return 0;
}

int cmd_fetch(int argc, char **argv)
{
	cli_repository_open_options open_opts = { argv + 1, argc - 1};
	git_repository *repo = NULL;
	git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
	cli_opt invalid_opt;
	git_buf upstream = GIT_BUF_INIT;
	git_reference *head = NULL;
	git_remote *remote = NULL;
	int error, ret = 0;

	if (cli_opt_parse(&invalid_opt, opts, argv + 1, argc - 1, CLI_OPT_PARSE_GNU))
		return cli_opt_usage_error(COMMAND_NAME, opts, &invalid_opt);

	if (show_help) {
		print_help();
		return 0;
	}

	if (cli_repository_open(&repo, &open_opts) < 0 ||
	    git_repository_head(&head, repo) < 0) {
		ret = cli_error_git();
		goto done;
	}

	if (!quiet) {
		fetch_opts.callbacks.sideband_progress = cli_progress_fetch_sideband;
		fetch_opts.callbacks.transfer_progress = cli_progress_fetch_transfer;
		fetch_opts.callbacks.update_tips = &update_tips;
		fetch_opts.callbacks.payload = &progress;
	}

	if (verbose) {
		fetch_opts.update_flags |= GIT_REMOTE_UPDATE_REPORT_UNCHANGED;
	}

	if (remote_path) {
		error = git_remote_lookup(&remote, repo, remote_path);

		if (error == GIT_ENOTFOUND || error == GIT_EINVALIDSPEC)
			error = git_remote_create_anonymous(&remote, repo, remote_path);
	} else {
		error = git_branch_upstream_remote(&upstream, repo, git_reference_name(head));

		if (error == 0) {
			error = git_remote_lookup(&remote, repo, upstream.ptr);
		} else if (error == GIT_ENOTFOUND) {
			error = git_remote_lookup(&remote, repo, "origin");

			if (error == GIT_ENOTFOUND) {
				ret = 0;
				goto done;
			}
		}
	}

	if (error < 0) {
		ret = cli_error_git();
		goto done;
	}

    /* TODO: need a cancellation handler to interrupt fetch cleanly */
	if (git_remote_fetch(remote, NULL, &fetch_opts, "fetch") < 0) {
		ret = cli_error_git();
		goto done;
	}

	cli_progress_finish(&progress);

done:
	cli_progress_dispose(&progress);
	git_buf_dispose(&upstream);
	git_remote_free(remote);
	git_reference_free(head);
	git_repository_free(repo);
	return ret;
}