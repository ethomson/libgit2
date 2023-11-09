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

#define COMMAND_NAME "push"

static cli_progress progress = CLI_PROGRESS_INIT;

static char *remote_path;
static char **references = NULL;
static int show_help, quiet, verbose;

static const cli_opt_spec opts[] = {
	CLI_COMMON_OPT,

	{ CLI_OPT_TYPE_SWITCH,    "quiet",       'q', &quiet,       1,
	  CLI_OPT_USAGE_DEFAULT,   NULL,         "don't display progress information" },
	{ CLI_OPT_TYPE_SWITCH,    "verbose",     'v', &verbose,     1,
	  CLI_OPT_USAGE_DEFAULT,   NULL,         "display additional information about the remote" },
	{ CLI_OPT_TYPE_LITERAL },
	{ CLI_OPT_TYPE_ARG,       "repository",   0,  &remote_path, 0,
	  0,                      "repository",  "repository path or remote name" },
	{ CLI_OPT_TYPE_ARGS,      "references",   0,  &references,  0,
	  0,                      "references",  "references to push" },
	{ 0 }
};

static void print_help(void)
{
	cli_opt_usage_fprint(stdout, PROGRAM_NAME, COMMAND_NAME, opts);
	printf("\n");

	printf("Push changes to a remote repository.\n");
	printf("\n");

	printf("Options:\n");

	cli_opt_help_fprint(stdout, opts);
}

int cmd_push(int argc, char **argv)
{
	cli_repository_open_options open_opts = { argv + 1, argc - 1};
	git_repository *repo = NULL;
	git_reference *head = NULL;
	git_push_options push_opts = GIT_PUSH_OPTIONS_INIT;
	cli_opt invalid_opt;
	git_buf upstream = GIT_BUF_INIT;
	git_remote *remote = NULL;
	int error, ret = 0;

	char *refspec = "refs/heads/main";
	const git_strarray refspecs = {
		&refspec,
		1
	};

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
		push_opts.callbacks.sideband_progress = cli_progress_fetch_sideband;
		push_opts.callbacks.transfer_progress = cli_progress_fetch_transfer;
		push_opts.callbacks.payload = &progress;
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

	if (git_remote_push(remote, &refspecs, &push_opts) < 0) {
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
