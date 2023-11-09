/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>
#include <git2.h>
#include "cli.h"
#include "cmd.h"

#include "git2/smart.h"

#define COMMAND_NAME "upload-pack"

int show_help;
const char *directory;

static const cli_opt_spec opts[] = {
	{ CLI_OPT_TYPE_SWITCH,    "help",         0,  &show_help,   1,
	  CLI_OPT_USAGE_HIDDEN | CLI_OPT_USAGE_STOP_PARSING, NULL,
	  "display help about the " COMMAND_NAME " command" },

	{ CLI_OPT_TYPE_ARG,       "directory",    0,  &directory,  0,
	  CLI_OPT_USAGE_DEFAULT,  "directory",    "directory to serve" },
	{ 0 }
};

static void print_help(void)
{
	cli_opt_usage_fprint(stdout, PROGRAM_NAME, COMMAND_NAME, opts);
	printf("\n");

	printf("Serve a fetch to a git client.\n");
	printf("\n");

	printf("Options:\n");

	cli_opt_help_fprint(stdout, opts);
}

int cmd_upload_pack(int argc, char **argv)
{
	git_repository *repo = NULL;
	git_smart_server *server = NULL;
	cli_opt invalid_opt;
	int ret = 0;

	if (cli_opt_parse(&invalid_opt, opts, argv + 1, argc - 1, CLI_OPT_PARSE_GNU))
		return cli_opt_usage_error(COMMAND_NAME, opts, &invalid_opt);

	if (show_help) {
		print_help();
		return 0;
	}

	if (!directory) {
		ret = cli_error_usage("you must specify a path to serve");
		goto done;
	}

	if (git_repository_open_ext(&repo, directory,
			GIT_REPOSITORY_OPEN_NO_SEARCH, NULL) < 0)
		return cli_error_git();

	if (git_smart_server_init(&server, repo) < 0)
		return cli_error_git();

	if (git_smart_server_uploadpack(server) < 0)
		return cli_error_git();

done:
	git_smart_server_free(server);
	git_repository_free(repo);
	return ret;
}
