/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include <stdio.h>
#include <git2.h>
#include "cli.h"

int main(int argc, char **argv)
{
	gitcli_opt_parser optparser;
	gitcli_opt opt;

	int show_version = 0;
	const char *command = NULL;
	char **args = NULL;
	int args_len = 0;

	const gitcli_opt_spec global_opt_specs[] = {
		{ GITCLI_OPT_SWITCH, "version",   0, &show_version, 1, NULL,      "display the version" },
		{ GITCLI_OPT_ARG,    "command",   0, &command,      0, "command", "the command to run", GITCLI_OPT_USAGE_REQUIRED },
		{ GITCLI_OPT_ARGS,   "args",      0, &args,         0, "args",    "arguments for the command" },
		{ 0 }
	};

	if (git_libgit2_init() < 0) {
		fprintf(stderr, "error: failed to initialize libgit2\n");
		exit(1);
	}

	gitcli_opt_parser_init(&optparser, global_opt_specs, argv + 1, argc - 1);

	/* Parse the top-level (global) options and command information */
	while (gitcli_opt_parser_next(&opt, &optparser)) {
		if (!opt.spec) {
			gitcli_opt_status_fprint(stderr, &opt);
			gitcli_opt_usage_fprint(stderr, GIT_CLI_NAME, global_opt_specs);
			return 129;
		}

		/*
		 * When we see a command, stop parsing the command line and capture
		 * the remaining arguments as args for the command itself.
		 */
		if (command) {
			args = &argv[optparser.idx + 1];
			args_len = argc - (optparser.idx + 1);
			break;
		}
	}

	if (show_version) {
		printf("%s version %s\n", GIT_CLI_NAME, LIBGIT2_VERSION);
		exit(0);
	}

	git_libgit2_shutdown();
}
