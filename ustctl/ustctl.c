/* Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011  Ericsson AB, Nils Carlson <nils.carlson@ericsson.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <fcntl.h>

#include "ust/ustctl.h"
#include "usterr.h"
#include "cli.h"
#include "scanning_functions.h"

void usage(const char *process_name)
{
	fprintf(stderr, "Usage: %s COMMAND [ARGS]...\n", process_name);
	fprintf(stderr,
		"Control tracing within a process that supports UST,\n"
		" the Userspace Tracing libary\n"
		"Options:\n"
		"  -h[<cmd>], --help[=<cmd>]        "
		"help, for a command if provided\n"
		"  -l, --list                       "
		"short list of commands\n"
		"  -e, --extended-list              "
	       "extented list of commands with help\n"
		"Commands:\n");
	list_cli_cmds(CLI_DESCRIPTIVE_LIST);
}

struct option options[] =
{
	{"help", 2, NULL, 'h'},
	{"list", 0, NULL, 'l'},
	{"extended-list", 0, NULL, 'e'},
	{NULL, 0, NULL, 0},
};

int main(int argc, char *argv[])
{
	struct cli_cmd *cli_cmd;
	int opt;

	if(argc <= 1) {
		fprintf(stderr, "No operation specified.\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	while ((opt = getopt_long(argc, argv, "+h::le",
				  options, NULL)) != -1) {
		switch (opt) {
		case 'h':
			if (!optarg) {
				usage(argv[0]);
			} else {
				if (cli_print_help(optarg)) {
					fprintf(stderr, "No such command %s\n",
						optarg);
				}
			}
			exit(EXIT_FAILURE);
			break;
		case 'l':
			list_cli_cmds(CLI_SIMPLE_LIST);
			exit(EXIT_FAILURE);
			break;
		case 'e':
			list_cli_cmds(CLI_EXTENDED_LIST);
			exit(EXIT_FAILURE);
		default:
			fprintf(stderr, "Unknown option\n");
			break;
		}
	}

	cli_cmd = find_cli_cmd(argv[optind]);
	if (!cli_cmd) {
		fprintf(stderr, "No such command %s\n",
			argv[optind]);
		exit(EXIT_FAILURE);
	}

	cli_dispatch_cmd(cli_cmd, argc - optind, &argv[optind]);

	return 0;
}

static int list_trace_events(int argc, char *argv[])
{
	struct trace_event_status *tes = NULL;
	int i;
	pid_t pid;

	pid = parse_pid(argv[1]);

	if (ustctl_get_tes(&tes, pid)) {
		ERR("error while trying to list "
		    "trace_events for PID %u\n",
		    pid);
		return -1;
	}
	i = 0;
	for (i = 0; tes[i].name; i++) {
		printf("{PID: %u, trace_event: %s}\n",
		       pid,
		       tes[i].name);
	}
	ustctl_free_tes(tes);

	return 0;
}

static int set_sock_path(int argc, char *argv[])
{
	pid_t pid;

	pid = parse_pid(argv[1]);

	if (ustctl_set_sock_path(argv[2], pid)) {
		ERR("error while trying to set sock path for PID %u\n", pid);
		return -1;
	}

	return 0;
}

static int get_sock_path(int argc, char *argv[])
{
	pid_t pid;
	char *sock_path;

	pid = parse_pid(argv[1]);

	if (ustctl_get_sock_path(&sock_path, pid)) {
		ERR("error while trying to get sock path for PID %u\n", pid);
		return -1;
	}
	printf("The socket path is %s\n", sock_path);
	free(sock_path);

	return 0;
}

struct cli_cmd __cli_cmds general_cmds[] = {
	{
		.name = "list-trace-events",
		.description = "List trace-events for a given pid",
		.help_text = "list-trace-events <pid>\n"
		"List the trace-events in a process\n",
		.function = list_trace_events,
		.desired_args = 1,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "set-sock-path",
		.description = "Set the path to the consumer daemon socket",
		.help_text = "set-sock-path <pid> <sock-path>\n"
		"Set the path to the consumer daemon socket\n",
		.function = set_sock_path,
		.desired_args = 2,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "get-sock-path",
		.description = "Get the path to the consumer daemon socket",
		.help_text = "get-sock-path <pid>\n"
		"Get the path to the consumer daemon socket\n",
		.function = get_sock_path,
		.desired_args = 1,
		.desired_args_op = CLI_EQ,
	},
};
