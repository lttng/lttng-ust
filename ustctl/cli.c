/* Copyright (C) 2011  Ericsson AB, Nils Carlson <nils.carlson@ericsson.com>
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
#include <stdlib.h>
#include <string.h>
#include "cli.h"

/* This dummy command is needed to create the sections in cli.o before
 *  other .o files have these sections, usefull for development.
 */
static int _dummy(int argc, char *argv[]) {
	return 0;
}

/* Define a dummy cmd to guarantee existence of the builtin variables */
struct cli_cmd __cli_cmds __dummy_cli_cmd[] = {
	{
		.name = "_dummy",
		.description = NULL,
		.help_text = NULL,
		.function = _dummy,
		.desired_args = 0,
		.desired_args_op = 0,
	},
};

extern struct cli_cmd __start___cli_cmds[] __attribute__((visibility("hidden")));
extern struct cli_cmd __stop___cli_cmds[] __attribute__((visibility("hidden")));

static struct cli_cmd **cli_cmd_list;
static int cli_cmd_list_size;

static char *process_name;

static int compute_cli_cmds_size(void)
{
	long cli_cmds_start, cli_cmds_end;

	cli_cmds_start = (long)__start___cli_cmds;
	cli_cmds_end = (long)__stop___cli_cmds;

	return (cli_cmds_end - cli_cmds_start) / sizeof(struct cli_cmd);
}

static void __attribute__((constructor)) generate_cli_cmd_list(int argc, char *argv[])
{
	struct cli_cmd *cli_cmd;
	int section_size, i;

	process_name = basename(argv[0]);

	section_size = compute_cli_cmds_size();

	cli_cmd_list = malloc(section_size * sizeof(void *));
	if (!cli_cmd_list) {
		fprintf(stderr, "Failed to allocate command list!");
		exit(EXIT_FAILURE);
	}

	cli_cmd_list_size = 0;

	cli_cmd = __start___cli_cmds;
	for (i = 0; i < section_size; i++) {
		if (&cli_cmd[i] == &__dummy_cli_cmd[0]) {
			continue;
		}

		if (cli_cmd[i].name) {
			cli_cmd_list[cli_cmd_list_size++] = &cli_cmd[i];
		}
	}
}

struct cli_cmd *find_cli_cmd(const char *command)
{
	int i;

	for (i = 0; i < cli_cmd_list_size; i++) {
		if (!strcmp(cli_cmd_list[i]->name, command)) {
			return cli_cmd_list[i];
		}
	}

	return NULL;
}

static int cmpcli_cmds(const void *p1, const void *p2)
{
	return strcmp(* (char * const *) ((struct cli_cmd *)p1)->name,
		      * (char * const *) ((struct cli_cmd *)p2)->name);
}

#define HELP_BUFFER_SIZE 4096

static void print_cmd_help(const char *prefix, const char *infix,
			   struct cli_cmd *cli_cmd)
{
	if (cli_cmd->help_text) {
		fprintf(stderr, "%s%s%s",
			prefix,
			infix,
			cli_cmd->help_text);
	} else if (cli_cmd->description) {
		fprintf(stderr, "%s%s%s\n%s\n",
			prefix,
			infix,
			cli_cmd->name,
			cli_cmd->description);
	} else {
		fprintf(stderr, "No help available for %s\n",
			cli_cmd->name);
	}
}

void list_cli_cmds(int option)
{
	int i;

	qsort(cli_cmd_list, cli_cmd_list_size, sizeof(void *), cmpcli_cmds);

	for (i = 0; i < cli_cmd_list_size; i++) {
		switch (option) {
		case CLI_SIMPLE_LIST:
			fprintf(stderr, "%s ", cli_cmd_list[i]->name);
			break;
		case CLI_DESCRIPTIVE_LIST:
			fprintf(stderr, "   %-25s%s\n", cli_cmd_list[i]->name,
				cli_cmd_list[i]->description);
			break;
		case CLI_EXTENDED_LIST:
			print_cmd_help("", "", cli_cmd_list[i]);
			fprintf(stderr, "\n");
			break;
		}
	}

	if (option == CLI_SIMPLE_LIST) {
		fprintf(stderr, "\n");
	}
}

int cli_print_help(const char *command)
{
	struct cli_cmd *cli_cmd;

	cli_cmd = find_cli_cmd(command);
	if (!cli_cmd) {
		return -1;
	}

	print_cmd_help(process_name, " ", cli_cmd);

	return 0;
}

static void cli_check_argc(const char *command, int args,
			   int operator, int desired_args)
{
	switch(operator) {
	case CLI_EQ:
		if (args != desired_args)
			goto print_error;
		break;
	case CLI_GE:
		if (args < desired_args)
			goto print_error;
		break;
	}

	return;

print_error:
	fprintf(stderr, "%s %s requires %s%d argument%s, see usage.\n",
		process_name, command, operator == CLI_EQ ? "" : "at least ",
		desired_args, desired_args > 1 ? "s" : "");
	cli_print_help(command);
	exit(EXIT_FAILURE);
}


void cli_dispatch_cmd(struct cli_cmd *cmd, int argc, char *argv[])
{
	cli_check_argc(cmd->name, argc - 1, cmd->desired_args_op,
		       cmd->desired_args);

	if (cmd->function(argc, argv)) {
		exit(EXIT_FAILURE);
	}

	exit(EXIT_SUCCESS);
}
