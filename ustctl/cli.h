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
#ifndef _CLI_H
#define _CLI_H

struct cli_cmd {
	const char *name;
	const char *description;
	const char *help_text;
	int (*function)(int, char **);
	int desired_args;
	int desired_args_op;
} __attribute__((aligned(8)));

#define __cli_cmds __attribute__((section("__cli_cmds"), aligned(8), used))

struct cli_cmd *find_cli_cmd(const char *command);

enum cli_list_opts {
	CLI_SIMPLE_LIST,
	CLI_DESCRIPTIVE_LIST,
	CLI_EXTENDED_LIST,
};

void list_cli_cmds(int option);

int cli_print_help(const char *command);

enum cli_arg_ops {
	CLI_EQ,
	CLI_GE,
};

void cli_dispatch_cmd(struct cli_cmd *cmd, int argc, char *argv[]);

#endif /* _CLI_H */
