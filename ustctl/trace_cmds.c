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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <ust/ustctl.h>
#include "scanning_functions.h"
#include "usterr.h"
#include "cli.h"


static int create_trace(int argc, char *argv[])
{
	int sock;

	sock = parse_and_connect_pid(argv[1]);

	if (ustctl_create_trace(sock, argv[2])) {
		ERR("Failed to create trace %s for PID %s\n", argv[2], argv[1]);
		return -1;
	}

	return 0;
}

static int alloc_trace(int argc, char *argv[])
{
	int sock;

	sock = parse_and_connect_pid(argv[1]);

	if (ustctl_alloc_trace(sock, argv[2])) {
		ERR("Failed to allocate trace %s for PID %s\n", argv[2], argv[1]);
		return -1;
	}
	return 0;
}

static int start_trace(int argc, char *argv[])
{
	int sock;

	sock = parse_and_connect_pid(argv[1]);

	if (ustctl_start_trace(sock, argv[2])) {
		ERR("Failed to start trace %s for PID %s\n", argv[2], argv[1]);
		return -1;
	}
	return 0;
}

static int stop_trace(int argc, char *argv[])
{
	int sock;

	sock = parse_and_connect_pid(argv[1]);

	if (ustctl_stop_trace(sock, argv[2])) {
		ERR("Failed to stop trace %s for PID %s\n", argv[2], argv[1]);
		return -1;
	}
	return 0;
}

static int destroy_trace(int argc, char *argv[])
{
	int sock;

	sock = parse_and_connect_pid(argv[1]);

	if (ustctl_destroy_trace(sock, argv[2])) {
		ERR("Failed to destroy trace %s for PID %s\n", argv[2], argv[1]);
		return -1;
	}
	return 0;
}

static int force_subbuf_switch(int argc, char *argv[])
{
	int sock;

	sock = parse_and_connect_pid(argv[1]);

	if (ustctl_force_switch(sock, argv[2])) {
		ERR("error while trying to force switch for PID %s\n", argv[1]);
		return -1;
	}

	return 0;
}

struct cli_cmd __cli_cmds trace_cmds[] = {
	{
		.name = "create-trace",
		.description = "Create a trace for a process",
		.help_text = "create-trace <pid> <trace>\n"
		"Create a trace for a process\n",
		.function = create_trace,
		.desired_args = 2,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "alloc-trace",
		.description = "Allocate a trace for a process",
		.help_text = "alloc-trace <pid> <trace>\n"
		"Allocate a trace for a process\n",
		.function = alloc_trace,
		.desired_args = 2,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "start-trace",
		.description = "Start a trace for a process",
		.help_text = "start-trace <pid> <trace>\n"
		"Start a trace for a process\n",
		.function = start_trace,
		.desired_args = 2,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "stop-trace",
		.description = "Stop a trace for a process",
		.help_text = "stop-trace <pid> <trace>\n"
		"Stop a trace for a process\n",
		.function = stop_trace,
		.desired_args = 2,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "destroy-trace",
		.description = "Destroy a trace for a process",
		.help_text = "destroy-trace <pid> <trace>\n"
		"Destroy a trace for a process\n",
		.function = destroy_trace,
		.desired_args = 2,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "force-subbuf-switch",
		.description = "Force a subbuffer switch",
		.help_text = "force-subbuf-switch <pid> <trace>\n"
		"Force a subbuffer switch for a trace, currently this forces\n"
		"a subbuffer switch for all traces in a process\n",
		.function = force_subbuf_switch,
		.desired_args = 2,
		.desired_args_op = CLI_EQ,
	},
};
