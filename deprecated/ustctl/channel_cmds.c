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

static int set_subbuf_size(int argc, char *argv[])
{
	int sock, result = 0;
	char *channel = NULL;
	unsigned int size;

	sock = parse_and_connect_pid(argv[1]);

	if (scan_ch_and_num(argv[3], &channel, &size)) {
		fprintf(stderr, "Failed to scan channel and size from"
				" %s\n", argv[3]);
		if (channel)
			free(channel);
		return -1;
	}
	if (ustctl_set_subbuf_size(sock, argv[2], channel, size)) {
		ERR("error while trying to set the size of subbuffers "
		    "for PID %s\n",
		    argv[1]);
		result = -1;
	}

	free(channel);

	return result;
}

static int set_subbuf_num(int argc, char *argv[])
{
	int sock, result = 0;
	char *channel = NULL;
	unsigned int num;

	sock = parse_and_connect_pid(argv[1]);

	if (scan_ch_and_num(argv[3], &channel, &num)) {
		fprintf(stderr, "Failed to scan channel and number from"
				" %s\n", argv[3]);
		if (channel)
			free(channel);
		return -1;
	}
	if (ustctl_set_subbuf_num(sock, argv[2], channel, num)) {
		ERR("error while trying to set the number of subbuffers for PID %s\n",
		    argv[1]);
		result = -1;
	}

	free(channel);

	return result;
}

static int get_subbuf_size(int argc, char *argv[])
{
	int sock;
	unsigned int size;

	sock = parse_and_connect_pid(argv[1]);

	if ((size = ustctl_get_subbuf_size(sock, argv[2], argv[3])) < 0) {
		ERR("error while trying to get the subbuffer size from PID %s\n",
		    argv[1]);
		return -1;
	}

	printf("The subbufer size is %d bytes\n", size);

	return 0;
}

static int get_subbuf_num(int argc, char *argv[])
{
	int sock;
	unsigned int num;

	sock = parse_and_connect_pid(argv[1]);

	if ((num = ustctl_get_subbuf_num(sock, argv[2], argv[3])) < 0) {
		ERR("error while trying to get the subbuffer size from PID %s\n",
		    argv[1]);
		return -1;
	}

	printf("There are %u subbufers in each buffer\n", num);

	return 0;
}

struct cli_cmd __cli_cmds channel_cmds[] = {
	{
		.name = "set-subbuf-size",
		.description = "Set the subbuffer size for a channel",
		.help_text = "set-subbuf-size <pid> <trace> <channel>/<size> \n"
		"Set the subbuffer size for a channel\n",
		.function = set_subbuf_size,
		.desired_args = 3,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "set-subbuf-num",
		.description = "Set the number of subbuffers for a channel",
		.help_text = "set-subbuf-num <pid> <trace> <channel>/<num> \n"
		"Set the number of subbuffers for a channel\n",
		.function = set_subbuf_num,
		.desired_args = 3,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "get-subbuf-size",
		.description = "Get the subbuffer size for a channel",
		.help_text = "get-subbuf-size <pid> <trace> <channel>\n"
		"Get the subbuffer size for a channel\n",
		.function = get_subbuf_size,
		.desired_args = 3,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "get-subbuf-num",
		.description = "Get the number of subbuffers for a channel",
		.help_text = "get-subbuf-num <pid> <trace> <channel>\n"
		"Get the number of subbuffers for a channel\n",
		.function = get_subbuf_num,
		.desired_args = 3,
		.desired_args_op = CLI_EQ,
	},
};
