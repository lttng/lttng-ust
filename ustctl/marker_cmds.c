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
#include <ust/ustcmd.h>
#include "scanning_functions.h"
#include "usterr.h"
#include "cli.h"

static int list_markers(int argc, char *argv[])
{
	struct marker_status *cmsf = NULL;
	int i;
	pid_t pid;

	pid = parse_pid(argv[1]);

	if (ustcmd_get_cmsf(&cmsf, pid)) {
		ERR("error while trying to list markers for PID %u\n", pid);
		return -1;
	}
	for (i = 0; cmsf[i].channel; i++) {
		printf("{PID: %u, channel/marker: %s/%s, "
		       "state: %u, fmt: %s}\n",
		       (unsigned int) pid,
		       cmsf[i].channel,
		       cmsf[i].marker,
		       cmsf[i].state,
		       cmsf[i].fs);
	}
	ustcmd_free_cmsf(cmsf);
	return 0;
}

static int enable_marker(int argc, char *argv[])
{
	int i, result = 0;
	pid_t pid;
	char *channel, *marker;

	pid = parse_pid(argv[1]);

	for (i = 3; i < argc; i++) {
		channel = NULL;
		marker = NULL;
		if (scan_ch_marker(argv[i],
				   &channel, &marker)) {
			result = -1;
			fprintf(stderr, "Failed to scan channel and marker from"
				" %s\n", argv[i]);
			if (channel)
				free(channel);
			if (marker)
				free(marker);
		}
		if (ustcmd_set_marker_state(argv[2], channel, marker, 1, pid)) {
			PERROR("error while trying to enable marker %s with PID %u",
			       argv[i], pid);
			result = -1;
		}
		free(channel);
		free(marker);
	}

	return result;
}

static int disable_marker(int argc, char *argv[])
{
	int i, result = 0;
	pid_t pid;
	char *channel, *marker;

	pid = parse_pid(argv[1]);

	for (i = 3; i < argc; i++) {
		channel = NULL;
		marker = NULL;
		if (scan_ch_marker(argv[i],
				   &channel, &marker)) {
			fprintf(stderr, "Failed to scan channel and marker from"
				" %s\n", argv[i]);
			if (channel)
				free(channel);
			if (marker)
				free(marker);
			return -1;
		}
		if (ustcmd_set_marker_state(argv[2], channel, marker, 0, pid)) {
			PERROR("error while trying to disable marker %s with PID %u",
			       argv[i], pid);
			result = -1;
		}
		free(channel);
		free(marker);
	}

	return result;
}

struct cli_cmd __cli_cmds marker_cmds[] = {
	{
		.name = "list-markers",
		.description = "List markers for a given pid",
		.help_text = "list-markers <pid>\n"
		"List the markers in a process\n",
		.function = list_markers,
		.desired_args = 1,
		.desired_args_op = CLI_EQ,
	},
	{
		.name = "enable-marker",
		.description = "Enable markers for a given pid",
		.help_text = "enable-marker <pid> <trace> <channel>/<marker>... \n"
		"Enable the listed markers for the trace in process pid\n",
		.function = enable_marker,
		.desired_args = 3,
		.desired_args_op = CLI_GE,
	},
	{
	       .name = "disable-marker",
	       .description = "Disable markers for a given pid",
	       .help_text = "disable-marker <pid> <trace> <channel>/<marker>... \n"
	       "Disable the listed markers for the trace in process pid\n",
	       .function = disable_marker,
	       .desired_args = 3,
	       .desired_args_op = CLI_GE,
	}
};
