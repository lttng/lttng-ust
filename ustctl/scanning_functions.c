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
#include <ust/ustctl.h>
#include "usterr.h"


int parse_and_connect_pid(const char *pid_string)
{
	pid_t pid;
	int sock;

	errno = 0;
	pid = strtoull(pid_string, NULL, 10);
	if (errno) {
		perror("Failed to parse pid");
		exit(EXIT_FAILURE);
	}

	sock = ustctl_connect_pid(pid);
	if (sock < 0) {
		perror("Failed to connect to process");
		exit(EXIT_FAILURE);
	}

	return sock;
}

int scan_ch_marker(const char *channel_marker, char **channel, char **marker)
{
	int result;

	*channel = NULL;
	*marker = NULL;

	result = sscanf(channel_marker, "%a[^/]/%as", channel, marker);
	if (result != 2) {
		if (errno) {
			PERROR("Failed to read channel and marker names");
		} else {
			ERR("Failed to parse marker and channel names");
		}
		if (*channel) {
			free(*channel);
		}
		if (*marker) {
			free(*marker);
		}
		return -1;
	}

	return 0;
}

int scan_ch_and_num(const char *ch_num, char **channel, unsigned int *num)
{
	int result;

	*channel = NULL;

	result = sscanf(ch_num, "%a[^/]/%u", channel, num);
	if (result != 2) {
		if (errno) {
			PERROR("Failed to parse channel and number");
		} else {
			ERR("Failed to parse channel and number");
		}
		if (*channel) {
			free(*channel);
		}
		return -1;
	}

	return 0;
}
