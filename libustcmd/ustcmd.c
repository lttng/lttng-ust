/* Copyright (C) 2009  Pierre-Marc Fournier, Philippe Proulx-Barrette
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
#include <string.h>
#include <dirent.h>

#include "ustcomm.h"
#include "ustcmd.h"

pid_t *ustcmd_get_online_pids(void)
{
	struct dirent *dirent;
	DIR *dir;
	unsigned int ret_size = 1 * sizeof(pid_t), i = 0;

	dir = opendir(SOCK_DIR);
	if (!dir) {
		return NULL;
	}

	pid_t *ret = (pid_t *) malloc(ret_size);

	while ((dirent = readdir(dir))) {
		if (!strcmp(dirent->d_name, ".") ||
			!strcmp(dirent->d_name, "..")) {

			continue;
		}

		if (dirent->d_type != DT_DIR &&
			!!strcmp(dirent->d_name, "ustd")) {

			sscanf(dirent->d_name, "%u", (unsigned int *) &ret[i]);
			if (pid_is_online(ret[i])) {
				ret_size += sizeof(pid_t);
				ret = (pid_t *) realloc(ret, ret_size);
				++i;
			}
		}
	}

	ret[i] = 0; /* Array end */

	if (ret[0] == 0) {
		 /* No PID at all */
		free(ret);
		return NULL;
	}

	closedir(dir);
	return ret;
}

/**
 * Sets marker state (USTCMD_MS_ON or USTCMD_MS_OFF).
 *
 * @param mn	Marker name
 * @param state	Marker's new state
 * @param pid	Traced process ID
 * @return	0 if successful, or errors {USTCMD_ERR_GEN, USTCMD_ERR_ARG}
 */
int ustcmd_set_marker_state(const char *mn, int state, pid_t pid)
{
	char *cmd_str [] = {"disable_marker", "enable_marker"};
	char *cmd;
	int result;

	if (mn == NULL) {
		return USTCMD_ERR_ARG;
	}

	asprintf(&cmd, "%s %s", cmd_str[state], mn);

	result = ustcmd_send_cmd(cmd, pid, NULL);
	if (result) {
		free(cmd);
		return USTCMD_ERR_GEN;
	}

	free(cmd);
	return 0;
}

/**
 * Set subbuffer size.
 *
 * @param channel_size	Channel name and size
 * @param pid		Traced process ID
 * @return		0 if successful, or error
 */
int ustcmd_set_subbuf_size(const char *channel_size, pid_t pid)
{
	char *cmd;
	int result;

	asprintf(&cmd, "%s %s", "set_subbuf_size", channel_size);

	result = ustcmd_send_cmd(cmd, pid, NULL);
	if (result) {
		free(cmd);
		return 1;
	}

	free(cmd);
	return 0;
}

/**
 * Set subbuffer num.
 *
 * @param channel_num	Channel name and num
 * @param pid		Traced process ID
 * @return		0 if successful, or error
 */
int ustcmd_set_subbuf_num(const char *channel_size, pid_t pid)
{
	char *cmd;
	int result;

	asprintf(&cmd, "%s %s", "set_subbuf_num", channel_size);

	result = ustcmd_send_cmd(cmd, pid, NULL);
	if (result) {
		free(cmd);
		return 1;
	}

	free(cmd);
	return 0;
}


/**
 * Destroys an UST trace according to a PID.
 *
 * @param pid	Traced process ID
 * @return	0 if successful, or error USTCMD_ERR_GEN
 */
int ustcmd_destroy_trace(pid_t pid)
{
	int result;

	result = ustcmd_send_cmd("trace_destroy", pid, NULL);
	if (result) {
		return USTCMD_ERR_GEN;
	}

	return 0;
}

/**
 * Starts an UST trace (and setups it) according to a PID.
 *
 * @param pid	Traced process ID
 * @return	0 if successful, or error USTCMD_ERR_GEN
 */
int ustcmd_setup_and_start(pid_t pid)
{
	int result;

	result = ustcmd_send_cmd("start", pid, NULL);
	if (result) {
		return USTCMD_ERR_GEN;
	}

	return 0;
}

/**
 * Creates an UST trace according to a PID.
 *
 * @param pid	Traced process ID
 * @return	0 if successful, or error USTCMD_ERR_GEN
 */
int ustcmd_create_trace(pid_t pid)
{
	int result;

	result = ustcmd_send_cmd("trace_create", pid, NULL);
	if (result) {
		return USTCMD_ERR_GEN;
	}

	return 0;
}

/**
 * Starts an UST trace according to a PID.
 *
 * @param pid	Traced process ID
 * @return	0 if successful, or error USTCMD_ERR_GEN
 */
int ustcmd_start_trace(pid_t pid)
{
	int result;

	result = ustcmd_send_cmd("trace_start", pid, NULL);
	if (result) {
		return USTCMD_ERR_GEN;
	}

	return 0;
}

/**
 * Alloc an UST trace according to a PID.
 *
 * @param pid	Traced process ID
 * @return	0 if successful, or error USTCMD_ERR_GEN
 */
int ustcmd_alloc_trace(pid_t pid)
{
	int result;

	result = ustcmd_send_cmd("trace_alloc", pid, NULL);
	if (result) {
		return USTCMD_ERR_GEN;
	}

	return 0;
}

/**
 * Stops an UST trace according to a PID.
 *
 * @param pid	Traced process ID
 * @return	0 if successful, or error USTCMD_ERR_GEN
 */
int ustcmd_stop_trace(pid_t pid)
{
	int result;

	result = ustcmd_send_cmd("trace_stop", pid, NULL);
	if (result) {
		return USTCMD_ERR_GEN;
	}

	return 0;
}

/**
 * Counts newlines ('\n') in a string.
 *
 * @param str	String to search in
 * @return	Total newlines count
 */
unsigned int ustcmd_count_nl(const char *str)
{
	unsigned int i = 0, tot = 0;

	while (str[i] != '\0') {
		if (str[i] == '\n') {
			++tot;
		}
		++i;
	}

	return tot;
}

/**
 * Frees a CMSF array.
 *
 * @param cmsf	CMSF array to free
 * @return	0 if successful, or error USTCMD_ERR_ARG
 */
int ustcmd_free_cmsf(struct marker_status *cmsf)
{
	if (cmsf == NULL) {
		return USTCMD_ERR_ARG;
	}

	unsigned int i = 0;
	while (cmsf[i].channel != NULL) {
		free(cmsf[i].channel);
		free(cmsf[i].marker);
		free(cmsf[i].fs);
		++i;
	}
	free(cmsf);

	return 0;
}

/**
 * Gets channel/marker/state/format string for a given PID.
 *
 * @param cmsf	Pointer to CMSF array to be filled (callee allocates, caller
 *		frees with `ustcmd_free_cmsf')
 * @param pid	Targeted PID
 * @return	0 if successful, or errors {USTCMD_ERR_ARG, USTCMD_ERR_GEN}
 */
int ustcmd_get_cmsf(struct marker_status **cmsf, const pid_t pid)
{
	char *big_str = NULL;
	int result;
	struct marker_status *tmp_cmsf = NULL;
	unsigned int i = 0, cmsf_ind = 0;

	if (cmsf == NULL) {
		return USTCMD_ERR_ARG;
	}
	result = ustcmd_send_cmd("list_markers", pid, &big_str);
	if (result) {
		return USTCMD_ERR_GEN;
	}

	if (big_str == NULL) {
		fprintf(stderr, "ustcmd: error while getting markers list\n");
		return USTCMD_ERR_GEN;
	}

	tmp_cmsf = (struct marker_status *) malloc(sizeof(struct marker_status) *
		(ustcmd_count_nl(big_str) + 1));
	if (tmp_cmsf == NULL) {
		return USTCMD_ERR_GEN;
	}

	/* Parse received reply string (format: "[chan]/[mark] [st] [fs]"): */
	while (big_str[i] != '\0') {
		char state;

		sscanf(big_str + i, "marker: %a[^/]/%a[^ ] %c %a[^\n]",
			&tmp_cmsf[cmsf_ind].channel,
			&tmp_cmsf[cmsf_ind].marker,
			&state,
			&tmp_cmsf[cmsf_ind].fs);
		tmp_cmsf[cmsf_ind].state = (state == USTCMD_MS_CHR_ON ?
			USTCMD_MS_ON : USTCMD_MS_OFF); /* Marker state */

		while (big_str[i] != '\n') {
			++i; /* Go to next '\n' */
		}
		++i; /* Skip current pointed '\n' */
		++cmsf_ind;
	}
	tmp_cmsf[cmsf_ind].channel = NULL;
	tmp_cmsf[cmsf_ind].marker = NULL;
	tmp_cmsf[cmsf_ind].fs = NULL;

	*cmsf = tmp_cmsf;

	free(big_str);
	return 0;
}

/**
 * Shoots a given command using ustcomm.
 *
 * @param cmd	Null-terminated command to shoot
 * @param pid	Targeted PID
 * @param reply	Pointer to string to be filled with a reply string (must
 *		be NULL if no reply is needed for the given command).
 * @return	0 if successful, or errors {USTCMD_ERR_ARG, USTCMD_ERR_CONN}
 */

int ustcmd_send_cmd(const char *cmd, const pid_t pid, char **reply)
{
	struct ustcomm_connection conn;

	if (cmd == NULL) {
		return USTCMD_ERR_ARG;
	}

	if (ustcomm_connect_app(pid, &conn)) {
		fprintf(stderr, "ustcmd_send_cmd: could not connect to PID %u\n",
			(unsigned int) pid);
		return USTCMD_ERR_CONN;
	}

	ustcomm_send_request(&conn, cmd, reply);

	return 0;
}
