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
#include "ust/ustcmd.h"
#include "usterr.h"

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
			/* FIXME: Here we previously called pid_is_online, which
			 * always returned 1, now I replaced it with just 1.
			 * We need to figure out an intelligent way of solving
			 * this, maybe connect-disconnect.
			 */
			if (1) {
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

	if (asprintf(&cmd, "%s %s", cmd_str[state], mn) < 0) {
		ERR("ustcmd_set_marker_state : asprintf failed (%s %s)",
		    cmd_str[state], mn);
		return USTCMD_ERR_GEN;
	}

	result = ustcmd_send_cmd(cmd, pid, NULL);
	if (result != 1) {
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

	if (asprintf(&cmd, "%s %s", "set_subbuf_size", channel_size) < 0) {
		ERR("ustcmd_set_subbuf_size : asprintf failed (set_subbuf_size %s)",
		    channel_size);
		return -1;
	}

	result = ustcmd_send_cmd(cmd, pid, NULL);
	if (result != 1) {
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

	if (asprintf(&cmd, "%s %s", "set_subbuf_num", channel_size) < 0) {
		ERR("ustcmd_set_subbuf_num : asprintf failed (set_subbuf_num %s",
		    channel_size);
		return -1;
	}

	result = ustcmd_send_cmd(cmd, pid, NULL);
	if (result != 1) {
		free(cmd);
		return 1;
	}

	free(cmd);
	return 0;
}

/**
 * Get subbuffer size.
 *
 * @param channel	Channel name
 * @param pid		Traced process ID
 * @return		subbuf size if successful, or error
 */
int ustcmd_get_subbuf_size(const char *channel, pid_t pid)
{
	char *cmd, *reply;
	int result;

	/* format: channel_cpu */
	if (asprintf(&cmd, "%s %s_0", "get_subbuf_size", channel) < 0) {
		ERR("ustcmd_get_subbuf_size : asprintf failed (get_subbuf_size, %s_0",
		    channel);
		return -1;
	}

	result = ustcmd_send_cmd(cmd, pid, &reply);
	if (result != 1) {
		free(cmd);
		return -1;
	}

	result = atoi(reply);
	free(cmd);
	free(reply);
	return result;
}

/**
 * Get subbuffer num.
 *
 * @param channel	Channel name
 * @param pid		Traced process ID
 * @return		subbuf cnf if successful, or error
 */
int ustcmd_get_subbuf_num(const char *channel, pid_t pid)
{
	char *cmd, *reply;
	int result;

	/* format: channel_cpu */
	if (asprintf(&cmd, "%s %s_0", "get_n_subbufs", channel) < 0) {
		ERR("ustcmd_get_subbuf_num : asprintf failed (get_n_subbufs, %s_0",
		    channel);
		return -1;
	}

	result = ustcmd_send_cmd(cmd, pid, &reply);
	if (result != 1) {
		free(cmd);
		return -1;
	}

	result = atoi(reply);
	free(cmd);
	free(reply);
	return result;
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
	if (result != 1) {
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
	if (result != 1) {
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
	if (result != 1) {
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
	if (result != 1) {
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
	if (result != 1) {
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
	if (result != 1) {
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
 * @return	0 if successful, or -1 on error
 */
int ustcmd_get_cmsf(struct marker_status **cmsf, const pid_t pid)
{
	char *big_str = NULL;
	int result;
	struct marker_status *tmp_cmsf = NULL;
	unsigned int i = 0, cmsf_ind = 0;

	if (cmsf == NULL) {
		return -1;
	}
	result = ustcmd_send_cmd("list_markers", pid, &big_str);
	if (result != 1) {
		ERR("error while getting markers list");
		return -1;
	}

	tmp_cmsf = (struct marker_status *) malloc(sizeof(struct marker_status) *
		(ustcmd_count_nl(big_str) + 1));
	if (tmp_cmsf == NULL) {
		ERR("Failed to allocate CMSF array");
		return -1;
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
 * Frees a TES array.
 *
 * @param tes	TES array to free
 * @return	0 if successful, or error USTCMD_ERR_ARG
 */
int ustcmd_free_tes(struct trace_event_status *tes)
{
	if (tes == NULL) {
		return USTCMD_ERR_ARG;
	}

	unsigned int i = 0;
	while (tes[i].name != NULL) {
		free(tes[i].name);
		++i;
	}
	free(tes);

	return 0;
}

/**
 * Gets trace_events string for a given PID.
 *
 * @param tes	Pointer to TES array to be filled (callee allocates, caller
 *		frees with `ustcmd_free_tes')
 * @param pid	Targeted PID
 * @return	0 if successful, or -1 on error
 */
int ustcmd_get_tes(struct trace_event_status **tes,
			    const pid_t pid)
{
	char *big_str = NULL;
	int result;
	struct trace_event_status *tmp_tes = NULL;
	unsigned int i = 0, tes_ind = 0;

	if (tes == NULL) {
		return -1;
	}

	result = ustcmd_send_cmd("list_trace_events", pid, &big_str);
	if (result != 1) {
		ERR("error while getting trace_event list");
		return -1;
	}

	tmp_tes = (struct trace_event_status *)
		zmalloc(sizeof(struct trace_event_status) *
			(ustcmd_count_nl(big_str) + 1));
	if (tmp_tes == NULL) {
		ERR("Failed to allocate TES array");
		return -1;
	}

	/* Parse received reply string (format: "[name]"): */
	while (big_str[i] != '\0') {
		char state;

		sscanf(big_str + i, "trace_event: %a[^\n]",
			&tmp_tes[tes_ind].name);
		while (big_str[i] != '\n') {
			++i; /* Go to next '\n' */
		}
		++i; /* Skip current pointed '\n' */
		++tes_ind;
	}
	tmp_tes[tes_ind].name = NULL;

	*tes = tmp_tes;

	free(big_str);
	return 0;
}

/**
 * Set socket path
 *
 * @param sock_path	Socket path
 * @param pid		Traced process ID
 * @return		0 if successful, or error
 */
int ustcmd_set_sock_path(const char *sock_path, pid_t pid)
{
	char *cmd;
	int result;

	if (asprintf(&cmd, "%s %s", "set_sock_path", sock_path) < 0) {
		ERR("ustcmd_set_sock_path : asprintf failed (set_sock_path, %s",
		    sock_path);
		return -1;
	}

	result = ustcmd_send_cmd(cmd, pid, NULL);
	if (result != 1) {
		free(cmd);
		return USTCMD_ERR_GEN;
	}

	free(cmd);
	return 0;
}

/**
 * Get socket path
 *
 * @param sock_path	Pointer to where the socket path will be returned
 * @param pid		Traced process ID
 * @return		0 if successful, or error
 */
int ustcmd_get_sock_path(char **sock_path, pid_t pid)
{
	char *cmd, *reply;
	int result;

	if (asprintf(&cmd, "%s", "get_sock_path") < 0) {
		ERR("ustcmd_get_sock_path : asprintf failed");
		return USTCMD_ERR_GEN;
	}

	result = ustcmd_send_cmd(cmd, pid, &reply);
	if (result != 1) {
		free(cmd);
		return USTCMD_ERR_GEN;
	}

	free(cmd);
	*sock_path = reply;
	return 0;
}

int ustcmd_force_switch(pid_t pid)
{
	int result;

	result = ustcmd_send_cmd("force_switch", pid, NULL);
	if (result != 1) {
		return USTCMD_ERR_GEN;
	}

	return 0;
}

/**
 * Sends a given command to a traceable process
 *
 * @param cmd	Null-terminated command to send
 * @param pid	Targeted PID
 * @param reply	Pointer to string to be filled with a reply string (must
 *		be NULL if no reply is needed for the given command).
 * @return	-1 if not successful, 0 on EOT, 1 on success
 */

int ustcmd_send_cmd(const char *cmd, const pid_t pid, char **reply)
{
	int app_fd;
	int retval;

	if (ustcomm_connect_app(pid, &app_fd)) {
		ERR("could not connect to PID %u", (unsigned int) pid);
		return -1;
	}

	retval = ustcomm_send_request(app_fd, cmd, reply);

	close(app_fd);

	return retval;
}
