/* Copyright (C) 2009  Pierre-Marc Fournier
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

#ifndef _USTCTL_H
#define _USTCTL_H

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <fcntl.h>

#define USTCTL_ERR_CONN		1 /* Process connection error */
#define USTCTL_ERR_ARG		2 /* Invalid function argument */
#define USTCTL_ERR_GEN		3 /* General ustctl error */

#define USTCTL_MS_CHR_OFF	'0' /* Marker state 'on' character */
#define USTCTL_MS_CHR_ON	'1' /* Marker state 'on' character */
#define USTCTL_MS_OFF		0   /* Marker state 'on' value */
#define USTCTL_MS_ON		1   /* Marker state 'on' value */

#define USTCTL_SOCK_PATH	"/tmp/socks/"

/* Channel/marker/state/format string (cmsf) info. structure */
struct ust_marker_status {
	char *channel; /* Channel name (end of ust_marker_status array if NULL) */
	char *ust_marker; /* Marker name (end of ust_marker_status array if NULL) */
	int state; /* State (0 := marker disabled, 1 := marker enabled) */
	char *fs; /* Format string (end of ust_marker_status array if NULL) */
};

struct trace_event_status {
	char *name;
};

extern pid_t *ustctl_get_online_pids(void);

extern int ustctl_connect_pid(pid_t pid);

extern int ustctl_set_ust_marker_state(int sock, const char *trace,
				   const char *channel, const char *ust_marker,
				   int state);

extern int ustctl_set_subbuf_size(int sock, const char *trace,
				  const char *channel,
				  unsigned int subbuf_size);

extern int ustctl_set_subbuf_num(int sock, const char *trace,
				 const char *channel,
				 unsigned int num);

extern int ustctl_get_subbuf_size(int sock, const char *trace,
				  const char *channel);

extern int ustctl_get_subbuf_num(pid_t pid, const char *trace,
				 const char *channel);

extern int ustctl_destroy_trace(int sock, const char *trace);

extern int ustctl_setup_and_start(int sock, const char *trace);

extern int ustctl_stop_trace(int sock, const char *trace);

extern int ustctl_create_trace(int sock, const char *trace);

extern int ustctl_start_trace(int sock, const char *trace);

extern int ustctl_alloc_trace(int sock, const char *trace);

extern int ustctl_free_cmsf(struct ust_marker_status *);
extern int ustctl_free_tes(struct trace_event_status *);
extern unsigned int ustctl_count_nl(const char *);

extern int ustctl_get_cmsf(int sock, struct ust_marker_status **);

extern int ustctl_get_tes(int sock, struct trace_event_status **);

extern int ustctl_set_sock_path(int sock, const char *sock_path);

extern int ustctl_get_sock_path(int sock, char **sock_path);

extern int ustctl_force_switch(int sock, const char *trace);

#endif /* _USTCTL_H */
