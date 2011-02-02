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
struct marker_status {
	char *channel; /* Channel name (end of marker_status array if NULL) */
	char *marker; /* Marker name (end of marker_status array if NULL) */
	int state; /* State (0 := marker disabled, 1 := marker enabled) */
	char *fs; /* Format string (end of marker_status array if NULL) */
};

struct trace_event_status {
	char *name;
};

extern pid_t *ustctl_get_online_pids(void);
extern int ustctl_set_marker_state(const char *trace, const char *channel,
				   const char *marker, int state, pid_t pid);
extern int ustctl_set_subbuf_size(const char *trace, const char *channel,
				  unsigned int subbuf_size, pid_t pid);
extern int ustctl_set_subbuf_num(const char *trace, const char *channel,
				 unsigned int num, pid_t pid);
extern int ustctl_get_subbuf_size(const char *trace, const char *channel,
				  pid_t pid);
extern int ustctl_get_subbuf_num(const char *trace, const char *channel,
				 pid_t pid);
extern int ustctl_destroy_trace(const char *trace, pid_t pid);
extern int ustctl_setup_and_start(const char *trace, pid_t pid);
extern int ustctl_stop_trace(const char *trace, pid_t pid);
extern int ustctl_create_trace(const char *trace, pid_t pid);
extern int ustctl_start_trace(const char *trace, pid_t pid);
extern int ustctl_alloc_trace(const char *trace, pid_t pid);
extern int ustctl_free_cmsf(struct marker_status *);
extern unsigned int ustctl_count_nl(const char *);
extern int ustctl_get_cmsf(struct marker_status **, pid_t);
extern int ustctl_free_tes(struct trace_event_status *);
extern int ustctl_get_tes(struct trace_event_status **, pid_t);
extern int ustctl_set_sock_path(const char *sock_path, pid_t pid);
extern int ustctl_get_sock_path(char **sock_path, pid_t pid);
extern int ustctl_force_switch(pid_t pid);

#endif /* _USTCTL_H */
