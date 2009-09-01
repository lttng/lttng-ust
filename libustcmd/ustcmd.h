#ifndef _USTCMD_H
#define _USTCMD_H

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <fcntl.h>

#include "ustcomm.h"
#include "ustcmd.h"

#define USTCMD_ERR_CONN		1 // Process connection error 
#define USTCMD_ERR_ARG		2 // Invalid function argument
#define USTCMD_ERR_GEN		3 // General ustcmd error

#define USTCMD_MS_CHR_OFF	'0' // Marker state 'on' character
#define USTCMD_MS_CHR_ON	'1' // Marker state 'on' character
#define USTCMD_MS_OFF		0 // Marker state 'on' value
#define USTCMD_MS_ON		1 // Marker state 'on' value

#define USTCMD_SOCK_PATH	"/tmp/socks/" // UST sockets directory

// Channel/marker/state/format string (cmsf) info. structure
struct USTcmd_cmsf {
	char* channel; // Channel name (end of USTcmd_cmsf array if NULL)
	char* marker; // Marker name (end of USTcmd_cmsf array if NULL)
	int state; // State (0 := marker disabled, 1 := marker enabled)
	char* fs; // Format string (end of USTcmd_cmsf array if NULL)
};

pid_t* ustcmd_get_online_pids(void);
int ustcmd_set_marker_state(const char*, int, pid_t);
int ustcmd_destroy_trace(pid_t);
int ustcmd_setup_and_start(pid_t);
int ustcmd_stop_trace(pid_t);
int ustcmd_start_trace(pid_t);
int ustcmd_free_cmsf(struct USTcmd_cmsf*);
unsigned int ustcmd_count_nl(const char*);
int ustcmd_shoot(const char*, pid_t, char**);
int ustcmd_get_cmsf(struct USTcmd_cmsf**, pid_t);

#endif // _USTCMD_H
