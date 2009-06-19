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

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <fcntl.h>

#include "ustcomm.h"

struct ust_opts {
	char *cmd;
	pid_t *pids;
	int take_reply;
};

char *progname = NULL;

void usage(void)
{
	fprintf(stderr, "usage: %s [OPTIONS] COMMAND PID...\n", progname);
	fprintf(stderr, "\nControl the tracing of a process that supports LTTng Userspace Tracing.\n\
\n\
Commands:\n\
    --start-trace\t\t\tStart tracing\n\
    --stop-trace\t\t\tStop tracing\n\
    --destroy-trace\t\t\tDestroy the trace\n\
    --enable-marker CHANNEL/MARKER\tEnable a marker\n\
    --disable-marker CHANNEL/MARKER\tDisable a marker\n\
    --list-markers\tList the markers of the process and their state\n\
\n\
");
}

int parse_opts_long(int argc, char **argv, struct ust_opts *opts)
{
	int c;

	opts->cmd = NULL;
	opts->pids = NULL;
	opts->take_reply = 0;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"start-trace", 0, 0, 1000},
			{"stop-trace", 0, 0, 1001},
			{"destroy-trace", 0, 0, 1002},
			{"list-markers", 0, 0, 1004},
			{"print-markers", 0, 0, 1005},
			{"pid", 1, 0, 1006},
			{"enable-marker", 1, 0, 1007},
			{"disable-marker", 1, 0, 1008},
			{"start", 0, 0, 1009},
			{"help", 0, 0, 'h'},
			{"version", 0, 0, 1010},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			printf("option %s", long_options[option_index].name);
			if (optarg)
				printf(" with arg %s", optarg);
			printf("\n");
			break;

		case 1000:
			opts->cmd = strdup("trace_start");
			break;
		case 1001:
			opts->cmd = strdup("trace_stop");
			break;
		case 1009:
			opts->cmd = strdup("start");
			break;
		case 1002:
			opts->cmd = strdup("trace_destroy");
			break;
		case 1004:
			opts->cmd = strdup("list_markers");
			opts->take_reply = 1;
			break;
		case 1007:
			asprintf(&opts->cmd, "enable_marker %s", optarg);
			break;
		case 1008:
			asprintf(&opts->cmd, "disable_marker %s", optarg);
			break;
		case 'h':
			usage();
			exit(0);
		case 1010:
			printf("Version 0\n");

		default:
			/* unknown option or other error; error is printed by getopt, just return */
			return 1;
		}
	}

	if(argc - optind > 0) {
		int i;
		int pididx=0;
		opts->pids = malloc((argc-optind+1) * sizeof(pid_t));

		for(i=optind; i<argc; i++) {
			opts->pids[pididx++] = atoi(argv[i]);
		}
		opts->pids[pididx] = -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	pid_t *pidit;
	//char *msg = argv[2];
	struct ustcomm_connection conn;
	int result;
	struct ust_opts opts;

	progname = argv[0];

	if(argc <= 1) {
		fprintf(stderr, "No operation specified.\n");
		usage();
		exit(EXIT_FAILURE);
	}

	result = parse_opts_long(argc, argv, &opts);
	if(result) {
		usage();
		exit(EXIT_FAILURE);
	}

	if(opts.pids == NULL) {
		fprintf(stderr, "No pid specified.\n");
		usage();
		exit(EXIT_FAILURE);
	}
	if(opts.cmd == NULL) {
		fprintf(stderr, "No command specified.\n");
		usage();
		exit(EXIT_FAILURE);
	}

	pidit = opts.pids;

	while(*pidit != -1) {
		char *reply;
		char **preply;

		if(opts.take_reply)
			preply = &reply;
		else
			preply = NULL;

		result = ustcomm_connect_app(*pidit, &conn);
		if(result) {
			fprintf(stderr, "error connecting to process\n");
			exit(EXIT_FAILURE);
		}
		ustcomm_send_request(&conn, opts.cmd, preply);

		if(opts.take_reply)
			printf("%s", reply);
		pidit++;
	}

	free(opts.pids);
	free(opts.cmd);

	return 0;
}
