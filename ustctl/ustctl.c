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
#include "ustcmd.h"
#include "usterr.h"

enum command {
	CREATE_TRACE=1000,
	ALLOC_TRACE,
	START_TRACE,
	STOP_TRACE,
	DESTROY_TRACE,
	LIST_MARKERS,
	ENABLE_MARKER,
	DISABLE_MARKER,
	GET_ONLINE_PIDS,
	SET_SUBBUF_SIZE,
	SET_SUBBUF_NUM,
	GET_SUBBUF_SIZE,
	GET_SUBBUF_NUM,
	GET_SOCK_PATH,
	SET_SOCK_PATH,
	UNKNOWN
};

struct ust_opts {
	enum command cmd;
	pid_t *pids;
	char *regex;
};

char *progname = NULL;

void usage(void)
{
	fprintf(stderr, "usage: %s COMMAND PIDs...\n", progname);
	fprintf(stderr, "\nControl the tracing of a process that supports LTTng Userspace Tracing.\n\
\n\
Commands:\n\
    --create-trace\t\t\tCreate trace\n\
    --alloc-trace\t\t\tAlloc trace\n\
    --start-trace\t\t\tStart tracing\n\
    --stop-trace\t\t\tStop tracing\n\
    --destroy-trace\t\t\tDestroy the trace\n\
    --set-subbuf-size \"CHANNEL/bytes\"\tSet the size of subbuffers per channel\n\
    --set-subbuf-num \"CHANNEL/n\"\tSet the number of subbuffers per channel\n\
    --set-sock-path\t\t\tSet the path of the daemon socket\n\
    --get-subbuf-size \"CHANNEL\"\t\tGet the size of subbuffers per channel\n\
    --get-subbuf-num \"CHANNEL\"\t\tGet the number of subbuffers per channel\n\
    --get-sock-path\t\t\tGet the path of the daemon socket\n\
    --enable-marker \"CHANNEL/MARKER\"\tEnable a marker\n\
    --disable-marker \"CHANNEL/MARKER\"\tDisable a marker\n\
    --list-markers\t\t\tList the markers of the process, their\n\t\t\t\t\t  state and format string\n\
\
");
}

int parse_opts_long(int argc, char **argv, struct ust_opts *opts)
{
	int c;

	opts->pids = NULL;
	opts->regex = NULL;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{ "create-trace", 0, 0, CREATE_TRACE },
			{ "alloc-trace", 0, 0, ALLOC_TRACE },
			{ "start-trace", 0, 0, START_TRACE },
			{ "stop-trace", 0, 0, STOP_TRACE },
			{ "destroy-trace", 0, 0, DESTROY_TRACE },
			{ "list-markers", 0, 0, LIST_MARKERS },
			{ "enable-marker", 1, 0, ENABLE_MARKER },
			{ "disable-marker", 1, 0, DISABLE_MARKER },
			{ "help", 0, 0, 'h' },
			{ "online-pids", 0, 0, GET_ONLINE_PIDS },
			{ "set-subbuf-size", 1, 0, SET_SUBBUF_SIZE },
			{ "set-subbuf-num", 1, 0, SET_SUBBUF_NUM },
			{ "get-subbuf-size", 1, 0, GET_SUBBUF_SIZE },
			{ "get-subbuf-num", 1, 0, GET_SUBBUF_NUM },
			{ "get-sock-path", 0, 0, GET_SOCK_PATH },
			{ "set-sock-path", 1, 0, SET_SOCK_PATH },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "h", long_options, &option_index);
		if (c == -1)
			break;

		if(c >= 1000)
			opts->cmd = c;

		switch (c) {
		case 0:
			printf("option %s", long_options[option_index].name);
			if (optarg)
				printf(" with arg %s", optarg);
			printf("\n");
			break;

		case ENABLE_MARKER:
		case DISABLE_MARKER:
		case SET_SUBBUF_SIZE:
		case SET_SUBBUF_NUM:
		case GET_SUBBUF_SIZE:
		case GET_SUBBUF_NUM:
		case SET_SOCK_PATH:
			opts->regex = strdup(optarg);
			break;

		case 'h':
			usage();
			exit(0);

		case '?':
			fprintf(stderr, "Invalid argument\n\n");
			usage();
			exit(1);
		}
	}

	if (argc - optind > 0 && opts->cmd != GET_ONLINE_PIDS) {
		int i;
		int pididx=0;
		opts->pids = malloc((argc-optind+1) * sizeof(pid_t));

		for(i=optind; i<argc; i++) {
			/* don't take any chances, use a long long */
			long long tmp;
			char *endptr;
			tmp = strtoull(argv[i], &endptr, 10);
			if(*endptr != '\0') {
				ERR("The pid \"%s\" is invalid.", argv[i]);
				return 1;
			}
			opts->pids[pididx++] = (pid_t) tmp;
		}
		opts->pids[pididx] = -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	pid_t *pidit;
	int result;
	char *tmp;
	struct ust_opts opts;

	progname = argv[0];

	if(argc <= 1) {
		fprintf(stderr, "No operation specified.\n");
		usage();
		exit(EXIT_FAILURE);
	}

	result = parse_opts_long(argc, argv, &opts);
	if(result) {
		fprintf(stderr, "\n");
		usage();
		exit(EXIT_FAILURE);
	}

	if(opts.pids == NULL && opts.cmd != GET_ONLINE_PIDS) {
		fprintf(stderr, "No pid specified.\n");
		usage();
		exit(EXIT_FAILURE);
	}
	if(opts.cmd == UNKNOWN) {
		fprintf(stderr, "No command specified.\n");
		usage();
		exit(EXIT_FAILURE);
	}
	if (opts.cmd == GET_ONLINE_PIDS) {
		pid_t *pp = ustcmd_get_online_pids();
		unsigned int i = 0;

		if (pp) {
			while (pp[i] != 0) {
				printf("%u\n", (unsigned int) pp[i]);
				++i;
			}
			free(pp);
		}

		exit(EXIT_SUCCESS);
	}

	pidit = opts.pids;
	struct marker_status *cmsf = NULL;

	while(*pidit != -1) {
		switch (opts.cmd) {
			case CREATE_TRACE:
				result = ustcmd_create_trace(*pidit);
				if (result) {
					ERR("error while trying to create trace with PID %u\n", (unsigned int) *pidit);
					break;
				}
				break;

			case START_TRACE:
				result = ustcmd_start_trace(*pidit);
				if (result) {
					ERR("error while trying to for trace with PID %u\n", (unsigned int) *pidit);
					break;
				}
				break;

			case STOP_TRACE:
				result = ustcmd_stop_trace(*pidit);
				if (result) {
					ERR("error while trying to stop trace for PID %u\n", (unsigned int) *pidit);
					break;
				}
				break;

			case DESTROY_TRACE:
				result = ustcmd_destroy_trace(*pidit);
				if (result) {
					ERR("error while trying to destroy trace with PID %u\n", (unsigned int) *pidit);
					break;
				}
				break;

			case LIST_MARKERS:
				cmsf = NULL;
				if (ustcmd_get_cmsf(&cmsf, *pidit)) {
					fprintf(stderr,
						"error while trying to list markers for"
						" PID %u\n", (unsigned int) *pidit);
					break;
				}
				unsigned int i = 0;
				while (cmsf[i].channel != NULL) {
					printf("{PID: %u, channel/marker: %s/%s, "
						"state: %u, fmt: %s}\n",
						(unsigned int) *pidit,
						cmsf[i].channel,
						cmsf[i].marker,
						cmsf[i].state,
						cmsf[i].fs);
					++i;
				}
				ustcmd_free_cmsf(cmsf);
				break;

			case ENABLE_MARKER:
				if(opts.regex)
					ustcmd_set_marker_state(opts.regex, 1, *pidit);
				break;
			case DISABLE_MARKER:
				if(opts.regex)
					ustcmd_set_marker_state(opts.regex, 0, *pidit);
				break;

			case SET_SUBBUF_SIZE:
				ustcmd_set_subbuf_size(opts.regex, *pidit);
				break;

			case SET_SUBBUF_NUM:
				ustcmd_set_subbuf_num(opts.regex, *pidit);
				break;

			case GET_SUBBUF_SIZE:
				result = ustcmd_get_subbuf_size(opts.regex, *pidit);
				if (result == -1) {
					ERR("error while trying to get_subuf_size with PID %u\n", (unsigned int) *pidit);
					break;
				}

				printf("the size of subbufers is %d\n", result);
				break;

			case GET_SUBBUF_NUM:
				result = ustcmd_get_subbuf_num(opts.regex, *pidit);
				if (result == -1) {
					ERR("error while trying to get_subuf_num with PID %u\n", (unsigned int) *pidit);
					break;
				}

				printf("the number of subbufers is %d\n", result);
				break;

			case ALLOC_TRACE:
				result = ustcmd_alloc_trace(*pidit);
				if (result) {
					ERR("error while trying to alloc trace with PID %u\n", (unsigned int) *pidit);
					break;
				}
				break;

			case GET_SOCK_PATH:
				result = ustcmd_get_sock_path(&tmp, *pidit);
				if (result) {
					ERR("error while trying to get sock path for PID %u\n", (unsigned int) *pidit);
					break;
				}
				printf("the socket path is %s\n", tmp);
				free(tmp);
				break;

			case SET_SOCK_PATH:
				result = ustcmd_set_sock_path(opts.regex, *pidit);
				if (result) {
					ERR("error while trying to set sock path for PID %u\n", (unsigned int) *pidit);
				}
				break;

			default:
				ERR("unknown command\n");
			break;
		}

		pidit++;
	}

	if (opts.pids != NULL) {
		free(opts.pids);
	}
	if (opts.regex != NULL) {
		free(opts.regex);
	}

	return 0;
}

