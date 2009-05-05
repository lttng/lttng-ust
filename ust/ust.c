#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>

#include "ustcomm.h"

struct ust_opts {
	char *cmd;
	pid_t *pids;
	int take_reply;
};

int parse_opts_long(int argc, char **argv, struct ust_opts *opts)
{
	int c;
	int digit_optind = 0;

	opts->cmd = NULL;
	opts->pids = NULL;
	opts->take_reply = 0;

	while (1) {
		int this_option_optind = optind ? optind : 1;
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
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "", long_options, &option_index);
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

char *progname = NULL;

void usage(void)
{
	fprintf(stderr, "usage: %s [OPTIONS] OPERATION PID...\n", progname);
	fprintf(stderr, "\nControl the tracing of a process that supports LTTng Userspace Tracing.\n\
\n\
Operations:\n\
\t--start-trace\tStart tracing\n\
\t--stop-trace\tStop tracing\n\
\t--destroy-trace\tDestroy the trace\n\
\t--enable-marker CHANNEL_NAME/MARKER_NAME\tEnable a marker\n\
\t--disable-marker CHANNEL_NAME/MARKER_NAME\tDisable a marker\n\
\t--list-markers\tList the markers of the process and their state\n\
\n\
");
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
