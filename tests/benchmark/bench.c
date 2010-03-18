/*
 * bench.c
 *
 * LTTng Userspace Tracer (UST) - benchmark tool
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>
#include <ust/marker.h>

static int nr_cpus;
static unsigned long nr_events;
pthread_mutex_t	mutex = PTHREAD_MUTEX_INITIALIZER;

void do_stuff(void)
{
	int v;
	FILE *file;
	int lock;

	v = 1;

	lock = pthread_mutex_lock(&mutex);
	file = fopen("/tmp/bench.txt", "a");
	fprintf(file, "%d", v);
	fclose(file);
	lock = pthread_mutex_unlock(&mutex);

#ifdef MARKER
	trace_mark(ust, event, "event %d", v);
#endif

}


void *function(void *arg)
{
	unsigned long i;

	for(i = 0; i < nr_events; i++) {
		do_stuff();
	}
	return NULL;
}


void usage(char **argv) {
	printf("Usage: %s nr_cpus nr_events\n", argv[0]);
}


int main(int argc, char **argv)
{
	void *retval;
	int i;

	if (argc < 3) {
		usage(argv);
		exit(1);
	}

	nr_cpus = atoi(argv[1]);
	printf("using %d processor(s)\n", nr_cpus);

	nr_events = atol(argv[2]);
	printf("using %ld events per cpu\n", nr_events);

	pthread_t thread[nr_cpus];
	for (i = 0; i < nr_cpus; i++) {
		if (pthread_create(&thread[i], NULL, function, NULL)) {
			fprintf(stderr, "thread create %d failed\n", i);
			exit(1);
		}
	}

	for (i = 0; i < nr_cpus; i++) {
		if (pthread_join(thread[i], &retval)) {
			fprintf(stderr, "thread join %d failed\n", i);
			exit(1);
		}
	}
	return 0;
}
