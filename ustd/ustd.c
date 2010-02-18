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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include "ustd.h"
#include "usterr.h"
#include "ustcomm.h"

/* return value: 0 = subbuffer is finished, it won't produce data anymore
 *               1 = got subbuffer successfully
 *               <0 = error
 */

#define GET_SUBBUF_OK 1
#define GET_SUBBUF_DONE 0
#define GET_SUBBUF_DIED 2

#define PUT_SUBBUF_OK 1
#define PUT_SUBBUF_DIED 0
#define PUT_SUBBUF_PUSHED 2
#define PUT_SUBBUF_DONE 3

char *sock_path=NULL;
char *trace_path=NULL;
int daemon_mode = 0;
char *pidfile = NULL;

/* Number of active buffers and the mutex to protect it. */
int active_buffers = 0;
pthread_mutex_t active_buffers_mutex = PTHREAD_MUTEX_INITIALIZER;
/* Whether a request to end the program was received. */
sig_atomic_t terminate_req = 0;

int get_subbuffer(struct buffer_info *buf)
{
	char *send_msg=NULL;
	char *received_msg=NULL;
	char *rep_code=NULL;
	int retval;
	int result;

	asprintf(&send_msg, "get_subbuffer %s", buf->name);
	result = ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	if((result == -1 && errno == EPIPE) || result == 0) {
		DBG("app died while being traced");
		retval = GET_SUBBUF_DIED;
		goto end;
	}
	else if(result < 0) {
		ERR("get_subbuffer: ustcomm_send_request failed");
		retval = -1;
		goto end;
	}

	result = sscanf(received_msg, "%as %ld", &rep_code, &buf->consumed_old);
	if(result != 2 && result != 1) {
		ERR("unable to parse response to get_subbuffer");
		retval = -1;
		goto end_rep;
	}

	DBG("received msg is %s", received_msg);

	if(!strcmp(rep_code, "OK")) {
		DBG("got subbuffer %s", buf->name);
		retval = GET_SUBBUF_OK;
	}
	else if(nth_token_is(received_msg, "END", 0) == 1) {
		retval = GET_SUBBUF_DONE;
		goto end_rep;
	}
	else if(!strcmp(received_msg, "NOTFOUND")) {
		WARN("For buffer %s, the trace was not found. This likely means it was destroyed by the user.", buf->name);
		retval = GET_SUBBUF_DONE;
		goto end_rep;
	}
	else {
		DBG("error getting subbuffer %s", buf->name);
		retval = -1;
	}

	/* FIMXE: free correctly the stuff */
end_rep:
	if(rep_code)
		free(rep_code);
end:
	if(send_msg)
		free(send_msg);
	if(received_msg)
		free(received_msg);

	return retval;
}

int put_subbuffer(struct buffer_info *buf)
{
	char *send_msg=NULL;
	char *received_msg=NULL;
	char *rep_code=NULL;
	int retval;
	int result;

	asprintf(&send_msg, "put_subbuffer %s %ld", buf->name, buf->consumed_old);
	result = ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	if(result < 0 && errno == ECONNRESET) {
		retval = PUT_SUBBUF_DIED;
		goto end;
	}
	else if(result < 0) {
		ERR("put_subbuffer: send_message failed");
		retval = -1;
		goto end;
	}
	else if(result == 0) {
		/* Program seems finished. However this might not be
		 * the last subbuffer that has to be collected.
		 */
		retval = PUT_SUBBUF_DIED;
		goto end;
	}

	result = sscanf(received_msg, "%as", &rep_code);
	if(result != 1) {
		ERR("unable to parse response to put_subbuffer");
		retval = -1;
		goto end_rep;
	}

	if(!strcmp(rep_code, "OK")) {
		DBG("subbuffer put %s", buf->name);
		retval = PUT_SUBBUF_OK;
	}
	else {
		DBG("put_subbuffer: received error, we were pushed");
		retval = PUT_SUBBUF_PUSHED;
		goto end_rep;
	}

end_rep:
	if(rep_code)
		free(rep_code);

end:
	if(send_msg)
		free(send_msg);
	if(received_msg)
		free(received_msg);

	return retval;
}

void decrement_active_buffers(void *arg)
{
	pthread_mutex_lock(&active_buffers_mutex);
	active_buffers--;
	pthread_mutex_unlock(&active_buffers_mutex);
}

int create_dir_if_needed(char *dir)
{
	int result;
	result = mkdir(dir, 0777);
	if(result == -1) {
		if(errno != EEXIST) {
			PERROR("mkdir");
			return -1;
		}
	}

	return 0;
}

int is_directory(const char *dir)
{
	int result;
	struct stat st;

	result = stat(dir, &st);
	if(result == -1) {
		PERROR("stat");
		return 0;
	}

	if(!S_ISDIR(st.st_mode)) {
		return 0;
	}

	return 1;
}

struct buffer_info *connect_buffer(pid_t pid, const char *bufname)
{
	struct buffer_info *buf;
	char *send_msg;
	char *received_msg;
	int result;
	char *tmp;
	int fd;
	struct shmid_ds shmds;

	buf = (struct buffer_info *) malloc(sizeof(struct buffer_info));
	if(buf == NULL) {
		ERR("add_buffer: insufficient memory");
		return NULL;
	}

	buf->name = bufname;
	buf->pid = pid;

	/* connect to app */
	result = ustcomm_connect_app(buf->pid, &buf->conn);
	if(result) {
		WARN("unable to connect to process, it probably died before we were able to connect");
		return NULL;
	}

	/* get pidunique */
	asprintf(&send_msg, "get_pidunique");
	result = ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);
	if(result == -1) {
		ERR("problem in ustcomm_send_request(get_pidunique)");
		return NULL;
	}

	result = sscanf(received_msg, "%lld", &buf->pidunique);
	if(result != 1) {
		ERR("unable to parse response to get_pidunique");
		return NULL;
	}
	free(received_msg);
	DBG("got pidunique %lld", buf->pidunique);

	/* get shmid */
	asprintf(&send_msg, "get_shmid %s", buf->name);
	result = ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);
	if(result == -1) {
		ERR("problem in ustcomm_send_request(get_shmid)");
		return NULL;
	}

	result = sscanf(received_msg, "%d %d", &buf->shmid, &buf->bufstruct_shmid);
	if(result != 2) {
		ERR("unable to parse response to get_shmid (\"%s\")", received_msg);
		return NULL;
	}
	free(received_msg);
	DBG("got shmids %d %d", buf->shmid, buf->bufstruct_shmid);

	/* get n_subbufs */
	asprintf(&send_msg, "get_n_subbufs %s", buf->name);
	result = ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);
	if(result == -1) {
		ERR("problem in ustcomm_send_request(g_n_subbufs)");
		return NULL;
	}

	result = sscanf(received_msg, "%d", &buf->n_subbufs);
	if(result != 1) {
		ERR("unable to parse response to get_n_subbufs");
		return NULL;
	}
	free(received_msg);
	DBG("got n_subbufs %d", buf->n_subbufs);

	/* get subbuf size */
	asprintf(&send_msg, "get_subbuf_size %s", buf->name);
	ustcomm_send_request(&buf->conn, send_msg, &received_msg);
	free(send_msg);

	result = sscanf(received_msg, "%d", &buf->subbuf_size);
	if(result != 1) {
		ERR("unable to parse response to get_subbuf_size");
		return NULL;
	}
	free(received_msg);
	DBG("got subbuf_size %d", buf->subbuf_size);

	/* attach memory */
	buf->mem = shmat(buf->shmid, NULL, 0);
	if(buf->mem == (void *) 0) {
		PERROR("shmat");
		return NULL;
	}
	DBG("successfully attached buffer memory");

	buf->bufstruct_mem = shmat(buf->bufstruct_shmid, NULL, 0);
	if(buf->bufstruct_mem == (void *) 0) {
		PERROR("shmat");
		return NULL;
	}
	DBG("successfully attached buffer bufstruct memory");

	/* obtain info on the memory segment */
	result = shmctl(buf->shmid, IPC_STAT, &shmds);
	if(result == -1) {
		PERROR("shmctl");
		return NULL;
	}
	buf->memlen = shmds.shm_segsz;

	/* open file for output */
	if(!trace_path) {
		/* Only create the directory if using the default path, because
		 * of the risk of typo when using trace path override. We don't
		 * want to risk creating plenty of useless directories in that case.
		 */
		result = create_dir_if_needed(USTD_DEFAULT_TRACE_PATH);
		if(result == -1) {
			ERR("could not create directory %s", USTD_DEFAULT_TRACE_PATH);
			return NULL;
		}

		trace_path = USTD_DEFAULT_TRACE_PATH;
	}

	asprintf(&tmp, "%s/%u_%lld", trace_path, buf->pid, buf->pidunique);
	result = create_dir_if_needed(tmp);
	if(result == -1) {
		ERR("could not create directory %s", tmp);
		free(tmp);
		return NULL;
	}
	free(tmp);

	asprintf(&tmp, "%s/%u_%lld/%s", trace_path, buf->pid, buf->pidunique, buf->name);
	result = fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 00600);
	if(result == -1) {
		PERROR("open");
		ERR("failed opening trace file %s", tmp);
		return NULL;
	}
	buf->file_fd = fd;
	free(tmp);

	pthread_mutex_lock(&active_buffers_mutex);
	active_buffers++;
	pthread_mutex_unlock(&active_buffers_mutex);

	return buf;
}

int write_current_subbuffer(struct buffer_info *buf)
{
	int result;

	void *subbuf_mem = buf->mem + (buf->consumed_old & (buf->n_subbufs * buf->subbuf_size-1));

	size_t cur_sb_size = subbuffer_data_size(subbuf_mem);

	result = patient_write(buf->file_fd, subbuf_mem, cur_sb_size);
	if(result == -1) {
		PERROR("write");
		/* FIXME: maybe drop this trace */
		return 0;
	}

	return 0;
}

int consumer_loop(struct buffer_info *buf)
{
	int result;

	pthread_cleanup_push(decrement_active_buffers, NULL);

	for(;;) {
		/* get the subbuffer */
		result = get_subbuffer(buf);
		if(result == -1) {
			ERR("error getting subbuffer");
			continue;
		}
		else if(result == GET_SUBBUF_DONE) {
			/* this is done */
			break;
		}
		else if(result == GET_SUBBUF_DIED) {
			finish_consuming_dead_subbuffer(buf);
			break;
		}

		/* write data to file */
		write_current_subbuffer(buf);
		/* FIXME: handle return value? */

		/* put the subbuffer */
		/* FIXME: we actually should unput the buffer before consuming... */
		result = put_subbuffer(buf);
		if(result == -1) {
			ERR("unknown error putting subbuffer (channel=%s)", buf->name);
			break;
		}
		else if(result == PUT_SUBBUF_PUSHED) {
			ERR("Buffer overflow (channel=%s), reader pushed. This channel will not be usable passed this point.", buf->name);
			break;
		}
		else if(result == PUT_SUBBUF_DIED) {
			WARN("application died while putting subbuffer");
			/* FIXME: probably need to skip the first subbuffer in finish_consuming_dead_subbuffer */
			finish_consuming_dead_subbuffer(buf);
			break;
		}
		else if(result == PUT_SUBBUF_DONE) {
			/* Done with this subbuffer */
			/* FIXME: add a case where this branch is used? Upon
			 * normal trace termination, at put_subbuf time, a
			 * special last-subbuffer code could be returned by
			 * the listener.
			 */
			break;
		}
		else if(result == PUT_SUBBUF_OK) {
		}
	}

	DBG("thread for buffer %s is stopping", buf->name);

	/* FIXME: destroy, unalloc... */

	pthread_cleanup_pop(1);

	return 0;
}

void free_buffer(struct buffer_info *buf)
{
}

struct consumer_thread_args {
	pid_t pid;
	const char *bufname;
};

void *consumer_thread(void *arg)
{
	struct buffer_info *buf = (struct buffer_info *) arg;
	struct consumer_thread_args *args = (struct consumer_thread_args *) arg;

	DBG("GOT ARGS: pid %d bufname %s", args->pid, args->bufname);

	buf = connect_buffer(args->pid, args->bufname);
	if(buf == NULL) {
		ERR("failed to connect to buffer");
		goto end;
	}

	consumer_loop(buf);

	free_buffer(buf);

	end:
	/* bufname is free'd in free_buffer() */
	free(args);
	return NULL;
}

int start_consuming_buffer(pid_t pid, const char *bufname)
{
	pthread_t thr;
	struct consumer_thread_args *args;

	DBG("beginning of start_consuming_buffer: args: pid %d bufname %s", pid, bufname);

	args = (struct consumer_thread_args *) malloc(sizeof(struct consumer_thread_args));

	args->pid = pid;
	args->bufname = strdup(bufname);
	DBG("beginning2 of start_consuming_buffer: args: pid %d bufname %s", args->pid, args->bufname);

	pthread_create(&thr, NULL, consumer_thread, args);
	DBG("end of start_consuming_buffer: args: pid %d bufname %s", args->pid, args->bufname);

	return 0;
}

void usage(void)
{
	fprintf(stderr, "Usage:\nustd OPTIONS\n\nOptions:\n"
			"\t-h\t\tDisplay this usage.\n"
			"\t-o DIR\t\tSpecify the directory where to output the traces.\n"
			"\t-s PATH\t\tSpecify the path to use for the daemon socket.\n"
			"\t-d\t\tStart as a daemon.\n"
			"\t--pidfile FILE\tWrite the PID in this file (when using -d).\n");
}

int parse_args(int argc, char **argv)
{
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"pidfile", 1, 0, 'p'},
			{"help", 0, 0, 'h'},
			{"version", 0, 0, 'V'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "hs:o:d", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 0:
			printf("option %s", long_options[option_index].name);
			if (optarg)
				printf(" with arg %s", optarg);
			printf("\n");
			break;
		case 's':
			sock_path = optarg;
			break;
		case 'o':
			trace_path = optarg;
			if(!is_directory(trace_path)) {
				ERR("Not a valid directory. (%s)", trace_path);
				return -1;
			}
			break;
		case 'd':
			daemon_mode = 1;
			break;
		case 'p':
			pidfile = strdup(optarg);
			break;
		case 'h':
			usage();
			exit(0);
		case 'V':
			printf("Version 0.0\n");
			break;

		default:
			/* unknown option or other error; error is
			printed by getopt, just return */
			return -1;
		}
	}

	return 0;
}

void sigterm_handler(int sig)
{
	terminate_req = 1;
}

static int write_pidfile(const char *file_name, pid_t pid)
{
	FILE *pidfp;

	pidfp = fopen(file_name, "w");
	if(!pidfp) {
		PERROR("fopen (%s)", pidfile);
		WARN("killing child process");
		return -1;
	}

	fprintf(pidfp, "%d\n", pid);

	fclose(pidfp);

	return 0;
}

int start_ustd(int fd)
{
	struct ustcomm_ustd ustd;
	int result;
	sigset_t sigset;
	struct sigaction sa;

	result = sigemptyset(&sigset);
	if(result == -1) {
		PERROR("sigemptyset");
		return 1;
	}
	sa.sa_handler = sigterm_handler;
	sa.sa_mask = sigset;
	sa.sa_flags = SA_RESTART;
	result = sigaction(SIGTERM, &sa, NULL);
	if(result == -1) {
		PERROR("sigaction");
		return 1;
	}

	result = ustcomm_init_ustd(&ustd, sock_path);
	if(result == -1) {
		ERR("failed to initialize socket");
		return 1;
	}

	/* setup handler for SIGPIPE */
	result = sigemptyset(&sigset);
	if(result == -1) {
		PERROR("sigemptyset");
		return 1;
	}
	result = sigaddset(&sigset, SIGPIPE);
	if(result == -1) {
		PERROR("sigaddset");
		return 1;
	}
	result = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if(result == -1) {
		PERROR("sigprocmask");
		return 1;
	}

	/* Write pidfile */
	if(pidfile) {
		result = write_pidfile(pidfile, getpid());
		if(result == -1) {
			ERR("failed to write pidfile");
			return 1;
		}
	}

	/* Notify parent that we are successfully started. */
	if(fd != -1) {
		/* write any one character */
		result = write(fd, "!", 1);
		if(result == -1) {
			PERROR("write");
			return -1;
		}
		if(result != 1) {
			ERR("Problem sending confirmation of daemon start to parent");
			return -1;
		}
		result = close(fd);
		if(result == -1) {
			PERROR("close");
		}
	}

	/* app loop */
	for(;;) {
		char *recvbuf;

		/* check for requests on our public socket */
		result = ustcomm_ustd_recv_message(&ustd, &recvbuf, NULL, 100);
		if(result == -1) {
			ERR("error in ustcomm_ustd_recv_message");
			goto loop_end;
		}
		if(result > 0) {
			if(!strncmp(recvbuf, "collect", 7)) {
				pid_t pid;
				char *bufname;
				int result;

				result = sscanf(recvbuf, "%*s %d %50as", &pid, &bufname);
				if(result != 2) {
					ERR("parsing error: %s", recvbuf);
					goto free_bufname;
				}

				result = start_consuming_buffer(pid, bufname);
				if(result < 0) {
					ERR("error in add_buffer");
					goto free_bufname;
				}

				free_bufname:
				free(bufname);
			}

			free(recvbuf);
		}

		loop_end:

		if(terminate_req) {
			pthread_mutex_lock(&active_buffers_mutex);
			if(active_buffers == 0) {
				pthread_mutex_unlock(&active_buffers_mutex);
				break;
			}
			pthread_mutex_unlock(&active_buffers_mutex);
		}
	}

	return 0;
}

int start_ustd_daemon()
{
	int result;
	int fd[2];
	pid_t child_pid;

	result = pipe(fd);

	result = child_pid = fork();
	if(result == -1) {
		PERROR("fork");
		return -1;
	}
	else if(result == 0) {
		return start_ustd(fd[1]);
	}
	else {
		char buf;

		result = read(fd[0], &buf, 1);
		if(result == -1) {
			PERROR("read");
			return -1;
		}
		if(result != 1) {
			ERR("did not receive valid confirmation that the daemon is started");
			return -1;
		}

		result = close(fd[0]);
		if(result == -1) {
			PERROR("close");
		}

		DBG("The daemon is now successfully started");
	}

	/* Wait for confirmation that the server is ready. */


	return 0;
}

int main(int argc, char **argv)
{
	int result;

	result = parse_args(argc, argv);
	if(result == -1) {
		exit(1);
	}

	if(daemon_mode) {
		result = start_ustd_daemon();
	}
	else {
		result = start_ustd(-1);
	}

	return result;
}
