/* Copyright (C) 2009  Pierre-Marc Fournier
 *               2010  Alexis Halle
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
#include <signal.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <getopt.h>

#include "ust/ustconsumer.h"
#include "../libustconsumer/lowlevel.h"
#include "usterr.h"

char *sock_path=NULL;
char *trace_path=NULL;
int daemon_mode = 0;
char *pidfile = NULL;

struct ustconsumer_instance *instance;

struct buffer_info_local {
	/* output file */
	int file_fd;
	/* the offset we must truncate to, to unput the last subbuffer */
	off_t previous_offset;
};

static int write_pidfile(const char *file_name, pid_t pid)
{
	FILE *pidfp;

	pidfp = fopen(file_name, "w");
	if(!pidfp) {
		PERROR("fopen (%s)", file_name);
		WARN("killing child process");
		return -1;
	}

	fprintf(pidfp, "%d\n", pid);

	fclose(pidfp);

	return 0;
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

int unwrite_last_subbuffer(struct buffer_info *buf)
{
	int result;
	struct buffer_info_local *buf_local = buf->user_data;

	result = ftruncate(buf_local->file_fd, buf_local->previous_offset);
	if(result == -1) {
		PERROR("ftruncate");
		return -1;
	}

	result = lseek(buf_local->file_fd, buf_local->previous_offset, SEEK_SET);
	if(result == (int)(off_t)-1) {
		PERROR("lseek");
		return -1;
	}

	return 0;
}

int write_current_subbuffer(struct buffer_info *buf)
{
	int result;
	struct buffer_info_local *buf_local = buf->user_data;

	void *subbuf_mem = buf->mem + (buf->consumed_old & (buf->n_subbufs * buf->subbuf_size-1));

	size_t cur_sb_size = subbuffer_data_size(subbuf_mem);

	off_t cur_offset = lseek(buf_local->file_fd, 0, SEEK_CUR);
	if(cur_offset == (off_t)-1) {
		PERROR("lseek");
		return -1;
	}

	buf_local->previous_offset = cur_offset;
	DBG("previous_offset: %ld", cur_offset);

	result = patient_write(buf_local->file_fd, subbuf_mem, cur_sb_size);
	if(result == -1) {
		PERROR("write");
		return -1;
	}

	return 0;
}

int on_read_subbuffer(struct ustconsumer_callbacks *data, struct buffer_info *buf)
{
	return write_current_subbuffer(buf);
}

int on_read_partial_subbuffer(struct ustconsumer_callbacks *data, struct buffer_info *buf,
				long subbuf_index, unsigned long valid_length)
{
	struct buffer_info_local *buf_local = buf->user_data;
	char *tmp;
	int result;
	unsigned long pad_size;

	result = patient_write(buf_local->file_fd, buf->mem + subbuf_index * buf->subbuf_size, valid_length);
	if(result == -1) {
		ERR("Error writing to buffer file");
		return result;
	}

	/* pad with empty bytes */
	pad_size = PAGE_ALIGN(valid_length)-valid_length;
	if(pad_size) {
		tmp = zmalloc(pad_size);
		result = patient_write(buf_local->file_fd, tmp, pad_size);
		if(result == -1) {
			ERR("Error writing to buffer file");
			return result;
		}
		free(tmp);
	}
	return result;
}

int on_open_buffer(struct ustconsumer_callbacks *data, struct buffer_info *buf)
{
	char *tmp;
	int result;
	int fd;
	struct buffer_info_local *buf_local =
		zmalloc(sizeof(struct buffer_info_local));

	if(!buf_local) {
		ERR("could not allocate buffer_info_local struct");
		return 1;
	}

	buf->user_data = buf_local;

	/* open file for output */
	if(!trace_path) {
		/* Only create the directory if using the default path, because
		 * of the risk of typo when using trace path override. We don't
		 * want to risk creating plenty of useless directories in that case.
		 */
		result = create_dir_if_needed(USTCONSUMER_DEFAULT_TRACE_PATH);
		if(result == -1) {
			ERR("could not create directory %s", USTCONSUMER_DEFAULT_TRACE_PATH);
			return 1;
		}

		trace_path = USTCONSUMER_DEFAULT_TRACE_PATH;
	}

	if (asprintf(&tmp, "%s/%u_%lld", trace_path, buf->pid, buf->pidunique) < 0) {
		ERR("on_open_buffer : asprintf failed (%s/%u_%lld)",
		    trace_path, buf->pid, buf->pidunique);
		return 1;
	}
	result = create_dir_if_needed(tmp);
	if(result == -1) {
		ERR("could not create directory %s", tmp);
		free(tmp);
		return 1;
	}
	free(tmp);

	if (asprintf(&tmp, "%s/%u_%lld/%s", trace_path, buf->pid, buf->pidunique, buf->name) < 0) {
		ERR("on_open_buffer : asprintf failed (%s/%u_%lld/%s)",
		    trace_path, buf->pid, buf->pidunique, buf->name);
		return 1;
	}
	result = fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 00600);
	if(result == -1) {
		PERROR("open");
		ERR("failed opening trace file %s", tmp);
		return 1;
	}
	buf_local->file_fd = fd;
	free(tmp);

	return 0;
}

int on_close_buffer(struct ustconsumer_callbacks *data, struct buffer_info *buf)
{
	struct buffer_info_local *buf_local = buf->user_data;
	int result = close(buf_local->file_fd);
	free(buf_local);
	if(result == -1) {
		PERROR("close");
	}
	return 0;
}

int on_put_error(struct ustconsumer_callbacks *data, struct buffer_info *buf)
{
	return unwrite_last_subbuffer(buf);
}

struct ustconsumer_callbacks *new_callbacks()
{
	struct ustconsumer_callbacks *callbacks =
		zmalloc(sizeof(struct ustconsumer_callbacks));

	if(!callbacks)
		return NULL;

	callbacks->on_open_buffer = on_open_buffer;
	callbacks->on_close_buffer = on_close_buffer;
	callbacks->on_read_subbuffer = on_read_subbuffer;
	callbacks->on_read_partial_subbuffer = on_read_partial_subbuffer;
	callbacks->on_put_error = on_put_error;
	callbacks->on_new_thread = NULL;
	callbacks->on_close_thread = NULL;
	callbacks->on_trace_end = NULL;

	return callbacks;

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

void usage(void)
{
	fprintf(stderr, "Usage:\nust-consumerd OPTIONS\n\nOptions:\n"
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
	ustconsumer_stop_instance(instance, 0);
}

int start_ustconsumer(int fd)
{
	int result;
	sigset_t sigset;
	struct sigaction sa;

	struct ustconsumer_callbacks *callbacks = new_callbacks();
	if(!callbacks) {
		PERROR("new_callbacks");
		return 1;
	}

	result = sigemptyset(&sigset);
	if(result == -1) {
		PERROR("sigemptyset");
		return 1;
	}
	sa.sa_handler = sigterm_handler;
	sa.sa_mask = sigset;
	sa.sa_flags = 0;
	result = sigaction(SIGTERM, &sa, NULL);
	if(result == -1) {
		PERROR("sigaction");
		return 1;
	}
	result = sigaction(SIGINT, &sa, NULL);
	if(result == -1) {
		PERROR("sigaction");
		return 1;
	}

	instance = ustconsumer_new_instance(callbacks, sock_path);
	if(!instance) {
		ERR("failed to create ustconsumer instance");
		return 1;
	}

	result = ustconsumer_init_instance(instance);
	if(result) {
		ERR("failed to initialize ustconsumer instance");
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

	ustconsumer_start_instance(instance);

	free(callbacks);

	return 0;
}

int start_ustconsumer_daemon()
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
		return start_ustconsumer(fd[1]);
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
		result = start_ustconsumer_daemon();
	}
	else {
		result = start_ustconsumer(-1);
	}

	return result;
}
