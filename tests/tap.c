/* Copyright (C) 2010 Nils Carlson
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
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

static int tap_planned = -1;
static int tap_count = 1;
static int tap_passed = 0;

static pthread_t stdout_thread;
static int pipefd[2];
static FILE *pipe_r_file;
static FILE *normal_stdout;

static void *_tap_comment_stdout(void *_unused)
{
	char line[4096];

	while (fgets(&line[0], 4096, pipe_r_file)) {
		if (strncmp(line, "_TAP", 4)) {
			fprintf(normal_stdout, "# %s", line);
		} else {
			fprintf(normal_stdout, &line[4]);
		}
	}
	pthread_exit(0);
}

static void tap_comment_stdout(void)
{
	int stdout_fileno, new_stdout, result, fd;

	if (pipe(pipefd) < 0) {
		perror("# Failed to open pipe");
		return;
	}

	pipe_r_file = fdopen(pipefd[0], "r");
	if (!pipe_r_file) {
		perror("# Couldn't create a FILE from the pipe");
		goto close_pipe;
	}

	stdout_fileno = fileno(stdout);
	if (stdout_fileno < 0) {
		perror("# Couldn't get fileno for stdout!?");
		goto close_pipe_r_file;
	}

	new_stdout = dup(stdout_fileno);
	if (new_stdout < 0) {
		perror("# Couldn't dup stdout");
		goto close_pipe_r_file;
	}

	normal_stdout = fdopen(new_stdout, "w");
	if (!normal_stdout) {
		perror("# Could create a FILE from new_stdout");
		goto close_dup_stdout;
	}

	result = pthread_create(&stdout_thread, NULL,
				_tap_comment_stdout, NULL);
	if (result < 0) {
		perror("# Couldn't start stdout_thread");
		goto close_normal_stdout;
	}

	fclose(stdout);
	fclose(stderr);

	fd = dup(pipefd[1]);
	if (fd != STDOUT_FILENO) {
		fprintf(stderr, "# Failed to open a new stdout!\n");
		goto close_normal_stdout;
	}

	stdout = fdopen(fd, "w");
	if (!stdout) {
		perror("Couldn't open a new stdout");
		goto close_fd;
	}

	fd = dup(pipefd[1]);
	if (fd != STDERR_FILENO) {
		fprintf(stderr, "# Failed to open a new stderr!\n");
		goto close_fd;
	}

	stderr = fdopen(fd, "w");
	if (!stderr) {
		perror("Couldn't open a new stderr");
		goto close_fd;
	}

	setlinebuf(stdout);
	setlinebuf(stderr);
	setlinebuf(pipe_r_file);

	return;

close_fd:
	close(fd);

close_normal_stdout:
	fclose(normal_stdout);

close_dup_stdout:
	close(new_stdout);

close_pipe_r_file:
	fclose(pipe_r_file);

close_pipe:
	close(pipefd[0]);
	close(pipefd[1]);

	return;
}

void tap_plan(int count)
{
	printf("1..%d\n", count);

	tap_count = 1;
	tap_planned = count;

	tap_comment_stdout();

}

int tap_status(void)
{
	if (tap_passed == tap_planned) {
		return 0;
	} else {
		return 1;
	}
}

void tap_ok(int bool, const char *format, ...)
{
	va_list args;
	char *ok_string = "_TAPok";
	char *not_ok_string = "_TAPnot ok";
	char string[4000];

	va_start(args, format);
	vsprintf(string, format, args);
	va_end(args);

	printf("%s %d - %s\n", bool ? ok_string : not_ok_string,
	       tap_count++, string);

	if (bool)
		tap_passed++;
}
