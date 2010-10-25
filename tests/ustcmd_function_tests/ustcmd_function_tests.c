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

/* Simple function tests for ustcmd */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#include <ust/marker.h>
#include <ust/ustcmd.h>

#include "tap.h"

static void ustcmd_function_tests(pid_t pid)
{
	int result;
	unsigned int subbuf_size, subbuf_num;
	unsigned int new_subbuf_size, new_subbuf_num;
	struct marker_status *marker_status, *ms_ptr;
	char *old_socket_path, *new_socket_path;
	char *tmp_ustd_socket = "/tmp/tmp_ustd_socket";

	printf("Connecting to pid %d\n", pid);

	/* marker status array functions */
	result = ustcmd_get_cmsf(&marker_status, pid);
	tap_ok(!result, "ustcmd_get_cmsf");

	result = 0;
	for (ms_ptr = marker_status; ms_ptr->channel; ms_ptr++) {
		if (!strcmp(ms_ptr->channel, "ust") &&
		    !strcmp(ms_ptr->marker, "bar")) {
			result = 1;
		}
	}
	tap_ok(result, "Found channel \"ust\", marker \"bar\"");

	tap_ok(!ustcmd_free_cmsf(marker_status), "ustcmd_free_cmsf");

	/* Get and set the socket path */
	tap_ok(!ustcmd_get_sock_path(&old_socket_path, pid),
	       "ustcmd_get_sock_path");

	printf("Socket path: %s\n", old_socket_path);

	tap_ok(!ustcmd_set_sock_path(tmp_ustd_socket, pid),
	       "ustcmd_set_sock_path - set a new path");

	tap_ok(!ustcmd_get_sock_path(&new_socket_path, pid),
	       "ustcmd_get_sock_path - get the new path");

	tap_ok(!strcmp(new_socket_path, tmp_ustd_socket),
	       "Compare the set path and the retrieved path");

	free(new_socket_path);

	tap_ok(!ustcmd_set_sock_path(old_socket_path, pid),
	       "Reset the socket path");

	free(old_socket_path);

	/* Enable, disable markers */
	tap_ok(!ustcmd_set_marker_state("ust", "bar", 1, pid),
	       "ustcmd_set_marker_state - existing marker ust bar");

	/* Create and allocate a trace */
	tap_ok(!ustcmd_create_trace(pid), "ustcmd_create_trace");

	tap_ok(!ustcmd_alloc_trace(pid), "ustcmd_alloc_trace");

	/* Get subbuf size and number */
	subbuf_num = ustcmd_get_subbuf_num("ust", pid);
	tap_ok(subbuf_num > 0, "ustcmd_get_subbuf_num - %d sub-buffers",
	       subbuf_num);

	subbuf_size = ustcmd_get_subbuf_size("ust", pid);
	tap_ok(subbuf_size, "ustcmd_get_subbuf_size - sub-buffer size is %d",
	       subbuf_size);

	/* Start the trace */
	tap_ok(!ustcmd_start_trace(pid), "ustcmd_start_trace");


	/* Stop the trace and destroy it*/
	tap_ok(!ustcmd_stop_trace(pid), "ustcmd_stop_trace");

	tap_ok(!ustcmd_destroy_trace(pid), "ustcmd_destroy_trace");

	/* Create a new trace */
	tap_ok(!ustcmd_create_trace(pid), "ustcmd_create_trace - create a new trace");

	printf("Setting new subbufer number and sizes (doubling)\n");
	new_subbuf_num = 2 * subbuf_num;
	new_subbuf_size = 2 * subbuf_size;

	tap_ok(!ustcmd_set_subbuf_num("ust", new_subbuf_num, pid),
	       "ustcmd_set_subbuf_num");

	tap_ok(!ustcmd_set_subbuf_size("ust", new_subbuf_size, pid),
	       "ustcmd_set_subbuf_size");


	/* Allocate the new trace */
	tap_ok(!ustcmd_alloc_trace(pid), "ustcmd_alloc_trace - allocate the new trace");


        /* Get subbuf size and number and compare with what was set */
	subbuf_num = ustcmd_get_subbuf_num("ust", pid);

	subbuf_size = ustcmd_get_subbuf_size("ust", pid);

	tap_ok(subbuf_num == new_subbuf_num, "Set a new subbuf number, %d == %d",
	       subbuf_num, new_subbuf_num);


	result = ustcmd_get_subbuf_size("ust", pid);
	tap_ok(subbuf_size == new_subbuf_size, "Set a new subbuf size, %d == %d",
	       subbuf_size, new_subbuf_size);

	tap_ok(!ustcmd_destroy_trace(pid), "ustcmd_destroy_trace - without ever starting");


	printf("##### Tests that definetly should work are completed #####\n");
	printf("############## Start expected failure cases ##############\n");

	tap_ok(ustcmd_set_marker_state("ust","bar", 1, pid),
	       "Enable already enabled marker ust/bar");

	tap_ok(ustcmd_set_marker_state("ustl", "blar", 1, pid),
	       "Enable non-existent marker ustl blar");

	tap_ok(ustcmd_start_trace(pid),
	       "Start a non-existent trace");

	tap_ok(ustcmd_destroy_trace(pid),
	       "Destroy non-existent trace");

	exit(tap_status() ? EXIT_FAILURE : EXIT_SUCCESS);

}


int main()
{
	int i, status, pipefd[2];
	pid_t parent_pid, child_pid;
	FILE *pipe_file;

	tap_plan(27);

	printf("Function tests for ustcmd\n");

	parent_pid = getpid();
	child_pid = fork();
	if (child_pid) {
		for(i=0; i<10; i++) {
			trace_mark(ust, bar, "str %s", "FOOBAZ");
			trace_mark(ust, bar2, "number1 %d number2 %d", 53, 9800);
			usleep(100000);
		}

		wait(&status);
	} else {
		ustcmd_function_tests(parent_pid);
	}

	exit(status ? EXIT_FAILURE : EXIT_SUCCESS);
}
