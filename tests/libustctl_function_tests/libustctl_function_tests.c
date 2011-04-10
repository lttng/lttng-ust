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

/* Simple function tests for ustctl */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

#include <ust/marker.h>
#include <ust/ustctl.h>

#include "tap.h"

static void ustctl_function_tests(pid_t pid)
{
	int result, sock;
	unsigned int subbuf_size, subbuf_num;
	unsigned int new_subbuf_size, new_subbuf_num;
	struct marker_status *marker_status, *ms_ptr;
	char *old_socket_path, *new_socket_path;
	char *tmp_ustd_socket = "/tmp/tmp_ustd_socket";
	char *trace = "auto";

	printf("Connecting to pid %d\n", pid);

	sock = ustctl_connect_pid(pid);
	tap_ok(sock > 0, "ustctl_connect_pid");

	/* marker status array functions */
	result = ustctl_get_cmsf(sock, &marker_status);
	tap_ok(!result, "ustctl_get_cmsf");

	result = 0;
	for (ms_ptr = marker_status; ms_ptr->channel; ms_ptr++) {
		if (!strcmp(ms_ptr->channel, "ust") &&
		    !strcmp(ms_ptr->marker, "bar")) {
			result = 1;
		}
	}
	tap_ok(result, "Found channel \"ust\", marker \"bar\"");

	tap_ok(!ustctl_free_cmsf(marker_status), "ustctl_free_cmsf");

	/* Get and set the socket path */
	tap_ok(!ustctl_get_sock_path(sock, &old_socket_path),
	       "ustctl_get_sock_path");

	printf("Socket path: %s\n", old_socket_path);

	tap_ok(!ustctl_set_sock_path(sock, tmp_ustd_socket),
	       "ustctl_set_sock_path - set a new path");

	tap_ok(!ustctl_get_sock_path(sock, &new_socket_path),
	       "ustctl_get_sock_path - get the new path");

	tap_ok(!strcmp(new_socket_path, tmp_ustd_socket),
	       "Compare the set path and the retrieved path");

	free(new_socket_path);

	tap_ok(!ustctl_set_sock_path(sock, old_socket_path),
	       "Reset the socket path");

	free(old_socket_path);

	/* Enable, disable markers */
	tap_ok(!ustctl_set_marker_state(sock, trace, "ust", "bar", 1),
	       "ustctl_set_marker_state - existing marker ust bar");

	/* Create and allocate a trace */
	tap_ok(!ustctl_create_trace(sock, trace), "ustctl_create_trace");

	tap_ok(!ustctl_alloc_trace(sock, trace), "ustctl_alloc_trace");

	/* Get subbuf size and number */
	subbuf_num = ustctl_get_subbuf_num(sock, trace, "ust");
	tap_ok(subbuf_num > 0, "ustctl_get_subbuf_num - %d sub-buffers",
	       subbuf_num);

	subbuf_size = ustctl_get_subbuf_size(sock, trace, "ust");
	tap_ok(subbuf_size, "ustctl_get_subbuf_size - sub-buffer size is %d",
	       subbuf_size);

	/* Start the trace */
	tap_ok(!ustctl_start_trace(sock, trace), "ustctl_start_trace");


	/* Stop the trace and destroy it*/
	tap_ok(!ustctl_stop_trace(sock, trace), "ustctl_stop_trace");

	tap_ok(!ustctl_destroy_trace(sock, trace), "ustctl_destroy_trace");

	/* Create a new trace */
	tap_ok(!ustctl_create_trace(sock, trace), "ustctl_create_trace - create a new trace");

	printf("Setting new subbufer number and sizes (doubling)\n");
	new_subbuf_num = 2 * subbuf_num;
	new_subbuf_size = 2 * subbuf_size;

	tap_ok(!ustctl_set_subbuf_num(sock, trace, "ust", new_subbuf_num),
	       "ustctl_set_subbuf_num");

	tap_ok(!ustctl_set_subbuf_size(sock, trace, "ust", new_subbuf_size),
	       "ustctl_set_subbuf_size");


	/* Allocate the new trace */
	tap_ok(!ustctl_alloc_trace(sock, trace), "ustctl_alloc_trace - allocate the new trace");


        /* Get subbuf size and number and compare with what was set */
	subbuf_num = ustctl_get_subbuf_num(sock, trace, "ust");

	subbuf_size = ustctl_get_subbuf_size(sock, trace, "ust");

	tap_ok(subbuf_num == new_subbuf_num, "Set a new subbuf number, %d == %d",
	       subbuf_num, new_subbuf_num);


	result = ustctl_get_subbuf_size(sock, trace, "ust");
	tap_ok(subbuf_size == new_subbuf_size, "Set a new subbuf size, %d == %d",
	       subbuf_size, new_subbuf_size);

	tap_ok(!ustctl_destroy_trace(sock, trace), "ustctl_destroy_trace - without ever starting");

	/*
	 * Activate a non-existent marker, this should be possible as the marker
	 * can be loaded at a later time.
	 */
	tap_ok(ustctl_set_marker_state(sock, trace, "ustl", "blar", 1) == 0,
	       "Enable non-existent marker ustl blar");

	printf("##### Tests that definetly should work are completed #####\n");
	printf("############## Start expected failure cases ##############\n");

	tap_ok(ustctl_set_marker_state(sock, trace, "ust","bar", 1),
	       "Enable already enabled marker ust/bar");

	tap_ok(EEXIST == errno,
	       "Right error code for enabling an already enabled marker");

	tap_ok(ustctl_start_trace(sock, trace),
	       "Start a non-existent trace");

	tap_ok(ustctl_destroy_trace(sock, trace),
	       "Destroy non-existent trace");

	exit(tap_status() ? EXIT_FAILURE : EXIT_SUCCESS);

}

int main(int argc, char **argv)
{
	int i, status;
	pid_t parent_pid, child_pid;

	tap_plan(29);

	printf("Function tests for ustctl\n");

	parent_pid = getpid();
	child_pid = fork();
	if (child_pid) {
		for(i=0; i<10; i++) {
			trace_mark(bar, "str %s", "FOOBAZ");
			trace_mark(bar2, "number1 %d number2 %d", 53, 9800);
			usleep(100000);
		}

		wait(&status);
	} else {
		ustctl_function_tests(parent_pid);
	}

	exit(status ? EXIT_FAILURE : EXIT_SUCCESS);
}
