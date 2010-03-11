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

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

#include <ust/marker.h>

int main(int argc, char **argv, char *env[])
{
	int result;

	if(argc < 2 ) {
		fprintf(stderr, "usage: fork PROG_TO_EXEC\n");
		exit(1);
	}

	printf("Fork test program, parent pid is %d\n", getpid());
	trace_mark(ust, before_fork, MARK_NOARGS);

	result = fork();
	if(result == -1) {
		perror("fork");
		return 1;
	}
	if(result == 0) {
		char *args[] = {"fork2", NULL};

		printf("Child pid is %d\n", getpid());

		trace_mark(ust, after_fork_child, MARK_NOARGS);

		trace_mark(ust, before_exec, "pid %d", getpid());

		result = execve(argv[1], args, env);
		if(result == -1) {
			perror("execve");
			return 1;
		}

		trace_mark(ust, after_exec, "pid %d", getpid());
	}
	else {
		trace_mark(ust, after_fork_parent, MARK_NOARGS);
	}

	return 0;
}
