#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

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

MARKER_LIB;
