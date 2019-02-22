/*
 * Copyright (C) 2009  Pierre-Marc Fournier
 * Copyright (C) 2011  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; version 2.1 of
 * the License.
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
#include <sys/wait.h>
#include <stdlib.h>
#include "utils.h"

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "ust_tests_fork.h"

int main(int argc, char **argv, char *env[])
{
	int result;
	char *after_fork_child_file_path = NULL;
	char *after_tracing_start_path = NULL;

	if (argc < 4) {
		fprintf(stderr, "usage: fork PROG_TO_EXEC PATH_TO_AFTER_FORK_FILE AFTER_TRACING_START_FILE\n");
		exit(1);
	}

	after_fork_child_file_path = argv[2];
	after_tracing_start_path = argv[3];

	printf("parent_pid %d\n", getpid());
	fflush(stdout);

	result = fork();
	if (result == -1) {
		perror("fork");
		return 1;
	}
	if (result == 0) {
		char *args[] = { "fork2", NULL };

		if (after_fork_child_file_path) {
			int ret;

			ret = create_file(after_fork_child_file_path);
			if (ret != 0) {
				exit(1);
			}
		}

		if (after_tracing_start_path) {
			int ret;

			ret = wait_on_file(after_tracing_start_path);
			if (ret != 0) {
				exit(1);
			}
		}

		tracepoint(ust_tests_fork, after_fork_child, getpid());

		result = execve(argv[1], args, env);
		if (result == -1) {
			perror("execve");
			result = 1;
			goto end;
		}
	} else {
		printf("child_pid %d\n", result);
		fflush(stdout);
		if (waitpid(result, NULL, 0) < 0) {
			perror("waitpid");
			result = 1;
			goto end;
		}
		tracepoint(ust_tests_fork, after_child_wait_parent, getpid());
	}
	result = 0;
end:
	return result;
}
