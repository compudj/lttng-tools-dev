/*
 * Copyright (C) - 2012 David Goulet <dgoulet@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation; version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 */

#define _LGPL_SOURCE
#include <getopt.h>
#include <assert.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <signal.h>
#include <poll.h>
#include <errno.h>
#include "utils.h"
#include "signal-helper.h"

#define TRACEPOINT_DEFINE
#include "tp.h"

static struct option long_options[] =
{
	/* These options set a flag. */
	{"iter", required_argument, 0, 'i'},
	{"wait", required_argument, 0, 'w'},
	{"sync-after-first-event", required_argument, 0, 'a'},
	{"sync-before-last-event", required_argument, 0, 'b'},
	{0, 0, 0, 0}
};

int main(int argc, char **argv)
{
	unsigned int i, netint;
	int option_index;
	char option_char;
	long values[] = { 1, 2, 3 };
	char text[10] = "test";
	double dbl = 2.0;
	float flt = 2222.0;
	int nr_iter = 100, ret = 0, first_event_file_created = 0;
	useconds_t nr_usec = 0;
	char *after_first_event_file_path = NULL;
	char *before_last_event_file_path = NULL;

	while((option_char = getopt_long(argc, argv, "i:w:a:b:c:d:", long_options, &option_index)) != -1) {
		switch (option_char) {
		case 'a':
			after_first_event_file_path = strdup(optarg);
			break;
		case 'b':
			before_last_event_file_path = strdup(optarg);
			break;
		case 'i':
			nr_iter = atoi(optarg);
			break;
		case 'w':
			nr_usec = atoi(optarg);
			break;
		case '?':
			/* getopt_long already printed an error message. */
			break;
		default:
			ret = -1;
			goto end;
		}
	}

	if (optind != argc) {
		fprintf(stderr, "Error: takes long options only.\n");
		ret = -1;
		goto end;
	}


	if (set_signal_handler()) {
		ret = -1;
		goto end;
	}

	for (i = 0; nr_iter < 0 || i < nr_iter; i++) {
		if (nr_iter >= 0 && i == nr_iter - 1) {
			/*
			 * Wait on synchronization before writing last
			 * event.
			 */
			if (before_last_event_file_path) {
				ret = wait_on_file(before_last_event_file_path);
				if (ret != 0) {
					goto end;
				}
			}
		}
		netint = htonl(i);
		tracepoint(tp, tptest, i, netint, values, text,
			strlen(text), dbl, flt);

		/*
		 * First loop we create the file if asked to indicate
		 * that at least one tracepoint has been hit.
		 */
		if (after_first_event_file_path && first_event_file_created == 0) {
			ret = create_file(after_first_event_file_path);

			if (ret != 0) {
				goto end;
			} else {
				first_event_file_created = 1;
			}
		}

		if (nr_usec) {
		        if (usleep_safe(nr_usec)) {
				ret = -1;
				goto end;
			}
		}
		if (should_quit) {
			break;
		}
	}

end:
	free(after_first_event_file_path);
	free(before_last_event_file_path);
	exit(!ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
