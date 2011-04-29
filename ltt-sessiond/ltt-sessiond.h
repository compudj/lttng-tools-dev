/* Copyright (C) 2011 - David Goulet <david.goulet@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef _LTT_SESSIOND_H
#define _LTT_SESSIOND_H

#define DEFAULT_HOME_DIR			"/tmp"
#define DEFAULT_UST_SOCK_DIR		"/tmp/ust-app-socks"
#define DEFAULT_GLOBAL_APPS_PIPE	"/tmp/ust-app-socks/global"

extern const char default_home_dir[],
	default_tracing_group[],
	default_ust_sock_dir[],
	default_global_apps_pipe[];

/* LTTng trace representation */
struct ltt_lttng_trace {
	struct cds_list_head list;
	char trace_name[NAME_MAX];
	struct cds_list_head marker_list;
};

/* UST trace representation */
struct ltt_ust_trace {
	struct cds_list_head list;
	int shmid;
	pid_t pid;
	struct cds_list_head markers;
};

struct ltt_ust_marker {
	struct cds_list_head list;
	char *name;
	char *channel;
};

#endif /* _LTT_SESSIOND_H */
