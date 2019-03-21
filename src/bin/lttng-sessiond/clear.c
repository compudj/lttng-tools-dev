/*
 * Copyright (C) 2019 - Jonathan Rajotte <jonathan.rajotte-julien@efficios.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define _LGPL_SOURCE
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <common/defaults.h>
#include <common/error.h>
#include <common/utils.h>

#include "clear.h"
#include "session.h"
#include "ust-app.h"
#include "kernel.h"


int cmd_clear_session(struct ltt_session *session)
{
	int ret;

	if (!session->has_been_started) {
		 /* Nothing to be cleared, do not warn */
		 ret = LTTNG_OK;
		 goto end;
	}

	/*
	 * Unsupported feature in lttng-relayd before 2.12.
	 */
	if (session->consumer->type == CONSUMER_DST_NET &&
			(session->consumer->relay_major_version == 2 &&
			session->consumer->relay_minor_version < 12)) {
		ret = LTTNG_ERR_CLEAR_NOT_AVAILABLE_RELAY;
		goto end;
	}

	if (session->ust_session) {
		switch (session->ust_session->buffer_type) {
		case LTTNG_BUFFER_PER_PID:
			ERR("Clear command not supported for per-pid buffers.");
			ret = LTTNG_ERR_CLEAR_NOT_AVAILABLE;
			goto error;
		case LTTNG_BUFFER_PER_UID:
		case LTTNG_BUFFER_GLOBAL:
			break;
		}
	}

	/*
	 * Clear kernel and UST session buffers and local files (if any).
	 */
	if (session->kernel_session) {
		ret = kernel_clear_session(session);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}
	if (session->ust_session) {
		ret = ust_app_clear_session(session);
		if (ret != LTTNG_OK) {
			goto error;
		}
	}

	/*
	 * Clear remote (relayd) session files.
	 */
	ret = consumer_clear_session(session);
	if (ret < 0) {
		ret = LTTNG_ERR_CLEAR_FAIL_CONSUMER;
		goto error;
	}
	ret = LTTNG_OK;
error:
end:
	return ret;
}
