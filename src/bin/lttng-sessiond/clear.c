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
#include "cmd.h"

struct cmd_clear_session_reply_context {
	int reply_sock_fd;
};

static
void cmd_clear_session_reply(const struct ltt_session *session,
		void *_reply_context)
{
	int ret;
	ssize_t comm_ret;
	const struct cmd_clear_session_reply_context *reply_context =
			_reply_context;
	struct lttng_dynamic_buffer payload;
	struct lttcomm_lttng_msg llm = {
		.cmd_type = LTTNG_CLEAR_SESSION,
		.ret_code = LTTNG_OK,
		.pid = UINT32_MAX,
		.cmd_header_size = 0,
		.data_size = 0,
	};

	lttng_dynamic_buffer_init(&payload);

	ret = lttng_dynamic_buffer_append(&payload, &llm, sizeof(llm));
        if (ret) {
		ERR("Failed to append session destruction message");
		goto error;
        }

	DBG("REPLY CLEAR COMPLETE");
	comm_ret = lttcomm_send_unix_sock(reply_context->reply_sock_fd,
			payload.data, payload.size);
	if (comm_ret != (ssize_t) payload.size) {
		ERR("Failed to send result of session \"%s\" clear to client",
				session->name);
	}
error:
	ret = close(reply_context->reply_sock_fd);
	if (ret) {
		PERROR("Failed to close client socket in deferred session clear reply");
	}
	lttng_dynamic_buffer_reset(&payload);
	free(_reply_context);
}

int cmd_clear_session(struct ltt_session *session, int *sock_fd)
{
	int ret = LTTNG_OK;
	struct cmd_clear_session_reply_context *reply_context = NULL;
	bool session_was_active = false;
	struct ltt_kernel_session *ksession;
	struct ltt_ust_session *usess;

	ksession = session->kernel_session;
	usess = session->ust_session;

	if (sock_fd) {
		reply_context = zmalloc(sizeof(*reply_context));
		if (!reply_context) {
			ret = LTTNG_ERR_NOMEM;
			goto end;
		}
		reply_context->reply_sock_fd = *sock_fd;
	}

	if (!session->has_been_started) {
		 /* Nothing to be cleared, do not warn */
		 goto end;
	}

	//TODO: 2.12
	/* Unsupported feature in lttng-relayd before 2.11. */
	if (session->consumer->type == CONSUMER_DST_NET &&
			(session->consumer->relay_major_version == 2 &&
			session->consumer->relay_minor_version < 11)) {
		ret = LTTNG_ERR_CLEAR_NOT_AVAILABLE_RELAY;
		goto end;
	}

	/*
	 * After a stop followed by a clear, all subsequent clear are
	 * effect-less until start is performed.
	 */
	if (session->cleared_after_last_stop) {
		ret = LTTNG_OK;
		goto end;
	}

	/*
	 * After a stop followed by a rotation, all subsequent clear are effect-less
	 * until start is performed.
	 */
	if (session->rotated_after_last_stop) {
		ret = LTTNG_OK;
		goto end;
	}

	if (!session->active) {
		session->cleared_after_last_stop = true;
	}

	session_was_active = session->active;
	if (session_was_active) {
		struct ltt_kernel_channel *kchan;

		/* Kernel tracer */
		if (ksession && ksession->active) {
			DBG("Stop kernel tracing");

			ret = kernel_stop_session(ksession);
			if (ret < 0) {
				ret = LTTNG_ERR_KERN_STOP_FAIL;
				goto end;
			}

			kernel_wait_quiescent();

			/* Flush metadata after stopping (if exists) */
			if (ksession->metadata_stream_fd >= 0) {
				ret = kernel_metadata_flush_buffer(ksession->metadata_stream_fd);
				if (ret < 0) {
					ERR("Kernel metadata flush failed");
					ret = LTTNG_ERR_UST_STOP_FAIL;
					goto end;
				}
			}

			/* Flush all buffers after stopping */
			cds_list_for_each_entry(kchan, &ksession->channel_list.head, list) {
				ret = kernel_flush_buffer(kchan);
				if (ret < 0) {
					ERR("Kernel flush buffer error");
					ret = LTTNG_ERR_UST_STOP_FAIL;
					goto end;
				}
			}

			ksession->active = 0;
			DBG("Kernel session stopped %s (id %" PRIu64 ")", session->name,
					session->id);
		}

		if (usess && usess->active) {
			ret = ust_app_stop_trace_all(usess);
			if (ret < 0) {
				ret = LTTNG_ERR_UST_STOP_FAIL;
				goto end;
			}
		}
	}

	/*
	 * Clear active kernel and UST session buffers.
	 */
	if (session->kernel_session) {
		ret = kernel_clear_session(session);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}
	if (session->ust_session) {
		ret = ust_app_clear_session(session);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}

	if (session->output_traces) {
		/*
		 * Use rotation to delete local and remote stream files.
		 */
		if (reply_context) {
			ret = session_add_clear_notifier(session,
					cmd_clear_session_reply,
					(void *) reply_context);
			if (ret) {
				ret = LTTNG_ERR_FATAL;
				goto end;
			}
			/*
			 * On success, ownership of reply_context has been
			 * passed to session_add_clear_notifier().
			 */
			reply_context = NULL;
			*sock_fd = -1;
		}
		ret = cmd_rotate_session(session, NULL, true,
			LTTNG_TRACE_CHUNK_COMMAND_TYPE_DELETE);
		if (ret != LTTNG_OK) {
			goto end;
		}
	}
	if (session_was_active) {
		/* Kernel tracing */
		if (ksession != NULL) {
			DBG("Start kernel tracing session %s", session->name);
			ret = start_kernel_session(ksession);
			if (ret != LTTNG_OK) {
				goto end;
			}
		}

		/* Flag session that trace should start automatically */
		if (usess) {
			int int_ret = ust_app_start_trace_all(usess);

			if (int_ret < 0) {
				ret = LTTNG_ERR_UST_START_FAIL;
				goto end;
			}
		}
	}
	ret = LTTNG_OK;
end:
	free(reply_context);
	return ret;
}
