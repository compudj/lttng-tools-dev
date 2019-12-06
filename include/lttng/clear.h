/*
 * Copyright (C) 2019 - Jérémie Galarneau <jeremie.galarneau@efficios.com>
 * Copyright (C) 2019 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef LTTNG_CLEAR_H
#define LTTNG_CLEAR_H

#include <lttng/lttng-error.h>

#ifdef __cplusplus
extern "C" {
#endif

struct lttng_clear_handle;

/*
 * Clear a tracing session.
 *
 * Clear the data buffers and trace data.
 *
 * For sessions saving trace data to disk and streaming over the network to a
 * relay daemon, the buffers content and existing stream files are cleared when
 * the clear command is issued.
 *
 * For snapshot sessions (flight recorder), only the buffer content is cleared.
 * Prior snapshots are individually recorded to disk, and are therefore
 * untouched by this "clear" command.
 *
 * For live sessions streaming over network to a relay daemon, the buffers
 * will be cleared, and the files on the relay daemon side will be cleared as
 * well. However, any active live trace viewer currently reading an existing
 * trace packet will be able to proceed to read that packet entirely before
 * skipping over cleared stream data.
 *
 * The clear command guarantees that no trace data preceding the instant it is
 * called will be in the resulting trace.
 *
 * Trace data produced from the moment it is called and when the
 * function returned might be present in the resulting trace.
 *
 * Provides an lttng_clear_handle which can be used to wait for the completion
 * of the session's clear.
 *
 * Return LTTNG_OK on success else a negative LTTng error code. The returned
 * handle is owned by the caller and must be free'd using
 * lttng_clear_handle_destroy().
 *
 * Important error codes:
 *    LTTNG_ERR_CLEAR_RELAY_DISALLOW
 *    LTTNG_ERR_CLEAR_NOT_AVAILABLE
 *    LTTNG_ERR_CLEAR_NOT_AVAILABLE_RELAY
 *    LTTNG_ERR_CLEAR_FAIL_CONSUMER
*/
extern enum lttng_error_code lttng_clear_session(const char *session_name,
		struct lttng_clear_handle **handle);

#endif /* LTTNG_CLEAR_H */
