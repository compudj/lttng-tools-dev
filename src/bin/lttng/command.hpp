/*
 * SPDX-FileCopyrightText: 2011 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef _LTTNG_CMD_H
#define _LTTNG_CMD_H

#include "conf.hpp"
#include "exception.hpp"
#include "utils.hpp"

#include <common/common.hpp>
#include <common/defaults.hpp>

#include <lttng/lttng.h>

#define DECL_COMMAND(_name) extern int cmd_##_name(int, const char **)

#ifdef LTTNG_EMBED_HELP
#define HELP_MSG_NAME	     help_msg
#define SHOW_HELP_ERROR_LINE ERR("Cannot show --help for `lttng-%s`", argv[0]);
#else
#define HELP_MSG_NAME	     NULL
#define SHOW_HELP_ERROR_LINE ;
#endif

#define SHOW_HELP()                                          \
	do {                                                 \
		ret = show_cmd_help(argv[0], HELP_MSG_NAME); \
                                                             \
		if (ret) {                                   \
			SHOW_HELP_ERROR_LINE                 \
			ret = CMD_ERROR;                     \
		}                                            \
	} while (0)

#define SHOW_HELP_THROW(cmd_name)                                                       \
	do {                                                                            \
		const auto _show_cmd_help_ret = show_cmd_help(cmd_name, HELP_MSG_NAME); \
                                                                                        \
		if (_show_cmd_help_ret) {                                               \
			LTTNG_THROW_CLI_SHOW_HELP_FAIL(cmd_name);                       \
		}                                                                       \
	} while (0)

enum cmd_error_code {
	CMD_SUCCESS = 0,
	CMD_ERROR,
	CMD_UNDEFINED,
	CMD_FATAL,
	CMD_WARNING,
	CMD_UNSUPPORTED,
};

struct cmd_struct {
	const char *name;
	int (*func)(int argc, const char **argv);
};

/*
 * How long `--wait` waits for a state dump, in seconds, when no
 * `--timeout` says otherwise.
 */
#define DEFAULT_STATEDUMP_WAIT_TIMEOUT_S 2.0

/*
 * Wait until no state dump which the session named `session_name` asked
 * for is outstanding, or until `timeout_s` seconds have elapsed,
 * whichever comes first.
 *
 * The waiting is done here, and not by the session daemon, because
 * nothing bounds how long an application takes to describe its own
 * state: an application which dumps by polling does so whenever its
 * event loop next runs its pending requests. A daemon which waited
 * would hold the locks every other session command needs for a length
 * of time an application chooses. Whoever asked to wait owns the
 * timeout, and waits from this side of the socket.
 *
 * Returns CMD_SUCCESS once nothing is outstanding, CMD_WARNING if the
 * timeout expired first, and CMD_ERROR if the session could not be
 * asked. Expiry is not an error: it is the ordinary outcome for an
 * application which has not reached its next poll.
 */
enum cmd_error_code wait_for_statedump(const char *session_name, double timeout_s);

DECL_COMMAND(list);
DECL_COMMAND(status);
DECL_COMMAND(create);
DECL_COMMAND(destroy);
DECL_COMMAND(start);
DECL_COMMAND(stop);
DECL_COMMAND(enable_events);
DECL_COMMAND(disable_events);
DECL_COMMAND(enable_channels);
DECL_COMMAND(disable_channels);
DECL_COMMAND(add_context);
DECL_COMMAND(set_session);
DECL_COMMAND(version);
DECL_COMMAND(view);
DECL_COMMAND(snapshot);
DECL_COMMAND(save);
DECL_COMMAND(load);
DECL_COMMAND(track);
DECL_COMMAND(untrack);
DECL_COMMAND(metadata);
DECL_COMMAND(regenerate);
DECL_COMMAND(rotate);
DECL_COMMAND(enable_rotation);
DECL_COMMAND(disable_rotation);
DECL_COMMAND(clear);
DECL_COMMAND(add_trigger);
DECL_COMMAND(list_triggers);
DECL_COMMAND(remove_trigger);
DECL_COMMAND(reclaim_memory);
DECL_COMMAND(add_map_channel);
DECL_COMMAND(show_maps);
DECL_COMMAND(export_maps);

extern int cmd_help(int argc, const char **argv, const struct cmd_struct commands[]);

#endif /* _LTTNG_CMD_H */
