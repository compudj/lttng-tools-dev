/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include <stdio.h>

#include <lttng/map/map-internal.h>

#include "common/argpar/argpar.h"
#include "common/argpar-utils/argpar-utils.h"

#include "../command.h"
#ifdef LTTNG_EMBED_HELP
static const char help_msg[] =
#include <lttng-disable-map.1.h>
;
#endif

enum {
	OPT_HELP,
	OPT_KERNEL,
	OPT_SESSION,
	OPT_USERSPACE,
};

static const
struct argpar_opt_descr disable_map_options[] = {
	{ OPT_HELP, 'h', "help", false },
	{ OPT_SESSION, 's', "session", true },
	{ OPT_USERSPACE, 'u', "userspace", false },
	{ OPT_KERNEL, 'k', "kernel", false },
	ARGPAR_OPT_DESCR_SENTINEL,
};

static
bool assign_string(char **dest, const char *src, const char *opt_name)
{
	bool ret;

	if (*dest) {
		ERR("Duplicate %s given.", opt_name);
		goto error;
	}

	*dest = strdup(src);
	if (!*dest) {
		ERR("Failed to allocate %s string.", opt_name);
		goto error;
	}

	ret = true;
	goto end;

error:
	ret = false;

end:
	return ret;
}

int cmd_disable_map(int argc, const char **argv)
{
	int ret;
	struct argpar_iter *argpar_iter = NULL;
	const struct argpar_item *argpar_item = NULL;
	const char *opt_map_name = NULL;
	enum lttng_error_code error_code_ret;
	bool opt_userspace = false, opt_kernel = false, found = false;
	char *opt_session_name = NULL, *session_name = NULL;
	struct lttng_domain dom = {};
	struct lttng_handle *handle;
	const struct lttng_map *map = NULL;
	enum lttng_map_status map_status;
	struct lttng_map_list *map_list = NULL;

	argc--;
	argv++;

	argpar_iter = argpar_iter_create(argc, argv, disable_map_options);
	if (!argpar_iter) {
		ERR("Failed to allocate an argpar iter.");
		goto error;
	}

	while (true) {
		enum parse_next_item_status status;
		status = parse_next_item(argpar_iter, &argpar_item, 1, argv,
				true, NULL, NULL);
		if (status == PARSE_NEXT_ITEM_STATUS_ERROR) {
			goto error;
		} else if (status == PARSE_NEXT_ITEM_STATUS_END) {
			break;
		}

		assert(status == PARSE_NEXT_ITEM_STATUS_OK);

		if (argpar_item_type(argpar_item) == ARGPAR_ITEM_TYPE_OPT) {
				const struct argpar_opt_descr *descr =
				argpar_item_opt_descr(argpar_item);
			const char *arg = argpar_item_opt_arg(argpar_item);

			switch (descr->id) {
			case OPT_HELP:
				SHOW_HELP();
				ret = 0;
				goto end;
			case OPT_SESSION:
				if (!assign_string(&opt_session_name, arg,
						"-s/--session")) {
					goto error;
				}
				break;
			case OPT_USERSPACE:
				opt_userspace = true;
				break;
			case OPT_KERNEL:
				opt_kernel = true;
				break;
			default:
				abort();
			}

		} else if (opt_map_name) {
			ERR("Unexpected argument: %s",
					argpar_item_non_opt_arg(argpar_item));
			goto error;
		} else {
			opt_map_name = argpar_item_non_opt_arg(argpar_item);
		}
	}

	if (!opt_map_name) {
		ERR("Missing `name` argument.");
		goto error;
	}

	if (!opt_session_name) {
		session_name = get_session_name();
		if (session_name == NULL) {
			goto error;
		}
	} else {
		session_name = opt_session_name;
	}

	/* Check that one and only one domain option was provided. */
	ret = print_missing_or_multiple_domains(
			opt_kernel + opt_userspace, false);
	if (ret) {
		goto error;
	}

	if (opt_kernel) {
		dom.type = LTTNG_DOMAIN_KERNEL;
		dom.buf_type = LTTNG_BUFFER_GLOBAL;
	} else {
		dom.type=LTTNG_DOMAIN_UST;
		dom.buf_type = LTTNG_BUFFER_PER_UID;
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	error_code_ret = lttng_list_maps(handle, &map_list);
	if (error_code_ret != LTTNG_OK) {
		ERR("Error getting map list");
		ret = CMD_ERROR;
		goto end;
	}

	for_each_map_const(map, map_list) {
		const char *map_name = NULL;

		map_status = lttng_map_get_name(map, &map_name);
		if (map_status != LTTNG_MAP_STATUS_OK) {
			ERR("Error getting map name");
			ret = CMD_ERROR;
			goto end;
		}

		if (opt_map_name != NULL) {
			if (strncmp(map_name, opt_map_name, NAME_MAX) == 0) {

				error_code_ret = lttng_disable_map(handle, map);
				if (error_code_ret != LTTNG_OK) {
					ERR("Error disabling map \"%s\"", opt_map_name);
					goto error;
				}

				found = true;
				break;
			}
		}
	}
	if (found) {
		MSG("Disabled map `%s`.", opt_map_name);
		ret = CMD_SUCCESS;
	} else {
		MSG("Map `%s` not found.", opt_map_name);
		ret = CMD_ERROR;
	}


	goto end;

error:
	ret = CMD_ERROR;

end:
	argpar_item_destroy(argpar_item);
	argpar_iter_destroy(argpar_iter);

	return ret;
}
