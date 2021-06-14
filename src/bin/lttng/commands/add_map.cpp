/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#define _LGPL_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <lttng/map/map.h>

#include "common/argpar/argpar.h"
#include "common/argpar-utils/argpar-utils.h"
#include "common/utils.h"

#include "../command.h"
#include "../utils.h"

#define LTTNG_MAP_DEFAULT_SIZE 4096

enum {
	OPT_HELP,
	OPT_SESSION,
	OPT_USERSPACE,
	OPT_KERNEL,
	OPT_MAX_KEY_COUNT,
	OPT_PER_PID,
	OPT_PER_UID,
	OPT_BITNESS,
	OPT_COALESCE_HITS,
};

static const struct argpar_opt_descr add_map_opt_descrs[] = {

	{ OPT_HELP, 'h', "help", false },
	{ OPT_SESSION, 's', "session", true },
	{ OPT_USERSPACE, 'u', "userspace", false },
	{ OPT_KERNEL, 'k', "kernel", false },
	{ OPT_MAX_KEY_COUNT, '\0', "max-key-count", true},
	{ OPT_PER_PID, '\0', "per-pid", false},
	{ OPT_PER_UID, '\0', "per-uid", false},
	{ OPT_BITNESS, '\0', "bitness", true},
	{ OPT_COALESCE_HITS, '\0', "coalesce-hits", false},
	ARGPAR_OPT_DESCR_SENTINEL
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

int cmd_add_map(int argc, const char **argv)
{
	int ret;
	struct argpar_iter *argpar_iter = NULL;
	const struct argpar_item *argpar_item = NULL;
	enum lttng_error_code error_code_ret;
	bool opt_userspace = false, opt_kernel = false, opt_buffers_uid = false,
		opt_buffers_pid = false, opt_coalesce_hits = false;
	char *opt_session_name = NULL, *session_name = NULL, *opt_max_key_count = NULL, *opt_bitness = NULL;
	const char *opt_map_name = NULL;;
	enum lttng_map_bitness bitness_type;
	enum lttng_map_boundary_policy boundary_policy;
	enum lttng_map_status map_status;
	uint64_t dimensions_sizes[1] = {0};
	unsigned long long bitness;
	struct lttng_map *map;
	struct lttng_domain dom = {};
	struct lttng_handle *handle = NULL;

	argc--;
	argv++;

	argpar_iter = argpar_iter_create(argc, argv, add_map_opt_descrs);
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
				ret = CMD_SUCCESS;
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
			case OPT_MAX_KEY_COUNT:
				if (!assign_string(&opt_max_key_count, arg,
						"--max-key-count")) {
					goto error;
				}
				break;
			case OPT_PER_PID:
				opt_buffers_pid = true;
				break;
			case OPT_PER_UID:
				opt_buffers_uid = true;
				break;
			case OPT_BITNESS:
				if (!assign_string(&opt_bitness, arg,
						"--bitness")) {
					goto error;
				}
				break;
			case OPT_COALESCE_HITS:
				opt_coalesce_hits = true;
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
		ERR("Missing map name");
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
		if (opt_buffers_uid || opt_buffers_pid) {
			ERR("Buffer type not supported for kernel domain");
			goto error;
		}
		dom.buf_type = LTTNG_BUFFER_GLOBAL;
	} else {
		dom.type = LTTNG_DOMAIN_UST;

		if (opt_buffers_uid && opt_buffers_pid) {
			ERR("Only one domain can be specified");
			goto error;
		}
		if (opt_buffers_pid) {
			dom.buf_type = LTTNG_BUFFER_PER_PID;
		} else {
			/* Defaults to per UID */
			dom.buf_type = LTTNG_BUFFER_PER_UID;
		}
	}

	handle = lttng_create_handle(session_name, &dom);
	if (handle == NULL) {
		ret = -1;
		goto error;
	}

	if (opt_max_key_count) {
		unsigned long long max_key_count;
		if (utils_parse_unsigned_long_long(opt_max_key_count, &max_key_count) != 0) {
			ERR("Failed to parse `%s` as an integer.", opt_max_key_count);
			goto error;
		}

		dimensions_sizes[0] = max_key_count;
	} else {
		dimensions_sizes[0] = LTTNG_MAP_DEFAULT_SIZE;
	}

	if (opt_bitness) {
		if (utils_parse_unsigned_long_long(opt_bitness, &bitness) != 0) {
			ERR("Failed to parse `%s` as an integer.", opt_bitness);
			goto error;
		}
		switch (bitness) {
		case 32:
			bitness_type = LTTNG_MAP_BITNESS_32BITS;
			break;
		case 64:
			bitness_type = LTTNG_MAP_BITNESS_64BITS;
			break;
		default:
			ERR("Bitness %llu not supported", bitness);
			goto error;
		}

	} else {
		bitness_type = LTTNG_MAP_BITNESS_64BITS;
	}

	/*
	 * Currently, the only boundary policy supported by the tracers is
	 * overflow.
	 */
	boundary_policy = LTTNG_MAP_BOUNDARY_POLICY_OVERFLOW;

	map_status = lttng_map_create(opt_map_name, 1, dimensions_sizes, dom.type,
			dom.buf_type, bitness_type, boundary_policy,
			opt_coalesce_hits, &map);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Creating map \"%s\"", opt_map_name);
		goto error;
	}

	error_code_ret = lttng_add_map(handle, map);
	if (error_code_ret != LTTNG_OK) {
		ERR("Adding map \"%s\": %s", opt_map_name,
				lttng_strerror(error_code_ret));
		lttng_map_destroy(map);
		goto error;
	}

	MSG("Map %s created.", opt_map_name);
	ret = CMD_SUCCESS;

	lttng_map_destroy(map);

	goto end;

error:
	ret = CMD_ERROR;
end:
	if (!opt_session_name) {
		free(session_name);
	}

	argpar_item_destroy(argpar_item);
	argpar_iter_destroy(argpar_iter);
	free(opt_session_name);
	free(opt_max_key_count);
	free(opt_bitness);
	lttng_destroy_handle(handle);
	return ret;
}
