/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#include "lttng/domain.h"
#include <common/kernel-ctl/kernel-ctl.h>
#include <lttng/map/map.h>
#include <lttng/map/map-content-internal.h>
#include <lttng/map/map-internal.h>

#include "lttng-sessiond.h"
#include "lttng-ust-error.h"
#include "notification-thread-commands.h"
#include "trace-kernel.h"
#include "trace-ust.h"

#include "map.h"

enum lttng_error_code map_kernel_add(struct ltt_kernel_session *ksession,
		struct lttng_map *map)
{
	int ret, fd;
	enum lttng_error_code ret_code;
	struct ltt_kernel_map *kmap;
	enum lttng_map_status map_status;
	const char *map_name;

	assert(lttng_map_get_domain(map) == LTTNG_DOMAIN_KERNEL);

	map_status = lttng_map_get_name(map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Can't get map name");
		ret_code = LTTNG_ERR_INVALID_MAP;
		goto end;
	}

	kmap = trace_kernel_get_map_by_name(map_name, ksession);
	if (kmap) {
		DBG("Kernel map named \"%s\" already present", map_name);
		ret_code = LTTNG_ERR_KERNEL_MAP_EXIST;
		goto end;
	}

	kmap = trace_kernel_create_map(map);
	if (!kmap) {
		ERR("Error create kernel map");
		ret_code = LTTNG_ERR_KERNEL_MAP_CREATE_FAIL;
		goto end;
	}

	fd = kernctl_create_session_counter(ksession->fd,
			&kmap->counter_conf);
	if (fd < 0) {
		PERROR("ioctl kernel create session counter");
		ret_code = LTTNG_ERR_KERNEL_MAP_ENABLE_FAIL;
		goto error_free_map;
	}

	kmap->fd = fd;

	/* Prevent fd duplication after execlp() */
	ret = fcntl(kmap->fd, F_SETFD, FD_CLOEXEC);
	if (ret < 0) {
		PERROR("fcntl session counter fd");
		ret_code = LTTNG_ERR_KERNEL_MAP_ENABLE_FAIL;
		goto error_free_map;
	}

	kmap->map = map;
	lttng_map_get(map);
	cds_list_add(&kmap->list, &ksession->map_list.head);
	ksession->map_count++;

	DBG("Kernel session counter created (fd: %d)", kmap->fd);

	ret = kernctl_enable(kmap->fd);
	if (ret < 0) {
		PERROR("Enable kernel map");
		ret_code = LTTNG_ERR_KERNEL_MAP_ENABLE_FAIL;
		goto error_free_map;
	}

	ret_code = LTTNG_OK;

	goto end;
error_free_map:
	trace_kernel_destroy_map(kmap);
	ksession->map_count--;
end:
	return ret_code;
}

enum lttng_error_code map_kernel_enable(struct ltt_kernel_session *ksess,
		struct ltt_kernel_map *kmap)
{
	const char *map_name;
	int ret;
	enum lttng_error_code ret_code = LTTNG_OK;
	enum lttng_map_status map_status;

	assert(ksess);
	assert(kmap);

	map_status = lttng_map_get_name(kmap->map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Error getting kernel map name");
		ret_code = LTTNG_ERR_INVALID_MAP;
		goto end;
	}

	/* If already enabled, everything is OK */
	if (kmap->enabled) {
		DBG3("Map %s already enabled. Skipping", map_name);
		ret_code = LTTNG_ERR_KERNEL_MAP_EXIST;
		goto end;
	} else {
		kmap->enabled = 1;
		lttng_map_set_is_enabled(kmap->map, true);
		DBG2("Map %s enabled successfully", map_name);
	}

	DBG2("Map %s being enabled in kernel domain", map_name);

	ret = kernctl_enable(kmap->fd);
	if (ret < 0) {
		PERROR("Enable kernel map");
		ret_code = LTTNG_ERR_KERNEL_MAP_ENABLE_FAIL;
		goto end;
	}

	ret_code = LTTNG_OK;
end:
	return ret_code;
}

enum lttng_error_code map_kernel_disable(struct ltt_kernel_session *usess,
		struct ltt_kernel_map *kmap)
{
	int ret;
	enum lttng_error_code ret_code = LTTNG_OK;
	enum lttng_map_status map_status;
	const char *map_name = NULL;

	assert(usess);
	assert(kmap);

	map_status = lttng_map_get_name(kmap->map, &map_name);
	if (map_status != LTTNG_MAP_STATUS_OK) {
		ERR("Error getting kernel map name");
		ret_code = LTTNG_ERR_INVALID_MAP;
		goto end;
	}

	/* Already disabled */
	if (kmap->enabled == 0) {
		DBG2("Map kernel %s already disabled", map_name);
		ret_code = LTTNG_ERR_KERNEL_MAP_EXIST;
		goto end;
	}

	kmap->enabled = 0;
	lttng_map_set_is_enabled(kmap->map, false);

	DBG2("Map %s being disabled in kernel global domain", map_name);

	/* Disable map for global domain */
	ret = kernctl_disable(kmap->fd);
	if (ret < 0) {
		ret_code = LTTNG_ERR_KERNEL_MAP_DISABLE_FAIL;
		goto end;
	}

	DBG2("Map %s disabled successfully", map_name);

end:
	return ret_code;
}
