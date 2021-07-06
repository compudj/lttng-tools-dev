/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_INTERNAL_H
#define LTTNG_MAP_INTERNAL_H

#include <common/macros.h>
#include <common/optional.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <urcu/ref.h>

#include "map.h"

struct lttng_payload;
struct lttng_payload_view;
struct mi_writer;

struct lttng_map {
	/* Reference counting is only exposed to internal users. */
	struct urcu_ref ref;

	char *name;
	LTTNG_OPTIONAL(bool) is_enabled;
	enum lttng_map_bitness bitness;
	enum lttng_map_boundary_policy boundary_policy;
	enum lttng_domain_type domain;
	enum lttng_buffer_type buffer_type;
	bool coalesce_hits;
	unsigned int dimension_count;
	uint64_t *dimension_sizes;
};

struct lttng_map_list {
	struct lttng_dynamic_pointer_array array;
};

struct lttng_map_comm {
	uint32_t name_length /* Includes '\0' */;
	uint32_t length;
	uint8_t is_enabled;
	uint8_t bitness;
	uint8_t boundary_policy;
	uint8_t domain;
	uint8_t buffer_type;
	uint8_t coalesce_hits;;
	uint64_t dimension_count;

	/* length excludes its own length. */
	/* A name and dimension sizes follow. */
	char payload[];
} LTTNG_PACKED;

struct lttng_map_list_comm {
	uint32_t count;
	/* Count * lttng_map_comm structure */
	char payload[];
} LTTNG_PACKED;

ssize_t lttng_map_create_from_payload(struct lttng_payload_view *view,
		struct lttng_map **map);

int lttng_map_serialize(const struct lttng_map *map,
		struct lttng_payload *payload);

enum lttng_error_code lttng_map_mi_serialize(const struct lttng_map *map,
		struct mi_writer *writer);

void lttng_map_get(struct lttng_map *map);

void lttng_map_put(struct lttng_map *map);

void lttng_map_set_is_enabled(struct lttng_map *map, bool enabled);

/*
 * Allocate a new list of maps.
 * The returned object must be freed via lttng_map_list_destroy.
 */
struct lttng_map_list *lttng_map_list_create(void);

/*
 * Add a map to the maps set.
 *
 * A reference to the added map is acquired on behalf of the map set
 * on success.
 */
enum lttng_map_status lttng_map_list_add(struct lttng_map_list *map_list,
		struct lttng_map *map);

ssize_t lttng_map_list_create_from_payload(struct lttng_payload_view *view,
		struct lttng_map_list **map_list);

/*
 * Serialize a map list to an lttng_payload object.
 * Return LTTNG_OK on success, negative lttng error code on error.
 */
int lttng_map_list_serialize(const struct lttng_map_list *map_list,
		struct lttng_payload *payload);

#define for_each_map_const(__map_element, __map_list) \
	for (unsigned int __map_idx = 0; \
			(__map_element = lttng_map_list_get_at_index(__map_list, __map_idx)); \
			__map_idx++)


#endif /* LTTNG_MAP_INTERNAL_H */
