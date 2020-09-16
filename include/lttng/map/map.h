/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_H
#define LTTNG_MAP_H

#include <stddef.h>
#include <stdbool.h>

#include <lttng/domain.h>
#include <lttng/handle.h>
#include <lttng/lttng-error.h>
#include <lttng/lttng-export.h>

struct lttng_map;
struct lttng_map_list;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_map_status {
	LTTNG_MAP_STATUS_OK = 0,
	LTTNG_MAP_STATUS_ERROR = -1,
	LTTNG_MAP_STATUS_INVALID = -2,
	LTTNG_MAP_STATUS_UNSET = -3,
};

enum lttng_map_bitness {
	LTTNG_MAP_BITNESS_32BITS = 32,
	LTTNG_MAP_BITNESS_64BITS = 64,
};

enum lttng_map_boundary_policy {
	LTTNG_MAP_BOUNDARY_POLICY_OVERFLOW,
};

/*
 * Return LTTNG_MAP_STATUS_OK on success, LTTNG_MAP_STATUS_INVALID if invalid
 * parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_map_status lttng_map_create(const char *name,
		unsigned int dimension_count,
		uint64_t *dimension_sizes,
		enum lttng_domain_type domain,
		enum lttng_buffer_type buffer_type,
		enum lttng_map_bitness bitness,
		enum lttng_map_boundary_policy boundary_policy,
		bool coalesce_hits,
		struct lttng_map **map);

LTTNG_EXPORT extern enum lttng_map_status lttng_map_get_name(
		const struct lttng_map *map, const char **name);

LTTNG_EXPORT extern enum lttng_map_status lttng_map_set_name(
		struct lttng_map *map, const char *name);

/*
 * Get the number of dimensions.
 */
LTTNG_EXPORT extern unsigned int lttng_map_get_dimension_count(
		const struct lttng_map *map);

/*
 * Get the number of elements for the provided dimension.
 *
 * Return LTTNG_MAP_STATUS_OK on success, LTTNG_MAP_STATUS_INVALID if invalid
 * parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_map_status lttng_map_get_dimension_length(
		const struct lttng_map *map, unsigned int dimension,
		uint64_t *dimension_length);

LTTNG_EXPORT extern int lttng_map_get_is_enabled(const struct lttng_map *map);

LTTNG_EXPORT extern enum lttng_map_bitness lttng_map_get_bitness(
		const struct lttng_map *map);

LTTNG_EXPORT extern enum lttng_domain_type lttng_map_get_domain(
		const struct lttng_map *map);

LTTNG_EXPORT extern enum lttng_buffer_type lttng_map_get_buffer_type(
		const struct lttng_map *map);

LTTNG_EXPORT extern enum lttng_map_boundary_policy lttng_map_get_boundary_policy(
		const struct lttng_map *map);

LTTNG_EXPORT extern bool lttng_map_get_coalesce_hits(
		const struct lttng_map *map);

LTTNG_EXPORT extern void lttng_map_destroy(struct lttng_map *map);

LTTNG_EXPORT extern enum lttng_error_code lttng_add_map(struct lttng_handle *handle,
		struct lttng_map *map);

LTTNG_EXPORT extern enum lttng_error_code lttng_enable_map(struct lttng_handle *handle,
		const char *map_name);

LTTNG_EXPORT extern enum lttng_error_code lttng_disable_map(struct lttng_handle *handle,
		const char *map_name);

/*
 * Get a map from the list at a given index.
 *
 * Note that the map list maintains the ownership of the returned map.
 * It must not be destroyed by the user, nor should a reference to it be held
 * beyond the lifetime of the map list.
 *
 * Returns a map, or NULL on error.
 */
LTTNG_EXPORT extern const struct lttng_map *lttng_map_list_get_at_index(
		const struct lttng_map_list *map_list, unsigned int index);

/*
 * Get the number of map in a map list.
 */

LTTNG_EXPORT extern enum lttng_map_status lttng_map_list_get_count(
		const struct lttng_map_list *map_list, unsigned int *count);

/*
 * Destroy a map list.
 */
LTTNG_EXPORT extern void lttng_map_list_destroy(struct lttng_map_list *map_list);

/*
 * Return the list of maps configured for a given handle.
 */
LTTNG_EXPORT extern enum lttng_error_code lttng_list_maps(struct lttng_handle *handle,
		struct lttng_map_list **map_list);

#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_H */
