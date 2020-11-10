/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CONTENT_H
#define LTTNG_MAP_CONTENT_H

#include <stddef.h>
#include <stdbool.h>

#include <lttng/domain.h>
#include <lttng/handle.h>
#include <lttng/map/map.h>

struct lttng_map_key_value_pair;
/* A list of key value pair. */
struct lttng_map_key_value_pair_list;
/* A list of key value pair list. */
struct lttng_map_content;

#ifdef __cplusplus
extern "C" {
#endif

enum lttng_map_content_status {
	LTTNG_MAP_CONTENT_STATUS_OK = 0,
	LTTNG_MAP_CONTENT_STATUS_ERROR = -1,
	LTTNG_MAP_CONTENT_STATUS_INVALID = -2,
	LTTNG_MAP_CONTENT_STATUS_UNSET = -3,
};

enum lttng_map_key_value_pair_list_type {
	LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_KERNEL,
	LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_UID,
	LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID,
	LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID_AGGREGATED,
};

/*
 * Get the key of a key-value.
 *
 * The caller does not assume the ownership of the returned key.
 * The key shall only be used for the duration of the key-value's lifetime.
 *
 * Returns LTTNG_MAP_STATUS_OK and a pointer to the key-value's key on success,
 * LTTNG_MAP_STATUS_INVALID if an invalid parameter is passed, or
 */
LTTNG_EXPORT extern enum lttng_map_content_status lttng_map_key_value_pair_get_key(
		const struct lttng_map_key_value_pair *kv_pair, const char **key);

LTTNG_EXPORT extern bool lttng_map_key_value_pair_get_has_overflowed(
		const struct lttng_map_key_value_pair *key_value);

LTTNG_EXPORT extern bool lttng_map_key_value_pair_get_has_underflowed(
		const struct lttng_map_key_value_pair *key_value);
/*
 * Get the value of a key-value.
 *
 * The caller does not assume the ownership of the returned value.
 * The value shall only be used for the duration of the key-value's lifetime.
 *
 * Returns LTTNG_MAP_STATUS_OK and a pointer to the key-value's value on success,
 * LTTNG_MAP_STATUS_INVALID if an invalid parameter is passed.
 */
LTTNG_EXPORT extern enum lttng_map_content_status lttng_map_key_value_pair_get_value(
		const struct lttng_map_key_value_pair *kv_pair, int64_t *value);

/*
 * Get the number of key-value pair lists in a map content.
 */
LTTNG_EXPORT extern enum lttng_map_content_status lttng_map_content_get_count(
		const struct lttng_map_content *map_content,
		unsigned int *count);

LTTNG_EXPORT extern const struct lttng_map_key_value_pair_list *lttng_map_content_get_at_index(
		const struct lttng_map_content *map_content,
		unsigned int index);

LTTNG_EXPORT extern enum lttng_buffer_type lttng_map_content_get_buffer_type(
			const struct lttng_map_content *map_content);

LTTNG_EXPORT extern void lttng_map_content_destroy(
		struct lttng_map_content *map_content);
/*
 * Get a key-value from the list at a given index.
 *
 * Note that the key value list maintains the ownership of the returned key
 * value.
 * It must not be destroyed by the user, nor should a reference to it be held
 * beyond the lifetime of the key value list.
 *
 * Returns a key-value, or NULL on error.
 */
LTTNG_EXPORT extern const struct lttng_map_key_value_pair *lttng_map_key_value_pair_list_get_at_index(
		const struct lttng_map_key_value_pair_list *kv_pair_list,
		unsigned int index);

/*
 * Get the number of key value pair in a key-value list.
 *
 * Return LTTNG_MAP_STATUS_OK on success,
 * LTTNG_MAP_STATUS_INVALID when invalid parameters are passed.
 */
LTTNG_EXPORT extern enum lttng_map_content_status lttng_map_key_value_pair_list_get_count(
		const struct lttng_map_key_value_pair_list *kv_pair_list,
		unsigned int *count);

LTTNG_EXPORT extern enum lttng_map_key_value_pair_list_type lttng_map_key_value_pair_list_get_type(
		const struct lttng_map_key_value_pair_list *kv_pair_list);

LTTNG_EXPORT extern uint64_t lttng_map_key_value_pair_list_get_identifer(
		const struct lttng_map_key_value_pair_list *kv_pair_list);

LTTNG_EXPORT extern uint64_t lttng_map_key_value_pair_list_get_cpu(
		const struct lttng_map_key_value_pair_list *kv_pair_list);

LTTNG_EXPORT extern bool lttng_map_key_value_pair_list_get_summed_all_cpu(
		const struct lttng_map_key_value_pair_list *kv_pair_list);

/*
 * Destroy key value pair list.
 */
LTTNG_EXPORT extern void lttng_map_key_value_pair_list_destroy(
		struct lttng_map_key_value_pair_list *kv_pair_list);

/*
 * List all key-value pairs for the given session and map.
 *
 * On success, a newly-allocated key-value list is returned.
 *
 * The key-value list must be destroyed by the caller (see
 * lttng_map_key_value_pair_list_destroy()).
 *
 * Returns LTTNG_OK on success, else a suitable LTTng error code.
 */
LTTNG_EXPORT extern enum lttng_error_code lttng_list_map_content(
		struct lttng_handle *handle, const struct lttng_map *map,
		const struct lttng_map_query *map_query,
		struct lttng_map_content **map_content);


#ifdef __cplusplus
}
#endif

#endif /* LTTNG_MAP_CONTENT_H */
