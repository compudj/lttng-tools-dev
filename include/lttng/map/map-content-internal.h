/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#ifndef LTTNG_MAP_CONTENT_INTERNAL_H
#define LTTNG_MAP_CONTENT_INTERNAL_H

#include <common/macros.h>
#include <common/optional.h>
#include <common/payload.h>
#include <common/payload-view.h>
#include <urcu/ref.h>

#include "map-content.h"

struct lttng_payload;
struct lttng_payload_view;

struct lttng_map_key_value_pair {
	char *key;
	int64_t value;
	bool has_overflowed;
	bool has_underflowed;
};

struct lttng_map_key_value_pair_list {
	enum lttng_map_key_value_pair_list_type type;
	uint64_t id; /* pid_t or uid_t */
	uint64_t cpu;
	bool summed_all_cpus;
	struct lttng_dynamic_pointer_array array;
};

struct lttng_map_content {
	enum lttng_buffer_type type;
	struct lttng_dynamic_pointer_array array;
};

struct lttng_map_key_value_pair_comm {
	uint32_t key_length /* Includes '\0' */;
	int64_t value;
	uint8_t has_overflowed;
	uint8_t has_underflowed;
} LTTNG_PACKED;

struct lttng_map_key_value_pair_list_comm {
	uint32_t count;
	uint8_t type; /* enum lttng_map_key_value_pair_list_type */
	uint64_t id; /* pid_t or uid_t */
	uint64_t cpu;
	uint8_t summed_all_cpus;
	/* Count * lttng_map_key_value_pair_comm structure */
	char payload[];
} LTTNG_PACKED;

struct lttng_map_content_comm {
	uint32_t count;
	uint8_t type; /* enum lttng_buffer_type */
	/* Count * lttng_map_key_value_pair_list structure */
	char payload[];
};

struct lttng_map_key_value_pair *lttng_map_key_value_pair_create(
		const char *key, int64_t value);

void lttng_map_key_value_pair_set_has_overflowed(
		struct lttng_map_key_value_pair *key_value);

void lttng_map_key_value_pair_set_has_underflowed(
		struct lttng_map_key_value_pair *key_value);

ssize_t lttng_map_key_value_pair_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_map_key_value_pair **key_value);

int lttng_map_key_value_pair_serialize(
		const struct lttng_map_key_value_pair *key_value,
		struct lttng_payload *payload);

void lttng_map_key_value_pair_destroy(
		struct lttng_map_key_value_pair *key_value);

struct lttng_map_key_value_pair_list *lttng_map_key_value_pair_list_create(
		enum lttng_map_key_value_pair_list_type type,
		bool summed_all_cpus);

enum lttng_map_content_status lttng_map_key_value_pair_list_set_identifier(
		struct lttng_map_key_value_pair_list *kv_pair_list,
		uint64_t identifier);

enum lttng_map_content_status lttng_map_key_value_pair_list_set_cpu(
		struct lttng_map_key_value_pair_list *kv_pair_list,
		uint64_t cpu);

enum lttng_map_content_status lttng_map_key_value_pair_list_append_key_value(
		struct lttng_map_key_value_pair_list *key_values,
		struct lttng_map_key_value_pair *key_value);

ssize_t lttng_map_key_value_pair_list_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_map_key_value_pair_list **key_values);

int lttng_map_key_value_pair_list_serialize(
		const struct lttng_map_key_value_pair_list *key_values,
		struct lttng_payload *payload);

struct lttng_map_content *lttng_map_content_create(
		enum lttng_buffer_type type);

enum lttng_map_content_status lttng_map_content_append_key_value_list(
		struct lttng_map_content *map_content,
		struct lttng_map_key_value_pair_list *kv_list);

ssize_t lttng_map_content_create_from_payload(
		struct lttng_payload_view *view,
		struct lttng_map_content **map_content);

int lttng_map_content_serialize(
		const struct lttng_map_content *map_content,
		struct lttng_payload *payload);

#endif /* LTTNG_MAP_CONTENT_INTERNAL_H */
