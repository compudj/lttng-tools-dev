/*
 * Copyright (C) 2020 Francis Deslauriers <francis.deslauriers@efficios.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <assert.h>
#include <string.h>

#include <common/error.h>
#include <common/macros.h>
#include <common/optional.h>
#include <common/payload.h>

#include <lttng/lttng.h>
#include <lttng/map/map-content-internal.h>

struct lttng_map_key_value_pair *lttng_map_key_value_pair_create(const char *key,
		int64_t value)
{
	struct lttng_map_key_value_pair *key_value;

	key_value = (lttng_map_key_value_pair *) zmalloc(sizeof(struct lttng_map_key_value_pair));
	if (!key_value) {
		goto end;
	}

	key_value->key = strdup(key);
	if (!key_value->key) {
		free(key_value);
		key_value = NULL;
		goto end;
	}
	key_value->value = value;

end:
	return key_value;
}

enum lttng_map_content_status lttng_map_key_value_pair_get_key(
		const struct lttng_map_key_value_pair *key_value,
		const char **key)
{
	assert(key_value);
	assert(key_value->key);

	*key = key_value->key;
	return LTTNG_MAP_CONTENT_STATUS_OK;
}

enum lttng_map_content_status lttng_map_key_value_pair_get_value(
		const struct lttng_map_key_value_pair *key_value,
		int64_t *value)
{
	assert(key_value);
	*value = key_value->value;
	return LTTNG_MAP_CONTENT_STATUS_OK;
}

void lttng_map_key_value_pair_set_has_overflowed(
		struct lttng_map_key_value_pair *key_value)
{
	assert(key_value);

	key_value->has_overflowed = true;
}

void lttng_map_key_value_pair_set_has_underflowed(
		struct lttng_map_key_value_pair *key_value)
{
	assert(key_value);

	key_value->has_underflowed = true;
}

bool lttng_map_key_value_pair_get_has_overflowed(
		const struct lttng_map_key_value_pair *key_value)
{
	assert(key_value);

	return key_value->has_overflowed;
}

bool lttng_map_key_value_pair_get_has_underflowed(
		const struct lttng_map_key_value_pair *key_value)
{
	assert(key_value);

	return key_value->has_underflowed;
}

ssize_t lttng_map_key_value_pair_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_map_key_value_pair **key_value)
{
	const struct lttng_map_key_value_pair_comm *kv_pair_comm;
	struct lttng_map_key_value_pair *kv_pair;
	ssize_t ret, offset = 0;
	const char *key;
	int64_t value;

	if (!src_view || !key_value) {
		ret = -1;
		goto end;
	}

	kv_pair_comm = (typeof(kv_pair_comm)) src_view->buffer.data;
	offset += sizeof(*kv_pair_comm);

	if (kv_pair_comm->key_length == 0) {
		ret = -1;
		goto end;
	}

	value = kv_pair_comm->value;

	{
		struct lttng_payload_view key_view =
			lttng_payload_view_from_view(src_view, offset,
					kv_pair_comm->key_length);
		key = key_view.buffer.data;
		if (!lttng_buffer_view_contains_string(&key_view.buffer,
					key, kv_pair_comm->key_length)) {
			ret = -1;
			goto end;
		}
	}

	offset += kv_pair_comm->key_length;

	kv_pair = lttng_map_key_value_pair_create(key, value);
	if (!kv_pair) {
		ret = -1;
		goto end;
	}

	kv_pair->has_overflowed = kv_pair_comm->has_overflowed;
	kv_pair->has_underflowed = kv_pair_comm->has_underflowed;

	*key_value = kv_pair;

	ret = offset;

end:
	return ret;
}

int lttng_map_key_value_pair_serialize(
		const struct lttng_map_key_value_pair *key_value,
		struct lttng_payload *payload)
{
	int ret;
	size_t key_len;
	struct lttng_map_key_value_pair_comm kv_pair_comm = {0};

	assert(key_value);
	assert(key_value->key);

	key_len = strlen(key_value->key) + 1;

	kv_pair_comm.key_length = key_len;
	kv_pair_comm.value = key_value->value;
	kv_pair_comm.has_overflowed = key_value->has_overflowed;
	kv_pair_comm.has_underflowed = key_value->has_underflowed;

	ret = lttng_dynamic_buffer_append(&payload->buffer, &kv_pair_comm,
			sizeof(kv_pair_comm));
	if (ret) {
		goto end;
	}

	/* Append key.*/
	ret = lttng_dynamic_buffer_append(
			&payload->buffer, key_value->key, key_len);
	if (ret) {
		goto end;
	}

end:
	return ret;
}

void lttng_map_key_value_pair_destroy(struct lttng_map_key_value_pair *key_value)
{
	if (!key_value) {
		return;
	}

	free(key_value->key);
	free(key_value);
}

static void delete_map_key_value_pair_array_element(void *ptr)
{
	struct lttng_map_key_value_pair *key_value = (lttng_map_key_value_pair *) ptr;
	lttng_map_key_value_pair_destroy(key_value);
}

struct lttng_map_key_value_pair_list *lttng_map_key_value_pair_list_create(
		enum lttng_map_key_value_pair_list_type type,
		bool summed_all_cpus)
{
	struct lttng_map_key_value_pair_list *map_key_values = NULL;

	map_key_values = (lttng_map_key_value_pair_list *) zmalloc(sizeof(*map_key_values));
	if (!map_key_values) {
		goto end;
	}

	map_key_values->type = type;
	map_key_values->summed_all_cpus = summed_all_cpus;

	lttng_dynamic_pointer_array_init(&map_key_values->array,
			delete_map_key_value_pair_array_element);

end:
	return map_key_values;
}

enum lttng_map_content_status lttng_map_key_value_pair_list_set_identifier(
		struct lttng_map_key_value_pair_list *kv_pair_list,
		uint64_t identifier)
{
	enum lttng_map_content_status status;
	assert(kv_pair_list);

	switch (kv_pair_list->type) {
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID:
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_UID:
		kv_pair_list->id = identifier;
		status = LTTNG_MAP_CONTENT_STATUS_OK;
		break;
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID_AGGREGATED:
		ERR("Cannot set an identifier for an UST per-pid aggregation key value pair list");
		status = LTTNG_MAP_CONTENT_STATUS_INVALID;
		break;
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_KERNEL:
		ERR("Cannot set an identifier for a kernel key value pair list");
		status = LTTNG_MAP_CONTENT_STATUS_INVALID;
		break;
	default:
		ERR("Unknown key value par list type %d", kv_pair_list->type);
		abort();
	}

	return status;
}

bool lttng_map_key_value_pair_list_get_summed_all_cpu(
		const struct lttng_map_key_value_pair_list *kv_pair_list)
{
	assert(kv_pair_list);

	return kv_pair_list->summed_all_cpus;
}

enum lttng_map_content_status lttng_map_key_value_pair_list_set_cpu(
		struct lttng_map_key_value_pair_list *kv_pair_list,
		uint64_t cpu)
{
	assert(kv_pair_list);

	kv_pair_list->cpu = cpu;

	return LTTNG_MAP_CONTENT_STATUS_OK;
}

uint64_t lttng_map_key_value_pair_list_get_cpu(
		const struct lttng_map_key_value_pair_list *kv_pair_list)
{
	assert(kv_pair_list);

	return kv_pair_list->cpu;
}

enum lttng_map_key_value_pair_list_type lttng_map_key_value_pair_list_get_type(
		const struct lttng_map_key_value_pair_list *kv_pair_list)
{
	assert(kv_pair_list);

	return kv_pair_list->type;
}

enum lttng_map_content_status lttng_map_key_value_pair_list_append_key_value(
		struct lttng_map_key_value_pair_list *kv_pair_list,
		struct lttng_map_key_value_pair *key_value)
{
	int ret;
	enum lttng_map_content_status status;

	assert(kv_pair_list);
	assert(key_value);

	ret = lttng_dynamic_pointer_array_add_pointer(&kv_pair_list->array,
			key_value);
	if (ret) {
		status = LTTNG_MAP_CONTENT_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_MAP_CONTENT_STATUS_OK;

end:
	return status;
}

uint64_t lttng_map_key_value_pair_list_get_identifer(
		const struct lttng_map_key_value_pair_list *kv_pair_list)
{
	assert(kv_pair_list);

	switch (kv_pair_list->type) {
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID:
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_UID:
		break;
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID_AGGREGATED:
		ERR("No identifier for UST per-pid aggregation key value pair lists");
		abort();
		break;
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_KERNEL:
		ERR("No identifier for kernel key value pair lists");
		abort();
		break;
	default:
		ERR("Unknown key value par list type %d", kv_pair_list->type);
		abort();
	}

	return kv_pair_list->id;
}

const struct lttng_map_key_value_pair *lttng_map_key_value_pair_list_get_at_index(
		const struct lttng_map_key_value_pair_list *kv_pair_list,
		unsigned int index)
{
	struct lttng_map_key_value_pair *key_value = NULL;

	assert(kv_pair_list);
	if (index >= lttng_dynamic_pointer_array_get_count(&kv_pair_list->array)) {
		goto end;
	}

	key_value = (struct lttng_map_key_value_pair *)
			lttng_dynamic_pointer_array_get_pointer(
					&kv_pair_list->array, index);
end:
	return key_value;
}

enum lttng_map_content_status lttng_map_key_value_pair_list_get_count(
		const struct lttng_map_key_value_pair_list *kv_pair_list,
		unsigned int *count)
{
	enum lttng_map_content_status status;

	if (!kv_pair_list || !count) {
		status = LTTNG_MAP_CONTENT_STATUS_INVALID;;
		goto end;
	}

	*count = lttng_dynamic_pointer_array_get_count(&kv_pair_list->array);

	status = LTTNG_MAP_CONTENT_STATUS_OK;
end:
	return status;
}

void lttng_map_key_value_pair_list_destroy(struct lttng_map_key_value_pair_list *kv_pair_list)
{
	if (!kv_pair_list) {
		return;
	}

	lttng_dynamic_pointer_array_reset(&kv_pair_list->array);
	free(kv_pair_list);
}

int lttng_map_key_value_pair_list_serialize(
		const struct lttng_map_key_value_pair_list *kv_pair_list,
		struct lttng_payload *payload)
{
	int ret;
	unsigned int i, count;
	enum lttng_map_content_status status;
	struct lttng_map_key_value_pair_list_comm kv_pair_list_comm = {};

	kv_pair_list_comm.id = kv_pair_list->id;
	kv_pair_list_comm.cpu = kv_pair_list->cpu;
	kv_pair_list_comm.type = (uint8_t) kv_pair_list->type;
	kv_pair_list_comm.summed_all_cpus = (uint8_t) kv_pair_list->summed_all_cpus;

	status = lttng_map_key_value_pair_list_get_count(kv_pair_list, &count);
	if (status != LTTNG_MAP_CONTENT_STATUS_OK) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	kv_pair_list_comm.count = count;
	ret = lttng_dynamic_buffer_append(&payload->buffer, &kv_pair_list_comm,
			sizeof(kv_pair_list_comm));
	if (ret) {
		goto end;
	}
	for (i = 0; i < count; i++) {
		const struct lttng_map_key_value_pair *kv_pair =
				lttng_map_key_value_pair_list_get_at_index(kv_pair_list, i);

		assert(kv_pair);

		ret = lttng_map_key_value_pair_serialize(kv_pair, payload);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

ssize_t lttng_map_key_value_pair_list_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_map_key_value_pair_list **kv_pair_list)
{
	ssize_t ret, offset = 0;
	unsigned int i;
	enum lttng_map_content_status status;
	const struct lttng_map_key_value_pair_list_comm *kv_pair_list_comm;
	struct lttng_map_key_value_pair_list *local_key_values = NULL;
	enum lttng_map_key_value_pair_list_type type;

	kv_pair_list_comm = (typeof(kv_pair_list_comm)) src_view->buffer.data;
	offset += sizeof(*kv_pair_list_comm);

	type = (lttng_map_key_value_pair_list_type) kv_pair_list_comm->type;

	local_key_values = lttng_map_key_value_pair_list_create(
			type, kv_pair_list_comm->summed_all_cpus);
	if (!local_key_values) {
		ret = -1;
		goto end;
	}

	local_key_values->cpu = kv_pair_list_comm->cpu;

	switch (lttng_map_key_value_pair_list_get_type(local_key_values)) {
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_PID:
	case LTTNG_MAP_KEY_VALUE_PAIR_LIST_TYPE_UST_PER_UID:
		status = lttng_map_key_value_pair_list_set_identifier(local_key_values,
			kv_pair_list_comm->id);
		if (status != LTTNG_MAP_CONTENT_STATUS_OK) {
			ret = -1;
			goto end;
		}
		break;
	default:
		break;
	}

	for (i = 0; i < kv_pair_list_comm->count; i++) {
		struct lttng_map_key_value_pair *kv_pair = NULL;
		struct lttng_payload_view kv_view =
				lttng_payload_view_from_view(src_view, offset, -1);
		ssize_t kv_size;

		kv_size = lttng_map_key_value_pair_create_from_payload(
				&kv_view, &kv_pair);
		if (kv_size < 0) {
			ret = kv_size;
			goto end;
		}

		/* Transfer ownership of the key-value to the collection. */
		status = lttng_map_key_value_pair_list_append_key_value(local_key_values,
				kv_pair);
		if (status != LTTNG_MAP_CONTENT_STATUS_OK) {
			ret = -1;
			goto end;
		}

		offset += kv_size;
	}

	/* Pass ownership to caller. */
	*kv_pair_list = local_key_values;
	local_key_values = NULL;

	ret = offset;
end:
	lttng_map_key_value_pair_list_destroy(local_key_values);
	return ret;
}

static void delete_map_key_value_pair_list_array_element(void *ptr)
{
	struct lttng_map_key_value_pair_list *kv_list = (lttng_map_key_value_pair_list *)ptr;
	lttng_map_key_value_pair_list_destroy(kv_list);
}

struct lttng_map_content *lttng_map_content_create(
		enum lttng_buffer_type type)
{
	struct lttng_map_content *map_content = NULL;

	map_content = (lttng_map_content *) zmalloc(sizeof(*map_content));
	if (!map_content) {
		goto end;
	}

	map_content->type = type;

	lttng_dynamic_pointer_array_init(&map_content->array,
			delete_map_key_value_pair_list_array_element);

end:
	return map_content;
}

enum lttng_map_content_status lttng_map_content_get_count(
		const struct lttng_map_content *map_content,
		unsigned int *count)
{
	enum lttng_map_content_status status = LTTNG_MAP_CONTENT_STATUS_OK;

	if (!map_content || !count) {
		status = LTTNG_MAP_CONTENT_STATUS_INVALID;
		goto end;
	}

	*count = lttng_dynamic_pointer_array_get_count(&map_content->array);
	status = LTTNG_MAP_CONTENT_STATUS_OK;
end:
	return status;
}

enum lttng_buffer_type lttng_map_content_get_buffer_type(
			const struct lttng_map_content *map_content)
{
	assert(map_content);

	return map_content->type;
}

enum lttng_map_content_status lttng_map_content_append_key_value_list(
		struct lttng_map_content *map_content,
		struct lttng_map_key_value_pair_list *kv_list)
{
	int ret;
	enum lttng_map_content_status status;

	assert(map_content);
	assert(kv_list);

	ret = lttng_dynamic_pointer_array_add_pointer(&map_content->array,
			kv_list);
	if (ret) {
		status = LTTNG_MAP_CONTENT_STATUS_ERROR;
		goto end;
	}

	status = LTTNG_MAP_CONTENT_STATUS_OK;

end:
	return status;
}

const struct lttng_map_key_value_pair_list *lttng_map_content_get_at_index(
		const struct lttng_map_content *map_content,
		unsigned int index)
{
	struct lttng_map_key_value_pair_list *kv_pair_list = NULL;

	assert(map_content);
	if (index >= lttng_dynamic_pointer_array_get_count(&map_content->array)) {
		goto end;
	}

	kv_pair_list = (struct lttng_map_key_value_pair_list *)
			lttng_dynamic_pointer_array_get_pointer(
					&map_content->array, index);
end:
	return kv_pair_list;
}

ssize_t lttng_map_content_create_from_payload(
		struct lttng_payload_view *src_view,
		struct lttng_map_content **map_content)
{
	ssize_t ret, offset = 0;
	unsigned int i;
	struct lttng_map_content_comm *map_content_comm;
	struct lttng_map_content *local_map_content;
	enum lttng_buffer_type type;

	map_content_comm = (typeof(map_content_comm)) src_view->buffer.data;
	offset += sizeof(*map_content_comm);

	type = (lttng_buffer_type) map_content_comm->type;

	local_map_content = lttng_map_content_create(type);
	if (!local_map_content) {
		ret = -1;
		goto end;
	}

	for (i = 0; i < map_content_comm->count; i++) {
		struct lttng_map_key_value_pair_list *kv_pair_list = NULL;
		struct lttng_payload_view kv_list_view =
				lttng_payload_view_from_view(src_view, offset, -1);
		ssize_t kv_list_size;

		kv_list_size = lttng_map_key_value_pair_list_create_from_payload(
				&kv_list_view, &kv_pair_list);
		if (kv_list_size < 0) {
			ret = kv_list_size;
			goto end;
		}

		/* Transfer ownership of the key-value to the collection. */
		ret = lttng_map_content_append_key_value_list(local_map_content,
				kv_pair_list);
		if (ret < 0) {
			ret = -1;
			goto end;
		}

		offset += kv_list_size;
	}

	/* Pass ownership to caller. */
	*map_content = local_map_content;
	local_map_content = NULL;

	ret = offset;
end:
	lttng_map_content_destroy(local_map_content);
	return ret;
}

int lttng_map_content_serialize(
		const struct lttng_map_content *map_content,
		struct lttng_payload *payload)
{
	int ret;
	unsigned int i, count;
	enum lttng_map_content_status status;
	struct lttng_map_content_comm map_content_comm = {};

	status = lttng_map_content_get_count(map_content, &count);
	if (status != LTTNG_MAP_CONTENT_STATUS_OK) {
		ret = LTTNG_ERR_INVALID;
		goto end;
	}

	map_content_comm.count = count;
	map_content_comm.type = lttng_map_content_get_buffer_type(map_content);

	ret = lttng_dynamic_buffer_append(&payload->buffer, &map_content_comm,
			sizeof(map_content_comm));
	if (ret) {
		goto end;
	}
	for (i = 0; i < count; i++) {
		const struct lttng_map_key_value_pair_list *kv_pair_list =
				lttng_map_content_get_at_index(map_content, i);

		assert(kv_pair_list);

		ret = lttng_map_key_value_pair_list_serialize(kv_pair_list, payload);
		if (ret) {
			goto end;
		}
	}

end:
	return ret;
}

void lttng_map_content_destroy(struct lttng_map_content *map_content)
{
	if (!map_content) {
		return;
	}

	lttng_dynamic_pointer_array_reset(&map_content->array);
	free(map_content);
}
