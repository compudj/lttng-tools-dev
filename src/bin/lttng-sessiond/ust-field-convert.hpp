/*
 * SPDX-FileCopyrightText: 2022 Jérémie Galarneau <jeremie.galarneau@efficios.com>
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_FIELD_CONVERT_HPP
#define LTTNG_SESSIOND_UST_FIELD_CONVERT_HPP

#include "field.hpp"
#include "ust-field-quirks.hpp"
#include "ust-trace-class.hpp"

#include <lttng/ust-ctl.h>

#include <cstddef>
#include <vector>

namespace lttng {
namespace sessiond {
namespace ust {

std::vector<trace::field::cuptr>
create_trace_fields_from_ust_ctl_fields(const lttng::sessiond::ust::trace_class& session,
					const lttng_ust_ctl_field *fields,
					std::size_t field_count,
					trace::field_location::root lookup_root,
					ctl_field_quirks quirks = ctl_field_quirks::NONE);

/*
 * Decode the attributes of an event, which the application sends as the
 * trailing fields of its event registration.
 */
trace::attribute_set create_trace_attributes_from_ust_ctl_fields(const lttng_ust_ctl_field *fields,
								 std::size_t attribute_count);

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_FIELD_CONVERT_HPP */
