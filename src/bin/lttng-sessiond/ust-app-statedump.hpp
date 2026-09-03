/*
 * SPDX-FileCopyrightText: 2026 EfficiOS Inc.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 */

#ifndef LTTNG_SESSIOND_UST_APP_STATEDUMP_HPP
#define LTTNG_SESSIOND_UST_APP_STATEDUMP_HPP

#include <atomic>

namespace lttng {
namespace sessiond {
namespace ust {

/*
 * Whether a state dump which this session daemon asked one application
 * for has yet to be taken by it.
 *
 * WHY THIS IS KEPT HERE RATHER THAN ASKED FOR. The application reports
 * what became of a state dump it was asked for, on the notification
 * socket, so the answer is already on its way to us. Keeping it means a
 * client which waits for a state dump costs nothing on the application:
 * without it, every round of that wait would be a command socket
 * round-trip to every application of the session, at whatever rate the
 * client polls.
 *
 * The obligation is raised BEFORE the request is sent to the
 * application, never after: the application queues its state dump
 * before it answers the command which asked for it, so the notification
 * saying the dump was taken may arrive while that command's reply is
 * still being handled. Raising it afterwards would overwrite that
 * notification and leave the obligation standing forever.
 *
 * Thread safety: the notification thread lowers it, the client command
 * thread raises and reads it. It is a single word and the two are
 * independent, so it takes no lock and orders nothing.
 */
class app_statedump_state final {
public:
	app_statedump_state() = default;
	app_statedump_state(const app_statedump_state&) = delete;
	app_statedump_state(app_statedump_state&&) = delete;
	app_statedump_state& operator=(const app_statedump_state&) = delete;
	app_statedump_state& operator=(app_statedump_state&&) = delete;
	~app_statedump_state() = default;

	/* A state dump was asked of the application. */
	void set_outstanding() noexcept
	{
		_outstanding.store(true, std::memory_order_relaxed);
	}

	/*
	 * The application reported what became of it: either it walked
	 * its state, or the request was dropped because the recording
	 * session stopped. Either way nothing is owed any more.
	 */
	void clear_outstanding() noexcept
	{
		_outstanding.store(false, std::memory_order_relaxed);
	}

	bool is_outstanding() const noexcept
	{
		return _outstanding.load(std::memory_order_relaxed);
	}

private:
	std::atomic<bool> _outstanding{ false };
};

} /* namespace ust */
} /* namespace sessiond */
} /* namespace lttng */

#endif /* LTTNG_SESSIOND_UST_APP_STATEDUMP_HPP */
