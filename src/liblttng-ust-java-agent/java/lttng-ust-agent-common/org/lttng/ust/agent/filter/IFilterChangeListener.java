/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015 EfficiOS Inc.
 * Copyright (C) 2015 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

package org.lttng.ust.agent.filter;

import org.lttng.ust.agent.session.EventRule;

/**
 * Filter notification listener interface.
 * <p>
 * Applications wanting to be notified of event filtering rule changes should
 * implement this interface, then register their listener using
 * {@link FilterChangeNotifier#registerListener}.
 * </p>
 * <p>
 * The callbacks defined in this interface will be called whenever an event rule
 * is added or removed. The manager will take care of the reference-counting in
 * case multiple tracing sessions enable the exact same rules. For example, the
 * {@link #eventRuleRemoved} callback is only called when there are no more
 * session interested into it.
 * </p>
 * <p>
 * Do not forget to unregister the listener after use, using
 * {@link FilterChangeNotifier#unregisterListener}. If you do not, or if
 * you use an anonymous listener for example, these will remain attached until
 * the complete shutdown of the application.
 * </p>
 * <p>
 * Only one thread is used to dispatch notifications, sequentially. This means
 * that if a callback hangs it will prevent other listeners from receiving
 * notifications. Please take care of not blocking inside the listener
 * callbacks, and use separate threads for potentially long or blocking
 * operations.
 * </p>
 *
 * @author Alexandre Montplaisir
 */
public interface IFilterChangeListener {

	/**
	 * Notification that a new event rule is now enabled in the tracing
	 * sessions.
	 *
	 * @param rule
	 *            The event rule that was enabled
	 */
	void eventRuleAdded(EventRule rule);

	/**
	 * Notification that an existing event rule is now disabled in the tracing
	 * sessions.
	 *
	 * @param rule
	 *            The event rule that was disabled
	 */
	void eventRuleRemoved(EventRule rule);
}
