/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015 EfficiOS Inc.
 * Copyright (C) 2015 Alexandre Montplaisir <alexmonthy@efficios.com>
 */

package org.lttng.ust.agent;

import java.util.Collection;
import java.util.Map;

/**
 * Interface to define LTTng Java agents.
 *
 * An "agent" is a representative of an LTTng session daemon in the Java world.
 * It tracks the settings of a tracing session as they defined in the session
 * daemon.
 *
 * It also track the current logging handlers that are sending events to UST.
 *
 * @author Alexandre Montplaisir
 *
 * @param <T>
 *            The type of logging handler that should register to this agent
 */
public interface ILttngAgent<T extends ILttngHandler> {

	// ------------------------------------------------------------------------
	// Agent configuration elements
	// ------------------------------------------------------------------------

	/**
	 * Tracing domains. Corresponds to domains defined by LTTng Tools.
	 */
	enum Domain {
		JUL(3), LOG4J(4), LOG4J2(6);
		private int value;

		private Domain(int value) {
			this.value = value;
		}

		public int value() {
			return value;
		}
	}

	/**
	 * The tracing domain of this agent.
	 *
	 * @return The tracing domain.
	 */
	Domain getDomain();

	// ------------------------------------------------------------------------
	// Log handler registering
	// ------------------------------------------------------------------------

	/**
	 * Register a handler to this agent.
	 *
	 * @param handler
	 *            The handler to register
	 */
	void registerHandler(T handler);

	/**
	 * Deregister a handler from this agent.
	 *
	 * @param handler
	 *            The handler to deregister.
	 */
	void unregisterHandler(T handler);

	// ------------------------------------------------------------------------
	// Tracing session parameters
	// ------------------------------------------------------------------------

	/**
	 * Query if a given event is currently enabled in a current tracing session,
	 * meaning it should be sent to UST.
	 *
	 * @param eventName
	 *            The name of the event to check.
	 * @return True if the event is currently enabled, false if it is not.
	 */
	boolean isEventEnabled(String eventName);

	/**
	 * Return the list of application contexts enabled in the tracing sessions.
	 *
	 * @return The application contexts, first indexed by retriever name, then
	 *         by context name
	 */
	Collection<Map.Entry<String, Map<String, Integer>>> getEnabledAppContexts();
}
