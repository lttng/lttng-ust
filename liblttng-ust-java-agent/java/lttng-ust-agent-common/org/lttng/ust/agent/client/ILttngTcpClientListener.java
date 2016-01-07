/*
 * Copyright (C) 2015 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License, version 2.1 only,
 * as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

package org.lttng.ust.agent.client;

import java.util.Collection;

import org.lttng.ust.agent.session.EventRule;

/**
 * TCP client listener interface.
 *
 * This interface contains callbacks that are called when the TCP client
 * receives commands from the session daemon. These callbacks will define what
 * do to with each command.
 *
 * @author Alexandre Montplaisir
 */
public interface ILttngTcpClientListener {

	/**
	 * Callback for the TCP client to notify the listener agent that a request
	 * for enabling an event rule was sent from the session daemon.
	 *
	 * @param eventRule
	 *            The event rule that was requested to be enabled
	 * @return Since we do not track individual sessions, right now this command
	 *         cannot fail. It will always return true.
	 */
	boolean eventEnabled(EventRule eventRule);

	/**
	 * Callback for the TCP client to notify the listener agent that a request
	 * for disabling an event was sent from the session daemon.
	 *
	 * @param eventName
	 *            The name of the event that was requested to be disabled.
	 * @return True if the command completed successfully, false if we should
	 *         report an error (event was not enabled, etc.)
	 */
	boolean eventDisabled(String eventName);

	/**
	 * Callback for the TCP client to notify the listener agent that a request
	 * for enabling an application-specific context was sent from the session
	 * daemon.
	 *
	 * @param contextRetrieverName
	 *            The name of the retriever in which the context is present.
	 *            This is used to namespace the contexts.
	 * @param contextName
	 *            The name of the context that was requested to be enabled
	 * @return Since we do not track individual sessions, right now this command
	 *         cannot fail. It will always return true.
	 */
	boolean appContextEnabled(String contextRetrieverName, String contextName);

	/**
	 * Callback for the TCP client to notify the listener agent that a request
	 * for disabling an application-specific context was sent from the session
	 * daemon.
	 *
	 * @param contextRetrieverName
	 *            The name of the retriever in which the context is present.
	 *            This is used to namespace the contexts.
	 * @param contextName
	 *            The name of the context that was requested to be disabled.
	 * @return True if the command completed successfully, false if we should
	 *         report an error (context was not previously enabled for example)
	 */
	boolean appContextDisabled(String contextRetrieverName, String contextName);

	/**
	 * List the events that are available in the agent's tracing domain.
	 *
	 * In Java terms, this means loggers that have at least one LTTng log
	 * handler of their corresponding domain attached.
	 *
	 * @return The list of available events
	 */
	Collection<String> listAvailableEvents();
}
