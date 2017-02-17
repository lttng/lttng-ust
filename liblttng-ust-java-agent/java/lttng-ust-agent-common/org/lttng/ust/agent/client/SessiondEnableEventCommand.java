/*
 * Copyright (C) 2015 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.lttng.ust.agent.session.EventRule;
import org.lttng.ust.agent.session.LogLevelSelector;

/**
 * Session daemon command indicating to the Java agent that some events were
 * enabled in the tracing session.
 *
 * @author Alexandre Montplaisir
 * @author David Goulet
 */
class SessiondEnableEventCommand extends SessiondCommand {

	/** Fixed event name length. Value defined by the lttng agent protocol. */
	private static final int EVENT_NAME_LENGTH = 256;

	private final boolean commandIsValid;

	/* Parameters of the event rule being enabled */
	private final String eventName;
	private final LogLevelSelector logLevelFilter;
	private final String filterString;

	public SessiondEnableEventCommand(byte[] data) {
		if (data == null) {
			throw new IllegalArgumentException();
		}
		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.BIG_ENDIAN);
		int logLevel = buf.getInt();
		int logLevelType = buf.getInt();
		logLevelFilter = new LogLevelSelector(logLevel, logLevelType);

		/* Read the event name */
		byte[] eventNameBytes = new byte[EVENT_NAME_LENGTH];
		buf.get(eventNameBytes);
		eventName = new String(eventNameBytes, SESSIOND_PROTOCOL_CHARSET).trim();

		/* Read the filter string */
		filterString = readNextString(buf);

		/* The command was invalid if the string could not be read correctly */
		commandIsValid = (filterString != null);
	}

	@Override
	public LttngAgentResponse execute(ILttngTcpClientListener agent) {
		if (!commandIsValid) {
			return LttngAgentResponse.FAILURE_RESPONSE;
		}

		EventRule rule = new EventRule(eventName, logLevelFilter, filterString);
		boolean success = agent.eventEnabled(rule);
		return (success ? LttngAgentResponse.SUCESS_RESPONSE : LttngAgentResponse.FAILURE_RESPONSE);
	}

	@Override
	public String toString() {
		return "SessiondEnableEventCommand["
				+ "eventName=" + eventName
				+ ", logLevel=" + logLevelFilter.toString()
				+ ", filterString=" + filterString
				+"]";
	}
}
