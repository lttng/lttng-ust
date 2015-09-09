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
class SessiondEnableEventCommand implements ISessiondCommand {

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
		buf.order(ByteOrder.LITTLE_ENDIAN);
		int logLevel = buf.getInt();
		int logLevelType = buf.getInt();
		logLevelFilter = new LogLevelSelector(logLevel, logLevelType);

		/* Read the event name */
		byte[] eventNameBytes = new byte[EVENT_NAME_LENGTH];
		buf.get(eventNameBytes);
		eventName = new String(eventNameBytes).trim();

		/*
		 * Read the filter string. The buffer contains the length (number of
		 * bytes), then the bytes themselves.
		 *
		 * The length is represented as an unsigned int, but it should never
		 * be greater than Integer.MAX_VALUE.
		 */
		int filterStringLength = buf.getInt();
		if (filterStringLength < 0) {
			/*
			 * The (unsigned) length is above what the sessiond should send. The
			 * command cannot be processed.
			 */
			filterString = null;
			commandIsValid = false;
			return;
		}
		if (filterStringLength == 0) {
			/* There is explicitly no filter string */
			filterString = "";
			commandIsValid = true;
			return;
		}

		byte[] filterStringBytes = new byte[filterStringLength];
		buf.get(filterStringBytes);
		filterString = new String(filterStringBytes).trim();

		commandIsValid = true;
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
}
