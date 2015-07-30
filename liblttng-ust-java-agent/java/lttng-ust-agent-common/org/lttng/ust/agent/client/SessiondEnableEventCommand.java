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

import org.lttng.ust.agent.AbstractLttngAgent;

/**
 * Session daemon command indicating to the Java agent that some events were
 * enabled in the tracing session.
 *
 * @author Alexandre Montplaisir
 * @author David Goulet
 */
class SessiondEnableEventCommand implements ISessiondCommand {

	private static final int INT_SIZE = 4;

	/** Event name to enable in the tracing session */
	private final String eventName;

	public SessiondEnableEventCommand(byte[] data) {
		if (data == null) {
			throw new IllegalArgumentException();
		}
		int dataOffset = INT_SIZE * 2;

		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.LITTLE_ENDIAN);
		buf.getInt(); // logLevel, currently unused
		buf.getInt(); // logLevelType, currently unused
		eventName = new String(data, dataOffset, data.length - dataOffset).trim();
	}

	@Override
	public ILttngAgentResponse execute(AbstractLttngAgent<?> agent) {
		boolean success = agent.eventEnabled(this.eventName);
		return (success ? ILttngAgentResponse.SUCESS_RESPONSE : ILttngAgentResponse.FAILURE_RESPONSE);
	}
}
