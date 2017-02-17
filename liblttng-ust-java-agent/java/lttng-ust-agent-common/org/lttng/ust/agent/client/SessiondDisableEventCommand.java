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

/**
 * Session daemon command indicating to the Java agent that some events were
 * disabled in the tracing session.
 *
 * @author Alexandre Montplaisir
 * @author David Goulet
 */
class SessiondDisableEventCommand extends SessiondCommand {

	/**
	 * Response sent when the disable-event command asks to disable an
	 * unknown event.
	 */
	private static final LttngAgentResponse DISABLE_EVENT_FAILURE_RESPONSE = new LttngAgentResponse() {
		@Override
		public ReturnCode getReturnCode() {
			return ReturnCode.CODE_UNKNOWN_LOGGER_NAME;
		}
	};

	/** Event name to disable from the tracing session */
	private final String eventName;

	public SessiondDisableEventCommand(byte[] data) {
		if (data == null) {
			throw new IllegalArgumentException();
		}
		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.BIG_ENDIAN);
		eventName = new String(data, SESSIOND_PROTOCOL_CHARSET).trim();
	}

	@Override
	public LttngAgentResponse execute(ILttngTcpClientListener agent) {
		boolean success = agent.eventDisabled(this.eventName);
		return (success ? LttngAgentResponse.SUCESS_RESPONSE : DISABLE_EVENT_FAILURE_RESPONSE);
	}

	@Override
	public String toString() {
		return "SessiondDisableEventCommand["
				+ "eventName=" + eventName
				+"]";
	}
}
