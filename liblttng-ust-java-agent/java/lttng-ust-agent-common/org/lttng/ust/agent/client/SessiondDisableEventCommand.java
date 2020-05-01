/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015 EfficiOS Inc.
 * Copyright (C) 2015 Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
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
