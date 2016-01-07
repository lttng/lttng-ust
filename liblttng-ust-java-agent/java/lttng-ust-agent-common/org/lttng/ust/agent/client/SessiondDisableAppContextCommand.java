/*
 * Copyright (C) 2016 - EfficiOS Inc., Alexandre Montplaisir <alexmonthy@efficios.com>
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
 * Session daemon command indicating to the Java agent that an
 * application-specific context was disabled in the tracing session.
 *
 * @author Alexandre Montplaisir
 */
class SessiondDisableAppContextCommand extends SessiondCommand {

	private final String retrieverName;
	private final String contextName;

	private final boolean commandIsValid;

	public SessiondDisableAppContextCommand(byte[] data) {
		if (data == null) {
			throw new IllegalArgumentException();
		}
		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.BIG_ENDIAN);

		/*
		 * The buffer contains the retriever name first, followed by the
		 * context's name.
		 */
		retrieverName = readNextString(buf);
		contextName = readNextString(buf);

		/* If any of these strings were null then the command was invalid */
		commandIsValid = ((retrieverName != null) && (contextName != null));
	}

	@Override
	public LttngAgentResponse execute(ILttngTcpClientListener agent) {
		if (!commandIsValid) {
			return LttngAgentResponse.FAILURE_RESPONSE;
		}

		boolean success = agent.appContextDisabled(retrieverName, contextName);
		return (success ? LttngAgentResponse.SUCESS_RESPONSE : DISABLE_APP_CONTEXT_FAILURE_RESPONSE);
	}

	/**
	 * Response sent when the disable-context command asks to disable an
	 * unknown context name.
	 */
	private static final LttngAgentResponse DISABLE_APP_CONTEXT_FAILURE_RESPONSE = new LttngAgentResponse() {
		@Override
		public ReturnCode getReturnCode() {
			/* Same return code used for unknown event/logger names */
			return ReturnCode.CODE_UNKNOWN_LOGGER_NAME;
		}
	};
}
