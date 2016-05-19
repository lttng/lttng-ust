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
import java.util.Collection;

/**
 * Session daemon command asking the Java agent to list its registered loggers,
 * which corresponds to event names in the tracing session.
 *
 * @author Alexandre Montplaisir
 * @author David Goulet
 */
class SessiondListLoggersCommand extends SessiondCommand {

	@Override
	public LttngAgentResponse execute(ILttngTcpClientListener agent) {
		final Collection<String> loggerList = agent.listAvailableEvents();
		return new SessiondListLoggersResponse(loggerList);
	}

	private static class SessiondListLoggersResponse extends LttngAgentResponse {

		private final static int SIZE = 12;

		private final Collection<String> loggers;

		public SessiondListLoggersResponse(Collection<String> loggers) {
			this.loggers = loggers;
		}

		@Override
		public ReturnCode getReturnCode() {
			/* This command can't really fail */
			return ReturnCode.CODE_SUCCESS_CMD;
		}

		@Override
		public byte[] getBytes() {
			/*
			 * Compute the data size, which is the number of bytes of each
			 * encoded string, +1 per string for the \0
			 */
			int dataSize = 0;
			for (String logger : loggers) {
				dataSize += logger.getBytes(SESSIOND_PROTOCOL_CHARSET).length + 1;
			}

			/* Prepare the buffer */
			byte data[] = new byte[SIZE + dataSize];
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);

			/* Write the header section of the response */
			buf.putInt(getReturnCode().getCode());
			buf.putInt(dataSize);
			buf.putInt(loggers.size());

			/* Write the payload */
			for (String logger : loggers) {
				buf.put(logger.getBytes(SESSIOND_PROTOCOL_CHARSET));
				/* NULL terminated byte after the logger name. */
				buf.put((byte) 0x0);
			}
			return data;
		}
	}

}
