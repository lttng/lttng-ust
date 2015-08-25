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
import java.util.ArrayList;
import java.util.List;

import org.lttng.ust.agent.AbstractLttngAgent;

/**
 * Session daemon command asking the Java agent to list its registered loggers,
 * which corresponds to event names in the tracing session.
 *
 * @author Alexandre Montplaisir
 * @author David Goulet
 */
class SessiondListLoggersCommand implements ISessiondCommand {

	@Override
	public LttngAgentResponse execute(AbstractLttngAgent<?> agent) {
		final List<String> loggerList = new ArrayList<String>();
		int dataSize = 0;

		for (String event : agent.listEnabledEvents()) {
			loggerList.add(event);
			dataSize += event.length() + 1;
		}

		return new SessiondListLoggersResponse(loggerList, dataSize);
	}

	private static class SessiondListLoggersResponse extends LttngAgentResponse {

		private final static int SIZE = 12;

		private final List<String> loggers;
		private final int dataSize;

		public SessiondListLoggersResponse(List<String> loggers, int dataSize) {
			this.loggers = loggers;
			this.dataSize = dataSize;
		}

		@Override
		public ReturnCode getReturnCode() {
			/* This command can't really fail */
			return ReturnCode.CODE_SUCCESS_CMD;
		}

		@Override
		public byte[] getBytes() {
			byte data[] = new byte[SIZE + dataSize];
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);

			/* Returned code */
			buf.putInt(getReturnCode().getCode());
			buf.putInt(dataSize);
			buf.putInt(loggers.size());

			for (String logger : loggers) {
				buf.put(logger.getBytes());
				/* NULL terminated byte after the logger name. */
				buf.put((byte) 0x0);
			}
			return data;
		}
	}

}
