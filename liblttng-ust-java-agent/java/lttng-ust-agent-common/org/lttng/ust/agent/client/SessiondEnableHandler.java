/*
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

class SessiondEnableHandler implements ISessiondResponse, ISessiondCommand {

	private static final int INT_SIZE = 4;

	/** Event name to enable in the tracing session */
	private String eventName;

	/** Return status code to the session daemon. */
	public LttngAgentRetCode code;

	@Override
	public void populate(byte[] data) {
		int dataOffset = INT_SIZE * 2;

		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.LITTLE_ENDIAN);
		buf.getInt(); //logLevel, currently unused
		buf.getInt(); //logLevelType, currently unused
		eventName = new String(data, dataOffset, data.length - dataOffset).trim();
	}

	@Override
	public byte[] getBytes() {
		byte data[] = new byte[INT_SIZE];
		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putInt(code.getCode());
		return data;
	}

	public String getEventName() {
		return eventName;
	}

	/**
	 * Execute enable handler action which is to enable the given handler to the
	 * received name.
	 *
	 * @param agent
	 *            The agent on which to execute the command
	 */
	public void execute(AbstractLttngAgent<?> agent) {
		if (agent.eventEnabled(this.eventName)) {
			this.code = LttngAgentRetCode.CODE_SUCCESS_CMD;
		} else {
			this.code = LttngAgentRetCode.CODE_INVALID_CMD;
		}
	}
}
