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
import java.util.ArrayList;
import java.util.List;

import org.lttng.ust.agent.ILttngAgent;

class SessiondListLoggersResponse implements ISessiondResponse {

	private final static int SIZE = 12;

	private int dataSize = 0;
	private int nbLogger = 0;

	private final List<String> loggerList = new ArrayList<String>();

	/** Return status code to the session daemon. */
	public LttngAgentRetCode code;

	@Override
	public byte[] getBytes() {
		byte data[] = new byte[SIZE + dataSize];
		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.BIG_ENDIAN);

		/* Returned code */
		buf.putInt(code.getCode());
		buf.putInt(dataSize);
		buf.putInt(nbLogger);

		for (String logger : loggerList) {
			buf.put(logger.getBytes());
			/* NULL terminated byte after the logger name. */
			buf.put((byte) 0x0);
		}
		return data;
	}

	public void execute(ILttngAgent<?> agent) {
		for (String event : agent.listEnabledEvents()) {
			this.loggerList.add(event);
			this.nbLogger++;
			this.dataSize += event.length() + 1;
		}

		this.code = LttngAgentRetCode.CODE_SUCCESS_CMD;
	}
}
