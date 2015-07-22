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

class SessiondHeaderCommand implements ISessiondCommand {

	/** ABI size of command header. */
	public static final int HEADER_SIZE = 16;

	/** Payload size in bytes following this header. */
	private long dataSize;
	/** Command type. */
	private LttngAgentCommand cmd;

	@Override
	public void populate(byte[] data) {
		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.BIG_ENDIAN);

		dataSize = buf.getLong();
		cmd = LttngAgentCommand.values()[buf.getInt() - 1];
		buf.getInt(); // command version, currently unused
	}

	public long getDataSize() {
		return dataSize;
	}

	public LttngAgentCommand getCommandType() {
		return cmd;
	}
}
