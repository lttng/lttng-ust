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

import org.lttng.ust.agent.client.SessiondCommand.CommandType;

/**
 * Header of session daemon commands.
 *
 * @author Alexandre Montplaisir
 * @author David Goulet
 */
class SessiondCommandHeader {

	/** ABI size of command header. */
	public static final int HEADER_SIZE = 16;

	/** Payload size in bytes following this header. */
	private final long dataSize;

	/** Command type. */
	private final CommandType cmd;

	public SessiondCommandHeader(byte[] data) {
		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.BIG_ENDIAN);

		dataSize = buf.getLong();
		cmd = CommandType.values()[buf.getInt() - 1];
		buf.getInt(); // command version, currently unused
	}

	public long getDataSize() {
		return dataSize;
	}

	public CommandType getCommandType() {
		return cmd;
	}
}
