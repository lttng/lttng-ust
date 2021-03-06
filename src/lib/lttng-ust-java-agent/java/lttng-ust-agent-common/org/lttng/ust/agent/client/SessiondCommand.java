/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2015-2016 EfficiOS Inc.
 * Copyright (C) 2015-2016 Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2013 David Goulet <dgoulet@efficios.com>
 */

package org.lttng.ust.agent.client;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;

/**
 * Base class to represent all commands sent from the session daemon to the Java
 * agent. The agent is then expected to execute the command and provide a
 * response.
 *
 * @author Alexandre Montplaisir
 */
abstract class SessiondCommand {

	/**
	 * Encoding that should be used for the strings in the sessiond agent
	 * protocol on the socket.
	 */
	protected static final Charset SESSIOND_PROTOCOL_CHARSET = Charset.forName("UTF-8");

	enum CommandType {
		/** List logger(s). */
		CMD_LIST(1),
		/** Enable logger by name. */
		CMD_EVENT_ENABLE(2),
		/** Disable logger by name. */
		CMD_EVENT_DISABLE(3),
		/** Registration done */
		CMD_REG_DONE(4),
		/** Enable application context */
		CMD_APP_CTX_ENABLE(5),
		/** Disable application context */
		CMD_APP_CTX_DISABLE(6);

		private int code;

		private CommandType(int c) {
			code = c;
		}

		public int getCommandType() {
			return code;
		}
	}

	/**
	 * Execute the command handler's action on the specified tracing agent.
	 *
	 * @param agent
	 *            The agent on which to execute the command
	 * @return If the command completed successfully or not
	 */
	public abstract LttngAgentResponse execute(ILttngTcpClientListener agent);

	/**
	 * Utility method to read agent-protocol strings passed on the socket. The
	 * buffer will contain a 32-bit integer representing the length, immediately
	 * followed by the string itself.
	 *
	 * @param buffer
	 *            The ByteBuffer from which to read. It should already be setup
	 *            and positioned where the read should begin.
	 * @return The string that was read, or <code>null</code> if it was badly
	 *         formatted.
	 */
	protected static String readNextString(ByteBuffer buffer) {
		int nbBytes = buffer.getInt();
		if (nbBytes < 0) {
			/* The string length should be positive */
			return null;
		}
		if (nbBytes == 0) {
			/* The string is explicitly an empty string */
			return "";
		}

		byte[] stringBytes = new byte[nbBytes];
		buffer.get(stringBytes);
		return new String(stringBytes, SESSIOND_PROTOCOL_CHARSET).trim();
	}
}
