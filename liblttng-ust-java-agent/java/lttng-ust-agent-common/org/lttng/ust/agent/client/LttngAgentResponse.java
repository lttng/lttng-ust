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
 * Interface for all response messages sent from the Java agent to the sessiond
 * daemon. Normally sent after a command coming from the session daemon was
 * executed.
 *
 * @author Alexandre Montplaisir
 */
abstract class LttngAgentResponse {

	private static final int INT_SIZE = 4;

	public static final LttngAgentResponse SUCESS_RESPONSE = new LttngAgentResponse() {
		@Override
		public ReturnCode getReturnCode() {
			return ReturnCode.CODE_SUCCESS_CMD;
		}
	};

	public static final LttngAgentResponse FAILURE_RESPONSE = new LttngAgentResponse() {
		@Override
		public ReturnCode getReturnCode() {
			return ReturnCode.CODE_INVALID_CMD;
		}
	};

	/**
	 * Return codes used in agent responses, to indicate success or different
	 * types of failures of the commands.
	 */
	protected enum ReturnCode {

		CODE_SUCCESS_CMD(1, "sucess"),
		CODE_INVALID_CMD(2, "invalid"),
		CODE_UNKNOWN_LOGGER_NAME(3, "unknown logger name");

		private final int code;
		private final String toString;

		private ReturnCode(int c, String str) {
			code = c;
			toString = str;
		}

		public int getCode() {
			return code;
		}

		/**
		 * Mainly used for debugging. The strings are not sent through the
		 * socket.
		 */
		@Override
		public String toString() {
			return toString;
		}
	}

	/**
	 * Get the {@link ReturnCode} that goes with this response. It is expected
	 * by the session daemon, but some commands may require more than this
	 * in their response.
	 *
	 * @return The return code
	 */
	public abstract ReturnCode getReturnCode();

	/**
	 * Gets a byte array of the response so that it may be streamed.
	 *
	 * @return The byte array of the response
	 */
	public byte[] getBytes() {
		byte data[] = new byte[INT_SIZE];
		ByteBuffer buf = ByteBuffer.wrap(data);
		buf.order(ByteOrder.BIG_ENDIAN);
		buf.putInt(getReturnCode().getCode());
		return data;
	}

	@Override
	public String toString() {
		return "LttngAgentResponse["
				+ "code=" + getReturnCode().getCode()
				+ ", " + getReturnCode().toString()
				+ "]";
	}
}
