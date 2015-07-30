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
interface ILttngAgentResponse {

	int INT_SIZE = 4;

	/**
	 * Return codes used in agent responses, to indicate success or different
	 * types of failures of the commands.
	 */
	enum ReturnCode {

		CODE_SUCCESS_CMD(1),
		CODE_INVALID_CMD(2),
		CODE_UNK_LOGGER_NAME(3);

		private int code;

		private ReturnCode(int c) {
			code = c;
		}

		public int getCode() {
			return code;
		}
	}

	/**
	 * Get the {@link ReturnCode} that goes with this response. It is expected
	 * by the session daemon, but some commands may require more than this
	 * in their response.
	 *
	 * @return The return code
	 */
	ReturnCode getReturnCode();

	/**
	 * Gets a byte array of the response so that it may be streamed.
	 *
	 * @return The byte array of the response
	 */
	byte[] getBytes();

	ILttngAgentResponse SUCESS_RESPONSE = new ILttngAgentResponse() {

		@Override
		public ReturnCode getReturnCode() {
			return ReturnCode.CODE_SUCCESS_CMD;
		}

		@Override
		public byte[] getBytes() {
			byte data[] = new byte[INT_SIZE];
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);
			buf.putInt(getReturnCode().getCode());
			return data;
		}
	};

	ILttngAgentResponse FAILURE_RESPONSE = new ILttngAgentResponse() {

		@Override
		public ReturnCode getReturnCode() {
			return ReturnCode.CODE_INVALID_CMD;
		}

		@Override
		public byte[] getBytes() {
			byte data[] = new byte[INT_SIZE];
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);
			buf.putInt(getReturnCode().getCode());
			return data;
		}
	};
}
