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

interface ISessiondResponse {

	enum LttngAgentRetCode {
		CODE_SUCCESS_CMD(1),
		CODE_INVALID_CMD(2),
		CODE_UNK_LOGGER_NAME(3);
		private int code;

		private LttngAgentRetCode(int c) {
			code = c;
		}

		public int getCode() {
			return code;
		}
	}

	/**
	 * Gets a byte array of the command so that it may be streamed
	 *
	 * @return the byte array of the command
	 */
	byte[] getBytes();
}
