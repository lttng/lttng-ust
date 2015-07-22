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

interface ISessiondCommand {

	enum LttngAgentCommand {

		/** List logger(s). */
		CMD_LIST(1),
		/** Enable logger by name. */
		CMD_ENABLE(2),
		/** Disable logger by name. */
		CMD_DISABLE(3),
		/** Registration done */
		CMD_REG_DONE(4);

		private int code;

		private LttngAgentCommand(int c) {
			code = c;
		}

		public int getCommand() {
			return code;
		}
	}

	/**
	 * Populate the class from a byte array
	 *
	 * @param data
	 * 		the byte array containing the streamed command
	 */
	void populate(byte[] data);
}