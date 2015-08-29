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

/**
 * Interface to represent all commands sent from the session daemon to the Java
 * agent. The agent is then expected to execute the command and provide a
 * response.
 *
 * @author Alexandre Montplaisir
 */
interface ISessiondCommand {

	enum CommandType {

		/** List logger(s). */
		CMD_LIST(1),
		/** Enable logger by name. */
		CMD_ENABLE(2),
		/** Disable logger by name. */
		CMD_DISABLE(3),
		/** Registration done */
		CMD_REG_DONE(4);

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
	public LttngAgentResponse execute(ILttngTcpClientListener agent);
}