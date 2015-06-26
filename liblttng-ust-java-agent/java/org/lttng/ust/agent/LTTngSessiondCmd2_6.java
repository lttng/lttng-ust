/*
 * Copyright (C) 2013 - David Goulet <dgoulet@efficios.com>
 *
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

package org.lttng.ust.agent;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

interface LTTngSessiondCmd2_6 {
	/**
	 * Maximum name length for a logger name to be send to sessiond.
	 */
	final static int NAME_MAX = 255;

	/*
	 * Size of a primitive type int in byte. Because you know, Java can't
	 * provide that since it does not makes sense...
	 */
	final static int INT_SIZE = 4;

	public interface SessiondResponse {
		/**
		 * Gets a byte array of the command so that it may be streamed
		 *
		 * @return the byte array of the command
		 */
		public byte[] getBytes();
	}

	public interface SessiondCommand {
		/**
		 * Populate the class from a byte array
		 *
		 * @param data
		 * 		the byte array containing the streamed command
		 */
		public void populate(byte[] data);
	}

	public enum lttng_agent_command {
		/** List logger(s). */
		CMD_LIST(1),
		/** Enable logger by name. */
		CMD_ENABLE(2),
		/** Disable logger by name. */
		CMD_DISABLE(3),
		/** Registration done */
		CMD_REG_DONE(4);

		private int code;

		private lttng_agent_command(int c) {
			code = c;
		}

		public int getCommand() {
			return code;
		}
	}

	enum lttng_agent_ret_code {
		CODE_SUCCESS_CMD(1),
		CODE_INVALID_CMD(2),
		CODE_UNK_LOGGER_NAME(3);
		private int code;

		private lttng_agent_ret_code(int c) {
			code = c;
		}

		public int getCode() {
			return code;
		}
	}

	public class sessiond_hdr implements SessiondCommand {
		/** ABI size of command header. */
		public final static int SIZE = 16;
		/** Payload size in bytes following this header.  */
		public long data_size;
		/** Command type. */
		public lttng_agent_command cmd;
		/** Command version. */
		public int cmd_version;

		public void populate(byte[] data) {
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);

			data_size = buf.getLong();
			cmd = lttng_agent_command.values()[buf.getInt() - 1];
			cmd_version = buf.getInt();
		}
	}

	public class sessiond_enable_handler implements SessiondResponse, SessiondCommand {
		private final static int SIZE = 4;
		public String name;
		public int lttngLogLevel;
		public int lttngLogLevelType;

		/** Return status code to the session daemon. */
		public lttng_agent_ret_code code;

		@Override
		public void populate(byte[] data) {
			int data_offset = INT_SIZE * 2;

			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.LITTLE_ENDIAN);
			lttngLogLevel = buf.getInt();
			lttngLogLevelType = buf.getInt();
			name = new String(data, data_offset, data.length - data_offset).trim();
		}

		@Override
		public byte[] getBytes() {
			byte data[] = new byte[SIZE];
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);
			buf.putInt(code.getCode());
			return data;
		}

		/**
		 * Execute enable handler action which is to enable the given handler
		 * to the received name.
		 */
		public void execute(LogFramework log) {
			if (log.enableLogger(this.name)) {
				this.code = lttng_agent_ret_code.CODE_SUCCESS_CMD;
			} else {
				this.code = lttng_agent_ret_code.CODE_INVALID_CMD;
			}
		}
	}

	public class sessiond_disable_handler implements SessiondResponse, SessiondCommand {
		private final static int SIZE = 4;
		public String name;


		/** Return status code to the session daemon. */
		public lttng_agent_ret_code code;

		@Override
		public void populate(byte[] data) {
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.LITTLE_ENDIAN);
			name = new String(data).trim();
		}

		@Override
		public byte[] getBytes() {
			byte data[] = new byte[SIZE];
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);
			buf.putInt(code.getCode());
			return data;
		}

		/**
		 * Execute disable handler action which is to disable the given handler
		 * to the received name.
		 */
		public void execute(LogFramework log) {
			if (log.disableLogger(this.name)) {
				this.code = lttng_agent_ret_code.CODE_SUCCESS_CMD;
			} else {
				this.code = lttng_agent_ret_code.CODE_INVALID_CMD;
			}
		}
	}

	public class sessiond_list_logger implements SessiondResponse {
		private final static int SIZE = 12;

		private int data_size = 0;
		private int nb_logger = 0;

		List<String> logger_list = new ArrayList<String>();

		/** Return status code to the session daemon. */
		public lttng_agent_ret_code code;

		@Override
		public byte[] getBytes() {
			byte data[] = new byte[SIZE + data_size];
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);

			/* Returned code */
			buf.putInt(code.getCode());
			buf.putInt(data_size);
			buf.putInt(nb_logger);

			for (String logger: logger_list) {
				buf.put(logger.getBytes());
				/* NULL terminated byte after the logger name. */
				buf.put((byte) 0x0);
			}
			return data;
		}

		public void execute(LogFramework log) {
			String loggerName;

			Iterator<String> loggers = log.listLoggers();
			while (loggers.hasNext()) {
				loggerName = loggers.next();
				this.logger_list.add(loggerName);
				this.nb_logger++;
				this.data_size += loggerName.length() + 1;
			}

			this.code = lttng_agent_ret_code.CODE_SUCCESS_CMD;
		}
	}
}
