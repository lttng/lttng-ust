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

package org.lttng.ust.jul;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.lang.Object;
import java.util.logging.Logger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Enumeration;

public interface LTTngSessiondCmd2_4 {
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

	public enum lttng_jul_command {
		/** List logger(s). */
		CMD_LIST(1),
		/** Enable logger by name. */
		CMD_ENABLE(2),
		/** Disable logger by name. */
		CMD_DISABLE(3);
		private int code;

		private lttng_jul_command(int c) {
			code = c;
		}

		public int getCommand() {
			return code;
		}
	}

	enum lttng_jul_ret_code {
		CODE_SUCCESS_CMD(1),
		CODE_INVALID_CMD(2),
		CODE_UNK_LOGGER_NAME(3);
		private int code;

		private lttng_jul_ret_code(int c) {
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
		public lttng_jul_command cmd;
		/** Command version. */
		public int cmd_version;

		public void populate(byte[] data) {
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);

			data_size = buf.getLong();
			cmd = lttng_jul_command.values()[buf.getInt() - 1];
			cmd_version = buf.getInt();
		}
	}

	public class sessiond_enable_handler implements SessiondResponse, SessiondCommand {
		private final static int SIZE = 4;
		public String name;
		public int lttngLogLevel;
		public int lttngLogLevelType;

		/** Return status code to the session daemon. */
		public lttng_jul_ret_code code;

		@Override
		public void populate(byte[] data) {
			int data_offset = INT_SIZE * 2;

			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.LITTLE_ENDIAN);
			lttngLogLevel = buf.getInt();
			lttngLogLevelType = buf.getInt();
			name = new String(data, data_offset, data.length - data_offset);
		}

		@Override
		public byte[] getBytes() {
			byte data[] = new byte[SIZE];
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);
			buf.putInt(code.getCode());
			return data;
		}

		/*
		 * Enable a logger meaning add our handler to it using an exiting
		 * event. If successful, the logger is added to the given enabled
		 * Loggers hashmap.
		 *
		 * @return 0 if NO logger is found else 1 if added.
		 */
		public int enableLogger(LTTngLogHandler handler, LTTngEvent event,
				HashMap enabledLoggers) {
			Logger logger;

			logger = handler.logManager.getLogger(event.name);
			if (logger == null) {
				return 0;
			}

			handler.setEvent(event);
			logger.addHandler(handler);
			enabledLoggers.put(event.name, logger);

			return 1;
		}

		/**
		 * Execute enable handler action which is to enable the given handler
		 * to the received name.
		 *
		 * @return Event name as a string if the event is NOT found thus was
		 * not enabled.
		 */
		public LTTngEvent execute(LTTngLogHandler handler, HashMap enabledLoggers) {
			int ret;
			Logger logger;
			LTTngEvent event;

			if (name == null) {
				this.code = lttng_jul_ret_code.CODE_INVALID_CMD;
				return null;
			}

			/* Wild card to enable ALL logger. */
			if (name.trim().equals("*")) {
				String loggerName;
				Enumeration loggers = handler.logManager.getLoggerNames();

				/*
				 * Keep the loglevel value for all events in case an event
				 * appears later on.
				 */
				handler.logLevelUseAll = 1;
				handler.logLevelAll = lttngLogLevel;
				handler.logLevelTypeAll = lttngLogLevelType;

				while (loggers.hasMoreElements()) {
					loggerName = loggers.nextElement().toString();
					/* Somehow there is always an empty string at the end. */
					if (loggerName == "") {
						continue;
					}

					if (enabledLoggers.get(loggerName) != null) {
						continue;
					}

					/*
					 * Create new event object and set it in the log handler so
					 * we can process the record entry with the right
					 * attributes like the loglevels.
					 */
					event = new LTTngEvent(loggerName, lttngLogLevel,
							lttngLogLevelType);
					enableLogger(handler, event, enabledLoggers);
				}
				this.code = lttng_jul_ret_code.CODE_SUCCESS_CMD;

				event = new LTTngEvent("*", lttngLogLevel, lttngLogLevelType);
				return event;
			}

			this.code = lttng_jul_ret_code.CODE_SUCCESS_CMD;

			/*
			 * Create new event object and set it in the log handler so we can
			 * process the record entry with the right attributes like the
			 * loglevels.
			 */
			event = new LTTngEvent(name.trim(), lttngLogLevel,
					lttngLogLevelType);
			ret = enableLogger(handler, event, enabledLoggers);
			if (ret == 1) {
				return null;
			}
			return event;
		}
	}

	public class sessiond_disable_handler implements SessiondResponse, SessiondCommand {
		private final static int SIZE = 4;
		public String name;

		/** Return status code to the session daemon. */
		public lttng_jul_ret_code code;

		@Override
		public void populate(byte[] data) {
			ByteBuffer buf = ByteBuffer.wrap(data);
			buf.order(ByteOrder.BIG_ENDIAN);
			name = new String(data, 0, data.length);
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
		public void execute(LTTngLogHandler handler) {
			Logger logger;

			if (name == null) {
				this.code = lttng_jul_ret_code.CODE_INVALID_CMD;
				return;
			}

			/* Wild card to disable ALL logger. */
			if (name.trim().equals("*")) {
				String loggerName;
				Enumeration loggers = handler.logManager.getLoggerNames();
				while (loggers.hasMoreElements()) {
					loggerName = loggers.nextElement().toString();
					/* Somehow there is always an empty string at the end. */
					if (loggerName == "") {
						continue;
					}

					logger = handler.logManager.getLogger(loggerName);
					logger.removeHandler(handler);
				}
				this.code = lttng_jul_ret_code.CODE_SUCCESS_CMD;
				return;
			}

			logger = handler.logManager.getLogger(name.trim());
			if (logger == null) {
				this.code = lttng_jul_ret_code.CODE_UNK_LOGGER_NAME;
			} else {
				logger.removeHandler(handler);
				this.code = lttng_jul_ret_code.CODE_SUCCESS_CMD;
			}
		}
	}

	public class sessiond_list_logger implements SessiondResponse {
		private final static int SIZE = 12;

		private int data_size = 0;
		private int nb_logger = 0;

		List<String> logger_list = new ArrayList<String>();

		/** Return status code to the session daemon. */
		public lttng_jul_ret_code code;

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

		/**
		 * Execute enable handler action which is to enable the given handler
		 * to the received name.
		 */
		public void execute(LTTngLogHandler handler) {
			String loggerName;

			Enumeration loggers = handler.logManager.getLoggerNames();
			while (loggers.hasMoreElements()) {
				loggerName = loggers.nextElement().toString();
				/* Somehow there is always an empty string at the end. */
				if (loggerName == "") {
					continue;
				}

				this.logger_list.add(loggerName);
				this.nb_logger++;
				this.data_size += loggerName.length() + 1;
			}

			this.code = lttng_jul_ret_code.CODE_SUCCESS_CMD;
		}
	}
}
