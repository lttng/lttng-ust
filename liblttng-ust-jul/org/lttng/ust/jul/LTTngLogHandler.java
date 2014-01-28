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

package org.lttng.ust.jul;

import java.lang.String;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.LogManager;
import java.util.logging.Level;
import java.util.HashMap;

import org.lttng.ust.jul.LTTngUst;

/* Note: This is taken from the LTTng tools ABI. */
class LTTngLogLevelABI {
	/* Loglevel type. */
	public static final int LOGLEVEL_TYPE_ALL = 0;
	public static final int LOGLEVEL_TYPE_RANGE = 1;
	public static final int LOGLEVEL_TYPE_SINGLE = 2;
}

class LTTngLogLevel {
	/* Event name on which this loglevel is applied on. */
	private String event_name;
	/* This level is a JUL int level value. */
	private int level;
	private int type;

	public LTTngLogLevel(String event_name, int level, int type) {
		this.event_name = event_name;
		this.type = type;
		this.level = level;
	}

	public String getName() {
		return this.event_name;
	}

	public int getLevel() {
		return this.level;
	}

	public int getType() {
		return this.type;
	}
}

public class LTTngLogHandler extends Handler {
	public LogManager logManager;

	private HashMap<String, LTTngLogLevel> logLevels =
		new HashMap<String, LTTngLogLevel>();

	public LTTngLogHandler(LogManager logManager) {
		super();

		this.logManager = logManager;

		/* Initialize LTTng UST tracer. */
		LTTngUst.init();
	}

	public void setLogLevel(String event_name, int level, int type) {
		LTTngLogLevel lttngLogLevel = new LTTngLogLevel(event_name, level,
				type);
		logLevels.put(event_name, lttngLogLevel);
	}

	@Override
	public void close() throws SecurityException {}

	@Override
	public void flush() {}

	@Override
	public void publish(LogRecord record) {
		int fire_tp = 0, rec_log_level, ev_type, ev_log_level;
		LTTngLogLevel lttngLogLevel;
		String event_name = record.getLoggerName();

		lttngLogLevel = logLevels.get(event_name);
		if (lttngLogLevel != null) {
			rec_log_level = record.getLevel().intValue();
			ev_log_level = lttngLogLevel.getLevel();
			ev_type = lttngLogLevel.getType();

			switch (ev_type) {
			case LTTngLogLevelABI.LOGLEVEL_TYPE_RANGE:
				if (ev_log_level <= rec_log_level) {
					fire_tp = 1;
				}
				break;
			case LTTngLogLevelABI.LOGLEVEL_TYPE_SINGLE:
				if (ev_log_level == rec_log_level) {
					fire_tp = 1;
				}
				break;
			case LTTngLogLevelABI.LOGLEVEL_TYPE_ALL:
				fire_tp = 1;
				break;
			}
		} else {
			/* No loglevel attached thus fire tracepoint. */
			fire_tp = 1;
		}

		if (fire_tp == 0) {
			return;
		}

		/*
		 * Specific tracepoing designed for JUL events. The source class of the
		 * caller is used for the event name, the raw message is taken, the
		 * loglevel of the record and the thread ID.
		 */
		LTTngUst.tracepoint(record.getMessage(), record.getLoggerName(),
				record.getSourceClassName(), record.getSourceMethodName(),
				record.getMillis(), record.getLevel().intValue(),
				record.getThreadID());
	}
}
